//! SSH 层：按 banner 识别。命中受信主机密钥时先探测校验；命中 SSH 凭证插件时
//! 进入双向 MITM（终止客户端会话，注入凭证连接真实服务器，桥接通道）。

use crate::audit::AuditWriter;
use crate::config::{Config, PluginProtocol};
use crate::duplex::{CaptureConfig, PrefixedIo};
use crate::inspect::{self, Inspection};
use crate::policy::{ConnectionContext, Destination};
use crate::protocol::context::contextual_error;
use crate::protocol::handlers::bridge_layer;
use crate::protocol::stack::{BoxedStream, LayerContext, LayerKind, ProtocolHandler};
use crate::ssh_mitm::{run_ssh_mitm, SshAuditContext, SshAuthAccount, SshAuthCandidates};
use serde_json::json;
use std::future::Future;
use std::io;
use std::pin::Pin;

pub(crate) struct SshLayer;

impl ProtocolHandler for SshLayer {
    fn name(&self) -> &'static str {
        "ssh"
    }
    fn kind(&self) -> LayerKind {
        LayerKind::Native
    }

    fn detect(&self, data: &[u8], port: u16) -> Option<Inspection> {
        inspect::inspect_ssh(data, port)
    }

    fn serve(
        &self,
        ctx: LayerContext,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            let config = ctx.inner.config.clone();
            let destination = ctx.inner.context.destination.clone();
            let audit = ctx.inner.audit.clone();
            let error_context = ctx.inner.context.clone();
            let rule_id = ctx.inner.decision.rule_id.clone();
            let plugins = ctx.inner.decision.plugins.clone();
            let ssh_mitm_key = ctx.inner.ssh_mitm_key.clone();
            let audit_profile = plugins.audit_for(PluginProtocol::Ssh).cloned();
            let transcript_requested = audit_profile
                .as_ref()
                .is_some_and(|profile| profile.ssh_transcript);
            let transcript = audit_profile.as_ref().and_then(|profile| {
                if !profile.ssh_transcript {
                    return None;
                }
                Some(CaptureConfig {
                    root: config.audit.transcript_dir.clone()?,
                    date_key: crate::retention::date_key(crate::retention::unix_timestamp_ms()),
                    limit: profile.body_limit,
                    session_id: error_context.session_id.clone(),
                    connection_id: error_context.connection_id,
                    stream_id: None,
                    client_upload: profile.transcript_client_upload,
                    server_response: profile.transcript_server_response,
                })
            });

            if let Err(error) = verify_ssh_host_key(&config, &destination).await {
                return deny(&audit, &error_context, rule_id.as_deref(), error);
            }

            if let Some(plugin) = plugins.credential_for(PluginProtocol::Ssh) {
                let accounts = plugin
                    .ssh_accounts
                    .iter()
                    .map(|account| SshAuthAccount {
                        username: account.username.clone(),
                        keys: account
                            .private_keys
                            .iter()
                            .filter_map(|key| key.value.resolve().ok())
                            .collect(),
                        passwords: account
                            .passwords
                            .iter()
                            .filter_map(|password| password.resolve().ok())
                            .collect(),
                    })
                    .collect::<Vec<_>>();
                if accounts
                    .iter()
                    .all(|account| account.keys.is_empty() && account.passwords.is_empty())
                {
                    return deny(
                        &audit,
                        &error_context,
                        rule_id.as_deref(),
                        io::Error::other("SSH 凭证账号缺少可用的私钥或密码"),
                    );
                }

                let LayerContext {
                    inner: _inner,
                    client,
                    upstream,
                    peek,
                    depth: _depth,
                } = ctx;
                let client = Box::new(PrefixedIo::new(client, peek)) as BoxedStream;
                return run_ssh_mitm(
                    client,
                    upstream,
                    SshAuthCandidates { accounts },
                    SshAuditContext {
                        audit: audit.clone(),
                        context: error_context.clone(),
                        rule_id: rule_id.clone(),
                        server_key: ssh_mitm_key,
                        record_events: audit_profile.is_some(),
                        transcript,
                    },
                )
                .await;
            }

            if transcript_requested {
                audit.connection(
                    "ssh_audit_requires_credential",
                    &error_context,
                    rule_id.as_deref(),
                    "passthrough",
                    "skipped",
                    None,
                    None,
                    Some(json!({
                        "message": "SSH 会话内容捕获需要同一路由绑定 SSH 凭证；本次未保存密文流",
                    })),
                );
            }

            bridge_layer(ctx, Some(json!("ssh"))).await
        })
    }
}

fn deny(
    audit: &AuditWriter,
    context: &ConnectionContext,
    rule_id: Option<&str>,
    error: io::Error,
) -> io::Result<()> {
    let error = contextual_error(context, "ssh_host_key_verification", error);
    audit.connection(
        "authorize",
        context,
        rule_id,
        "deny",
        "ssh_host_key_mismatch",
        None,
        None,
        Some(json!({"message": error.to_string()})),
    );
    Err(error)
}

/// 若目标命中 `Config.ssh_host_keys` 中的受信主机密钥，则另开探测连接校验其公钥；
/// 不一致时拒绝，未命中则按原样透传。
async fn verify_ssh_host_key(config: &Config, destination: &Destination) -> io::Result<()> {
    let host = destination
        .hostnames
        .first()
        .cloned()
        .unwrap_or_else(|| destination.ip.to_string());
    let trusted = config
        .ssh_host_keys
        .iter()
        .find(|key| key.enabled && key_matches_target(&key.host, destination))
        .cloned();
    let Some(key) = trusted else {
        return Ok(());
    };
    let (key_type, key_blob) = (key.key_type.clone(), key.key_blob.clone());
    let probe_host = destination.ip.to_string();
    let port = destination.port;
    let matches = tokio::task::spawn_blocking(move || {
        crate::certificate::ssh_host_key_matches(&probe_host, port, &key_type, &key_blob)
    })
    .await
    .map_err(io::Error::other)??;
    if matches {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "SSH 主机密钥与受信记录不一致：{host}:{port}"
        )))
    }
}

/// 受信记录里的 `host`（`host` 或 `host:port`）是否命中目标。
fn key_matches_target(entry: &str, destination: &Destination) -> bool {
    let (entry_host, entry_port) = match entry.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => {
            (host.trim_end_matches(['[', ']']), Some(port))
        }
        _ => (entry.trim_end_matches(['[', ']']), None),
    };
    if entry_port.is_some_and(|port| port != &destination.port.to_string()) {
        return false;
    }
    let entry_host = entry_host.trim_end_matches('.').to_ascii_lowercase();
    if entry_host == destination.ip.to_string() {
        return true;
    }
    destination
        .hostnames
        .iter()
        .any(|candidate| candidate.trim_end_matches('.').to_ascii_lowercase() == entry_host)
}
