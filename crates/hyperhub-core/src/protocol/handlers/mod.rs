//! 协议处理器注册表：每协议一个模块，实现 `ProtocolHandler` 后在此登记。
//!
//! 加协议 = 在 `handlers/` 新增模块（探测 + 服务 + 可下钻）并加入
//! `builtin_protocols()`；`run_stack` 按注册顺序命中层后交给层 serve，
//! 无需改动 `handle_authenticated` 的分派。

pub(crate) mod git;
pub(crate) mod http;
pub(crate) mod http_connect;
pub(crate) mod https;
pub(crate) mod raw;
pub(crate) mod socks5;
pub(crate) mod ssh;

pub(crate) use git::GitLayer;
pub(crate) use http::HttpLayer;
pub(crate) use http_connect::HttpConnectLayer;
pub(crate) use https::TlsLayer;
pub(crate) use raw::RawLayer;
pub(crate) use socks5::Socks5Layer;
pub(crate) use ssh::SshLayer;

use crate::config::{PluginConfig, PluginProtocol};
use crate::duplex::{bridge, CaptureConfig, PrefixedIo};
use crate::protocol::context::action_name;
use crate::protocol::stack::{LayerContext, ProtocolHandler};
use serde_json::{json, Value};
use std::io;
use std::time::Instant;

/// 内置协议注册表：注册顺序即探测优先级 ssh → socks5 → CONNECT → http → tls → git → raw。
pub(crate) fn builtin_protocols() -> [&'static dyn ProtocolHandler; 7] {
    [
        &SshLayer,
        &Socks5Layer,
        &HttpConnectLayer,
        &HttpLayer,
        &TlsLayer,
        &GitLayer,
        &RawLayer,
    ]
}

fn raw_transport_capture_enabled(
    protocol: Option<PluginProtocol>,
    profile: Option<&PluginConfig>,
) -> bool {
    protocol == Some(PluginProtocol::Git)
        && profile.is_some_and(PluginConfig::git_transcript_enabled)
}

/// 透传服务：`PrefixedIo` 回放已消费字节后双向桥接，并按层打审计标签。
pub(crate) async fn bridge_layer(ctx: LayerContext, handler_tag: Option<Value>) -> io::Result<()> {
    let inner = ctx.inner;
    let protocol = match handler_tag.as_ref().and_then(Value::as_str) {
        Some("ssh") => Some(PluginProtocol::Ssh),
        Some("git") => Some(PluginProtocol::Git),
        _ => None,
    };
    let profile = protocol.and_then(|p| inner.decision.plugins.audit_for(p));
    // SSH 的网络字节仍是密文，不能冒充会话转录；可读的 SSH 内容只在凭证 MITM
    // 解密后的 channel 数据面旁路捕获。Git 暂保留现有的原始流捕获语义。
    let capture = raw_transport_capture_enabled(protocol, profile);
    let transcript = if capture {
        inner
            .config
            .audit
            .transcript_dir
            .as_deref()
            .map(|root| CaptureConfig {
                root: root.to_owned(),
                date_key: crate::retention::date_key(crate::retention::unix_timestamp_ms()),
                limit: profile.map(|profile| profile.body_limit).unwrap_or(0),
                session_id: inner.context.session_id.clone(),
                connection_id: inner.context.connection_id,
                stream_id: None,
                client_upload: profile.is_some_and(|value| value.transcript_client_upload),
                server_response: profile.is_some_and(|value| value.transcript_server_response),
            })
    } else {
        None
    };
    let started = Instant::now();
    let result = bridge(
        PrefixedIo::new(ctx.client, ctx.peek),
        ctx.upstream,
        transcript,
    )
    .await?;
    let mut extra = serde_json::Map::new();
    if !result.transcripts.is_empty() {
        extra.insert("transcripts".into(), json!(result.transcripts));
    }
    if let Some(tag) = handler_tag {
        extra.insert("handler".into(), tag);
    }
    inner.audit.connection(
        "close",
        &inner.context,
        inner.decision.rule_id.as_deref(),
        action_name(inner.decision.deny, inner.decision.upstream.is_some()),
        "closed",
        Some((result.bytes_up, result.bytes_down)),
        Some(started.elapsed().as_millis()),
        (!extra.is_empty()).then(|| Value::Object(extra)),
    );
    if protocol == Some(PluginProtocol::Git) && profile.is_some() {
        inner.audit.connection(
            "git_session",
            &inner.context,
            inner.decision.rule_id.as_deref(),
            action_name(inner.decision.deny, inner.decision.upstream.is_some()),
            "completed",
            Some((result.bytes_up, result.bytes_down)),
            Some(started.elapsed().as_millis()),
            Some(json!({"transcripts": result.transcripts})),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect;
    use crate::protocol::stack::ProtocolHandler;

    fn first_match(data: &[u8], port: u16) -> &'static dyn ProtocolHandler {
        builtin_protocols()
            .iter()
            .copied()
            .find(|layer| layer.detect(data, port).is_some())
            .unwrap()
    }

    #[test]
    fn registration_order_puts_connect_before_plain_http() {
        assert_eq!(
            first_match(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
                7890
            )
            .name(),
            "http_proxy_connect"
        );
        assert_eq!(
            first_match(
                b"GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: example.com\r\n\r\n",
                443
            )
            .name(),
            "http"
        );
        assert_eq!(
            first_match(&inspect::tests::client_hello("example.com", &[b"h2"]), 443).name(),
            "tls"
        );
        assert_eq!(first_match(&[5, 1, 0], 7890).name(), "socks5");
        assert_eq!(first_match(b"SSH-2.0-OpenSSH_9.0\r\n", 22).name(), "ssh");
        assert_eq!(first_match(b"\x00unknown\x01", 1234).name(), "raw");
    }

    #[test]
    fn ssh_passthrough_never_captures_ciphertext_as_transcript() {
        let profile = PluginConfig {
            capture_body: true,
            ssh_transcript: true,
            protocols: vec![PluginProtocol::Git],
            ..PluginConfig::default()
        };

        assert!(!raw_transport_capture_enabled(
            Some(PluginProtocol::Ssh),
            Some(&profile)
        ));
        assert!(raw_transport_capture_enabled(
            Some(PluginProtocol::Git),
            Some(&profile)
        ));

        let explicit = PluginConfig {
            capture_body: true,
            git_transcript: Some(false),
            protocols: vec![PluginProtocol::Http, PluginProtocol::Git],
            ..PluginConfig::default()
        };
        assert!(!raw_transport_capture_enabled(
            Some(PluginProtocol::Git),
            Some(&explicit)
        ));
    }
}
