//! SOCKS5 层：识别客户端自己的 SOCKS5 greeting，握手原样中继给上游代理、
//! 解析 CONNECT 目标重新决策，完成后读取内层前缀继续下钻。

use crate::client_proxy::{
    complete_socks5_connect, is_socks5_greeting, negotiate_socks5, resolve_socks5_target,
    write_socks5_reply,
};
use crate::duplex::PrefixedIo;
use crate::http::read_decrypted_prefix;
use crate::inspect::Inspection;
use crate::policy::Protocol;
use crate::protocol::context::{contextual_error, HandlerContext};
use crate::protocol::stack::{run_stack, LayerContext, LayerKind, ProtocolHandler};
use serde_json::json;
use std::future::Future;
use std::io;
use std::pin::Pin;

pub(crate) struct Socks5Layer;

impl ProtocolHandler for Socks5Layer {
    fn name(&self) -> &'static str {
        "socks5"
    }
    fn kind(&self) -> LayerKind {
        LayerKind::Passthrough
    }

    fn detect(&self, data: &[u8], _port: u16) -> Option<Inspection> {
        is_socks5_greeting(data).then(|| Inspection {
            protocol: Protocol::Unknown,
            hostname: None,
            port: None,
            http_method: None,
            tls_alpn: Vec::new(),
            proxy_form: false,
            detail: Some(json!({"proxy_protocol": "socks5"})),
        })
    }

    fn serve(
        &self,
        ctx: LayerContext,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            let LayerContext {
                inner,
                client,
                upstream,
                peek,
                depth,
            } = ctx;
            let error_context = inner.context.clone();
            let proxy_address = format!(
                "{}:{}",
                error_context.destination.ip, error_context.destination.port
            );
            let mut client = PrefixedIo::new(client, peek);
            let mut upstream = upstream;
            let target = negotiate_socks5(&mut client, &mut upstream)
                .await
                .map_err(|error| {
                    contextual_error(&error_context, "socks5_via_client_proxy", error)
                })?;
            let destination =
                resolve_socks5_target(target, &inner.context.session_id, &inner.sessions)
                    .await
                    .map_err(|error| {
                        contextual_error(&error_context, "socks5_via_client_proxy", error)
                    })?;
            let mut context = inner.context.clone();
            context.destination = destination;
            let decision = inner.policy.decide(&context);
            if decision.deny {
                write_socks5_reply(&mut client, 2).await?;
                inner.audit.connection(
                    "authorize",
                    &context,
                    decision.rule_id.as_deref(),
                    "deny",
                    "denied",
                    None,
                    None,
                    Some(json!({
                        "client_proxy": &proxy_address,
                        "client_proxy_protocol": "socks5",
                        "preserved": true,
                    })),
                );
                return Ok(());
            }
            if !complete_socks5_connect(&mut client, &mut upstream, &context.destination)
                .await
                .map_err(|error| {
                    contextual_error(&error_context, "socks5_via_client_proxy", error)
                })?
            {
                inner.audit.connection(
                    "connect",
                    &context,
                    decision.rule_id.as_deref(),
                    "proxy",
                    "client_proxy_rejected",
                    None,
                    None,
                    Some(json!({
                        "client_proxy": &proxy_address,
                        "client_proxy_protocol": "socks5",
                        "preserved": true,
                    })),
                );
                return Ok(());
            }
            let host = context
                .destination
                .hostnames
                .first()
                .cloned()
                .unwrap_or_else(|| context.destination.ip.to_string());
            let inner = HandlerContext {
                host,
                mitm: inner.mitm,
                ssh_mitm_key: inner.ssh_mitm_key,
                config: inner.config,
                policy: inner.policy,
                audit: inner.audit,
                context,
                decision,
                sessions: inner.sessions,
                upstream_tunneled: false,
            };
            let port = inner.context.destination.port;
            let mut client = client.into_inner();
            let prefix = read_decrypted_prefix(&mut client, port)
                .await
                .map_err(|error| {
                    contextual_error(&error_context, "socks5_via_client_proxy", error)
                })?;
            run_stack(client, upstream, prefix, depth + 1, inner).await
        })
    }
}
