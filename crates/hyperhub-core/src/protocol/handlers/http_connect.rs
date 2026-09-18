//! HTTP 客户端代理 CONNECT 层：CONNECT 头原样转发、响应原样中继，2xx 后对
//! 隧道做 TLS MITM 并下钻；外层代理协议端到端保留。

use crate::duplex::PrefixedIo;
use crate::http::proxy_https_via_http_proxy;
use crate::inspect::{self, Inspection};
use crate::protocol::context::contextual_error;
use crate::protocol::stack::{LayerContext, LayerKind, ProtocolHandler};
use std::future::Future;
use std::io;
use std::pin::Pin;

pub(crate) struct HttpConnectLayer;

impl ProtocolHandler for HttpConnectLayer {
    fn name(&self) -> &'static str {
        "http_proxy_connect"
    }
    fn kind(&self) -> LayerKind {
        LayerKind::Tunnel
    }

    fn detect(&self, data: &[u8], port: u16) -> Option<Inspection> {
        let inspection = inspect::inspect_http(data, port)?;
        if inspection.proxy_form
            && inspection
                .http_method
                .as_deref()
                .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
        {
            Some(inspection)
        } else {
            None
        }
    }

    fn serve(
        &self,
        ctx: LayerContext,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            let error_context = ctx.inner.context.clone();
            let depth = ctx.depth;
            proxy_https_via_http_proxy(
                PrefixedIo::new(ctx.client, ctx.peek),
                ctx.upstream,
                depth,
                ctx.inner,
            )
            .await
            .map_err(|error| contextual_error(&error_context, "tls_mitm_via_client_proxy", error))
        })
    }
}
