//! TLS 层：ClientHello → MITM 解密后下钻 `run_stack`。

use crate::duplex::PrefixedIo;
use crate::http::proxy_https;
use crate::inspect::{self, Inspection};
use crate::protocol::context::contextual_error;
use crate::protocol::stack::{LayerContext, LayerKind, ProtocolHandler};
use std::future::Future;
use std::io;
use std::pin::Pin;

pub(crate) struct TlsLayer;

impl ProtocolHandler for TlsLayer {
    fn name(&self) -> &'static str {
        "tls"
    }
    fn kind(&self) -> LayerKind {
        LayerKind::Https
    }

    fn detect(&self, data: &[u8], port: u16) -> Option<Inspection> {
        inspect::inspect_tls(data, port)
    }

    fn serve(
        &self,
        ctx: LayerContext,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            let error_context = ctx.inner.context.clone();
            let depth = ctx.depth;
            proxy_https(
                PrefixedIo::new(ctx.client, ctx.peek),
                ctx.upstream,
                depth,
                ctx.inner,
            )
            .await
            .map_err(|error| contextual_error(&error_context, "tls_mitm", error))
        })
    }
}
