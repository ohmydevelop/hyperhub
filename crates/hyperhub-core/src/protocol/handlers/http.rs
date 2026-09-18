//! 明文 HTTP 层：注入/捕获/WebSocket 升级（含 git-over-http 与 absolute-form）。

use crate::duplex::PrefixedIo;
use crate::http::proxy_http;
use crate::inspect::{self, Inspection};
use crate::protocol::stack::{LayerContext, LayerKind, ProtocolHandler};
use std::future::Future;
use std::io;
use std::pin::Pin;

pub(crate) struct HttpLayer;

impl ProtocolHandler for HttpLayer {
    fn name(&self) -> &'static str {
        "http"
    }
    fn kind(&self) -> LayerKind {
        LayerKind::Http
    }

    fn detect(&self, data: &[u8], port: u16) -> Option<Inspection> {
        inspect::inspect_http(data, port)
    }

    fn serve(
        &self,
        ctx: LayerContext,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            proxy_http(
                PrefixedIo::new(ctx.client, ctx.peek),
                ctx.upstream,
                ctx.inner,
            )
            .await
        })
    }
}
