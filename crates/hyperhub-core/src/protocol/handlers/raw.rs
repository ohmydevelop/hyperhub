//! 终态 raw 层：`PrefixedIo` 回放已消费字节后双向透传。

use crate::inspect::Inspection;
use crate::protocol::handlers::bridge_layer;
use crate::protocol::stack::{LayerContext, LayerKind, ProtocolHandler};
use std::future::Future;
use std::io;
use std::pin::Pin;

pub(crate) struct RawLayer;

impl ProtocolHandler for RawLayer {
    fn name(&self) -> &'static str {
        "raw"
    }
    fn kind(&self) -> LayerKind {
        LayerKind::Passthrough
    }

    fn detect(&self, _data: &[u8], _port: u16) -> Option<Inspection> {
        Some(Inspection::unknown())
    }

    fn serve(
        &self,
        ctx: LayerContext,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move { bridge_layer(ctx, None).await })
    }
}
