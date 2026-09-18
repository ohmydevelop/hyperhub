//! git 原生层：pkt-line 识别后透传（v1 不做二进制解析）。

use crate::inspect::{self, Inspection};
use crate::protocol::handlers::bridge_layer;
use crate::protocol::stack::{LayerContext, LayerKind, ProtocolHandler};
use serde_json::json;
use std::future::Future;
use std::io;
use std::pin::Pin;

pub(crate) struct GitLayer;

impl ProtocolHandler for GitLayer {
    fn name(&self) -> &'static str {
        "git"
    }
    fn kind(&self) -> LayerKind {
        LayerKind::Native
    }

    fn detect(&self, data: &[u8], port: u16) -> Option<Inspection> {
        inspect::inspect_git(data, port)
    }

    fn serve(
        &self,
        ctx: LayerContext,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move { bridge_layer(ctx, Some(json!("git"))).await })
    }
}
