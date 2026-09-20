//! 协议层共享上下文：所有栈层共用的策略/审计/会话依赖与工具。
//!
//! `HandlerContext` 由 `socks.rs` 构造、经各层下钻传递；`contextual_error` 统一
//! 错误上下文；`action_name` 供审计动作命名。

use crate::audit::AuditWriter;
use crate::config::Config;
use crate::http::TlsMitm;
use crate::policy::{ConnectionContext, PolicySnapshot, RouteDecision};
use crate::session::SessionRegistry;
use std::io;
use std::sync::Arc;

/// 协议处理器上下文：与具体流解耦，携带全部策略/审计依赖，供各层服务与下钻使用。
pub(crate) struct HandlerContext {
    pub host: String,
    pub mitm: Arc<TlsMitm>,
    pub ssh_mitm_key: Arc<russh::keys::PrivateKey>,
    pub config: Arc<Config>,
    pub policy: Arc<PolicySnapshot>,
    pub audit: AuditWriter,
    pub context: ConnectionContext,
    pub decision: RouteDecision,
    pub sessions: SessionRegistry,
    pub trust: Option<Arc<crate::trust::TrustStore>>,
    /// true 时 upstream 已是到真实目标的隧道，HTTP 层应把 absolute-form 转 origin-form。
    pub upstream_tunneled: bool,
}

pub(crate) fn contextual_error(
    context: &ConnectionContext,
    phase: &str,
    error: io::Error,
) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "session={} connection={} pid={} phase={phase}: {error}",
            context.session_id, context.connection_id, context.process.pid
        ),
    )
}

pub(crate) fn action_name(deny: bool, upstream: bool) -> &'static str {
    if deny {
        "deny"
    } else if upstream {
        "proxy"
    } else {
        "passthrough"
    }
}
