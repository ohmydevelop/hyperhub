//! 协议处理：入站分类原语 + 递归协议栈。
//!
//! 不变量：serve 对"原对端"说的协议 = 客户端对"原对端"说的协议；
//! MITM 只替换被审计的最内层（tls/http），外层代理协议（HTTP CONNECT、
//! SOCKS5、absolute-form）必须端到端保留。
//!
//! 布局：
//! - `context.rs`   共享上下文（HandlerContext / contextual_error / action_name）
//! - `detect.rs`    首包分类原语（classify_ingress / IngressTransport）
//! - `transport.rs` 上游传输形态（ConnectedUpstream / UpstreamTransport）
//! - `stack.rs`     栈机制（run_stack / 深度上限 / LayerContext / ProtocolHandler）
//! - `handlers/`    每协议一个模块（ssh / socks5 / http_connect / http / https / git / raw）
//!   加协议 = 新增 `handlers/<name>.rs` 并在 `handlers::builtin_protocols()` 注册。

pub(crate) mod context;
pub(crate) mod detect;
pub(crate) mod handlers;
pub(crate) mod stack;
pub(crate) mod transport;

pub(crate) use context::HandlerContext;
pub(crate) use detect::{classify_ingress, IngressTransport};
pub(crate) use stack::{run_stack, BoxedStream};
pub(crate) use transport::{ConnectedUpstream, UpstreamTransport};
