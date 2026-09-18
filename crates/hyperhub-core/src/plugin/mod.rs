//! MITM 插件运行时：把"协议审计 / 凭证注入 / 协议转换"抽象为按协议注册的插件。
//!
//! 配置模型（`PluginConfig` / `PluginKind` / `PluginProtocol`）在 `config.rs`；
//! 这里提供路由决策解析后的热路径视图 `PluginSet`，以及插件扩展点：
//! - `Plugin` 基 trait（标识 kind 与协议能力）。
//! - 每协议类型化钩子 trait（http / ws / ssh / git；response / message 预留）。
//! v1 只实现"凭证 transform"与"审计 observe"，协议转换（convert）预留。

use crate::config::{PluginConfig, PluginKind, PluginProtocol};

/// 每 route 解析出的插件集合，按声明顺序执行。
#[derive(Debug, Clone, Default)]
pub struct PluginSet(pub Vec<PluginConfig>);

impl PluginSet {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &PluginConfig> {
        self.0.iter()
    }

    /// 命中所给协议的全部插件（audit + credential，顺序与配置一致）。
    pub fn for_protocol(&self, protocol: PluginProtocol) -> impl Iterator<Item = &PluginConfig> {
        self.0
            .iter()
            .filter(move |p| p.protocols.contains(&protocol))
    }

    pub fn audit_for(&self, protocol: PluginProtocol) -> Option<&PluginConfig> {
        self.0
            .iter()
            .find(|p| p.kind == PluginKind::Audit && p.protocols.contains(&protocol))
    }

    pub fn credential_for(&self, protocol: PluginProtocol) -> Option<&PluginConfig> {
        self.0
            .iter()
            .find(|p| p.kind == PluginKind::Credential && p.protocols.contains(&protocol))
    }

    /// git 载体是否为 HTTP（决定是否对 git@443/80 做 TLS MITM）：
    /// 仅当所有凭证插件都支持 http 载体时才 MITM，SSH-only 凭证要求原生透传。
    pub fn git_http_allowed(&self) -> bool {
        self.0
            .iter()
            .filter(|p| p.kind == PluginKind::Credential)
            .all(|p| p.protocols.contains(&PluginProtocol::Http))
    }
}

/// 插件基 trait：提供身份与能力，具体协议能力由各协议钩子 trait 表达。
pub trait Plugin: Send + Sync {
    fn config(&self) -> &PluginConfig;
    fn kind(&self) -> PluginKind {
        self.config().kind
    }
}

/// HTTP 插件钩子（credential transform 与 audit observe 共用）。
pub trait HttpHook: Plugin {
    /// 请求下行（client → upstream）回调；凭证插件返回需注入的头/URI 变更。
    fn on_http_request(&self, _ctx: &HttpRequestCtx) {}
}

/// WebSocket 插件钩子（audit observe；v1 无 transform）。
pub trait WsHook: Plugin {
    fn on_ws_frame(&self, _direction: StreamDirection) {}
}

/// SSH 插件钩子（audit observe；v1 不终止会话，无 transform）。
pub trait SshHook: Plugin {
    fn on_ssh_transcript(&self, _direction: StreamDirection) {}
}

/// Git 插件钩子（audit observe；v1 不解析 git 二进制）。
pub trait GitHook: Plugin {
    fn on_git_transcript(&self, _direction: StreamDirection) {}
}

/// HTTP 请求回调上下文：凭证插件据此注入 Authorization / Cookie / Query。
#[derive(Debug, Clone, Default)]
pub struct HttpRequestCtx {
    pub method: String,
    pub path_and_query: String,
}

/// 流方向：供 observe 类钩子区分上下行。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    Downstream,
    Upstream,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(id: &str, protocols: &[PluginProtocol]) -> PluginConfig {
        PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: id.into(),
            kind: PluginKind::Credential,
            protocols: protocols.to_vec(),
            ..PluginConfig::default()
        }
    }

    #[test]
    fn git_http_allowed_requires_http_carrier() {
        assert!(PluginSet(vec![]).git_http_allowed());
        assert!(PluginSet(vec![credential("h", &[PluginProtocol::Http])]).git_http_allowed());
        assert!(PluginSet(vec![credential(
            "both",
            &[PluginProtocol::Http, PluginProtocol::Ssh]
        )])
        .git_http_allowed());
        assert!(!PluginSet(vec![credential("s", &[PluginProtocol::Ssh])]).git_http_allowed());
    }

    #[test]
    fn selects_plugins_by_protocol() {
        let set = PluginSet(vec![
            credential("h", &[PluginProtocol::Http]),
            PluginConfig {
                uuid: crate::config::new_config_uuid(),
                id: "audit".into(),
                kind: PluginKind::Audit,
                protocols: vec![PluginProtocol::Http, PluginProtocol::Ws],
                ..PluginConfig::default()
            },
        ]);
        assert_eq!(
            set.credential_for(PluginProtocol::Http)
                .map(|p| p.id.as_str()),
            Some("h")
        );
        assert!(set.credential_for(PluginProtocol::Ssh).is_none());
        assert_eq!(
            set.audit_for(PluginProtocol::Ws).map(|p| p.id.as_str()),
            Some("audit")
        );
        assert_eq!(set.for_protocol(PluginProtocol::Http).count(), 2);
    }
}
