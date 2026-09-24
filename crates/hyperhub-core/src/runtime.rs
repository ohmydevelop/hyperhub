//! 运行时配置快照：serve 启动后支持配置热更新。
//!
//! `RuntimeState` 持有一份原子替换的快照（配置 + 编译后的策略 + 解析后的环境变量）。
//! 每个连接 / 控制请求开始时取一次快照：新连接使用新配置，已建立的连接保持其
//! 开始时的旧快照，互不影响。热更新失败时旧快照原样保留。

use crate::config::{Config, ConfigError};
use crate::policy::PolicySnapshot;
use crate::protection::ProtectionSnapshot;
use crate::session::{unix_timestamp_ms, SessionEnvironmentVariable};
use std::sync::{Arc, RwLock};

/// 一次性快照：连接或控制请求开始时取用，生命周期内保持不变。
#[derive(Clone)]
pub struct RuntimeSnapshot {
    pub config: Arc<Config>,
    pub policy: Arc<PolicySnapshot>,
    pub protection: Arc<ProtectionSnapshot>,
    pub environment: Arc<Vec<SessionEnvironmentVariable>>,
    /// 快照创建 / 最近一次热更新的时间（毫秒），供 `status` 验证重载是否生效。
    pub updated_at_ms: u64,
}

/// 可热更新的运行时状态：`apply` 校验并原子替换快照，失败时保持旧快照。
#[derive(Clone)]
pub struct RuntimeState {
    inner: Arc<RwLock<RuntimeSnapshot>>,
    updates: tokio::sync::watch::Sender<u64>,
}

impl RuntimeState {
    pub fn new(config: Arc<Config>) -> Result<Self, ConfigError> {
        let config = (*config).clone();
        config.validate()?;
        let config = Arc::new(config);
        let policy = Arc::new(PolicySnapshot::compile(&config).map_err(ConfigError::Validation)?);
        let protection =
            Arc::new(ProtectionSnapshot::compile(&config).map_err(ConfigError::Validation)?);
        let environment = Arc::new(resolve_environment(&config)?);
        let snapshot = RuntimeSnapshot {
            config,
            policy,
            protection,
            environment,
            updated_at_ms: unix_timestamp_ms(),
        };
        let (updates, _) = tokio::sync::watch::channel(snapshot.updated_at_ms);
        Ok(Self {
            inner: Arc::new(RwLock::new(snapshot)),
            updates,
        })
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        self.inner.read().expect("runtime state poisoned").clone()
    }

    /// 构建待更新快照但不发布，供需要先准备外部资源的热更新流程使用。
    pub fn prepare_update(&self, config: Arc<Config>) -> Result<RuntimeSnapshot, String> {
        let previous = self.snapshot();
        let mut config = (*config).clone();
        // 审计存储由 HyperHub 托管；热更新 JSON 会跳过这两个字段，
        // 反序列化为 None 时沿用旧快照路径，避免内容转录静默停止。
        if config.audit.log.is_none() {
            config.audit.log = previous.config.audit.log.clone();
        }
        if config.audit.transcript_dir.is_none() {
            config.audit.transcript_dir = previous.config.audit.transcript_dir.clone();
        }
        config.validate().map_err(|error| error.to_string())?;
        let config = Arc::new(config);
        let policy = Arc::new(PolicySnapshot::compile(&config)?);
        let protection = Arc::new(ProtectionSnapshot::compile(&config)?);
        let environment =
            Arc::new(resolve_environment(&config).map_err(|error| error.to_string())?);
        Ok(RuntimeSnapshot {
            config,
            policy,
            protection,
            environment,
            updated_at_ms: unix_timestamp_ms().max(previous.updated_at_ms.saturating_add(1)),
        })
    }

    /// 发布一个已准备完成的快照。
    pub fn commit_update(&self, snapshot: RuntimeSnapshot) {
        let version = snapshot.updated_at_ms;
        *self.inner.write().expect("runtime state poisoned") = snapshot;
        let _ = self.updates.send(version);
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.updates.subscribe()
    }

    /// 热更新：编译新策略并解析环境变量，全部成功后才替换快照。
    pub fn apply(&self, config: Arc<Config>) -> Result<(), String> {
        let snapshot = self.prepare_update(config)?;
        self.commit_update(snapshot);
        Ok(())
    }
}

fn resolve_environment(config: &Config) -> Result<Vec<SessionEnvironmentVariable>, ConfigError> {
    config
        .environment
        .iter()
        .map(|variable| {
            let value = variable.value.resolve()?;
            if value.contains('\0') {
                return Err(ConfigError::Validation(format!(
                    "environment variable '{}' contains a NUL character",
                    variable.name
                )));
            }
            Ok(SessionEnvironmentVariable {
                name: variable.name.clone(),
                value,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteRule;
    use crate::policy::{ConnectionContext, Destination, ProcessInfo, Protocol};

    fn context(host: &str) -> ConnectionContext {
        ConnectionContext {
            session_id: "s".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "git".into(),
            },
            destination: Destination {
                ip: "10.0.0.1".parse().unwrap(),
                port: 443,
                hostnames: vec![host.into()],
            },
            protocol: Protocol::Unknown,
        }
    }

    fn rule(id: &str, target: &str) -> RouteRule {
        RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: id.into(),
            enabled: true,
            priority: 0,
            endpoints: vec![crate::config::RouteEndpoint {
                target: target.into(),
                port: None,
            }],
            action: crate::config::RuleAction::Pass,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec![],
            protection: None,
            allow_sensitive_upload: false,
            legacy: Default::default(),
        }
    }

    #[test]
    fn apply_swaps_snapshot_and_keeps_old_on_failure() {
        let mut config = Config::default();
        config.rules.push(rule("old", "example.com"));
        let state = RuntimeState::new(Arc::new(config)).unwrap();

        let first = state.snapshot();
        assert_eq!(
            first
                .policy
                .decide(&context("example.com"))
                .rule_id
                .as_deref(),
            Some("old")
        );

        let mut next = Config::default();
        next.rules.push(rule("new", "example.com"));
        let prepared = state.prepare_update(Arc::new(next)).unwrap();
        assert_eq!(
            state.snapshot().config.rules[0].id,
            "old",
            "preparing an update must not publish it"
        );
        state.commit_update(prepared);
        let second = state.snapshot();
        assert_eq!(
            second
                .policy
                .decide(&context("example.com"))
                .rule_id
                .as_deref(),
            Some("new")
        );
        assert!(second.updated_at_ms > first.updated_at_ms);
        assert_eq!(second.config.rules[0].id, "new");

        // 无效配置（无法编译）不得破坏旧快照。
        let mut broken = Config::default();
        broken.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            action: crate::config::RuleAction::Deny,
            upstream: Some("missing".into()),
            ..rule("broken", "example.com")
        });
        assert!(state.apply(Arc::new(broken)).is_err());
        assert_eq!(
            state.snapshot().config.rules[0].id,
            "new",
            "failed reload must keep the previous snapshot"
        );
    }

    #[test]
    fn hot_update_preserves_managed_audit_paths() {
        let mut config = Config::default();
        config.audit.log = Some("state/audit/security-alerts.jsonl".into());
        config.audit.transcript_dir = Some("state/audit/transcripts".into());
        let state = RuntimeState::new(Arc::new(config)).unwrap();

        let next = Config::default();
        let serialized = serde_json::to_string(&next).unwrap();
        let deserialized: Config = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.audit.log, None);
        assert_eq!(deserialized.audit.transcript_dir, None);

        state.apply(Arc::new(deserialized)).unwrap();
        let snapshot = state.snapshot().config;
        assert_eq!(
            snapshot.audit.log,
            Some("state/audit/security-alerts.jsonl".into())
        );
        assert_eq!(
            snapshot.audit.transcript_dir,
            Some("state/audit/transcripts".into())
        );
    }
}
