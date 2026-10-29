//! Capability checks for attaching to already initialized application contexts.
use super::{Backend, Origin};
use crate::config::{Config, PluginProtocol, RuleAction};
use serde::{Deserialize, Serialize};
mod native_dns;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReport {
    pub supported: Vec<String>,
    pub limitations: Vec<String>,
    pub unsupported_required: Vec<String>,
}
impl CapabilityReport {
    pub fn require_supported(&self) -> Result<(), String> {
        if self.unsupported_required.is_empty() {
            return Ok(());
        }
        Err(format!(
            "dynamic attachment cannot preserve the configured traffic semantics: {}",
            self.unsupported_required.join("; ")
        ))
    }
}

pub fn dynamic_capabilities(config: &Config, backend: Backend) -> CapabilityReport {
    dynamic_capabilities_for_origin(config, backend, Origin::Attach)
}

/// Origin identifies the immutable DNS contract of this attachment. A child
/// may have owned startup while retaining its external creator's DNS contract.
pub fn dynamic_capabilities_for_origin(
    config: &Config,
    backend: Backend,
    origin: Origin,
) -> CapabilityReport {
    let mut report = CapabilityReport {
        supported: vec![
            "opaque_tcp".into(),
            "file_policy".into(),
            "process_policy".into(),
        ],
        limitations: vec![
            "existing_environment_and_trust_contexts_are_unchanged".into(),
            "future_children_inherit_existing_environment".into(),
            "preexisting_file_descriptors_are_not_retroactively_closed".into(),
            "preexisting_foreign_dns_caches_are_not_observable".into(),
            "explicit_synthetic_dns_requires_a_dedicated_address_pool".into(),
        ],
        unsupported_required: vec![],
    };
    if backend == Backend::Gum {
        report
            .limitations
            .push("direct_syscalls_outside_native_hooks_are_not_covered".into());
    }
    if origin == Origin::Attach {
        report
            .limitations
            .push("native_dns_observations_do_not_authorize_connection_hostnames".into());
        report
            .unsupported_required
            .extend(native_dns::unsupported(config));
    }
    let mut check = |label: &str,
                     plugins: &[String],
                     protection: Option<&str>,
                     plaintext_only: bool| {
        let required_plugins: Vec<_> = plugins.iter().filter_map(|id| config.plugin(id)).collect();
        let tls = !plaintext_only
            && (required_plugins.iter().any(|p| {
                p.protocols
                    .iter()
                    .any(|p| matches!(p, PluginProtocol::Http | PluginProtocol::Ws))
            }) || protection
                .and_then(|id| config.protection(id))
                .is_some_and(|p| p.enabled && (p.data.enabled || p.intelligence.enabled)));
        let ssh = required_plugins.iter().any(|p| {
            p.protocols.contains(&PluginProtocol::Ssh)
                && (p.kind == crate::config::PluginKind::Credential || p.ssh_transcript)
        });
        if tls {
            report.unsupported_required.push(format!(
                "{label}: TLS inspection requires trust changes in existing application contexts"
            ));
        }
        if ssh {
            report.unsupported_required.push(format!("{label}: SSH interception requires host trust changes in existing application contexts"));
        }
    };
    if config.default_route.enabled && config.default_route.action != RuleAction::Deny {
        check(
            "default route",
            &config.default_route.plugins,
            config.default_route.protection.as_deref(),
            false,
        );
    }
    for route in &config.rules {
        if route.enabled && route.action != RuleAction::Deny {
            let plaintext = !route.endpoints.is_empty()
                && route
                    .endpoints
                    .iter()
                    .all(|e| e.target.starts_with("http://") || e.target.starts_with("ws://"));
            check(
                &format!("route {}", route.id),
                &route.plugins,
                route.protection.as_deref(),
                plaintext,
            );
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PluginConfig, PluginKind};
    #[test]
    fn opaque_configuration_and_environment_do_not_require_startup_trust() {
        let report = dynamic_capabilities(&Config::default(), Backend::Ptrace);
        assert!(report.require_supported().is_ok());
        assert!(report.limitations.iter().any(|l| l.contains("environment")));
    }
    #[test]
    fn required_tls_or_ssh_interception_refuses_without_weakening_configuration() {
        let mut config = Config::default();
        config.plugins.push(PluginConfig {
            id: "credential".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Http],
            ..PluginConfig::default()
        });
        config.default_route.plugins = vec!["credential".into()];
        assert!(dynamic_capabilities(&config, Backend::Gum)
            .require_supported()
            .is_err());
        config.plugins[0].protocols = vec![PluginProtocol::Ssh];
        assert!(dynamic_capabilities(&config, Backend::Gum)
            .require_supported()
            .unwrap_err()
            .contains("SSH"));
        config.default_route.enabled = false;
        assert!(dynamic_capabilities(&config, Backend::Gum)
            .require_supported()
            .is_ok());
    }
}
