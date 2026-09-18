use crate::config::{parse_route_target, Config, FirewallAction, RouteTarget};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallSnapshot {
    pub version: u64,
    pub default_action: Option<FirewallAction>,
    #[serde(default)]
    pub error_action: FirewallAction,
    pub rules: Vec<FirewallSnapshotRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallSnapshotRule {
    pub id: String,
    pub action: FirewallAction,
    pub endpoints: Vec<FirewallSnapshotEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallSnapshotEndpoint {
    pub target: FirewallTarget,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum FirewallTarget {
    Domain { host: String, wildcard: bool },
    Ip(IpAddr),
    Network(IpNet),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallAuditStage {
    Dns,
    Connect,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDecisionSource {
    Rule,
    Default,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallAuditEvent {
    pub decision: FirewallAction,
    pub rule_id: Option<String>,
    pub source: FirewallDecisionSource,
    pub stage: FirewallAuditStage,
    pub hostname: Option<String>,
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub process_pid: u32,
    pub process_tid: u32,
    pub snapshot_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallDecision {
    pub action: FirewallAction,
    pub rule_id: Option<String>,
    pub source: FirewallDecisionSource,
}

pub fn decide(
    snapshot: &FirewallSnapshot,
    hostnames: &[String],
    ip: IpAddr,
    port: u16,
) -> FirewallDecision {
    for rule in &snapshot.rules {
        if rule.endpoints.iter().any(|endpoint| {
            endpoint.port.is_none_or(|configured| configured == port)
                && match &endpoint.target {
                    FirewallTarget::Domain { host, wildcard } => hostnames
                        .iter()
                        .any(|candidate| domain_matches(candidate, host, *wildcard)),
                    FirewallTarget::Ip(configured) => hostnames.is_empty() && ip == *configured,
                    FirewallTarget::Network(network) => {
                        hostnames.is_empty() && network.contains(&ip)
                    }
                }
        }) {
            return FirewallDecision {
                action: rule.action,
                rule_id: Some(rule.id.clone()),
                source: FirewallDecisionSource::Rule,
            };
        }
    }
    FirewallDecision {
        action: snapshot.default_action.unwrap_or(FirewallAction::Pass),
        rule_id: None,
        source: FirewallDecisionSource::Default,
    }
}

fn domain_matches(candidate: &str, configured: &str, wildcard: bool) -> bool {
    let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
    let configured = configured.trim_end_matches('.').to_ascii_lowercase();
    if wildcard {
        candidate != configured && candidate.ends_with(&format!(".{configured}"))
    } else {
        candidate == configured
    }
}

pub fn compile_snapshot(config: &Config, version: u64) -> Result<Option<FirewallSnapshot>, String> {
    if !config.firewall.enabled {
        return Ok(None);
    }

    let mut rules = Vec::new();
    for (order, rule) in config.firewall.rules.iter().enumerate() {
        if !rule.enabled {
            continue;
        }
        let endpoints = rule
            .endpoints
            .iter()
            .map(|endpoint| match parse_route_target(&endpoint.target)? {
                RouteTarget::Domain {
                    host,
                    wildcard,
                    path_prefix,
                } => {
                    if path_prefix.is_some() {
                        return Err(format!(
                            "firewall rule '{}' target '{}' cannot contain a URL path",
                            rule.id, endpoint.target
                        ));
                    }
                    Ok(FirewallSnapshotEndpoint {
                        target: FirewallTarget::Domain { host, wildcard },
                        port: endpoint.port,
                    })
                }
                RouteTarget::Ip(ip) => Ok(FirewallSnapshotEndpoint {
                    target: FirewallTarget::Ip(ip),
                    port: endpoint.port,
                }),
                RouteTarget::Network(network) => Ok(FirewallSnapshotEndpoint {
                    target: FirewallTarget::Network(network),
                    port: endpoint.port,
                }),
            })
            .collect::<Result<Vec<_>, String>>()?;
        rules.push((
            Reverse(rule.priority),
            order,
            FirewallSnapshotRule {
                id: rule.id.clone(),
                action: rule.action,
                endpoints,
            },
        ));
    }
    rules.sort_by_key(|(priority, order, _)| (*priority, *order));

    Ok(Some(FirewallSnapshot {
        version,
        default_action: config.firewall.default.as_ref().map(|rule| rule.action),
        error_action: config.firewall.error_action,
        rules: rules.into_iter().map(|(_, _, rule)| rule).collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FirewallConfig, FirewallDefaultRule, FirewallRule};

    fn rule(id: &str, priority: i32, action: FirewallAction) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            enabled: true,
            priority,
            action,
            endpoints: vec![crate::config::FirewallEndpoint {
                target: format!("{id}.example"),
                port: None,
            }],
            legacy: Default::default(),
        }
    }

    #[test]
    fn compiles_a_stable_snapshot() {
        let config = Config {
            firewall: FirewallConfig {
                enabled: true,
                default: Some(FirewallDefaultRule {
                    action: FirewallAction::Pass,
                }),
                error_action: FirewallAction::Pass,
                rules: vec![
                    rule("low", 1, FirewallAction::Pass),
                    rule("first", 5, FirewallAction::Deny),
                    rule("second", 5, FirewallAction::Pass),
                ],
            },
            ..Config::default()
        };
        config.validate().unwrap();

        let snapshot = compile_snapshot(&config, 7).unwrap().unwrap();
        assert_eq!(snapshot.version, 7);
        assert_eq!(snapshot.default_action, Some(FirewallAction::Pass));
        assert_eq!(
            snapshot
                .rules
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>(),
            ["first", "second", "low"]
        );
    }

    #[test]
    fn preserves_domain_wildcard_in_agent_snapshot() {
        let mut config = Config::default();
        config.firewall.enabled = true;
        config.firewall.rules.push(FirewallRule {
            id: "wildcard".into(),
            enabled: true,
            priority: 1,
            action: FirewallAction::Deny,
            endpoints: vec![crate::config::FirewallEndpoint {
                target: "*.example.com".into(),
                port: Some(443),
            }],
            legacy: Default::default(),
        });

        let snapshot = compile_snapshot(&config, 8).unwrap().unwrap();
        assert_eq!(
            snapshot.rules[0].endpoints[0],
            FirewallSnapshotEndpoint {
                target: FirewallTarget::Domain {
                    host: "example.com".into(),
                    wildcard: true,
                },
                port: Some(443),
            }
        );
    }

    #[test]
    fn decision_matches_ip_default_and_domain_rules() {
        let snapshot = FirewallSnapshot {
            version: 1,
            default_action: Some(FirewallAction::Deny),
            error_action: FirewallAction::Pass,
            rules: vec![FirewallSnapshotRule {
                id: "allow-example".into(),
                action: FirewallAction::Pass,
                endpoints: vec![FirewallSnapshotEndpoint {
                    target: FirewallTarget::Domain {
                        host: "example.com".into(),
                        wildcard: true,
                    },
                    port: Some(443),
                }],
            }],
        };
        assert_eq!(
            decide(
                &snapshot,
                &["api.example.com".into()],
                "192.0.2.1".parse().unwrap(),
                443,
            )
            .action,
            FirewallAction::Pass
        );
        assert_eq!(
            decide(&snapshot, &[], "192.0.2.1".parse().unwrap(), 80).action,
            FirewallAction::Deny
        );
    }
}
