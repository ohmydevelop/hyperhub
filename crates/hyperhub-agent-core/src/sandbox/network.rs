#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
use crate::{
    exchange_control, parse_ip, state, AgentControlRequest, AgentControlResponse, HH_ERR_INVALID,
    HH_ERR_NOT_INITIALIZED, HH_ERR_PROTOCOL,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
use std::net::SocketAddr;
#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FirewallAction {
    #[default]
    Pass,
    Deny,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct FirewallSnapshot {
    pub(crate) version: u64,
    pub(crate) default_action: Option<FirewallAction>,
    #[serde(default)]
    pub(crate) error_action: FirewallAction,
    pub(crate) rules: Vec<FirewallSnapshotRule>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct FirewallSnapshotRule {
    pub(crate) id: String,
    pub(crate) action: FirewallAction,
    pub(crate) endpoints: Vec<FirewallEndpoint>,
    #[serde(default)]
    pub(crate) protection: Option<String>,
    #[serde(default)]
    pub(crate) prefilter_policy: super::PrefilterPolicy,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct FirewallEndpoint {
    pub(crate) target: FirewallRuleTarget,
    pub(crate) port: Option<u16>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub(crate) enum FirewallRuleTarget {
    Domain(FirewallDomainTarget),
    Ip(IpAddr),
    Network(ipnet::IpNet),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FirewallDomainTarget {
    pub(crate) host: String,
    pub(crate) wildcard: bool,
    pub(crate) include_apex: bool,
}

impl<'de> Deserialize<'de> for FirewallDomainTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum WireValue {
            Legacy(String),
            Explicit {
                host: String,
                #[serde(default)]
                wildcard: bool,
            },
        }

        Ok(match WireValue::deserialize(deserializer)? {
            WireValue::Legacy(host) => Self {
                host,
                wildcard: true,
                include_apex: true,
            },
            WireValue::Explicit { host, wildcard } => Self {
                host,
                wildcard,
                include_apex: false,
            },
        })
    }
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FirewallConnectTarget {
    pub(crate) hostname: Option<String>,
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) bypass: bool,
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FirewallAuditStage {
    Dns,
    Connect,
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FirewallDecisionSource {
    Rule,
    Default,
    Error,
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
#[derive(Clone, Debug, Serialize)]
pub(crate) struct FirewallAuditEvent {
    pub(crate) decision: FirewallAction,
    pub(crate) rule_id: Option<String>,
    pub(crate) source: FirewallDecisionSource,
    pub(crate) stage: FirewallAuditStage,
    pub(crate) hostname: Option<String>,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) port: Option<u16>,
    pub(crate) process_pid: u32,
    pub(crate) process_tid: u32,
    pub(crate) snapshot_version: u64,
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn firewall_snapshot() -> Option<Arc<FirewallSnapshot>> {
    state().lock().ok()?.sandbox.firewall.clone()
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn firewall_connect_target(
    family: i32,
    address: &[u8],
    port: u16,
) -> Option<FirewallConnectTarget> {
    let ip = parse_ip(address).ok()?;
    let core = state().lock().ok()?;
    let hostname = core.gateway.dns.get(&(family, address.to_vec())).cloned();
    let bypass = core.gateway.proxy == Some(SocketAddr::new(ip, port));
    Some(FirewallConnectTarget {
        hostname,
        ip,
        port,
        bypass,
    })
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
#[cfg_attr(all(windows, feature = "gum-agent"), allow(dead_code))]
pub(crate) fn firewall_decision(
    snapshot: &FirewallSnapshot,
    target: &FirewallConnectTarget,
) -> (FirewallAction, Option<String>, FirewallDecisionSource) {
    if target.bypass {
        return (FirewallAction::Pass, None, FirewallDecisionSource::Default);
    }
    for rule in &snapshot.rules {
        if rule.endpoints.iter().any(|endpoint| {
            endpoint.port.is_none_or(|port| port == target.port)
                && match &endpoint.target {
                    FirewallRuleTarget::Domain(domain) => {
                        target.hostname.as_deref().is_some_and(|hostname| {
                            domain_matches(
                                hostname,
                                &domain.host,
                                domain.wildcard,
                                domain.include_apex,
                            )
                        })
                    }
                    FirewallRuleTarget::Ip(ip) => target.hostname.is_none() && target.ip == *ip,
                    FirewallRuleTarget::Network(network) => {
                        target.hostname.is_none() && network.contains(&target.ip)
                    }
                }
        }) {
            return (
                rule.action,
                Some(rule.id.clone()),
                FirewallDecisionSource::Rule,
            );
        }
    }
    (
        snapshot.default_action.unwrap_or(FirewallAction::Pass),
        None,
        FirewallDecisionSource::Default,
    )
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
#[cfg_attr(all(windows, feature = "gum-agent"), allow(dead_code))]
fn domain_matches(candidate: &str, configured: &str, wildcard: bool, include_apex: bool) -> bool {
    let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
    let configured = configured.trim_end_matches('.').to_ascii_lowercase();
    if wildcard {
        (include_apex && candidate == configured)
            || (candidate != configured && candidate.ends_with(&format!(".{configured}")))
    } else {
        candidate == configured
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) struct FirewallRefresh {
    pub(crate) version: u64,
    pub(crate) changed: bool,
    pub(crate) firewall: Option<FirewallSnapshot>,
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn refresh_firewall(current_version: u64) -> Result<FirewallRefresh, i32> {
    let (endpoint, session_id, token) = {
        let core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        if !core.session.initialized {
            return Err(HH_ERR_NOT_INITIALIZED);
        }
        (
            core.session.control_endpoint.clone(),
            core.session.session_id.clone(),
            core.session.token.clone(),
        )
    };
    let request = AgentControlRequest::RefreshFirewall {
        session_id: &session_id,
        token: &token,
        current_version,
    };
    match exchange_control(&endpoint, &request)? {
        AgentControlResponse::FirewallRefresh {
            version,
            changed,
            firewall,
        } => Ok(FirewallRefresh {
            version,
            changed,
            firewall,
        }),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn report_firewall_audit(event: &FirewallAuditEvent) -> Result<(), i32> {
    let (endpoint, session_id, token) = {
        let core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        if !core.session.initialized {
            return Err(HH_ERR_NOT_INITIALIZED);
        }
        (
            core.session.control_endpoint.clone(),
            core.session.session_id.clone(),
            core.session.token.clone(),
        )
    };
    let request = AgentControlRequest::ReportFirewallAudit {
        session_id: &session_id,
        token: &token,
        event,
    };
    match exchange_control(&endpoint, &request)? {
        AgentControlResponse::Ok => Ok(()),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(test, any(windows, target_os = "linux"), feature = "gum-agent"))]
mod tests {
    use super::*;

    #[test]
    fn firewall_decision_matches_domain_and_port() {
        let snapshot = FirewallSnapshot {
            version: 1,
            default_action: Some(FirewallAction::Pass),
            error_action: FirewallAction::Pass,
            rules: vec![FirewallSnapshotRule {
                id: "deny-baidu".into(),
                action: FirewallAction::Deny,
                protection: None,
                prefilter_policy: super::PrefilterPolicy::None,
                endpoints: vec![FirewallEndpoint {
                    target: FirewallRuleTarget::Domain(FirewallDomainTarget {
                        host: "www.baidu.com".into(),
                        wildcard: false,
                        include_apex: false,
                    }),
                    port: Some(443),
                }],
            }],
        };
        let target = FirewallConnectTarget {
            hostname: Some("WWW.BAIDU.COM".into()),
            ip: "198.18.0.1".parse().unwrap(),
            port: 443,
            bypass: false,
        };
        let (action, rule_id, source) = firewall_decision(&snapshot, &target);
        assert_eq!(action, FirewallAction::Deny);
        assert_eq!(rule_id.as_deref(), Some("deny-baidu"));
        assert_eq!(source, FirewallDecisionSource::Rule);

        let target = FirewallConnectTarget { port: 80, ..target };
        assert_eq!(
            firewall_decision(&snapshot, &target).0,
            FirewallAction::Pass
        );
    }

    #[test]
    fn firewall_decision_matches_direct_ip_and_network_without_hostname() {
        let snapshot = FirewallSnapshot {
            version: 1,
            default_action: None,
            error_action: FirewallAction::Pass,
            rules: vec![FirewallSnapshotRule {
                id: "deny-private".into(),
                action: FirewallAction::Deny,
                protection: None,
                prefilter_policy: super::PrefilterPolicy::None,
                endpoints: vec![FirewallEndpoint {
                    target: FirewallRuleTarget::Network("10.0.0.0/8".parse().unwrap()),
                    port: None,
                }],
            }],
        };
        let target = FirewallConnectTarget {
            hostname: None,
            ip: "10.1.2.3".parse().unwrap(),
            port: 22,
            bypass: false,
        };
        assert_eq!(
            firewall_decision(&snapshot, &target).0,
            FirewallAction::Deny
        );
    }
}
