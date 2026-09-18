use crate::hook_runtime::{
    AgentHookPlugin, CallbackCategory, HookDecision, HookError, HookFailureMode,
};
use crate::windows_gum::runtime::PluginRegistrar;
use arc_swap::ArcSwapOption;
use std::net::IpAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

const WSAHOST_NOT_FOUND: i32 = 11001;
const WSAEACCES: i32 = 10013;
const AUDIT_QUEUE_CAPACITY: usize = 256;
const FIREWALL_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

struct FirewallPlugin {
    snapshot: Arc<ArcSwapOption<crate::FirewallSnapshot>>,
    current_version: Arc<AtomicU64>,
    audit: Option<SyncSender<crate::FirewallAuditEvent>>,
    dropped_events: Arc<AtomicU64>,
}

#[derive(Debug, PartialEq, Eq)]
enum FirewallDecision {
    Pass,
    ErrorPass,
    Deny {
        rule_id: Option<String>,
        source: crate::FirewallDecisionSource,
    },
}

impl FirewallPlugin {
    fn new() -> Self {
        let initial = crate::firewall_snapshot();
        let current_version = Arc::new(AtomicU64::new(
            initial.as_deref().map_or(0, |snapshot| snapshot.version),
        ));
        let snapshot = Arc::new(ArcSwapOption::from(initial));
        if cfg!(test) {
            return Self {
                snapshot,
                current_version,
                audit: None,
                dropped_events: Arc::new(AtomicU64::new(0)),
            };
        }
        let (sender, receiver) = sync_channel(AUDIT_QUEUE_CAPACITY);
        let dropped_events = Arc::new(AtomicU64::new(0));
        let report_failures = dropped_events.clone();
        let worker_snapshot = snapshot.clone();
        let worker_version = current_version.clone();
        let audit = match std::thread::Builder::new()
            .name("hyperhub-firewall-runtime".into())
            .spawn(move || {
                let mut reported_drops = 0;
                let mut last_refresh = Instant::now() - FIREWALL_REFRESH_INTERVAL;
                loop {
                    let timeout = FIREWALL_REFRESH_INTERVAL.saturating_sub(last_refresh.elapsed());
                    match receiver.recv_timeout(timeout) {
                        Ok(event) => {
                            if crate::report_firewall_audit(&event).is_err() {
                                report_failures.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    if last_refresh.elapsed() >= FIREWALL_REFRESH_INTERVAL {
                        let version = worker_version.load(Ordering::Acquire);
                        if let Ok(refresh) = crate::refresh_firewall(version) {
                            apply_refresh(&worker_snapshot, &worker_version, refresh);
                        }
                        last_refresh = Instant::now();
                    }
                    let dropped = report_failures.load(Ordering::Relaxed);
                    if dropped != reported_drops
                        && std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some()
                    {
                        eprintln!("hyperhub-agent: firewall audit dropped_or_failed={dropped}");
                        reported_drops = dropped;
                    }
                }
            }) {
            Ok(_) => Some(sender),
            Err(error) => {
                if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
                    eprintln!("hyperhub-agent: cannot start firewall runtime worker: {error}");
                }
                None
            }
        };
        Self {
            snapshot,
            current_version,
            audit,
            dropped_events,
        }
    }

    fn failure_mode(&self) -> HookFailureMode {
        if self
            .snapshot
            .load_full()
            .as_deref()
            .is_some_and(|snapshot| snapshot.error_action == crate::FirewallAction::Deny)
        {
            HookFailureMode::FailClosed
        } else {
            HookFailureMode::FailOpen
        }
    }

    fn failure_decision(&self) -> FirewallDecision {
        let action = self
            .snapshot
            .load_full()
            .as_deref()
            .map_or(crate::FirewallAction::Pass, |snapshot| {
                snapshot.error_action
            });
        match action {
            crate::FirewallAction::Pass => FirewallDecision::ErrorPass,
            crate::FirewallAction::Deny => FirewallDecision::Deny {
                rule_id: None,
                source: crate::FirewallDecisionSource::Error,
            },
        }
    }

    fn error_decision(&self, action: crate::FirewallAction) -> FirewallDecision {
        match action {
            crate::FirewallAction::Pass => FirewallDecision::ErrorPass,
            crate::FirewallAction::Deny => FirewallDecision::Deny {
                rule_id: None,
                source: crate::FirewallDecisionSource::Error,
            },
        }
    }

    fn evaluate_dns_safely(&self, hostname: &str) -> FirewallDecision {
        catch_unwind(AssertUnwindSafe(|| self.evaluate_dns(hostname)))
            .unwrap_or_else(|_| self.failure_decision())
    }

    fn evaluate_connect_safely(
        &self,
        target: Option<&crate::FirewallConnectTarget>,
    ) -> FirewallDecision {
        catch_unwind(AssertUnwindSafe(|| self.evaluate_connect(target)))
            .unwrap_or_else(|_| self.failure_decision())
    }

    fn evaluate_dns(&self, hostname: &str) -> FirewallDecision {
        let snapshot = self.snapshot.load_full();
        let Some(snapshot) = snapshot.as_deref() else {
            return FirewallDecision::Pass;
        };
        let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
        if hostname.is_empty() {
            return self.error_decision(snapshot.error_action);
        }

        for rule in &snapshot.rules {
            let domain_match = rule.endpoints.iter().any(|endpoint| {
                    matches!(&endpoint.target, crate::FirewallRuleTarget::Domain(domain) if domain_matches(&hostname, &domain.host, domain.wildcard, domain.include_apex))
                });
            let needs_connect = rule.endpoints.iter().any(|endpoint| {
                endpoint.port.is_some()
                    || matches!(
                        endpoint.target,
                        crate::FirewallRuleTarget::Ip(_) | crate::FirewallRuleTarget::Network(_)
                    )
            });
            if !domain_match && !needs_connect {
                continue;
            }
            if needs_connect {
                // The DNS adapter does not know the destination port or the real address behind a
                // fake IP. Defer to socket.connect so an earlier rule cannot be bypassed.
                return FirewallDecision::Pass;
            }
            return action_decision(
                rule.action,
                Some(rule.id.clone()),
                crate::FirewallDecisionSource::Rule,
            );
        }
        default_decision(snapshot, crate::FirewallDecisionSource::Default)
    }

    fn evaluate_connect(&self, target: Option<&crate::FirewallConnectTarget>) -> FirewallDecision {
        let snapshot = self.snapshot.load_full();
        let Some(snapshot) = snapshot.as_deref() else {
            return FirewallDecision::Pass;
        };
        let Some(target) = target else {
            return self.error_decision(snapshot.error_action);
        };
        if target.bypass {
            return FirewallDecision::Pass;
        }

        for rule in &snapshot.rules {
            if !rule.endpoints.iter().any(|endpoint| {
                endpoint.port.is_none_or(|port| port == target.port)
                    && match &endpoint.target {
                        crate::FirewallRuleTarget::Domain(domain) => {
                            target.hostname.as_deref().is_some_and(|hostname| {
                                domain_matches(
                                    hostname,
                                    &domain.host,
                                    domain.wildcard,
                                    domain.include_apex,
                                )
                            })
                        }
                        // A fake-IP connection retains its hostname but not the upstream address.
                        // IP/CIDR selectors therefore apply only to direct IP connections.
                        crate::FirewallRuleTarget::Ip(ip) => {
                            target.hostname.is_none() && target.ip == *ip
                        }
                        crate::FirewallRuleTarget::Network(network) => {
                            target.hostname.is_none() && network.contains(&target.ip)
                        }
                    }
            }) {
                continue;
            }
            return action_decision(
                rule.action,
                Some(rule.id.clone()),
                crate::FirewallDecisionSource::Rule,
            );
        }
        default_decision(snapshot, crate::FirewallDecisionSource::Default)
    }

    fn report_decision(
        &self,
        decision: FirewallDecision,
        stage: crate::FirewallAuditStage,
        hostname: Option<String>,
        ip: Option<IpAddr>,
        port: Option<u16>,
    ) -> bool {
        let (decision_action, rule_id, source) = match decision {
            FirewallDecision::Pass => return false,
            FirewallDecision::ErrorPass => (
                crate::FirewallAction::Pass,
                None,
                crate::FirewallDecisionSource::Error,
            ),
            FirewallDecision::Deny { rule_id, source } => {
                (crate::FirewallAction::Deny, rule_id, source)
            }
        };
        let snapshot_version = self.snapshot.load_full().as_deref().map_or_else(
            || self.current_version.load(Ordering::Acquire),
            |snapshot| snapshot.version,
        );
        let event = crate::FirewallAuditEvent {
            decision: decision_action,
            rule_id,
            source,
            stage,
            hostname,
            ip,
            port,
            process_pid: unsafe { GetCurrentProcessId() },
            process_tid: unsafe { GetCurrentThreadId() },
            snapshot_version,
        };
        let Some(audit) = &self.audit else {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
            return decision_action == crate::FirewallAction::Deny;
        };
        if let Err(error) = audit.try_send(event) {
            match error {
                TrySendError::Full(_) | TrySendError::Disconnected(_) => {
                    self.dropped_events.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        decision_action == crate::FirewallAction::Deny
    }
}

fn apply_refresh(
    snapshot: &ArcSwapOption<crate::FirewallSnapshot>,
    current_version: &AtomicU64,
    refresh: crate::FirewallRefresh,
) {
    let current = current_version.load(Ordering::Acquire);
    if refresh.version < current {
        return;
    }
    if refresh.changed {
        snapshot.store(refresh.firewall.map(Arc::new));
    }
    current_version.store(refresh.version, Ordering::Release);
}

impl AgentHookPlugin for FirewallPlugin {
    fn id(&self) -> &'static str {
        "firewall"
    }
}

pub(crate) fn register(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    let plugin = Arc::new(FirewallPlugin::new());
    let plugin_id = plugin.id();
    let dns_plugin = plugin.clone();
    registrar.dns_before_with_failure_mode(
        plugin_id,
        CallbackCategory::Control,
        HookFailureMode::FailOpen,
        move |context| {
            if dns_plugin.failure_mode() == HookFailureMode::FailClosed {
                context.denied_error = Some(WSAHOST_NOT_FOUND);
            }
            let decision = dns_plugin.evaluate_dns_safely(&context.hostname);
            if dns_plugin.report_decision(
                decision,
                crate::FirewallAuditStage::Dns,
                Some(context.hostname.clone()),
                None,
                None,
            ) {
                return Ok(context.deny(WSAHOST_NOT_FOUND));
            }
            context.denied_error = None;
            Ok(HookDecision::Continue)
        },
    );

    let connect_plugin = plugin.clone();
    registrar.connect_before_with_failure_mode(
        plugin_id,
        CallbackCategory::Control,
        HookFailureMode::FailOpen,
        move |context| {
            if connect_plugin.failure_mode() == HookFailureMode::FailClosed {
                context.denied_error = Some(WSAEACCES);
            }
            let decision = connect_plugin.evaluate_connect_safely(context.source());
            let target = context.source().cloned();
            if connect_plugin.report_decision(
                decision,
                crate::FirewallAuditStage::Connect,
                target.as_ref().and_then(|target| target.hostname.clone()),
                target.as_ref().map(|target| target.ip),
                target.as_ref().map(|target| target.port),
            ) {
                return Ok(context.deny(WSAEACCES));
            }
            context.denied_error = None;
            Ok(HookDecision::Continue)
        },
    );

    registrar.retain_plugin(plugin)
}

fn action_decision(
    action: crate::FirewallAction,
    rule_id: Option<String>,
    source: crate::FirewallDecisionSource,
) -> FirewallDecision {
    match action {
        crate::FirewallAction::Pass => FirewallDecision::Pass,
        crate::FirewallAction::Deny => FirewallDecision::Deny { rule_id, source },
    }
}

fn default_decision(
    snapshot: &crate::FirewallSnapshot,
    source: crate::FirewallDecisionSource,
) -> FirewallDecision {
    action_decision(
        snapshot
            .default_action
            .unwrap_or(crate::FirewallAction::Pass),
        None,
        source,
    )
}

fn domain_matches(candidate: &str, configured: &str, wildcard: bool, include_apex: bool) -> bool {
    let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
    if wildcard {
        (include_apex && candidate == configured)
            || (candidate != configured && candidate.ends_with(&format!(".{configured}")))
    } else {
        candidate == configured
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(snapshot: crate::FirewallSnapshot) -> FirewallPlugin {
        let version = snapshot.version;
        let (audit, _receiver) = sync_channel(1);
        FirewallPlugin {
            snapshot: Arc::new(ArcSwapOption::from(Some(Arc::new(snapshot)))),
            current_version: Arc::new(AtomicU64::new(version)),
            audit: Some(audit),
            dropped_events: Arc::new(AtomicU64::new(0)),
        }
    }

    fn snapshot(default_action: Option<crate::FirewallAction>) -> crate::FirewallSnapshot {
        crate::FirewallSnapshot {
            version: 9,
            default_action,
            error_action: default_action.unwrap_or(crate::FirewallAction::Pass),
            rules: vec![crate::FirewallSnapshotRule {
                id: "deny-private".into(),
                action: crate::FirewallAction::Deny,
                endpoints: vec![crate::FirewallEndpoint {
                    target: crate::FirewallRuleTarget::Network("10.0.0.0/8".parse().unwrap()),
                    port: Some(443),
                }],
            }],
        }
    }

    #[test]
    fn connect_matches_ip_cidr_and_port() {
        let plugin = plugin(snapshot(None));
        let target = crate::FirewallConnectTarget {
            hostname: None,
            ip: "10.1.2.3".parse().unwrap(),
            port: 443,
            bypass: false,
        };
        assert!(matches!(
            plugin.evaluate_connect(Some(&target)),
            FirewallDecision::Deny { .. }
        ));
        let target = crate::FirewallConnectTarget { port: 80, ..target };
        assert_eq!(
            plugin.evaluate_connect(Some(&target)),
            FirewallDecision::Pass
        );
    }

    #[test]
    fn domain_port_rule_defers_dns_and_matches_the_recorded_connect_target() {
        let plugin = plugin(crate::FirewallSnapshot {
            version: 1,
            default_action: None,
            error_action: crate::FirewallAction::Pass,
            rules: vec![crate::FirewallSnapshotRule {
                id: "domain-port".into(),
                action: crate::FirewallAction::Deny,
                endpoints: vec![crate::FirewallEndpoint {
                    target: crate::FirewallRuleTarget::Domain(crate::FirewallDomainTarget {
                        host: "example.com".into(),
                        wildcard: true,
                        include_apex: false,
                    }),
                    port: Some(443),
                }],
            }],
        });
        assert_eq!(
            plugin.evaluate_dns("api.example.com"),
            FirewallDecision::Pass
        );
        let target = crate::FirewallConnectTarget {
            hostname: Some("api.example.com".into()),
            ip: "198.18.0.1".parse().unwrap(),
            port: 443,
            bypass: false,
        };
        assert!(matches!(
            plugin.evaluate_connect(Some(&target)),
            FirewallDecision::Deny { .. }
        ));
    }

    #[test]
    fn endpoints_do_not_cross_match_targets_and_ports() {
        let plugin = plugin(crate::FirewallSnapshot {
            version: 1,
            default_action: None,
            error_action: crate::FirewallAction::Pass,
            rules: vec![crate::FirewallSnapshotRule {
                id: "bound-endpoints".into(),
                action: crate::FirewallAction::Deny,
                endpoints: vec![
                    crate::FirewallEndpoint {
                        target: crate::FirewallRuleTarget::Domain(crate::FirewallDomainTarget {
                            host: "one.example".into(),
                            wildcard: false,
                            include_apex: false,
                        }),
                        port: Some(443),
                    },
                    crate::FirewallEndpoint {
                        target: crate::FirewallRuleTarget::Domain(crate::FirewallDomainTarget {
                            host: "two.example".into(),
                            wildcard: false,
                            include_apex: false,
                        }),
                        port: Some(80),
                    },
                ],
            }],
        });
        let target = crate::FirewallConnectTarget {
            hostname: Some("one.example".into()),
            ip: "198.18.0.1".parse().unwrap(),
            port: 80,
            bypass: false,
        };
        assert_eq!(
            plugin.evaluate_connect(Some(&target)),
            FirewallDecision::Pass
        );
    }

    #[test]
    fn proxy_endpoint_bypasses_default_deny() {
        let plugin = plugin(snapshot(Some(crate::FirewallAction::Deny)));
        let target = crate::FirewallConnectTarget {
            hostname: None,
            ip: "127.0.0.1".parse().unwrap(),
            port: 18444,
            bypass: true,
        };
        assert_eq!(
            plugin.evaluate_connect(Some(&target)),
            FirewallDecision::Pass
        );
    }

    #[test]
    fn wildcard_domain_rules_include_subdomains_but_not_apex() {
        let plugin = plugin(crate::FirewallSnapshot {
            version: 1,
            default_action: None,
            error_action: crate::FirewallAction::Pass,
            rules: vec![crate::FirewallSnapshotRule {
                id: "domain".into(),
                action: crate::FirewallAction::Deny,
                endpoints: vec![crate::FirewallEndpoint {
                    target: crate::FirewallRuleTarget::Domain(crate::FirewallDomainTarget {
                        host: "example.com".into(),
                        wildcard: true,
                        include_apex: false,
                    }),
                    port: None,
                }],
            }],
        });
        assert!(matches!(
            plugin.evaluate_dns("Api.Example.com."),
            FirewallDecision::Deny { .. }
        ));
        assert_eq!(plugin.evaluate_dns("example.com"), FirewallDecision::Pass);
    }

    #[test]
    fn exact_domain_rules_exclude_subdomains() {
        let plugin = plugin(crate::FirewallSnapshot {
            version: 1,
            default_action: None,
            error_action: crate::FirewallAction::Pass,
            rules: vec![crate::FirewallSnapshotRule {
                id: "domain".into(),
                action: crate::FirewallAction::Deny,
                endpoints: vec![crate::FirewallEndpoint {
                    target: crate::FirewallRuleTarget::Domain(crate::FirewallDomainTarget {
                        host: "example.com".into(),
                        wildcard: false,
                        include_apex: false,
                    }),
                    port: None,
                }],
            }],
        });
        assert!(matches!(
            plugin.evaluate_dns("Example.com."),
            FirewallDecision::Deny { .. }
        ));
        assert_eq!(
            plugin.evaluate_dns("api.example.com"),
            FirewallDecision::Pass
        );
    }

    #[test]
    fn legacy_domain_wire_keeps_apex_and_subdomain_matching() {
        let target: crate::FirewallRuleTarget =
            serde_json::from_str(r#"{"kind":"domain","value":"example.com"}"#).unwrap();
        let plugin = plugin(crate::FirewallSnapshot {
            version: 1,
            default_action: None,
            error_action: crate::FirewallAction::Pass,
            rules: vec![crate::FirewallSnapshotRule {
                id: "legacy-domain".into(),
                action: crate::FirewallAction::Deny,
                endpoints: vec![crate::FirewallEndpoint { target, port: None }],
            }],
        });

        for hostname in ["example.com", "api.example.com", "a.b.example.com"] {
            assert!(matches!(
                plugin.evaluate_dns(hostname),
                FirewallDecision::Deny { .. }
            ));
        }
        let target = crate::FirewallConnectTarget {
            hostname: Some("api.example.com".into()),
            ip: "198.18.0.1".parse().unwrap(),
            port: 443,
            bypass: false,
        };
        assert!(matches!(
            plugin.evaluate_connect(Some(&target)),
            FirewallDecision::Deny { .. }
        ));
    }

    #[test]
    fn missing_snapshot_and_missing_default_pass() {
        let (audit, _receiver) = sync_channel(1);
        let missing = FirewallPlugin {
            snapshot: Arc::new(ArcSwapOption::empty()),
            current_version: Arc::new(AtomicU64::new(0)),
            audit: Some(audit),
            dropped_events: Arc::new(AtomicU64::new(0)),
        };
        assert_eq!(missing.evaluate_dns("example.com"), FirewallDecision::Pass);
        let configured = plugin(snapshot(None));
        assert_eq!(
            configured.evaluate_connect(None),
            FirewallDecision::ErrorPass
        );
        assert_eq!(configured.failure_mode(), HookFailureMode::FailOpen);
    }

    #[test]
    fn default_deny_controls_failure_mode_and_invalid_target() {
        let configured = plugin(snapshot(Some(crate::FirewallAction::Deny)));
        assert_eq!(configured.failure_mode(), HookFailureMode::FailClosed);
        assert!(matches!(
            configured.evaluate_connect(None),
            FirewallDecision::Deny {
                source: crate::FirewallDecisionSource::Error,
                ..
            }
        ));
    }

    #[test]
    fn refresh_replaces_rules_and_default_failure_mode() {
        let configured = plugin(snapshot(None));
        assert_eq!(configured.failure_mode(), HookFailureMode::FailOpen);
        apply_refresh(
            &configured.snapshot,
            &configured.current_version,
            crate::FirewallRefresh {
                version: 10,
                changed: true,
                firewall: Some(snapshot(Some(crate::FirewallAction::Deny))),
            },
        );
        assert_eq!(configured.current_version.load(Ordering::Acquire), 10);
        assert_eq!(configured.failure_mode(), HookFailureMode::FailClosed);
        assert!(matches!(
            configured.evaluate_connect(None),
            FirewallDecision::Deny { .. }
        ));

        apply_refresh(
            &configured.snapshot,
            &configured.current_version,
            crate::FirewallRefresh {
                version: 9,
                changed: true,
                firewall: None,
            },
        );
        assert_eq!(configured.current_version.load(Ordering::Acquire), 10);
        assert_eq!(configured.failure_mode(), HookFailureMode::FailClosed);

        apply_refresh(
            &configured.snapshot,
            &configured.current_version,
            crate::FirewallRefresh {
                version: 11,
                changed: true,
                firewall: None,
            },
        );
        assert_eq!(configured.failure_mode(), HookFailureMode::FailOpen);
        assert_eq!(configured.evaluate_connect(None), FirewallDecision::Pass);
    }

    #[test]
    fn full_audit_queue_drops_without_changing_the_deny_decision() {
        let (audit, _receiver) = sync_channel(1);
        let configured = snapshot(Some(crate::FirewallAction::Deny));
        let plugin = FirewallPlugin {
            snapshot: Arc::new(ArcSwapOption::from(Some(Arc::new(configured.clone())))),
            current_version: Arc::new(AtomicU64::new(configured.version)),
            audit: Some(audit),
            dropped_events: Arc::new(AtomicU64::new(0)),
        };
        assert!(plugin.report_decision(
            FirewallDecision::Deny {
                rule_id: None,
                source: crate::FirewallDecisionSource::Default,
            },
            crate::FirewallAuditStage::Dns,
            Some("one.example".into()),
            None,
            None,
        ));
        assert!(plugin.report_decision(
            FirewallDecision::Deny {
                rule_id: None,
                source: crate::FirewallDecisionSource::Default,
            },
            crate::FirewallAuditStage::Dns,
            Some("two.example".into()),
            None,
            None,
        ));
        assert_eq!(plugin.dropped_events.load(Ordering::Relaxed), 1);
    }
}
