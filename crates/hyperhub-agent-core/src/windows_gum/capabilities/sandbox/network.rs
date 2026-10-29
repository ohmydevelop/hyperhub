use crate::hook_runtime::{
    AgentHookPlugin, CallbackCategory, HookDecision, HookError, HookFailureMode,
};
use crate::snapshot::Snapshot;
use crate::windows_gum::runtime::PluginRegistrar;
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
    snapshot: Arc<Snapshot<crate::FirewallSnapshot>>,
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
        let snapshot = Arc::new(Snapshot::from(initial));
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
        let worker = crate::attachment::resident_background_enter();
        let audit = match std::thread::Builder::new()
            .name("hyperhub-firewall-runtime".into())
            .spawn(move || {
                crate::engine_call::background(|| {
                    let _worker = worker;
                    let mut reported_drops = 0;
                    let mut last_refresh = Instant::now() - FIREWALL_REFRESH_INTERVAL;
                    loop {
                        let dormant = crate::attachment::stopping_background();
                        let timeout = if dormant {
                            Duration::from_millis(100)
                        } else {
                            FIREWALL_REFRESH_INTERVAL
                                .saturating_sub(last_refresh.elapsed())
                                .min(Duration::from_millis(100))
                        };
                        match receiver.recv_timeout(timeout) {
                            Ok(event) => {
                                if crate::attachment::stopping_background()
                                    || crate::report_firewall_audit(&event).is_err()
                                {
                                    report_failures.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(RecvTimeoutError::Timeout) => {}
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                        if crate::attachment::stopping_background() {
                            continue;
                        }
                        if last_refresh.elapsed() >= FIREWALL_REFRESH_INTERVAL {
                            let version = worker_version.load(Ordering::Acquire);
                            if let Ok(refresh) = crate::refresh_firewall(version) {
                                apply_refresh(&worker_snapshot, &worker_version, refresh);
                            }
                            last_refresh = Instant::now();
                        }
                        let dropped = report_failures.load(Ordering::Relaxed);
                        if dropped != reported_drops && crate::attachment::legacy_debug() {
                            eprintln!("hyperhub-agent: firewall audit dropped_or_failed={dropped}");
                            reported_drops = dropped;
                        }
                    }
                })
            }) {
            Ok(_) => Some(sender),
            Err(error) => {
                if crate::attachment::legacy_debug() {
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

    fn current_snapshot(&self) -> Option<Arc<crate::FirewallSnapshot>> {
        if crate::attachment::managed() {
            crate::firewall_snapshot()
        } else {
            self.snapshot.load_full()
        }
    }
    #[cfg(test)]
    fn failure_mode(&self) -> HookFailureMode {
        if self
            .current_snapshot()
            .as_deref()
            .is_some_and(|snapshot| snapshot.error_action == crate::FirewallAction::Deny)
        {
            HookFailureMode::FailClosed
        } else {
            HookFailureMode::FailOpen
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

    fn with_reader(
        &self,
        snapshot: Option<&crate::FirewallSnapshot>,
        call: impl FnOnce() -> FirewallDecision,
    ) -> FirewallDecision {
        catch_unwind(AssertUnwindSafe(call)).unwrap_or_else(|_| {
            self.error_decision(
                snapshot.map_or(crate::FirewallAction::Pass, |value| value.error_action),
            )
        })
    }
    fn evaluate_dns_reader(
        &self,
        snapshot: Option<&crate::FirewallSnapshot>,
        hostname: &str,
    ) -> FirewallDecision {
        self.with_reader(snapshot, || self.evaluate_dns_snapshot(snapshot, hostname))
    }
    fn evaluate_connect_reader(
        &self,
        snapshot: Option<&crate::FirewallSnapshot>,
        target: Option<&crate::FirewallConnectTarget>,
    ) -> FirewallDecision {
        self.with_reader(snapshot, || {
            self.evaluate_connect_snapshot(snapshot, target)
        })
    }
    #[cfg(test)]
    fn evaluate_dns(&self, hostname: &str) -> FirewallDecision {
        self.evaluate_dns_snapshot(self.current_snapshot().as_deref(), hostname)
    }
    #[cfg(test)]
    fn evaluate_connect(&self, target: Option<&crate::FirewallConnectTarget>) -> FirewallDecision {
        self.evaluate_connect_snapshot(self.current_snapshot().as_deref(), target)
    }
    fn evaluate_dns_snapshot(
        &self,
        snapshot: Option<&crate::FirewallSnapshot>,
        hostname: &str,
    ) -> FirewallDecision {
        if !crate::attachment::enforcing() {
            return FirewallDecision::Pass;
        }
        let Some(snapshot) = snapshot else {
            return FirewallDecision::Pass;
        };
        match crate::firewall_dns_decision(snapshot, hostname) {
            Ok(decision) => action_decision(
                if decision.action == "pass" {
                    crate::FirewallAction::Pass
                } else {
                    crate::FirewallAction::Deny
                },
                decision.rule_id,
                if decision.source == "rule" {
                    crate::FirewallDecisionSource::Rule
                } else {
                    crate::FirewallDecisionSource::Default
                },
            ),
            Err(_) => self.error_decision(snapshot.error_action),
        }
    }
    fn evaluate_connect_snapshot(
        &self,
        snapshot: Option<&crate::FirewallSnapshot>,
        target: Option<&crate::FirewallConnectTarget>,
    ) -> FirewallDecision {
        if !crate::attachment::enforcing() {
            return FirewallDecision::Pass;
        }
        let Some(snapshot) = snapshot else {
            return FirewallDecision::Pass;
        };
        let Some(target) = target else {
            return self.error_decision(snapshot.error_action);
        };
        let (action, rule_id, source) = crate::firewall_decision(snapshot, target);
        if source == crate::FirewallDecisionSource::Error {
            self.error_decision(action)
        } else {
            action_decision(action, rule_id, source)
        }
    }
    #[cfg(test)]
    fn report_decision(
        &self,
        decision: FirewallDecision,
        stage: crate::FirewallAuditStage,
        hostname: Option<String>,
        ip: Option<IpAddr>,
        port: Option<u16>,
    ) -> bool {
        let version = self.current_snapshot().as_deref().map_or_else(
            || self.current_version.load(Ordering::Acquire),
            |snapshot| snapshot.version,
        );
        self.report_decision_at_version(decision, stage, hostname, ip, port, version)
    }
    fn report_decision_at_version(
        &self,
        decision: FirewallDecision,
        stage: crate::FirewallAuditStage,
        hostname: Option<String>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        snapshot_version: u64,
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
    snapshot: &Snapshot<crate::FirewallSnapshot>,
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
            let snapshot = dns_plugin.current_snapshot();
            if snapshot
                .as_deref()
                .is_some_and(|snapshot| snapshot.error_action == crate::FirewallAction::Deny)
            {
                context.denied_error = Some(WSAHOST_NOT_FOUND);
            }
            let decision = dns_plugin.evaluate_dns_reader(snapshot.as_deref(), &context.hostname);
            if dns_plugin.report_decision_at_version(
                decision,
                crate::FirewallAuditStage::Dns,
                Some(context.hostname.clone()),
                None,
                None,
                snapshot.as_deref().map_or(0, |snapshot| snapshot.version),
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
            let snapshot = connect_plugin.current_snapshot();
            if snapshot
                .as_deref()
                .is_some_and(|snapshot| snapshot.error_action == crate::FirewallAction::Deny)
            {
                context.denied_error = Some(WSAEACCES);
            }
            let decision =
                connect_plugin.evaluate_connect_reader(snapshot.as_deref(), context.source());
            let target = context.source().cloned();
            if connect_plugin.report_decision_at_version(
                decision,
                crate::FirewallAuditStage::Connect,
                target.as_ref().and_then(|target| target.hostname.clone()),
                target.as_ref().map(|target| target.ip),
                target.as_ref().map(|target| target.port),
                snapshot.as_deref().map_or(0, |snapshot| snapshot.version),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(snapshot: crate::FirewallSnapshot) -> FirewallPlugin {
        let version = snapshot.version;
        let (audit, _receiver) = sync_channel(1);
        FirewallPlugin {
            snapshot: Arc::new(Snapshot::from(Some(Arc::new(snapshot)))),
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
                protection: None,
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
                protection: None,
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
                protection: None,
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
                protection: None,
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
                protection: None,
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
                protection: None,
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
            snapshot: Arc::new(Snapshot::empty()),
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
            snapshot: Arc::new(Snapshot::from(Some(Arc::new(configured.clone())))),
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
    #[test]
    fn a_policy_reader_keeps_its_failure_action_and_audit_version_after_publication() {
        let (audit, receiver) = sync_channel(1);
        let mut initial = snapshot(Some(crate::FirewallAction::Pass));
        initial.version = 41;
        let configured = FirewallPlugin {
            snapshot: Arc::new(Snapshot::from(Some(Arc::new(initial)))),
            current_version: Arc::new(AtomicU64::new(41)),
            audit: Some(audit),
            dropped_events: Arc::new(AtomicU64::new(0)),
        };
        let reader = configured.current_snapshot().unwrap();
        let mut next = snapshot(Some(crate::FirewallAction::Deny));
        next.version = 42;
        configured.snapshot.store(Some(Arc::new(next)));
        let fallback = configured.with_reader(Some(&reader), || {
            panic!("intentional policy callback failure")
        });
        assert_eq!(fallback, FirewallDecision::ErrorPass);
        assert!(!configured.report_decision_at_version(
            fallback,
            crate::FirewallAuditStage::Dns,
            Some("fixture.test".into()),
            None,
            None,
            reader.version
        ));
        let event = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(event.snapshot_version, 41);
        assert_eq!(event.decision, crate::FirewallAction::Pass);
        assert_eq!(configured.failure_mode(), HookFailureMode::FailClosed);
        assert!(matches!(
            configured.evaluate_connect(None),
            FirewallDecision::Deny {
                source: crate::FirewallDecisionSource::Error,
                ..
            }
        ));
    }
}
