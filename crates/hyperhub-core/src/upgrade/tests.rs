use super::*;
use crate::engine_hosts::Registration;
use hyperhub_engine::{
    host::{self, Acknowledgement, Backend},
    management::{Command, Reply},
};
use hyperhub_runtime::{Engine, Lease, Manifest, Runtime, Settings};
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct Root(std::path::PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hh-rollout-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct TestEngine {
    manifest: Manifest,
    value: u8,
    healthy: Arc<AtomicBool>,
}
impl Engine for TestEngine {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn health(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }
    fn invoke(&self, _: &Lease, _: u32, _: &[u8], output: &mut [u8]) -> Result<usize, i32> {
        output[0] = self.value;
        Ok(1)
    }
}
fn manifest(version: &str) -> Manifest {
    hyperhub_engine::manifest(version.as_bytes(), version)
}
fn value(lease: &Lease) -> u8 {
    let mut bytes = [0];
    lease.invoke(0, &[], &mut bytes).unwrap();
    bytes[0]
}
struct Actor {
    runtime: Arc<Runtime>,
    registration: Option<Registration>,
    root_start: u64,
    host_start: u64,
    session: String,
    native_base: String,
    number: u32,
    log: Vec<String>,
    fail_commit: bool,
    discard_ack: bool,
    candidate_health: Arc<AtomicBool>,
}
impl Actor {
    fn new(registry: &EngineHosts, number: u32) -> Self {
        Self::new_in(registry, number, "unit")
    }
    fn new_in(registry: &EngineHosts, number: u32, session: &str) -> Self {
        let runtime = Arc::new(
            Runtime::new(
                Arc::new(TestEngine {
                    manifest: manifest("0"),
                    value: 0,
                    healthy: Arc::new(AtomicBool::new(true)),
                }),
                Settings {
                    health_window: Duration::ZERO,
                    ..Settings::default()
                },
            )
            .unwrap(),
        );
        let root_start = crate::session::process_start_time(std::process::id()).unwrap_or(1);
        let host_start =
            crate::session::process_start_time(std::process::id()).unwrap_or(root_start);
        let registration = registry
            .register(
                session.into(),
                String::new(),
                Backend::LinuxPtrace,
                std::process::id(),
                std::process::id(),
                u64::from(number),
                Some(root_start),
                Some(host_start),
                host::report(&runtime).unwrap(),
            )
            .unwrap();
        Self {
            runtime,
            registration: Some(registration),
            root_start,
            host_start,
            session: session.into(),
            native_base: String::new(),
            number,
            log: vec![],
            fail_commit: false,
            discard_ack: false,
            candidate_health: Arc::new(AtomicBool::new(true)),
        }
    }
    fn reconnect(&mut self, registry: &EngineHosts) {
        self.registration.take();
        self.registration = Some(
            registry
                .register(
                    self.session.clone(),
                    self.native_base.clone(),
                    Backend::LinuxPtrace,
                    std::process::id(),
                    std::process::id(),
                    u64::from(self.number),
                    Some(self.root_start),
                    Some(self.host_start),
                    host::report(&self.runtime).unwrap(),
                )
                .unwrap(),
        );
    }
    fn process(&mut self, registry: &EngineHosts, journal: &Path) {
        let Some(registration) = &mut self.registration else {
            return;
        };
        while let Ok(delivery) = registration.receiver.try_recv() {
            // Independent write-ahead oracle: read the actual stable file before
            // any simulated participant action. This is a state-machine test;
            // the separate native-target Suite verifies real module loading.
            let envelope: serde_json::Value =
                serde_json::from_slice(&fs::read(journal).unwrap()).unwrap();
            let book: serde_json::Value =
                serde_json::from_str(envelope["value"].as_str().unwrap()).unwrap();
            assert!(book["records"]
                .as_object()
                .unwrap()
                .values()
                .any(|record| record["participants"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["pending"]["request"]["request_id"].as_str()
                        == Some(&delivery.request_id))));
            registry
                .delivered(&registration.id, &delivery.request_id)
                .unwrap();
            let label = match &delivery.command {
                Command::Prepare { .. } => "prepare",
                Command::CommitHeld { .. } => "commit",
                Command::QueryTransaction { .. } => "query",
                Command::FinalizeObservation { .. } => "finalize",
                Command::Rollback { .. } => "rollback",
                _ => "other",
            };
            self.log.push(label.into());
            let reply = match delivery.command {
                Command::Prepare { id, manifest, .. } => {
                    let candidate = Arc::new(TestEngine {
                        manifest: manifest.clone(),
                        value: manifest.version.parse().unwrap(),
                        healthy: self.candidate_health.clone(),
                    });
                    match self.runtime.prepare(&id, &manifest, || Ok(candidate)) {
                        Ok(transaction) => Reply::Transaction { transaction },
                        Err(error) => Reply::Error {
                            message: error.to_string(),
                            code: "failed".into(),
                        },
                    }
                }
                Command::CommitHeld { .. } if self.fail_commit => Reply::Error {
                    message: "injected commit rejection".into(),
                    code: "failed".into(),
                },
                command => unsafe { hyperhub_engine::management::execute(&self.runtime, command) },
            };
            if self.discard_ack {
                self.discard_ack = false;
                continue;
            }
            registry
                .acknowledge(
                    &registration.id,
                    Acknowledgement {
                        request_id: delivery.request_id,
                        reply,
                        snapshot: host::report(&self.runtime).unwrap(),
                    },
                    false,
                )
                .unwrap();
        }
        self.runtime.observe().unwrap();
        registry
            .acknowledge(
                &registration.id,
                Acknowledgement {
                    request_id: "heartbeat".into(),
                    reply: Reply::Ok,
                    snapshot: host::report(&self.runtime).unwrap(),
                },
                true,
            )
            .unwrap();
    }
}
struct Rig {
    coordinator: Option<Coordinator>,
    registry: EngineHosts,
    actors: Vec<Actor>,
    root: Root,
}
impl Rig {
    fn new(count: u32) -> Self {
        let root = Root::new();
        let registry = EngineHosts::default();
        let actors = (1..=count).map(|n| Actor::new(&registry, n)).collect();
        let coordinator = Coordinator::open_with_limits(
            &root.0.join("store"),
            Zeroizing::new(vec![7; 32]),
            registry.clone(),
            Duration::from_secs(30),
            Duration::ZERO,
        )
        .unwrap();
        Self {
            coordinator: Some(coordinator),
            registry,
            actors,
            root,
        }
    }
    fn request(&self, action: Action) -> Request {
        Request {
            id: "group".into(),
            issued_at_ms: crate::session::unix_timestamp_ms(),
            action,
        }
    }
    fn submit(&self, action: Action) -> Record {
        self.coordinator
            .as_ref()
            .unwrap()
            .submit_sync(self.request(action))
            .unwrap()
    }
    fn prepare(&self) -> Action {
        Action::Prepare {
            manifest: manifest("1"),
            source: self.root.0.join("candidate"),
            cache: self.root.0.join("cache"),
            hosts: self
                .actors
                .iter()
                .map(|a| a.registration.as_ref().unwrap().id.clone())
                .collect(),
        }
    }
    fn phase(&self) -> Phase {
        self.coordinator
            .as_ref()
            .unwrap()
            .status(Some("group"))
            .records[0]
            .phase
    }
    fn tick(&mut self) {
        self.coordinator.as_ref().unwrap().tick().unwrap();
        for actor in &mut self.actors {
            actor.process(&self.registry, &self.root.0.join("store/journal.json"));
        }
    }
    fn until(&mut self, phase: Phase) {
        for _ in 0..100 {
            if self.phase() == phase {
                return;
            }
            self.tick();
        }
        panic!(
            "expected {phase:?}, got {:?}",
            self.coordinator.as_ref().unwrap().status(Some("group"))
        );
    }
    fn prepared(&mut self) {
        self.submit(self.prepare());
        self.until(Phase::Prepared);
    }
    fn committed(&mut self) {
        self.prepared();
        self.submit(Action::Commit);
        self.until(Phase::Committed);
    }
    fn reopen(&mut self) {
        self.coordinator.take();
        self.coordinator = Some(
            Coordinator::open_with_limits(
                &self.root.0.join("store"),
                Zeroizing::new(vec![7; 32]),
                self.registry.clone(),
                Duration::from_secs(30),
                Duration::ZERO,
            )
            .unwrap(),
        );
    }
}

#[test]
fn global_finalize_is_durable_and_old_leases_drain_without_closing_calls() {
    let mut rig = Rig::new(2);
    let old: Vec<_> = rig.actors.iter().map(|a| a.runtime.acquire()).collect();
    rig.committed();
    for actor in &rig.actors {
        assert!(actor.runtime.snapshot().unwrap().retired[0].rollback_reserved);
        assert_eq!(value(&actor.runtime.acquire()), 1);
    }
    let observed = rig.submit(Action::Observe).health_started_at_ms;
    rig.submit(Action::Observe);
    assert_eq!(
        rig.coordinator
            .as_ref()
            .unwrap()
            .status(Some("group"))
            .records[0]
            .health_started_at_ms,
        observed
    );
    rig.until(Phase::Finalizing);
    assert!(rig
        .actors
        .iter()
        .all(|a| !a.log.contains(&"finalize".into())));
    rig.until(Phase::Draining);
    for lease in &old {
        assert_eq!(value(lease), 0);
    }
    assert!(rig
        .actors
        .iter()
        .all(|a| a.runtime.snapshot().unwrap().retired[0].references == 1));
    drop(old);
    rig.until(Phase::Complete);
    assert!(rig
        .actors
        .iter()
        .all(|a| a.runtime.snapshot().unwrap().retired.is_empty()));
}

#[test]
fn partial_commit_failure_queries_uncertain_state_and_rolls_back_the_group() {
    let mut rig = Rig::new(2);
    rig.prepared();
    rig.actors[1].fail_commit = true;
    rig.submit(Action::Commit);
    rig.until(Phase::RolledBack);
    assert!(rig.actors.iter().all(|a| value(&a.runtime.acquire()) == 0));
    assert_eq!(
        rig.actors[0]
            .log
            .iter()
            .filter(|s| s.as_str() == "rollback")
            .count(),
        1
    );
    assert!(rig.actors[1].log.contains(&"query".into()));
}

#[test]
fn lost_commit_ack_and_recreated_coordinator_do_not_commit_twice() {
    let mut rig = Rig::new(1);
    rig.prepared();
    rig.actors[0].discard_ack = true;
    rig.submit(Action::Commit);
    rig.tick();
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 1);
    rig.actors[0].reconnect(&rig.registry);
    rig.reopen();
    rig.until(Phase::Committed);
    assert_eq!(
        rig.actors[0]
            .log
            .iter()
            .filter(|s| s.as_str() == "commit")
            .count(),
        1
    );
    assert!(rig.actors[0].log.contains(&"query".into()));
    assert!(rig.actors[0].runtime.snapshot().unwrap().retired[0].rollback_reserved);
    rig.submit(Action::Rollback {
        reason: "owner rollback after recovery".into(),
    });
    rig.until(Phase::RolledBack);
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 0);
}

#[test]
fn lost_finalize_ack_reconciles_the_irrevocable_decision_and_keeps_old_calls() {
    let mut rig = Rig::new(1);
    let old = rig.actors[0].runtime.acquire();
    rig.committed();
    rig.submit(Action::Observe);
    rig.until(Phase::Finalizing);
    rig.actors[0].discard_ack = true;
    rig.tick();
    assert!(!rig.actors[0].runtime.snapshot().unwrap().retired[0].rollback_reserved);
    rig.actors[0].reconnect(&rig.registry);
    rig.reopen();
    rig.until(Phase::Draining);
    assert_eq!(value(&old), 0);
    drop(old);
    rig.until(Phase::Complete);
}

#[test]
fn a_journal_write_failure_prevents_external_actions_and_requires_recovery() {
    let mut rig = Rig::new(1);
    let obstruction = rig.root.0.join("store/journal.json");
    fs::create_dir(&obstruction).unwrap();
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .submit_sync(rig.request(rig.prepare()))
        .is_err());
    assert!(rig.registry.commands().is_empty());
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .status(None)
        .error
        .is_some());
    fs::remove_dir(obstruction).unwrap();
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .submit_sync(rig.request(rig.prepare()))
        .is_err());
    rig.reopen();
    rig.prepared();
    rig.submit(Action::Abort);
    rig.until(Phase::Aborted);
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 0);
}

#[test]
fn a_failed_post_commit_journal_write_recovers_from_the_recorded_intent() {
    let mut rig = Rig::new(1);
    rig.prepared();
    rig.submit(Action::Commit);
    rig.tick();
    let journal = rig.root.0.join("store/journal.json");
    let backup = rig.root.0.join("store/saved.json");
    fs::rename(&journal, &backup).unwrap();
    fs::create_dir(&journal).unwrap();
    assert!(rig.coordinator.as_ref().unwrap().tick().is_err());
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 1);
    fs::remove_dir(&journal).unwrap();
    fs::rename(backup, journal).unwrap();
    rig.reopen();
    rig.until(Phase::Committed);
    assert_eq!(
        rig.actors[0]
            .log
            .iter()
            .filter(|s| s.as_str() == "commit")
            .count(),
        1
    );
}

#[test]
fn incompatible_prepare_and_repeated_ids_have_no_unintended_participant_action() {
    let mut rig = Rig::new(1);
    let mut action = rig.prepare();
    if let Action::Prepare { manifest, .. } = &mut action {
        manifest.state_schema += 1;
    }
    assert_eq!(rig.submit(action.clone()).phase, Phase::RequiresRestart);
    rig.submit(action);
    rig.tick();
    assert!(rig.registry.commands().is_empty());
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .submit_sync(rig.request(rig.prepare()))
        .is_err());
    let record = rig.coordinator.as_ref().unwrap().status(Some("group"));
    assert_eq!(record.records[0].phase, Phase::RequiresRestart);
}

#[test]
fn stale_health_reports_cannot_finalize_a_group() {
    let mut rig = Rig::new(1);
    let clock = Arc::new(AtomicU64::new(crate::session::unix_timestamp_ms()));
    let time = clock.clone();
    Arc::get_mut(&mut rig.coordinator.as_mut().unwrap().0)
        .unwrap()
        .now = Arc::new(move || time.load(Ordering::Acquire));
    rig.committed();
    rig.submit(Action::Observe);
    clock.fetch_add(5000, Ordering::AcqRel);
    rig.coordinator.as_ref().unwrap().tick().unwrap();
    assert_eq!(rig.phase(), Phase::Observing);
    assert!(rig.actors[0].runtime.snapshot().unwrap().retired[0].rollback_reserved);
}

#[test]
fn journal_authentication_lock_and_owner_purposes_are_enforced() {
    let mut rig = Rig::new(1);
    rig.prepared();
    assert!(Coordinator::open(
        &rig.root.0.join("store"),
        Zeroizing::new(vec![7; 32]),
        rig.registry.clone()
    )
    .is_err());
    rig.coordinator.take();
    assert!(Coordinator::open(
        &rig.root.0.join("store"),
        Zeroizing::new(vec![8; 32]),
        rig.registry.clone()
    )
    .is_err());
    let path = rig.root.0.join("store/journal.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    envelope["proof"][0] = serde_json::json!(envelope["proof"][0].as_u64().unwrap() ^ 1);
    let bytes = serde_json::to_vec(&envelope).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(Coordinator::open(
        &rig.root.0.join("store"),
        Zeroizing::new(vec![7; 32]),
        rig.registry.clone()
    )
    .is_err());
    assert_eq!(fs::read(path).unwrap(), bytes);
    let request = rig.request(Action::Commit);
    let proof = request.proof(&[7; 32]).unwrap();
    assert!(request.authenticate(&[7; 32], &proof));
    assert!(!request.authenticate(&[8; 32], &proof));
    let other = crate::engine_hosts::OwnerCommand {
        request_id: "group".into(),
        host_id: "host".into(),
        issued_at_ms: request.issued_at_ms,
        command: Command::Observe,
    };
    assert!(!request.authenticate(&[7; 32], &other.proof(&[7; 32]).unwrap()));
}

#[test]
fn a_participant_health_failure_compensates_every_committed_host() {
    let mut rig = Rig::new(2);
    rig.committed();
    rig.submit(Action::Observe);
    rig.actors[1]
        .candidate_health
        .store(false, Ordering::Release);
    // A Host performs its own health check before reporting the failure. The
    // coordinator must restore the other Host too, including after recovery.
    rig.actors[1].process(&rig.registry, &rig.root.0.join("store/journal.json"));
    rig.reopen();
    rig.until(Phase::RolledBack);
    assert!(rig.actors.iter().all(|a| value(&a.runtime.acquire()) == 0));
}

#[test]
fn a_new_upgrade_can_finish_while_an_older_stream_remains_pinned() {
    let mut rig = Rig::new(1);
    let old = rig.actors[0].runtime.acquire();
    rig.committed();
    rig.submit(Action::Observe);
    rig.until(Phase::Draining);
    let middle = rig.actors[0].runtime.acquire();
    let mut action = rig.prepare();
    if let Action::Prepare {
        manifest: candidate,
        ..
    } = &mut action
    {
        *candidate = manifest("2");
    }
    let send = |rig: &Rig, action| {
        let mut request = rig.request(action);
        request.id = "next".into();
        rig.coordinator
            .as_ref()
            .unwrap()
            .submit_sync(request)
            .unwrap()
    };
    send(&rig, action);
    let wait = |rig: &mut Rig, expected| {
        for _ in 0..100 {
            if rig
                .coordinator
                .as_ref()
                .unwrap()
                .status(Some("next"))
                .records[0]
                .phase
                == expected
            {
                return;
            }
            rig.tick();
        }
        panic!("second transaction did not reach {expected:?}");
    };
    wait(&mut rig, Phase::Prepared);
    send(&rig, Action::Commit);
    wait(&mut rig, Phase::Committed);
    send(&rig, Action::Observe);
    wait(&mut rig, Phase::Draining);
    assert_eq!(value(&old), 0);
    assert_eq!(value(&middle), 1);
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 2);
    rig.reopen();
    rig.until(Phase::Draining);
    drop(middle);
    rig.tick();
    assert_eq!(rig.phase(), Phase::Draining);
    drop(old);
    rig.until(Phase::Complete);
    wait(&mut rig, Phase::Complete);
}

#[test]
fn status_redacts_artifact_paths_and_does_not_wait_for_storage() {
    let mut rig = Rig::new(1);
    rig.prepared();
    let coordinator = rig.coordinator.as_ref().unwrap();
    let _storage_busy = coordinator.0.state.lock().unwrap();
    let status = serde_json::to_value(coordinator.status(Some("group"))).unwrap();
    let record = &status["records"][0];
    assert!(record.get("source").is_none());
    assert!(record.get("cache").is_none());
    assert!(record["participants"][0].get("pending").is_none());
    assert!(coordinator.busy());
}

#[test]
fn reconnected_host_with_a_different_process_incarnation_is_not_selected() {
    let mut rig = Rig::new(1);
    rig.prepared();
    let before = rig.actors[0].log.len();
    rig.actors[0].host_start += 1;
    rig.actors[0].reconnect(&rig.registry);
    rig.submit(Action::Commit);
    for _ in 0..4 {
        rig.tick();
    }
    assert_eq!(rig.phase(), Phase::Switching);
    assert_eq!(rig.actors[0].log.len(), before);
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 0);
    // The original process can reconnect and complete; never retarget by PID.
    rig.actors[0].host_start -= 1;
    rig.actors[0].reconnect(&rig.registry);
    rig.until(Phase::Committed);
}

#[tokio::test]
async fn cancelled_runner_can_restart_and_recover_persisted_work() {
    let rig = Rig::new(1);
    let coordinator = rig.coordinator.as_ref().unwrap();
    rig.submit(rig.prepare());
    let first = coordinator.spawn().unwrap();
    assert!(coordinator.spawn().is_none());
    coordinator.stop_runner();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(!coordinator.runner_running());
    coordinator
        .submit(rig.request(Action::Recover))
        .await
        .unwrap();
    let second = coordinator.spawn().unwrap();
    assert!(coordinator.runner_running());
    coordinator.stop_runner();
    assert!(second.await.unwrap_err().is_cancelled());
}

#[test]
fn bounded_summary_retains_the_active_transaction_ahead_of_old_ids() {
    let rig = Rig::new(1);
    for number in 0..40 {
        let mut action = rig.prepare();
        if let Action::Prepare { manifest, .. } = &mut action {
            manifest.state_schema += 1;
        }
        let mut request = rig.request(action);
        request.id = format!("z-rejected-{number:02}");
        rig.coordinator
            .as_ref()
            .unwrap()
            .submit_sync(request)
            .unwrap();
    }
    rig.submit(rig.prepare());
    let status = rig.coordinator.as_ref().unwrap().status(None);
    assert_eq!(status.records.len(), 32);
    assert_eq!(status.records_omitted, 9);
    assert_eq!(status.records[0].id, "group");
    assert_eq!(status.records[0].phase, Phase::Preparing);
    assert_eq!(status.records[0].participants_omitted, 1);
}

#[path = "admission_tests.rs"]
mod admission_tests;
