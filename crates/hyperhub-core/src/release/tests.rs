use super::*;
use crate::engine_hosts::HostStatus;
use crate::session::{SessionRegistry, SessionSnapshot};
use hyperhub_engine::host::Backend;

fn sessions() -> Vec<SessionSnapshot> {
    let registry = SessionRegistry::default();
    let challenge = registry
        .begin_auth("unit-session".into(), "release-unit".into(), [2; 32])
        .unwrap();
    let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
    let session = registry
        .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(30))
        .unwrap();
    assert!(registry.activate("unit-session", &session.token, std::process::id()));
    registry.snapshot()
}
fn host(session: &str, backend: Backend) -> HostStatus {
    let pid = std::process::id();
    HostStatus {
        native_base_sha256: String::new(),
        session_id: session.into(),
        host_id: "unit-host".into(),
        backend,
        host_pid: pid,
        host_start_time: crate::session::process_start_time(pid),
        root_pid: pid,
        root_start_time: crate::session::process_start_time(pid),
        member_instance: 1,
        online: true,
        last_seen_ms: crate::session::unix_timestamp_ms(),
        snapshot: hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
    }
}

#[test]
fn a_starting_member_is_missing_until_its_own_host_enrolls() {
    let sessions = sessions();
    assert_eq!(
        uncovered_processes(&sessions, &[]),
        vec![std::process::id()]
    );
    let own = host("unit-session", Backend::LinuxGum);
    assert!(uncovered_processes(&sessions, &[own]).is_empty());
}

#[test]
fn another_session_or_a_disconnected_host_cannot_cover_a_member() {
    let sessions = sessions();
    let other = host("other-session", Backend::LinuxGum);
    assert_eq!(
        uncovered_processes(&sessions, &[other]),
        vec![std::process::id()]
    );
    let mut disconnected = host("unit-session", Backend::LinuxGum);
    disconnected.online = false;
    assert_eq!(
        uncovered_processes(&sessions, &[disconnected]),
        vec![std::process::id()]
    );
}

#[test]
fn ptrace_coverage_uses_the_authenticated_session_not_the_old_root_pid() {
    let sessions = sessions();
    let mut tracer = host("unit-session", Backend::LinuxPtrace);
    tracer.root_pid = u32::MAX;
    assert!(uncovered_processes(&sessions, &[tracer.clone()]).is_empty());
    tracer.backend = Backend::LinuxGum;
    assert_eq!(
        uncovered_processes(&sessions, &[tracer]),
        vec![std::process::id()]
    );
}

#[test]
fn a_late_unknown_member_remains_visible_to_health_admission() {
    let mut sessions = sessions();
    sessions[0].processes[0].hook_status = "unknown".into();
    assert_eq!(
        uncovered_processes(&sessions, &[]),
        vec![std::process::id()]
    );
    sessions[0].processes[0].hook_status = "fork_pending".into();
    assert!(uncovered_processes(&sessions, &[]).is_empty());
    for bypass in ["unhook", "bypass"] {
        sessions[0].processes[0].hook_status = bypass.into();
        assert!(uncovered_processes(&sessions, &[]).is_empty());
    }
}

struct ModelRoot(std::path::PathBuf);
impl Drop for ModelRoot {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("release model retained at {}", self.0.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

async fn model() -> (Coordinator, ModelRoot, super::super::Plan) {
    use super::super::{Base, Bundle, Plan};
    use crate::{config::Config, socks::SocksService};
    let root = ModelRoot(std::env::temp_dir().join(format!(
        "hh-release-model-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let worker = std::env::var_os("HH_FORWARD_WORKER_FIXTURE")
        .map(PathBuf::from)
        .expect("set HH_FORWARD_WORKER_FIXTURE to the built source fixture or final CLI");
    let sessions = crate::session::SessionRegistry::default();
    let hosts = EngineHosts::default();
    let mut config = Config::default();
    config.audit.log = Some(root.0.join("audit.jsonl"));
    let service = SocksService::new_with_debug_output(
        Arc::new(config),
        sessions.clone(),
        Vec::new(),
        false,
        None,
        b"release-model-isolated-master",
    )
    .unwrap();
    let service = tokio::task::spawn_blocking(move || service.with_forward_workers(worker))
        .await
        .unwrap()
        .unwrap();
    let workers = service.forward_workers().unwrap();
    let engine = upgrade::Coordinator::open_with_limits(
        &root.0.join("engine"),
        Zeroizing::new(vec![7; 32]),
        hosts.clone(),
        Duration::from_secs(30),
        Duration::ZERO,
    )
    .unwrap();
    let target = root.0.join("installed");
    std::fs::write(&target, b"original-private-installed-image").unwrap();
    let (worker_sha256, worker_size) = installer::digest(&target).unwrap();
    let source = root.0.join("module");
    std::fs::write(&source, b"unit-model-manifest-only").unwrap();
    let plan = Plan {
        bundle: Bundle {
            format: 1,
            version: env!("CARGO_PKG_VERSION").into(),
            target: hyperhub_engine::TARGET.into(),
            base: Base::resident(),
            engine: hyperhub_engine::manifest(
                b"unit-model-manifest-only",
                env!("CARGO_PKG_VERSION"),
            ),
            engine_file: super::super::engine_name().into(),
            worker_sha256: worker_sha256.clone(),
            worker_size,
        },
        executable: target.clone(),
        engine: source,
        cache: root.0.join("cache"),
        target: target.clone(),
        expected_target_sha256: worker_sha256,
    };
    let coordinator = Coordinator::open(
        &root.0.join("release"),
        Zeroizing::new(vec![7; 32]),
        engine,
        hosts,
        workers,
        &target,
        sessions,
    )
    .unwrap();
    (coordinator, root, plan)
}
fn message(id: &str, action: Action) -> Request {
    Request {
        id: id.into(),
        issued_at_ms: crate::session::unix_timestamp_ms(),
        action,
    }
}
fn stored(coordinator: &Coordinator, id: &str) -> Record {
    coordinator.0.state.lock().unwrap().book.records[id].clone()
}
fn update(coordinator: &Coordinator, record: Record) {
    coordinator.save_record(record).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a built forwarding worker fixture; run by the platform Suite"]
async fn durable_release_recovery_status_installation_and_missing_host_boundaries() {
    let (coordinator, root, plan) = model().await;
    let id = "durable-model";
    coordinator
        .submit_sync(message(
            id,
            Action::Prepare {
                plan: plan.clone(),
                auto_commit: false,
            },
        ))
        .unwrap();
    assert!(coordinator
        .submit_sync(message(
            id,
            Action::Prepare {
                plan: plan.clone(),
                auto_commit: true,
            }
        ))
        .unwrap_err()
        .to_string()
        .contains("conflict"));
    let mut record = stored(&coordinator, id);
    let workers = coordinator.0.workers.status();
    assert!(reject_older_release(&Book::default(), &plan, &workers).is_ok());
    let mut lower = plan.clone();
    lower.bundle.version = "0.0.1".into();
    lower.bundle.engine.version = "0.0.1".into();
    assert!(reject_older_release(&Book::default(), &lower, &workers).is_err());
    let mut active_newer = workers.clone();
    active_newer
        .workers
        .iter_mut()
        .find(|worker| worker.generation == active_newer.active_generation)
        .unwrap()
        .version = "9.0.0".into();
    assert!(reject_older_release(&Book::default(), &plan, &active_newer).is_err());
    let mut history = coordinator.0.state.lock().unwrap().book.clone();
    history.records.get_mut(id).unwrap().plan.bundle.version = "9.0.0".into();
    // An uncommitted abandoned plan cannot raise the global stable floor.
    assert!(reject_older_release(&history, &plan, &workers).is_ok());
    history.records.get_mut(id).unwrap().finalize_decided = true;
    assert!(reject_older_release(&history, &plan, &workers).is_err());
    // Model an idle durable Prepared checkpoint. The real runner is started,
    // stopped, then restarted by Recover; native switching is tested in release_live.
    record.phase = Phase::Prepared;
    update(&coordinator, record);
    let initial_worker = coordinator.0.workers.status().active_generation;
    let before_tick = coordinator.status(Some(id)).records[0].updated_at_ms;
    coordinator.spawn();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while coordinator.status(Some(id)).records[0].updated_at_ms <= before_tick {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Release runner never ticked"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    coordinator.stop_runner();
    while coordinator
        .0
        .runner
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|runner| !runner.is_finished())
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Release runner did not stop"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    coordinator.submit_sync(message(id, Action::Abort)).unwrap();
    coordinator
        .submit(message(id, Action::Recover))
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while coordinator.status(Some(id)).records[0].phase != Phase::RolledBack {
        assert!(
            tokio::time::Instant::now() < deadline,
            "recovered Release runner did not compensate"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        coordinator.0.workers.status().active_generation,
        initial_worker
    );
    assert_eq!(
        installer::digest(&plan.target).unwrap().0,
        plan.expected_target_sha256
    );
    coordinator.stop_runner();
    while coordinator
        .0
        .runner
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|runner| !runner.is_finished())
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "recovered Release runner did not stop"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut record = stored(&coordinator, id);
    record.finalize_decided = true;
    record.phase = Phase::Installing;
    record.helper_started_at_ms = Some(100);
    record.helper_attempt = 1;
    update(&coordinator, record.clone());
    assert!(coordinator
        .submit_sync(message(id, Action::Abort))
        .unwrap_err()
        .to_string()
        .contains("irreversible"));
    coordinator.install(&mut record, 15_101).unwrap();
    assert_eq!(record.phase, Phase::InstallationPending);
    assert!(!record.installation_confirmed);
    update(&coordinator, record.clone());
    let recovered = coordinator
        .submit_sync(message(id, Action::Recover))
        .unwrap();
    assert_eq!(recovered.phase, Phase::Installing);
    assert!(!recovered.installation_confirmed && recovered.finalize_decided);
    assert!(stored(&coordinator, id).helper_started_at_ms.is_none());
    // A lost direct acknowledgement can be recovered from its durable signed receipt.
    let acknowledgement = installer::Acknowledgement {
        id: id.into(),
        attempt: 1,
        sha256: plan.bundle.worker_sha256.clone(),
        installed: true,
        error: None,
        issued_at_ms: crate::session::unix_timestamp_ms(),
    };
    let mut wrong_attempt = acknowledgement.clone();
    wrong_attempt.attempt += 1;
    assert!(coordinator
        .acknowledge_installation(wrong_attempt)
        .await
        .is_err());
    let original = std::fs::read(&plan.target).unwrap();
    std::fs::write(&plan.target, b"a different installed image").unwrap();
    assert!(coordinator
        .acknowledge_installation(acknowledgement.clone())
        .await
        .is_err());
    assert!(!stored(&coordinator, id).installation_confirmed);
    std::fs::write(&plan.target, original).unwrap();
    let signed = installer::SignedAcknowledgement {
        proof: acknowledgement.proof(&[7; 32]).unwrap(),
        ack: acknowledgement,
    };
    let receipt = coordinator
        .0
        .directory
        .join(format!("install-{id}-1.ack.json"));
    crate::config_store::save_durable_private_bytes(
        &receipt,
        &serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
    record.phase = Phase::Installing;
    coordinator.install(&mut record, 15_102).unwrap();
    assert!(record.installation_confirmed);
    assert_eq!(record.phase, Phase::Draining);
    update(&coordinator, record.clone());
    // Recover must not erase the in-memory WAL when the on-disk journal vanished.
    let journal = root.0.join("release/journal.json");
    let bytes = std::fs::read(&journal).unwrap();
    std::fs::remove_file(&journal).unwrap();
    assert!(coordinator
        .submit_sync(message(id, Action::Recover))
        .is_err());
    assert_eq!(coordinator.status(Some(id)).records.len(), 1);
    assert!(stored(&coordinator, id).installation_confirmed);
    std::fs::write(&journal, bytes).unwrap();
    // Specific status must inspect the full log, before the 32-row summary limit.
    record.phase = Phase::Complete;
    update(&coordinator, record.clone());
    for n in 0..40 {
        let mut incompatible = plan.clone();
        incompatible.bundle.base.frida_version = format!("unsupported-{n}");
        coordinator
            .submit_sync(message(
                &format!("old-{n:02}"),
                Action::Prepare {
                    plan: incompatible,
                    auto_commit: false,
                },
            ))
            .unwrap();
    }
    let summary = coordinator.status(None);
    assert_eq!(summary.records.len(), 32);
    assert_eq!(summary.records_omitted, 9);
    assert_eq!(coordinator.status(Some(id)).records[0].id, id);
    // Reaping is independent of transaction phase and a frozen WAL. This is a
    // real short-lived OS process; --list does not execute the test harness.
    let helper = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    coordinator
        .0
        .helpers
        .lock()
        .unwrap()
        .insert(id.into(), helper);
    coordinator.0.state.lock().unwrap().error = Some("model WAL is unavailable".into());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while coordinator.0.helpers.lock().unwrap().contains_key(id) {
        coordinator.tick().await.unwrap();
        assert!(
            tokio::time::Instant::now() < deadline,
            "completed helper was not reaped during a WAL error"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(stored(&coordinator, id).phase, Phase::Complete);
    coordinator.0.state.lock().unwrap().error = None;
    // A member with no Engine channel is a bounded enrollment wait, then restart.
    let challenge = coordinator
        .0
        .sessions
        .begin_auth("late-session".into(), "model-target".into(), [4; 32])
        .unwrap();
    let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
    let session = coordinator
        .0
        .sessions
        .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(30))
        .unwrap();
    assert!(coordinator
        .0
        .sessions
        .activate("late-session", &session.token, std::process::id()));
    let mut pending = record;
    pending.finalize_decided = false;
    pending.installation_confirmed = false;
    pending.abort_requested = false;
    pending.phase = Phase::Preparing;
    pending.prepare_deadline_ms = u64::MAX;
    coordinator.advance(&mut pending).await.unwrap();
    assert_eq!(pending.phase, Phase::Preparing);
    assert_eq!(pending.requires_restart_processes, vec![std::process::id()]);
    pending.prepare_deadline_ms = 0;
    assert_eq!(
        coordinator.advance(&mut pending).await.unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    pending.phase = Phase::Observing;
    pending.uncovered_since_ms = None;
    coordinator.advance(&mut pending).await.unwrap();
    assert!(!pending.finalize_decided);
    pending.uncovered_since_ms = Some(0);
    assert_eq!(
        coordinator.advance(&mut pending).await.unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    coordinator.0.sessions.revoke("late-session");
    let gap = "engine-finalize-before-release-wal";
    coordinator
        .submit_sync(message(
            gap,
            Action::Prepare {
                plan: plan.clone(),
                auto_commit: false,
            },
        ))
        .unwrap();
    let engine = &coordinator.0.engine;
    let engine_action = |action| upgrade::Request {
        id: gap.into(),
        issued_at_ms: crate::session::unix_timestamp_ms(),
        action,
    };
    engine
        .submit(engine_action(upgrade::Action::PrepareAll {
            native_base_sha256: plan.bundle.base.native_base_sha256.clone(),
            manifest: plan.bundle.engine.clone(),
            source: plan.engine.clone(),
            cache: plan.cache.clone(),
            hosts: vec![],
        }))
        .await
        .unwrap();
    engine.tick().unwrap();
    engine
        .submit(engine_action(upgrade::Action::Commit))
        .await
        .unwrap();
    engine.tick().unwrap();
    engine
        .submit(engine_action(upgrade::Action::ObserveHeld))
        .await
        .unwrap();
    engine
        .submit(engine_action(upgrade::Action::Finalize))
        .await
        .unwrap();
    assert!(
        !stored(&coordinator, gap).finalize_decided,
        "model must preserve the cross-log crash gap"
    );
    assert!(coordinator
        .submit_sync(message(gap, Action::Abort))
        .is_err());
    // Freeze the real Engine WAL, restore its valid file, then recover through
    // the product API. This must clear both logs before restarting its runner.
    let engine_journal = root.0.join("engine/journal.json");
    let engine_backup = root.0.join("engine/saved-journal.json");
    std::fs::rename(&engine_journal, &engine_backup).unwrap();
    std::fs::create_dir(&engine_journal).unwrap();
    assert!(engine
        .submit(engine_action(upgrade::Action::ObserveHeld))
        .await
        .is_err());
    assert!(engine.status(Some(gap)).error.is_some());
    assert!(coordinator
        .submit_sync(message(gap, Action::Abort))
        .is_err());
    std::fs::remove_dir(&engine_journal).unwrap();
    std::fs::rename(&engine_backup, &engine_journal).unwrap();
    coordinator
        .submit(message(gap, Action::Recover))
        .await
        .unwrap();
    assert!(engine.status(Some(gap)).error.is_none());
    coordinator.stop_runner();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while coordinator
        .0
        .runner
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|runner| !runner.is_finished())
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "cross-log recovered runner did not stop"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    coordinator.0.workers.shutdown();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while coordinator
        .0
        .workers
        .status()
        .workers
        .iter()
        .any(|worker| worker.phase != "exited")
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "model worker did not stop"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn compatible_bundle() -> super::super::Bundle {
    super::super::Bundle {
        format: 1,
        version: env!("CARGO_PKG_VERSION").into(),
        target: hyperhub_engine::TARGET.into(),
        base: super::super::Base::resident(),
        engine: hyperhub_engine::manifest(b"release-boundary-model", env!("CARGO_PKG_VERSION")),
        engine_file: super::super::engine_name().into(),
        worker_sha256: "a".repeat(64),
        worker_size: 1,
    }
}
#[test]
fn late_incompatible_native_hosts_require_restart_until_the_incarnation_is_gone() {
    let bundle = compatible_bundle();
    let mut late = host("unit-session", Backend::LinuxGum);
    late.native_base_sha256 = bundle.base.native_base_sha256.clone();
    assert!(reject_incompatible_hosts(&[late.clone()], &bundle).is_ok());
    late.native_base_sha256 = "f".repeat(64);
    assert_eq!(
        reject_incompatible_hosts(&[late.clone()], &bundle)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    late.online = false;
    assert!(reject_incompatible_hosts(&[late.clone()], &bundle).is_ok());
    late.online = true;
    late.host_start_time = late.host_start_time.map(|s| s + 1);
    assert!(reject_incompatible_hosts(&[late.clone()], &bundle).is_ok());
    late.host_start_time = None;
    assert_eq!(
        reject_incompatible_hosts(&[late], &bundle)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
}

#[test]
fn bundle_base_fingerprints_are_required_and_distinguish_resident_incompatibility() {
    let original = compatible_bundle();
    original.validate().unwrap();
    let mut changed = original.clone();
    changed.base.native_base_sha256 = "d".repeat(64);
    changed.validate().unwrap();
    assert_ne!(changed.base, super::super::Base::resident());
    changed = original.clone();
    changed.base.serve_base_sha256 = "e".repeat(64);
    changed.validate().unwrap();
    assert_ne!(changed.base, super::super::Base::resident());
    changed.base.serve_base_sha256.clear();
    assert!(changed.validate().is_err());
}
