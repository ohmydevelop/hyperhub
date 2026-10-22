use hyperhub_runtime::{abi, Engine, Error, Manifest, Runtime, Settings, Stage};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

fn manifest(version: u8) -> Manifest {
    Manifest {
        version: version.to_string(),
        target: "test-target".into(),
        abi: abi::ABI_V1,
        state_schema: 1,
        hooks: 3,
        sha256: format!("{version:064x}"),
        size: 1,
    }
}
struct TestEngine {
    manifest: Manifest,
    healthy: Arc<AtomicBool>,
    drops: Arc<AtomicUsize>,
}
impl Drop for TestEngine {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl Engine for TestEngine {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn health(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }
    fn invoke(
        &self,
        _: &hyperhub_runtime::Lease,
        _: u32,
        _: &[u8],
        output: &mut [u8],
    ) -> Result<usize, i32> {
        if output.is_empty() {
            return Err(abi::BUFFER_TOO_SMALL);
        }
        output[0] = self.manifest.version.parse().unwrap();
        Ok(1)
    }
}
fn engine(version: u8, healthy: Arc<AtomicBool>, drops: Arc<AtomicUsize>) -> Arc<dyn Engine> {
    Arc::new(TestEngine {
        manifest: manifest(version),
        healthy,
        drops,
    })
}
fn good(version: u8) -> Arc<dyn Engine> {
    engine(
        version,
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicUsize::new(0)),
    )
}
fn settings() -> Settings {
    Settings {
        health_window: Duration::ZERO,
        ..Settings::default()
    }
}
fn runtime() -> Runtime {
    Runtime::new(good(0), settings()).unwrap()
}
fn upgrade(runtime: &Runtime, version: u8) {
    let id = format!("upgrade-{version}");
    runtime
        .prepare(&id, &manifest(version), || Ok(good(version)))
        .unwrap();
    runtime.commit(&id).unwrap();
    runtime.observe().unwrap();
}
fn value(lease: &hyperhub_runtime::Lease) -> u8 {
    let mut bytes = [0];
    assert_eq!(lease.invoke(0, &[], &mut bytes), Ok(1));
    bytes[0]
}

#[test]
fn partial_group_commit_keeps_rollback_code_until_the_coordinator_decides() {
    let first = runtime();
    let second = runtime();
    for host in [&first, &second] {
        host.prepare("group", &manifest(1), || Ok(good(1))).unwrap();
    }
    first.commit_held("group").unwrap();
    let completed_entry = first.acquire();
    // A zero health window exposes premature expiry deterministically: an
    // ordinary standalone commit would already discard its rollback reserve.
    first.observe().unwrap();
    first.observe().unwrap();
    let status = first.snapshot().unwrap();
    assert_eq!(status.transactions[0].stage, Stage::Draining);
    assert!(status.retired[0].rollback_reserved);
    assert_eq!(status.retired[0].references, 0);
    second.abort("group").unwrap();
    assert_eq!(
        first
            .rollback("group", "another participant failed")
            .unwrap()
            .stage,
        Stage::RolledBack
    );
    assert_eq!(value(&first.acquire()), 0);
    assert_eq!(value(&second.acquire()), 0);
    assert_eq!(value(&completed_entry), 1);
    assert_eq!(first.snapshot().unwrap().retired[0].references, 1);
}

#[test]
fn global_confirmation_explicitly_starts_and_completes_held_observation() {
    let host = runtime();
    host.prepare("confirmed", &manifest(1), || Ok(good(1)))
        .unwrap();
    assert!(matches!(
        host.begin_observation("confirmed"),
        Err(Error::NotPrepared)
    ));
    host.commit_held("confirmed").unwrap();
    // Replaying either commit variant must not accidentally release the hold.
    host.commit("confirmed").unwrap();
    host.observe().unwrap();
    assert_eq!(host.query("confirmed").unwrap().stage, Stage::Draining);
    host.begin_observation("confirmed").unwrap();
    host.begin_observation("confirmed").unwrap();
    host.observe().unwrap();
    assert_eq!(
        host.begin_observation("confirmed").unwrap().stage,
        Stage::Complete
    );
    assert!(host.snapshot().unwrap().retired.is_empty());
    assert!(matches!(
        host.rollback("confirmed", "too late"),
        Err(Error::AlreadyCommitted)
    ));
    host.prepare("next", &manifest(2), || Ok(good(2))).unwrap();
    host.commit_held("next").unwrap();
    assert_eq!(
        host.begin_observation("confirmed").unwrap().stage,
        Stage::Complete
    );
    host.observe().unwrap();
    assert_eq!(host.query("next").unwrap().stage, Stage::Draining);
    assert!(host.snapshot().unwrap().retired[0].rollback_reserved);
}

#[test]
fn a_held_commit_still_rolls_back_an_unhealthy_new_engine() {
    let host = runtime();
    let healthy = Arc::new(AtomicBool::new(true));
    host.prepare("health", &manifest(1), || {
        Ok(engine(1, healthy.clone(), Arc::new(AtomicUsize::new(0))))
    })
    .unwrap();
    host.commit_held("health").unwrap();
    healthy.store(false, Ordering::Release);
    host.observe().unwrap();
    assert_eq!(host.query("health").unwrap().stage, Stage::RolledBack);
    assert_eq!(value(&host.acquire()), 0);
    assert!(matches!(
        host.begin_observation("health"),
        Err(Error::NotPrepared)
    ));
}

#[test]
fn new_calls_switch_and_pending_entry_exit_or_callbacks_keep_old_code() {
    let drops = Arc::new(AtomicUsize::new(0));
    let runtime = Runtime::new(
        engine(0, Arc::new(AtomicBool::new(true)), drops.clone()),
        settings(),
    )
    .unwrap();
    let entered = runtime.acquire();
    let completion = entered.clone();
    assert_eq!(value(&entered), 0);
    upgrade(&runtime, 1);
    assert_eq!(value(&runtime.acquire()), 1);
    assert_eq!(value(&entered), 0);
    assert_eq!(value(&completion), 0);
    let status = runtime.snapshot().unwrap();
    assert_eq!(status.retired.len(), 1);
    assert_eq!(status.retired[0].references, 2);
    assert_eq!(status.transactions[0].stage, Stage::Draining);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(entered);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(completion);
    let status = runtime.snapshot().unwrap();
    assert!(status.retired.is_empty());
    assert_eq!(status.transactions[0].stage, Stage::Complete);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn incompatible_hooks_state_abi_or_target_never_execute_loader() {
    for changed in 0..4 {
        let runtime = runtime();
        let mut candidate = manifest(1);
        match changed {
            0 => candidate.hooks ^= 1,
            1 => candidate.state_schema += 1,
            2 => candidate.abi += 1,
            _ => candidate.target = "other-target".into(),
        }
        let tx = runtime
            .prepare("incompatible", &candidate, || {
                panic!("incompatible loader ran")
            })
            .unwrap();
        assert_eq!(tx.stage, Stage::RequiresRestart);
        assert_eq!(
            runtime.commit("incompatible").unwrap_err(),
            Error::NotPrepared
        );
        assert_eq!(value(&runtime.acquire()), 0);
    }
}

#[test]
fn transaction_retries_never_load_or_switch_twice_and_conflicts_are_rejected() {
    let runtime = runtime();
    let first = runtime
        .prepare("retry", &manifest(1), || Ok(good(1)))
        .unwrap();
    let retry = runtime
        .prepare("retry", &manifest(1), || panic!("duplicate load"))
        .unwrap();
    assert_eq!(first.generation, retry.generation);
    assert_eq!(
        runtime
            .prepare("retry", &manifest(2), || unreachable!())
            .unwrap_err(),
        Error::Conflict
    );
    let committed = runtime.commit("retry").unwrap();
    let repeated = runtime.commit("retry").unwrap();
    assert_eq!(committed.generation, repeated.generation);
    assert_eq!(runtime.abort("retry").unwrap_err(), Error::AlreadyCommitted);
    runtime.observe().unwrap();
    assert_eq!(runtime.commit("retry").unwrap().stage, Stage::Complete);
    assert_eq!(runtime.snapshot().unwrap().active.generation, 1);
}

#[test]
fn abort_during_load_keeps_old_dispatch_and_drops_late_candidate() {
    let runtime = Arc::new(runtime());
    let drops = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let other = runtime.clone();
    let observed = drops.clone();
    let thread = std::thread::spawn(move || {
        other.prepare("cancel", &manifest(1), || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(engine(1, Arc::new(AtomicBool::new(true)), observed))
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        runtime.snapshot().unwrap().transactions[0].stage,
        Stage::Preparing
    );
    assert_eq!(value(&runtime.acquire()), 0);
    assert_eq!(runtime.abort("cancel").unwrap().stage, Stage::Aborted);
    release_tx.send(()).unwrap();
    assert_eq!(thread.join().unwrap().unwrap_err(), Error::TimedOut);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(value(&runtime.acquire()), 0);
}

#[test]
fn timeout_rejects_late_preparation_without_switching() {
    let runtime = Runtime::new(
        good(0),
        Settings {
            prepare_timeout: Duration::ZERO,
            ..settings()
        },
    )
    .unwrap();
    assert_eq!(
        runtime
            .prepare("late", &manifest(1), || Ok(good(1)))
            .unwrap_err(),
        Error::TimedOut
    );
    assert_eq!(
        runtime.snapshot().unwrap().transactions[0].stage,
        Stage::Aborted
    );
    assert_eq!(value(&runtime.acquire()), 0);
}

#[test]
fn unhealthy_candidate_or_bad_load_does_not_touch_active_generation() {
    let runtime = runtime();
    assert_eq!(
        runtime
            .prepare("load-fail", &manifest(1), || Err(Error::Artifact(
                "bad bytes".into()
            )))
            .unwrap_err(),
        Error::Artifact("bad bytes".into())
    );
    assert_eq!(
        runtime
            .prepare("health-fail", &manifest(2), || Ok(engine(
                2,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicUsize::new(0))
            )))
            .unwrap_err(),
        Error::Unhealthy
    );
    assert_eq!(
        runtime
            .prepare("different-manifest", &manifest(3), || Ok(good(4)))
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(value(&runtime.acquire()), 0);
}

#[test]
fn failed_health_rolls_back_future_calls_but_keeps_failed_generation_leases_alive() {
    let runtime = runtime();
    let healthy = Arc::new(AtomicBool::new(true));
    let drops = Arc::new(AtomicUsize::new(0));
    runtime
        .prepare("rollback", &manifest(1), || {
            Ok(engine(1, healthy.clone(), drops.clone()))
        })
        .unwrap();
    runtime.commit("rollback").unwrap();
    let in_flight = runtime.acquire();
    healthy.store(false, Ordering::Release);
    runtime.observe().unwrap();
    assert_eq!(value(&runtime.acquire()), 0);
    assert_eq!(value(&in_flight), 1);
    assert_eq!(
        runtime.snapshot().unwrap().transactions[0].stage,
        Stage::RolledBack
    );
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(in_flight);
    assert!(runtime.snapshot().unwrap().retired.is_empty());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn fifth_retained_generation_is_rejected_without_forced_retirement() {
    let runtime = runtime();
    let mut held = Vec::new();
    for version in 1..=4 {
        held.push(runtime.acquire());
        upgrade(&runtime, version);
    }
    assert_eq!(runtime.snapshot().unwrap().retired.len(), 4);
    assert_eq!(
        runtime
            .prepare("too-many", &manifest(5), || panic!("loader should not run"))
            .unwrap_err(),
        Error::RetainedLimit
    );
    assert_eq!(value(&runtime.acquire()), 4);
    for (expected, lease) in held.iter().enumerate() {
        assert_eq!(value(lease), expected as u8);
    }
    held.clear();
    assert!(runtime.snapshot().unwrap().retired.is_empty());
    upgrade(&runtime, 6);
    assert_eq!(value(&runtime.acquire()), 6);
}

#[test]
fn concurrent_dispatch_never_mixes_version_and_implementation_within_one_lease() {
    let runtime = Arc::new(
        Runtime::new(
            good(0),
            Settings {
                max_retired: 64,
                ..settings()
            },
        )
        .unwrap(),
    );
    let start = Arc::new(Barrier::new(5));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let runtime = runtime.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                for _ in 0..2000 {
                    let lease = runtime.acquire();
                    let expected: u8 = lease.version().parse().unwrap();
                    assert_eq!(value(&lease), expected);
                }
            })
        })
        .collect();
    start.wait();
    for version in 1..=32 {
        runtime
            .prepare(&format!("swap-{version}"), &manifest(version), || {
                Ok(good(version))
            })
            .unwrap();
        runtime.commit(&format!("swap-{version}")).unwrap();
        runtime.observe().unwrap();
    }
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(value(&runtime.acquire()), 32);
}

#[test]
fn bounded_transaction_history_rejects_new_ids_but_remembers_old_results() {
    let runtime = Runtime::new(
        good(0),
        Settings {
            max_transactions: 1,
            ..settings()
        },
    )
    .unwrap();
    upgrade(&runtime, 1);
    assert_eq!(
        runtime
            .prepare("new-id", &manifest(2), || unreachable!())
            .unwrap_err(),
        Error::RetainedLimit
    );
    assert_eq!(
        runtime
            .prepare("upgrade-1", &manifest(1), || unreachable!())
            .unwrap()
            .stage,
        Stage::Complete
    );
}

#[test]
fn coordinator_can_rollback_a_successful_participant_on_partial_failure() {
    let runtime = runtime();
    runtime
        .prepare("group", &manifest(1), || Ok(good(1)))
        .unwrap();
    runtime.commit("group").unwrap();
    let in_flight = runtime.acquire();
    assert_eq!(
        runtime
            .rollback("group", "other Host rejected candidate")
            .unwrap()
            .stage,
        Stage::RolledBack
    );
    assert_eq!(value(&runtime.acquire()), 0);
    assert_eq!(value(&in_flight), 1);
    assert_eq!(
        runtime.rollback("group", "retry").unwrap().stage,
        Stage::RolledBack
    );
    upgrade(&runtime, 2);
    // A retry of a terminal transaction must not roll back the new one.
    runtime.rollback("group", "late retry").unwrap();
    assert_eq!(value(&runtime.acquire()), 2);
}

#[test]
fn rollback_cannot_displace_another_transaction_or_a_completed_upgrade() {
    let runtime = runtime();
    upgrade(&runtime, 1);
    assert_eq!(
        runtime.rollback("upgrade-1", "too late").unwrap_err(),
        Error::AlreadyCommitted
    );
    runtime
        .prepare("next", &manifest(2), || Ok(good(2)))
        .unwrap();
    runtime.commit("next").unwrap();
    assert_eq!(
        runtime
            .rollback("upgrade-1", "wrong transaction")
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(value(&runtime.acquire()), 2);
}

struct ReentrantEngine {
    manifest: Manifest,
    runtime: Arc<std::sync::Mutex<Option<std::sync::Weak<Runtime>>>>,
    dropped: Arc<AtomicBool>,
}
impl Engine for ReentrantEngine {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn health(&self) -> bool {
        true
    }
    fn invoke(
        &self,
        _: &hyperhub_runtime::Lease,
        _: u32,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, i32> {
        Ok(0)
    }
}
impl Drop for ReentrantEngine {
    fn drop(&mut self) {
        if let Some(runtime) = self
            .runtime
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|r| r.upgrade())
        {
            // Reenter the real mutex. A destructor under it would deadlock.
            assert!(runtime.snapshot().is_ok());
        }
        self.dropped.store(true, Ordering::Release);
    }
}
#[test]
fn module_reclamation_and_prepared_abort_drop_after_unlocking() {
    for abort in [false, true] {
        let runtime = Arc::new(runtime());
        let dropped = Arc::new(AtomicBool::new(false));
        let weak = Arc::new(std::sync::Mutex::new(Some(Arc::downgrade(&runtime))));
        runtime
            .prepare("reentrant", &manifest(1), || {
                Ok(Arc::new(ReentrantEngine {
                    manifest: manifest(1),
                    runtime: weak,
                    dropped: dropped.clone(),
                }))
            })
            .unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let other = runtime.clone();
        let thread = std::thread::spawn(move || {
            if abort {
                other.abort("reentrant").unwrap();
            } else {
                other.commit("reentrant").unwrap();
                other.rollback("reentrant", "fixture").unwrap();
            }
            done_tx.send(()).unwrap();
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("module destructor deadlocked");
        thread.join().unwrap();
        assert!(dropped.load(Ordering::Acquire));
    }
}
