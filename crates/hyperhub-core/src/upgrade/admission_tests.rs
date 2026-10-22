use super::*;
use hyperhub_engine::bootstrap::Candidate;

fn selected(rig: &Rig) -> Candidate {
    rig.coordinator
        .as_ref()
        .unwrap()
        .bootstrap("unit", &manifest("0"), "")
        .unwrap()
        .1
        .unwrap()
}
fn child(rig: &mut Rig, candidate: Option<Candidate>) -> usize {
    let mut actor = Actor::new(&rig.registry, 100 + rig.actors.len() as u32);
    if let Some(candidate) = candidate {
        let engine = Arc::new(TestEngine {
            value: candidate.deployment.manifest.version.parse().unwrap(),
            manifest: candidate.deployment.manifest.clone(),
            healthy: actor.candidate_health.clone(),
        });
        actor
            .runtime
            .prepare(&candidate.id, &candidate.deployment.manifest, || Ok(engine))
            .unwrap();
        actor.runtime.commit_held(&candidate.id).unwrap();
    }
    actor.process(&rig.registry, &rig.root.0.join("store/journal.json"));
    rig.actors.push(actor);
    rig.actors.len() - 1
}
fn admitted(rig: &mut Rig, index: usize) {
    for _ in 0..100 {
        let id = rig.actors[index].registration.as_ref().unwrap().id.clone();
        if rig.coordinator.as_ref().unwrap().admit(&id).unwrap() {
            return;
        }
        rig.tick();
    }
    panic!(
        "admission did not settle: {:?}",
        rig.coordinator.as_ref().unwrap().status(Some("group"))
    );
}

#[test]
fn candidate_child_joins_the_same_group_and_rolls_back() {
    let mut rig = Rig::new(1);
    rig.committed();
    let candidate = selected(&rig);
    let index = child(&mut rig, Some(candidate));
    admitted(&mut rig, index);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 1);
    assert_eq!(
        rig.coordinator
            .as_ref()
            .unwrap()
            .status(Some("group"))
            .records[0]
            .participants
            .len(),
        2
    );
    rig.submit(Action::Rollback {
        reason: "rollback includes the admitted child".into(),
    });
    rig.until(Phase::RolledBack);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 0);
}

#[test]
fn rollback_settlement_accepts_only_proven_clean_retirement() {
    for clean in [true, false] {
        let mut rig = Rig::new(2);
        rig.committed();
        let coordinator = rig.coordinator.as_ref().unwrap();
        {
            let mut state = coordinator.0.state.lock().unwrap();
            let mut book = state.book.clone();
            let participant = &mut book.records.get_mut("group").unwrap().participants[0];
            participant.exited = true;
            participant.exit_clean = clean;
            participant.cleanup_done = true;
            participant.finalized = true;
            participant.stage = Some(hyperhub_runtime::Stage::Complete);
            participant.pending = None;
            state.persist(book).unwrap();
        }
        rig.submit(Action::Rollback {
            reason: "native observer requested rollback".into(),
        });
        rig.until(if clean {
            Phase::RolledBack
        } else {
            Phase::Failed
        });
        let active = &rig
            .coordinator
            .as_ref()
            .unwrap()
            .status(Some("group"))
            .records[0]
            .participants[1]
            .host_id;
        let actor = rig
            .actors
            .iter()
            .find(|a| &a.registration.as_ref().unwrap().id == active)
            .unwrap();
        assert_eq!(value(&actor.runtime.acquire()), 0);
        rig.reopen();
        assert_eq!(
            rig.phase(),
            if clean {
                Phase::RolledBack
            } else {
                Phase::Failed
            }
        );
        assert_eq!(
            rig.coordinator
                .as_ref()
                .unwrap()
                .status(Some("group"))
                .records[0]
                .participants[0]
                .exit_clean,
            clean
        );
    }
}

#[test]
fn rollback_between_selection_and_enrollment_reopens_child_cleanup() {
    let mut rig = Rig::new(1);
    rig.committed();
    let candidate = selected(&rig);
    rig.submit(Action::Rollback {
        reason: "selection raced rollback".into(),
    });
    rig.until(Phase::RolledBack);
    let index = child(&mut rig, Some(candidate));
    admitted(&mut rig, index);
    rig.until(Phase::RolledBack);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 0);
    assert!(rig.actors[index]
        .runtime
        .snapshot()
        .unwrap()
        .retired
        .iter()
        .all(|g| !g.rollback_reserved));
}

#[test]
fn finalize_between_selection_and_enrollment_releases_child_reservation() {
    let mut rig = Rig::new(1);
    rig.committed();
    let candidate = selected(&rig);
    rig.submit(Action::Observe);
    rig.until(Phase::Complete);
    let index = child(&mut rig, Some(candidate));
    admitted(&mut rig, index);
    rig.until(Phase::Complete);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 1);
    assert!(rig.actors[index]
        .runtime
        .snapshot()
        .unwrap()
        .retired
        .iter()
        .all(|g| !g.rollback_reserved));
    rig.reopen();
    let (stable, candidate) = rig
        .coordinator
        .as_ref()
        .unwrap()
        .bootstrap("unit", &manifest("0"), "")
        .unwrap();
    assert_eq!(stable.unwrap().manifest, manifest("1"));
    assert!(candidate.is_none());
}

#[test]
fn a_stable_selection_before_group_commit_catches_up_before_admission() {
    let mut rig = Rig::new(1);
    rig.prepared();
    let (stable, candidate) = rig
        .coordinator
        .as_ref()
        .unwrap()
        .bootstrap("unit", &manifest("0"), "")
        .unwrap();
    assert!(stable.is_none() && candidate.is_none());
    rig.submit(Action::Commit);
    rig.until(Phase::Committed);
    let index = child(&mut rig, None);
    admitted(&mut rig, index);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 1);
    assert!(rig.actors[index].log.contains(&"prepare".into()));
    assert!(rig.actors[index].log.contains(&"commit".into()));
    rig.submit(Action::Rollback {
        reason: "catchup retained the original stable generation".into(),
    });
    rig.until(Phase::RolledBack);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 0);
}

#[test]
fn a_child_of_a_prepared_group_cannot_be_omitted_from_commit() {
    let mut rig = Rig::new(1);
    rig.prepared();
    let index = child(&mut rig, None);
    let id = rig.actors[index].registration.as_ref().unwrap().id.clone();
    assert!(!rig.coordinator.as_ref().unwrap().admit(&id).unwrap());
    assert_eq!(
        rig.coordinator
            .as_ref()
            .unwrap()
            .submit_sync(rig.request(Action::Commit))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    admitted(&mut rig, index);
    rig.until(Phase::Prepared);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 0);
    rig.submit(Action::Commit);
    rig.until(Phase::Committed);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 1);
}

#[test]
fn prepare_includes_a_child_registered_after_the_cli_host_snapshot() {
    let mut rig = Rig::new(1);
    let stale_cli_snapshot = rig.prepare();
    let index = child(&mut rig, None);
    rig.submit(stale_cli_snapshot);
    let id = rig.actors[index].registration.as_ref().unwrap().id.clone();
    assert!(!rig.coordinator.as_ref().unwrap().admit(&id).unwrap());
    admitted(&mut rig, index);
    rig.until(Phase::Prepared);
    assert_eq!(
        rig.coordinator
            .as_ref()
            .unwrap()
            .status(Some("group"))
            .records[0]
            .participants
            .len(),
        2
    );
    rig.submit(Action::Commit);
    rig.until(Phase::Committed);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 1);
}

#[test]
fn a_child_registered_after_prepare_persistence_is_durably_adopted() {
    let mut rig = Rig::new(1);
    rig.submit(rig.prepare());
    let index = child(&mut rig, None);
    let id = rig.actors[index].registration.as_ref().unwrap().id.clone();
    assert!(!rig.coordinator.as_ref().unwrap().admit(&id).unwrap());
    admitted(&mut rig, index);
    rig.until(Phase::Prepared);
    rig.submit(Action::Commit);
    rig.until(Phase::Committed);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 1);
}

#[test]
fn a_local_session_transaction_never_changes_another_session() {
    let mut rig = Rig::new(1);
    rig.committed();
    let mut other = Actor::new_in(&rig.registry, 1, "other");
    other.process(&rig.registry, &rig.root.0.join("store/journal.json"));
    let coordinator = rig.coordinator.as_ref().unwrap();
    assert!(coordinator
        .admit(&other.registration.as_ref().unwrap().id)
        .unwrap());
    let (stable, candidate) = coordinator.bootstrap("other", &manifest("0"), "").unwrap();
    assert!(stable.is_none() && candidate.is_none());
    rig.submit(Action::Observe);
    rig.until(Phase::Complete);
    let coordinator = rig.coordinator.as_ref().unwrap();
    let (stable, candidate) = coordinator.bootstrap("other", &manifest("0"), "").unwrap();
    assert!(stable.is_none() && candidate.is_none());
    assert_eq!(
        coordinator.status(Some("group")).records[0]
            .participants
            .len(),
        1
    );
    assert_eq!(value(&other.runtime.acquire()), 0);
}

#[test]
fn incompatible_session_selection_requires_restart() {
    let mut rig = Rig::new(1);
    rig.committed();
    let mut incompatible = manifest("0");
    incompatible.state_schema += 1;
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .bootstrap("unit", &incompatible, "")
        .unwrap_err()
        .to_string()
        .contains("requires_restart"));
    // A new session's built-in implementation does not inherit a local trial.
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .bootstrap("new", &incompatible, "")
        .unwrap()
        .1
        .is_none());
}

#[test]
fn an_inherited_old_selection_is_finalized_before_catching_up_a_newer_group() {
    let mut rig = Rig::new(1);
    rig.committed();
    let old = selected(&rig);
    rig.submit(Action::Observe);
    rig.until(Phase::Complete);
    let coordinator = rig.coordinator.as_ref().unwrap().clone();
    coordinator
        .submit_sync(Request {
            id: "new-group".into(),
            issued_at_ms: crate::session::unix_timestamp_ms(),
            action: Action::Prepare {
                manifest: manifest("2"),
                source: rig.root.0.join("second"),
                cache: rig.root.0.join("cache"),
                hosts: vec![rig.actors[0].registration.as_ref().unwrap().id.clone()],
            },
        })
        .unwrap();
    for phase in [Phase::Prepared, Phase::Committed] {
        for _ in 0..100 {
            if coordinator.status(Some("new-group")).records[0].phase == phase {
                break;
            }
            rig.tick();
        }
        assert_eq!(
            coordinator.status(Some("new-group")).records[0].phase,
            phase
        );
        if phase == Phase::Prepared {
            coordinator
                .submit_sync(Request {
                    id: "new-group".into(),
                    issued_at_ms: 0,
                    action: Action::Commit,
                })
                .unwrap();
        }
    }
    let index = child(&mut rig, Some(old));
    admitted(&mut rig, index);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 2);
    let log = &rig.actors[index].log;
    assert!(
        log.iter().position(|x| x == "finalize").unwrap()
            < log.iter().position(|x| x == "prepare").unwrap()
    );
    coordinator
        .submit_sync(Request {
            id: "new-group".into(),
            issued_at_ms: 0,
            action: Action::Rollback {
                reason: "newer group rollback".into(),
            },
        })
        .unwrap();
    for _ in 0..100 {
        if coordinator.status(Some("new-group")).records[0].phase == Phase::RolledBack {
            break;
        }
        rig.tick();
    }
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 1);
}

#[test]
fn held_observation_keeps_rollback_until_an_explicit_global_decision() {
    let mut rig = Rig::new(1);
    rig.committed();
    rig.submit(Action::ObserveHeld);
    for _ in 0..20 {
        rig.tick();
    }
    assert_eq!(rig.phase(), Phase::Observing);
    assert!(rig.actors[0].runtime.snapshot().unwrap().retired[0].rollback_reserved);
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .submit_sync(rig.request(Action::Observe))
        .is_err());
    rig.submit(Action::Finalize);
    assert_eq!(rig.phase(), Phase::Finalizing);
    assert!(!rig.actors[0].log.contains(&"finalize".into()));
    rig.until(Phase::Complete);
}

#[test]
fn held_finalize_checks_elapsed_time_freshness_and_survives_recovery() {
    let mut rig = Rig::new(1);
    let epoch = crate::session::unix_timestamp_ms();
    let clock = Arc::new(AtomicU64::new(epoch));
    let time = clock.clone();
    let inner = Arc::get_mut(&mut rig.coordinator.as_mut().unwrap().0).unwrap();
    inner.now = Arc::new(move || time.load(Ordering::Acquire));
    inner.health_window_ms = 50;
    rig.committed();
    rig.submit(Action::ObserveHeld);
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .submit_sync(rig.request(Action::Finalize))
        .is_err());
    clock.store(epoch + 5000, Ordering::Release);
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .submit_sync(rig.request(Action::Finalize))
        .is_err());
    rig.reopen();
    let restarted = rig
        .coordinator
        .as_ref()
        .unwrap()
        .status(Some("group"))
        .records[0]
        .health_started_at_ms
        .unwrap();
    Arc::get_mut(&mut rig.coordinator.as_mut().unwrap().0)
        .unwrap()
        .now = Arc::new(move || restarted + 100);
    for _ in 0..4 {
        rig.tick();
    }
    assert_eq!(rig.phase(), Phase::Observing);
    assert!(rig.actors[0].runtime.snapshot().unwrap().retired[0].rollback_reserved);
    rig.submit(Action::Finalize);
    rig.until(Phase::Complete);
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .bootstrap("unit", &manifest("0"), "")
        .unwrap()
        .0
        .is_some());
}

fn second_committed_group() -> Rig {
    let mut rig = Rig::new(1);
    rig.committed();
    rig.submit(Action::Observe);
    rig.until(Phase::Complete);
    let coordinator = rig.coordinator.as_ref().unwrap().clone();
    coordinator
        .submit_sync(Request {
            id: "second".into(),
            issued_at_ms: 0,
            action: Action::Prepare {
                manifest: manifest("2"),
                source: rig.root.0.join("second"),
                cache: rig.root.0.join("cache"),
                hosts: vec![rig.actors[0].registration.as_ref().unwrap().id.clone()],
            },
        })
        .unwrap();
    for phase in [Phase::Prepared, Phase::Committed] {
        for _ in 0..100 {
            if coordinator.status(Some("second")).records[0].phase == phase {
                break;
            }
            rig.tick();
        }
        assert_eq!(coordinator.status(Some("second")).records[0].phase, phase);
        if phase == Phase::Prepared {
            coordinator
                .submit_sync(Request {
                    id: "second".into(),
                    issued_at_ms: 0,
                    action: Action::Commit,
                })
                .unwrap();
        }
    }
    rig
}

#[test]
fn fresh_exec_with_stable_and_candidate_is_not_downgraded_during_admission() {
    let mut rig = second_committed_group();
    let (stable, candidate) = rig
        .coordinator
        .as_ref()
        .unwrap()
        .bootstrap("unit", &manifest("0"), "")
        .unwrap();
    let stable = stable.unwrap();
    let candidate = candidate.unwrap();
    let mut actor = Actor::new(&rig.registry, 200);
    for (id, manifest, finalized) in [
        ("bootstrap-stable", stable.manifest, true),
        (candidate.id.as_str(), candidate.deployment.manifest, false),
    ] {
        let engine = Arc::new(TestEngine {
            value: manifest.version.parse().unwrap(),
            manifest: manifest.clone(),
            healthy: actor.candidate_health.clone(),
        });
        actor.runtime.prepare(id, &manifest, || Ok(engine)).unwrap();
        actor.runtime.commit_held(id).unwrap();
        if finalized {
            actor.runtime.finalize_observation(id).unwrap();
        }
    }
    actor.process(&rig.registry, &rig.root.0.join("store/journal.json"));
    rig.actors.push(actor);
    let index = rig.actors.len() - 1;
    admitted(&mut rig, index);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 2);
    assert!(!rig.actors[index].log.iter().any(|x| x == "prepare"));
}

#[test]
fn a_fork_from_builtin_catches_up_stable_before_the_new_candidate() {
    let mut rig = second_committed_group();
    let index = child(&mut rig, None);
    admitted(&mut rig, index);
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 2);
    assert_eq!(
        rig.actors[index]
            .log
            .iter()
            .filter(|x| x.as_str() == "prepare")
            .count(),
        2
    );
    let coordinator = rig.coordinator.as_ref().unwrap().clone();
    coordinator
        .submit_sync(Request {
            id: "second".into(),
            issued_at_ms: 0,
            action: Action::Rollback {
                reason: "restore stable, not original builtin".into(),
            },
        })
        .unwrap();
    for _ in 0..100 {
        if coordinator.status(Some("second")).records[0].phase == Phase::RolledBack {
            break;
        }
        rig.tick();
    }
    assert_eq!(value(&rig.actors[index].runtime.acquire()), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn an_exited_root_does_not_mark_a_live_tracer_as_exited() {
    let rig = Rig::new(0);
    let pid = std::process::id();
    let start = crate::session::process_start_time(pid).unwrap();
    let registration = rig
        .registry
        .register(
            "unit".into(),
            String::new(),
            Backend::LinuxPtrace,
            pid,
            u32::MAX,
            1,
            Some(1),
            Some(start),
            host::report(&hyperhub_engine::resident()).unwrap(),
        )
        .unwrap();
    let mut prepare = rig.prepare();
    if let Action::Prepare { hosts, .. } = &mut prepare {
        hosts.push(registration.id.clone());
    }
    rig.submit(prepare);
    drop(registration);
    rig.coordinator.as_ref().unwrap().tick().unwrap();
    let record = &rig
        .coordinator
        .as_ref()
        .unwrap()
        .status(Some("group"))
        .records[0];
    assert_eq!(record.phase, Phase::Preparing);
    assert!(!record.participants[0].exited);
    assert_eq!(record.participants[0].identity.host_pid, pid);
    assert_eq!(record.participants[0].identity.host_start_time, start);
}

fn empty_global_committed() -> Rig {
    let mut rig = Rig::new(0);
    rig.submit(Action::PrepareAll {
        native_base_sha256: String::new(),
        manifest: manifest("1"),
        source: rig.root.0.join("global"),
        cache: rig.root.0.join("cache"),
        hosts: vec![],
    });
    rig.until(Phase::Prepared);
    rig.submit(Action::Commit);
    rig.until(Phase::Committed);
    rig
}

#[test]
fn an_empty_global_group_adopts_a_later_new_session_and_rolls_it_back() {
    let mut rig = empty_global_committed();
    let candidate = rig
        .coordinator
        .as_ref()
        .unwrap()
        .bootstrap("new-session", &manifest("0"), "")
        .unwrap()
        .1
        .unwrap();
    let mut actor = Actor::new_in(&rig.registry, 80, "new-session");
    let engine = Arc::new(TestEngine {
        manifest: candidate.deployment.manifest.clone(),
        value: 1,
        healthy: actor.candidate_health.clone(),
    });
    actor
        .runtime
        .prepare(&candidate.id, &candidate.deployment.manifest, || Ok(engine))
        .unwrap();
    actor.runtime.commit_held(&candidate.id).unwrap();
    actor.process(&rig.registry, &rig.root.0.join("store/journal.json"));
    rig.actors.push(actor);
    admitted(&mut rig, 0);
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 1);
    rig.submit(Action::Rollback {
        reason: "include the session created during global upgrade".into(),
    });
    rig.until(Phase::RolledBack);
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 0);
}

#[test]
fn a_finalized_global_deployment_bootstraps_a_future_session() {
    let mut rig = empty_global_committed();
    rig.submit(Action::Observe);
    rig.until(Phase::Complete);
    let (stable, candidate) = rig
        .coordinator
        .as_ref()
        .unwrap()
        .bootstrap("future", &manifest("0"), "")
        .unwrap();
    assert_eq!(stable.unwrap().manifest, manifest("1"));
    assert!(candidate.is_none());
    let mut actor = Actor::new_in(&rig.registry, 81, "future");
    actor.process(&rig.registry, &rig.root.0.join("store/journal.json"));
    rig.actors.push(actor);
    admitted(&mut rig, 0);
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 1);
    assert!(rig.actors[0]
        .runtime
        .snapshot()
        .unwrap()
        .retired
        .iter()
        .all(|g| !g.rollback_reserved));
}

#[test]
fn a_global_deployment_never_downgrades_a_newer_builtin() {
    let mut rig = empty_global_committed();
    for observing in [false, true] {
        if observing {
            rig.submit(Action::Observe);
            rig.until(Phase::Complete);
        }
        let (stable, candidate) = rig
            .coordinator
            .as_ref()
            .unwrap()
            .bootstrap("newer", &manifest("2"), "")
            .unwrap();
        assert!(stable.is_none() && candidate.is_none());
    }
    let mut actor = Actor::new_in(&rig.registry, 82, "newer");
    actor.registration.take();
    actor.runtime = Arc::new(
        Runtime::new(
            Arc::new(TestEngine {
                manifest: manifest("2"),
                value: 2,
                healthy: Arc::new(AtomicBool::new(true)),
            }),
            Settings::default(),
        )
        .unwrap(),
    );
    actor.reconnect(&rig.registry);
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .admit(&actor.registration.as_ref().unwrap().id)
        .unwrap());
    assert_eq!(value(&actor.runtime.acquire()), 2);
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .status(Some("group"))
        .records[0]
        .participants
        .is_empty());
}

#[test]
fn a_new_participant_starts_a_fresh_global_health_window() {
    let mut rig = Rig::new(1);
    let clock = Arc::new(AtomicU64::new(crate::session::unix_timestamp_ms()));
    let time = clock.clone();
    Arc::get_mut(&mut rig.coordinator.as_mut().unwrap().0)
        .unwrap()
        .now = Arc::new(move || time.load(Ordering::Acquire));
    rig.committed();
    let initial = rig
        .submit(Action::ObserveHeld)
        .health_started_at_ms
        .unwrap();
    let candidate = selected(&rig);
    clock.fetch_add(100, Ordering::AcqRel);
    let index = child(&mut rig, Some(candidate));
    let id = rig.actors[index].registration.as_ref().unwrap().id.clone();
    assert!(!rig.coordinator.as_ref().unwrap().admit(&id).unwrap());
    assert_eq!(
        rig.coordinator
            .as_ref()
            .unwrap()
            .status(Some("group"))
            .records[0]
            .health_started_at_ms,
        Some(initial + 100)
    );
    assert_eq!(
        rig.coordinator
            .as_ref()
            .unwrap()
            .submit_sync(rig.request(Action::Finalize))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    admitted(&mut rig, index);
}

#[test]
fn a_different_native_base_never_bootstraps_or_adopts_an_older_global_engine() {
    let mut rig = empty_global_committed();
    let new_base = "a".repeat(64);
    for finalize in [false, true] {
        if finalize {
            rig.submit(Action::Observe);
            rig.until(Phase::Complete);
        }
        let (stable, candidate) = rig
            .coordinator
            .as_ref()
            .unwrap()
            .bootstrap("fresh-base-session", &manifest("0"), &new_base)
            .unwrap();
        assert!(stable.is_none() && candidate.is_none());
    }
    let mut actor = Actor::new_in(&rig.registry, 90, "fresh-base-session");
    actor.native_base = new_base;
    actor.reconnect(&rig.registry);
    rig.actors.push(actor);
    admitted(&mut rig, 0);
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 0);
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .status(Some("group"))
        .records[0]
        .participants
        .is_empty());
}

#[test]
fn manual_prepare_rejects_sessions_with_mixed_native_bases() {
    let mut rig = Rig::new(2);
    rig.actors[1].native_base = "b".repeat(64);
    rig.actors[1].reconnect(&rig.registry);
    let record = rig.submit(rig.prepare());
    assert_eq!(record.phase, Phase::RequiresRestart);
    assert!(record.participants.iter().all(|p| p.stage.is_none()));
}

#[test]
fn a_global_release_cannot_prepare_against_a_different_live_native_base() {
    let rig = Rig::new(1);
    let record = rig.submit(Action::PrepareAll {
        native_base_sha256: "c".repeat(64),
        manifest: manifest("1"),
        source: rig.root.0.join("candidate"),
        cache: rig.root.0.join("cache"),
        hosts: vec![],
    });
    assert_eq!(record.phase, Phase::RequiresRestart);
    assert!(record.participants.iter().all(|p| p.stage.is_none()));
}

#[test]
fn an_unknown_exit_waits_for_bounded_evidence_then_fails_conservatively() {
    let mut rig = Rig::new(1);
    rig.committed();
    let mut record = rig
        .coordinator
        .as_ref()
        .unwrap()
        .0
        .state
        .lock()
        .unwrap()
        .book
        .records["group"]
        .clone();
    // The recorded incarnation has ended, while that PID now names another process.
    record.participants[0].identity.host_start_time += 1;
    let now = crate::session::unix_timestamp_ms();
    let mut deliveries = Vec::new();
    participant::advance(&mut record, &[], &rig.registry, now, &mut deliveries).unwrap();
    assert_eq!(record.phase, Phase::Committed);
    assert!(!record.participants[0].exited);
    participant::advance(&mut record, &[], &rig.registry, now + 1999, &mut deliveries).unwrap();
    assert_eq!(record.phase, Phase::Committed);
    assert!(!record.participants[0].exited);
    participant::advance(&mut record, &[], &rig.registry, now + 2000, &mut deliveries).unwrap();
    assert_eq!(record.phase, Phase::Failed);
    assert!(record.participants[0].exited);
    assert!(!record.participants[0].exit_clean);
    assert!(deliveries.is_empty());
}

fn finalize_global_version(rig: &mut Rig, version: &str) {
    rig.submit(Action::PrepareAll {
        native_base_sha256: String::new(),
        manifest: manifest(version),
        source: rig.root.0.join("global"),
        cache: rig.root.0.join("cache"),
        hosts: vec![],
    });
    rig.until(Phase::Prepared);
    rig.submit(Action::Commit);
    rig.until(Phase::Committed);
    rig.submit(Action::Observe);
    rig.until(Phase::Complete);
}
fn lower_global_request(rig: &Rig) -> Request {
    Request {
        id: "stale-lower-release".into(),
        issued_at_ms: crate::session::unix_timestamp_ms(),
        action: Action::PrepareAll {
            native_base_sha256: String::new(),
            manifest: manifest("2"),
            source: rig.root.0.join("lower"),
            cache: rig.root.0.join("cache"),
            hosts: vec![],
        },
    }
}
#[test]
fn an_empty_global_group_never_downgrades_its_finalized_version() {
    let mut rig = Rig::new(0);
    finalize_global_version(&mut rig, "3");
    let error = rig
        .coordinator
        .as_ref()
        .unwrap()
        .submit_sync(lower_global_request(&rig))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("cannot downgrade"));
    assert_eq!(
        rig.coordinator.as_ref().unwrap().status(None).records.len(),
        1
    );
    assert_eq!(
        rig.coordinator
            .as_ref()
            .unwrap()
            .bootstrap("future", &manifest("1"), "")
            .unwrap()
            .0
            .unwrap()
            .manifest,
        manifest("3")
    );
}
#[test]
fn an_older_builtin_cannot_authorize_downgrading_its_active_global_version() {
    let mut rig = Rig::new(1);
    rig.actors[0].runtime = Arc::new(
        Runtime::new(
            Arc::new(TestEngine {
                manifest: manifest("1"),
                value: 1,
                healthy: Arc::new(AtomicBool::new(true)),
            }),
            Settings {
                health_window: Duration::ZERO,
                ..Settings::default()
            },
        )
        .unwrap(),
    );
    rig.actors[0].reconnect(&rig.registry);
    finalize_global_version(&mut rig, "3");
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 3);
    assert_eq!(rig.actors[0].runtime.snapshot().unwrap().host.version, "1");
    assert!(rig
        .coordinator
        .as_ref()
        .unwrap()
        .submit_sync(lower_global_request(&rig))
        .is_err());
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 3);
}
#[test]
fn a_session_local_experiment_keeps_its_explicit_version_semantics() {
    let mut rig = Rig::new(1);
    finalize_global_version(&mut rig, "3");
    let mut action = rig.prepare();
    if let Action::Prepare {
        manifest: candidate,
        ..
    } = &mut action
    {
        *candidate = manifest("2");
    }
    rig.coordinator
        .as_ref()
        .unwrap()
        .submit_sync(Request {
            id: "local-experiment".into(),
            issued_at_ms: crate::session::unix_timestamp_ms(),
            action,
        })
        .unwrap();
    for _ in 0..100 {
        rig.tick();
        let phase = rig
            .coordinator
            .as_ref()
            .unwrap()
            .status(Some("local-experiment"))
            .records[0]
            .phase;
        if phase == Phase::Prepared {
            return;
        }
    }
    panic!(
        "local experiment did not prepare: {:?}",
        rig.coordinator
            .as_ref()
            .unwrap()
            .status(Some("local-experiment"))
    );
}

fn exec_same_identity(rig: &mut Rig, candidate: Option<Candidate>) {
    let fresh = Actor::new(&rig.registry, 900);
    if let Some(candidate) = candidate {
        let engine = Arc::new(TestEngine {
            value: candidate.deployment.manifest.version.parse().unwrap(),
            manifest: candidate.deployment.manifest.clone(),
            healthy: fresh.candidate_health.clone(),
        });
        fresh
            .runtime
            .prepare(&candidate.id, &candidate.deployment.manifest, || Ok(engine))
            .unwrap();
        fresh.runtime.commit_held(&candidate.id).unwrap();
    }
    rig.actors[0].runtime = fresh.runtime.clone();
    rig.actors[0].candidate_health = fresh.candidate_health.clone();
    drop(fresh);
    rig.actors[0].reconnect(&rig.registry);
}

#[test]
fn observing_same_identity_exec_reconciles_reset_generation_before_health_check() {
    for (admit_before_tick, install_candidate) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let mut rig = Rig::new(1);
        // The old image has already switched several times. exec starts a new
        // Runtime, so the same candidate is generation one in the new image.
        for n in 0..4 {
            let id = format!("previous-{n}");
            let engine = Arc::new(TestEngine {
                manifest: manifest("0"),
                value: 0,
                healthy: rig.actors[0].candidate_health.clone(),
            });
            rig.actors[0]
                .runtime
                .prepare(&id, &manifest("0"), || Ok(engine))
                .unwrap();
            rig.actors[0].runtime.commit_held(&id).unwrap();
            rig.actors[0].runtime.finalize_observation(&id).unwrap();
        }
        rig.actors[0].process(&rig.registry, &rig.root.0.join("store/journal.json"));
        rig.committed();
        rig.submit(Action::ObserveHeld);
        let candidate = selected(&rig);
        exec_same_identity(&mut rig, install_candidate.then_some(candidate));
        if admit_before_tick {
            let id = rig.actors[0].registration.as_ref().unwrap().id.clone();
            assert!(!rig.coordinator.as_ref().unwrap().admit(&id).unwrap());
        }
        rig.tick();
        assert_eq!(
            rig.phase(),
            Phase::Observing,
            "must query new image before comparing counters"
        );
        admitted(&mut rig, 0);
        let status = rig.coordinator.as_ref().unwrap().status(Some("group"));
        assert_eq!(status.records[0].phase, Phase::Observing);
        assert_eq!(status.records[0].participants[0].generation, Some(1));
        rig.submit(Action::Rollback {
            reason: "new image remains in the original group".into(),
        });
        rig.until(Phase::RolledBack);
        assert_eq!(value(&rig.actors[0].runtime.acquire()), 0);
    }
}

#[test]
fn same_identity_exec_selected_before_terminal_decision_reopens_cleanup() {
    for finalize in [false, true] {
        let mut rig = Rig::new(1);
        rig.committed();
        let candidate = selected(&rig);
        if finalize {
            rig.submit(Action::Observe);
            rig.until(Phase::Complete);
        } else {
            rig.submit(Action::Rollback {
                reason: "exec selection raced rollback".into(),
            });
            rig.until(Phase::RolledBack);
        }
        exec_same_identity(&mut rig, Some(candidate));
        let id = rig.actors[0].registration.as_ref().unwrap().id.clone();
        assert!(
            !rig.coordinator.as_ref().unwrap().admit(&id).unwrap(),
            "new image still holds an unacknowledged reservation"
        );
        admitted(&mut rig, 0);
        rig.until(if finalize {
            Phase::Complete
        } else {
            Phase::RolledBack
        });
        let snapshot = rig.actors[0].runtime.snapshot().unwrap();
        assert!(!snapshot.retired.iter().any(|r| r.rollback_reserved));
        assert_eq!(value(&rig.actors[0].runtime.acquire()), u8::from(finalize));
    }
}

#[test]
fn same_identity_exec_without_old_transaction_catches_up_finalized_stable() {
    let mut rig = Rig::new(1);
    rig.committed();
    rig.submit(Action::Observe);
    rig.until(Phase::Complete);
    exec_same_identity(&mut rig, None);
    admitted(&mut rig, 0);
    assert_eq!(value(&rig.actors[0].runtime.acquire()), 1);
    assert!(!rig.actors[0]
        .runtime
        .snapshot()
        .unwrap()
        .retired
        .iter()
        .any(|r| r.rollback_reserved));
}
