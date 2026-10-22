use super::*;
use crate::engine_hosts::{DeliveryState, HostStatus, OwnerCommand};
use crate::upgrade::{Pending, Purpose};
use hyperhub_engine::management::{Command, Reply};
use hyperhub_runtime::Stage;

struct Failure {
    reason: String,
    restart: bool,
}

// PID and process birth survive exec; Runtime generation counters do not.
// Rebind only after the old channel has left, and query the new image before
// using any channel-derived confirmation in a durable group decision.
pub(super) fn rebind(record: &mut Record, index: usize, host: &HostStatus, now: u64) {
    if record.participants[index].host_id == host.host_id {
        return;
    }
    let transaction = host
        .snapshot
        .transactions
        .iter()
        .find(|t| t.id == record.id);
    let selected = transaction.is_some_and(|t| {
        t.manifest == record.manifest
            && matches!(t.stage, Stage::Prepared | Stage::Draining | Stage::Complete)
    });
    let participant = &mut record.participants[index];
    participant.host_id = host.host_id.clone();
    participant.pending = None;
    if transaction.is_none() && record.finalize_decided && participant.finalized {
        // A lower counter proves the old Runtime disappeared at exec. If the
        // counter did not reset, preserve the normal retired-lease drain check:
        // a plain reconnect can retain old leases after its transaction report
        // has left the bounded wire history.
        participant.recovering = false;
        if participant
            .generation
            .is_some_and(|g| host.snapshot.active.generation < g)
        {
            participant.stage = Some(Stage::Complete);
        }
        return;
    }
    participant.recovering = true;
    participant.generation = transaction.and_then(|t| t.generation);
    participant.stage = transaction.map(|t| t.stage);
    participant.confirmed = transaction.is_some_and(|t| {
        t.manifest == record.manifest && matches!(t.stage, Stage::Draining | Stage::Complete)
    });
    participant.finalized = false;
    participant.cleanup_done = false;
    participant.previous_generation = participant
        .generation
        .map_or(host.snapshot.active.generation, |g| g.saturating_sub(1));
    if record.finalize_decided {
        record.phase = Phase::Finalizing;
    } else if record.phase.terminal() && selected {
        record.phase = if participant.confirmed {
            Phase::RollingBack
        } else {
            Phase::Aborting
        };
    } else if record.phase == Phase::Observing {
        record.health_started_at_ms = Some(now);
    }
}

pub(super) fn advance(
    record: &mut Record,
    known: &[HostStatus],
    registry: &EngineHosts,
    now: u64,
    deliveries: &mut Vec<OwnerCommand>,
) -> io::Result<()> {
    if matches!(record.phase, Phase::Preparing | Phase::Prepared)
        && now >= record.preparing_deadline_ms
    {
        fail(
            record,
            Failure {
                reason: "upgrade preparation timed out".into(),
                restart: false,
            },
        );
    }
    for index in 0..record.participants.len() {
        if record.participants[index].exited {
            continue;
        }
        let identity = record.participants[index].identity.clone();
        let failed = registry.process_failure(&identity, record.created_at_ms);
        if let Some(reason) = &failed {
            fail(
                record,
                Failure {
                    reason: reason.clone(),
                    restart: record.finalize_decided,
                },
            );
        }
        let normal = registry.normal_exit(&identity);
        let gone = gone(&identity);
        if normal || gone {
            let participant = &mut record.participants[index];
            let started = *participant.exit_wait_started_ms.get_or_insert(now);
            if normal || failed.is_some() || now.saturating_sub(started) >= 2000 {
                participant.exited = true;
                participant.exit_clean = normal && failed.is_none();
                participant.cleanup_done = true;
                participant.finalized = true;
                participant.stage = Some(Stage::Complete);
                participant.pending = None;
                participant.reason = Some(
                    if normal {
                        "managed process exited normally"
                    } else {
                        "managed process exited without a normal completion proof"
                    }
                    .into(),
                );
                if !normal
                    && failed.is_none()
                    && !matches!(record.phase, Phase::Finalizing | Phase::Draining)
                {
                    fail(
                        record,
                        Failure {
                            reason: "managed process exit proof is unavailable".into(),
                            restart: false,
                        },
                    );
                }
            }
            continue;
        }
        record.participants[index].exit_wait_started_ms = None;
        let selected = known.iter().find(|host| identity.matches(host)).cloned();
        let Some(mut host) = selected else {
            continue;
        };
        rebind(record, index, &host, now);
        let phase = record.phase;
        let participant = &mut record.participants[index];
        if let Some(pending) = participant.pending.clone() {
            match registry.command(&pending.request.request_id) {
                Some(status) if status.state == DeliveryState::Acknowledged => {
                    participant.pending = None;
                    let failure = accept(
                        participant,
                        phase,
                        &record.id,
                        &record.manifest,
                        pending.purpose,
                        status.reply.ok_or_else(|| {
                            io::Error::other("Host acknowledgement has no result")
                        })?,
                    );
                    if let Some(failure) = failure {
                        fail(record, failure);
                    }
                    // Read a report at least as new as the acknowledgement.
                    // A pre-ACK snapshot can otherwise look like a rollback.
                    if let Some(updated) = registry.host(Some(&host.host_id)).into_iter().next() {
                        host = updated;
                    }
                }
                Some(status) if status.state == DeliveryState::Unknown => {
                    participant.pending = None;
                    participant.recovering = true;
                }
                _ if now.saturating_sub(pending.request.issued_at_ms) >= 35_000 => {
                    participant.pending = None;
                    participant.recovering = true;
                }
                _ => {}
            }
        }
        let participant = &mut record.participants[index];
        if participant.confirmed
            && !participant.recovering
            && matches!(record.phase, Phase::Committed | Phase::Observing)
            && Some(host.snapshot.active.generation) != participant.generation
        {
            participant.recovering = true;
            fail(
                record,
                Failure {
                    reason: "new Host generation failed before global finalization".into(),
                    restart: false,
                },
            );
        }
        let participant = &mut record.participants[index];
        if record.phase == Phase::Draining && participant.finalized {
            if let Some(generation) = participant.generation {
                if host.snapshot.active.generation >= generation
                    && !host
                        .snapshot
                        .retired
                        .iter()
                        .any(|old| old.generation < generation)
                {
                    participant.stage = Some(Stage::Complete);
                }
            }
        }
        if participant.pending.is_none() && !participant.exited {
            let desired = if participant.recovering {
                Some((
                    Purpose::Recover,
                    Command::QueryTransaction {
                        id: record.id.clone(),
                    },
                ))
            } else {
                desired(record, index)
            };
            if let Some((purpose, command)) = desired {
                let participant = &mut record.participants[index];
                participant.sequence = participant
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("upgrade command sequence exhausted"))?;
                participant.pending = Some(Pending {
                    purpose,
                    request: OwnerCommand {
                        request_id: format!(
                            "rollout-{}-{index}-{}",
                            record.id, participant.sequence
                        ),
                        host_id: participant.host_id.clone(),
                        issued_at_ms: now,
                        command,
                    },
                });
            }
        }
        if let Some(pending) = &record.participants[index].pending {
            deliveries.push(pending.request.clone());
        }
    }
    finish_phase(record, known, now);
    Ok(())
}

fn desired(record: &Record, index: usize) -> Option<(Purpose, Command)> {
    let participant = &record.participants[index];
    let id = record.id.clone();
    match record.phase {
        Phase::Preparing
        | Phase::Switching
        | Phase::Committed
        | Phase::Observing
        | Phase::Finalizing
            if participant.stage.is_none() && !participant.confirmed =>
        {
            Some((
                Purpose::Prepare,
                Command::Prepare {
                    id,
                    manifest: record.manifest.clone(),
                    source: record.source.clone(),
                    cache: record.cache.clone(),
                },
            ))
        }
        Phase::Switching | Phase::Committed | Phase::Observing | Phase::Finalizing
            if !participant.confirmed && participant.stage == Some(Stage::Prepared) =>
        {
            Some((Purpose::Commit, Command::CommitHeld { id }))
        }
        Phase::Aborting | Phase::RollingBack if !participant.cleanup_done => {
            if participant.confirmed && participant.stage != Some(Stage::RolledBack) {
                Some((
                    Purpose::Rollback,
                    Command::Rollback {
                        id,
                        reason: record
                            .reason
                            .clone()
                            .unwrap_or_else(|| "group upgrade failed".into()),
                    },
                ))
            } else if participant.stage.is_some() {
                Some((Purpose::Abort, Command::Abort { id }))
            } else {
                Some((Purpose::Recover, Command::QueryTransaction { id }))
            }
        }
        Phase::Finalizing
            if participant.confirmed && !participant.finalized && !participant.cleanup_done =>
        {
            Some((Purpose::Finalize, Command::FinalizeObservation { id }))
        }
        _ => None,
    }
}

fn accept(
    participant: &mut Participant,
    phase: Phase,
    id: &str,
    manifest: &hyperhub_runtime::Manifest,
    purpose: Purpose,
    reply: Reply,
) -> Option<Failure> {
    match reply {
        Reply::Transaction { transaction }
            if transaction.id == id && &transaction.manifest == manifest =>
        {
            participant.stage = Some(transaction.stage);
            participant.reason = transaction.reason.clone();
            participant.recovering = false;
            if let Some(generation) = transaction.generation {
                participant.generation = Some(generation);
            }
            if matches!(transaction.stage, Stage::Draining | Stage::Complete) {
                participant.confirmed = true;
            }
            if matches!(transaction.stage, Stage::RolledBack | Stage::Aborted) {
                participant.cleanup_done = true;
            }
            match purpose {
                Purpose::Prepare if transaction.stage != Stage::Prepared => Some(Failure {
                    reason: transaction.reason.unwrap_or_else(|| {
                        format!("Host preparation returned {:?}", transaction.stage)
                    }),
                    restart: transaction.stage == Stage::RequiresRestart,
                }),
                Purpose::Commit
                    if !matches!(transaction.stage, Stage::Draining | Stage::Complete) =>
                {
                    Some(Failure {
                        reason: "Host commit did not select the candidate".into(),
                        restart: false,
                    })
                }
                Purpose::Abort => {
                    participant.cleanup_done = true;
                    None
                }
                Purpose::Rollback if transaction.stage != Stage::RolledBack => {
                    participant.cleanup_done = true;
                    Some(Failure {
                        reason: "Host could not confirm rollback; requires_restart".into(),
                        restart: true,
                    })
                }
                Purpose::Rollback => {
                    participant.cleanup_done = true;
                    None
                }
                Purpose::Finalize
                    if matches!(transaction.stage, Stage::Draining | Stage::Complete) =>
                {
                    participant.finalized = true;
                    None
                }
                Purpose::Finalize => {
                    participant.cleanup_done = true;
                    Some(Failure {
                        reason: "Host finalization is inconsistent; requires_restart".into(),
                        restart: true,
                    })
                }
                Purpose::Recover
                    if matches!(
                        transaction.stage,
                        Stage::RolledBack | Stage::Aborted | Stage::Failed | Stage::RequiresRestart
                    ) && !matches!(phase, Phase::Aborting | Phase::RollingBack) =>
                {
                    Some(Failure {
                        reason: transaction
                            .reason
                            .unwrap_or_else(|| "Host transaction is no longer viable".into()),
                        restart: transaction.stage == Stage::RequiresRestart,
                    })
                }
                _ => None,
            }
        }
        Reply::Error { code, message } => {
            participant.reason = Some(message.clone());
            if purpose == Purpose::Recover && code == "not_prepared" && !participant.confirmed {
                participant.recovering = false;
                participant.stage = None;
                if matches!(phase, Phase::Aborting | Phase::RollingBack) {
                    participant.cleanup_done = true;
                }
                return None;
            }
            if matches!(purpose, Purpose::Rollback | Purpose::Finalize)
                && matches!(code.as_str(), "not_prepared" | "already_committed")
            {
                participant.cleanup_done = true;
                participant.recovering = false;
                return Some(Failure {
                    reason: format!(
                        "Host cannot reconcile {purpose:?}: {message}; requires_restart"
                    ),
                    restart: true,
                });
            }
            participant.recovering = true;
            Some(Failure {
                reason: format!("Host {purpose:?} failed: {message}"),
                restart: code == "requires_restart",
            })
        }
        _ => {
            participant.recovering = true;
            Some(Failure {
                reason: "Host acknowledgement does not match the transaction".into(),
                restart: true,
            })
        }
    }
}

fn fail(record: &mut Record, failure: Failure) {
    record.restart_requested |= failure.restart;
    if record.reason.is_none() {
        record.reason = Some(failure.reason);
    }
    if record.phase == Phase::Finalizing {
        return;
    }
    if record.phase == Phase::Draining {
        record.phase = Phase::RequiresRestart;
        return;
    }
    if !matches!(record.phase, Phase::Aborting | Phase::RollingBack) {
        record.phase = if matches!(record.phase, Phase::Preparing | Phase::Prepared) {
            Phase::Aborting
        } else {
            Phase::RollingBack
        };
    }
}

fn finish_phase(record: &mut Record, known: &[HostStatus], now: u64) {
    match record.phase {
        Phase::Preparing
            if record
                .participants
                .iter()
                .all(|p| p.exited || (p.stage == Some(Stage::Prepared) && p.pending.is_none())) =>
        {
            record.phase = Phase::Prepared
        }
        Phase::Switching
            if record
                .participants
                .iter()
                .all(|p| p.exited || (p.confirmed && p.pending.is_none())) =>
        {
            record.phase = Phase::Committed
        }
        Phase::Observing => {
            let elapsed = now.saturating_sub(record.health_started_at_ms.unwrap_or(now));
            let fresh = healthy(record, known, now);
            if !record.defer_finalize && elapsed >= record.health_window_ms && fresh {
                // Driver persists this global decision before a finalize send.
                record.finalize_decided = true;
                record.phase = Phase::Finalizing;
            }
        }
        Phase::Finalizing
            if record
                .participants
                .iter()
                .all(|p| p.finalized || p.cleanup_done) =>
        {
            record.phase = if record.restart_requested {
                Phase::RequiresRestart
            } else {
                Phase::Draining
            }
        }
        Phase::Draining
            if record
                .participants
                .iter()
                .all(|p| p.stage == Some(Stage::Complete) || p.exited) =>
        {
            record.phase = Phase::Complete
        }
        Phase::Aborting | Phase::RollingBack
            if record
                .participants
                .iter()
                .all(|p| p.cleanup_done && p.pending.is_none()) =>
        {
            record.phase = if record.restart_requested {
                Phase::RequiresRestart
            } else if record
                .participants
                .iter()
                .any(|p| p.exited && !p.exit_clean)
            {
                Phase::Failed
            } else if record.rollback_requested {
                Phase::RolledBack
            } else if record.phase == Phase::RollingBack {
                Phase::RolledBack
            } else if record.reason.is_some() {
                Phase::Failed
            } else {
                Phase::Aborted
            };
        }
        _ => {}
    }
}

pub(super) fn gone(identity: &Identity) -> bool {
    EngineHosts::process_is_gone(identity.host_pid, identity.host_start_time)
}

pub(super) fn healthy(record: &Record, known: &[HostStatus], now: u64) -> bool {
    record.participants.iter().all(|p| {
        p.exited
            || (p.confirmed
                && !p.recovering
                && p.pending.is_none()
                && known.iter().any(|host| {
                    p.identity.matches(host)
                        && now.saturating_sub(host.last_seen_ms) < 2500
                        && Some(host.snapshot.active.generation) == p.generation
                }))
    })
}
