use super::*;
use crate::engine_hosts::{DeliveryState, HostStatus, OwnerCommand};
use crate::upgrade::{Pending, Purpose};
use hyperhub_engine::management::{Command, Reply};
use hyperhub_runtime::Stage;

struct Failure {
    reason: String,
    restart: bool,
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
        let selected = known
            .iter()
            .find(|host| record.participants[index].identity.matches(host))
            .cloned();
        let Some(mut host) = selected else {
            let participant = &mut record.participants[index];
            if gone(&participant.identity) {
                participant.exited = true;
                participant.cleanup_done = true;
                participant.pending = None;
                participant.reason = Some("target process exited".into());
                if !matches!(record.phase, Phase::Finalizing | Phase::Draining) {
                    fail(
                        record,
                        Failure {
                            reason: "target process exited during upgrade".into(),
                            restart: false,
                        },
                    );
                }
            }
            continue;
        };
        let phase = record.phase;
        let participant = &mut record.participants[index];
        if participant.host_id != host.host_id {
            participant.host_id = host.host_id.clone();
            participant.pending = None;
            participant.recovering = true;
        }
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
        Phase::Preparing if participant.stage.is_none() => Some((
            Purpose::Prepare,
            Command::Prepare {
                id,
                manifest: record.manifest.clone(),
                source: record.source.clone(),
                cache: record.cache.clone(),
            },
        )),
        Phase::Switching
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
        Phase::Finalizing if !participant.finalized && !participant.cleanup_done => {
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
                .all(|p| p.stage == Some(Stage::Prepared) && p.pending.is_none()) =>
        {
            record.phase = Phase::Prepared
        }
        Phase::Switching
            if record
                .participants
                .iter()
                .all(|p| p.confirmed && p.pending.is_none()) =>
        {
            record.phase = Phase::Committed
        }
        Phase::Observing => {
            let elapsed = now.saturating_sub(record.health_started_at_ms.unwrap_or(now));
            let fresh = record.participants.iter().all(|p| {
                known.iter().any(|host| {
                    p.identity.matches(host)
                        && now.saturating_sub(host.last_seen_ms) < 2500
                        && Some(host.snapshot.active.generation) == p.generation
                })
            });
            if elapsed >= record.health_window_ms && fresh {
                // Driver persists this global decision before a finalize send.
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
            } else if record.participants.iter().any(|p| p.exited) {
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

fn gone(identity: &Identity) -> bool {
    if let Some(start) = crate::session::process_start_time(identity.root_pid) {
        return start != identity.root_start_time;
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::metadata(format!("/proc/{}", identity.root_pid))
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, GetLastError, ERROR_INVALID_PARAMETER},
            System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        };
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, identity.root_pid);
        if process.is_null() {
            GetLastError() == ERROR_INVALID_PARAMETER
        } else {
            CloseHandle(process);
            false
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}
