//! Startup stays suspended until a new Host has joined its session's durable
//! transaction, including decisions that raced with bootstrap selection.
use super::*;
use hyperhub_engine::bootstrap::{Candidate, Deployment};
use hyperhub_runtime::{Manifest, Stage};

fn scoped(record: &Record, session: &str, host: &Manifest, native_base: &str) -> bool {
    record.native_base_sha256 == native_base
        && record.manifest.target == host.target
        && (if record.all_sessions {
            super::super::not_older(&record.manifest, host)
        } else {
            record
                .participants
                .iter()
                .any(|p| p.identity.session_id == session)
        })
}
fn deployment(record: &Record) -> Deployment {
    Deployment {
        manifest: record.manifest.clone(),
        source: record.source.clone(),
        cache: record.cache.clone(),
    }
}
fn active_matches(host: &crate::engine_hosts::HostStatus, manifest: &Manifest) -> bool {
    if host.snapshot.active.generation == 0 {
        return host.snapshot.host == *manifest;
    }
    host.snapshot.transactions.iter().any(|t| {
        t.generation == Some(host.snapshot.active.generation)
            && matches!(t.stage, Stage::Draining | Stage::Complete)
            && t.manifest == *manifest
    })
}
fn latest_stable<'a>(
    book: &'a Book,
    session: &str,
    host: &Manifest,
    native_base: &str,
) -> Option<&'a Record> {
    book.records
        .values()
        .filter(|r| r.finalize_decided && scoped(r, session, host, native_base))
        .max_by_key(|r| (r.finalize_order, r.created_at_ms, &r.id))
}

impl Coordinator {
    pub(crate) fn bootstrap(
        &self,
        session: &str,
        host: &Manifest,
        native_base_sha256: &str,
    ) -> io::Result<(Option<Deployment>, Option<Candidate>)> {
        host.validate().map_err(io::Error::other)?;
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("upgrade coordinator poisoned"))?;
        if let Some(error) = &state.error {
            return Err(io::Error::other(error.clone()));
        }
        let stable = latest_stable(&state.book, session, host, native_base_sha256);
        let candidate = state.book.records.values().find(|r| {
            scoped(r, session, host, native_base_sha256)
                && !r.finalize_decided
                && matches!(r.phase, Phase::Committed | Phase::Observing)
                && r.participants
                    .iter()
                    .all(|p| p.exited || (p.confirmed && !p.recovering && p.pending.is_none()))
        });
        if stable
            .into_iter()
            .chain(candidate)
            .any(|r| !r.manifest.compatible_with(host))
        {
            return Err(io::Error::other(
                "session Engine deployment is incompatible; requires_restart",
            ));
        }
        Ok((
            stable.map(deployment),
            candidate.map(|r| Candidate {
                id: r.id.clone(),
                deployment: deployment(r),
            }),
        ))
    }

    /// Linearization point for admission. Registration precedes this call, so
    /// every subsequent decision includes this Host before its target resumes.
    pub(crate) fn admit(&self, host_id: &str) -> io::Result<bool> {
        let host = self
            .0
            .hosts
            .host(Some(host_id))
            .into_iter()
            .next()
            .filter(|host| host.online)
            .ok_or_else(|| io::Error::other("Engine Host left during admission"))?;
        let identity = Identity::from_host(&host)?;
        if participant::gone(&identity) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Engine Host process exited before admission",
            ));
        }
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("upgrade coordinator poisoned"))?;
        if let Some(error) = &state.error {
            return Err(io::Error::other(error.clone()));
        }
        let mut book = state.book.clone();
        let latest = latest_stable(
            &book,
            &host.session_id,
            &host.snapshot.host,
            &host.native_base_sha256,
        )
        .map(|r| r.id.clone());
        let active_candidate = host.snapshot.transactions.iter().any(|t| {
            t.generation == Some(host.snapshot.active.generation)
                && matches!(t.stage, Stage::Draining | Stage::Complete)
                && book.records.get(&t.id).is_some_and(|r| {
                    !r.finalize_decided
                        && scoped(
                            r,
                            &host.session_id,
                            &host.snapshot.host,
                            &host.native_base_sha256,
                        )
                        && r.manifest == t.manifest
                })
        });
        let needs_stable = !active_candidate
            && latest
                .as_ref()
                .and_then(|id| book.records.get(id))
                .is_some_and(|r| !active_matches(&host, &r.manifest));
        let now = (self.0.now)();
        let mut changed = false;
        let mut ready = true;
        // Resolve an older held selection first. A newer preparation must not
        // race its rollback/finalize reservation in the same native Runtime.
        let held = host
            .snapshot
            .transactions
            .iter()
            .find(|t| {
                matches!(t.stage, Stage::Draining | Stage::Complete)
                    && book.records.get(&t.id).is_some_and(|r| {
                        scoped(
                            r,
                            &host.session_id,
                            &host.snapshot.host,
                            &host.native_base_sha256,
                        ) && !r.participants.iter().any(|p| {
                            p.identity == identity
                                && p.host_id == host_id
                                && (p.finalized || p.cleanup_done)
                        })
                    })
            })
            .map(|t| t.id.clone());
        let focus = held.or_else(|| needs_stable.then(|| latest.clone()).flatten());
        for record in book.records.values_mut() {
            if !scoped(
                record,
                &host.session_id,
                &host.snapshot.host,
                &host.native_base_sha256,
            ) {
                continue;
            }
            let transaction = host
                .snapshot
                .transactions
                .iter()
                .find(|t| t.id == record.id);
            if transaction.is_some_and(|t| t.manifest != record.manifest) {
                return Err(io::Error::other(
                    "Engine enrollment transaction manifest differs; requires_restart",
                ));
            }
            let existing = record
                .participants
                .iter()
                .position(|p| p.identity == identity);
            let unfinished = !record.phase.terminal() && record.phase != Phase::Draining;
            let needs_stable = needs_stable && latest.as_deref() == Some(&record.id);
            let selected = transaction.is_some_and(|t| {
                matches!(t.stage, Stage::Prepared | Stage::Draining | Stage::Complete)
            });
            if existing.is_none() && !unfinished && !needs_stable && !selected {
                continue;
            }
            if !record.manifest.compatible_with(&host.snapshot.host) {
                return Err(io::Error::other(
                    "Engine admission capability differs; requires_restart",
                ));
            }
            if let Some(index) = existing {
                if record.participants[index].host_id != host_id
                    && (unfinished || selected || needs_stable)
                {
                    if focus.as_ref().is_some_and(|id| id != &record.id) {
                        ready = false;
                        continue;
                    }
                    if needs_stable {
                        record.participants[index].finalized = false;
                    }
                    participant::rebind(record, index, &host, now);
                    record.updated_at_ms = now;
                    changed = true;
                }
            }
            if existing.is_none() {
                if focus.as_ref().is_some_and(|id| id != &record.id) {
                    ready = false;
                    continue;
                }
                if record.participants.len() >= 256 {
                    return Err(io::Error::other(
                        "Engine transaction participant limit reached",
                    ));
                }
                let stage = transaction.map(|t| t.stage);
                let generation = transaction.and_then(|t| t.generation);
                record.participants.push(Participant {
                    identity: identity.clone(),
                    host_id: host_id.into(),
                    previous_generation: generation
                        .map_or(host.snapshot.active.generation, |g| g.saturating_sub(1)),
                    generation,
                    stage,
                    reason: None,
                    confirmed: matches!(stage, Some(Stage::Draining | Stage::Complete)),
                    finalized: false,
                    cleanup_done: false,
                    exited: false,
                    sequence: 0,
                    pending: None,
                    recovering: true,
                    exit_wait_started_ms: None,
                    exit_clean: false,
                });
                if record.finalize_decided {
                    record.phase = Phase::Finalizing;
                } else if record.phase.terminal() {
                    record.phase = if matches!(stage, Some(Stage::Draining | Stage::Complete)) {
                        Phase::RollingBack
                    } else {
                        Phase::Aborting
                    };
                } else if record.phase == Phase::Prepared {
                    record.phase = Phase::Preparing;
                    record.preparing_deadline_ms = now.saturating_add(self.0.prepare_timeout_ms);
                } else if record.phase == Phase::Observing {
                    record.health_started_at_ms = Some(now);
                }
                record.updated_at_ms = now;
                changed = true;
            }
            let p = record
                .participants
                .iter()
                .find(|p| p.identity == identity)
                .unwrap();
            if p.exited {
                return Err(io::Error::other(
                    "Engine participant process identity expired",
                ));
            }
            let settled = p.pending.is_none() && !p.recovering;
            ready &= settled
                && match record.phase {
                    Phase::Preparing | Phase::Prepared => p.stage == Some(Stage::Prepared),
                    Phase::Switching | Phase::Committed | Phase::Observing => p.confirmed,
                    Phase::Finalizing | Phase::Draining | Phase::Complete => p.finalized,
                    Phase::Aborting
                    | Phase::RollingBack
                    | Phase::Aborted
                    | Phase::RolledBack
                    | Phase::Failed => p.cleanup_done,
                    Phase::RequiresRestart => false,
                };
        }
        if changed {
            let saved = state.persist(book);
            self.publish(&state);
            saved?;
        }
        Ok(ready)
    }
}
