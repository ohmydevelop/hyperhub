use super::{
    store::Store, Action, Identity, Participant, Phase, Record, RecordView, Request, Status,
};
use crate::engine_hosts::EngineHosts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[path = "actions.rs"]
mod actions;
#[path = "admission.rs"]
mod admission;
#[path = "participant.rs"]
mod participant;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Book {
    records: BTreeMap<String, Record>,
    #[serde(default)]
    finalize_order: u64,
}
struct State {
    book: Book,
    store: Store,
    error: Option<String>,
    recovery_dirty: bool,
}
impl State {
    fn persist(&mut self, book: Book) -> io::Result<()> {
        if let Some(error) = &self.error {
            return Err(io::Error::other(error.clone()));
        }
        if let Err(error) = self.store.save(&book) {
            // Rename may have happened before directory fsync failed. Freeze
            // further actions until the authenticated log is reopened.
            self.error = Some(format!(
                "upgrade journal write failed; recovery required: {error}"
            ));
            return Err(error);
        }
        self.book = book;
        self.recovery_dirty = false;
        Ok(())
    }
}
struct Inner {
    state: Mutex<State>,
    hosts: EngineHosts,
    runner: Mutex<Option<tokio::task::AbortHandle>>,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
    health_window_ms: u64,
    prepare_timeout_ms: u64,
    published: RwLock<Published>,
}
struct Published {
    records: BTreeMap<String, RecordView>,
    error: Option<String>,
    busy: bool,
}
impl Published {
    fn from_state(state: &State) -> Self {
        Self {
            records: state
                .book
                .records
                .iter()
                .map(|(id, record)| (id.clone(), RecordView::from_record(record, true)))
                .collect(),
            error: state.error.clone(),
            busy: state.error.is_some()
                || state
                    .book
                    .records
                    .values()
                    .any(|record| !record.phase.terminal() && record.phase != Phase::Draining),
        }
    }
}
#[derive(Clone)]
pub struct Coordinator(Arc<Inner>);

impl Coordinator {
    pub fn open(directory: &Path, key: Zeroizing<Vec<u8>>, hosts: EngineHosts) -> io::Result<Self> {
        Self::open_with_limits(
            directory,
            key,
            hosts,
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
    }
    pub(crate) fn open_with_limits(
        directory: &Path,
        key: Zeroizing<Vec<u8>>,
        hosts: EngineHosts,
        prepare: Duration,
        health: Duration,
    ) -> io::Result<Self> {
        let epoch = crate::session::unix_timestamp_ms();
        let started = Instant::now();
        let now = Arc::new(move || {
            epoch.saturating_add(started.elapsed().as_millis().min(u64::MAX as u128) as u64)
        });
        let store = Store::open(directory, key)?;
        let mut book: Book = store.load()?.unwrap_or_default();
        if book.records.len() > 128 {
            return Err(io::Error::other(
                "upgrade journal transaction limit exceeded",
            ));
        }
        let mut recovery_dirty = false;
        for record in book
            .records
            .values_mut()
            .filter(|record| !record.phase.terminal())
        {
            if record.participants.len() > 256 || !super::valid_id(&record.id) {
                return Err(io::Error::other("upgrade journal record is invalid"));
            }
            for participant in &mut record.participants {
                participant.pending = None;
                participant.recovering = true;
            }
            record.preparing_deadline_ms = record
                .preparing_deadline_ms
                .min(epoch.saturating_add(prepare.as_millis().min(u64::MAX as u128) as u64));
            if record.phase == Phase::Observing {
                // Do not count unobserved coordinator downtime as healthy time.
                record.health_started_at_ms = Some(epoch);
            }
            recovery_dirty = true;
        }
        let state = State {
            book,
            store,
            error: None,
            recovery_dirty,
        };
        let published = RwLock::new(Published::from_state(&state));
        Ok(Self(Arc::new(Inner {
            state: Mutex::new(state),
            hosts,
            runner: Mutex::new(None),
            now,
            health_window_ms: health.as_millis().min(u64::MAX as u128) as u64,
            prepare_timeout_ms: prepare.as_millis().min(u64::MAX as u128) as u64,
            published,
        })))
    }
    pub fn spawn(&self) -> Option<tokio::task::JoinHandle<()>> {
        let mut runner = self.0.runner.lock().ok()?;
        if runner.as_ref().is_some_and(|handle| !handle.is_finished()) {
            return None;
        }
        let weak = Arc::downgrade(&self.0);
        let handle = tokio::spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                let coordinator = Self(inner);
                if tokio::task::spawn_blocking(move || coordinator.tick())
                    .await
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        *runner = Some(handle.abort_handle());
        Some(handle)
    }
    pub fn stop_runner(&self) {
        if let Ok(runner) = self.0.runner.lock() {
            if let Some(handle) = runner.as_ref() {
                handle.abort();
            }
        }
    }
    pub fn runner_running(&self) -> bool {
        self.0
            .runner
            .lock()
            .map(|runner| runner.as_ref().is_some_and(|handle| !handle.is_finished()))
            .unwrap_or(false)
    }
    pub async fn submit(&self, request: Request) -> io::Result<Record> {
        let coordinator = self.clone();
        tokio::task::spawn_blocking(move || coordinator.submit_sync(request))
            .await
            .map_err(io::Error::other)?
    }
    pub fn status(&self, id: Option<&str>) -> Status {
        match self.0.published.read() {
            Ok(state) => {
                let mut records: Vec<_> = state
                    .records
                    .values()
                    .filter(|r| id.is_none_or(|id| r.id == id))
                    .collect();
                // A caller-chosen ID must not hide the current transaction
                // behind old terminal history in a bounded summary.
                records.sort_by_key(|record| {
                    (
                        record.phase.terminal(),
                        std::cmp::Reverse(record.updated_at_ms),
                        std::cmp::Reverse(record.created_at_ms),
                        &record.id,
                    )
                });
                Status {
                    records: records
                        .into_iter()
                        .take(if id.is_some() { 1 } else { 32 })
                        .map(|record| {
                            let mut view = record.clone();
                            if id.is_none() {
                                view.participants_omitted = view.participants.len();
                                view.participants.clear();
                            }
                            view
                        })
                        .collect(),
                    records_omitted: if id.is_some() {
                        0
                    } else {
                        state.records.len().saturating_sub(32)
                    },
                    error: state.error.clone(),
                }
            }
            Err(_) => Status {
                records: vec![],
                records_omitted: 0,
                error: Some("upgrade coordinator state poisoned".into()),
            },
        }
    }
    pub(crate) fn busy(&self) -> bool {
        self.0
            .published
            .read()
            .map(|state| state.busy)
            .unwrap_or(true)
    }
    fn submit_sync(&self, request: Request) -> io::Result<Record> {
        if !super::valid_id(&request.id) {
            return Err(io::Error::other("invalid upgrade transaction ID"));
        }
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("upgrade coordinator poisoned"))?;
        if matches!(request.action, Action::Recover) {
            let mut book: Book = state
                .store
                .load()?
                .ok_or_else(|| io::Error::other("upgrade journal is missing"))?;
            let now = (self.0.now)();
            for record in book
                .records
                .values_mut()
                .filter(|record| !record.phase.terminal())
            {
                for participant in &mut record.participants {
                    participant.pending = None;
                    participant.recovering = true;
                }
                record.preparing_deadline_ms = record
                    .preparing_deadline_ms
                    .min(now.saturating_add(self.0.prepare_timeout_ms));
                if record.phase == Phase::Observing {
                    record.health_started_at_ms = Some(now);
                }
            }
            let result = book
                .records
                .get(&request.id)
                .ok_or_else(|| io::Error::other("unknown upgrade transaction"))?
                .clone();
            // Revalidate the authenticated file before allowing a previously
            // frozen writer to resume. An invalid file remains untouched.
            state.error = None;
            let saved = state.persist(book);
            self.publish(&state);
            saved?;
            return Ok(result);
        }
        if let Some(error) = &state.error {
            return Err(io::Error::other(error.clone()));
        }
        let mut book = state.book.clone();
        let now = (self.0.now)();
        actions::apply(&self.0, &mut book, &request, now)?;
        order_finalizations(&mut book)?;
        let result = book
            .records
            .get(&request.id)
            .ok_or_else(|| io::Error::other("unknown upgrade transaction"))?
            .clone();
        let saved = state.persist(book);
        self.publish(&state);
        saved?;
        Ok(result)
    }
    pub(crate) fn tick(&self) -> io::Result<()> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("upgrade coordinator poisoned"))?;
        if let Some(error) = &state.error {
            return Err(io::Error::other(error.clone()));
        }
        let mut book = state.book.clone();
        let now = (self.0.now)();
        let hosts = self.0.hosts.host(None);
        let mut changed = state.recovery_dirty;
        let mut deliveries = Vec::new();
        for record in book.records.values_mut().filter(|r| !r.phase.terminal()) {
            let before = serde_json::to_vec(record).map_err(io::Error::other)?;
            participant::advance(record, &hosts, &self.0.hosts, now, &mut deliveries)?;
            if before != serde_json::to_vec(record).map_err(io::Error::other)? {
                record.updated_at_ms = now;
                changed = true;
            }
        }
        order_finalizations(&mut book)?;
        // Every new intent and the irreversible finalize decision reach disk
        // before the first corresponding message leaves the coordinator.
        if changed {
            let saved = state.persist(book);
            self.publish(&state);
            saved?;
        }
        for delivery in deliveries {
            // Full/offline queues retain their durable intent for retry. The
            // Host registry deduplicates a previously accepted delivery.
            let _ = self.0.hosts.dispatch_coordinated(delivery);
        }
        let pending = state
            .book
            .records
            .values()
            .flat_map(|record| {
                record.participants.iter().filter_map(|participant| {
                    participant
                        .pending
                        .as_ref()
                        .map(|pending| pending.request.request_id.clone())
                })
            })
            .collect();
        self.0.hosts.retire_coordinated(&pending);
        let referenced = state
            .book
            .records
            .values()
            .filter(|record| !record.phase.terminal())
            .flat_map(|record| record.participants.iter().filter(|p| !p.exited))
            .map(|p| {
                (
                    p.identity.session_id.clone(),
                    p.identity.host_pid,
                    p.identity.host_start_time,
                )
            })
            .collect();
        // Retire exit evidence only after its group result is in the journal.
        // Online Hosts and recent unconsumed reports retain independent grace.
        self.0.hosts.retire_exit_evidence(&referenced);
        // Preserve intent ordering across runner interruption and recovery.
        // Dispatch only enqueues a command; it performs no target or file IO.
        drop(state);
        Ok(())
    }
    fn publish(&self, state: &State) {
        // Build outside the publication lock. Status never waits for journal IO.
        let next = Published::from_state(state);
        if let Ok(mut published) = self.0.published.write() {
            *published = next;
        }
    }
}

pub(super) fn fingerprint(value: &impl Serialize) -> io::Result<String> {
    Ok(hyperhub_runtime::artifact::hex(&Sha256::digest(
        serde_json::to_vec(value).map_err(io::Error::other)?,
    )))
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

fn order_finalizations(book: &mut Book) -> io::Result<()> {
    for record in book
        .records
        .values_mut()
        .filter(|r| r.finalize_decided && r.finalize_order == 0)
    {
        book.finalize_order = book
            .finalize_order
            .checked_add(1)
            .ok_or_else(|| io::Error::other("deployment order exhausted"))?;
        record.finalize_order = book.finalize_order;
    }
    Ok(())
}
