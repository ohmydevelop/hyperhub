use super::{installer, Action, Phase, Record, RecordView, Request, Status};
use crate::engine_hosts::EngineHosts;
use crate::socks::WorkerManager;
use crate::upgrade::{self, store::Store};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Book {
    records: BTreeMap<String, Record>,
}
struct State {
    book: Book,
    store: Store,
    error: Option<String>,
}
struct Inner {
    state: Mutex<State>,
    published: RwLock<Status>,
    key: Zeroizing<Vec<u8>>,
    engine: upgrade::Coordinator,
    hosts: EngineHosts,
    workers: WorkerManager,
    sessions: crate::session::SessionRegistry,
    directory: PathBuf,
    helper: PathBuf,
    target: PathBuf,
    helpers: Mutex<BTreeMap<String, Child>>,
    runner: Mutex<Option<tokio::task::AbortHandle>>,
    tick: tokio::sync::Mutex<()>,
    epoch: u64,
    started: Instant,
}
#[derive(Clone)]
pub struct Coordinator(Arc<Inner>);

impl Coordinator {
    pub fn open(
        directory: &Path,
        key: Zeroizing<Vec<u8>>,
        engine: upgrade::Coordinator,
        hosts: EngineHosts,
        workers: WorkerManager,
        target: &Path,
        sessions: crate::session::SessionRegistry,
    ) -> io::Result<Self> {
        let store = Store::open(directory, key.clone())?;
        let mut book: Book = store.load()?.unwrap_or_default();
        let epoch = crate::session::unix_timestamp_ms();
        for record in book
            .records
            .values_mut()
            .filter(|record| record.phase == Phase::Observing)
        {
            record.health_started_at_ms = Some(epoch);
        }
        if book.records.len() > 128
            || book
                .records
                .values()
                .any(|record| !super::valid_id(&record.id) || record.hosts.len() > 256)
        {
            return Err(io::Error::other("invalid release coordinator journal"));
        }
        // Keep an immutable helper image before any installed pathname changes.
        // The resident executable can remain mapped for arbitrarily long time.
        let executable = std::env::current_exe()?;
        let (hash, size) = installer::digest(&executable)?;
        let manifest = hyperhub_runtime::Manifest {
            version: env!("CARGO_PKG_VERSION").into(),
            target: hyperhub_engine::TARGET.into(),
            abi: hyperhub_runtime::abi::ABI_V1,
            state_schema: 1,
            hooks: 0,
            sha256: hash,
            size,
        };
        let helper = hyperhub_runtime::artifact::Artifact::install(
            &directory.join("helpers"),
            &manifest,
            std::fs::File::open(executable)?,
        )
        .map_err(io::Error::other)?;
        let helper_path = directory.join(format!(
            "helper-{}{}",
            manifest.sha256,
            std::env::consts::EXE_SUFFIX
        ));
        if !helper_path.try_exists()? {
            std::fs::hard_link(helper.path(), &helper_path)?;
        }
        if installer::digest(&helper_path)? != (manifest.sha256, size) {
            return Err(io::Error::other("resident helper image mismatch"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&helper_path, std::fs::Permissions::from_mode(0o500))?;
        }
        let status = published(&book, None, None);
        Ok(Self(Arc::new(Inner {
            state: Mutex::new(State {
                book,
                store,
                error: None,
            }),
            published: RwLock::new(status),
            key,
            engine,
            hosts,
            workers,
            sessions,
            directory: directory.to_owned(),
            helper: helper_path,
            target: target.to_owned(),
            helpers: Mutex::new(BTreeMap::new()),
            runner: Mutex::new(None),
            tick: tokio::sync::Mutex::new(()),
            epoch,
            started: Instant::now(),
        })))
    }
    pub fn spawn(&self) {
        let Ok(mut runner) = self.0.runner.lock() else {
            return;
        };
        if runner.as_ref().is_some_and(|runner| !runner.is_finished()) {
            return;
        }
        let weak = Arc::downgrade(&self.0);
        let task = tokio::spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                let coordinator = Self(inner);
                let _ = coordinator.tick().await;
                drop(coordinator);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        *runner = Some(task.abort_handle());
    }
    pub fn stop_runner(&self) {
        if let Ok(runner) = self.0.runner.lock() {
            if let Some(runner) = runner.as_ref() {
                runner.abort();
            }
        }
    }
    pub fn status(&self, id: Option<&str>) -> Status {
        let Ok(status) = self.0.published.read() else {
            return Status {
                records: vec![],
                records_omitted: 0,
                error: Some("release status unavailable".into()),
            };
        };
        let mut status = status.clone();
        if let Some(id) = id {
            status.records.retain(|record| record.id == id);
            status.records_omitted = 0;
        } else {
            status.records_omitted = status.records.len().saturating_sub(32);
            status.records.truncate(32);
        }
        status
    }
    pub async fn submit(&self, request: Request) -> io::Result<RecordView> {
        let _tick = self.0.tick.lock().await;
        let recovery = matches!(request.action, Action::Recover);
        let id = request.id.clone();
        let coordinator = self.clone();
        let result = tokio::task::spawn_blocking(move || coordinator.submit_sync(request))
            .await
            .map_err(io::Error::other)??;
        if recovery && !self.0.engine.status(Some(&id)).records.is_empty() {
            self.0
                .engine
                .submit(upgrade::Request {
                    id,
                    issued_at_ms: crate::session::unix_timestamp_ms(),
                    action: upgrade::Action::Recover,
                })
                .await?;
        }
        self.spawn();
        Ok(result)
    }
    fn submit_sync(&self, request: Request) -> io::Result<RecordView> {
        if !super::valid_id(&request.id) {
            return Err(io::Error::other("invalid release transaction id"));
        }
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("release state poisoned"))?;
        if matches!(request.action, Action::Recover) {
            let mut book: Book = state.store.load()?.ok_or_else(|| {
                io::Error::other(
                    "release journal is missing; recovery cannot discard live transactions",
                )
            })?;
            let record = book
                .records
                .get_mut(&request.id)
                .ok_or_else(|| io::Error::other("unknown release transaction"))?;
            if record.phase == Phase::InstallationPending {
                record.phase = Phase::Installing;
                record.helper_started_at_ms = None;
            }
            state.error = None;
            self.persist(&mut state, book)?;
            return Ok(state.book.records[&request.id].view());
        }
        if let Some(error) = &state.error {
            return Err(io::Error::other(error.clone()));
        }
        let mut book = state.book.clone();
        match request.action {
            Action::Prepare { plan, auto_commit } => {
                plan.bundle.validate()?;
                let digest = hyperhub_runtime::artifact::hex(&Sha256::digest(
                    serde_json::to_vec(&(&plan, auto_commit)).map_err(io::Error::other)?,
                ));
                if let Some(record) = book.records.get(&request.id) {
                    return if record.prepare_digest == digest {
                        Ok(record.view())
                    } else {
                        Err(io::Error::other("release transaction id conflict"))
                    };
                }
                reject_older_release(&book, &plan, &self.0.workers.status())?;
                if book.records.len() >= 128 {
                    return Err(io::Error::other(
                        "release journal transaction limit reached",
                    ));
                }
                if book
                    .records
                    .values()
                    .any(|r| !r.phase.terminal() && r.phase != Phase::Draining)
                {
                    return Err(io::Error::other("another release transaction is active"));
                }
                if !plan.executable.is_absolute()
                    || !plan.engine.is_absolute()
                    || !plan.cache.is_absolute()
                    || plan.target != self.0.target
                    || !installer::valid_hash(&plan.expected_target_sha256)
                {
                    return Err(io::Error::other(
                        "release artifact or installation path is invalid",
                    ));
                }
                let hosts: Vec<_> = self
                    .0
                    .hosts
                    .host(None)
                    .into_iter()
                    .filter(|h| {
                        h.online
                            && !h.host_start_time.is_some_and(|start| {
                                EngineHosts::process_is_gone(h.host_pid, start)
                            })
                    })
                    .collect();
                let requires_restart_processes =
                    uncovered_processes(&self.0.sessions.snapshot(), &hosts);
                let incompatible = plan.bundle.base != super::Base::resident()
                    || plan.bundle.target != hyperhub_engine::TARGET
                    || hosts.iter().any(|host| {
                        !plan.bundle.engine.compatible_with(&host.snapshot.host)
                            || host.native_base_sha256 != plan.bundle.base.native_base_sha256
                    });
                let now = crate::session::unix_timestamp_ms();
                book.records.insert(request.id.clone(),Record{id:request.id.clone(),plan,phase:if incompatible{Phase::RequiresRestart}else{Phase::Preparing},
                    reason:incompatible.then(||"a managed process has no compatible resident Host, or Base ABI, schema, Hook set, Frida version or target differs; requires_restart".into()),created_at_ms:now,updated_at_ms:now,
                    prepare_deadline_ms:now.saturating_add(30_000),health_started_at_ms:None,commit_requested:auto_commit,abort_requested:false,
                    finalize_decided:false,installation_confirmed:false,hosts:hosts.into_iter().map(|h|h.host_id).collect(),worker_generation:None,worker_pid:None,
                    helper_pid:None,helper_started_at_ms:None,helper_attempt:0,prepare_digest:digest,requires_restart_processes,uncovered_since_ms:None,restart_requested:incompatible});
            }
            Action::Commit => {
                book.records
                    .get_mut(&request.id)
                    .ok_or_else(|| io::Error::other("unknown release transaction"))?
                    .commit_requested = true;
            }
            Action::Abort => {
                let engine = self.0.engine.status(Some(&request.id));
                if engine.error.is_some() {
                    return Err(io::Error::other(
                        "Engine journal recovery is required before aborting this release",
                    ));
                }
                let engine_finalized = engine.records.iter().any(|engine| {
                    matches!(
                        engine.phase,
                        upgrade::Phase::Finalizing
                            | upgrade::Phase::Draining
                            | upgrade::Phase::Complete
                    )
                });
                let record = book
                    .records
                    .get_mut(&request.id)
                    .ok_or_else(|| io::Error::other("unknown release transaction"))?;
                if record.finalize_decided || engine_finalized {
                    return Err(io::Error::other(
                        "release finalize decision is irreversible",
                    ));
                }
                record.abort_requested = true;
            }
            Action::Recover => unreachable!(),
        }
        self.persist(&mut state, book)?;
        Ok(state.book.records[&request.id].view())
    }
    pub async fn acknowledge_installation(
        &self,
        ack: installer::Acknowledgement,
    ) -> io::Result<RecordView> {
        let coordinator = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = coordinator
                .0
                .state
                .lock()
                .map_err(|_| io::Error::other("release state poisoned"))?;
            let mut book = state.book.clone();
            let record = book
                .records
                .get_mut(&ack.id)
                .ok_or_else(|| io::Error::other("unknown installation job"))?;
            if !record.finalize_decided
                || record.helper_attempt != ack.attempt
                || record.plan.bundle.worker_sha256 != ack.sha256
            {
                return Err(io::Error::other(
                    "installation acknowledgement does not match the durable job",
                ));
            }
            if ack.installed {
                if installer::digest(&record.plan.target)?
                    != (
                        record.plan.bundle.worker_sha256.clone(),
                        record.plan.bundle.worker_size,
                    )
                {
                    return Err(io::Error::other(
                        "installed executable does not match acknowledgement",
                    ));
                }
                record.installation_confirmed = true;
                record.phase = Phase::Draining;
                record.reason = None;
            } else if !record.installation_confirmed {
                record.phase = Phase::InstallationPending;
                record.reason = ack.error;
            }
            record.updated_at_ms = crate::session::unix_timestamp_ms();
            let id = record.id.clone();
            coordinator.persist(&mut state, book)?;
            Ok(state.book.records[&id].view())
        })
        .await
        .map_err(io::Error::other)?
    }
    fn persist(&self, state: &mut State, book: Book) -> io::Result<()> {
        if let Some(error) = &state.error {
            return Err(io::Error::other(error.clone()));
        }
        if let Err(error) = state.store.save(&book) {
            state.error = Some(format!(
                "release journal write failed; recovery required: {error}"
            ));
            self.publish(state);
            return Err(error);
        }
        state.book = book;
        self.publish(state);
        Ok(())
    }
    fn publish(&self, state: &State) {
        if let Ok(mut status) = self.0.published.write() {
            *status = published(&state.book, state.error.clone(), None);
        }
    }
    fn save_record(&self, mut record: Record) -> io::Result<()> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("release state poisoned"))?;
        let mut book = state.book.clone();
        let current = book
            .records
            .get(&record.id)
            .ok_or_else(|| io::Error::other("release disappeared"))?;
        record.commit_requested |= current.commit_requested;
        record.abort_requested |= current.abort_requested;
        if current.installation_confirmed {
            record.installation_confirmed = true;
            if matches!(record.phase, Phase::Installing | Phase::InstallationPending) {
                record.phase = Phase::Draining;
                record.reason = None;
            }
        }
        record.updated_at_ms = crate::session::unix_timestamp_ms();
        book.records.insert(record.id.clone(), record);
        self.persist(&mut state, book)
    }
    async fn engine_action(&self, record: &Record, action: upgrade::Action) -> io::Result<()> {
        self.0
            .engine
            .submit(upgrade::Request {
                id: record.id.clone(),
                issued_at_ms: crate::session::unix_timestamp_ms(),
                action,
            })
            .await
            .map(|_| ())
    }
    async fn tick(&self) -> io::Result<()> {
        let _tick = self.0.tick.lock().await;
        // A direct acknowledgement can finish installation before the next
        // Installing tick. Reap independently of transaction phase and WAL state.
        self.0
            .helpers
            .lock()
            .map_err(|_| io::Error::other("installation helper state poisoned"))?
            .retain(|_, child| !matches!(child.try_wait(), Ok(Some(_))));
        let records = {
            let state = self
                .0
                .state
                .lock()
                .map_err(|_| io::Error::other("release state poisoned"))?;
            if state.error.is_some() {
                return Ok(());
            }
            state
                .book
                .records
                .values()
                .filter(|r| !r.phase.terminal() && r.phase != Phase::InstallationPending)
                .cloned()
                .collect::<Vec<_>>()
        };
        for mut record in records {
            if let Err(error) = self.advance(&mut record).await {
                record.restart_requested |= error.kind() == io::ErrorKind::Unsupported;
                record.reason = Some(error.to_string().chars().take(1024).collect());
                record.phase = if record.finalize_decided {
                    if record.phase == Phase::Installing {
                        Phase::InstallationPending
                    } else {
                        Phase::RequiresRestart
                    }
                } else {
                    Phase::RollingBack
                };
            }
            self.save_record(record)?;
        }
        Ok(())
    }
    async fn advance(&self, record: &mut Record) -> io::Result<()> {
        let now = self
            .0
            .epoch
            .saturating_add(self.0.started.elapsed().as_millis().min(u64::MAX as u128) as u64);
        let engine = self
            .0
            .engine
            .status(Some(&record.id))
            .records
            .into_iter()
            .next();
        if let Some(engine) = &engine {
            record.hosts = engine
                .participants
                .iter()
                .map(|participant| participant.host_id.clone())
                .collect();
        }
        if engine.as_ref().is_some_and(|r| {
            matches!(
                r.phase,
                upgrade::Phase::Finalizing | upgrade::Phase::Draining | upgrade::Phase::Complete
            )
        }) {
            record.finalize_decided = true;
        }
        if record.abort_requested && !record.finalize_decided {
            record.phase = Phase::RollingBack;
        }
        if !record.finalize_decided
            && engine.as_ref().is_some_and(|r| {
                matches!(
                    r.phase,
                    upgrade::Phase::RollingBack
                        | upgrade::Phase::RolledBack
                        | upgrade::Phase::Failed
                        | upgrade::Phase::RequiresRestart
                        | upgrade::Phase::Aborting
                        | upgrade::Phase::Aborted
                )
            })
        {
            record.reason = engine.as_ref().and_then(|r| r.reason.clone());
            record.phase = Phase::RollingBack;
        }
        match record.phase {
            Phase::Preparing => {
                reject_incompatible_hosts(&self.0.hosts.host(None), &record.plan.bundle)?;
                record.requires_restart_processes =
                    uncovered_processes(&self.0.sessions.snapshot(), &self.0.hosts.host(None));
                if !record.requires_restart_processes.is_empty() {
                    if now >= record.prepare_deadline_ms {
                        return Err(io::Error::new(io::ErrorKind::Unsupported, "managed programs did not register compatible Engine Hosts within 30 seconds; requires_restart"));
                    }
                    record.reason =
                        Some("waiting for managed programs to register their Engine Hosts".into());
                    return Ok(());
                }
                record.reason = None;
                if now >= record.prepare_deadline_ms {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "release preparation exceeded 30 seconds",
                    ));
                }
                let expected_engine = (
                    record.plan.bundle.engine.sha256.clone(),
                    record.plan.bundle.engine.size,
                );
                if installer::digest(&record.plan.engine)? != expected_engine {
                    return Err(io::Error::other("release Engine digest or size mismatch"));
                }
                let manager = self.0.workers.clone();
                let id = record.id.clone();
                let path = record.plan.executable.clone();
                let hash = record.plan.bundle.worker_sha256.clone();
                let manifest = record.plan.bundle.engine.clone();
                let source = record.plan.engine.clone();
                let cache = record.plan.cache.clone();
                let worker = tokio::task::spawn_blocking(move || {
                    manager.prepare_bundle(&id, &path, &hash, &manifest, &source, &cache)
                })
                .await
                .map_err(io::Error::other)??;
                record.worker_generation = Some(worker.generation);
                record.worker_pid = Some(worker.pid);
                if worker.version != record.plan.bundle.version {
                    return Err(io::Error::other(
                        "candidate worker version differs from its release bundle",
                    ));
                }
                self.engine_action(
                    record,
                    upgrade::Action::PrepareAll {
                        native_base_sha256: record.plan.bundle.base.native_base_sha256.clone(),
                        manifest: record.plan.bundle.engine.clone(),
                        source: record.plan.engine.clone(),
                        cache: record.plan.cache.clone(),
                        hosts: Vec::new(),
                    },
                )
                .await?;
                if self
                    .0
                    .engine
                    .status(Some(&record.id))
                    .records
                    .first()
                    .is_some_and(|r| r.phase == upgrade::Phase::Prepared)
                {
                    record.phase = Phase::Prepared;
                }
            }
            Phase::Prepared if record.commit_requested => record.phase = Phase::Switching,
            Phase::Switching => {
                let worker = self.0.workers.commit(&record.id)?;
                record.worker_generation = Some(worker.generation);
                record.worker_pid = Some(worker.pid);
                if !worker.healthy {
                    return Err(io::Error::other(
                        "candidate forwarding worker failed during commit",
                    ));
                }
                match self.engine_action(record, upgrade::Action::Commit).await {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    result => result?,
                }
                if self
                    .0
                    .engine
                    .status(Some(&record.id))
                    .records
                    .first()
                    .is_some_and(|r| r.phase == upgrade::Phase::Committed)
                {
                    record.phase = Phase::Observing;
                    record.health_started_at_ms = Some(now);
                }
            }
            Phase::Observing => {
                if !record.finalize_decided {
                    reject_incompatible_hosts(&self.0.hosts.host(None), &record.plan.bundle)?;
                }
                record.requires_restart_processes =
                    uncovered_processes(&self.0.sessions.snapshot(), &self.0.hosts.host(None));
                if !record.finalize_decided && !record.requires_restart_processes.is_empty() {
                    let started = *record.uncovered_since_ms.get_or_insert(now);
                    if now.saturating_sub(started) >= 30_000 {
                        return Err(io::Error::new(io::ErrorKind::Unsupported, "new managed programs have no compatible Engine Hosts; requires_restart"));
                    }
                    record.reason =
                        Some("waiting for new managed programs to join the upgrade".into());
                    return Ok(());
                }
                record.uncovered_since_ms = None;
                record.reason = None;
                let workers = self.0.workers.status();
                if !workers.workers.iter().any(|worker| {
                    Some(worker.generation) == record.worker_generation && worker.healthy
                }) {
                    return Err(io::Error::other(
                        "candidate forwarding worker failed health observation",
                    ));
                }
                if record.finalize_decided {
                    record.phase = Phase::Finalizing;
                } else {
                    self.engine_action(record, upgrade::Action::ObserveHeld)
                        .await?;
                    if engine
                        .as_ref()
                        .and_then(|engine| engine.health_started_at_ms)
                        .is_some_and(|started| now.saturating_sub(started) >= 30_000)
                    {
                        match self.engine_action(record, upgrade::Action::Finalize).await {
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => return Err(error),
                            Ok(()) => {
                                record.finalize_decided = true;
                                record.phase = Phase::Finalizing;
                            }
                        }
                    }
                }
            }
            Phase::Finalizing => {
                if !record.finalize_decided {
                    return Err(io::Error::other(
                        "missing durable release finalize decision",
                    ));
                }
                self.0.workers.finalize(&record.id)?;
                record.phase = Phase::Installing;
            }
            Phase::Installing => self.install(record, now)?,
            Phase::Draining => {
                let workers = self.0.workers.query(&record.id)?;
                if workers.phase == "complete"
                    && engine
                        .as_ref()
                        .is_some_and(|e| e.phase == upgrade::Phase::Complete)
                {
                    record.phase = Phase::Complete;
                }
            }
            Phase::RollingBack => {
                if record.finalize_decided {
                    return Err(io::Error::other(
                        "cannot roll back an irreversible release decision",
                    ));
                }
                let worker = self.0.workers.query(&record.id);
                if let Ok(worker) = worker {
                    if !matches!(worker.phase.as_str(), "failed" | "aborted" | "rolled_back") {
                        if let Err(error) = self.0.workers.rollback(&record.id) {
                            record.restart_requested = true;
                            record.reason =
                                Some(format!("worker rollback could not be confirmed: {error}"));
                        }
                    }
                }
                if let Some(engine) = engine {
                    match engine.phase {
                        upgrade::Phase::Preparing | upgrade::Phase::Prepared => {
                            self.engine_action(record, upgrade::Action::Abort).await?
                        }
                        upgrade::Phase::Switching
                        | upgrade::Phase::Committed
                        | upgrade::Phase::Observing => {
                            self.engine_action(
                                record,
                                upgrade::Action::Rollback {
                                    reason: record
                                        .reason
                                        .clone()
                                        .unwrap_or_else(|| "release aborted".into()),
                                },
                            )
                            .await?
                        }
                        upgrade::Phase::RolledBack
                        | upgrade::Phase::Aborted
                        | upgrade::Phase::Failed => {
                            record.phase = if record.restart_requested
                                || !record.requires_restart_processes.is_empty()
                            {
                                Phase::RequiresRestart
                            } else {
                                Phase::RolledBack
                            }
                        }
                        upgrade::Phase::RequiresRestart => record.phase = Phase::RequiresRestart,
                        _ => {}
                    }
                } else {
                    record.phase = if record.restart_requested {
                        Phase::RequiresRestart
                    } else {
                        Phase::RolledBack
                    };
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn install(&self, record: &mut Record, now: u64) -> io::Result<()> {
        if record.installation_confirmed {
            record.phase = Phase::Draining;
            return Ok(());
        }
        if let Some(started) = record.helper_started_at_ms {
            let receipt = self.0.directory.join(format!(
                "install-{}-{}.ack.json",
                record.id, record.helper_attempt
            ));
            match installer::SignedAcknowledgement::read(&receipt, &self.0.key) {
                Ok(signed) => {
                    let ack = signed.ack;
                    if ack.id != record.id
                        || ack.attempt != record.helper_attempt
                        || ack.sha256 != record.plan.bundle.worker_sha256
                    {
                        return Err(io::Error::other(
                            "persisted installation receipt does not match this job",
                        ));
                    }
                    if ack.installed
                        && installer::digest(&record.plan.target)?
                            == (
                                record.plan.bundle.worker_sha256.clone(),
                                record.plan.bundle.worker_size,
                            )
                    {
                        record.installation_confirmed = true;
                        record.phase = Phase::Draining;
                        record.reason = None;
                        return Ok(());
                    }
                    record.phase = Phase::InstallationPending;
                    record.reason = ack.error.or_else(|| {
                        Some(
                            "installation receipt could not confirm the installed executable"
                                .into(),
                        )
                    });
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let mut helpers = self
                .0
                .helpers
                .lock()
                .map_err(|_| io::Error::other("installation helper state poisoned"))?;
            if let Some(child) = helpers.get_mut(&record.id) {
                if child.try_wait()?.is_some() {
                    helpers.remove(&record.id);
                }
            }
            if helpers.contains_key(&record.id) || now.saturating_sub(started) < 15_000 {
                return Ok(());
            }
            record.phase = Phase::InstallationPending;
            record.reason=Some("installation helper acknowledgement missing; recover to query and retry installation".into());
            return Ok(());
        }
        record.helper_attempt = record
            .helper_attempt
            .checked_add(1)
            .ok_or_else(|| io::Error::other("installation attempt count exhausted"))?;
        record.helper_started_at_ms = Some(now);
        let job = installer::SignedJob::sign(
            installer::Job {
                id: record.id.clone(),
                attempt: record.helper_attempt,
                issued_at_ms: crate::session::unix_timestamp_ms(),
                source: record.plan.executable.clone(),
                target: record.plan.target.clone(),
                sha256: record.plan.bundle.worker_sha256.clone(),
                size: record.plan.bundle.worker_size,
                expected_target_sha256: record.plan.expected_target_sha256.clone(),
                start_after_install: false,
            },
            &self.0.key,
        )?;
        let path = self.0.directory.join(format!(
            "install-{}-{}.json",
            record.id, record.helper_attempt
        ));
        crate::config_store::save_durable_private_bytes(
            &path,
            &serde_json::to_vec(&job).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        // Journal the exact job before creating the helper process. A missing
        // acknowledgement remains uncertain and is never called complete.
        self.save_record(record.clone())?;
        let child = Command::new(&self.0.helper)
            .arg("upgrade-install-helper")
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        record.helper_pid = Some(child.id());
        self.0
            .helpers
            .lock()
            .map_err(|_| io::Error::other("installation helper state poisoned"))?
            .insert(record.id.clone(), child);
        Ok(())
    }
}
fn reject_older_release(
    book: &Book,
    plan: &super::Plan,
    workers: &crate::socks::WorkerGroupStatus,
) -> io::Result<()> {
    let candidate = upgrade::release_version(&plan.bundle.version)
        .ok_or_else(|| io::Error::other("product upgrade requires a valid semantic version"))?;
    let versions = book
        .records
        .values()
        .filter(|record| record.finalize_decided)
        .map(|record| record.plan.bundle.version.as_str())
        .chain(
            workers
                .workers
                .iter()
                .filter(|worker| worker.generation == workers.active_generation)
                .map(|worker| worker.version.as_str()),
        )
        .chain(std::iter::once(env!("CARGO_PKG_VERSION")));
    if versions
        .filter_map(upgrade::release_version)
        .any(|version| candidate < version)
    {
        return Err(io::Error::other(
            "product upgrade would downgrade a finalized or active version",
        ));
    }
    Ok(())
}

fn reject_incompatible_hosts(
    hosts: &[crate::engine_hosts::HostStatus],
    bundle: &super::Bundle,
) -> io::Result<()> {
    if hosts.iter().any(|host| {
        host.online
            && !host
                .host_start_time
                .is_some_and(|start| EngineHosts::process_is_gone(host.host_pid, start))
            && (!bundle.engine.compatible_with(&host.snapshot.host)
                || host.native_base_sha256 != bundle.base.native_base_sha256)
    }) {
        return Err(io::Error::new(io::ErrorKind::Unsupported,
            "a managed process has an incompatible native Base or Engine contract; requires_restart"));
    }
    Ok(())
}

pub(super) fn uncovered_processes(
    sessions: &[crate::session::SessionSnapshot],
    hosts: &[crate::engine_hosts::HostStatus],
) -> Vec<u32> {
    use crate::session::SessionLifecycle;
    use hyperhub_engine::host::Backend;
    let mut uncovered = Vec::new();
    for session in sessions
        .iter()
        .filter(|session| session.lifecycle == SessionLifecycle::RootProcess)
    {
        for process in &session.processes {
            if matches!(
                process.hook_status.as_str(),
                "fork_pending" | "unhook" | "bypass"
            ) {
                continue;
            }
            let covered = hosts.iter().any(|host| {
                host.online
                    && host.session_id == session.session_id
                    && (host.backend == Backend::LinuxPtrace || host.root_pid == process.pid)
            });
            if !covered {
                uncovered.push(process.pid);
            }
        }
    }
    uncovered.sort_unstable();
    uncovered.dedup();
    uncovered
}

fn published(book: &Book, error: Option<String>, id: Option<&str>) -> Status {
    let mut records: Vec<_> = book
        .records
        .values()
        .filter(|r| id.is_none_or(|id| r.id == id))
        .map(Record::view)
        .collect();
    records.sort_by_key(|record| {
        (
            record.phase.terminal(),
            std::cmp::Reverse(record.created_at_ms),
            record.id.clone(),
        )
    });
    let omitted = 0;
    Status {
        records,
        records_omitted: omitted,
        error,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
