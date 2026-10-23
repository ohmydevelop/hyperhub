use super::protocol::{EnginePreflight, Frame, Identity, TIMEOUT, VERSION};
use super::wire::{self, Wire};
use crate::session::AuthenticatedSession;
use crate::socks::forwarding::ResidentAuthority;
use crate::socks::SocksService;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use tokio::sync::oneshot;

mod artifact;
mod dispatch;
mod resident;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub generation: u64,
    pub pid: u32,
    pub start_time: Option<u64>,
    pub version: String,
    pub sha256: String,
    pub phase: String,
    pub live_connections: usize,
    pub healthy: bool,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerTransactionStatus {
    pub id: String,
    pub phase: String,
    pub generation: u64,
    pub previous_generation: Option<u64>,
    pub sha256: String,
    pub engine: Option<hyperhub_runtime::Manifest>,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerGroupStatus {
    pub active_generation: u64,
    pub retained_generations: usize,
    pub workers: Vec<WorkerStatus>,
    pub transactions: Vec<WorkerTransactionStatus>,
}
#[derive(Clone)]
pub struct WorkerManager(Arc<Inner>);
struct Inner {
    service: SocksService,
    root: Arc<artifact::Root>,
    state: Mutex<State>,
    preparation: Mutex<()>,
    claims: Arc<Mutex<HashSet<(String, u32, u64)>>>,
    closing: AtomicBool,
    resident_sha256: String,
}
struct State {
    active: u64,
    next: u64,
    workers: BTreeMap<u64, Arc<Worker>>,
    transactions: BTreeMap<String, WorkerTransactionStatus>,
}
struct Worker {
    generation: u64,
    pid: u32,
    start_time: Option<u64>,
    executable: artifact::Executable,
    wire: Wire,
    deadlines: super::deadline::Scheduler,
    authority: Arc<ResidentAuthority>,
    child: Mutex<Child>,
    version: Mutex<String>,
    offers: Mutex<HashMap<u64, Offer>>,
    next_offer: AtomicU64,
    connected: AtomicBool,
    retiring: AtomicBool,
    drain_sent: AtomicBool,
    exited: AtomicBool,
    last_pong: Mutex<std::time::Instant>,
    ping: AtomicU64,
    rpc_queue: Mutex<Option<mpsc::SyncSender<RpcWork>>>,
    booted: Mutex<Option<mpsc::Sender<io::Result<String>>>>,
    reason: Mutex<Option<String>>,
}
type RpcWork = (u64, u64, super::authority::Request);
struct Offer {
    ready: Option<mpsc::Sender<io::Result<()>>>,
    done: Option<oneshot::Sender<io::Result<()>>>,
    granted: bool,
    sent: bool,
    cancelled: bool,
    cancellation_socket: Option<std::net::TcpStream>,
}
impl WorkerManager {
    pub(crate) fn new(service: SocksService, executable: &Path) -> io::Result<Self> {
        Self::new_authenticated(service, executable, None)
    }
    pub(crate) fn new_authenticated(
        service: SocksService,
        executable: &Path,
        key: Option<&[u8]>,
    ) -> io::Result<Self> {
        let root = artifact::Root::new_authenticated(key)?;
        let digest = artifact::source_digest(executable)?;
        let artifact = root.install(executable, &digest)?;
        let claims = Arc::new(Mutex::new(HashSet::new()));
        let worker = Worker::start(&service, 1, artifact, claims.clone(), None)?;
        Ok(Self(Arc::new(Inner {
            service,
            root,
            state: Mutex::new(State {
                active: 1,
                next: 2,
                workers: BTreeMap::from([(1, worker)]),
                transactions: BTreeMap::new(),
            }),
            preparation: Mutex::new(()),
            claims,
            closing: AtomicBool::new(false),
            resident_sha256: digest,
        })))
    }
    /// Starts and validates a candidate without changing connection dispatch.
    /// This operation blocks for preparation; async callers must spawn_blocking.
    pub fn prepare(
        &self,
        id: &str,
        executable: &Path,
        expected_sha256: &str,
    ) -> io::Result<WorkerStatus> {
        self.prepare_inner(id, executable, expected_sha256, None)
    }
    /// Preflight the native Engine inside the isolated candidate before it can
    /// become ready. This also validates bundles when no target Host is enrolled.
    pub fn prepare_bundle(
        &self,
        id: &str,
        executable: &Path,
        expected_sha256: &str,
        engine_manifest: &hyperhub_runtime::Manifest,
        engine_source: &Path,
        engine_cache: &Path,
    ) -> io::Result<WorkerStatus> {
        engine_manifest.validate().map_err(io::Error::other)?;
        self.prepare_inner(
            id,
            executable,
            expected_sha256,
            Some(EnginePreflight {
                manifest: engine_manifest.clone(),
                source: engine_source.to_path_buf(),
                cache: engine_cache.to_path_buf(),
            }),
        )
    }
    fn prepare_inner(
        &self,
        id: &str,
        executable: &Path,
        expected_sha256: &str,
        engine: Option<EnginePreflight>,
    ) -> io::Result<WorkerStatus> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        {
            return Err(io::Error::other("invalid worker transaction id"));
        }
        let _preparation = self
            .0
            .preparation
            .lock()
            .map_err(|_| io::Error::other("worker preparation state poisoned"))?;
        if self.0.closing.load(Ordering::Acquire) {
            return Err(io::Error::other(
                "forwarding worker manager is shutting down",
            ));
        }
        let generation = {
            let mut state = self
                .0
                .state
                .lock()
                .map_err(|_| io::Error::other("worker group state poisoned"))?;
            if let Some(transaction) = state.transactions.get(id) {
                if transaction.sha256 != expected_sha256
                    || transaction.engine.as_ref() != engine.as_ref().map(|engine| &engine.manifest)
                {
                    return Err(io::Error::other(
                        "worker transaction id conflicts with a different artifact",
                    ));
                }
                return state
                    .workers
                    .get(&transaction.generation)
                    .map(|worker| worker.status())
                    .ok_or_else(|| io::Error::other("worker transaction has no candidate"));
            }
            if state.transactions.values().any(|transaction| {
                matches!(
                    transaction.phase.as_str(),
                    "preparing" | "prepared" | "committed"
                )
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another worker transaction retains rollback ownership",
                ));
            }
            if state
                .workers
                .values()
                .filter(|worker| {
                    worker.generation != state.active && !worker.exited.load(Ordering::Acquire)
                })
                .count()
                >= 4
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "retained forwarding worker generation limit reached",
                ));
            }
            if state.transactions.len() >= 128 {
                let removable = state
                    .transactions
                    .iter()
                    .find(|(_, transaction)| {
                        matches!(
                            transaction.phase.as_str(),
                            "complete" | "rolled_back" | "failed" | "aborted"
                        )
                    })
                    .map(|(id, _)| id.clone());
                if let Some(id) = removable {
                    state.transactions.remove(&id);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "worker transaction history is full",
                    ));
                }
            }
            let generation = state.next;
            state.next = state
                .next
                .checked_add(1)
                .ok_or_else(|| io::Error::other("worker generation exhausted"))?;
            state.transactions.insert(
                id.into(),
                WorkerTransactionStatus {
                    id: id.into(),
                    phase: "preparing".into(),
                    generation,
                    previous_generation: None,
                    sha256: expected_sha256.into(),
                    engine: engine.as_ref().map(|engine| engine.manifest.clone()),
                    reason: None,
                },
            );
            generation
        };
        let result = self
            .0
            .root
            .install(executable, expected_sha256)
            .and_then(|artifact| {
                Worker::start(
                    &self.0.service,
                    generation,
                    artifact,
                    self.0.claims.clone(),
                    engine,
                )
            });
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("worker group state poisoned"))?;
        match result {
            Ok(worker) => {
                let status = worker.status();
                state.workers.insert(generation, worker);
                state.transactions.get_mut(id).unwrap().phase = "prepared".into();
                Ok(status)
            }
            Err(error) => {
                let transaction = state.transactions.get_mut(id).unwrap();
                transaction.phase = "failed".into();
                transaction.reason = Some(error.to_string());
                Err(error)
            }
        }
    }
    /// Only swaps the dispatch generation. Existing streams keep their worker.
    pub fn commit(&self, id: &str) -> io::Result<WorkerStatus> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("worker group state poisoned"))?;
        let transaction = state
            .transactions
            .get(id)
            .ok_or_else(|| io::Error::other("unknown worker transaction"))?
            .clone();
        let candidate = state
            .workers
            .get(&transaction.generation)
            .ok_or_else(|| io::Error::other("worker candidate is unavailable"))?
            .clone();
        if matches!(
            transaction.phase.as_str(),
            "committed" | "draining" | "complete"
        ) {
            return Ok(candidate.status());
        }
        if transaction.phase != "prepared" || !candidate.healthy() {
            return Err(io::Error::other(
                "worker candidate is not prepared and healthy",
            ));
        }
        let previous = state.active;
        state.active = candidate.generation;
        let transaction = state.transactions.get_mut(id).unwrap();
        transaction.phase = "committed".into();
        transaction.previous_generation = Some(previous);
        Ok(candidate.status())
    }
    /// Releases the rollback reservation after the global durable decision.
    pub fn finalize(&self, id: &str) -> io::Result<WorkerStatus> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("worker group state poisoned"))?;
        let transaction = state
            .transactions
            .get(id)
            .ok_or_else(|| io::Error::other("unknown worker transaction"))?
            .clone();
        if !matches!(
            transaction.phase.as_str(),
            "committed" | "draining" | "complete"
        ) {
            return Err(io::Error::other("worker transaction is not committed"));
        }
        let worker = state
            .workers
            .get(&transaction.generation)
            .ok_or_else(|| io::Error::other("worker candidate is unavailable"))?
            .clone();
        if matches!(transaction.phase.as_str(), "draining" | "complete") {
            return Ok(worker.status());
        }
        if transaction.phase == "committed" && !worker.healthy() {
            return Err(io::Error::other(
                "worker candidate failed health observation",
            ));
        }
        if let Some(previous) = transaction
            .previous_generation
            .and_then(|generation| state.workers.get(&generation))
        {
            previous.retiring.store(true, Ordering::Release);
        }
        state.transactions.get_mut(id).unwrap().phase = "draining".into();
        Ok(worker.status())
    }
    pub fn rollback(&self, id: &str) -> io::Result<WorkerStatus> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("worker group state poisoned"))?;
        let transaction = state
            .transactions
            .get(id)
            .ok_or_else(|| io::Error::other("unknown worker transaction"))?
            .clone();
        let candidate = state
            .workers
            .get(&transaction.generation)
            .ok_or_else(|| io::Error::other("worker candidate is unavailable"))?
            .clone();
        if matches!(transaction.phase.as_str(), "rolled_back" | "aborted") {
            return Ok(candidate.status());
        }
        match transaction.phase.as_str() {
            "prepared" => state.transactions.get_mut(id).unwrap().phase = "aborted".into(),
            "committed" => {
                let previous = transaction
                    .previous_generation
                    .and_then(|generation| state.workers.get(&generation))
                    .filter(|worker| worker.healthy())
                    .ok_or_else(|| io::Error::other("previous worker is unavailable for rollback"))?
                    .generation;
                state.active = previous;
                state.transactions.get_mut(id).unwrap().phase = "rolled_back".into();
            }
            _ => {
                return Err(io::Error::other(
                    "worker transaction cannot roll back after finalization",
                ))
            }
        }
        candidate.retiring.store(true, Ordering::Release);
        Ok(candidate.status())
    }
    pub fn abort(&self, id: &str) -> io::Result<WorkerStatus> {
        if !matches!(self.query(id)?.phase.as_str(), "prepared" | "aborted") {
            return Err(io::Error::other(
                "cannot abort a committed worker transaction",
            ));
        }
        self.rollback(id)
    }
    pub fn query(&self, id: &str) -> io::Result<WorkerTransactionStatus> {
        self.refresh();
        self.0
            .state
            .lock()
            .map_err(|_| io::Error::other("worker group state poisoned"))?
            .transactions
            .get(id)
            .cloned()
            .ok_or_else(|| io::Error::other("unknown worker transaction"))
    }
    pub fn status(&self) -> WorkerGroupStatus {
        self.refresh();
        let state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        WorkerGroupStatus {
            active_generation: state.active,
            retained_generations: state
                .workers
                .values()
                .filter(|worker| {
                    worker.generation != state.active && !worker.exited.load(Ordering::Acquire)
                })
                .count(),
            workers: state
                .workers
                .values()
                .map(|worker| worker.status())
                .collect(),
            transactions: state.transactions.values().cloned().collect(),
        }
    }
    /// Stop control-plane IO for a failed generation. Granted sockets remain
    /// alive until their business streams drain or their sessions are revoked.
    /// Async callers must offload this operation because native IO is cancelled.
    pub fn quarantine(&self, generation: u64, reason: &str) -> io::Result<()> {
        let worker = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("worker group state poisoned"))?
            .workers
            .get(&generation)
            .cloned()
            .ok_or_else(|| io::Error::other("unknown forwarding worker generation"))?;
        worker.disconnected(reason);
        Ok(())
    }
    /// Stop accepting future dispatch and let all existing streams drain.
    pub fn shutdown(&self) {
        if let Ok(state) = self.0.state.lock() {
            for worker in state.workers.values() {
                worker.retiring.store(true, Ordering::Release);
            }
        }
    }
    /// Transfer only this instance's cache retirement to an authenticated
    /// helper. Existing granted streams remain owned by their old workers.
    pub fn shutdown_cleanup(&self, executable: &Path, key: &[u8]) -> io::Result<()> {
        let deadline = std::time::Instant::now() + super::cleanup::ADMISSION;
        self.0.closing.store(true, Ordering::Release);
        // A partially prepared generation must not appear after our process
        // snapshot. Never wait without a deadline for preparation or its RPCs.
        let _preparation = loop {
            match self.0.preparation.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(io::Error::other("worker preparation state poisoned"))
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "cache cleanup could not snapshot an unfinished worker preparation",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        };
        let workers =
            {
                let state = loop {
                    match self.0.state.try_lock() {
                        Ok(state) => break state,
                        Err(std::sync::TryLockError::Poisoned(_)) => {
                            return Err(io::Error::other("worker group state poisoned"))
                        }
                        Err(std::sync::TryLockError::WouldBlock) => {
                            if std::time::Instant::now() >= deadline {
                                return Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "cache cleanup worker snapshot deadline expired",
                                ));
                            }
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                    }
                };
                for worker in state.workers.values() {
                    worker.retiring.store(true, Ordering::Release);
                }
                state
                    .workers
                    .values()
                    .filter(|worker| !worker.exited.load(Ordering::Acquire))
                    .map(|worker| {
                        Ok(super::cleanup::ProcessIdentity {
                            pid: worker.pid,
                            birth: worker.start_time.filter(|birth| *birth != 0).ok_or_else(
                                || io::Error::other("cache cleanup worker birth is unavailable"),
                            )?,
                        })
                    })
                    .collect::<io::Result<Vec<_>>>()?
            };
        let root = self.0.root.clone();
        let executable = executable.to_owned();
        let sha256 = self.0.resident_sha256.clone();
        let key = zeroize::Zeroizing::new(key.to_vec());
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("hh-cache-transfer".into())
            .spawn(move || {
                let result =
                    super::cleanup::Job::capture(root.directory(), workers).and_then(|job| {
                        super::cleanup::start(job, &executable, &sha256, &key, deadline)
                    });
                let _ = send.send(result);
            })?;
        let result = receive
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cache cleanup admission deadline expired",
                )
            })
            .and_then(|result| result);
        if thread.is_finished() {
            let _ = thread.join();
        }
        result
    }
    fn refresh(&self) {
        if let Ok(mut state) = self.0.state.lock() {
            let finished: Vec<_> = state
                .transactions
                .iter()
                .filter(|(_, transaction)| {
                    transaction.phase == "draining"
                        && transaction
                            .previous_generation
                            .and_then(|generation| state.workers.get(&generation))
                            .is_none_or(|worker| worker.exited.load(Ordering::Acquire))
                })
                .map(|(id, _)| id.clone())
                .collect();
            for id in finished {
                state.transactions.get_mut(&id).unwrap().phase = "complete".into();
            }
            let referenced: HashSet<u64> = state
                .transactions
                .values()
                .flat_map(|transaction| {
                    std::iter::once(transaction.generation).chain(transaction.previous_generation)
                })
                .chain(std::iter::once(state.active))
                .collect();
            state.workers.retain(|generation, worker| {
                !worker.exited.load(Ordering::Acquire) || referenced.contains(generation)
            });
        }
    }
}
