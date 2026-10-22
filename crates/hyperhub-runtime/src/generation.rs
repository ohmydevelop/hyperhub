use crate::Manifest;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidManifest,
    InvalidTransaction,
    Conflict,
    Busy,
    RequiresRestart,
    RetainedLimit,
    TimedOut,
    Unhealthy,
    NotPrepared,
    AlreadyCommitted,
    Poisoned,
    Artifact(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Internal Rust interface. Only the `native` adapter crosses the C ABI.
pub trait Engine: Send + Sync {
    fn manifest(&self) -> &Manifest;
    fn health(&self) -> bool;
    fn invoke(
        &self,
        calling: &Lease,
        operation: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, i32>;
}

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub switch_budget: Duration,
    pub prepare_timeout: Duration,
    pub health_window: Duration,
    pub max_retired: usize,
    /// Reject new transactions when full. Reusing an old ID must never commit twice.
    pub max_transactions: usize,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            switch_budget: Duration::from_millis(100),
            prepare_timeout: Duration::from_secs(30),
            health_window: Duration::from_secs(30),
            max_retired: 4,
            max_transactions: 4096,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Preparing,
    Prepared,
    Switching,
    Draining,
    Complete,
    RolledBack,
    RequiresRestart,
    Aborted,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub manifest: Manifest,
    pub stage: Stage,
    pub generation: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerationStatus {
    pub generation: u64,
    pub version: String,
    pub references: usize,
    pub rollback_reserved: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub host: Manifest,
    pub active: GenerationStatus,
    pub retired: Vec<GenerationStatus>,
    pub transactions: Vec<Transaction>,
    #[serde(default)]
    pub transactions_omitted: usize,
}

struct Generation {
    id: u64,
    engine: Arc<dyn Engine>,
}
/// A lease pins code, not Host resources. Clone it for pending asynchronous work.
#[derive(Clone)]
pub struct Lease(Arc<Generation>);
impl fmt::Debug for Lease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Lease")
            .field("generation", &self.generation())
            .field("version", &self.version())
            .finish()
    }
}
impl Lease {
    pub fn generation(&self) -> u64 {
        self.0.id
    }
    pub fn version(&self) -> &str {
        &self.0.engine.manifest().version
    }
    pub fn invoke(&self, operation: u32, input: &[u8], output: &mut [u8]) -> Result<usize, i32> {
        self.0.engine.invoke(self, operation, input, output)
    }
    pub(crate) fn belongs_to(&self, engine: &dyn Engine) -> bool {
        std::ptr::eq(
            self.0.engine.as_ref() as *const dyn Engine as *const (),
            engine as *const dyn Engine as *const (),
        )
    }
}

struct Pending {
    id: String,
    started: Instant,
    generation: Option<Arc<Generation>>,
}
struct Observation {
    id: String,
    previous: u64,
    deadline: Instant,
}
struct State {
    next: u64,
    pending: Option<Pending>,
    observation: Option<Observation>,
    retired: Vec<Arc<Generation>>,
    transactions: BTreeMap<String, Transaction>,
    garbage: Vec<Arc<Generation>>,
}

// Module destructors may call Host services. Never run them under the
// transaction lock, including collection, abort and timeout paths.
struct StateGuard<'a>(Option<MutexGuard<'a, State>>);
impl Deref for StateGuard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        self.0.as_ref().unwrap()
    }
}
impl DerefMut for StateGuard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.0.as_mut().unwrap()
    }
}
impl Drop for StateGuard<'_> {
    fn drop(&mut self) {
        let garbage = std::mem::take(&mut self.garbage);
        drop(self.0.take());
        drop(garbage);
    }
}

pub struct Runtime {
    host: Manifest,
    settings: Settings,
    active: ArcSwap<Generation>,
    state: Mutex<State>,
}

impl Runtime {
    pub fn new(initial: Arc<dyn Engine>, settings: Settings) -> Result<Self, Error> {
        initial.manifest().validate()?;
        if !initial.health() {
            return Err(Error::Unhealthy);
        }
        Ok(Self {
            host: initial.manifest().clone(),
            settings,
            active: ArcSwap::from_pointee(Generation {
                id: 0,
                engine: initial,
            }),
            state: Mutex::new(State {
                next: 1,
                pending: None,
                observation: None,
                retired: Vec::new(),
                transactions: BTreeMap::new(),
                garbage: Vec::new(),
            }),
        })
    }

    /// Does not take the transaction mutex. IO and callbacks can hold leases
    /// while another thread prepares or commits a generation.
    pub fn acquire(&self) -> Lease {
        Lease(self.active.load_full())
    }

    fn lock(&self) -> Result<StateGuard<'_>, Error> {
        self.state
            .lock()
            .map(|guard| StateGuard(Some(guard)))
            .map_err(|_| Error::Poisoned)
    }

    fn collect(state: &mut State) {
        let reserved = state.observation.as_ref().map(|o| o.previous);
        let mut index = 0;
        while index < state.retired.len() {
            let g = &state.retired[index];
            if reserved != Some(g.id) && Arc::strong_count(g) == 1 {
                state.garbage.push(state.retired.remove(index));
            } else {
                index += 1;
            }
        }
        // Draining is complete only when this transaction's previous generations
        // have no live leases. A newer transaction must not conceal them.
        for tx in state.transactions.values_mut() {
            if tx.stage == Stage::Draining
                && state.observation.as_ref().is_none_or(|o| o.id != tx.id)
                && !state
                    .retired
                    .iter()
                    .any(|g| g.id < tx.generation.unwrap_or(0))
            {
                tx.stage = Stage::Complete;
            }
        }
    }

    fn expire(state: &mut State, timeout: Duration) {
        if state
            .pending
            .as_ref()
            .is_some_and(|p| p.started.elapsed() >= timeout)
        {
            let pending = state.pending.take().unwrap();
            if let Some(generation) = pending.generation {
                state.garbage.push(generation);
            }
            let tx = state.transactions.get_mut(&pending.id).unwrap();
            tx.stage = Stage::Aborted;
            tx.reason = Some("preparation timed out".into());
        }
    }

    /// `load` runs outside the transaction mutex. A slow loader cannot stall
    /// dispatch or prevent abort/query. Native code must honor its own bound;
    /// deadlines cannot preempt arbitrary code in the Host address space.
    pub fn prepare<F>(&self, id: &str, manifest: &Manifest, load: F) -> Result<Transaction, Error>
    where
        F: FnOnce() -> Result<Arc<dyn Engine>, Error>,
    {
        manifest.validate()?;
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        {
            return Err(Error::InvalidTransaction);
        }
        {
            let mut state = self.lock()?;
            Self::expire(&mut state, self.settings.prepare_timeout);
            Self::collect(&mut state);
            if let Some(tx) = state.transactions.get(id) {
                return if tx.manifest == *manifest {
                    Ok(tx.clone())
                } else {
                    Err(Error::Conflict)
                };
            }
            if state.pending.is_some() || state.observation.is_some() {
                return Err(Error::Busy);
            }
            if state.transactions.len() >= self.settings.max_transactions {
                return Err(Error::RetainedLimit);
            }
            let compatible = manifest.compatible_with(&self.host);
            let tx = Transaction {
                id: id.into(),
                manifest: manifest.clone(),
                stage: if compatible {
                    Stage::Preparing
                } else {
                    Stage::RequiresRestart
                },
                generation: None,
                reason: (!compatible)
                    .then(|| "target, base ABI, state schema or native hook set differs".into()),
            };
            state.transactions.insert(id.into(), tx.clone());
            if !compatible {
                return Ok(tx);
            }
            // Committing retains the current generation for the health window.
            if state.retired.len() >= self.settings.max_retired {
                let tx = state.transactions.get_mut(id).unwrap();
                tx.stage = Stage::Failed;
                tx.reason = Some("retained generation limit reached".into());
                return Err(Error::RetainedLimit);
            }
            state.pending = Some(Pending {
                id: id.into(),
                started: Instant::now(),
                generation: None,
            });
        }
        let result = load().and_then(|engine| {
            if engine.manifest() != manifest {
                Err(Error::Conflict)
            } else if !engine.health() {
                Err(Error::Unhealthy)
            } else {
                Ok(engine)
            }
        });
        let mut state = self.lock()?;
        Self::expire(&mut state, self.settings.prepare_timeout);
        if !state.pending.as_ref().is_some_and(|p| p.id == id) {
            // An abort/timeout won. Dropping the candidate must not undo it.
            return Err(Error::TimedOut);
        }
        match result {
            Ok(engine) => {
                let generation = state.next;
                state.next = state.next.checked_add(1).ok_or(Error::RetainedLimit)?;
                state.pending.as_mut().unwrap().generation = Some(Arc::new(Generation {
                    id: generation,
                    engine,
                }));
                let tx = state.transactions.get_mut(id).unwrap();
                tx.stage = Stage::Prepared;
                tx.generation = Some(generation);
                Ok(tx.clone())
            }
            Err(error) => {
                state.pending = None;
                let tx = state.transactions.get_mut(id).unwrap();
                tx.stage = Stage::Failed;
                tx.reason = Some(error.to_string());
                Err(error)
            }
        }
    }

    pub fn commit(&self, id: &str) -> Result<Transaction, Error> {
        let started = Instant::now();
        let mut state = loop {
            match self.state.try_lock() {
                Ok(state) => break StateGuard(Some(state)),
                Err(TryLockError::Poisoned(_)) => return Err(Error::Poisoned),
                Err(TryLockError::WouldBlock) => {
                    if started.elapsed() >= self.settings.switch_budget {
                        return Err(Error::TimedOut);
                    }
                    std::thread::yield_now();
                }
            }
        };
        Self::expire(&mut state, self.settings.prepare_timeout);
        let tx = state.transactions.get(id).ok_or(Error::NotPrepared)?;
        if matches!(
            tx.stage,
            Stage::Draining | Stage::Complete | Stage::RolledBack
        ) {
            return Ok(tx.clone());
        }
        if tx.stage != Stage::Prepared {
            return Err(Error::NotPrepared);
        }
        let pending = state.pending.take().ok_or(Error::NotPrepared)?;
        if pending.id != id {
            state.pending = Some(pending);
            return Err(Error::Conflict);
        }
        state.transactions.get_mut(id).unwrap().stage = Stage::Switching;
        let old = self.active.swap(pending.generation.unwrap());
        state.observation = Some(Observation {
            id: id.into(),
            previous: old.id,
            deadline: Instant::now() + self.settings.health_window,
        });
        state.retired.push(old);
        let tx = state.transactions.get_mut(id).unwrap();
        tx.stage = Stage::Draining;
        Ok(tx.clone())
    }

    pub fn abort(&self, id: &str) -> Result<Transaction, Error> {
        let mut state = self.lock()?;
        let tx = state.transactions.get(id).ok_or(Error::NotPrepared)?;
        if matches!(
            tx.stage,
            Stage::Draining | Stage::Complete | Stage::RolledBack
        ) {
            return Err(Error::AlreadyCommitted);
        }
        if state.pending.as_ref().is_some_and(|p| p.id == id) {
            if let Some(generation) = state.pending.take().unwrap().generation {
                state.garbage.push(generation);
            }
        }
        let tx = state.transactions.get_mut(id).unwrap();
        if matches!(tx.stage, Stage::Preparing | Stage::Prepared) {
            tx.stage = Stage::Aborted;
        }
        Ok(tx.clone())
    }

    /// Revert a committed participant while its rollback reservation is held.
    /// Used when another participant or the installation helper fails. An old
    /// transaction cannot roll back a later upgrade.
    pub fn rollback(&self, id: &str, reason: &str) -> Result<Transaction, Error> {
        let mut state = self.lock()?;
        let tx = state.transactions.get(id).ok_or(Error::NotPrepared)?;
        if tx.stage == Stage::RolledBack {
            return Ok(tx.clone());
        }
        let observation = state.observation.as_ref().ok_or(Error::AlreadyCommitted)?;
        if observation.id != id {
            return Err(Error::Conflict);
        }
        let previous = observation.previous;
        let index = state
            .retired
            .iter()
            .position(|g| g.id == previous)
            .ok_or(Error::NotPrepared)?;
        let old = state.retired.remove(index);
        let failed = self.active.swap(old);
        state.retired.push(failed);
        state.observation = None;
        let tx = state.transactions.get_mut(id).unwrap();
        tx.stage = Stage::RolledBack;
        tx.reason = Some(reason.chars().take(1024).collect());
        let result = tx.clone();
        Self::collect(&mut state);
        Ok(result)
    }

    /// Called by the resident coordinator. Healthy observation expiry releases
    /// only the rollback reservation. Leases keep old code mapped independently.
    /// Rollback redirects future calls; it does not undo completed IO.
    pub fn observe(&self) -> Result<(), Error> {
        let current = self.active.load_full();
        let healthy = current.engine.health();
        let mut state = self.lock()?;
        if self.active.load().id != current.id {
            return Ok(());
        }
        if let Some(observation) = &state.observation {
            if !healthy {
                let previous = observation.previous;
                let id = observation.id.clone();
                let index = state
                    .retired
                    .iter()
                    .position(|g| g.id == previous)
                    .ok_or(Error::NotPrepared)?;
                let old = state.retired.remove(index);
                let failed = self.active.swap(old);
                state.retired.push(failed);
                state.observation = None;
                let tx = state.transactions.get_mut(&id).unwrap();
                tx.stage = Stage::RolledBack;
                tx.reason = Some("new engine failed its health check".into());
            } else if Instant::now() >= observation.deadline {
                state.observation = None;
            }
        }
        drop(current);
        Self::expire(&mut state, self.settings.prepare_timeout);
        Self::collect(&mut state);
        Ok(())
    }

    pub fn query(&self, id: &str) -> Result<Transaction, Error> {
        let mut state = self.lock()?;
        Self::expire(&mut state, self.settings.prepare_timeout);
        Self::collect(&mut state);
        state
            .transactions
            .get(id)
            .cloned()
            .ok_or(Error::NotPrepared)
    }
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        self.snapshot_limited(usize::MAX)
    }
    pub fn snapshot_limited(&self, transactions: usize) -> Result<Snapshot, Error> {
        let mut state = self.lock()?;
        Self::expire(&mut state, self.settings.prepare_timeout);
        Self::collect(&mut state);
        let active = self.active.load_full();
        let reserved = state.observation.as_ref().map(|o| o.previous);
        let status = |g: &Arc<Generation>, extra: usize| GenerationStatus {
            generation: g.id,
            version: g.engine.manifest().version.clone(),
            references: Arc::strong_count(g).saturating_sub(1 + extra),
            rollback_reserved: reserved == Some(g.id),
        };
        let mut transaction_report: Vec<_> = state
            .transactions
            .values()
            .rev()
            .take(transactions)
            .cloned()
            .collect();
        transaction_report.reverse();
        Ok(Snapshot {
            host: self.host.clone(),
            active: status(&active, 1),
            retired: state.retired.iter().map(|g| status(g, 0)).collect(),
            transactions: transaction_report,
            transactions_omitted: state.transactions.len().saturating_sub(transactions),
        })
    }
}
