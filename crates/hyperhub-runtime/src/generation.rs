use crate::Manifest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, TryLockError};
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
    /// Rebuild process-local ownership in a suspended fork child. Production
    /// native Engines implement this; arbitrary Host-service implementations
    /// must supply their own explicit fork contract.
    /// # Safety
    /// Call only in the sole child rebuild thread before target resumption.
    #[cfg(target_os = "linux")]
    unsafe fn fork_copy(&self) -> Result<Arc<dyn Engine>, Error> {
        Err(Error::RequiresRestart)
    }
    #[cfg(target_os = "linux")]
    fn fork_module_key(&self) -> usize {
        0
    }
    /// # Safety
    /// Same suspended-child requirements as `fork_copy`. Once per actual DSO.
    #[cfg(target_os = "linux")]
    unsafe fn fork_reset(&self) -> Result<(), Error> {
        Ok(())
    }
    /// Release the original copied OS ownership after `fork_copy`. The old
    /// object must remain leaked and can never be used or dropped in this child.
    /// # Safety
    /// Same child-only requirements as `fork_copy`; exactly once per object.
    #[cfg(target_os = "linux")]
    unsafe fn fork_release(&self) {}
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
    deadline: Option<Instant>,
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

// First acquisition can occur inside a loader/allocator Hook. ArcSwap's lazy
// thread-local debt registration takes the native loader lock on first use.
// A short pointer-only read lock avoids that lock inversion. No Engine code,
// allocation or module destruction runs while this lock is held.
struct ActiveGeneration(RwLock<Arc<Generation>>);
impl ActiveGeneration {
    fn from_pointee(generation: Generation) -> Self {
        Self(RwLock::new(Arc::new(generation)))
    }
    fn load_full(&self) -> Arc<Generation> {
        self.0.read().expect("active generation poisoned").clone()
    }
    fn swap(&self, generation: Arc<Generation>) -> Arc<Generation> {
        std::mem::replace(
            &mut self.0.write().expect("active generation poisoned"),
            generation,
        )
    }
}

pub struct Runtime {
    host: Manifest,
    settings: Settings,
    active: ActiveGeneration,
    state: Mutex<State>,
}

#[cfg(target_os = "linux")]
pub struct ForkGuard<'a> {
    _guard: MutexGuard<'a, State>,
    pub image: ForkImage,
}
#[cfg(target_os = "linux")]
impl ForkGuard<'_> {
    pub fn into_image(self) -> ForkImage {
        let Self { _guard, image } = self;
        drop(_guard);
        image
    }
    /// # Safety
    /// Invoke only in the fork child. A Frida rebuild thread may differ from
    /// the thread that acquired the inherited guard. Never unlock or drop it.
    pub unsafe fn into_child_image(self) -> ForkImage {
        let Self { _guard, image } = self;
        std::mem::forget(_guard);
        image
    }
}
#[cfg(target_os = "linux")]
pub struct ForkImage {
    host: Manifest,
    settings: Settings,
    next: u64,
    active: Arc<Generation>,
    retired: Vec<Arc<Generation>>,
    transactions: BTreeMap<String, Transaction>,
    observation: Option<(String, u64, Option<Instant>)>,
    discarded: Vec<Arc<Generation>>,
}
#[cfg(target_os = "linux")]
pub struct ForkedRuntime {
    pub runtime: Arc<Runtime>,
    generations: BTreeMap<u64, Arc<Generation>>,
}
#[cfg(target_os = "linux")]
impl ForkedRuntime {
    pub fn rebind(&self, inherited: &Lease) -> Result<Lease, Error> {
        self.generations
            .get(&inherited.generation())
            .cloned()
            .map(Lease)
            .ok_or(Error::NotPrepared)
    }
}
#[cfg(target_os = "linux")]
impl ForkImage {
    /// # Safety
    /// This image was frozen before the fork and is now used only by the
    /// suspended child's rebuild thread. Forget every original Runtime/Lease
    /// copied from the parent; no inherited mutex or Arc counter is reusable.
    pub unsafe fn rebuild(self) -> Result<ForkedRuntime, Error> {
        let this = std::mem::ManuallyDrop::new(self);
        let mut engines: BTreeMap<usize, Arc<dyn Engine>> = BTreeMap::new();
        let mut originals: BTreeMap<usize, Arc<dyn Engine>> = BTreeMap::new();
        let mut generations = BTreeMap::new();
        let mut reset_modules = std::collections::BTreeSet::new();
        for original in std::iter::once(&this.active).chain(this.retired.iter()) {
            let key = Arc::as_ptr(&original.engine) as *const () as usize;
            if let std::collections::btree_map::Entry::Vacant(entry) = engines.entry(key) {
                if reset_modules.insert(original.engine.fork_module_key()) {
                    unsafe { original.engine.fork_reset()? };
                }
                entry.insert(unsafe { original.engine.fork_copy()? });
                originals.insert(key, original.engine.clone());
            }
            generations.insert(
                original.id,
                Arc::new(Generation {
                    id: original.id,
                    engine: engines[&key].clone(),
                }),
            );
        }
        let mut transactions = this.transactions.clone();
        for tx in transactions.values_mut() {
            if matches!(
                tx.stage,
                Stage::Preparing | Stage::Prepared | Stage::Switching
            ) {
                tx.stage = Stage::Aborted;
                tx.reason = Some("preparation belonged to the parent process".into());
            }
        }
        let runtime = Arc::new(Runtime {
            host: this.host.clone(),
            settings: this.settings,
            active: ActiveGeneration(RwLock::new(generations[&this.active.id].clone())),
            state: Mutex::new(State {
                next: this.next,
                pending: None,
                observation: this.observation.as_ref().map(|(id, previous, deadline)| {
                    Observation {
                        id: id.clone(),
                        previous: *previous,
                        deadline: *deadline,
                    }
                }),
                retired: this
                    .retired
                    .iter()
                    .map(|g| generations[&g.id].clone())
                    .collect(),
                transactions,
                garbage: Vec::new(),
            }),
        });
        for original in &this.discarded {
            let key = Arc::as_ptr(&original.engine) as *const () as usize;
            originals
                .entry(key)
                .or_insert_with(|| original.engine.clone());
        }
        // Copied Rust objects have parent-only reference counts. Keep one leaked
        // reference permanently so their Drop cannot close a reassigned fd or
        // dlopen handle. Native OS resources transfer explicitly, exactly once.
        for (_, original) in originals {
            unsafe {
                original.fork_release();
            }
            std::mem::forget(original);
        }
        Ok(ForkedRuntime {
            runtime,
            generations,
        })
    }
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
            active: ActiveGeneration::from_pointee(Generation {
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

    #[cfg(target_os = "linux")]
    pub fn freeze_fork(&self) -> Result<ForkGuard<'_>, Error> {
        let started = Instant::now();
        let guard = loop {
            let guard = self.state.lock().map_err(|_| Error::Poisoned)?;
            if !guard
                .pending
                .as_ref()
                .is_some_and(|p| p.generation.is_none())
            {
                break guard;
            }
            drop(guard);
            if started.elapsed() >= self.settings.prepare_timeout {
                return Err(Error::TimedOut);
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let mut discarded = guard.garbage.clone();
        if let Some(generation) = guard.pending.as_ref().and_then(|p| p.generation.clone()) {
            discarded.push(generation);
        }
        let image = ForkImage {
            host: self.host.clone(),
            settings: self.settings,
            next: guard.next,
            active: self.active.load_full(),
            retired: guard.retired.clone(),
            transactions: guard.transactions.clone(),
            observation: guard
                .observation
                .as_ref()
                .map(|o| (o.id.clone(), o.previous, o.deadline)),
            discarded,
        };
        Ok(ForkGuard {
            _guard: guard,
            image,
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
        self.commit_inner(id, false)
    }

    /// Coordinated commits retain rollback code until the durable coordinator
    /// confirms the global decision and explicitly starts observation. A lost
    /// coordinator must not expire rollback ability on a partially committed
    /// group. The existing retained-generation limit still applies.
    pub fn commit_held(&self, id: &str) -> Result<Transaction, Error> {
        self.commit_inner(id, true)
    }

    fn commit_inner(&self, id: &str, hold_observation: bool) -> Result<Transaction, Error> {
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
            deadline: (!hold_observation).then(|| Instant::now() + self.settings.health_window),
        });
        state.retired.push(old);
        let tx = state.transactions.get_mut(id).unwrap();
        tx.stage = Stage::Draining;
        Ok(tx.clone())
    }

    /// Idempotent: retries never extend an already-running health window.
    pub fn begin_observation(&self, id: &str) -> Result<Transaction, Error> {
        let mut state = self.lock()?;
        let tx = state.transactions.get(id).ok_or(Error::NotPrepared)?;
        if !matches!(tx.stage, Stage::Draining | Stage::Complete) {
            return Err(Error::NotPrepared);
        }
        if let Some(observation) = state
            .observation
            .as_mut()
            .filter(|observation| observation.id == id)
        {
            observation
                .deadline
                .get_or_insert_with(|| Instant::now() + self.settings.health_window);
        }
        Ok(state.transactions.get(id).unwrap().clone())
    }

    /// Release a coordinated reservation after a durable global health decision.
    /// This does not close leases or connections. Old transactions cannot release
    /// the reservation of a newer transaction, and retries have no new effect.
    pub fn finalize_observation(&self, id: &str) -> Result<Transaction, Error> {
        let mut state = self.lock()?;
        let transaction = state.transactions.get(id).ok_or(Error::NotPrepared)?;
        if !matches!(transaction.stage, Stage::Draining | Stage::Complete) {
            return Err(Error::NotPrepared);
        }
        if state
            .observation
            .as_ref()
            .is_some_and(|observation| observation.id == id)
        {
            state.observation = None;
        }
        Self::collect(&mut state);
        Ok(state.transactions.get(id).unwrap().clone())
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
        if self.active.load_full().id != current.id {
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
            } else if observation
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
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
        let transaction_report = if transactions >= state.transactions.len() {
            state.transactions.values().cloned().collect()
        } else {
            let mut ids = std::collections::BTreeSet::new();
            for id in state
                .pending
                .as_ref()
                .map(|p| &p.id)
                .into_iter()
                .chain(state.observation.as_ref().map(|o| &o.id))
                .chain(state.transactions.keys().rev())
            {
                if ids.len() >= transactions {
                    break;
                }
                ids.insert(id);
            }
            ids.into_iter()
                .filter_map(|id| state.transactions.get(id).cloned())
                .collect()
        };
        Ok(Snapshot {
            host: self.host.clone(),
            active: status(&active, 1),
            retired: state.retired.iter().map(|g| status(g, 0)).collect(),
            transactions: transaction_report,
            transactions_omitted: state.transactions.len().saturating_sub(transactions),
        })
    }
}
