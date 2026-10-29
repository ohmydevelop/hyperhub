//! Fork callbacks only freeze parent ownership. The gated child's independent
//! entry point reconstructs process locks, native ownership, and exact leases.
use crate::runtime::{state, AgentRuntime};
use hyperhub_runtime::{generation::ForkGuard, Runtime};
use std::cell::Cell;
use std::sync::{
    atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, Ordering},
    Arc, Mutex, MutexGuard, RwLockReadGuard,
};

static INSTALLED: AtomicBool = AtomicBool::new(false);
static CHILD: AtomicBool = AtomicBool::new(false);
// Frozen managed-tree admission is known before any new SDK entry is scheduled.
static CHILD_PROTECTED: AtomicBool = AtomicBool::new(false);
static CHILD_READY: AtomicU32 = AtomicU32::new(0);
static CHILD_LEASE: [AtomicU8; 32] = [const { AtomicU8::new(0) }; 32];
static FORK_LISTENER_ARMED: AtomicBool = AtomicBool::new(false);
// This counter is intentionally observable. `hyperhub_fork_listener_mark_armed`
// is a Frida Interceptor ABI hook point, so its release body must never collapse
// to a one-byte `ret` that cannot be relocated by the interceptor.
static FORK_LISTENER_MARK_TRIGGERS: AtomicU32 = AtomicU32::new(0);
static FORK_LISTENER_TRANSITION: AtomicU32 = AtomicU32::new(0);
static FORK_LISTENER_PREPARED: AtomicBool = AtomicBool::new(false);
static FORK_LISTENER_EPOCH: AtomicU32 = AtomicU32::new(0);
static FORK_LISTENER_GENERATION: AtomicU32 = AtomicU32::new(1);
thread_local! {
    // Set by the late listener for this actual native invocation, before
    // libc invokes pthread_atfork. A listener installed during an older call
    // cannot promise that its onLeave will run for that call.
    static LATE_LISTENER_ENTERED: Cell<bool> = const { Cell::new(false) };
    // Initialized before kernel fork. The child changes the copied slot to
    // Child in its actual atfork callback, without allocating or using a TID.
    static RETURN_OWNER: Cell<ReturnOwner> = const { Cell::new(ReturnOwner::None) };
}
#[derive(Clone, Copy)]
enum ReturnOwner {
    None,
    Parent(*mut Frozen),
    Child,
}
static RECOVERING: AtomicBool = AtomicBool::new(false);
static CHILD_SIGNAL_MASK: AtomicU64 = AtomicU64::new(0);
static CHILD_SIGNAL_MASKED: AtomicBool = AtomicBool::new(false);
static GATE: AtomicPtr<Mutex<()>> = AtomicPtr::new(std::ptr::null_mut());
fn gate() -> &'static Mutex<()> {
    let mut pointer = GATE.load(Ordering::Acquire);
    if pointer.is_null() {
        let fresh = Box::into_raw(Box::new(Mutex::new(())));
        match GATE.compare_exchange(
            std::ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => pointer = fresh,
            Err(existing) => {
                unsafe {
                    drop(Box::from_raw(fresh));
                }
                pointer = existing;
            }
        }
    }
    unsafe { &*pointer }
}

fn wake_listener_transition() {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            &FORK_LISTENER_TRANSITION as *const AtomicU32 as *const u32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            i32::MAX,
        );
    }
}

fn listener_gate() -> MutexGuard<'static, ()> {
    loop {
        while FORK_LISTENER_TRANSITION.load(Ordering::Acquire) != 0 {
            let expected = FORK_LISTENER_TRANSITION.load(Ordering::Acquire);
            if expected == 0 {
                break;
            }
            let timeout = libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    &FORK_LISTENER_TRANSITION as *const AtomicU32 as *const u32,
                    libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                    expected,
                    &timeout,
                    std::ptr::null::<u32>(),
                    0u32,
                );
            }
        }
        let guard = gate()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if FORK_LISTENER_TRANSITION.load(Ordering::Acquire) == 0 {
            return guard;
        }
        drop(guard);
    }
}

fn finish_listener_transition() {
    FORK_LISTENER_TRANSITION.store(0, Ordering::Release);
    wake_listener_transition();
}
static FROZEN: AtomicPtr<Frozen> = AtomicPtr::new(std::ptr::null_mut());
fn take_late_listener_entry() -> bool {
    LATE_LISTENER_ENTERED.with(|entered| entered.replace(false))
}
fn take_return_owner() -> ReturnOwner {
    RETURN_OWNER.with(|owner| owner.replace(ReturnOwner::None))
}

unsafe fn take_parent_snapshot(owner: ReturnOwner) -> Option<Box<Frozen>> {
    let ReturnOwner::Parent(pointer) = owner else {
        return None;
    };
    if pointer.is_null()
        || FROZEN
            .compare_exchange(
                pointer,
                std::ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        return None;
    }
    // Only the thread that acquired this Frozen's guards can own its Parent
    // token. A late callback installed during an older call has no such token.
    Some(unsafe { Box::from_raw(pointer) })
}
static NATIVE_ALIASES: AtomicPtr<crate::native_alias_snapshot::NativeAliasSnapshot> =
    AtomicPtr::new(std::ptr::null_mut());
struct Frozen {
    runtime: Option<ForkGuard<'static>>,
    agent: Option<MutexGuard<'static, AgentRuntime>>,
    gate: Option<MutexGuard<'static, ()>>,
    owner: *const Runtime,
    snapshot: Option<AgentRuntime>,
    error: Option<String>,
    lease: Option<[u8; 32]>,
    unmanaged: bool,
    late_listener_entered: bool,
    alias_pin: Option<Arc<crate::native_alias_snapshot::NativeAliasSnapshot>>,
    alias_guard:
        Option<RwLockReadGuard<'static, Arc<crate::native_alias_snapshot::NativeAliasSnapshot>>>,
}
pub(super) fn native_alias_plan(
    ip: std::net::IpAddr,
    port: u16,
) -> Result<Option<crate::HhConnectPlan>, i32> {
    let pointer = NATIVE_ALIASES.load(Ordering::Acquire);
    if pointer.is_null() {
        Ok(None)
    } else {
        unsafe { &*pointer }.plan(ip, port)
    }
}
pub(super) fn check_native_alias(ip: std::net::IpAddr, hostname: &str) -> Result<(), i32> {
    let pointer = NATIVE_ALIASES.load(Ordering::Acquire);
    if pointer.is_null() {
        Ok(())
    } else {
        unsafe { &*pointer }.check_observed(ip, hostname)
    }
}
pub(crate) fn awaiting_rebuild() -> bool {
    CHILD.load(Ordering::Acquire)
}

pub(crate) fn new_policy_blocked() -> bool {
    CHILD.load(Ordering::Acquire) && !RECOVERING.load(Ordering::Acquire)
}
pub(crate) fn install() -> Result<(), String> {
    super::fork_handoff::initialize()?;
    let _gate = crate::attachment::state_gate()?;
    crate::attachment::startup::check()
        .map_err(|_| "attachment initialization cancelled before atfork registration")?;
    if INSTALLED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    let result = unsafe { libc::pthread_atfork(Some(prepare), Some(parent), Some(child)) };
    if result != 0 {
        INSTALLED.store(false, Ordering::Release);
        Err(format!("cannot install fork snapshot callbacks: {result}"))
    } else {
        Ok(())
    }
}
pub(crate) fn callbacks_installed() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

pub(crate) fn prepare_activation_transition(
    change: impl FnOnce() -> Result<(), i32>,
) -> Result<(), i32> {
    // A Host mutation must not wait for a fork that may itself need the
    // manager to release Core's startup gate. A busy operation remains wholly
    // uncommitted and may be retried with the same approved request.
    let _guard = match gate().try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return Err(crate::HH_ERR_ACTIVATION_BUSY),
        Err(std::sync::TryLockError::Poisoned(_)) => return Err(crate::HH_ERR_PROTOCOL),
    };
    if FORK_LISTENER_TRANSITION.load(Ordering::Acquire) != 0 {
        return Err(crate::HH_ERR_ACTIVATION_BUSY);
    }
    change()
}

unsafe extern "C" fn prepare() {
    crate::engine_call::background(|| {
        let gate = listener_gate();
        // The capture-mode transition uses the same gate. A fork waiting for
        // another fork must observe the mode after it acquires ownership.
        let unmanaged = crate::attachment::managed()
            && (!crate::attachment::propagating() || !fork_listener_current());
        let late_listener_entered = take_late_listener_entry();
        let mut frozen = Frozen {
            runtime: None,
            agent: None,
            gate: Some(gate),
            owner: std::ptr::null(),
            snapshot: None,
            error: None,
            lease: None,
            unmanaged,
            late_listener_entered,
            alias_pin: None,
            alias_guard: None,
        };
        let result = (|| -> Result<(), String> {
            if unmanaged {
                return Ok(());
            }
            if !FORK_LISTENER_ARMED.load(Ordering::Acquire) {
                return Err("native fork return gate is not armed".into());
            }
            frozen.lease =
                Some(super::fork_handoff::begin().map_err(|_| "cannot authorize fork handoff")?);
            let owner = state()
                .lock()
                .map_err(|_| "Agent state poisoned")?
                .engine
                .clone();
            // The raw Arc owns this borrow until parent cleanup. The fork child leaks
            // the original Runtime after explicit native OS-resource ownership transfer.
            frozen.owner = Arc::into_raw(owner);
            let runtime: &'static Runtime = unsafe { &*frozen.owner };
            frozen.runtime = Some(runtime.freeze_fork().map_err(|e| e.to_string())?);
            let agent = state().lock().map_err(|_| "Agent state poisoned")?;
            let sandbox = crate::SandboxState {
                firewall: agent.sandbox.firewall.clone(),
                process: Arc::new(crate::snapshot::Snapshot::from(
                    agent.sandbox.process.load_full(),
                )),
                file: Arc::new(crate::snapshot::Snapshot::from(
                    agent.sandbox.file.load_full(),
                )),
                version: Arc::new(std::sync::atomic::AtomicU64::new(
                    agent.sandbox.version.load(Ordering::Acquire),
                )),
            };
            frozen.snapshot = Some(AgentRuntime {
                engine: hyperhub_engine::resident(),
                session: agent.session.clone(),
                gateway: agent.gateway.clone(),
                trust: agent.trust.clone(),
                sandbox,
            });
            frozen.agent = Some(agent);
            Ok(())
        })();
        if let Err(error) = result {
            frozen.error = Some(error);
        }
        // Lock order is GATE -> Engine/state -> publisher. A publisher writer
        // already owns Agent state, so taking this read guard earlier reverses
        // that order. Hold it through kernel fork to prevent an alias reaching
        // application memory after the child snapshot has been pinned.
        let inherited = NATIVE_ALIASES.load(Ordering::Acquire);
        if unmanaged
            && (!crate::attachment::local_owner() || crate::attachment::startup::native_only())
        {
            // This unmanaged process owns a lifetime pin that is never replaced
            // or freed. Its copied publisher lock must never be entered, even
            // when this child later forks again or the pin could not be captured.
            if !inherited.is_null() {
                unsafe {
                    Arc::increment_strong_count(inherited);
                }
                frozen.alias_pin = Some(unsafe { Arc::from_raw(inherited) });
            }
        } else {
            match crate::native_alias_snapshot::pin_for_fork() {
                Ok((pin, guard)) => {
                    frozen.alias_pin = Some(pin);
                    frozen.alias_guard = Some(guard);
                }
                Err(code) => {
                    frozen.error = Some(format!("cannot pin native alias compatibility: {code}"));
                }
            }
        }
        let pointer = Box::into_raw(Box::new(frozen));
        FROZEN.store(pointer, Ordering::Release);
        RETURN_OWNER.with(|owner| owner.set(ReturnOwner::Parent(pointer)));
    });
    // Last: socket lifecycle never waits behind Engine/state while holding this fence.
    unsafe { hyperhub_runtime::owned_ipc_fds::fork_prepare() };
}
unsafe extern "C" fn parent() {
    unsafe { hyperhub_runtime::owned_ipc_fds::fork_parent() };
    unsafe { finish_parent(crate::attachment::local_owner()) };
}

unsafe fn finish_parent(local_owner: bool) {
    let ReturnOwner::Parent(pointer) = RETURN_OWNER.with(Cell::get) else {
        return;
    };
    if pointer.is_null() || FROZEN.load(Ordering::Acquire) != pointer {
        return;
    }
    let frozen = unsafe { &mut *pointer };
    drop(frozen.alias_guard.take());
    drop(frozen.alias_pin.take());
    if frozen.unmanaged {
        if local_owner && frozen.late_listener_entered {
            // A resident tree still owns the permanent late listener. Core may
            // be holding this fork between libc's parent callback and its final
            // onLeave callback. Keep that interval visible to activation only
            // if this invocation actually entered that listener. The global
            // PREPARED flag can become true during an older, unobserved fork.
            return;
        }
        drop(unsafe { take_parent_snapshot(take_return_owner()) });
        return;
    }
    drop(frozen.runtime.take());
    drop(frozen.agent.take());
    if !frozen.owner.is_null() {
        unsafe {
            drop(Arc::from_raw(frozen.owner));
        }
        frozen.owner = std::ptr::null();
    }
    drop(frozen.snapshot.take());
    // Retain the serial fork gate until the post-Frida return callback has
    // consumed the real fork result and cancelled a failed fork's handoff.
}
unsafe extern "C" fn child() {
    // First, for both tree-managed and process/unmanaged descendants. Vanished
    // control workers cannot run their copied Stream/Listener destructors.
    unsafe { hyperhub_runtime::owned_ipc_fds::fork_child() };
    // The child's OS identity changed, but its fork-calling thread inherited
    // this already-initialized TLS slot. Host rebuild may consume FROZEN before
    // onLeave, so child return ownership must not depend on that global pointer.
    RETURN_OWNER.with(|owner| owner.set(ReturnOwner::Child));
    let pointer = FROZEN.load(Ordering::Acquire);
    if !pointer.is_null() {
        let frozen = unsafe { &mut *pointer };
        // Neither a copied lock guard nor an Arc destructor may run here.
        std::mem::forget(frozen.alias_guard.take());
        if let Some(pin) = frozen.alias_pin.take() {
            NATIVE_ALIASES.store(Arc::into_raw(pin).cast_mut(), Ordering::Release);
        }
    }
    // A later native-only descendant may fork without a managed rebuild. It
    // must create its own gate in parent context instead of using this lock.
    GATE.store(std::ptr::null_mut(), Ordering::Release);
    let unmanaged = if pointer.is_null() {
        crate::attachment::managed() && !crate::attachment::propagating()
    } else {
        // Freeze admission is chosen before kernel fork. A concurrent logical
        // detach must not discard an already-reserved child's snapshot.
        (*pointer).unmanaged
    };
    CHILD_PROTECTED.store(
        !unmanaged && crate::attachment::managed(),
        Ordering::Release,
    );
    if unmanaged {
        RETURN_OWNER.with(|owner| owner.set(ReturnOwner::None));
        FROZEN.store(std::ptr::null_mut(), Ordering::Release);
        crate::attachment::after_fork_unmanaged_child();
        crate::engine_call::reset_after_fork();
        return;
    }
    crate::attachment::after_fork_child();
    CHILD.store(true, Ordering::Release);
    RECOVERING.store(false, Ordering::Release);
    CHILD_SIGNAL_MASKED.store(false, Ordering::Release);
    CHILD_READY.store(1, Ordering::Release);
    let pointer = FROZEN.load(Ordering::Acquire);
    let lease = if pointer.is_null() {
        None
    } else {
        unsafe { &*pointer }.lease.as_ref()
    };
    if let Some(lease) = lease {
        for (destination, source) in CHILD_LEASE.iter().zip(lease) {
            destination.store(*source, Ordering::Relaxed);
        }
    }
    let claimed = !pointer.is_null()
        && unsafe { &*pointer }.error.is_none()
        && unsafe { &*pointer }
            .lease
            .as_ref()
            .is_some_and(|lease| unsafe { super::fork_handoff::claim(lease).is_ok() });
    if !claimed && CHILD_PROTECTED.load(Ordering::Acquire) {
        // Do not wait inside pthread_atfork: Frida still has to restore its
        // runtime and dispatch the authenticated recovery worker. The final
        // return callback, not this callback, holds the application thread.
        return;
    }
    if !claimed {
        // Copied Runtime locks cannot safely serve application calls. A lost
        // manager never permits an unregistered child to return to the target.
        unsafe {
            if !live_failure_passthrough() {
                libc::syscall(libc::SYS_exit_group, 126);
            }
        };
    }
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_is_armed() -> u32 {
    u32::from(fork_listener_current())
}

fn fork_listener_current() -> bool {
    FORK_LISTENER_ARMED.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_mark_armed(
    _generation: u32,
    _deadline_millis: u64,
) -> i32 {
    // The permanent script intercepts this call to install its callback. The
    // separate generation-checked commit below is the only readiness publish.
    // Keep an actual atomic side effect here: an empty or compiler-only body
    // becomes too short for Frida to patch in optimized Agent artifacts.
    FORK_LISTENER_MARK_TRIGGERS.fetch_add(1, Ordering::Relaxed);
    // The listener replaces this result with the exact rearm transaction
    // status. If no permanent script owns the trigger, fail closed.
    crate::HH_ERR_PROTOCOL
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_rearm_begin(generation: u32, deadline_millis: u64) -> i32 {
    let _guard = match gate().try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return crate::HH_ERR_ACTIVATION_BUSY,
        Err(std::sync::TryLockError::Poisoned(_)) => return crate::HH_ERR_PROTOCOL,
    };
    if FORK_LISTENER_TRANSITION.load(Ordering::Acquire) != 0
        || FORK_LISTENER_GENERATION.load(Ordering::Acquire) != generation
        || monotonic_millis() >= deadline_millis
    {
        return crate::HH_ERR_ACTIVATION_BUSY;
    }
    FORK_LISTENER_TRANSITION.store(1, Ordering::Release);
    super::native_rearm_begin();
    crate::HH_OK
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_rearm_commit(
    generation: u32,
    deadline_millis: u64,
) -> i32 {
    let _guard = match gate().try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return crate::HH_ERR_ACTIVATION_BUSY,
        Err(std::sync::TryLockError::Poisoned(_)) => return crate::HH_ERR_PROTOCOL,
    };
    if FORK_LISTENER_TRANSITION.load(Ordering::Acquire) != 1 {
        return crate::HH_ERR_PROTOCOL;
    }
    if FORK_LISTENER_GENERATION.load(Ordering::Acquire) != generation
        || monotonic_millis() >= deadline_millis
    {
        return crate::HH_ERR_ACTIVATION_BUSY;
    }
    FORK_LISTENER_ARMED.store(true, Ordering::Release);
    FORK_LISTENER_EPOCH.fetch_add(1, Ordering::AcqRel);
    super::native_arm_confirmed();
    super::native_arm_installed();
    finish_listener_transition();
    crate::HH_OK
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_rearm_cancel() -> i32 {
    let _guard = match gate().try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return crate::HH_ERR_ACTIVATION_BUSY,
        Err(std::sync::TryLockError::Poisoned(_)) => return crate::HH_ERR_PROTOCOL,
    };
    if FORK_LISTENER_TRANSITION.load(Ordering::Acquire) != 1 {
        return crate::HH_ERR_PROTOCOL;
    }
    finish_listener_transition();
    crate::HH_OK
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_abort_begin() -> i32 {
    let _guard = match gate().try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return crate::HH_ERR_ACTIVATION_BUSY,
        Err(std::sync::TryLockError::Poisoned(_)) => return crate::HH_ERR_PROTOCOL,
    };
    if FORK_LISTENER_TRANSITION.load(Ordering::Acquire) == 0 {
        FORK_LISTENER_TRANSITION.store(1, Ordering::Release);
    }
    crate::HH_OK
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_abort_commit() -> i32 {
    let _guard = match gate().try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return crate::HH_ERR_ACTIVATION_BUSY,
        Err(std::sync::TryLockError::Poisoned(_)) => return crate::HH_ERR_PROTOCOL,
    };
    if FORK_LISTENER_TRANSITION.load(Ordering::Acquire) != 1 {
        return crate::HH_ERR_PROTOCOL;
    }
    FORK_LISTENER_GENERATION.fetch_add(1, Ordering::AcqRel);
    FORK_LISTENER_ARMED.store(false, Ordering::Release);
    super::native_rearm_begin();
    finish_listener_transition();
    crate::HH_OK
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_generation() -> u32 {
    FORK_LISTENER_GENERATION.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_abort_arm() -> i32 {
    // The permanent listener script intercepts this trigger and replaces its
    // return value with abort_run's result. Reaching the body means no script
    // owns the listener, so the caller must not claim retirement.
    crate::HH_ERR_PROTOCOL
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_prepare_rearm() {
    super::native_rearm_begin();
}

const REARM_COMMITTED: i32 = 0x4848_4f4b;

fn with_rearm_gate(change: impl FnOnce() -> i32) -> i32 {
    let _guard = match gate().try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return crate::HH_ERR_ACTIVATION_BUSY,
        Err(std::sync::TryLockError::Poisoned(_)) => return crate::HH_ERR_PROTOCOL,
    };
    // The synchronous NativeCallback always returns through this native stack
    // frame, including a JavaScript interruption. No JS finally is needed to
    // unlock the guard, and no other thread can receive or release it.
    match change() {
        REARM_COMMITTED => crate::HH_OK,
        error if error < 0 => error,
        // A NativeCallback interrupted by QuickJS returns a zero-filled native
        // result. That value must never stand for a committed transaction.
        _ => crate::HH_ERR_PROTOCOL,
    }
}

fn monotonic_millis() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut now) } != 0 {
        return u64::MAX;
    }
    (now.tv_sec.max(0) as u64)
        .saturating_mul(1_000)
        .saturating_add((now.tv_nsec.max(0) as u64) / 1_000_000)
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_rearm_run(
    generation: u32,
    deadline_millis: u64,
    apply: Option<extern "C" fn() -> i32>,
    commit: Option<extern "C" fn() -> i32>,
    rollback: Option<extern "C" fn() -> i32>,
) -> i32 {
    let (Some(apply), Some(commit), Some(rollback)) = (apply, commit, rollback) else {
        return crate::HH_ERR_PROTOCOL;
    };
    with_rearm_gate(|| {
        if FORK_LISTENER_GENERATION.load(Ordering::Acquire) != generation
            || monotonic_millis() >= deadline_millis
        {
            return crate::HH_ERR_ACTIVATION_BUSY;
        }
        let applied = apply();
        if applied != REARM_COMMITTED {
            return applied;
        }
        if FORK_LISTENER_GENERATION.load(Ordering::Acquire) != generation
            || monotonic_millis() >= deadline_millis
        {
            return match rollback() {
                REARM_COMMITTED => crate::HH_ERR_ACTIVATION_BUSY,
                error if error < 0 => error,
                _ => crate::HH_ERR_PROTOCOL,
            };
        }
        let committed = commit();
        if committed != REARM_COMMITTED {
            let _ = rollback();
            return committed;
        }
        if FORK_LISTENER_GENERATION.load(Ordering::Acquire) != generation
            || monotonic_millis() >= deadline_millis
        {
            return match rollback() {
                REARM_COMMITTED => crate::HH_ERR_ACTIVATION_BUSY,
                error if error < 0 => error,
                _ => crate::HH_ERR_PROTOCOL,
            };
        }
        // Listener publication and the native ready state share this gate and
        // generation check. Application fork preparation uses the same gate,
        // so it cannot observe the staged listener before commit completes.
        FORK_LISTENER_ARMED.store(true, Ordering::Release);
        FORK_LISTENER_EPOCH.fetch_add(1, Ordering::AcqRel);
        super::native_arm_confirmed();
        super::native_arm_installed();
        REARM_COMMITTED
    })
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_abort_run(change: Option<extern "C" fn() -> i32>) -> i32 {
    let Some(change) = change else {
        return crate::HH_ERR_PROTOCOL;
    };
    // Abort is issued by the Frida owner. Never block that owner behind an
    // application fork or an in-flight listener transaction that may itself
    // need Frida progress; CleanupPending retries an explicit busy result.
    let _guard = match gate().try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return crate::HH_ERR_ACTIVATION_BUSY,
        Err(std::sync::TryLockError::Poisoned(_)) => return crate::HH_ERR_PROTOCOL,
    };
    FORK_LISTENER_GENERATION.fetch_add(1, Ordering::AcqRel);
    FORK_LISTENER_ARMED.store(false, Ordering::Release);
    super::native_rearm_begin();
    match change() {
        REARM_COMMITTED => crate::HH_OK,
        error if error < 0 => error,
        _ => crate::HH_ERR_PROTOCOL,
    }
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_recovery_pending() -> u32 {
    u32::from(CHILD.load(Ordering::Acquire))
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_epoch() -> u32 {
    FORK_LISTENER_EPOCH.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_confirm_rearm() -> u32 {
    // Legacy ABI retained for resident-module identification. Transactional
    // rearm publishes epoch and readiness inside rearm_run's native gate.
    FORK_LISTENER_EPOCH
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1)
}

#[no_mangle]
pub unsafe extern "C" fn hyperhub_fork_listener_enter(
    _context: *mut super::gum::GumInvocationContext,
) {
    LATE_LISTENER_ENTERED.with(|entered| entered.set(fork_listener_current()));
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_is_prepared() -> u32 {
    u32::from(FORK_LISTENER_PREPARED.load(Ordering::Acquire))
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_mark_prepared() {
    FORK_LISTENER_PREPARED.store(true, Ordering::Release);
}

/// Runs before Frida's native fork-recovery listener, after all libc atfork
/// callbacks. Only Frida's recovery can run until the final return gate opens.
#[no_mangle]
pub unsafe extern "C" fn hyperhub_fork_recovery_begin(
    context: *mut super::gum::GumInvocationContext,
) {
    if crate::attachment::managed()
        && !CHILD.load(Ordering::Acquire)
        && (!crate::attachment::propagating() || !fork_listener_current())
    {
        return;
    }
    if fork_result(super::gum::return_value(context) as usize) == 0 {
        // Linux x86_64/aarch64 use an eight-byte kernel signal set. Preserve
        // changes made by application atfork callbacks, which have now finished.
        // Recovery recreates threads through ptrace, without delivery of a
        // catchable asynchronous signal to this original application thread.
        let previous = match replace_signal_mask(recovery_async_signal_mask()) {
            Ok(previous) => previous,
            Err(()) => {
                if !live_failure_passthrough() {
                    libc::syscall(libc::SYS_exit_group, 126);
                }
                return;
            }
        };
        CHILD_SIGNAL_MASK.store(previous, Ordering::Relaxed);
        CHILD_SIGNAL_MASKED.store(true, Ordering::Release);
        RECOVERING.store(true, Ordering::Release);
    }
}

/// Called by the manager's persistent native listener after Frida's fork
/// recovery. The child path uses no allocation, TLS initialization, inherited
/// mutex, or Engine entry.
#[no_mangle]
pub unsafe extern "C" fn hyperhub_fork_return_gate(context: *mut super::gum::GumInvocationContext) {
    // Also clear calls that returned without reaching our atfork prepare
    // callback (for example, another interceptor replaced the native call).
    LATE_LISTENER_ENTERED.with(|entered| entered.set(false));
    let owner = take_return_owner();
    match owner {
        ReturnOwner::None => return,
        ReturnOwner::Parent(_) => {
            let result = fork_result(super::gum::return_value(context) as usize);
            // A real child must have run the atfork child callback. Never drop
            // copied parent guards if a foreign interceptor fabricated zero.
            if result == 0 {
                return;
            }
            let Some(mut frozen) = take_parent_snapshot(owner) else {
                return;
            };
            // Admission was frozen before kernel fork, independently of a
            // logical phase change while Core handled its native listener.
            if frozen.unmanaged {
                return;
            }
            if result < 0 {
                if let Some(lease) = frozen.lease.take() {
                    let _ = super::fork_handoff::cancel(&lease);
                }
            } else if frozen
                .lease
                .as_ref()
                .is_none_or(|lease| super::fork_handoff::await_attachment(lease).is_err())
            {
                // Returning before the child owns a Core session would let an
                // immediate parent exit unload the child's Frida provider.
                // A lost manager cannot authorize that uncovered transition.
                if !live_failure_passthrough() {
                    libc::syscall(libc::SYS_exit_group, 126);
                }
                return;
            }
            drop(frozen.gate.take());
            return;
        }
        ReturnOwner::Child => {}
    }
    if CHILD_READY.load(Ordering::Acquire) != 0 {
        let mut lease = [0u8; 32];
        for (destination, source) in lease.iter_mut().zip(&CHILD_LEASE) {
            *destination = source.load(Ordering::Relaxed);
        }
        if super::fork_handoff::ready(&lease).is_err() {
            if !live_failure_passthrough() {
                libc::syscall(libc::SYS_exit_group, 126);
            }
            return;
        }
    }
    // The callback can execute after parent gating was automatically released.
    // Keep the original application thread here until the manager has completed
    // enrollment and armed the surviving child's own fork gate.
    let deadline = match super::fork_handoff::monotonic_ms() {
        Ok(now) => now + 10_000,
        Err(()) => {
            if !live_failure_passthrough() {
                libc::syscall(libc::SYS_exit_group, 126);
            }
            return;
        }
    };
    loop {
        let expected = CHILD_READY.load(Ordering::Acquire);
        if expected == 0 {
            break;
        }
        let remaining = super::fork_handoff::monotonic_ms()
            .map(|now| deadline - now)
            .unwrap_or(0);
        if remaining <= 0 {
            if !live_failure_passthrough() {
                libc::syscall(libc::SYS_exit_group, 126);
            }
            return;
        }
        let timeout = libc::timespec {
            tv_sec: remaining / 1_000,
            tv_nsec: (remaining % 1_000) * 1_000_000,
        };
        let waited = libc::syscall(
            libc::SYS_futex,
            &CHILD_READY as *const AtomicU32 as *const u32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            &timeout,
            std::ptr::null::<u32>(),
            0u32,
        );
        if waited < 0 && *libc::__errno_location() == libc::ETIMEDOUT {
            if !live_failure_passthrough() {
                libc::syscall(libc::SYS_exit_group, 126);
            }
        }
    }
    if CHILD_SIGNAL_MASKED.swap(false, Ordering::AcqRel) {
        let previous = CHILD_SIGNAL_MASK.load(Ordering::Relaxed);
        // Publication has cleared CHILD. Restoring the mask may immediately
        // deliver an application handler; it must use the rebuilt Host policy.
        if replace_signal_mask(previous).is_err() {
            if !live_failure_passthrough() {
                libc::syscall(libc::SYS_exit_group, 126);
            }
        }
    }
}

// A live-attached application does not become owned by its observer. If the
// native fork handoff itself fails, do not kill it as the legacy launcher did.
// The child's copied state is abandoned atomically so no vanished-parent lock
// is entered. The manager records the resulting loss of coverage explicitly.
unsafe fn live_failure_passthrough() -> bool {
    if !crate::attachment::managed() {
        return false;
    }
    if CHILD.load(Ordering::Acquire) && CHILD_PROTECTED.load(Ordering::Acquire) {
        // Managed admission is captured by atfork before SDK entry. Ordinary
        // startup delay or failure must neither erase its eventual rollback
        // binding nor bypass an Active parent's policy. Only real publication or approved cancellation opens
        // this original thread's return gate.
        wait_protected_child();
        return true;
    }
    if CHILD.load(Ordering::Acquire) {
        RETURN_OWNER.with(|owner| owner.set(ReturnOwner::None));
        CHILD.store(false, Ordering::Release);
        CHILD_READY.store(0, Ordering::Release);
        FROZEN.store(std::ptr::null_mut(), Ordering::Release);
        if CHILD_SIGNAL_MASKED.swap(false, Ordering::AcqRel) {
            let _ = replace_signal_mask(CHILD_SIGNAL_MASK.load(Ordering::Acquire));
        }
        crate::attachment::after_fork_unmanaged_child();
        crate::engine_call::reset_after_fork();
    }
    true
}

unsafe fn wait_protected_child() {
    while CHILD_READY.load(Ordering::Acquire) != 0 {
        let expected = CHILD_READY.load(Ordering::Acquire);
        if expected == 0 {
            break;
        }
        let timeout = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        libc::syscall(
            libc::SYS_futex,
            &CHILD_READY as *const AtomicU32 as *const u32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            &timeout,
            std::ptr::null::<u32>(),
            0u32,
        );
    }
    if CHILD_SIGNAL_MASKED.swap(false, Ordering::AcqRel) {
        let _ = replace_signal_mask(CHILD_SIGNAL_MASK.load(Ordering::Acquire));
    }
}

fn fork_result(raw: usize) -> libc::pid_t {
    raw as libc::pid_t
}

fn recovery_async_signal_mask() -> u64 {
    // Frida/Gum uses its exception machinery while rebuilding after fork.
    // Blocking synchronous faults makes a recoverable probe terminate the
    // process before either the service or application handler can run.
    let mut mask = u64::MAX;
    for signal in [
        libc::SIGSEGV,
        libc::SIGBUS,
        libc::SIGILL,
        libc::SIGFPE,
        libc::SIGTRAP,
        libc::SIGSYS,
    ] {
        mask &= !(1u64 << (signal - 1));
    }
    mask
}

unsafe fn replace_signal_mask(mask: u64) -> Result<u64, ()> {
    let mut previous = 0u64;
    if libc::syscall(
        libc::SYS_rt_sigprocmask,
        libc::SIG_SETMASK,
        &mask,
        &mut previous,
        std::mem::size_of::<u64>(),
    ) == 0
    {
        Ok(previous)
    } else {
        Err(())
    }
}

fn publish_state(
    child: &AtomicBool,
    ready: &AtomicU32,
    receipt: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    if ready.load(Ordering::Acquire) != 2 {
        return Err("fork child enrollment is not ready for publication");
    }
    // The original application may call _exit as soon as the gate opens.
    // Commit its complete receipt first; it must not depend on a publisher
    // thread surviving after application execution becomes possible.
    receipt()?;
    child.store(false, Ordering::Release);
    ready.store(0, Ordering::Release);
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            ready as *const AtomicU32 as *const u32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            i32::MAX,
        );
    }
    Ok(())
}
pub(crate) fn publish(
    receipt: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    publish_state(&CHILD, &CHILD_READY, receipt)
}
/// Only called after a verified lifecycle Detach cancelled this initializer.
/// A startup error alone must not release an Active tree's protected child.
pub(crate) fn cancel_initialization_after_approved_detach() {
    if !crate::attachment::startup::cancelled()
        || crate::attachment::startup::running() != 0
        || !CHILD.load(Ordering::Acquire)
    {
        return;
    }
    // Copied parent guards cannot be dropped by this worker. Native-only
    // execution keeps their old ownership pinned rather than unlocking them.
    FROZEN.store(std::ptr::null_mut(), Ordering::Release);
    GATE.store(Box::into_raw(Box::new(Mutex::new(()))), Ordering::Release);
    CHILD.store(false, Ordering::Release);
    CHILD_PROTECTED.store(false, Ordering::Release);
    CHILD_READY.store(0, Ordering::Release);
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            &CHILD_READY as *const AtomicU32 as *const u32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            i32::MAX,
        );
    }
    // The original thread owns and restores CHILD_SIGNAL_MASK on its return
    // path. This worker must not change another thread's signal mask.
}
pub(crate) fn rebuild() -> Result<(), String> {
    if !CHILD.load(Ordering::Acquire) {
        return Err("missing frozen fork child state".into());
    }
    let pointer = FROZEN.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if pointer.is_null() {
        return Err("fork snapshot is missing".into());
    }
    let mut frozen = unsafe { Box::from_raw(pointer) };
    let image = frozen
        .runtime
        .take()
        .map(|guard| unsafe { guard.into_child_image() });
    // These guards were acquired by the parent's fork-calling thread. Frida
    // invokes rebuild in a different child thread: unlocking them is undefined.
    std::mem::forget(frozen.agent.take());
    std::mem::forget(frozen.gate.take());
    GATE.store(Box::into_raw(Box::new(Mutex::new(()))), Ordering::Release);
    let Some(image) = image else {
        return Err(frozen
            .error
            .take()
            .unwrap_or_else(|| "fork Runtime snapshot is missing".into()));
    };
    let mut rebuilt = frozen
        .snapshot
        .take()
        .ok_or("fork Host snapshot is missing")?;
    // Install fresh Host locks before loading native modules. Constructor-created
    // threads must never wait on a copied lock owned by a vanished parent thread.
    crate::runtime::replace_fork_state_preserving_access(AgentRuntime::default());
    crate::engine_call::background(|| {
        let forked = unsafe { image.rebuild() }.map_err(|e| e.to_string())?;
        for socket in rebuilt.gateway.sockets.values_mut() {
            socket.engine = forked.rebind(&socket.engine).map_err(|e| e.to_string())?;
        }
        rebuilt.engine = forked.runtime.clone();
        crate::native_alias_snapshot::rebuild(&rebuilt.gateway);
        crate::runtime::replace_fork_state_preserving_access(rebuilt);
        crate::attachment::startup::runtime_rebuilt()
            .map_err(|_| "fork Runtime publication failed")?;
        crate::attachment::startup::check().map_err(|_| "fork initialization was cancelled")?;
        super::initialize_mapping_probe()?;
        drop(forked);
        crate::control::reenroll_fork_engine()
            .map_err(|e| format!("fork Engine enrollment failed: {e}"))?;
        crate::attachment::startup::check().map_err(|_| "fork initialization was cancelled")?;
        crate::subscribe_sandbox();
        crate::attachment::startup::check().map_err(|_| "fork initialization was cancelled")?;
        CHILD_READY.store(2, Ordering::Release);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static MODEL_PERSISTENT_LISTENER: AtomicBool = AtomicBool::new(false);
    static MODEL_STAGED_LISTENER: AtomicBool = AtomicBool::new(false);
    static MODEL_PREVIOUS_LISTENER: AtomicBool = AtomicBool::new(false);
    static MODEL_INSTALL_ENTERED: AtomicBool = AtomicBool::new(false);
    static MODEL_INSTALL_RELEASED: AtomicBool = AtomicBool::new(false);
    static MODEL_APPLY_CALLED: AtomicBool = AtomicBool::new(false);
    static MODEL_COMMIT_CALLED: AtomicBool = AtomicBool::new(false);
    static MODEL_ROLLBACK_CALLED: AtomicBool = AtomicBool::new(false);

    extern "C" fn install_model_listener() -> i32 {
        MODEL_APPLY_CALLED.store(true, Ordering::Release);
        MODEL_PREVIOUS_LISTENER.store(
            MODEL_PERSISTENT_LISTENER.load(Ordering::Acquire),
            Ordering::Release,
        );
        MODEL_STAGED_LISTENER.store(true, Ordering::Release);
        REARM_COMMITTED
    }

    extern "C" fn commit_model_listener() -> i32 {
        MODEL_COMMIT_CALLED.store(true, Ordering::Release);
        if !MODEL_STAGED_LISTENER.swap(false, Ordering::AcqRel) {
            return crate::HH_ERR_PROTOCOL;
        }
        MODEL_PERSISTENT_LISTENER.store(true, Ordering::Release);
        REARM_COMMITTED
    }

    extern "C" fn rollback_model_listener() -> i32 {
        MODEL_ROLLBACK_CALLED.store(true, Ordering::Release);
        MODEL_STAGED_LISTENER.store(false, Ordering::Release);
        MODEL_PERSISTENT_LISTENER.store(
            MODEL_PREVIOUS_LISTENER.load(Ordering::Acquire),
            Ordering::Release,
        );
        REARM_COMMITTED
    }

    extern "C" fn abort_model_listener() -> i32 {
        MODEL_PERSISTENT_LISTENER.store(false, Ordering::Release);
        REARM_COMMITTED
    }

    extern "C" fn install_model_listener_and_wait() -> i32 {
        let result = install_model_listener();
        MODEL_INSTALL_ENTERED.store(true, Ordering::Release);
        while !MODEL_INSTALL_RELEASED.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        result
    }

    #[test]
    fn mark_armed_trigger_has_code_without_publishing_readiness() {
        const CHILD: &str = "HH_TEST_MARK_ARMED_TRIGGER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let test = format!(
                "{}::mark_armed_trigger_has_code_without_publishing_readiness",
                module_path!().split_once("::").unwrap().1
            );
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .env(CHILD, "1")
                .args(["--exact", &test, "--test-threads=1"])
                .status()
                .unwrap()
                .success());
            return;
        }
        FORK_LISTENER_ARMED.store(false, Ordering::Release);
        let before = FORK_LISTENER_MARK_TRIGGERS.load(Ordering::Acquire);
        let epoch = FORK_LISTENER_EPOCH.load(Ordering::Acquire);
        assert_eq!(
            hyperhub_fork_listener_mark_armed(17, u64::MAX),
            crate::HH_ERR_PROTOCOL
        );
        assert_eq!(
            FORK_LISTENER_MARK_TRIGGERS.load(Ordering::Acquire),
            before.wrapping_add(1)
        );
        assert_eq!(hyperhub_fork_listener_is_armed(), 0);
        assert_eq!(FORK_LISTENER_EPOCH.load(Ordering::Acquire), epoch);
    }

    #[test]
    fn rearm_transition_holds_fork_gate_until_commit_or_cancel() {
        const CHILD: &str = "HH_TEST_REARM_TRANSITION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let test = format!(
                "{}::rearm_transition_holds_fork_gate_until_commit_or_cancel",
                module_path!().split_once("::").unwrap().1
            );
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .env(CHILD, "1")
                .args(["--exact", &test, "--test-threads=1"])
                .status()
                .unwrap()
                .success());
            return;
        }
        FORK_LISTENER_TRANSITION.store(0, Ordering::Release);
        FORK_LISTENER_ARMED.store(false, Ordering::Release);
        let generation = FORK_LISTENER_GENERATION.load(Ordering::Acquire);
        let epoch = FORK_LISTENER_EPOCH.load(Ordering::Acquire);
        assert_eq!(
            hyperhub_fork_listener_rearm_begin(generation, u64::MAX),
            crate::HH_OK
        );
        let (ready, waiting) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let _guard = listener_gate();
            ready.send(()).unwrap();
        });
        assert!(waiting
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        assert_eq!(
            hyperhub_fork_listener_rearm_commit(generation, u64::MAX),
            crate::HH_OK
        );
        waiting
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        waiter.join().unwrap();
        assert_eq!(FORK_LISTENER_EPOCH.load(Ordering::Acquire), epoch + 1);
        assert_eq!(hyperhub_fork_listener_is_armed(), 1);

        assert_eq!(
            hyperhub_fork_listener_rearm_begin(generation, u64::MAX),
            crate::HH_OK
        );
        assert_eq!(hyperhub_fork_listener_rearm_cancel(), crate::HH_OK);
        assert_eq!(FORK_LISTENER_EPOCH.load(Ordering::Acquire), epoch + 1);
        assert_eq!(FORK_LISTENER_TRANSITION.load(Ordering::Acquire), 0);
    }

    #[test]
    fn arm_generation_serializes_abort_late_install_and_commit() {
        const CHILD: &str = "HH_TEST_ARM_GENERATION_TRANSACTION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let test = format!(
                "{}::arm_generation_serializes_abort_late_install_and_commit",
                module_path!().split_once("::").unwrap().1
            );
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(test)
                .arg("--nocapture")
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        MODEL_PERSISTENT_LISTENER.store(false, Ordering::Release);

        // A: abort wins before a delayed mark transaction. The old token must
        // not execute the listener-install callback at all.
        MODEL_APPLY_CALLED.store(false, Ordering::Release);
        MODEL_COMMIT_CALLED.store(false, Ordering::Release);
        MODEL_ROLLBACK_CALLED.store(false, Ordering::Release);
        let stale = hyperhub_fork_listener_generation();
        assert_eq!(
            hyperhub_fork_listener_abort_run(Some(abort_model_listener)),
            crate::HH_OK
        );
        assert_eq!(
            hyperhub_fork_listener_rearm_run(
                stale,
                u64::MAX,
                Some(install_model_listener),
                Some(commit_model_listener),
                Some(rollback_model_listener),
            ),
            crate::HH_ERR_ACTIVATION_BUSY
        );
        assert!(!MODEL_APPLY_CALLED.load(Ordering::Acquire));
        assert!(!MODEL_COMMIT_CALLED.load(Ordering::Acquire));
        assert!(!MODEL_ROLLBACK_CALLED.load(Ordering::Acquire));
        assert!(!MODEL_PERSISTENT_LISTENER.load(Ordering::Acquire));

        // B: the callback has installed its listener but has not returned its
        // commit marker. Abort blocks on the same gate; application fork
        // preparation uses that gate too and cannot observe partial state.
        let pending = hyperhub_fork_listener_generation();
        MODEL_INSTALL_ENTERED.store(false, Ordering::Release);
        MODEL_INSTALL_RELEASED.store(false, Ordering::Release);
        let arm = std::thread::spawn(move || {
            hyperhub_fork_listener_rearm_run(
                pending,
                u64::MAX,
                Some(install_model_listener_and_wait),
                Some(commit_model_listener),
                Some(rollback_model_listener),
            )
        });
        while !MODEL_INSTALL_ENTERED.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        assert!(MODEL_STAGED_LISTENER.load(Ordering::Acquire));
        assert!(!MODEL_PERSISTENT_LISTENER.load(Ordering::Acquire));
        assert_eq!(
            hyperhub_fork_listener_abort_run(Some(abort_model_listener)),
            crate::HH_ERR_ACTIVATION_BUSY
        );
        assert!(MODEL_STAGED_LISTENER.load(Ordering::Acquire));
        assert!(!MODEL_PERSISTENT_LISTENER.load(Ordering::Acquire));
        MODEL_INSTALL_RELEASED.store(true, Ordering::Release);
        assert_eq!(arm.join().unwrap(), crate::HH_OK);
        assert_eq!(
            hyperhub_fork_listener_abort_run(Some(abort_model_listener)),
            crate::HH_OK
        );
        assert!(!MODEL_PERSISTENT_LISTENER.load(Ordering::Acquire));

        // A staged candidate that crosses its target-side monotonic deadline
        // is rolled back under the gate. It never reaches commit or readiness.
        MODEL_PERSISTENT_LISTENER.store(false, Ordering::Release);
        MODEL_STAGED_LISTENER.store(false, Ordering::Release);
        MODEL_INSTALL_ENTERED.store(false, Ordering::Release);
        MODEL_INSTALL_RELEASED.store(false, Ordering::Release);
        MODEL_COMMIT_CALLED.store(false, Ordering::Release);
        MODEL_ROLLBACK_CALLED.store(false, Ordering::Release);
        FORK_LISTENER_ARMED.store(false, Ordering::Release);
        let epoch_before_timeout = FORK_LISTENER_EPOCH.load(Ordering::Acquire);
        let deadline = monotonic_millis().saturating_add(20);
        let generation = hyperhub_fork_listener_generation();
        let expired = std::thread::spawn(move || {
            hyperhub_fork_listener_rearm_run(
                generation,
                deadline,
                Some(install_model_listener_and_wait),
                Some(commit_model_listener),
                Some(rollback_model_listener),
            )
        });
        while !MODEL_INSTALL_ENTERED.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        while monotonic_millis() < deadline {
            std::thread::yield_now();
        }
        MODEL_INSTALL_RELEASED.store(true, Ordering::Release);
        assert_eq!(expired.join().unwrap(), crate::HH_ERR_ACTIVATION_BUSY);
        assert!(!MODEL_COMMIT_CALLED.load(Ordering::Acquire));
        assert!(MODEL_ROLLBACK_CALLED.load(Ordering::Acquire));
        assert!(!MODEL_STAGED_LISTENER.load(Ordering::Acquire));
        assert!(!MODEL_PERSISTENT_LISTENER.load(Ordering::Acquire));
        assert_eq!(hyperhub_fork_listener_is_armed(), 0);
        assert_eq!(
            FORK_LISTENER_EPOCH.load(Ordering::Acquire),
            epoch_before_timeout
        );

        // C: a committed generation can still be retired. Abort removes its
        // listener and clears the public armed state before returning success.
        MODEL_APPLY_CALLED.store(false, Ordering::Release);
        MODEL_COMMIT_CALLED.store(false, Ordering::Release);
        MODEL_ROLLBACK_CALLED.store(false, Ordering::Release);
        let committed = hyperhub_fork_listener_generation();
        assert_eq!(
            hyperhub_fork_listener_rearm_run(
                committed,
                u64::MAX,
                Some(install_model_listener),
                Some(commit_model_listener),
                Some(rollback_model_listener),
            ),
            crate::HH_OK
        );
        assert!(MODEL_APPLY_CALLED.load(Ordering::Acquire));
        assert!(MODEL_COMMIT_CALLED.load(Ordering::Acquire));
        assert!(!MODEL_ROLLBACK_CALLED.load(Ordering::Acquire));
        assert_eq!(hyperhub_fork_listener_is_armed(), 1);
        assert_eq!(
            hyperhub_fork_listener_abort_run(Some(abort_model_listener)),
            crate::HH_OK
        );
        assert!(!MODEL_PERSISTENT_LISTENER.load(Ordering::Acquire));
        assert_eq!(hyperhub_fork_listener_is_armed(), 0);
    }

    #[test]
    fn installing_a_listener_during_an_older_fork_does_not_leak_its_parent_gate() {
        const CHILD: &str = "HH_TEST_FORK_LISTENER_INSTALLATION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.env_clear();
            for (name, value) in std::env::vars_os() {
                if matches!(
                    name.to_str(),
                    Some("PATH" | "LD_LIBRARY_PATH" | "DYLD_LIBRARY_PATH")
                ) {
                    command.env(name, value);
                }
            }
            let test = format!(
                "{}::installing_a_listener_during_an_older_fork_does_not_leak_its_parent_gate",
                module_path!().split_once("::").unwrap().1
            );
            assert!(command
                .env(CHILD, "1")
                .args(["--exact", &test, "--test-threads=1"])
                .status()
                .unwrap()
                .success());
            return;
        }
        use super::*;
        // Model both a fork that entered before late-listener installation and
        // a later call that really entered it. Each owns its exact gate guard.
        for observed in [false, true] {
            assert!(!take_late_listener_entry());
            if observed {
                unsafe { hyperhub_fork_listener_enter(std::ptr::null_mut()) };
                assert!(!std::thread::spawn(take_late_listener_entry).join().unwrap());
            }
            let gate = Box::leak(Box::new(Mutex::new(())));
            let frozen = Box::new(Frozen {
                runtime: None,
                agent: None,
                gate: Some(gate.lock().unwrap()),
                owner: std::ptr::null(),
                snapshot: None,
                error: None,
                lease: None,
                unmanaged: true,
                late_listener_entered: take_late_listener_entry(),
                alias_pin: None,
                alias_guard: None,
            });
            assert!(!take_late_listener_entry());
            let pointer = Box::into_raw(frozen);
            assert!(FROZEN.swap(pointer, Ordering::AcqRel).is_null());
            RETURN_OWNER.with(|owner| owner.set(ReturnOwner::Parent(pointer)));
            // Installation is published while the older native call is in
            // flight. Its absence from that call cannot be inferred from this.
            FORK_LISTENER_PREPARED.store(true, Ordering::Release);
            unsafe { finish_parent(true) };
            if observed {
                assert!(matches!(
                    gate.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                // The actual onLeave callback owns this release in production.
                drop(unsafe { take_parent_snapshot(take_return_owner()) }.unwrap());
            } else {
                assert!(FROZEN.load(Ordering::Acquire).is_null());
            }
            assert!(gate.try_lock().is_ok());
        }

        // A's unobserved fork has already released its parent gate/token. B
        // acquires the next guard on another real thread. Gum may now call a
        // newly installed onLeave for A: it must not consume B's snapshot or
        // unlock B's Rust guard from A's thread.
        let (ready, installed) = std::sync::mpsc::channel();
        let (resume, proceed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let gate = Box::leak(Box::new(Mutex::new(())));
            let pointer = Box::into_raw(Box::new(Frozen {
                runtime: None,
                agent: None,
                gate: Some(gate.lock().unwrap()),
                owner: std::ptr::null(),
                snapshot: None,
                error: None,
                lease: None,
                unmanaged: true,
                late_listener_entered: true,
                alias_pin: None,
                alias_guard: None,
            }));
            assert!(FROZEN.swap(pointer, Ordering::AcqRel).is_null());
            RETURN_OWNER.with(|owner| owner.set(ReturnOwner::Parent(pointer)));
            ready.send(pointer as usize).unwrap();
            proceed.recv().unwrap();
            assert_eq!(FROZEN.load(Ordering::Acquire), pointer);
            assert!(matches!(
                gate.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            drop(unsafe { take_parent_snapshot(take_return_owner()) }.unwrap());
            assert!(gate.try_lock().is_ok());
        });
        let pointer = installed.recv().unwrap() as *mut Frozen;
        unsafe { hyperhub_fork_return_gate(std::ptr::null_mut()) };
        assert_eq!(FROZEN.load(Ordering::Acquire), pointer);
        assert!(unsafe {
            take_parent_snapshot(ReturnOwner::Parent(
                std::ptr::NonNull::<Frozen>::dangling().as_ptr(),
            ))
        }
        .is_none());
        assert_eq!(FROZEN.load(Ordering::Acquire), pointer);
        // A child's Host may already have consumed its copied snapshot and
        // published CHILD=false before its original native thread reaches
        // onLeave. Its explicit Child token must neither depend on that bool
        // nor consume a later fork's global snapshot.
        assert!(!super::CHILD.load(Ordering::Acquire));
        RETURN_OWNER.with(|owner| owner.set(ReturnOwner::Child));
        unsafe { hyperhub_fork_return_gate(std::ptr::null_mut()) };
        assert_eq!(FROZEN.load(Ordering::Acquire), pointer);
        assert!(matches!(take_return_owner(), ReturnOwner::None));
        resume.send(()).unwrap();
        worker.join().unwrap();
        assert!(FROZEN.load(Ordering::Acquire).is_null());

        let epoch = FORK_LISTENER_EPOCH.load(Ordering::Acquire);
        let invoked = std::cell::Cell::new(false);
        let blocked = super::gate().lock().unwrap();
        assert_eq!(
            with_rearm_gate(|| {
                invoked.set(true);
                REARM_COMMITTED
            }),
            crate::HH_ERR_ACTIVATION_BUSY
        );
        assert!(!invoked.get());
        assert_eq!(FORK_LISTENER_EPOCH.load(Ordering::Acquire), epoch);
        drop(blocked);
        assert_eq!(
            hyperhub_fork_listener_rearm_run(
                FORK_LISTENER_GENERATION.load(Ordering::Acquire),
                u64::MAX,
                None,
                None,
                None,
            ),
            crate::HH_ERR_PROTOCOL
        );
        extern "C" fn interrupted_callback() -> i32 {
            0
        }
        assert_eq!(
            hyperhub_fork_listener_rearm_run(
                FORK_LISTENER_GENERATION.load(Ordering::Acquire),
                u64::MAX,
                Some(interrupted_callback),
                Some(interrupted_callback),
                Some(interrupted_callback),
            ),
            crate::HH_ERR_PROTOCOL
        );
        assert!(super::gate().try_lock().is_ok());
        assert_eq!(with_rearm_gate(|| -31), -31);
        assert!(super::gate().try_lock().is_ok());
        assert_eq!(
            with_rearm_gate(|| {
                assert_eq!(
                    with_rearm_gate(|| REARM_COMMITTED),
                    crate::HH_ERR_ACTIVATION_BUSY
                );
                assert_eq!(
                    std::thread::spawn(|| with_rearm_gate(|| REARM_COMMITTED))
                        .join()
                        .unwrap(),
                    crate::HH_ERR_ACTIVATION_BUSY
                );
                assert!(matches!(
                    super::gate().try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                REARM_COMMITTED
            }),
            crate::HH_OK
        );
        assert!(super::gate().try_lock().is_ok());
    }

    #[test]
    fn protected_preentry_child_waits_for_approved_cancellation() {
        const MARKER: &str = "HH_TEST_PROTECTED_PREENTRY_CHILD";
        if std::env::var_os(MARKER).is_none() {
            let test = format!(
                "{}::protected_preentry_child_waits_for_approved_cancellation",
                module_path!().split_once("::").unwrap().1
            );
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .env(MARKER, "1")
                .args(["--exact", &test, "--test-threads=1"])
                .status()
                .unwrap()
                .success());
            return;
        }
        use super::*;
        // The atfork admission exists before any Frida SDK entry or Host bind.
        assert!(!crate::attachment::startup::tracked());
        super::CHILD.store(true, Ordering::Release);
        CHILD_PROTECTED.store(true, Ordering::Release);
        CHILD_READY.store(1, Ordering::Release);
        let (finished, completion) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            unsafe { wait_protected_child() };
            finished.send(()).unwrap();
        });
        // Calling the cancellation helper without a verified cancellation is a
        // no-op, including this pre-entry window. A normal failure cannot open it.
        cancel_initialization_after_approved_detach();
        assert!(completion
            .recv_timeout(std::time::Duration::from_millis(30))
            .is_err());
        assert!(super::CHILD.load(Ordering::Acquire));
        assert_eq!(CHILD_READY.load(Ordering::Acquire), 1);
        let startup = crate::attachment::startup::begin_for_test(true);
        crate::attachment::startup::cancel_for_test();
        assert!(completion
            .recv_timeout(std::time::Duration::from_millis(30))
            .is_err());
        startup.finish(false);
        // This test has no bound Bootstrap/local owner, so the internal helper
        // is called explicitly only after the admitted cancellation is terminal.
        cancel_initialization_after_approved_detach();
        completion
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        waiter.join().unwrap();
        assert!(!super::CHILD.load(Ordering::Acquire));
        assert!(!CHILD_PROTECTED.load(Ordering::Acquire));
        assert_eq!(CHILD_READY.load(Ordering::Acquire), 0);
    }

    #[test]
    fn publication_receipt_failure_keeps_the_original_thread_held() {
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        let child = AtomicBool::new(true);
        let ready = AtomicU32::new(2);
        assert_eq!(
            super::publish_state(&child, &ready, || Err("receipt failed")),
            Err("receipt failed")
        );
        assert!(child.load(Ordering::Acquire));
        assert_eq!(ready.load(Ordering::Acquire), 2);
        let committed = AtomicBool::new(false);
        super::publish_state(&child, &ready, || {
            assert!(child.load(Ordering::Acquire));
            assert_eq!(ready.load(Ordering::Acquire), 2);
            committed.store(true, Ordering::Release);
            Ok(())
        })
        .unwrap();
        assert!(committed.load(Ordering::Acquire));
        assert!(!child.load(Ordering::Acquire));
        assert_eq!(ready.load(Ordering::Acquire), 0);
    }

    #[test]
    fn preparing_capture_does_not_wait_or_apply_while_a_fork_owns_the_gate() {
        let gate = super::gate().lock().unwrap();
        let changed = std::sync::atomic::AtomicBool::new(false);
        assert_eq!(
            super::prepare_activation_transition(|| {
                changed.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            }),
            Err(crate::HH_ERR_ACTIVATION_BUSY)
        );
        assert!(!changed.load(std::sync::atomic::Ordering::Acquire));
        drop(gate);
        assert_eq!(
            super::prepare_activation_transition(|| {
                changed.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            }),
            Ok(())
        );
        assert!(changed.load(std::sync::atomic::Ordering::Acquire));
    }

    unsafe fn current_mask() -> u64 {
        let mut mask = 0u64;
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &mut mask,
                std::mem::size_of::<u64>()
            ),
            0
        );
        mask
    }

    #[test]
    fn recovery_mask_preserves_callback_changes_and_parent_thread_mask() {
        let parent = unsafe { current_mask() };
        std::thread::spawn(|| unsafe {
            let original = current_mask();
            let callback = original | (1u64 << (libc::SIGUSR2 - 1));
            super::replace_signal_mask(callback).unwrap();
            let saved = super::replace_signal_mask(super::recovery_async_signal_mask()).unwrap();
            let protected = current_mask();
            super::replace_signal_mask(saved).unwrap();
            let restored = current_mask();
            super::replace_signal_mask(original).unwrap();
            assert_eq!(saved, callback);
            assert_eq!(restored, callback);
            assert_ne!(protected & (1u64 << (libc::SIGUSR1 - 1)), 0);
            assert_ne!(protected & (1u64 << (libc::SIGTERM - 1)), 0);
            for signal in [
                libc::SIGSEGV,
                libc::SIGBUS,
                libc::SIGILL,
                libc::SIGFPE,
                libc::SIGTRAP,
                libc::SIGSYS,
            ] {
                assert_eq!(protected & (1u64 << (signal - 1)), 0);
            }
            assert_eq!(protected & (1u64 << (libc::SIGKILL - 1)), 0);
            assert_eq!(protected & (1u64 << (libc::SIGSTOP - 1)), 0);
        })
        .join()
        .unwrap();
        assert_eq!(unsafe { current_mask() }, parent);
    }

    #[test]
    fn fork_failure_uses_pid_t_width_after_native_return() {
        assert_eq!(super::fork_result(u32::MAX as usize), -1);
        assert_eq!(super::fork_result(usize::MAX), -1);
        assert_eq!(super::fork_result(0), 0);
        assert_eq!(super::fork_result(123), 123);
    }
}
