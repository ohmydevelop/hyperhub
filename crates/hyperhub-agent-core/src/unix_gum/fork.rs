//! Fork callbacks only freeze parent ownership. The gated child's independent
//! entry point reconstructs process locks, native ownership, and exact leases.
use crate::runtime::{state, AgentRuntime};
use hyperhub_runtime::{generation::ForkGuard, Runtime};
use std::sync::{
    atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, Ordering},
    Arc, Mutex, MutexGuard,
};

static INSTALLED: AtomicBool = AtomicBool::new(false);
static CHILD: AtomicBool = AtomicBool::new(false);
static CHILD_READY: AtomicU32 = AtomicU32::new(0);
static CHILD_LEASE: [AtomicU8; 32] = [const { AtomicU8::new(0) }; 32];
static FORK_LISTENER_ARMED: AtomicBool = AtomicBool::new(false);
static FORK_LISTENER_PREPARED: AtomicBool = AtomicBool::new(false);
static FORK_LISTENER_EPOCH: AtomicU32 = AtomicU32::new(0);
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
static FROZEN: AtomicPtr<Frozen> = AtomicPtr::new(std::ptr::null_mut());
struct Frozen {
    runtime: Option<ForkGuard<'static>>,
    agent: Option<MutexGuard<'static, AgentRuntime>>,
    gate: Option<MutexGuard<'static, ()>>,
    owner: *const Runtime,
    snapshot: Option<AgentRuntime>,
    error: Option<String>,
    lease: Option<[u8; 32]>,
}
pub(crate) fn awaiting_rebuild() -> bool {
    CHILD.load(Ordering::Acquire)
}

pub(crate) fn new_policy_blocked() -> bool {
    CHILD.load(Ordering::Acquire) && !RECOVERING.load(Ordering::Acquire)
}
pub(crate) fn install() -> Result<(), String> {
    super::fork_handoff::initialize()?;
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
unsafe extern "C" fn prepare() {
    crate::engine_call::background(|| {
        let gate = gate().lock().unwrap_or_else(|p| p.into_inner());
        let mut frozen = Frozen {
            runtime: None,
            agent: None,
            gate: Some(gate),
            owner: std::ptr::null(),
            snapshot: None,
            error: None,
            lease: None,
        };
        let result = (|| -> Result<(), String> {
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
        FROZEN.store(Box::into_raw(Box::new(frozen)), Ordering::Release);
    });
}
unsafe extern "C" fn parent() {
    let pointer = FROZEN.load(Ordering::Acquire);
    if pointer.is_null() {
        return;
    }
    let frozen = unsafe { &mut *pointer };
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
    if !claimed {
        // Copied Runtime locks cannot safely serve application calls. A lost
        // manager never permits an unregistered child to return to the target.
        unsafe { libc::syscall(libc::SYS_exit_group, 126) };
    }
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_is_armed() -> u32 {
    u32::from(FORK_LISTENER_ARMED.load(Ordering::Acquire))
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_mark_armed() {
    FORK_LISTENER_ARMED.store(true, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_epoch() -> u32 {
    FORK_LISTENER_EPOCH.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn hyperhub_fork_listener_confirm_rearm() -> u32 {
    FORK_LISTENER_EPOCH
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1)
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
    if fork_result(super::gum::return_value(context) as usize) == 0 {
        // Linux x86_64/aarch64 use an eight-byte kernel signal set. Preserve
        // changes made by application atfork callbacks, which have now finished.
        // Recovery recreates threads through ptrace, without delivery of a
        // catchable asynchronous signal to this original application thread.
        let previous = match replace_signal_mask(u64::MAX) {
            Ok(previous) => previous,
            Err(()) => {
                libc::syscall(libc::SYS_exit_group, 126);
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
    let result = fork_result(super::gum::return_value(context) as usize);
    if result != 0 {
        let pointer = FROZEN.swap(std::ptr::null_mut(), Ordering::AcqRel);
        if !pointer.is_null() {
            let mut frozen = Box::from_raw(pointer);
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
                libc::syscall(libc::SYS_exit_group, 126);
                return;
            }
            drop(frozen.gate.take());
        }
        return;
    }
    if CHILD_READY.load(Ordering::Acquire) != 0 {
        let mut lease = [0u8; 32];
        for (destination, source) in lease.iter_mut().zip(&CHILD_LEASE) {
            *destination = source.load(Ordering::Relaxed);
        }
        if super::fork_handoff::ready(&lease).is_err() {
            libc::syscall(libc::SYS_exit_group, 126);
            return;
        }
    }
    // The callback can execute after parent gating was automatically released.
    // Keep the original application thread here until the manager has completed
    // enrollment and armed the surviving child's own fork gate.
    let deadline = match super::fork_handoff::monotonic_ms() {
        Ok(now) => now + 10_000,
        Err(()) => {
            libc::syscall(libc::SYS_exit_group, 126);
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
            libc::syscall(libc::SYS_exit_group, 126);
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
            libc::syscall(libc::SYS_exit_group, 126);
        }
    }
    if CHILD_SIGNAL_MASKED.swap(false, Ordering::AcqRel) {
        let previous = CHILD_SIGNAL_MASK.load(Ordering::Relaxed);
        // Publication has cleared CHILD. Restoring the mask may immediately
        // deliver an application handler; it must use the rebuilt Host policy.
        if replace_signal_mask(previous).is_err() {
            libc::syscall(libc::SYS_exit_group, 126);
        }
    }
}

fn fork_result(raw: usize) -> libc::pid_t {
    raw as libc::pid_t
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

pub(crate) fn publish() -> Result<(), &'static str> {
    if CHILD_READY.load(Ordering::Acquire) != 2 {
        return Err("fork child enrollment is not ready for publication");
    }
    CHILD.store(false, Ordering::Release);
    CHILD_READY.store(0, Ordering::Release);
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            &CHILD_READY as *const AtomicU32 as *const u32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            i32::MAX,
        );
    }
    Ok(())
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
    crate::runtime::replace_state_after_fork(AgentRuntime::default());
    crate::engine_call::background(|| {
        let forked = unsafe { image.rebuild() }.map_err(|e| e.to_string())?;
        for socket in rebuilt.gateway.sockets.values_mut() {
            socket.engine = forked.rebind(&socket.engine).map_err(|e| e.to_string())?;
        }
        rebuilt.engine = forked.runtime.clone();
        crate::runtime::replace_state_after_fork(rebuilt);
        drop(forked);
        crate::control::reenroll_fork_engine()
            .map_err(|e| format!("fork Engine enrollment failed: {e}"))?;
        crate::subscribe_sandbox();
        CHILD_READY.store(2, Ordering::Release);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
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
            let saved = super::replace_signal_mask(u64::MAX).unwrap();
            let protected = current_mask();
            super::replace_signal_mask(saved).unwrap();
            let restored = current_mask();
            super::replace_signal_mask(original).unwrap();
            assert_eq!(saved, callback);
            assert_eq!(restored, callback);
            assert_ne!(protected & (1u64 << (libc::SIGUSR1 - 1)), 0);
            assert_ne!(protected & (1u64 << (libc::SIGTERM - 1)), 0);
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
