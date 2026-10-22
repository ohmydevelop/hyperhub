//! Fork callbacks only freeze parent ownership. The gated child's independent
//! entry point reconstructs process locks, native ownership, and exact leases.
use crate::runtime::{state, AgentRuntime};
use hyperhub_runtime::{generation::ForkGuard, Runtime};
use std::sync::{
    atomic::{AtomicBool, AtomicPtr, Ordering},
    Arc, Mutex, MutexGuard,
};

static INSTALLED: AtomicBool = AtomicBool::new(false);
static CHILD: AtomicBool = AtomicBool::new(false);
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
}
pub(crate) fn awaiting_rebuild() -> bool {
    CHILD.load(Ordering::Acquire)
}
pub(crate) fn install() -> Result<(), String> {
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
        };
        let result = (|| -> Result<(), String> {
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
    let pointer = FROZEN.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if pointer.is_null() {
        return;
    }
    let mut frozen = unsafe { Box::from_raw(pointer) };
    drop(frozen.runtime.take());
    drop(frozen.agent.take());
    if !frozen.owner.is_null() {
        unsafe {
            drop(Arc::from_raw(frozen.owner));
        }
    }
    drop(frozen.snapshot.take());
    drop(frozen.gate.take());
}
unsafe extern "C" fn child() {
    // No allocation, TLS initialization, mutex acquisition, IO, or native code.
    CHILD.store(true, Ordering::Release);
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
        CHILD.store(false, Ordering::Release);
        crate::control::reenroll_fork_engine()
            .map_err(|e| format!("fork Engine enrollment failed: {e}"))?;
        crate::subscribe_sandbox();
        Ok(())
    })
}
