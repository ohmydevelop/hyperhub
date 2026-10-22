//! Resident, thread-bound generation context. Never access destroyed TLS from a
//! native Hook: thread teardown can call intercepted file/socket functions.
use hyperhub_runtime::{Lease, Runtime};
use std::cell::{Cell, RefCell};
#[cfg(any(test, all(any(windows, target_os = "linux"), feature = "gum-agent")))]
use std::sync::atomic::{AtomicU64, Ordering};

thread_local! {
    static CALLING: RefCell<Option<Lease>> = const { RefCell::new(None) };
    // No destructor: this flag remains readable after CALLING is destroyed.
    // Do not initialize CALLING just to probe it.
    static INITIALIZED: Cell<bool> = const { Cell::new(false) };
    static HOST_BACKGROUND: Cell<bool> = const { Cell::new(false) };
}
#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn host_background() -> bool {
    HOST_BACKGROUND.with(Cell::get)
}
/// Only dedicated resident-control threads use this guard. Blocking control IO
/// must bypass target hooks without pinning an Engine generation while idle.
#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn background<T>(call: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            HOST_BACKGROUND.with(|flag| flag.set(self.0));
        }
    }
    let _reset = Reset(HOST_BACKGROUND.with(|flag| flag.replace(true)));
    call()
}
fn alive() -> bool {
    !INITIALIZED.with(Cell::get) || CALLING.try_with(|_| ()).is_ok()
}
#[cfg(any(test, all(any(windows, target_os = "linux"), feature = "gum-agent")))]
static EPOCH: AtomicU64 = AtomicU64::new(0);
#[cfg(any(test, all(any(windows, target_os = "linux"), feature = "gum-agent")))]
pub(crate) struct EngineCallGuard {
    previous: Option<Lease>,
    epoch: u64,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(any(test, all(any(windows, target_os = "linux"), feature = "gum-agent")))]
impl EngineCallGuard {
    pub(crate) fn available() -> bool {
        alive()
    }
    pub(crate) fn enter() -> Option<Self> {
        if !alive() {
            return None;
        }
        // Release the Agent-state lock BEFORE initializing CALLING: registering
        // a TLS destructor can acquire the native loader lock.
        let engine = crate::state().lock().ok()?.engine.clone();
        let lease = engine.acquire();
        Self::with_lease(lease)
    }
    /// Call after entering the Host Hook guard. Async completions replace its
    /// active lease with theirs. The caller must not hold Agent-state locks.
    pub(crate) fn with_lease(lease: Lease) -> Option<Self> {
        let guard = CALLING
            .try_with(|slot| Self {
                previous: slot.replace(Some(lease)),
                epoch: EPOCH.load(Ordering::Acquire),
                _thread: std::marker::PhantomData,
            })
            .ok()?;
        INITIALIZED.with(|value| value.set(true));
        Some(guard)
    }
}
#[cfg(any(test, all(any(windows, target_os = "linux"), feature = "gum-agent")))]
impl Drop for EngineCallGuard {
    fn drop(&mut self) {
        if self.epoch == EPOCH.load(Ordering::Acquire) {
            let _ = CALLING.try_with(|slot| {
                slot.replace(self.previous.take());
            });
        } else {
            std::mem::forget(self.previous.take());
        }
    }
}
pub(crate) fn calling(runtime: &Runtime) -> Result<Lease, i32> {
    if !alive() {
        return Err(crate::HH_ERR_INVALID);
    }
    if INITIALIZED.with(Cell::get) {
        if let Some(lease) = CALLING
            .try_with(|slot| slot.borrow().clone())
            .ok()
            .flatten()
        {
            return Ok(lease);
        }
    }
    // Direct ABI callers do not need a thread-local calling context. In
    // particular, do not register a destructor while they own process state.
    Ok(runtime.acquire())
}
#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn reset_after_fork() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    let _ = CALLING.try_with(|slot| std::mem::forget(slot.take()));
    INITIALIZED.with(|value| value.set(false));
}
pub(crate) fn trusted_io<T>(call: impl FnOnce() -> T) -> T {
    #[cfg(all(windows, feature = "gum-agent"))]
    {
        crate::windows_gum::with_host_io(call)
    }
    #[cfg(all(target_os = "linux", feature = "gum-agent"))]
    {
        crate::unix_gum::with_host_io(call)
    }
    #[cfg(not(all(any(windows, target_os = "linux"), feature = "gum-agent")))]
    {
        call()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicBool, Arc};
    #[test]
    fn native_hooks_decline_generation_access_after_thread_local_destruction() {
        struct Late {
            runtime: Arc<Runtime>,
            observed: Arc<AtomicBool>,
        }
        impl Drop for Late {
            fn drop(&mut self) {
                assert!(EngineCallGuard::enter().is_none());
                assert!(calling(&self.runtime).is_err());
                self.observed.store(true, Ordering::Release);
            }
        }
        thread_local! { static LATE: RefCell<Option<Late>> = const { RefCell::new(None) }; }
        let observed = Arc::new(AtomicBool::new(false));
        let done = observed.clone();
        std::thread::spawn(move || {
            let runtime = hyperhub_engine::resident();
            // Destructors run in reverse registration order. This destructor
            // runs after the calling slot.
            LATE.with(|slot| {
                slot.replace(Some(Late {
                    runtime: runtime.clone(),
                    observed: done,
                }));
            });
            let lease = calling(&runtime).unwrap();
            let guard = EngineCallGuard::with_lease(lease).unwrap();
            drop(guard);
        })
        .join()
        .unwrap();
        assert!(observed.load(Ordering::Acquire));
    }
}
