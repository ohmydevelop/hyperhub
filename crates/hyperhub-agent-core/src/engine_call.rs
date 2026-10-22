//! Thread-bound generation context with explicit OS TLS ownership. Hooks can run
//! while the dynamic loader owns its lock and during other TLS destructors.
use hyperhub_runtime::{Lease, Runtime};
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicU64, Ordering};
mod slots;

struct Slot {
    calling: RefCell<Option<Lease>>,
    epoch: u64,
    #[cfg(test)]
    destroyed: RefCell<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
}
#[cfg(test)]
impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(flag) = self.destroyed.get_mut().take() {
            flag.store(true, Ordering::Release);
        }
    }
}
thread_local! {
    // These Cells have no destructor and never register with the loader.
    static HOST_BACKGROUND: Cell<bool> = const { Cell::new(false) };
    static CLEANED: Cell<bool> = const { Cell::new(false) };
    static DESTROYING: Cell<bool> = const { Cell::new(false) };
}
static EPOCH: AtomicU64 = AtomicU64::new(0);
#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn initialize_thread_slots() -> Result<(), i32> {
    slots::initialize()
}
#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn host_background() -> bool {
    HOST_BACKGROUND.with(Cell::get)
}
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
fn current_slot() -> *mut Slot {
    let pointer = slots::get().cast::<Slot>();
    if !pointer.is_null() && unsafe { (*pointer).epoch } != EPOCH.load(Ordering::Acquire) {
        // Only a fork child changes epoch. Parent Arc counters are copied, not
        // owned by this child; neither Drop nor unlock an inherited object.
        let _ = slots::set(std::ptr::null_mut());
        CLEANED.with(|flag| flag.set(false));
        std::ptr::null_mut()
    } else {
        pointer
    }
}
unsafe fn destroy_slot(value: *mut std::ffi::c_void) {
    if value.is_null() {
        return;
    }
    let pointer = value.cast::<Slot>();
    if slots::get() == value {
        let _ = slots::set(std::ptr::null_mut());
    }
    CLEANED.with(|flag| flag.set(true));
    if unsafe { (*pointer).epoch } != EPOCH.load(Ordering::Acquire) {
        return;
    }
    // Detach before freeing, and suppress only cleanup's own allocator reentry.
    // Other late destructors still receive a temporary scoped policy slot.
    let previous = HOST_BACKGROUND.with(|flag| flag.replace(true));
    DESTROYING.with(|flag| flag.set(true));
    unsafe {
        drop(Box::from_raw(pointer));
    }
    DESTROYING.with(|flag| flag.set(false));
    HOST_BACKGROUND.with(|flag| flag.set(previous));
}
fn alive() -> bool {
    !DESTROYING.with(Cell::get)
}
#[cfg(any(test, all(any(windows, target_os = "linux"), feature = "gum-agent")))]
pub(crate) struct EngineCallGuard {
    previous: Option<Lease>,
    slot: *mut Slot,
    epoch: u64,
    temporary: bool,
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
        let engine = crate::state().lock().ok()?.engine.clone();
        Self::with_lease(engine.acquire())
    }
    pub(crate) fn with_lease(lease: Lease) -> Option<Self> {
        if !alive() {
            return None;
        }
        let mut pointer = current_slot();
        let mut temporary = false;
        if pointer.is_null() {
            pointer = Box::into_raw(Box::new(Slot {
                calling: RefCell::new(None),
                epoch: EPOCH.load(Ordering::Acquire),
                #[cfg(test)]
                destroyed: RefCell::new(None),
            }));
            temporary = CLEANED.with(Cell::get);
            if slots::set(pointer.cast()).is_err() {
                unsafe {
                    drop(Box::from_raw(pointer));
                }
                return None;
            }
        }
        let previous = unsafe { &*pointer }.calling.replace(Some(lease));
        Some(Self {
            previous,
            slot: pointer,
            epoch: EPOCH.load(Ordering::Acquire),
            temporary,
            _thread: std::marker::PhantomData,
        })
    }
}
#[cfg(any(test, all(any(windows, target_os = "linux"), feature = "gum-agent")))]
impl Drop for EngineCallGuard {
    fn drop(&mut self) {
        if self.epoch == EPOCH.load(Ordering::Acquire) && slots::get().cast::<Slot>() == self.slot {
            unsafe { &*self.slot }.calling.replace(self.previous.take());
            if self.temporary {
                let _ = slots::set(std::ptr::null_mut());
                unsafe {
                    drop(Box::from_raw(self.slot));
                }
            }
        } else {
            std::mem::forget(self.previous.take());
        }
    }
}
pub(crate) fn calling(runtime: &Runtime) -> Result<Lease, i32> {
    if !alive() {
        return Err(crate::HH_ERR_INVALID);
    }
    let pointer = current_slot();
    if !pointer.is_null() {
        if let Some(lease) = unsafe { &*pointer }.calling.borrow().clone() {
            return Ok(lease);
        }
    }
    Ok(runtime.acquire())
}
#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn reset_after_fork() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    #[cfg(windows)]
    slots::reset_after_fork();
    let _ = current_slot();
    // The safe rebuild worker may be a new thread; original target threads
    // discard their copied slots lazily on their own first subsequent call.
    CLEANED.with(|flag| flag.set(false));
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
    fn native_slots_are_freed_at_thread_exit_and_late_destructors_keep_policy_context() {
        let destroyed = Arc::new(AtomicBool::new(false));
        let report = destroyed.clone();
        std::thread::spawn(move || {
            let runtime = hyperhub_engine::resident();
            let guard = EngineCallGuard::with_lease(runtime.acquire()).unwrap();
            let pointer = current_slot();
            unsafe { &*pointer }.destroyed.replace(Some(report.clone()));
            drop(guard);
            assert!(!report.load(Ordering::Acquire));
        })
        .join()
        .unwrap();
        assert!(
            destroyed.load(Ordering::Acquire),
            "OS TLS must free the actual Slot"
        );
        std::thread::spawn(|| {
            let runtime = hyperhub_engine::resident();
            let guard = EngineCallGuard::with_lease(runtime.acquire()).unwrap();
            drop(guard);
            unsafe {
                destroy_slot(current_slot().cast());
            }
            assert!(CLEANED.with(Cell::get));
            let guard = EngineCallGuard::with_lease(runtime.acquire()).unwrap();
            assert!(guard.temporary);
            assert_eq!(
                calling(&runtime).unwrap().generation(),
                runtime.acquire().generation()
            );
            drop(guard);
            assert!(
                current_slot().is_null(),
                "late destructor's scoped Slot must be freed immediately"
            );
            assert_eq!(runtime.snapshot().unwrap().active.references, 0);
        })
        .join()
        .unwrap();
    }
}
