//! OS TLS cleanup avoids Rust's loader-lock-taking __cxa_thread_atexit path.
use std::{
    ffi::c_void,
    sync::atomic::{AtomicUsize, Ordering},
};
static KEY: AtomicUsize = AtomicUsize::new(usize::MAX);
pub(super) fn initialize() -> Result<(), i32> {
    if KEY.load(Ordering::Acquire) != usize::MAX {
        return Ok(());
    }
    let fresh = create()?;
    if KEY
        .compare_exchange(usize::MAX, fresh, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        delete(fresh);
    }
    Ok(())
}
pub(super) fn set(value: *mut c_void) -> Result<(), i32> {
    initialize()?;
    set_key(KEY.load(Ordering::Acquire), value)
}
#[cfg(unix)]
unsafe extern "C" fn cleanup(value: *mut c_void) {
    unsafe { super::destroy_slot(value) }
}
#[cfg(windows)]
unsafe extern "system" fn cleanup(value: *const c_void) {
    unsafe { super::destroy_slot(value.cast_mut()) }
}
#[cfg(unix)]
fn create() -> Result<usize, i32> {
    let mut key = 0;
    let result = unsafe { libc::pthread_key_create(&mut key, Some(cleanup)) };
    if result == 0 {
        Ok(key as usize)
    } else {
        Err(crate::HH_ERR_INVALID)
    }
}
#[cfg(windows)]
fn create() -> Result<usize, i32> {
    let key = unsafe { windows_sys::Win32::System::Threading::FlsAlloc(Some(cleanup)) };
    if key == u32::MAX {
        Err(crate::HH_ERR_INVALID)
    } else {
        Ok(key as usize)
    }
}
#[cfg(unix)]
fn delete(key: usize) {
    unsafe {
        libc::pthread_key_delete(key as libc::pthread_key_t);
    }
}
#[cfg(windows)]
fn delete(key: usize) {
    unsafe {
        windows_sys::Win32::System::Threading::FlsFree(key as u32);
    }
}
#[cfg(unix)]
fn set_key(key: usize, value: *mut c_void) -> Result<(), i32> {
    if unsafe { libc::pthread_setspecific(key as libc::pthread_key_t, value) } == 0 {
        Ok(())
    } else {
        Err(crate::HH_ERR_INVALID)
    }
}
#[cfg(windows)]
fn set_key(key: usize, value: *mut c_void) -> Result<(), i32> {
    if unsafe { windows_sys::Win32::System::Threading::FlsSetValue(key as u32, value) } != 0 {
        Ok(())
    } else {
        Err(crate::HH_ERR_INVALID)
    }
}
#[cfg(all(windows, feature = "gum-agent"))]
pub(super) fn reset_after_fork() {
    // The copied key number has no ownership in the new MSYS process.
    KEY.store(usize::MAX, Ordering::Release);
}

pub(super) fn get() -> *mut c_void {
    let key = KEY.load(Ordering::Acquire);
    if key == usize::MAX {
        return std::ptr::null_mut();
    }
    #[cfg(unix)]
    {
        unsafe { libc::pthread_getspecific(key as libc::pthread_key_t) }
    }
    #[cfg(windows)]
    {
        unsafe { windows_sys::Win32::System::Threading::FlsGetValue(key as u32) }
    }
}
