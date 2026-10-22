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
    let _last_error = super::WindowsLastErrorGuard::capture();
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
    let _last_error = super::WindowsLastErrorGuard::capture();
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
    let _last_error = super::WindowsLastErrorGuard::capture();
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
        let _last_error = super::WindowsLastErrorGuard::capture();
        unsafe { windows_sys::Win32::System::Threading::FlsGetValue(key as u32) }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{GetLastError, SetLastError},
        Networking::WinSock::{WSAGetLastError, WSASetLastError, WSAENOTSOCK, WSAEWOULDBLOCK},
    };

    #[test]
    fn fiber_slot_operations_and_engine_release_preserve_application_errors() {
        for error in [0, 2, 5, WSAEWOULDBLOCK, WSAENOTSOCK] {
            std::thread::spawn(move || unsafe {
                WSASetLastError(error);
                initialize().unwrap();
                assert_eq!(GetLastError(), error as u32);
                assert!(get().is_null());
                assert_eq!(WSAGetLastError(), error);
                let key = create().unwrap();
                assert_eq!(WSAGetLastError(), error);
                set_key(key, std::ptr::null_mut()).unwrap();
                assert_eq!(WSAGetLastError(), error);
                delete(key);
                assert_eq!(WSAGetLastError(), error);

                let runtime = hyperhub_engine::resident();
                let guard = super::super::EngineCallGuard::with_lease(runtime.acquire()).unwrap();
                SetLastError(error as u32);
                assert!(!get().is_null());
                assert_eq!(WSAGetLastError(), error);
                drop(guard);
                assert_eq!(WSAGetLastError(), error);
            })
            .join()
            .unwrap();
        }
    }
}
