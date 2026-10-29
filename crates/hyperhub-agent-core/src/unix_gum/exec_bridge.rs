//! Route FD execution through Core's exec startup monitor without translating
//! the kernel operation into a pathname exec. Hook mutation is allowed only in
//! an unconfirmed, freshly installed image; inherited live fork hooks cannot be
//! removed through this interface.
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

#[derive(Clone, Copy)]
pub(super) enum Call {
    Fd {
        fd: i32,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    },
    At {
        fd: i32,
        path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
        flags: i32,
    },
}
#[derive(Clone, Copy)]
struct Pending {
    call: Option<Call>,
    executing: bool,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
}
thread_local! { static PENDING: Cell<Pending> = const { Cell::new(Pending { call: None, executing: false, argv: std::ptr::null(), envp: std::ptr::null() }) }; }
static ENTRY: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OWNER: AtomicU32 = AtomicU32::new(0);
static READY: AtomicBool = AtomicBool::new(false);
// 0: fresh owned replacement, 1: removed, 2: reinstalled, 3: confirmed/inherited.
static STAGE: AtomicU32 = AtomicU32::new(0);

pub(super) fn initialize_owner() {
    if let Some(entry) = unsafe { super::gum::find_export("execve") } {
        ENTRY.store(entry, Ordering::Release);
    }
    let pid = std::process::id();
    let old = OWNER.swap(pid, Ordering::AcqRel);
    if old != 0 && old != pid {
        STAGE.store(3, Ordering::Release);
    }
    READY.store(false, Ordering::Release);
}
pub(super) fn prepare() {
    READY.store(false, Ordering::Release);
}
pub(super) fn confirmed() -> bool {
    READY.load(Ordering::Acquire) && OWNER.load(Ordering::Acquire) == std::process::id()
}
pub(super) fn confirm() -> Result<(), i32> {
    if OWNER.load(Ordering::Acquire) != std::process::id() || STAGE.load(Ordering::Acquire) == 1 {
        return Err(crate::HH_ERR_NOT_INITIALIZED);
    }
    STAGE.store(3, Ordering::Release);
    READY.store(true, Ordering::Release);
    Ok(())
}
pub(super) fn remove_fresh() -> Result<(), i32> {
    if OWNER.load(Ordering::Acquire) != std::process::id() || READY.load(Ordering::Acquire) {
        return Err(crate::HH_ERR_INVALID);
    }
    let stage = STAGE.load(Ordering::Acquire);
    if !matches!(stage, 0 | 1) {
        return Err(crate::HH_ERR_INVALID);
    }
    if stage == 0 {
        super::manager::remove_exec_hook().map_err(|_| crate::HH_ERR_PROTOCOL)?;
        STAGE.store(1, Ordering::Release);
    }
    Ok(())
}
pub(super) fn reinstall_fresh() -> Result<(), i32> {
    if OWNER.load(Ordering::Acquire) != std::process::id() || READY.load(Ordering::Acquire) {
        return Err(crate::HH_ERR_INVALID);
    }
    match STAGE.load(Ordering::Acquire) {
        1 => {
            super::manager::reinstall_exec_hook().map_err(|_| crate::HH_ERR_PROTOCOL)?;
            STAGE.store(2, Ordering::Release);
            Ok(())
        }
        2 => Ok(()),
        _ => Err(crate::HH_ERR_INVALID),
    }
}
pub(super) fn dispatch(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> Option<Call> {
    PENDING.with(|slot| {
        let mut value = slot.get();
        if value.executing || !path.is_null() || argv != value.argv || envp != value.envp {
            return None;
        }
        let call = value.call?;
        value.executing = true;
        slot.set(value);
        Some(call)
    })
}
pub(super) fn executing() -> bool {
    PENDING.with(|slot| slot.get().executing)
}
pub(super) unsafe fn invoke(
    call: Call,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> i32 {
    struct Restore(Pending);
    impl Drop for Restore {
        fn drop(&mut self) {
            PENDING.with(|slot| slot.set(self.0));
        }
    }
    // Even unavailable argv metadata has a unique per-call empty vector. A
    // signal handler's unrelated execve(NULL,NULL,NULL) cannot consume this
    // thread's saved FD operation during the interval before Core entry.
    let empty_argv = [std::ptr::null()];
    let argv = if argv.is_null() {
        empty_argv.as_ptr()
    } else {
        argv
    };
    let prior = PENDING.with(|slot| {
        slot.replace(Pending {
            call: Some(call),
            executing: false,
            argv,
            envp,
        })
    });
    let _restore = Restore(prior);
    // Resolve the public entry, not our saved original trampoline: Core must
    // run its prepare/cancel listener outside the SDK's FD dispatch.
    let entry = ENTRY.load(Ordering::Acquire);
    if entry.is_null() {
        *libc::__errno_location() = libc::EIO;
        return -1;
    }
    let entry: unsafe extern "C" fn(
        *const libc::c_char,
        *const *const libc::c_char,
        *const *const libc::c_char,
    ) -> i32 = std::mem::transmute::<*mut c_void, _>(entry);
    let result = entry(std::ptr::null(), argv, envp);
    let error = *libc::__errno_location();
    drop(_restore);
    *libc::__errno_location() = error;
    result
}

// Metadata is copied through the kernel, not dereferenced from application
// pointers. Core receives only these owned, stable vectors (or NULL metadata).
// The actual FD invocation always retains the application's original pointers.
pub(super) struct Vector {
    values: Vec<std::ffi::CString>,
    pointers: Vec<*const libc::c_char>,
}
impl Vector {
    fn empty() -> Self {
        Self {
            values: Vec::new(),
            pointers: vec![std::ptr::null()],
        }
    }
    pub(super) fn pointer(&self) -> *const *const libc::c_char {
        self.pointers.as_ptr()
    }
    pub(super) fn values(&self) -> impl Iterator<Item = &std::ffi::CStr> {
        self.values.iter().map(|value| value.as_c_str())
    }
}
unsafe fn read_bytes(address: usize, bytes: &mut [u8]) -> Option<usize> {
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: bytes.len(),
    };
    let result = libc::syscall(
        libc::SYS_process_vm_readv,
        libc::getpid(),
        &local,
        1usize,
        &remote,
        1usize,
        0usize,
    );
    if result < 0 {
        None
    } else {
        Some(result as usize)
    }
}
pub(super) unsafe fn string(
    pointer: *const libc::c_char,
    limit: usize,
) -> Option<std::ffi::CString> {
    if pointer.is_null() {
        return None;
    }
    let mut value = Vec::new();
    let mut scratch = [0u8; 256];
    while value.len() < limit {
        let length = scratch.len().min(limit - value.len());
        let copied = read_bytes(
            (pointer as usize).checked_add(value.len())?,
            &mut scratch[..length],
        )?;
        if copied == 0 {
            return None;
        }
        if let Some(end) = scratch[..copied].iter().position(|byte| *byte == 0) {
            value.extend_from_slice(&scratch[..end]);
            return std::ffi::CString::new(value).ok();
        }
        value.extend_from_slice(&scratch[..copied]);
    }
    None
}
// Linux accepts a NULL argv as an empty argument list. This distinction is
// specific to argv: an unreadable non-NULL table is still unavailable metadata.
// The owned empty table is only metadata; Call retains the original NULL.
pub(super) unsafe fn argv(pointer: *const *const libc::c_char) -> Option<Vector> {
    if pointer.is_null() {
        Some(Vector::empty())
    } else {
        vector(pointer)
    }
}
pub(super) unsafe fn vector(pointer: *const *const libc::c_char) -> Option<Vector> {
    if pointer.is_null() {
        return None;
    }
    let mut values = Vec::new();
    let mut bytes = 0usize;
    for index in 0..4096usize {
        let mut word = [0u8; std::mem::size_of::<usize>()];
        if read_bytes(
            (pointer as usize).checked_add(index.checked_mul(word.len())?)?,
            &mut word,
        )? != word.len()
        {
            return None;
        }
        let address = usize::from_ne_bytes(word);
        if address == 0 {
            let mut pointers = values
                .iter()
                .map(|value: &std::ffi::CString| value.as_ptr())
                .collect::<Vec<_>>();
            pointers.push(std::ptr::null());
            return Some(Vector { values, pointers });
        }
        let value = string(address as *const libc::c_char, 131072)?;
        bytes = bytes.checked_add(value.as_bytes().len())?;
        if bytes > 1048576 {
            return None;
        }
        values.push(value);
    }
    None
}
pub(super) struct ErrnoRestore(Cell<Option<i32>>);
impl ErrnoRestore {
    pub(super) fn new() -> Self {
        Self(Cell::new(None))
    }
    pub(super) unsafe fn finish(&self, result: i32) -> i32 {
        self.0.set(Some(*libc::__errno_location()));
        result
    }
}
impl Drop for ErrnoRestore {
    fn drop(&mut self) {
        if let Some(error) = self.0.get() {
            unsafe {
                *libc::__errno_location() = error;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn metadata_copy_rejects_unreadable_strings_vectors_and_elements() {
        unsafe {
            let none = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(none, libc::MAP_FAILED);
            assert!(super::string(none.cast(), 4096).is_none());
            assert!(super::string(1usize as *const libc::c_char, 4096).is_none());
            assert!(super::vector(none.cast()).is_none());
            let vector = [
                none.cast::<libc::c_char>() as *const libc::c_char,
                std::ptr::null(),
            ];
            assert!(super::vector(vector.as_ptr()).is_none());
            assert_eq!(libc::munmap(none, 4096), 0);
            let text = std::ffi::CString::new("native argument").unwrap();
            let vector = [text.as_ptr(), std::ptr::null()];
            let copied = super::vector(vector.as_ptr()).unwrap();
            assert_eq!(std::ffi::CStr::from_ptr(*copied.pointer()), text.as_c_str());
        }
    }
    #[test]
    fn null_argv_is_known_empty_without_changing_vector_failure_semantics() {
        unsafe {
            let null = super::argv(std::ptr::null()).unwrap();
            assert_eq!(null.values().count(), 0);
            assert!((*null.pointer()).is_null());
            let empty = [std::ptr::null()];
            let explicit_empty = super::argv(empty.as_ptr()).unwrap();
            assert_eq!(explicit_empty.values().count(), 0);
            assert!((*explicit_empty.pointer()).is_null());
            assert!(super::argv(1usize as *const *const libc::c_char).is_none());
            assert!(super::vector(std::ptr::null()).is_none());
        }
    }
    #[test]
    fn errno_survives_later_argument_and_guard_cleanup() {
        unsafe {
            let saved = super::ErrnoRestore::new();
            *libc::__errno_location() = libc::ENOENT;
            assert_eq!(saved.finish(-1), -1);
            *libc::__errno_location() = libc::EINTR;
            drop(saved);
            assert_eq!(*libc::__errno_location(), libc::ENOENT);
        }
    }
    #[test]
    fn metadata_vector_owns_values_after_source_changes() {
        unsafe {
            let mut text = b"original\0".to_vec();
            let pointers = [text.as_ptr().cast(), std::ptr::null()];
            let copied = super::vector(pointers.as_ptr()).unwrap();
            text.fill(b'x');
            drop(text);
            assert_eq!(copied.values().collect::<Vec<_>>(), vec![c"original"]);
        }
    }
}
