use crate::windows_gum::gum::{original, HookGuard, INSIDE_HOOK};
use crate::windows_gum::runtime::{runtime, FileOperation, FileOperationContext};
use crate::windows_gum::shared::*;
use std::collections::HashMap;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_INVALID_HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileType, GetFinalPathNameByHandleW, FILE_TYPE_CHAR, FILE_TYPE_PIPE, FILE_TYPE_UNKNOWN,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetProcessId};
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022u32 as i32;
fn nt_succeeded(status: i32) -> bool {
    status >= 0
}
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}
#[repr(C)]
pub(in crate::windows_gum) struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *const c_void,
    security_qos: *const c_void,
}
type NtCreateFileFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *const ObjectAttributes,
    *mut c_void,
    *const i64,
    u32,
    u32,
    u32,
    u32,
    *const c_void,
    u32,
) -> i32;
type NtOpenFileFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *const ObjectAttributes,
    *mut c_void,
    u32,
    u32,
) -> i32;
type NtIoFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *const c_void,
    *const c_void,
    *mut c_void,
    *mut c_void,
    u32,
    *const i64,
    *const u32,
) -> i32;
type NtSetInformationFileFn =
    unsafe extern "system" fn(HANDLE, *mut c_void, *const c_void, u32, u32) -> i32;
type NtDeleteFileFn = unsafe extern "system" fn(*const ObjectAttributes) -> i32;
type NtCreateSectionFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *const ObjectAttributes,
    *const i64,
    u32,
    u32,
    HANDLE,
) -> i32;
type NtMapViewFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut *mut c_void,
    usize,
    usize,
    *const i64,
    *mut usize,
    u32,
    u32,
    u32,
) -> i32;
type NtDuplicateObjectFn =
    unsafe extern "system" fn(HANDLE, HANDLE, HANDLE, *mut HANDLE, u32, u32, u32) -> i32;
type NtCloseFn = unsafe extern "system" fn(HANDLE) -> i32;
pub(in crate::windows_gum) static ORIGINAL_NT_CREATE_FILE: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_OPEN_FILE: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_READ_FILE: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_WRITE_FILE: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_SET_INFORMATION_FILE: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_DELETE_FILE: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_CREATE_SECTION: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_MAP_VIEW_OF_SECTION: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_DUPLICATE_OBJECT: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_CLOSE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
fn handles() -> &'static Mutex<HashMap<usize, String>> {
    static H: OnceLock<Mutex<HashMap<usize, String>>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(HashMap::new()))
}
// Replace previous path metadata even when the new object has no file path.
// This prevents a reused section/file handle from retaining an older label.
fn remember_path(handle: HANDLE, path: Option<String>) {
    let _last_error = crate::engine_call::WindowsLastErrorGuard::capture();
    if let Ok(mut map) = handles().lock() {
        map.remove(&(handle as usize));
        if let Some(path) = path {
            map.insert(handle as usize, path);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FileIoTarget {
    Kernel,
    Policy(Option<String>),
}
fn classify_file_io(kind: u32, error: u32, path: impl FnOnce() -> Option<String>) -> FileIoTarget {
    match kind {
        FILE_TYPE_PIPE | FILE_TYPE_CHAR => FileIoTarget::Kernel,
        FILE_TYPE_UNKNOWN if error == ERROR_INVALID_HANDLE => FileIoTarget::Kernel,
        _ => FileIoTarget::Policy(path()),
    }
}
unsafe fn file_io_target(handle: HANDLE) -> FileIoTarget {
    // Drop before the original API call. Its own error/result must survive.
    let _last_error = crate::engine_call::WindowsLastErrorGuard::capture();
    SetLastError(0);
    let kind = GetFileType(handle);
    let error = GetLastError();
    classify_file_io(kind, error, || handle_path(handle))
}
unsafe fn dispatch_file_io(
    op: FileOperation,
    handle: HANDLE,
    original: impl FnOnce() -> i32,
) -> i32 {
    if INSIDE_HOOK.with(Cell::get) {
        return original();
    }
    match file_io_target(handle) {
        FileIoTarget::Kernel => original(),
        FileIoTarget::Policy(path) => dispatch(op, path, handle as usize, original),
    }
}
#[repr(C)]
#[derive(Default)]
struct SectionBasicInformation {
    base_address: *mut c_void,
    allocation_attributes: u32,
    maximum_size: i64,
}
type NtQuerySectionFn =
    unsafe extern "system" fn(HANDLE, u32, *mut c_void, usize, *mut usize) -> i32;

// NtQuerySection's authoritative allocation attributes distinguish pagefile
// memory from data/image files. No numeric handle is cached as exempt.
// https://learn.microsoft.com/windows/win32/devnotes/ntquerysection
unsafe fn anonymous_section(section: HANDLE) -> bool {
    let _last_error = crate::engine_call::WindowsLastErrorGuard::capture();
    static QUERY: OnceLock<Option<NtQuerySectionFn>> = OnceLock::new();
    let Some(query) = *QUERY.get_or_init(|| {
        crate::windows_gum::gum::find_export("ntdll.dll", "NtQuerySection")
            .map(|pointer| std::mem::transmute::<*mut c_void, NtQuerySectionFn>(pointer))
    }) else {
        return false;
    };
    let mut info = SectionBasicInformation::default();
    let mut returned = 0;
    let size = std::mem::size_of::<SectionBasicInformation>();
    let status = query(
        section,
        0,
        (&mut info as *mut SectionBasicInformation).cast(),
        size,
        &mut returned,
    );
    query_proves_anonymous(status, returned, &info)
}
fn query_proves_anonymous(status: i32, returned: usize, info: &SectionBasicInformation) -> bool {
    status == 0
        && returned == std::mem::size_of::<SectionBasicInformation>()
        && info.maximum_size > 0
        && info.allocation_attributes & (0x0080_0000 | 0x0100_0000) == 0
}
unsafe fn create_section(
    out: *mut HANDLE,
    file: HANDLE,
    operations: &[FileOperation],
    original: impl FnOnce() -> i32,
) -> i32 {
    let path = {
        let _last_error = crate::engine_call::WindowsLastErrorGuard::capture();
        if file.is_null() {
            None
        } else {
            handle_path(file)
        }
    };
    // A null backing file is explicitly pagefile-backed, so creating it is a
    // memory operation. Map authorization is re-proven by OS query each time.
    let result = if file.is_null() {
        original()
    } else {
        dispatch_operations(operations, path.clone(), file as usize, original)
    };
    if nt_succeeded(result) && !out.is_null() && !(*out).is_null() {
        remember_path(*out, path);
    }
    result
}
unsafe fn section_target(section: HANDLE) -> FileIoTarget {
    let _last_error = crate::engine_call::WindowsLastErrorGuard::capture();
    if anonymous_section(section) {
        FileIoTarget::Kernel
    } else {
        FileIoTarget::Policy(handle_path(section))
    }
}
unsafe fn map_section(
    section: HANDLE,
    operations: &[FileOperation],
    original: impl FnOnce() -> i32,
) -> i32 {
    if INSIDE_HOOK.with(Cell::get) {
        return original();
    }
    match section_target(section) {
        FileIoTarget::Kernel => original(),
        FileIoTarget::Policy(path) => {
            dispatch_operations(operations, path, section as usize, original)
        }
    }
}
unsafe fn duplicate_object(
    sp: HANDLE,
    sh: HANDLE,
    tp: HANDLE,
    out: *mut HANDLE,
    options: u32,
    original: impl FnOnce() -> i32,
) -> i32 {
    let (source_local, target_local, path) = {
        let _last_error = crate::engine_call::WindowsLastErrorGuard::capture();
        let current = GetCurrentProcessId();
        let source_local = GetProcessId(sp) == current;
        let target_local = GetProcessId(tp) == current;
        let path = if source_local { handle_path(sh) } else { None };
        (source_local, target_local, path)
    };
    let result = original();
    if source_local && options & 1 != 0 {
        remember_path(sh, None);
    }
    if nt_succeeded(result) && target_local && !out.is_null() && !(*out).is_null() {
        remember_path(*out, path);
    }
    result
}
fn close_object(handle: HANDLE, status: i32) -> i32 {
    if nt_succeeded(status) {
        remember_path(handle, None);
    }
    status
}

unsafe fn object_path(o: *const ObjectAttributes) -> Option<String> {
    let o = o.as_ref()?;
    let n = o.object_name.as_ref()?;
    if n.buffer.is_null() {
        return None;
    }
    let s = String::from_utf16_lossy(std::slice::from_raw_parts(
        n.buffer,
        usize::from(n.length / 2),
    ));
    let path = normalize(&s);
    if !o.root_directory.is_null() && !path.contains(':') && !path.starts_with("//") {
        if let Some(root) = handle_path(o.root_directory) {
            return Some(format!(
                "{}/{}",
                root.trim_end_matches('/'),
                path.trim_start_matches('/')
            ));
        }
    }
    Some(path)
}
fn normalize(s: &str) -> String {
    s.trim_start_matches(r"\??\")
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}
unsafe fn handle_path(h: HANDLE) -> Option<String> {
    if h.is_null() {
        return None;
    }
    if let Some(v) = handles().lock().ok()?.get(&(h as usize)).cloned() {
        return Some(v);
    }
    let mut b = vec![0u16; 32768];
    let n = GetFinalPathNameByHandleW(h, b.as_mut_ptr(), b.len() as u32, 0);
    if n == 0 || n as usize >= b.len() {
        return None;
    }
    let p = normalize(&String::from_utf16_lossy(&b[..n as usize]));
    handles().lock().ok()?.insert(h as usize, p.clone());
    Some(p)
}

unsafe fn rename_target_path(info: *const c_void, length: u32) -> Option<String> {
    if info.is_null() || length < 20 {
        return None;
    }
    let bytes = info.cast::<u8>();
    let root = bytes.add(8).cast::<HANDLE>().read_unaligned();
    let name_length = bytes.add(16).cast::<u32>().read_unaligned() as usize;
    if name_length == 0
        || name_length % 2 != 0
        || 20usize.saturating_add(name_length) > length as usize
    {
        return None;
    }
    let name = String::from_utf16_lossy(std::slice::from_raw_parts(
        bytes.add(20).cast::<u16>(),
        name_length / 2,
    ));
    let name = normalize(&name);
    if !root.is_null() && !name.contains(':') && !name.starts_with("//") {
        handle_path(root).map(|base| {
            format!(
                "{}/{}",
                base.trim_end_matches('/'),
                name.trim_start_matches('/')
            )
        })
    } else {
        Some(name)
    }
}
unsafe fn dispatch(
    op: FileOperation,
    path: Option<String>,
    handle: usize,
    original_call: impl FnOnce() -> i32,
) -> i32 {
    if INSIDE_HOOK.with(Cell::get) {
        return original_call();
    }
    let Some(_g) = HookGuard::enter() else {
        return original_call();
    };
    let mut c = FileOperationContext {
        operation: op,
        path,
        _handle: handle,
        result: STATUS_ACCESS_DENIED,
    };
    runtime().file_operation.dispatch(
        &mut c,
        |c| {
            c.result = original_call();
            c.result
        },
        |_, _, _| STATUS_ACCESS_DENIED,
    )
}
#[cfg(test)]
const FILE_CREATE: u32 = 2;
#[cfg(test)]
const FILE_OPEN_IF: u32 = 3;
#[cfg(test)]
const FILE_OVERWRITE: u32 = 4;
#[cfg(test)]
const FILE_OVERWRITE_IF: u32 = 5;

fn native_operations(operations: Vec<crate::FileSandboxOperation>) -> Vec<FileOperation> {
    operations
        .into_iter()
        .map(|operation| match operation {
            crate::FileSandboxOperation::Read => FileOperation::Read,
            crate::FileSandboxOperation::Write => FileOperation::Write,
            crate::FileSandboxOperation::Create => FileOperation::Create,
            crate::FileSandboxOperation::Delete => FileOperation::Delete,
            crate::FileSandboxOperation::Rename => FileOperation::Rename,
        })
        .collect()
}
fn operations_for_access(
    access: u32,
    disposition: Option<u32>,
    options: u32,
) -> Vec<FileOperation> {
    native_operations(crate::windows_gum::file_intents::open(
        access,
        disposition,
        options,
    ))
}
fn operations_for_protection(protection: u32) -> Vec<FileOperation> {
    native_operations(crate::windows_gum::file_intents::mapping(protection))
}

unsafe fn dispatch_operations(
    operations: &[FileOperation],
    path: Option<String>,
    handle: usize,
    original_call: impl FnOnce() -> i32,
) -> i32 {
    let Some((last, leading)) = operations.split_last() else {
        return original_call();
    };
    for operation in leading {
        let result = dispatch(*operation, path.clone(), handle, || 0);
        if result == STATUS_ACCESS_DENIED {
            return result;
        }
    }
    dispatch(*last, path, handle, original_call)
}
#[no_mangle]
pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_create_file(
    out: *mut HANDLE,
    a: u32,
    o: *const ObjectAttributes,
    ios: *mut c_void,
    size: *const i64,
    attrs: u32,
    share: u32,
    disp: u32,
    opts: u32,
    ea: *const c_void,
    ealen: u32,
) -> i32 {
    let Some(f) = original!(ORIGINAL_NT_CREATE_FILE, NtCreateFileFn) else {
        return STATUS_ACCESS_DENIED;
    };
    let p = object_path(o);
    let r = dispatch_operations(
        &operations_for_access(a, Some(disp), opts),
        p.clone(),
        0,
        || f(out, a, o, ios, size, attrs, share, disp, opts, ea, ealen),
    );
    if nt_succeeded(r) && !out.is_null() && !(*out).is_null() {
        remember_path(*out, p);
    }
    r
}
#[no_mangle]
pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_open_file(
    out: *mut HANDLE,
    a: u32,
    o: *const ObjectAttributes,
    ios: *mut c_void,
    share: u32,
    opts: u32,
) -> i32 {
    let Some(f) = original!(ORIGINAL_NT_OPEN_FILE, NtOpenFileFn) else {
        return STATUS_ACCESS_DENIED;
    };
    let p = object_path(o);
    let r = dispatch_operations(&operations_for_access(a, None, opts), p.clone(), 0, || {
        f(out, a, o, ios, share, opts)
    });
    if nt_succeeded(r) && !out.is_null() && !(*out).is_null() {
        remember_path(*out, p);
    }
    r
}
macro_rules! io_hook {
    ($name:ident,$slot:ident,$op:expr) => {
        pub(in crate::windows_gum) unsafe extern "system" fn $name(
            h: HANDLE,
            e: HANDLE,
            apc: *const c_void,
            ctx: *const c_void,
            ios: *mut c_void,
            b: *mut c_void,
            l: u32,
            off: *const i64,
            key: *const u32,
        ) -> i32 {
            let Some(f) = original!($slot, NtIoFn) else {
                return STATUS_ACCESS_DENIED;
            };
            dispatch_file_io($op, h, || f(h, e, apc, ctx, ios, b, l, off, key))
        }
    };
}
io_hook!(
    hook_nt_read_file,
    ORIGINAL_NT_READ_FILE,
    FileOperation::Read
);
io_hook!(
    hook_nt_write_file,
    ORIGINAL_NT_WRITE_FILE,
    FileOperation::Write
);
fn is_link_information(class: u32) -> bool {
    matches!(class, 11 | 57 | 72 | 73)
}
pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_set_information_file(
    h: HANDLE,
    ios: *mut c_void,
    info: *const c_void,
    len: u32,
    class: u32,
) -> i32 {
    let Some(f) = original!(ORIGINAL_NT_SET_INFORMATION_FILE, NtSetInformationFileFn) else {
        return STATUS_ACCESS_DENIED;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return f(h, ios, info, len, class);
    }
    let path = match file_io_target(h) {
        FileIoTarget::Kernel => return f(h, ios, info, len, class),
        FileIoTarget::Policy(path) => path,
    };
    if is_link_information(class) {
        let source = dispatch_operations(
            &[
                FileOperation::Read,
                FileOperation::Write,
                FileOperation::Rename,
            ],
            path,
            h as usize,
            || 0,
        );
        if source == STATUS_ACCESS_DENIED {
            return source;
        }
        // FileLinkInformation and FileLinkInformationEx use the same root/name
        // layout as their rename counterparts on the supported 64-bit targets.
        return dispatch(
            FileOperation::Create,
            rename_target_path(info, len),
            0,
            || f(h, ios, info, len, class),
        );
    }
    let op = if matches!(class, 10 | 56 | 65 | 66) {
        let source = dispatch_operations(
            &[
                FileOperation::Read,
                FileOperation::Write,
                FileOperation::Rename,
            ],
            path,
            h as usize,
            || 0,
        );
        if source == STATUS_ACCESS_DENIED {
            return source;
        }
        return dispatch_operations(
            &[FileOperation::Create, FileOperation::Rename],
            rename_target_path(info, len),
            0,
            || f(h, ios, info, len, class),
        );
    } else if matches!(class, 13 | 64) {
        FileOperation::Delete
    } else {
        FileOperation::Write
    };
    dispatch(op, path, h as usize, || f(h, ios, info, len, class))
}
pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_delete_file(
    o: *const ObjectAttributes,
) -> i32 {
    let Some(f) = original!(ORIGINAL_NT_DELETE_FILE, NtDeleteFileFn) else {
        return STATUS_ACCESS_DENIED;
    };
    dispatch(FileOperation::Delete, object_path(o), 0, || f(o))
}
pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_create_section(
    out: *mut HANDLE,
    a: u32,
    o: *const ObjectAttributes,
    size: *const i64,
    protect: u32,
    attrs: u32,
    file: HANDLE,
) -> i32 {
    let Some(f) = original!(ORIGINAL_NT_CREATE_SECTION, NtCreateSectionFn) else {
        return STATUS_ACCESS_DENIED;
    };
    let operations = operations_for_protection(protect);
    create_section(out, file, &operations, || {
        f(out, a, o, size, protect, attrs, file)
    })
}
pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_map_view_of_section(
    sec: HANDLE,
    proc: HANDLE,
    base: *mut *mut c_void,
    zero: usize,
    commit: usize,
    off: *const i64,
    size: *mut usize,
    inherit: u32,
    alloc: u32,
    protect: u32,
) -> i32 {
    let Some(f) = original!(ORIGINAL_NT_MAP_VIEW_OF_SECTION, NtMapViewFn) else {
        return STATUS_ACCESS_DENIED;
    };
    let operations = operations_for_protection(protect);
    map_section(sec, &operations, || {
        f(
            sec, proc, base, zero, commit, off, size, inherit, alloc, protect,
        )
    })
}
pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_duplicate_object(
    sp: HANDLE,
    sh: HANDLE,
    tp: HANDLE,
    out: *mut HANDLE,
    a: u32,
    attrs: u32,
    opts: u32,
) -> i32 {
    let Some(f) = original!(ORIGINAL_NT_DUPLICATE_OBJECT, NtDuplicateObjectFn) else {
        return STATUS_ACCESS_DENIED;
    };
    duplicate_object(sp, sh, tp, out, opts, || f(sp, sh, tp, out, a, attrs, opts))
}
pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_close(h: HANDLE) -> i32 {
    let Some(f) = original!(ORIGINAL_NT_CLOSE, NtCloseFn) else {
        return STATUS_ACCESS_DENIED;
    };
    close_object(h, f(h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, FILE_TYPE_DISK};
    use windows_sys::Win32::System::Pipes::CreatePipe;

    #[test]
    fn actual_pipe_io_bypasses_disk_policy_and_preserves_error_state() {
        unsafe {
            let mut read = null_mut();
            let mut write = null_mut();
            assert_ne!(CreatePipe(&mut read, &mut write, null(), 0), 0);
            let read = OwnedHandle::from_raw_handle(read);
            let write = OwnedHandle::from_raw_handle(write);
            for handle in [read.as_raw_handle(), write.as_raw_handle()] {
                WSASetLastError(12345);
                assert_eq!(file_io_target(handle), FileIoTarget::Kernel);
                assert_eq!(GetLastError(), 12345);
                assert_eq!(WSAGetLastError(), 12345);
            }
            let bytes = b"private-pipe";
            let mut transferred = 0;
            assert_ne!(
                dispatch_file_io(FileOperation::Write, write.as_raw_handle(), || WriteFile(
                    write.as_raw_handle(),
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut transferred,
                    null_mut()
                )),
                0
            );
            assert_eq!(transferred as usize, bytes.len());
            let mut received = [0; 12];
            assert_ne!(
                dispatch_file_io(FileOperation::Read, read.as_raw_handle(), || ReadFile(
                    read.as_raw_handle(),
                    received.as_mut_ptr(),
                    received.len() as u32,
                    &mut transferred,
                    null_mut()
                )),
                0
            );
            assert_eq!(transferred as usize, bytes.len());
            assert_eq!(&received, bytes);
        }
    }

    #[test]
    fn actual_pipe_information_preserves_native_status_and_error_state() {
        unsafe {
            let mut read = null_mut();
            let mut write = null_mut();
            assert_ne!(CreatePipe(&mut read, &mut write, null(), 0), 0);
            let read = OwnedHandle::from_raw_handle(read);
            let _write = OwnedHandle::from_raw_handle(write);
            let set: NtSetInformationFileFn = std::mem::transmute(
                crate::windows_gum::gum::find_export("ntdll.dll", "NtSetInformationFile").unwrap(),
            );
            let mut ios = [0usize; 2];
            let information = [0u32; 2];
            let expected = set(
                read.as_raw_handle(),
                ios.as_mut_ptr().cast(),
                information.as_ptr().cast(),
                8,
                23,
            );
            assert_eq!(expected, 0, "byte-mode synchronous pipe information");
            SetLastError(12345);
            assert_eq!(file_io_target(read.as_raw_handle()), FileIoTarget::Kernel);
            assert_eq!(GetLastError(), 12345);
            let actual = dispatch_file_io(FileOperation::Write, read.as_raw_handle(), || {
                SetLastError(54321);
                set(
                    read.as_raw_handle(),
                    ios.as_mut_ptr().cast(),
                    information.as_ptr().cast(),
                    8,
                    23,
                )
            });
            assert_eq!(actual, expected);
            assert_eq!(GetLastError(), 54321);
        }
    }

    #[test]
    fn actual_character_device_io_bypasses_disk_policy() {
        unsafe {
            use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
            let name: Vec<u16> = "NUL".encode_utf16().chain(Some(0)).collect();
            let handle = CreateFileW(
                name.as_ptr(),
                0xC000_0000,
                3,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            );
            assert_ne!(handle, INVALID_HANDLE_VALUE);
            let handle = OwnedHandle::from_raw_handle(handle);
            assert_eq!(file_io_target(handle.as_raw_handle()), FileIoTarget::Kernel);
        }
    }

    #[test]
    fn actual_disk_io_stays_in_file_policy_domain() {
        let path = std::env::temp_dir().join(format!(
            "hyperhub-io-domain-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        unsafe {
            SetLastError(12345);
            assert!(matches!(
                file_io_target(file.as_raw_handle()),
                FileIoTarget::Policy(Some(_))
            ));
            assert_eq!(GetLastError(), 12345);
        }
        remember_path(file.as_raw_handle(), None);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn unresolved_disk_and_unknown_handles_stay_in_file_policy_domain() {
        assert_eq!(
            classify_file_io(FILE_TYPE_DISK, ERROR_ACCESS_DENIED, || None),
            FileIoTarget::Policy(None)
        );
        assert_eq!(
            classify_file_io(FILE_TYPE_UNKNOWN, ERROR_ACCESS_DENIED, || None),
            FileIoTarget::Policy(None)
        );
        assert_eq!(
            classify_file_io(0x8000, ERROR_INVALID_HANDLE, || None),
            FileIoTarget::Policy(None)
        );
    }

    #[test]
    fn invalid_handle_io_keeps_original_ntstatus_and_original_error_state() {
        unsafe {
            let write: NtIoFn = std::mem::transmute(
                crate::windows_gum::gum::find_export("ntdll.dll", "NtWriteFile").unwrap(),
            );
            let mut ios = [0usize; 2];
            let mut byte = 0u8;
            let mut native = || {
                write(
                    null_mut(),
                    null_mut(),
                    null(),
                    null(),
                    ios.as_mut_ptr().cast(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    null(),
                    null(),
                )
            };
            let expected = native();
            assert!(expected < 0);
            SetLastError(12345);
            assert_eq!(file_io_target(null_mut()), FileIoTarget::Kernel);
            assert_eq!(GetLastError(), 12345);
            assert_eq!(file_io_target(INVALID_HANDLE_VALUE), FileIoTarget::Kernel);
            let actual = dispatch_file_io(FileOperation::Write, null_mut(), || {
                SetLastError(54321);
                write(
                    null_mut(),
                    null_mut(),
                    null(),
                    null(),
                    ios.as_mut_ptr().cast(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    null(),
                    null(),
                )
            });
            assert_eq!(actual, expected);
            assert_eq!(GetLastError(), 54321);
        }
    }

    struct NativeSection(OwnedHandle);
    impl Drop for NativeSection {
        fn drop(&mut self) {
            remember_path(self.0.as_raw_handle(), None);
        }
    }
    impl NativeSection {
        fn handle(&self) -> HANDLE {
            self.0.as_raw_handle()
        }
    }
    unsafe fn native_section(file: HANDLE) -> NativeSection {
        let create: NtCreateSectionFn = std::mem::transmute(
            crate::windows_gum::gum::find_export("ntdll.dll", "NtCreateSection").unwrap(),
        );
        let mut section = null_mut();
        let size = 4096_i64;
        // Allocate the OS fixture without requiring an injected plugin runtime.
        // Restore recursion state before every classification/policy assertion.
        struct RestoreHook(bool);
        impl Drop for RestoreHook {
            fn drop(&mut self) {
                INSIDE_HOOK.with(|inside| inside.set(self.0));
            }
        }
        let previous = INSIDE_HOOK.with(Cell::get);
        let result = {
            let _restore = RestoreHook(INSIDE_HOOK.with(|inside| inside.replace(true)));
            create_section(
                &mut section,
                file,
                &[FileOperation::Read, FileOperation::Write],
                || {
                    create(
                        &mut section,
                        0x000F_001F,
                        null(),
                        &size,
                        4,
                        0x0800_0000,
                        file,
                    )
                },
            )
        };
        assert_eq!(INSIDE_HOOK.with(Cell::get), previous);
        assert_eq!(result, 0);
        assert!(!section.is_null());
        NativeSection(OwnedHandle::from_raw_handle(section))
    }

    #[test]
    fn actual_anonymous_section_maps_without_a_disk_path_or_cached_exemption() {
        unsafe {
            use windows_sys::Win32::Foundation::DuplicateHandle;
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            let section = native_section(null_mut());
            SetLastError(12345);
            assert!(anonymous_section(section.handle()));
            assert_eq!(GetLastError(), 12345);
            assert_eq!(section_target(section.handle()), FileIoTarget::Kernel);
            assert!(!handles()
                .lock()
                .unwrap()
                .contains_key(&(section.handle() as usize)));
            let map: NtMapViewFn = std::mem::transmute(
                crate::windows_gum::gum::find_export("ntdll.dll", "NtMapViewOfSection").unwrap(),
            );
            let unmap: unsafe extern "system" fn(HANDLE, *mut c_void) -> i32 = std::mem::transmute(
                crate::windows_gum::gum::find_export("ntdll.dll", "NtUnmapViewOfSection").unwrap(),
            );
            let mut base = null_mut();
            let mut size = 4096_usize;
            assert_eq!(
                map_section(
                    section.handle(),
                    &[FileOperation::Read, FileOperation::Write],
                    || {
                        SetLastError(54321);
                        map(
                            section.handle(),
                            GetCurrentProcess(),
                            &mut base,
                            0,
                            0,
                            null(),
                            &mut size,
                            2,
                            0,
                            4,
                        )
                    }
                ),
                0
            );
            assert_eq!(GetLastError(), 54321);
            assert!(!base.is_null());
            base.cast::<u32>().write_volatile(0x1234_5678);
            assert_eq!(base.cast::<u32>().read_volatile(), 0x1234_5678);
            assert_eq!(unmap(GetCurrentProcess(), base), 0);
            let mut duplicate = null_mut();
            assert_ne!(
                DuplicateHandle(
                    GetCurrentProcess(),
                    section.handle(),
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    0,
                    2
                ),
                0
            );
            let duplicate = NativeSection(OwnedHandle::from_raw_handle(duplicate));
            assert!(anonymous_section(duplicate.handle()));
            assert!(!handles()
                .lock()
                .unwrap()
                .contains_key(&(duplicate.handle() as usize)));
        }
    }

    #[test]
    fn actual_disk_section_retains_backing_path_and_deny_policy() {
        let path = std::env::temp_dir().join(format!(
            "hyperhub-section-domain-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(4096).unwrap();
        unsafe {
            let section = native_section(file.as_raw_handle());
            assert!(!anonymous_section(section.handle()));
            let FileIoTarget::Policy(Some(backing)) = section_target(section.handle()) else {
                panic!("disk section lost its backing path");
            };
            let snapshot = crate::compile_file_snapshot(crate::FileSandboxSnapshot {
                default_action: crate::SandboxAction::Pass,
                error_action: crate::SandboxAction::Deny,
                rules: vec![crate::FileSandboxSnapshotRule {
                    id: "deny-disk-map".into(),
                    action: crate::SandboxAction::Deny,
                    patterns: vec![format!("^{}$", regex::escape(&backing))],
                    operations: vec![
                        crate::FileSandboxOperation::Read,
                        crate::FileSandboxOperation::Write,
                    ],
                    protection: None,
                }],
            })
            .unwrap();
            assert_eq!(
                crate::file_sandbox_decision(
                    &snapshot,
                    &backing,
                    crate::FileSandboxOperation::Write
                )
                .0,
                crate::SandboxAction::Deny
            );
            assert_eq!(
                crate::file_sandbox_decision(
                    &snapshot,
                    &backing,
                    crate::FileSandboxOperation::Read
                )
                .0,
                crate::SandboxAction::Deny
            );
        }
        remember_path(file.as_raw_handle(), None);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn query_limited_or_invalid_sections_never_gain_anonymous_authorization() {
        unsafe {
            use windows_sys::Win32::Foundation::DuplicateHandle;
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            let section = native_section(null_mut());
            let mut limited = null_mut();
            assert_ne!(
                DuplicateHandle(
                    GetCurrentProcess(),
                    section.handle(),
                    GetCurrentProcess(),
                    &mut limited,
                    4,
                    0,
                    0
                ),
                0
            );
            let limited = NativeSection(OwnedHandle::from_raw_handle(limited));
            assert!(!anonymous_section(limited.handle()));
            assert_eq!(section_target(limited.handle()), FileIoTarget::Policy(None));
            assert!(!anonymous_section(null_mut()));
            assert_eq!(section_target(null_mut()), FileIoTarget::Policy(None));
        }
    }

    #[test]
    fn incomplete_or_failed_section_queries_do_not_authorize_memory_maps() {
        let mut info = SectionBasicInformation {
            maximum_size: 4096,
            ..Default::default()
        };
        let size = std::mem::size_of::<SectionBasicInformation>();
        assert_eq!(size, 24);
        assert_eq!(
            std::mem::offset_of!(SectionBasicInformation, allocation_attributes),
            8
        );
        assert_eq!(
            std::mem::offset_of!(SectionBasicInformation, maximum_size),
            16
        );
        assert!(query_proves_anonymous(0, size, &info));
        assert!(!query_proves_anonymous(1, size, &info));
        assert!(!query_proves_anonymous(STATUS_ACCESS_DENIED, size, &info));
        assert!(!query_proves_anonymous(0, size - 1, &info));
        for attributes in [0x0080_0000, 0x0100_0000, 0x0180_0000] {
            info.allocation_attributes = attributes;
            assert!(!query_proves_anonymous(0, size, &info));
        }
        info.allocation_attributes = 0;
        info.maximum_size = 0;
        assert!(!query_proves_anonymous(0, size, &info));
    }

    #[test]
    fn open_if_with_read_access_is_classified_as_read() {
        assert_eq!(
            operations_for_access(0x80, Some(FILE_OPEN_IF), 0),
            vec![FileOperation::Create]
        );
    }

    #[test]
    fn open_if_with_write_access_is_classified_as_write() {
        assert_eq!(
            operations_for_access(0x102, Some(FILE_OPEN_IF), 0),
            vec![FileOperation::Create, FileOperation::Write]
        );
    }

    #[test]
    fn failed_nt_close_keeps_handle_state() {
        assert!(!nt_succeeded(STATUS_ACCESS_DENIED));
        assert!(nt_succeeded(0));
    }

    #[test]
    fn parses_relative_rename_target_from_file_information() {
        let name: Vec<u16> = r"\??\C:\tmp\target.txt".encode_utf16().collect();
        let mut bytes = vec![0_u8; 20 + name.len() * 2];
        bytes[16..20].copy_from_slice(&((name.len() * 2) as u32).to_ne_bytes());
        unsafe {
            std::ptr::copy_nonoverlapping(
                name.as_ptr().cast::<u8>(),
                bytes.as_mut_ptr().add(20),
                name.len() * 2,
            );
            assert_eq!(
                rename_target_path(bytes.as_ptr().cast(), bytes.len() as u32).as_deref(),
                Some("C:/tmp/target.txt")
            );
        }
    }

    #[test]
    fn both_hardlink_information_classes_are_namespace_operations() {
        assert!(is_link_information(11));
        assert!(is_link_information(72));
        assert!(is_link_information(57));
        assert!(is_link_information(73));
        for class in [10, 13, 56, 64, 65, 66, 71] {
            assert!(!is_link_information(class));
        }
    }

    #[test]
    fn create_and_overwrite_dispositions_are_classified_correctly() {
        assert_eq!(
            operations_for_access(0x80, Some(FILE_CREATE), 0),
            vec![FileOperation::Create]
        );
        assert_eq!(
            operations_for_access(0x80, Some(FILE_OVERWRITE), 0),
            vec![FileOperation::Write]
        );
        assert_eq!(
            operations_for_access(0x80, Some(FILE_OVERWRITE_IF), 0),
            vec![FileOperation::Create, FileOperation::Write]
        );
    }
}
