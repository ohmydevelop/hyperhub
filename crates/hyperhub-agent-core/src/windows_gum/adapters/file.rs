use crate::windows_gum::gum::{original, HookGuard, INSIDE_HOOK};
use crate::windows_gum::runtime::{runtime, FileOperation, FileOperationContext};
use crate::windows_gum::shared::*;
use std::collections::HashMap;
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022u32 as i32;
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
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

fn op_for_access(a: u32, disp: u32) -> FileOperation {
    match disp {
        FILE_CREATE => FileOperation::Create,
        FILE_OVERWRITE | FILE_OVERWRITE_IF => FileOperation::Write,
        FILE_OPEN_IF if a & 0x116 != 0 => FileOperation::Write,
        _ if a & 0x116 != 0 => FileOperation::Write,
        _ => FileOperation::Read,
    }
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
    let r = dispatch(op_for_access(a, disp), p.clone(), 0, || {
        f(out, a, o, ios, size, attrs, share, disp, opts, ea, ealen)
    });
    if r >= 0 && !out.is_null() && !(*out).is_null() {
        if let Some(p) = p {
            handles()
                .lock()
                .ok()
                .map(|mut m| m.insert(*out as usize, p));
        }
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
    let r = dispatch(op_for_access(a, 0), p.clone(), 0, || {
        f(out, a, o, ios, share, opts)
    });
    if r >= 0 && !out.is_null() && !(*out).is_null() {
        if let Some(p) = p {
            handles()
                .lock()
                .ok()
                .map(|mut m| m.insert(*out as usize, p));
        }
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
            dispatch($op, handle_path(h), h as usize, || {
                f(h, e, apc, ctx, ios, b, l, off, key)
            })
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
    let op = if matches!(class, 10 | 65) {
        FileOperation::Rename
    } else if matches!(class, 13 | 64) {
        FileOperation::Delete
    } else {
        FileOperation::Write
    };
    dispatch(op, handle_path(h), h as usize, || {
        f(h, ios, info, len, class)
    })
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
    let op =
        if protect & 0x04 != 0 || protect & 0x08 != 0 || protect & 0x40 != 0 || protect & 0x80 != 0
        {
            FileOperation::Write
        } else {
            FileOperation::Read
        };
    let p = handle_path(file);
    let r = dispatch(op, p.clone(), file as usize, || {
        f(out, a, o, size, protect, attrs, file)
    });
    if r >= 0 && !out.is_null() {
        if let Some(p) = p {
            handles()
                .lock()
                .ok()
                .map(|mut m| m.insert(*out as usize, p));
        }
    }
    r
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
    let op =
        if protect & 0x04 != 0 || protect & 0x08 != 0 || protect & 0x40 != 0 || protect & 0x80 != 0
        {
            FileOperation::Write
        } else {
            FileOperation::Read
        };
    dispatch(op, handle_path(sec), sec as usize, || {
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
    let r = f(sp, sh, tp, out, a, attrs, opts);
    if r >= 0 && !out.is_null() {
        if let Some(p) = handle_path(sh) {
            handles()
                .lock()
                .ok()
                .map(|mut m| m.insert(*out as usize, p));
        }
    }
    r
}
pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_close(h: HANDLE) -> i32 {
    let Some(f) = original!(ORIGINAL_NT_CLOSE, NtCloseFn) else {
        return STATUS_ACCESS_DENIED;
    };
    handles().lock().ok().map(|mut m| m.remove(&(h as usize)));
    f(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_if_with_read_access_is_classified_as_read() {
        assert_eq!(op_for_access(0x80, FILE_OPEN_IF), FileOperation::Read);
    }

    #[test]
    fn open_if_with_write_access_is_classified_as_write() {
        assert_eq!(op_for_access(0x120, FILE_OPEN_IF), FileOperation::Write);
    }

    #[test]
    fn create_and_overwrite_dispositions_are_classified_correctly() {
        assert_eq!(op_for_access(0x80, FILE_CREATE), FileOperation::Create);
        assert_eq!(op_for_access(0x80, FILE_OVERWRITE), FileOperation::Write);
        assert_eq!(op_for_access(0x80, FILE_OVERWRITE_IF), FileOperation::Write);
    }
}
