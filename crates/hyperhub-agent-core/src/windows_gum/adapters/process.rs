use std::cell::Cell;

use crate::windows_gum::gum::{find_msys_runtime_export, original, HookGuard, INSIDE_HOOK};
use crate::windows_gum::shared::*;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED};
use windows_sys::Win32::System::Environment::{GetCommandLineW, GetEnvironmentVariableW};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetStartupInfoW};

thread_local! {
    static AUTHORIZED_MSYS_FORK: Cell<bool> = const { Cell::new(false) };
    static INSIDE_MSYS_FORK_EXPORT: Cell<bool> = const { Cell::new(false) };
    static MSYS_FORK_WINDOWS_CHILD_PID: Cell<u32> = const { Cell::new(0) };
}

type MsysForkFn = unsafe extern "C" fn() -> i32;
type CygwinInternalPidFn = unsafe extern "C" fn(i32, i32) -> usize;
type CygwinErrnoFn = unsafe extern "C" fn() -> *mut i32;
type LdrLoadDllFn =
    unsafe extern "system" fn(*const u16, *const u32, *const UnicodeString, *mut HMODULE) -> i32;

#[repr(C)]
pub(in crate::windows_gum) struct UnicodeString {
    length: u16,
    _maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct RtlUserProcessParameters {
    _reserved1: [u8; 16],
    _reserved2: [*mut c_void; 10],
    image_path_name: UnicodeString,
    _command_line: UnicodeString,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MsysChildInfoHeader {
    msv_count: u32,
    cb: u32,
    intro: u32,
    _magic: u32,
    kind: u16,
}
pub(in crate::windows_gum) type CreateProcessAFn = unsafe extern "system" fn(
    *const u8,
    *mut u8,
    *const c_void,
    *const c_void,
    i32,
    u32,
    *const c_void,
    *const u8,
    *const STARTUPINFOA,
    *mut PROCESS_INFORMATION,
) -> i32;
pub(in crate::windows_gum) type CreateProcessWFn = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *const c_void,
    *const c_void,
    i32,
    u32,
    *const c_void,
    *const u16,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> i32;
pub(in crate::windows_gum) type CreateProcessInternalAFn = unsafe extern "system" fn(
    HANDLE,
    *const u8,
    *mut u8,
    *const c_void,
    *const c_void,
    i32,
    u32,
    *const c_void,
    *const u8,
    *const STARTUPINFOA,
    *mut PROCESS_INFORMATION,
    *mut HANDLE,
) -> i32;
pub(in crate::windows_gum) type CreateProcessInternalWFn = unsafe extern "system" fn(
    HANDLE,
    *const u16,
    *mut u16,
    *const c_void,
    *const c_void,
    i32,
    u32,
    *const c_void,
    *const u16,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
    *mut HANDLE,
) -> i32;
pub(in crate::windows_gum) type NtCreateUserProcessFn = unsafe extern "system" fn(
    *mut HANDLE,
    *mut HANDLE,
    u32,
    u32,
    *const c_void,
    *const c_void,
    u32,
    u32,
    *const c_void,
    *mut c_void,
    *const c_void,
) -> i32;

pub(in crate::windows_gum) static ORIGINAL_CREATE_PROCESS_A: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CREATE_PROCESS_W: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CREATE_PROCESS_INTERNAL_A: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CREATE_PROCESS_INTERNAL_W: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_NT_CREATE_USER_PROCESS: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_MSYS_FORK: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_MSYS_VFORK: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_LDR_LOAD_DLL: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());

pub(in crate::windows_gum) unsafe extern "system" fn hook_ldr_load_dll(
    search_path: *const u16,
    flags: *const u32,
    name: *const UnicodeString,
    module: *mut HMODULE,
) -> i32 {
    let Some(original) = original!(ORIGINAL_LDR_LOAD_DLL, LdrLoadDllFn) else {
        return STATUS_DLL_INIT_FAILED;
    };
    let _guard = HookGuard::enter();
    let status = original(search_path, flags, name, module);
    if status >= 0
        && !module.is_null()
        && !(*module).is_null()
        && is_msys_runtime_unicode(name)
        && !crate::windows_gum::manager::complete_msys_runtime_hook_install(*module)
        && !fork_observe_mode()
    {
        windows_sys::Win32::System::Threading::ExitProcess(ERROR_DLL_INIT_FAILED);
    }
    status
}

unsafe fn is_msys_runtime_unicode(name: *const UnicodeString) -> bool {
    if name.is_null() {
        return false;
    }
    let name = &*name;
    if name.buffer.is_null() || name.length == 0 || name.length % 2 != 0 {
        return false;
    }
    let length = usize::from(name.length / 2);
    wide_suffix_ascii_case_eq(name.buffer, length, "msys-2.0.dll")
        || wide_suffix_ascii_case_eq(name.buffer, length, "cygwin1.dll")
}

unsafe fn wide_suffix_ascii_case_eq(buffer: *const u16, length: usize, suffix: &str) -> bool {
    let suffix = suffix.as_bytes();
    if length < suffix.len() {
        return false;
    }
    let offset = length - suffix.len();
    for (index, expected) in suffix.iter().copied().enumerate() {
        let actual = *buffer.add(offset + index);
        if actual > u16::from(u8::MAX)
            || (actual as u8).to_ascii_lowercase() != expected.to_ascii_lowercase()
        {
            return false;
        }
    }
    true
}

struct ForkControlContext {
    endpoint: String,
    session_id: String,
    token: String,
    lease_id: String,
    parent_pid: u32,
}

pub(in crate::windows_gum) unsafe extern "C" fn hook_msys_fork() -> i32 {
    run_msys_fork_export(ORIGINAL_MSYS_FORK.load(Ordering::Acquire))
}

pub(in crate::windows_gum) unsafe extern "C" fn hook_msys_vfork() -> i32 {
    run_msys_fork_export(ORIGINAL_MSYS_VFORK.load(Ordering::Acquire))
}

unsafe fn run_msys_fork_export(original: *mut c_void) -> i32 {
    if original.is_null() {
        set_msys_errno_access_denied();
        return -1;
    }
    let original = std::mem::transmute::<*mut c_void, MsysForkFn>(original);
    if INSIDE_MSYS_FORK_EXPORT.with(|inside| inside.replace(true)) {
        return original();
    }
    struct ExportGuard;
    impl Drop for ExportGuard {
        fn drop(&mut self) {
            INSIDE_MSYS_FORK_EXPORT.with(|inside| inside.set(false));
            AUTHORIZED_MSYS_FORK.with(|authorized| authorized.set(false));
        }
    }
    let _guard = ExportGuard;
    let Some(context) = begin_fork_context() else {
        if fork_observe_mode() {
            AUTHORIZED_MSYS_FORK.with(|authorized| authorized.set(true));
            let result = original();
            AUTHORIZED_MSYS_FORK.with(|authorized| authorized.set(false));
            return result;
        }
        set_msys_errno_access_denied();
        return -1;
    };
    AUTHORIZED_MSYS_FORK.with(|authorized| authorized.set(true));
    MSYS_FORK_WINDOWS_CHILD_PID.with(|pid| pid.set(0));
    let result = original();
    AUTHORIZED_MSYS_FORK.with(|authorized| authorized.set(false));

    if result < 0 {
        let _ = crate::control::finish_fork_control(
            &context.endpoint,
            &context.session_id,
            &context.token,
            &context.lease_id,
            false,
        );
        return result;
    }
    if result == 0 {
        if crate::windows_gum::rebuild_after_msys_fork(&context.lease_id).is_err()
            && !fork_observe_mode()
        {
            windows_sys::Win32::System::Threading::ExitProcess(ERROR_ACCESS_DENIED);
        }
        return 0;
    }

    let child_pid = MSYS_FORK_WINDOWS_CHILD_PID
        .with(|captured| {
            let pid = captured.get();
            (pid != 0).then_some(pid)
        })
        .or_else(|| cygwin_pid_to_windows_pid(result));
    let Some(child_pid) = child_pid else {
        crate::report_child_injection_failure(
            context.parent_pid,
            0,
            None,
            "fork_pid_mapping",
            GetLastError(),
        );
        cancel_failed_fork(&context);
        return -1;
    };
    let executable = match std::env::current_exe() {
        Ok(path) => path.display().to_string(),
        Err(_) => {
            crate::report_child_injection_failure(
                context.parent_pid,
                child_pid,
                None,
                "fork_path_query",
                GetLastError(),
            );
            cancel_failed_fork(&context);
            return -1;
        }
    };
    if crate::control::register_fork_candidate_control(
        &context.endpoint,
        &context.session_id,
        &context.token,
        &context.lease_id,
        context.parent_pid,
        child_pid,
        &executable,
    )
    .is_err()
    {
        crate::report_child_injection_failure(
            context.parent_pid,
            child_pid,
            Some(&executable),
            "fork_candidate_registration",
            ERROR_ACCESS_DENIED,
        );
        cancel_failed_fork(&context);
        return -1;
    }
    if crate::windows_gum::capabilities::lifecycle::inject_fork_candidate(child_pid).is_err() {
        crate::report_child_injection_failure(
            context.parent_pid,
            child_pid,
            Some(&executable),
            "fork_agent_reload",
            GetLastError(),
        );
        cancel_failed_fork(&context);
        return -1;
    }
    for _ in 0..1000 {
        match crate::control::fork_status_control(
            &context.endpoint,
            &context.session_id,
            &context.token,
            &context.lease_id,
        ) {
            Ok(true) => {
                return if crate::control::finish_fork_control(
                    &context.endpoint,
                    &context.session_id,
                    &context.token,
                    &context.lease_id,
                    true,
                )
                .is_ok()
                {
                    result
                } else {
                    set_msys_errno_access_denied();
                    -1
                };
            }
            Ok(false) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(_) => break,
        }
    }
    if fork_observe_mode() {
        let _ = crate::control::finish_fork_control(
            &context.endpoint,
            &context.session_id,
            &context.token,
            &context.lease_id,
            false,
        );
        return result;
    }
    crate::report_child_injection_failure(
        context.parent_pid,
        child_pid,
        Some(&executable),
        "fork_attestation_wait",
        ERROR_ACCESS_DENIED,
    );
    cancel_failed_fork(&context);
    -1
}

fn begin_fork_context() -> Option<ForkControlContext> {
    let (endpoint, session_id, token) = {
        let runtime = crate::state().lock().ok()?;
        (
            runtime.session.control_endpoint.clone(),
            runtime.session.session_id.clone(),
            runtime.session.token.clone(),
        )
    };
    let parent_pid = unsafe { GetCurrentProcessId() };
    let lease_id =
        crate::control::begin_fork_control(&endpoint, &session_id, &token, parent_pid).ok()?;
    Some(ForkControlContext {
        endpoint,
        session_id,
        token,
        lease_id,
        parent_pid,
    })
}

fn cancel_failed_fork(context: &ForkControlContext) {
    let _ = crate::control::finish_fork_control(
        &context.endpoint,
        &context.session_id,
        &context.token,
        &context.lease_id,
        false,
    );
    unsafe { set_msys_errno_access_denied() };
}

unsafe fn cygwin_pid_to_windows_pid(pid: i32) -> Option<u32> {
    const CW_CYGWIN_PID_TO_WINPID: i32 = 17;
    let function = find_msys_runtime_export("cygwin_internal")?;
    let function = std::mem::transmute::<*mut c_void, CygwinInternalPidFn>(function);
    u32::try_from(function(CW_CYGWIN_PID_TO_WINPID, pid))
        .ok()
        .filter(|pid| *pid != 0)
}

unsafe fn set_msys_errno_access_denied() {
    const EACCES: i32 = 13;
    if let Some(function) = find_msys_runtime_export("__errno") {
        let function = std::mem::transmute::<*mut c_void, CygwinErrnoFn>(function);
        let errno = function();
        if !errno.is_null() {
            *errno = EACCES;
        }
    }
    SetLastError(ERROR_ACCESS_DENIED);
}

fn fork_observe_mode() -> bool {
    const NAME: [u16; 26] = [
        b'H' as u16,
        b'Y' as u16,
        b'P' as u16,
        b'E' as u16,
        b'R' as u16,
        b'H' as u16,
        b'U' as u16,
        b'B' as u16,
        b'_' as u16,
        b'E' as u16,
        b'N' as u16,
        b'F' as u16,
        b'O' as u16,
        b'R' as u16,
        b'C' as u16,
        b'E' as u16,
        b'M' as u16,
        b'E' as u16,
        b'N' as u16,
        b'T' as u16,
        b'_' as u16,
        b'M' as u16,
        b'O' as u16,
        b'D' as u16,
        b'E' as u16,
        0,
    ];
    let mut value = [0u16; 8];
    let length =
        unsafe { GetEnvironmentVariableW(NAME.as_ptr(), value.as_mut_ptr(), value.len() as u32) };
    length == 7
        && value[..7]
            .iter()
            .zip("observe".bytes())
            .all(|(actual, expected)| {
                *actual <= u16::from(u8::MAX) && (*actual as u8).to_ascii_lowercase() == expected
            })
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_create_process_w(
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u16,
    startup: *const STARTUPINFOW,
    information: *mut PROCESS_INFORMATION,
) -> i32 {
    let Some(original) = original!(ORIGINAL_CREATE_PROCESS_W, CreateProcessWFn) else {
        SetLastError(ERROR_DLL_INIT_FAILED);
        return 0;
    };
    if is_msys_fork_w(command_line, startup) {
        let _guard = HookGuard::enter();
        let result = original(
            application_name,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            creation_flags,
            environment,
            current_directory,
            startup,
            information,
        );
        remember_msys_fork_child_pid(result, information);
        return result;
    }
    intercept_child_creation(
        creation_flags,
        environment,
        information,
        executable_from_w(application_name, command_line),
        command_line_from_w(command_line),
        |context| {
            original(
                application_name,
                command_line,
                process_attributes,
                thread_attributes,
                inherit_handles,
                context.creation_flags,
                context.environment,
                current_directory,
                startup,
                context.information,
            )
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_create_process_a(
    application_name: *const u8,
    command_line: *mut u8,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u8,
    startup: *const STARTUPINFOA,
    information: *mut PROCESS_INFORMATION,
) -> i32 {
    let Some(original) = original!(ORIGINAL_CREATE_PROCESS_A, CreateProcessAFn) else {
        SetLastError(ERROR_DLL_INIT_FAILED);
        return 0;
    };
    intercept_child_creation(
        creation_flags,
        environment,
        information,
        executable_from_a(application_name, command_line),
        command_line_from_a(command_line),
        |context| {
            original(
                application_name,
                command_line,
                process_attributes,
                thread_attributes,
                inherit_handles,
                context.creation_flags,
                context.environment,
                current_directory,
                startup,
                context.information,
            )
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_create_process_internal_w(
    token: HANDLE,
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u16,
    startup: *const STARTUPINFOW,
    information: *mut PROCESS_INFORMATION,
    new_token: *mut HANDLE,
) -> i32 {
    let Some(original) = original!(ORIGINAL_CREATE_PROCESS_INTERNAL_W, CreateProcessInternalWFn)
    else {
        SetLastError(ERROR_DLL_INIT_FAILED);
        return 0;
    };
    if is_msys_fork_w(command_line, startup) {
        let _guard = HookGuard::enter();
        let result = original(
            token,
            application_name,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            creation_flags,
            environment,
            current_directory,
            startup,
            information,
            new_token,
        );
        remember_msys_fork_child_pid(result, information);
        return result;
    }
    intercept_child_creation(
        creation_flags,
        environment,
        information,
        executable_from_w(application_name, command_line),
        command_line_from_w(command_line),
        |context| {
            original(
                token,
                application_name,
                command_line,
                process_attributes,
                thread_attributes,
                inherit_handles,
                context.creation_flags,
                context.environment,
                current_directory,
                startup,
                context.information,
                new_token,
            )
        },
    )
}

unsafe fn remember_msys_fork_child_pid(result: i32, information: *mut PROCESS_INFORMATION) {
    if result != 0 && !information.is_null() {
        let pid = (*information).dwProcessId;
        if pid != 0 {
            MSYS_FORK_WINDOWS_CHILD_PID.with(|captured| captured.set(pid));
        }
    }
}

unsafe fn is_msys_fork_w(command_line: *const u16, startup: *const STARTUPINFOW) -> bool {
    if command_line.is_null() || startup.is_null() {
        return false;
    }
    let startup = &*startup;
    const MSYS_RUNTIME: [u16; 13] = [
        b'm' as u16,
        b's' as u16,
        b'y' as u16,
        b's' as u16,
        b'-' as u16,
        b'2' as u16,
        b'.' as u16,
        b'0' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    const CYGWIN_RUNTIME: [u16; 12] = [
        b'c' as u16,
        b'y' as u16,
        b'g' as u16,
        b'w' as u16,
        b'i' as u16,
        b'n' as u16,
        b'1' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    let runtime_loaded = !GetModuleHandleW(MSYS_RUNTIME.as_ptr()).is_null()
        || !GetModuleHandleW(CYGWIN_RUNTIME.as_ptr()).is_null();
    should_bypass_msys_fork(
        AUTHORIZED_MSYS_FORK.with(Cell::get),
        runtime_loaded,
        same_wide_string(command_line, GetCommandLineW()),
        is_msys_fork_context(startup),
    )
}

fn should_bypass_msys_fork(
    thread_authorized: bool,
    runtime_loaded: bool,
    command_line_matches: bool,
    valid_child_info: bool,
) -> bool {
    thread_authorized && runtime_loaded && command_line_matches && valid_child_info
}

unsafe fn same_wide_string(left: *const u16, right: *const u16) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    let mut offset = 0usize;
    loop {
        let left_value = *left.add(offset);
        let right_value = *right.add(offset);
        if left_value != right_value {
            return false;
        }
        if left_value == 0 {
            return true;
        }
        offset = offset.saturating_add(1);
    }
}

unsafe fn is_msys_fork_context(startup: &STARTUPINFOW) -> bool {
    const PROC_MAGIC_GENERIC: u32 = 0xaf00_fa64;
    const CHILD_INFO_FORK: u16 = 3;
    if startup.lpReserved2.is_null()
        || usize::from(startup.cbReserved2) < std::mem::size_of::<MsysChildInfoHeader>()
    {
        return false;
    }
    let header = startup
        .lpReserved2
        .cast::<MsysChildInfoHeader>()
        .read_unaligned();
    header.msv_count == 0
        && header.cb == u32::from(startup.cbReserved2)
        && header.intro == PROC_MAGIC_GENERIC
        && header.kind == CHILD_INFO_FORK
}

pub(in crate::windows_gum) unsafe fn is_current_process_msys_fork_bootstrap() -> bool {
    let mut startup: STARTUPINFOW = std::mem::zeroed();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    GetStartupInfoW(&mut startup);
    is_msys_fork_context(&startup)
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_create_process_internal_a(
    token: HANDLE,
    application_name: *const u8,
    command_line: *mut u8,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u8,
    startup: *const STARTUPINFOA,
    information: *mut PROCESS_INFORMATION,
    new_token: *mut HANDLE,
) -> i32 {
    let Some(original) = original!(ORIGINAL_CREATE_PROCESS_INTERNAL_A, CreateProcessInternalAFn)
    else {
        SetLastError(ERROR_DLL_INIT_FAILED);
        return 0;
    };
    intercept_child_creation(
        creation_flags,
        environment,
        information,
        executable_from_a(application_name, command_line),
        command_line_from_a(command_line),
        |context| {
            original(
                token,
                application_name,
                command_line,
                process_attributes,
                thread_attributes,
                inherit_handles,
                context.creation_flags,
                context.environment,
                current_directory,
                startup,
                context.information,
                new_token,
            )
        },
    )
}

unsafe fn executable_from_native(process_parameters: *const c_void) -> Option<String> {
    if process_parameters.is_null() {
        return None;
    }
    let parameters = &*process_parameters.cast::<RtlUserProcessParameters>();
    let name = &parameters.image_path_name;
    if name.buffer.is_null() || name.length == 0 || name.length % 2 != 0 {
        return None;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(
        name.buffer,
        usize::from(name.length / 2),
    )))
}

unsafe fn command_line_from_native(process_parameters: *const c_void) -> Option<String> {
    if process_parameters.is_null() {
        return None;
    }
    let parameters = &*process_parameters.cast::<RtlUserProcessParameters>();
    let value = &parameters._command_line;
    if value.buffer.is_null() {
        return None;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(
        value.buffer,
        usize::from(value.length / 2),
    )))
}
unsafe fn command_line_from_w(command_line: *mut u16) -> Option<String> {
    if command_line.is_null() {
        return None;
    }
    let mut len = 0;
    while *command_line.add(len) != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(
        command_line,
        len,
    )))
}
unsafe fn command_line_from_a(command_line: *mut u8) -> Option<String> {
    if command_line.is_null() {
        None
    } else {
        CStr::from_ptr(command_line.cast())
            .to_str()
            .ok()
            .map(str::to_owned)
    }
}

unsafe fn executable_from_w(
    application_name: *const u16,
    command_line: *mut u16,
) -> Option<String> {
    if !application_name.is_null() {
        let mut length = 0usize;
        while *application_name.add(length) != 0 {
            length += 1;
        }
        return Some(String::from_utf16_lossy(std::slice::from_raw_parts(
            application_name,
            length,
        )));
    }
    if command_line.is_null() {
        return None;
    }
    let mut length = 0usize;
    while *command_line.add(length) != 0 {
        length += 1;
    }
    let value = String::from_utf16_lossy(std::slice::from_raw_parts(command_line, length));
    first_command_line_token(&value)
}

unsafe fn executable_from_a(application_name: *const u8, command_line: *mut u8) -> Option<String> {
    if !application_name.is_null() {
        return CStr::from_ptr(application_name.cast())
            .to_str()
            .ok()
            .map(str::to_owned);
    }
    if command_line.is_null() {
        return None;
    }
    let value = CStr::from_ptr(command_line.cast()).to_str().ok()?;
    first_command_line_token(value)
}

fn first_command_line_token(value: &str) -> Option<String> {
    let value = value.trim_start();
    if let Some(value) = value.strip_prefix('"') {
        return Some(value.split('"').next()?.to_owned());
    }
    Some(value.split_whitespace().next()?.to_owned())
}

pub(in crate::windows_gum) unsafe fn intercept_child_creation(
    creation_flags: u32,
    environment: *const c_void,
    information: *mut PROCESS_INFORMATION,
    executable: Option<String>,
    command_line: Option<String>,
    call_original: impl FnOnce(&mut ChildProcessContext) -> i32,
) -> i32 {
    if information.is_null() || INSIDE_HOOK.with(Cell::get) {
        let mut context = ChildProcessContext::new(
            creation_flags,
            environment,
            information,
            executable.clone(),
            command_line.clone(),
        );
        return call_original(&mut context);
    }
    let Some(_guard) = HookGuard::enter() else {
        let mut context = ChildProcessContext::new(
            creation_flags,
            environment,
            information,
            executable.clone(),
            command_line.clone(),
        );
        return call_original(&mut context);
    };
    let mut context = ProcessCreateContext::Win32(ChildProcessContext::new(
        creation_flags,
        environment,
        information,
        executable,
        command_line,
    ));
    runtime().process_create.dispatch(
        &mut context,
        |context| {
            let ProcessCreateContext::Win32(context) = context else {
                unreachable!("Win32 child adapter changed context variant")
            };
            context.result = call_original(context);
            context.result
        },
        |context, current, _| {
            let ProcessCreateContext::Win32(context) = context else {
                unreachable!("Win32 child adapter changed context variant")
            };
            deny_child_process_callback(context, current.copied())
        },
    )
}

pub(in crate::windows_gum) unsafe fn deny_child_process_callback(
    context: &mut ChildProcessContext,
    current_result: Option<i32>,
) -> i32 {
    if current_result.is_some_and(|result| result != 0) && !context.information.is_null() {
        let information = &mut *context.information;
        if !information.hProcess.is_null() && !information.hThread.is_null() {
            return fail_created_child(information);
        }
    }
    SetLastError(ERROR_DLL_INIT_FAILED);
    0
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_nt_create_user_process(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
    process_access: u32,
    thread_access: u32,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    process_flags: u32,
    thread_flags: u32,
    process_parameters: *const c_void,
    create_info: *mut c_void,
    attribute_list: *const c_void,
) -> i32 {
    let Some(original) = original!(ORIGINAL_NT_CREATE_USER_PROCESS, NtCreateUserProcessFn) else {
        return STATUS_DLL_INIT_FAILED;
    };
    if process_handle.is_null() || thread_handle.is_null() || INSIDE_HOOK.with(Cell::get) {
        return original(
            process_handle,
            thread_handle,
            process_access,
            thread_access,
            process_attributes,
            thread_attributes,
            process_flags,
            thread_flags,
            process_parameters,
            create_info,
            attribute_list,
        );
    }
    let Some(_guard) = HookGuard::enter() else {
        return original(
            process_handle,
            thread_handle,
            process_access,
            thread_access,
            process_attributes,
            thread_attributes,
            process_flags,
            thread_flags,
            process_parameters,
            create_info,
            attribute_list,
        );
    };
    let mut context = ProcessCreateContext::Native(NativeChildProcessContext {
        process_handle,
        thread_handle,
        original_thread_flags: thread_flags,
        effective_thread_flags: thread_flags,
        result: STATUS_DLL_INIT_FAILED,
        executable: executable_from_native(process_parameters),
        command_line: command_line_from_native(process_parameters),
        should_hook: true,
        policy_version: 0,
        rule_id: None,
        decision_source: "unknown".into(),
    });
    runtime().process_create.dispatch(
        &mut context,
        |context| {
            let ProcessCreateContext::Native(context) = context else {
                unreachable!("native child adapter changed context variant")
            };
            context.result = original(
                context.process_handle,
                context.thread_handle,
                process_access,
                thread_access,
                process_attributes,
                thread_attributes,
                process_flags,
                context.effective_thread_flags,
                process_parameters,
                create_info,
                attribute_list,
            );
            context.result
        },
        |context, current, _| {
            let ProcessCreateContext::Native(context) = context else {
                unreachable!("native child adapter changed context variant")
            };
            deny_native_child_process_callback(context, current.copied())
        },
    )
}

pub(in crate::windows_gum) unsafe fn deny_native_child_process_callback(
    context: &mut NativeChildProcessContext,
    current_result: Option<i32>,
) -> i32 {
    if current_result.is_some_and(|result| result >= 0)
        && !context.process_handle.is_null()
        && !context.thread_handle.is_null()
        && !(*context.process_handle).is_null()
        && !(*context.thread_handle).is_null()
    {
        return fail_native_child(context.process_handle, context.thread_handle);
    }
    STATUS_DLL_INIT_FAILED
}

unsafe fn fail_native_child(process_handle: *mut HANDLE, thread_handle: *mut HANDLE) -> i32 {
    if !process_handle.is_null() && !(*process_handle).is_null() {
        TerminateProcess(*process_handle, ERROR_DLL_INIT_FAILED);
        CloseHandle(*process_handle);
        *process_handle = null_mut();
    }
    if !thread_handle.is_null() && !(*thread_handle).is_null() {
        CloseHandle(*thread_handle);
        *thread_handle = null_mut();
    }
    STATUS_DLL_INIT_FAILED
}

#[cfg(test)]
mod tests {
    use super::{is_msys_fork_context, should_bypass_msys_fork, MsysChildInfoHeader};
    use windows_sys::Win32::System::Threading::STARTUPINFOW;

    #[test]
    fn msys_fork_requires_the_fork_child_info_record() {
        fn startup_for(header: &mut MsysChildInfoHeader) -> STARTUPINFOW {
            let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
            startup.cbReserved2 = std::mem::size_of::<MsysChildInfoHeader>() as u16;
            startup.lpReserved2 = std::ptr::from_mut(header).cast();
            startup
        }

        let mut fork = MsysChildInfoHeader {
            msv_count: 0,
            cb: std::mem::size_of::<MsysChildInfoHeader>() as u32,
            intro: 0xaf00_fa64,
            _magic: 7,
            kind: 3,
        };
        assert!(unsafe { is_msys_fork_context(&startup_for(&mut fork)) });

        let mut spawn = MsysChildInfoHeader { kind: 2, ..fork };
        assert!(!unsafe { is_msys_fork_context(&startup_for(&mut spawn)) });
        let mut truncated = startup_for(&mut fork);
        truncated.cbReserved2 -= 1;
        assert!(!unsafe { is_msys_fork_context(&truncated) });
    }

    #[test]
    fn fork_bypass_requires_every_authorization_proof() {
        assert!(should_bypass_msys_fork(true, true, true, true));
        assert!(!should_bypass_msys_fork(false, true, true, true));
        assert!(!should_bypass_msys_fork(true, false, true, true));
        assert!(!should_bypass_msys_fork(true, true, false, true));
        assert!(!should_bypass_msys_fork(true, true, true, false));
    }
}

unsafe fn fail_created_child(information: &mut PROCESS_INFORMATION) -> i32 {
    TerminateProcess(information.hProcess, ERROR_DLL_INIT_FAILED);
    CloseHandle(information.hThread);
    CloseHandle(information.hProcess);
    *information = PROCESS_INFORMATION::default();
    SetLastError(ERROR_DLL_INIT_FAILED);
    0
}
