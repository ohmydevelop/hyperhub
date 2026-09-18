use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::sync::atomic::Ordering;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_DLL_INIT_FAILED, ERROR_TIMEOUT, HANDLE, HMODULE,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_ACP};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleW, GetProcAddress,
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateRemoteThread, GetCurrentProcessId, GetExitCodeThread, GetProcessId,
    OpenProcess, QueryFullProcessImageNameW, ResumeThread, TerminateProcess, WaitForSingleObject,
    CREATE_UNICODE_ENVIRONMENT, INFINITE, PROCESS_CREATE_THREAD, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
};

use crate::windows_gum::gum::{AGENT_MODULE, CHILD_EVENT_ID};
use crate::windows_gum::THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
pub(super) unsafe fn finish_native_child_process(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
    original_thread_flags: u32,
    status: i32,
    policy_version: u64,
    rule_id: Option<&str>,
    decision_source: &str,
    expected_executable: Option<&str>,
) -> i32 {
    if status < 0 || (*process_handle).is_null() || (*thread_handle).is_null() {
        return status;
    }
    let process = *process_handle;
    let thread = *thread_handle;
    let child_pid = GetProcessId(process);
    let event_name = inherited_child_event_name(child_pid);
    let result = match create_child_event(&event_name) {
        Some(event) => {
            let result = inject_and_register_child(
                process,
                event,
                child_pid,
                policy_version,
                rule_id,
                decision_source,
            );
            CloseHandle(event);
            result
        }
        None => Err(ChildInjectionFailure::last_error("event_create")),
    };
    if result.is_ok() {
        if original_thread_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED == 0
            && ResumeThread(thread) == u32::MAX
        {
            report_child_failure(
                child_pid,
                expected_executable,
                ChildInjectionFailure::last_error("thread_resume"),
            );
            return fail_native_child(process_handle, thread_handle);
        }
        return status;
    }
    report_child_failure(child_pid, expected_executable, result.unwrap_err());
    if observe_child_failures() {
        if original_thread_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED == 0 {
            let _ = ResumeThread(thread);
        }
        status
    } else {
        fail_native_child(process_handle, thread_handle)
    }
}

pub(super) unsafe fn fail_native_child(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
) -> i32 {
    const STATUS_DLL_INIT_FAILED: i32 = 0xC000_0142u32 as i32;
    let process = *process_handle;
    let thread = *thread_handle;
    let _ = TerminateProcess(process, ERROR_DLL_INIT_FAILED);
    let _ = WaitForSingleObject(process, 5_000);
    CloseHandle(thread);
    CloseHandle(process);
    *thread_handle = null_mut();
    *process_handle = null_mut();
    STATUS_DLL_INIT_FAILED
}

pub(super) fn child_event_name() -> String {
    format!(
        "Local\\HyperHubChildReady-{}-{}",
        unsafe { GetCurrentProcessId() },
        CHILD_EVENT_ID.fetch_add(1, Ordering::Relaxed)
    )
}

pub(crate) fn inherited_child_event_name(pid: u32) -> String {
    format!("Local\\HyperHubInheritedReady-{pid}")
}

pub(crate) fn agent_module_path() -> Option<std::path::PathBuf> {
    let module = AGENT_MODULE.load(Ordering::Acquire) as HMODULE;
    if module.is_null() {
        return None;
    }
    let mut path = vec![0u16; 32_768];
    let length = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) };
    if length == 0 || length as usize >= path.len() {
        return None;
    }
    path.truncate(length as usize);
    Some(std::path::PathBuf::from(String::from_utf16_lossy(&path)))
}

pub(super) unsafe fn create_child_event(name: &str) -> Option<HANDLE> {
    let mut wide = OsStr::new(name).encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let event = CreateEventW(null(), 1, 0, wide.as_ptr());
    (!event.is_null()).then_some(event)
}

pub(super) fn observe_child_failures() -> bool {
    std::env::var("HYPERHUB_ENFORCEMENT_MODE")
        .is_ok_and(|value| value.eq_ignore_ascii_case("observe"))
}

pub(super) unsafe fn finish_child_process(
    information: *mut PROCESS_INFORMATION,
    ready_event: HANDLE,
    caller_requested_suspended: bool,
    policy_version: u64,
    rule_id: Option<&str>,
    decision_source: &str,
    expected_executable: Option<&str>,
) -> i32 {
    let information = &mut *information;
    let result = inject_and_register_child(
        information.hProcess,
        ready_event,
        information.dwProcessId,
        policy_version,
        rule_id,
        decision_source,
    );
    CloseHandle(ready_event);
    if result.is_ok() {
        if !caller_requested_suspended && ResumeThread(information.hThread) == u32::MAX {
            report_child_failure(
                information.dwProcessId,
                expected_executable,
                ChildInjectionFailure::last_error("thread_resume"),
            );
            return fail_created_child(information);
        }
        return 1;
    }
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
        let failure = result.as_ref().unwrap_err();
        eprintln!(
            "HyperHub: child setup failed for pid {} at {} (error {})",
            information.dwProcessId, failure.stage, failure.error_code,
        );
    }
    report_child_failure(
        information.dwProcessId,
        expected_executable,
        result.unwrap_err(),
    );
    if observe_child_failures() {
        if !caller_requested_suspended {
            let _ = ResumeThread(information.hThread);
        }
        1
    } else {
        fail_created_child(information)
    }
}

#[derive(Debug)]
struct ChildInjectionFailure {
    stage: &'static str,
    error_code: u32,
    executable: Option<String>,
}

impl ChildInjectionFailure {
    unsafe fn last_error(stage: &'static str) -> Self {
        let error_code = GetLastError();
        Self {
            stage,
            error_code: if error_code == 0 {
                ERROR_DLL_INIT_FAILED
            } else {
                error_code
            },
            executable: None,
        }
    }
}

unsafe fn inject_and_register_child(
    process: HANDLE,
    ready_event: HANDLE,
    child_pid: u32,
    policy_version: u64,
    rule_id: Option<&str>,
    decision_source: &str,
) -> Result<(), ChildInjectionFailure> {
    inject_child_agent(process).map_err(|()| ChildInjectionFailure::last_error("dll_injection"))?;
    if WaitForSingleObject(ready_event, 30_000) != WAIT_OBJECT_0 {
        return Err(ChildInjectionFailure {
            stage: "ready_wait",
            error_code: ERROR_TIMEOUT,
            executable: None,
        });
    }
    let executable = query_process_path(process)
        .map_err(|()| ChildInjectionFailure::last_error("path_query"))?;
    crate::register_child_control(
        GetCurrentProcessId(),
        child_pid,
        &executable,
        &crate::ProcessHookDecision {
            hook: true,
            rule_id: rule_id.map(str::to_owned),
            source: decision_source.to_owned(),
            version: policy_version,
        },
    )
    .map_err(|error_code| ChildInjectionFailure {
        stage: "session_registration",
        error_code: error_code as u32,
        executable: Some(executable),
    })
}

unsafe fn report_child_failure(
    child_pid: u32,
    expected_executable: Option<&str>,
    failure: ChildInjectionFailure,
) {
    crate::report_child_injection_failure(
        GetCurrentProcessId(),
        child_pid,
        failure.executable.as_deref().or(expected_executable),
        failure.stage,
        failure.error_code,
    );
}

pub(super) unsafe fn fail_created_child(information: &mut PROCESS_INFORMATION) -> i32 {
    let _ = TerminateProcess(information.hProcess, ERROR_DLL_INIT_FAILED);
    let _ = WaitForSingleObject(information.hProcess, 5_000);
    CloseHandle(information.hThread);
    CloseHandle(information.hProcess);
    *information = std::mem::zeroed();
    SetLastError(ERROR_DLL_INIT_FAILED);
    0
}

pub(super) unsafe fn inject_child_agent(process: HANDLE) -> Result<(), ()> {
    let path = std::env::var_os("HYPERHUB_AGENT_PATH").ok_or(())?;
    crate::integrity::verify_agent_runtime(std::path::Path::new(&path))?;
    let mut library = path.encode_wide().collect::<Vec<_>>();
    if library.is_empty() || library.contains(&0) {
        return Err(());
    }
    library.push(0);
    let bytes = library.len() * std::mem::size_of::<u16>();
    let remote = VirtualAllocEx(
        process,
        null(),
        bytes,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    );
    if remote.is_null() {
        return Err(());
    }
    let result = (|| {
        if WriteProcessMemory(process, remote, library.as_ptr().cast(), bytes, null_mut()) == 0 {
            return Err(());
        }
        let kernel = wide_null("kernel32.dll");
        let module = GetModuleHandleW(kernel.as_ptr());
        if module.is_null() {
            return Err(());
        }
        let load_library = GetProcAddress(module, b"LoadLibraryW\0".as_ptr()).ok_or(())?;
        let start = std::mem::transmute(load_library);
        let thread = CreateRemoteThread(process, null(), 0, Some(start), remote, 0, null_mut());
        if thread.is_null() {
            return Err(());
        }
        let wait = WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        (wait == WAIT_OBJECT_0).then_some(()).ok_or(())
    })();
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    result
}

pub(in crate::windows_gum) unsafe fn inject_fork_candidate(child_pid: u32) -> Result<(), ()> {
    let process = OpenProcess(
        PROCESS_CREATE_THREAD
            | PROCESS_QUERY_LIMITED_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE,
        0,
        child_pid,
    );
    if process.is_null() {
        return Err(());
    }
    let result = (|| {
        inject_child_agent(process)?;
        let thread = CreateRemoteThread(
            process,
            null(),
            0,
            Some(crate::windows_gum::hyperhub_agent_postfork_start),
            null_mut(),
            0,
            null_mut(),
        );
        if thread.is_null() {
            return Err(());
        }
        let wait = WaitForSingleObject(thread, 10_000);
        let mut exit_code = ERROR_DLL_INIT_FAILED;
        let queried = GetExitCodeThread(thread, &mut exit_code);
        CloseHandle(thread);
        (wait == WAIT_OBJECT_0 && queried != 0 && exit_code == 0)
            .then_some(())
            .ok_or(())
    })();
    CloseHandle(process);
    result
}

pub(super) unsafe fn query_process_path(process: HANDLE) -> Result<String, ()> {
    let mut path = vec![0u16; 32_768];
    let mut length = path.len() as u32;
    if QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut length) == 0 {
        return Err(());
    }
    path.truncate(length as usize);
    Ok(String::from_utf16_lossy(&path))
}

pub(super) fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

pub(super) unsafe fn build_child_environment(
    environment: *const c_void,
    creation_flags: u32,
    event_name: &str,
) -> Result<Vec<u16>, ()> {
    let mut variables = BTreeMap::<String, Vec<u16>>::new();
    let entries = if environment.is_null() {
        std::env::vars_os()
            .map(|(key, value)| {
                let mut entry = key.encode_wide().collect::<Vec<_>>();
                entry.push('=' as u16);
                entry.extend(value.encode_wide());
                entry
            })
            .collect()
    } else if creation_flags & CREATE_UNICODE_ENVIRONMENT != 0 {
        read_wide_environment(environment.cast())?
    } else {
        read_ansi_environment(environment.cast())?
    };
    for entry in entries {
        insert_environment_entry(&mut variables, entry);
    }
    for key in [
        "HYPERHUB_SESSION_ID",
        "HYPERHUB_SESSION_TOKEN",
        "HYPERHUB_SOCKS_ADDR",
        "HYPERHUB_CONTROL_ENDPOINT",
        "HYPERHUB_ENFORCEMENT_MODE",
        "HYPERHUB_AGENT_PATH",
    ] {
        let value = std::env::var_os(key).ok_or(())?;
        insert_environment_value(&mut variables, key, &value);
    }
    let hash = std::env::var_os("HYPERHUB_AGENT_SHA256");
    let size = std::env::var_os("HYPERHUB_AGENT_SIZE");
    insert_agent_integrity_environment(&mut variables, hash.as_deref(), size.as_deref())?;
    if let Some(keys) = std::env::var_os("HYPERHUB_SESSION_ENV_KEYS") {
        insert_environment_value(&mut variables, "HYPERHUB_SESSION_ENV_KEYS", &keys);
        let keys = serde_json::from_str::<Vec<String>>(&keys.to_string_lossy()).map_err(|_| ())?;
        for key in keys {
            if key.to_ascii_uppercase().starts_with("HYPERHUB_") {
                return Err(());
            }
            let value = std::env::var_os(&key).ok_or(())?;
            insert_environment_value(&mut variables, &key, &value);
        }
    }
    insert_environment_value(
        &mut variables,
        "HYPERHUB_LOADED_EVENT",
        OsStr::new(event_name),
    );
    insert_environment_value(
        &mut variables,
        "HYPERHUB_READY_EVENT",
        OsStr::new(event_name),
    );
    variables.remove("HYPERHUB_CONFIG_PASSWORD");
    let mut block = Vec::new();
    for entry in variables.into_values() {
        block.extend(entry);
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

pub(super) unsafe fn read_wide_environment(pointer: *const u16) -> Result<Vec<Vec<u16>>, ()> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < 4 * 1024 * 1024 {
        if *pointer.add(offset) == 0 {
            return Ok(entries);
        }
        let start = offset;
        while offset < 4 * 1024 * 1024 && *pointer.add(offset) != 0 {
            offset += 1;
        }
        if offset >= 4 * 1024 * 1024 {
            return Err(());
        }
        entries.push(std::slice::from_raw_parts(pointer.add(start), offset - start).to_vec());
        offset += 1;
    }
    Err(())
}

pub(super) unsafe fn read_ansi_environment(pointer: *const u8) -> Result<Vec<Vec<u16>>, ()> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < 4 * 1024 * 1024 {
        if *pointer.add(offset) == 0 {
            return Ok(entries);
        }
        let start = offset;
        while offset < 4 * 1024 * 1024 && *pointer.add(offset) != 0 {
            offset += 1;
        }
        if offset >= 4 * 1024 * 1024 {
            return Err(());
        }
        let bytes = std::slice::from_raw_parts(pointer.add(start), offset - start);
        let length = i32::try_from(bytes.len()).map_err(|_| ())?;
        let required = MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), length, null_mut(), 0);
        if required <= 0 {
            return Err(());
        }
        let mut value = vec![0u16; required as usize];
        if MultiByteToWideChar(
            CP_ACP,
            0,
            bytes.as_ptr(),
            length,
            value.as_mut_ptr(),
            required,
        ) != required
        {
            return Err(());
        }
        entries.push(value);
        offset += 1;
    }
    Err(())
}

fn insert_agent_integrity_environment(
    variables: &mut BTreeMap<String, Vec<u16>>,
    hash: Option<&OsStr>,
    size: Option<&OsStr>,
) -> Result<(), ()> {
    match (hash, size) {
        (Some(hash), Some(size)) => {
            insert_environment_value(variables, "HYPERHUB_AGENT_SHA256", hash);
            insert_environment_value(variables, "HYPERHUB_AGENT_SIZE", size);
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(()),
    }
}

pub(super) fn insert_environment_value(
    variables: &mut BTreeMap<String, Vec<u16>>,
    key: &str,
    value: &OsStr,
) {
    let mut entry = OsStr::new(key).encode_wide().collect::<Vec<_>>();
    entry.push('=' as u16);
    entry.extend(value.encode_wide());
    variables.insert(key.to_ascii_uppercase(), entry);
}

pub(super) fn insert_environment_entry(
    variables: &mut BTreeMap<String, Vec<u16>>,
    entry: Vec<u16>,
) {
    let start = usize::from(entry.first() == Some(&('=' as u16)));
    let Some(separator) = entry
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, value)| (*value == '=' as u16).then_some(index))
    else {
        return;
    };
    let key = String::from_utf16_lossy(&entry[..separator]).to_uppercase();
    if !key.is_empty() {
        variables.insert(key, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_environment_is_optional_but_atomic() {
        let mut values = BTreeMap::new();
        assert!(insert_agent_integrity_environment(&mut values, None, None).is_ok());
        assert!(values.is_empty());

        assert!(insert_agent_integrity_environment(
            &mut values,
            Some(OsStr::new("00")),
            Some(OsStr::new("1")),
        )
        .is_ok());
        assert!(values.contains_key("HYPERHUB_AGENT_SHA256"));
        assert!(values.contains_key("HYPERHUB_AGENT_SIZE"));

        assert!(insert_agent_integrity_environment(
            &mut BTreeMap::new(),
            Some(OsStr::new("00")),
            None,
        )
        .is_err());
    }
}
