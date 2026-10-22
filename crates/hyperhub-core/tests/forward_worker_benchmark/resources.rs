use serde_json::{json, Value};
use std::io;

#[cfg(target_os = "linux")]
pub(super) fn sample(pid: u32) -> io::Result<Value> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let number = |key: &str| -> io::Result<u64> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| io::Error::other(format!("missing process resource {key}")))
    };
    Ok(json!({"pid":pid,"threads":number("Threads:")?,"rss_bytes":number("VmRSS:")?*1024}))
}

#[cfg(windows)]
pub(super) fn sample(pid: u32) -> io::Result<Value> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                THREADENTRY32,
            },
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        },
    };
    let raw = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of_val(&counters) as u32;
    if unsafe {
        GetProcessMemoryInfo(
            process.as_raw_handle().cast(),
            &mut counters,
            std::mem::size_of_val(&counters) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    let mut more = unsafe { Thread32First(snapshot.as_raw_handle().cast(), &mut entry) };
    let mut threads = 0;
    while more != 0 {
        if entry.th32OwnerProcessID == pid {
            threads += 1;
        }
        more = unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &mut entry) };
    }
    Ok(json!({"pid":pid,"threads":threads,"rss_bytes":counters.WorkingSetSize}))
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(super) fn sample(_pid: u32) -> io::Result<Value> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native worker resource benchmark requires Linux or Windows",
    ))
}
