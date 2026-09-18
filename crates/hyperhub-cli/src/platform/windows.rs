use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::io::IsTerminal;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_C_EVENT};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateProcessW, CreateRemoteThread, GetExitCodeProcess, ResumeThread,
    TerminateProcess, WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, INFINITE,
    PROCESS_INFORMATION, STARTUPINFOW,
};

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
const IMAGE_GUARD_XFG_ENABLED: u32 = 0x0080_0000;
const PE64_DATA_DIRECTORIES_OFFSET: usize = 0x70;
const PE64_NUMBER_OF_RVA_AND_SIZES_OFFSET: usize = 0x6c;
const PE64_DLL_CHARACTERISTICS_OFFSET: usize = 0x46;
const PE64_SIZE_OF_HEADERS_OFFSET: usize = 0x3c;
const IMAGE_SECTION_HEADER_SIZE: usize = 40;
const LOAD_CONFIG_GUARD_FLAGS_OFFSET: usize = 144;

fn should_ignore_console_event(ctrl_type: u32) -> bool {
    ctrl_type == CTRL_C_EVENT
}

unsafe extern "system" fn ignore_ctrl_c_event(ctrl_type: u32) -> i32 {
    should_ignore_console_event(ctrl_type) as i32
}

struct ConsoleCtrlCGuard {
    installed: bool,
}

impl ConsoleCtrlCGuard {
    unsafe fn install() -> Result<Self, String> {
        if !std::io::stdin().is_terminal() {
            return Ok(Self { installed: false });
        }
        if SetConsoleCtrlHandler(Some(ignore_ctrl_c_event), 1) == 0 {
            return Err(last_error("cannot install the parent Ctrl+C handler"));
        }
        Ok(Self { installed: true })
    }
}

impl Drop for ConsoleCtrlCGuard {
    fn drop(&mut self) {
        if self.installed {
            unsafe {
                SetConsoleCtrlHandler(Some(ignore_ctrl_c_event), 0);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeCapabilities {
    cfg: bool,
    xfg: bool,
}

pub fn doctor_target(target: &Path) -> Result<String, String> {
    let data = std::fs::read(target)
        .map_err(|error| format!("cannot read target {}: {error}", target.display()))?;
    let capabilities = inspect_pe(&data)?;
    let rustls = contains_ascii(&data, b"rustls");
    let ssl_cert_file = contains_ascii(&data, b"SSL_CERT_FILE");
    Ok(format!(
        "pe=x64 cfg={} xfg={} gum_agent=supported selected_backend=gum rustls={} ssl_cert_file={}",
        capabilities.cfg, capabilities.xfg, rustls, ssl_cert_file
    ))
}

fn contains_ascii(data: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && data.windows(needle.len()).any(|window| window == needle)
}

pub fn validate_target_runtime(target: &Path, runtime: &Path) -> Result<(), String> {
    let data = std::fs::read(target)
        .map_err(|error| format!("cannot read target {}: {error}", target.display()))?;
    let capabilities = inspect_pe(&data)?;
    validate_backend(capabilities, runtime)
}

fn inspect_pe(data: &[u8]) -> Result<PeCapabilities, String> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Err("target is not a PE executable".into());
    }
    let offset = read_u32(data, 0x3c)? as usize;
    if offset.checked_add(24).is_none_or(|end| end > data.len())
        || &data[offset..offset + 4] != b"PE\0\0"
    {
        return Err("target has an invalid PE header".into());
    }
    let machine = read_u16(data, offset + 4)?;
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(format!(
            "unsupported PE machine 0x{machine:04x}; Windows currently requires x64"
        ));
    }
    let section_count = read_u16(data, offset + 6)? as usize;
    let optional_size = read_u16(data, offset + 20)? as usize;
    let optional = offset + 24;
    let optional_end = optional
        .checked_add(optional_size)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| "target has a truncated PE optional header".to_string())?;
    if optional_size <= PE64_DLL_CHARACTERISTICS_OFFSET + 1
        || read_u16(data, optional)? != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    {
        return Err("target is not a valid PE32+ executable".into());
    }
    let dll_characteristics = read_u16(data, optional + PE64_DLL_CHARACTERISTICS_OFFSET)?;
    let cfg = dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0;
    let section_table = optional_end;
    let _section_end = section_count
        .checked_mul(IMAGE_SECTION_HEADER_SIZE)
        .and_then(|size| section_table.checked_add(size))
        .filter(|end| *end <= data.len())
        .ok_or_else(|| "target has a truncated PE section table".to_string())?;

    let xfg = load_config_guard_flags(data, optional, optional_size, section_table, section_count)?
        .is_some_and(|flags| flags & IMAGE_GUARD_XFG_ENABLED != 0);
    Ok(PeCapabilities { cfg, xfg })
}

fn load_config_guard_flags(
    data: &[u8],
    optional: usize,
    optional_size: usize,
    section_table: usize,
    section_count: usize,
) -> Result<Option<u32>, String> {
    if optional_size < PE64_DATA_DIRECTORIES_OFFSET
        || read_u32(data, optional + PE64_NUMBER_OF_RVA_AND_SIZES_OFFSET)? as usize
            <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
    {
        return Ok(None);
    }
    let directory = optional
        + PE64_DATA_DIRECTORIES_OFFSET
        + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * std::mem::size_of::<u64>();
    if directory + 8 > optional + optional_size {
        return Ok(None);
    }
    let rva = read_u32(data, directory)?;
    let directory_size = read_u32(data, directory + 4)? as usize;
    if rva == 0 || directory_size <= LOAD_CONFIG_GUARD_FLAGS_OFFSET + 3 {
        return Ok(None);
    }
    let size_of_headers = read_u32(data, optional + PE64_SIZE_OF_HEADERS_OFFSET)?;
    let Some(load_config) =
        rva_to_file_offset(data, rva, size_of_headers, section_table, section_count)?
    else {
        return Ok(None);
    };
    let declared_size = read_u32(data, load_config)? as usize;
    if declared_size <= LOAD_CONFIG_GUARD_FLAGS_OFFSET + 3 {
        return Ok(None);
    }
    Ok(Some(read_u32(
        data,
        load_config + LOAD_CONFIG_GUARD_FLAGS_OFFSET,
    )?))
}

fn rva_to_file_offset(
    data: &[u8],
    rva: u32,
    size_of_headers: u32,
    section_table: usize,
    section_count: usize,
) -> Result<Option<usize>, String> {
    if rva < size_of_headers {
        let offset = rva as usize;
        return Ok((offset < data.len()).then_some(offset));
    }
    for index in 0..section_count {
        let section = section_table + index * IMAGE_SECTION_HEADER_SIZE;
        let virtual_size = read_u32(data, section + 8)?;
        let virtual_address = read_u32(data, section + 12)?;
        let raw_size = read_u32(data, section + 16)?;
        let raw_offset = read_u32(data, section + 20)?;
        let span = virtual_size.max(raw_size);
        let Some(delta) = rva.checked_sub(virtual_address) else {
            continue;
        };
        if delta >= span || delta >= raw_size {
            continue;
        }
        let offset = raw_offset as usize + delta as usize;
        return Ok((offset < data.len()).then_some(offset));
    }
    Ok(None)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| "target has an invalid PE offset".to_string())?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| "target has a truncated PE structure".to_string())?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "target has an invalid PE offset".to_string())?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| "target has a truncated PE structure".to_string())?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn validate_backend(_capabilities: PeCapabilities, runtime: &Path) -> Result<(), String> {
    let is_gum = runtime
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("hyperhub_gum_agent.dll"));
    if !is_gum {
        return Err("unknown Windows agent runtime; expected hyperhub_gum_agent.dll".into());
    }
    Ok(())
}

pub fn run_injected<F>(
    target: &OsString,
    _argv0: &OsString,
    args: &[OsString],
    runtime: Option<&Path>,
    env: &[(OsString, OsString)],
    activate: F,
) -> Result<i32, String>
where
    F: FnOnce(u32, &OsStr) -> Result<bool, String>,
{
    let runtime = runtime.ok_or_else(|| {
        "Windows requires hyperhub_gum_agent.dll next to hyperhub or --runtime".to_string()
    })?;
    let runtime = runtime.canonicalize().map_err(|error| {
        format!(
            "cannot resolve agent runtime {}: {error}",
            runtime.display()
        )
    })?;
    validate_target_runtime(Path::new(target), &runtime)?;
    let runtime_directory = runtime
        .parent()
        .ok_or_else(|| "agent runtime path has no parent directory".to_string())?;
    let session_id = env
        .iter()
        .find(|(key, _)| {
            key.to_string_lossy()
                .eq_ignore_ascii_case("HYPERHUB_SESSION_ID")
        })
        .map(|(_, value)| value.to_string_lossy().into_owned())
        .ok_or_else(|| "run session ID is missing".to_string())?;
    let mut overrides = env.to_vec();
    let mut search_path = OsString::from(runtime_directory.as_os_str());
    if let Some(existing) = std::env::var_os("PATH") {
        search_path.push(";");
        search_path.push(existing);
    }
    overrides.push((OsString::from("PATH"), search_path));
    let ready_event_name = format!("Local\\HyperHubReady-{session_id}");
    let ready_event_name_wide = wide_null(OsStr::new(&ready_event_name))?;
    let ready_event = unsafe {
        let handle = CreateEventW(null(), 1, 0, ready_event_name_wide.as_ptr());
        if handle.is_null() {
            return Err(last_error("cannot create Gum Agent ready event"));
        }
        OwnedHandle(handle)
    };
    let loaded_event_name = format!("Local\\HyperHubLoaded-{session_id}");
    let loaded_event_name_wide = wide_null(OsStr::new(&loaded_event_name))?;
    let loaded_event = unsafe {
        let handle = CreateEventW(null(), 1, 0, loaded_event_name_wide.as_ptr());
        if handle.is_null() {
            return Err(last_error("cannot create Gum Agent loaded event"));
        }
        OwnedHandle(handle)
    };
    overrides.push((
        OsString::from("HYPERHUB_LOADED_EVENT"),
        OsString::from(loaded_event_name),
    ));
    overrides.push((
        OsString::from("HYPERHUB_READY_EVENT"),
        OsString::from(ready_event_name),
    ));
    overrides.push((
        OsString::from("HYPERHUB_AGENT_PATH"),
        runtime.as_os_str().to_owned(),
    ));

    let result = unsafe {
        launch_suspended_and_inject(
            target,
            args,
            &runtime,
            &overrides,
            loaded_event.0,
            ready_event.0,
            activate,
        )
    };
    result
}

unsafe fn launch_suspended_and_inject<F>(
    target: &OsStr,
    args: &[OsString],
    runtime: &Path,
    env: &[(OsString, OsString)],
    loaded_event: HANDLE,
    ready_event: HANDLE,
    activate: F,
) -> Result<i32, String>
where
    F: FnOnce(u32, &OsStr) -> Result<bool, String>,
{
    let target_wide = wide_null(target)?;
    let mut command_line = build_command_line(target, args)?;
    let mut environment = build_environment_block(env)?;
    let mut startup: STARTUPINFOW = std::mem::zeroed();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut info: PROCESS_INFORMATION = std::mem::zeroed();

    let created = CreateProcessW(
        target_wide.as_ptr(),
        command_line.as_mut_ptr(),
        null(),
        null(),
        1,
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        environment.as_mut_ptr().cast::<c_void>(),
        null(),
        &startup,
        &mut info,
    );
    if created == 0 {
        return Err(last_error("cannot create suspended target process"));
    }
    let mut process = SuspendedProcess::new(info.hProcess, info.hThread);
    let _ctrl_c_guard = ConsoleCtrlCGuard::install()?;

    let should_inject = activate(info.dwProcessId, target)?;
    if !should_inject {
        if ResumeThread(process.thread.0) == u32::MAX {
            return Err(last_error("cannot resume target main thread"));
        }
        process.resumed = true;
        if WaitForSingleObject(process.process.0, INFINITE) == WAIT_FAILED {
            return Err(last_error("waiting for target process failed"));
        }
        let mut status = 0u32;
        if GetExitCodeProcess(process.process.0, &mut status) == 0 {
            return Err(last_error("cannot read target exit status"));
        }
        process.finished = true;
        return Ok(status as i32);
    }

    let library = wide_null(runtime.as_os_str())?;
    let byte_count = library.len() * std::mem::size_of::<u16>();
    let remote = VirtualAllocEx(
        process.process.0,
        null(),
        byte_count,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    );
    if remote.is_null() {
        return Err(last_error("cannot allocate agent path in target process"));
    }
    let remote = RemoteMemory {
        process: process.process.0,
        address: remote,
    };
    if WriteProcessMemory(
        process.process.0,
        remote.address,
        library.as_ptr().cast::<c_void>(),
        byte_count,
        null_mut(),
    ) == 0
    {
        return Err(last_error("cannot write agent path into target process"));
    }

    let kernel32 = wide_null(OsStr::new("kernel32.dll"))?;
    let kernel = GetModuleHandleW(kernel32.as_ptr());
    if kernel.is_null() {
        return Err(last_error("cannot locate kernel32.dll"));
    }
    let load_library = GetProcAddress(kernel, b"LoadLibraryW\0".as_ptr());
    let Some(load_library) = load_library else {
        return Err(last_error("cannot locate LoadLibraryW"));
    };
    let start_routine = std::mem::transmute(load_library);
    let remote_thread = CreateRemoteThread(
        process.process.0,
        null(),
        0,
        Some(start_routine),
        remote.address,
        0,
        null_mut(),
    );
    if remote_thread.is_null() {
        return Err(last_error("cannot start agent loader in target process"));
    }
    let remote_thread = OwnedHandle(remote_thread);
    if WaitForSingleObject(remote_thread.0, INFINITE) == WAIT_FAILED {
        return Err(last_error("waiting for agent loader failed"));
    }
    match WaitForSingleObject(loaded_event, 5_000) {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => {
            return Err("agent DLL did not report initialization before timeout".into());
        }
        WAIT_FAILED => return Err(last_error("waiting for Gum Agent loaded event failed")),
        status => return Err(format!("unexpected Gum Agent loaded wait status {status}")),
    }
    drop(remote);
    drop(remote_thread);

    if ResumeThread(process.thread.0) == u32::MAX {
        return Err(last_error("cannot resume target main thread"));
    }
    process.resumed = true;
    match WaitForSingleObject(ready_event, 30_000) {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => return Err("timed out waiting for Gum Agent hooks to become ready".into()),
        WAIT_FAILED => return Err(last_error("waiting for Gum Agent ready event failed")),
        status => return Err(format!("unexpected Gum Agent ready wait status {status}")),
    }
    if WaitForSingleObject(process.process.0, INFINITE) == WAIT_FAILED {
        return Err(last_error("waiting for target process failed"));
    }
    let mut status = 0u32;
    if GetExitCodeProcess(process.process.0, &mut status) == 0 {
        return Err(last_error("cannot read target exit status"));
    }
    process.finished = true;
    Ok(status as i32)
}

fn build_command_line(target: &OsStr, args: &[OsString]) -> Result<Vec<u16>, String> {
    let mut command = Vec::new();
    append_quoted_argument(&mut command, target)?;
    for argument in args {
        command.push(' ' as u16);
        append_quoted_argument(&mut command, argument)?;
    }
    command.push(0);
    Ok(command)
}

fn append_quoted_argument(output: &mut Vec<u16>, argument: &OsStr) -> Result<(), String> {
    let units: Vec<u16> = argument.encode_wide().collect();
    if units.contains(&0) {
        return Err("target arguments cannot contain NUL characters".into());
    }
    let needs_quotes = units.is_empty()
        || units
            .iter()
            .any(|unit| matches!(*unit, 0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x22));
    if !needs_quotes {
        output.extend_from_slice(&units);
        return Ok(());
    }
    output.push('"' as u16);
    let mut backslashes = 0usize;
    for unit in units {
        if unit == '\\' as u16 {
            backslashes += 1;
        } else if unit == '"' as u16 {
            output.extend(std::iter::repeat_n('\\' as u16, backslashes * 2 + 1));
            output.push(unit);
            backslashes = 0;
        } else {
            output.extend(std::iter::repeat_n('\\' as u16, backslashes));
            output.push(unit);
            backslashes = 0;
        }
    }
    output.extend(std::iter::repeat_n('\\' as u16, backslashes * 2));
    output.push('"' as u16);
    Ok(())
}

fn build_environment_block(overrides: &[(OsString, OsString)]) -> Result<Vec<u16>, String> {
    let mut variables: BTreeMap<String, (OsString, OsString)> = BTreeMap::new();
    for (key, value) in std::env::vars_os().chain(overrides.iter().cloned()) {
        let normalized = key.to_string_lossy().to_uppercase();
        if normalized == "HYPERHUB_CONFIG_PASSWORD" || normalized.starts_with('=') {
            // `=C:` 等是 Windows 隐藏的驱动器当前目录变量，不属于子进程环境。
            continue;
        }
        variables.insert(normalized, (key, value));
    }
    let mut block = Vec::new();
    for (_, (key, value)) in variables {
        let key: Vec<u16> = key.encode_wide().collect();
        let value: Vec<u16> = value.encode_wide().collect();
        if key.is_empty() || key.contains(&0) || key.contains(&('=' as u16)) || value.contains(&0) {
            return Err("target environment contains an invalid name or NUL character".into());
        }
        block.extend(key);
        block.push('=' as u16);
        block.extend(value);
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn wide_null(value: &OsStr) -> Result<Vec<u16>, String> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err("Windows path contains a NUL character".into());
    }
    wide.push(0);
    Ok(wide)
}

fn last_error(operation: &str) -> String {
    let code = unsafe { GetLastError() };
    format!(
        "{operation}: {} (Windows error {code})",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct SuspendedProcess {
    process: OwnedHandle,
    thread: OwnedHandle,
    resumed: bool,
    finished: bool,
}

impl SuspendedProcess {
    fn new(process: HANDLE, thread: HANDLE) -> Self {
        Self {
            process: OwnedHandle(process),
            thread: OwnedHandle(thread),
            resumed: false,
            finished: false,
        }
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if !self.finished {
            unsafe {
                TerminateProcess(self.process.0, 1);
                if self.resumed {
                    WaitForSingleObject(self.process.0, 5_000);
                }
            }
        }
    }
}

struct RemoteMemory {
    process: HANDLE,
    address: *mut c_void,
}

impl Drop for RemoteMemory {
    fn drop(&mut self) {
        unsafe {
            VirtualFreeEx(self.process, self.address, 0, MEM_RELEASE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn pe64(cfg: bool, xfg: bool) -> Vec<u8> {
        let mut data = vec![0_u8; 0x400];
        let pe = 0x80;
        let optional = pe + 24;
        let optional_size = 0xf0;
        let section = optional + optional_size;
        data[..2].copy_from_slice(b"MZ");
        write_u32(&mut data, 0x3c, pe as u32);
        data[pe..pe + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut data, pe + 4, IMAGE_FILE_MACHINE_AMD64);
        write_u16(&mut data, pe + 6, 1);
        write_u16(&mut data, pe + 20, optional_size as u16);
        write_u16(&mut data, optional, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        write_u32(&mut data, optional + PE64_SIZE_OF_HEADERS_OFFSET, 0x200);
        write_u16(
            &mut data,
            optional + PE64_DLL_CHARACTERISTICS_OFFSET,
            if cfg {
                IMAGE_DLLCHARACTERISTICS_GUARD_CF
            } else {
                0
            },
        );
        write_u32(
            &mut data,
            optional + PE64_NUMBER_OF_RVA_AND_SIZES_OFFSET,
            16,
        );
        let load_config_directory = optional
            + PE64_DATA_DIRECTORIES_OFFSET
            + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * std::mem::size_of::<u64>();
        write_u32(&mut data, load_config_directory, 0x1000);
        write_u32(&mut data, load_config_directory + 4, 0x100);
        write_u32(&mut data, section + 8, 0x200);
        write_u32(&mut data, section + 12, 0x1000);
        write_u32(&mut data, section + 16, 0x200);
        write_u32(&mut data, section + 20, 0x200);
        write_u32(&mut data, 0x200, 0x100);
        write_u32(
            &mut data,
            0x200 + LOAD_CONFIG_GUARD_FLAGS_OFFSET,
            if xfg { IMAGE_GUARD_XFG_ENABLED } else { 0 },
        );
        data
    }

    fn rendered(value: &OsStr) -> String {
        let mut output = Vec::new();
        append_quoted_argument(&mut output, value).unwrap();
        String::from_utf16(&output).unwrap()
    }

    #[test]
    fn quotes_windows_arguments() {
        assert_eq!(rendered(OsStr::new("plain")), "plain");
        assert_eq!(rendered(OsStr::new("")), "\"\"");
        assert_eq!(rendered(OsStr::new("two words")), "\"two words\"");
        assert_eq!(rendered(OsStr::new("a\\\"b")), "\"a\\\\\\\"b\"");
        assert_eq!(
            rendered(OsStr::new("path with space\\")),
            "\"path with space\\\\\""
        );
    }

    #[test]
    fn reports_cfg_without_assuming_xfg() {
        assert_eq!(
            inspect_pe(&pe64(true, false)).unwrap(),
            PeCapabilities {
                cfg: true,
                xfg: false
            }
        );
    }

    #[test]
    fn reads_xfg_from_the_load_config_directory() {
        assert_eq!(
            inspect_pe(&pe64(true, true)).unwrap(),
            PeCapabilities {
                cfg: true,
                xfg: true
            }
        );
    }

    #[test]
    fn rejects_legacy_agent_names() {
        let capabilities = inspect_pe(&pe64(true, false)).unwrap();
        let error = validate_backend(capabilities, Path::new("legacy_agent.dll")).unwrap_err();
        assert!(error.contains("hyperhub_gum_agent.dll"));
    }

    #[test]
    fn gum_backend_supports_cfg_targets() {
        let capabilities = inspect_pe(&pe64(true, true)).unwrap();
        assert!(validate_backend(capabilities, Path::new("hyperhub_gum_agent.dll")).is_ok());
    }

    #[test]
    fn ignores_only_ctrl_c_console_events() {
        assert!(should_ignore_console_event(CTRL_C_EVENT));
        assert!(!should_ignore_console_event(
            windows_sys::Win32::System::Console::CTRL_BREAK_EVENT
        ));
        assert!(!should_ignore_console_event(
            windows_sys::Win32::System::Console::CTRL_CLOSE_EVENT
        ));
    }

    #[test]
    fn environment_block_skips_windows_hidden_drive_variables() {
        let block = build_environment_block(&[]).expect("hidden =drive variables must be skipped");
        assert_eq!(block.last(), Some(&0));
        let text = String::from_utf16_lossy(&block);
        assert!(!text.contains("=C:=C:"));
        assert!(!text.contains("=D:=D:"));
    }
}
