//! Native Windows loader for non-owning, approved process attachment.
//! No process termination, environment mutation or console operations occur here.
use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::{
        Diagnostics::{
            Debug::{
                FlushInstructionCache, GetThreadContext, ReadProcessMemory, SetThreadContext,
                WriteProcessMemory, CONTEXT, CONTEXT_CONTROL_AMD64,
            },
            ToolHelp::{
                CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
                TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
            },
        },
        LibraryLoader::{
            GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress,
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        },
        Memory::{
            VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx,
            MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_RELEASE, MEM_RESERVE,
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            PAGE_GUARD, PAGE_READWRITE,
        },
        Threading::{
            CreateRemoteThread, GetCurrentProcess, GetExitCodeThread, ResumeThread, SuspendThread,
            WaitForSingleObject, INFINITE,
        },
    },
};

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const STARTUP_GATE_BYTES: [u8; 2] = [0xeb, 0xfe];
const STARTUP_RELEASE_COUNTS: [u32; 3] = [1, 2, 1];

#[repr(C)]
struct ProcessBasicInformation {
    reserved1: *mut c_void,
    peb_base_address: *mut c_void,
    reserved2: [*mut c_void; 2],
    unique_process_id: usize,
    reserved3: *mut c_void,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: u32,
        information: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}
#[derive(Clone, Debug)]
pub struct Module {
    pub base: usize,
    pub size: usize,
    pub path: PathBuf,
    pub name: String,
}
fn error(message: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{message}: {e}"))
}
fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "module path contains NUL",
        ));
    }
    value.push(0);
    Ok(value)
}
fn text(value: &[u16]) -> String {
    String::from_utf16_lossy(&value[..value.iter().position(|c| *c == 0).unwrap_or(value.len())])
}
pub fn modules(pid: u32) -> io::Result<Vec<Module>> {
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(error("cannot snapshot target modules"));
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut ok = unsafe { Module32FirstW(handle.as_raw_handle(), &mut entry) };
    let mut result = Vec::new();
    while ok != 0 {
        result.push(Module {
            base: entry.modBaseAddr as usize,
            size: entry.modBaseSize as usize,
            path: PathBuf::from(text(&entry.szExePath)),
            name: text(&entry.szModule),
        });
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        ok = unsafe { Module32NextW(handle.as_raw_handle(), &mut entry) };
    }
    if result.is_empty() {
        return Err(error("target module list is empty"));
    }
    Ok(result)
}
fn normalized(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('/', "\\")
        .to_lowercase()
}
pub fn find_module(pid: u32, path: &Path) -> io::Result<Option<Module>> {
    let path = normalized(path);
    Ok(modules(pid)?
        .into_iter()
        .find(|m| normalized(&m.path) == path))
}
/// Resolve the real provider module of a potentially forwarded system export,
/// then apply its RVA to the same module in the target (never assume ASLR bases).
pub fn system_function(pid: u32, symbol: &std::ffi::CStr) -> io::Result<usize> {
    let kernel: Vec<u16> = "kernel32.dll".encode_utf16().chain(Some(0)).collect();
    let kernel = unsafe { GetModuleHandleW(kernel.as_ptr()) };
    if kernel.is_null() {
        return Err(error("kernel32 is unavailable"));
    }
    let function = unsafe { GetProcAddress(kernel, symbol.as_ptr().cast()) }
        .ok_or_else(|| error("system export is unavailable"))?;
    let function = function as *const () as usize;
    let mut owner: HMODULE = std::ptr::null_mut();
    if unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            function as *const u16,
            &mut owner,
        )
    } == 0
    {
        return Err(error("cannot identify system export module"));
    }
    let mut name = [0u16; 32768];
    let count = unsafe { GetModuleFileNameW(owner, name.as_mut_ptr(), name.len() as u32) } as usize;
    if count == 0 || count >= name.len() {
        return Err(error("cannot identify system module path"));
    }
    let path = PathBuf::from(String::from_utf16_lossy(&name[..count]));
    let remote = find_module(pid, &path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "system export provider is absent from target",
        )
    })?;
    remote
        .base
        .checked_add(function - owner as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "system export RVA overflow"))
}
struct RemoteBuffer {
    process: OwnedHandle,
    address: usize,
}
impl Drop for RemoteBuffer {
    fn drop(&mut self) {
        unsafe {
            VirtualFreeEx(
                self.process.as_raw_handle(),
                self.address as *mut c_void,
                0,
                MEM_RELEASE,
            );
        }
    }
}
fn duplicate_handle(handle: HANDLE, message: &str) -> io::Result<OwnedHandle> {
    let current = unsafe { GetCurrentProcess() };
    let mut duplicate = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            current,
            handle,
            current,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(error(message));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
}

fn duplicate_process(process: HANDLE) -> io::Result<OwnedHandle> {
    duplicate_handle(process, "cannot retain target process handle")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StartupImage {
    pe_offset: usize,
    entry_rva: u32,
    entry_bytes: [u8; 2],
    size_of_image: u32,
    executable_start: u32,
    executable_end: u32,
}

fn startup_stage(stage: &str, source: io::Error) -> io::Error {
    io::Error::new(
        source.kind(),
        format!("startup entry gate {stage}: {source}"),
    )
}

fn parse_startup_image(data: &[u8]) -> io::Result<StartupImage> {
    if data.get(..2) != Some(b"MZ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup target is not a PE image",
        ));
    }
    let pe_offset = u32_at(data, 0x3c)? as usize;
    if data.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup target has an invalid PE signature",
        ));
    }
    if u16_at(data, pe_offset + 4)? != IMAGE_FILE_MACHINE_AMD64 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "startup entry gating requires an x64 target",
        ));
    }
    let section_count = u16_at(data, pe_offset + 6)? as usize;
    let optional_size = u16_at(data, pe_offset + 20)? as usize;
    let optional = pe_offset
        .checked_add(24)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "startup PE header overflow"))?;
    let sections = optional.checked_add(optional_size).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "startup optional header overflow",
        )
    })?;
    let section_end = section_count
        .checked_mul(40)
        .and_then(|size| sections.checked_add(size))
        .filter(|end| *end <= data.len())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "startup target has a truncated section table",
            )
        })?;
    if section_count == 0
        || optional_size < 0x40
        || sections > data.len()
        || section_end > data.len()
        || u16_at(data, optional)? != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup target is not a valid PE32+ image",
        ));
    }
    let entry_rva = u32_at(data, optional + 0x10)?;
    let size_of_image = u32_at(data, optional + 0x38)?;
    let entry_end = entry_rva
        .checked_add(STARTUP_GATE_BYTES.len() as u32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "startup entry RVA overflow"))?;
    if entry_rva == 0 || size_of_image == 0 || entry_end > size_of_image {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup entry is outside the target image",
        ));
    }

    let mut executable = None;
    for index in 0..section_count {
        let section = sections + index * 40;
        let virtual_size = u32_at(data, section + 8)?;
        let virtual_address = u32_at(data, section + 12)?;
        let raw_size = u32_at(data, section + 16)?;
        let raw_address = u32_at(data, section + 20)?;
        let characteristics = u32_at(data, section + 36)?;
        let mapped_size = virtual_size.max(raw_size);
        let mapped_end = virtual_address.checked_add(mapped_size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "startup section range overflow")
        })?;
        if entry_rva >= virtual_address && entry_end <= mapped_end {
            if executable.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "startup entry belongs to overlapping sections",
                ));
            }
            if characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "startup entry section is not executable",
                ));
            }
            let raw_delta = entry_rva - virtual_address;
            let raw_start = raw_address.checked_add(raw_delta).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "startup entry file range overflow",
                )
            })?;
            let raw_end = raw_start
                .checked_add(STARTUP_GATE_BYTES.len() as u32)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "startup entry file range overflow",
                    )
                })?;
            if raw_delta + STARTUP_GATE_BYTES.len() as u32 > raw_size
                || raw_end as usize > data.len()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "startup entry has no complete on-disk instruction bytes",
                ));
            }
            let entry_bytes = data[raw_start as usize..raw_end as usize]
                .try_into()
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "startup entry has no complete on-disk instruction bytes",
                    )
                })?;
            executable = Some((virtual_address, mapped_end, entry_bytes));
        }
    }
    let (executable_start, executable_end, entry_bytes) = executable.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "startup entry is absent from the target sections",
        )
    })?;
    Ok(StartupImage {
        pe_offset,
        entry_rva,
        entry_bytes,
        size_of_image,
        executable_start,
        executable_end,
    })
}

fn verify_startup_entry_bytes(remote: [u8; 2], disk: StartupImage) -> io::Result<()> {
    if remote != disk.entry_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup entry gate remote instruction bytes differ from the target image",
        ));
    }
    Ok(())
}

unsafe fn read_remote_exact(
    process: HANDLE,
    address: usize,
    output: &mut [u8],
    stage: &str,
) -> io::Result<()> {
    let mut read = 0;
    if unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            output.as_mut_ptr().cast(),
            output.len(),
            &mut read,
        )
    } == 0
        || read != output.len()
    {
        return Err(startup_stage(stage, error("cannot read target memory")));
    }
    Ok(())
}

unsafe fn suspended_image_base(process: HANDLE) -> io::Result<usize> {
    let mut basic: ProcessBasicInformation = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            0,
            (&mut basic as *mut ProcessBasicInformation).cast(),
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "startup entry gate query-peb failed with NTSTATUS 0x{:08x}",
            status as u32
        )));
    }
    let peb = basic.peb_base_address as usize;
    if peb == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup entry gate query-peb returned a null PEB",
        ));
    }
    let mut bytes = [0u8; std::mem::size_of::<usize>()];
    unsafe { read_remote_exact(process, peb + 0x10, &mut bytes, "read-peb-image-base")? };
    let base = usize::from_le_bytes(bytes);
    if base == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup entry gate read-peb-image-base returned a null image",
        ));
    }
    Ok(base)
}

unsafe fn verify_remote_startup_image(
    process: HANDLE,
    image_base: usize,
    disk: StartupImage,
) -> io::Result<(usize, u32)> {
    let mut dos = [0u8; 0x40];
    unsafe { read_remote_exact(process, image_base, &mut dos, "read-remote-dos-header")? };
    if dos.get(..2) != Some(b"MZ") || u32_at(&dos, 0x3c)? as usize != disk.pe_offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup entry gate remote DOS header differs from the target image",
        ));
    }
    let mut nt = [0u8; 0x60];
    unsafe {
        read_remote_exact(
            process,
            image_base.checked_add(disk.pe_offset).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "remote PE address overflow")
            })?,
            &mut nt,
            "read-remote-nt-header",
        )?
    };
    if nt.get(..4) != Some(b"PE\0\0")
        || u16_at(&nt, 4)? != IMAGE_FILE_MACHINE_AMD64
        || u16_at(&nt, 24)? != IMAGE_NT_OPTIONAL_HDR64_MAGIC
        || u32_at(&nt, 24 + 0x10)? != disk.entry_rva
        || u32_at(&nt, 24 + 0x38)? != disk.size_of_image
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup entry gate remote PE identity differs from the target image",
        ));
    }
    let entry = image_base
        .checked_add(disk.entry_rva as usize)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "remote startup entry overflow")
        })?;
    let section_start = image_base
        .checked_add(disk.executable_start as usize)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "remote section start overflow")
        })?;
    let section_end = image_base
        .checked_add(disk.executable_end as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "remote section end overflow"))?;
    if entry < section_start
        || entry
            .checked_add(STARTUP_GATE_BYTES.len())
            .is_none_or(|end| end > section_end)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup entry gate remote entry escaped its executable section",
        ));
    }
    let mut region: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        VirtualQueryEx(
            process,
            entry as *const c_void,
            &mut region,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    } < std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
    {
        return Err(startup_stage(
            "query-entry-region",
            error("cannot query target memory"),
        ));
    }
    let region_start = region.BaseAddress as usize;
    let region_end = region_start.checked_add(region.RegionSize).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "startup memory region overflow")
    })?;
    let protection = region.Protect & 0xff;
    let executable = matches!(
        protection,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    );
    if region.AllocationBase as usize != image_base
        || region.State != MEM_COMMIT
        || region.Type != MEM_IMAGE
        || region.Protect & PAGE_GUARD != 0
        || !executable
        || entry < region_start
        || entry
            .checked_add(STARTUP_GATE_BYTES.len())
            .is_none_or(|end| end > region_end)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "startup entry gate is not in one committed executable image region",
        ));
    }
    Ok((entry, region.Protect))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryReplacement {
    Needed,
    AlreadyApplied,
}

fn entry_replacement(
    current: [u8; 2],
    expected: [u8; 2],
    replacement: [u8; 2],
) -> io::Result<EntryReplacement> {
    if current == replacement {
        Ok(EntryReplacement::AlreadyApplied)
    } else if current == expected {
        Ok(EntryReplacement::Needed)
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "startup entry bytes changed while the entry gate was active",
        ))
    }
}

unsafe fn restore_pending_entry_protection(
    process: HANDLE,
    entry: usize,
    pending_protection: &mut Option<u32>,
) -> io::Result<()> {
    let Some(protection) = *pending_protection else {
        return Ok(());
    };
    let mut replaced = 0;
    if unsafe {
        VirtualProtectEx(
            process,
            entry as *const c_void,
            STARTUP_GATE_BYTES.len(),
            protection,
            &mut replaced,
        )
    } == 0
    {
        return Err(error("cannot restore target entry protection"));
    }
    *pending_protection = None;
    Ok(())
}

unsafe fn replace_remote_entry(
    process: HANDLE,
    entry: usize,
    expected: [u8; 2],
    replacement: [u8; 2],
    pending_protection: &mut Option<u32>,
    stage: &str,
) -> io::Result<()> {
    // A previous write may have completed before restoring its page
    // protection failed. Restore exactly the protection observed by that
    // write before deciding whether another write is necessary.
    unsafe {
        restore_pending_entry_protection(process, entry, pending_protection)
            .map_err(|error| startup_stage(stage, error))?;
    }
    let mut current = [0u8; 2];
    unsafe { read_remote_exact(process, entry, &mut current, stage)? };
    match entry_replacement(current, expected, replacement)
        .map_err(|error| startup_stage(stage, error))?
    {
        EntryReplacement::AlreadyApplied => return Ok(()),
        EntryReplacement::Needed => {}
    }

    let mut actual_protection = 0;
    if unsafe {
        VirtualProtectEx(
            process,
            entry as *const c_void,
            replacement.len(),
            PAGE_EXECUTE_READWRITE,
            &mut actual_protection,
        )
    } == 0
    {
        return Err(startup_stage(
            stage,
            error("cannot make target entry writable"),
        ));
    }
    *pending_protection = Some(actual_protection);
    let mut written = 0;
    let write_error = if unsafe {
        WriteProcessMemory(
            process,
            entry as *const c_void,
            replacement.as_ptr().cast(),
            replacement.len(),
            &mut written,
        )
    } == 0
        || written != replacement.len()
    {
        Some(error("cannot replace target entry bytes"))
    } else if unsafe { FlushInstructionCache(process, entry as *const c_void, replacement.len()) }
        == 0
    {
        Some(error("cannot flush target entry instructions"))
    } else {
        None
    };
    let protection_error =
        unsafe { restore_pending_entry_protection(process, entry, pending_protection) }.err();
    match (write_error, protection_error) {
        (None, None) => Ok(()),
        (Some(primary), None) => Err(startup_stage(stage, primary)),
        (None, Some(protection)) => Err(startup_stage(stage, protection)),
        (Some(primary), Some(protection)) => Err(io::Error::new(
            primary.kind(),
            format!("startup entry gate {stage}: {primary}; rollback: {protection}"),
        )),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartupGateState {
    Armed,
    Running,
    Held,
    Released,
}

fn startup_transition(from: StartupGateState, to: StartupGateState) -> bool {
    matches!(
        (from, to),
        (StartupGateState::Armed, StartupGateState::Running)
            | (StartupGateState::Running, StartupGateState::Held)
            | (StartupGateState::Held, StartupGateState::Released)
    )
}

/// Owns the pre-entry hold on a newly-created x64 process.
///
/// The input process needs query, VM read/write/operation and duplicate rights;
/// the input primary thread needs suspend/resume and get/set-context rights. The
/// process must still have its one `CREATE_SUSPENDED` hold when this is created.
/// Dropping an unreleased gate restores the original entry bytes when safe and
/// never resumes the primary thread. The owned-process caller remains
/// responsible for terminating a target after any preparation error.
pub struct StartupEntryGate {
    process: OwnedHandle,
    thread: OwnedHandle,
    entry: usize,
    original: [u8; 2],
    pending_protection: Option<u32>,
    patch_active: bool,
    state: StartupGateState,
}

impl StartupEntryGate {
    fn transition(&mut self, to: StartupGateState, stage: &str) -> io::Result<()> {
        if !startup_transition(self.state, to) {
            return Err(io::Error::other(format!(
                "startup entry gate {stage}: invalid state {:?} -> {to:?}",
                self.state
            )));
        }
        self.state = to;
        Ok(())
    }

    unsafe fn restore_entry(&mut self, stage: &str) -> io::Result<()> {
        if self.patch_active {
            unsafe {
                replace_remote_entry(
                    self.process.as_raw_handle(),
                    self.entry,
                    STARTUP_GATE_BYTES,
                    self.original,
                    &mut self.pending_protection,
                    stage,
                )?
            };
            self.patch_active = false;
        }
        Ok(())
    }

    unsafe fn hold_running_for_failure(&mut self) -> io::Result<()> {
        let previous = unsafe { SuspendThread(self.thread.as_raw_handle()) };
        if previous == u32::MAX {
            return Err(startup_stage(
                "failure-quarantine",
                error("cannot suspend target primary thread"),
            ));
        }
        self.transition(StartupGateState::Held, "failure-quarantine")
    }

    unsafe fn run_to_entry(&mut self, timeout: Duration) -> io::Result<()> {
        let previous = unsafe { ResumeThread(self.thread.as_raw_handle()) };
        if previous == u32::MAX {
            return Err(startup_stage(
                "initial-resume",
                error("cannot resume target primary thread"),
            ));
        }
        self.transition(StartupGateState::Running, "initial-resume")?;
        if previous != STARTUP_RELEASE_COUNTS[0] {
            let quarantine = unsafe { self.hold_running_for_failure() };
            return match quarantine {
                Ok(()) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "startup entry gate initial-resume expected suspend count 1, got {previous}"
                    ),
                )),
                Err(error) => Err(error),
            };
        }
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "startup entry gate timeout overflow",
            )
        })?;
        loop {
            if Instant::now() >= deadline {
                unsafe { self.hold_running_for_failure()? };
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "startup entry gate wait-entry timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
            let previous = unsafe { SuspendThread(self.thread.as_raw_handle()) };
            if previous == u32::MAX {
                return Err(startup_stage(
                    "poll-suspend",
                    error("cannot suspend target primary thread"),
                ));
            }
            if previous != 0 {
                let resumed = unsafe { ResumeThread(self.thread.as_raw_handle()) };
                if resumed == u32::MAX {
                    self.transition(StartupGateState::Held, "poll-resume-failure")?;
                    return Err(startup_stage(
                        "poll-resume",
                        error("cannot balance target primary suspension"),
                    ));
                }
                unsafe { self.hold_running_for_failure()? };
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "startup entry gate poll-suspend found external suspend count {previous}"
                    ),
                ));
            }
            let mut context: CONTEXT = unsafe { std::mem::zeroed() };
            context.ContextFlags = CONTEXT_CONTROL_AMD64;
            if unsafe { GetThreadContext(self.thread.as_raw_handle(), &mut context) } == 0 {
                let context_error = error("cannot inspect target primary context");
                let resumed = unsafe { ResumeThread(self.thread.as_raw_handle()) };
                if resumed == u32::MAX {
                    self.transition(StartupGateState::Held, "context-resume-failure")?;
                }
                return Err(startup_stage("get-context", context_error));
            }
            if context.Rip as usize == self.entry {
                self.transition(StartupGateState::Held, "entry-reached")?;
                unsafe { self.restore_entry("restore-entry")? };
                context.Rip = self.entry as u64;
                if unsafe { SetThreadContext(self.thread.as_raw_handle(), &context) } == 0 {
                    return Err(startup_stage(
                        "set-entry-context",
                        error("cannot reset target primary instruction pointer"),
                    ));
                }
                return Ok(());
            }
            if unsafe { ResumeThread(self.thread.as_raw_handle()) } == u32::MAX {
                self.transition(StartupGateState::Held, "poll-resume-failure")?;
                return Err(startup_stage(
                    "poll-resume",
                    error("cannot balance target primary suspension"),
                ));
            }
        }
    }

    /// Remove the final entry hold after protection is READY and recovery state
    /// is durable. This is the only successful path that resumes the target.
    pub unsafe fn release(mut self) -> io::Result<()> {
        if self.state != StartupGateState::Held || self.patch_active {
            return Err(io::Error::other(
                "startup entry gate release requested before a restored entry hold",
            ));
        }
        // Add a probe suspension without ever releasing the existing hold. A
        // trusted caller must have exactly the one hold owned by this gate.
        // The Win32 API does not provide an atomic count-and-release operation;
        // a same-user controller racing these calls is outside this unprivileged
        // gate's trusted-control-plane boundary.
        let previous = unsafe { SuspendThread(self.thread.as_raw_handle()) };
        if previous == u32::MAX {
            return Err(startup_stage(
                "release-probe",
                error("cannot inspect target primary suspension"),
            ));
        }
        if previous != 1 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "startup entry gate release-probe expected suspend count {}, got {previous}",
                    STARTUP_RELEASE_COUNTS[0]
                ),
            ));
        }
        for (stage, expected) in ["release-probe-hold", "release-entry-hold"]
            .into_iter()
            .zip(STARTUP_RELEASE_COUNTS[1..].iter().copied())
        {
            let resumed = unsafe { ResumeThread(self.thread.as_raw_handle()) };
            if resumed == u32::MAX {
                return Err(startup_stage(
                    stage,
                    error("cannot resume target primary thread"),
                ));
            }
            if resumed != expected {
                // Another same-user controller changed the count between our
                // calls. Re-establish an isolation hold; the owned-process
                // caller will terminate the target instead of continuing.
                let _ = unsafe { SuspendThread(self.thread.as_raw_handle()) };
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "startup entry gate {stage} expected suspend count {expected}, got {resumed}"
                    ),
                ));
            }
        }
        self.transition(StartupGateState::Released, "release")
    }
}

impl Drop for StartupEntryGate {
    fn drop(&mut self) {
        unsafe {
            if self.state == StartupGateState::Running
                && SuspendThread(self.thread.as_raw_handle()) != u32::MAX
            {
                let _ = self.transition(StartupGateState::Held, "drop-quarantine");
            }
            if self.state != StartupGateState::Released && self.state != StartupGateState::Running {
                let _ = self.restore_entry("drop-restore-entry");
            }
        }
    }
}

/// Advance a freshly-created x64 process through the Windows loader, then hold
/// its primary thread on the original executable entrypoint. No Toolhelp module
/// enumeration or remote loader thread is used until this function succeeds.
pub unsafe fn hold_suspended_process_at_entry(
    process: HANDLE,
    thread: HANDLE,
    target: &Path,
    timeout: Duration,
) -> io::Result<StartupEntryGate> {
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "startup entry gate timeout must be non-zero",
        ));
    }
    let data = std::fs::read(target).map_err(|error| startup_stage("read-target-image", error))?;
    let disk =
        parse_startup_image(&data).map_err(|error| startup_stage("parse-target-image", error))?;
    let process = duplicate_handle(process, "cannot retain startup target process handle")?;
    let thread = duplicate_handle(thread, "cannot retain startup target thread handle")?;
    let image_base = unsafe { suspended_image_base(process.as_raw_handle())? };
    let (entry, _initial_protection) =
        unsafe { verify_remote_startup_image(process.as_raw_handle(), image_base, disk)? };
    let mut original = [0u8; 2];
    unsafe {
        read_remote_exact(
            process.as_raw_handle(),
            entry,
            &mut original,
            "read-original-entry",
        )?
    };
    verify_startup_entry_bytes(original, disk)?;
    let mut gate = StartupEntryGate {
        process,
        thread,
        entry,
        original,
        pending_protection: None,
        patch_active: true,
        state: StartupGateState::Armed,
    };
    unsafe {
        replace_remote_entry(
            gate.process.as_raw_handle(),
            gate.entry,
            gate.original,
            STARTUP_GATE_BYTES,
            &mut gate.pending_protection,
            "arm-entry",
        )?;
        gate.run_to_entry(timeout)?;
    }
    Ok(gate)
}
/// The supplied HANDLE must already have the least rights required by injection.
/// A timed-out remote call retains its input until the remote thread actually
/// exits; closing a thread handle or returning an error never terminates it.
pub unsafe fn call(process: HANDLE, function: usize, input: &[u8]) -> io::Result<u32> {
    if function == 0 || input.is_empty() || input.len() > super::MAX_FRAME + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid remote call",
        ));
    }
    let retained = duplicate_process(process)?;
    let address = unsafe {
        VirtualAllocEx(
            process,
            std::ptr::null(),
            input.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if address.is_null() {
        return Err(error("cannot allocate remote call input"));
    }
    let buffer = RemoteBuffer {
        process: retained,
        address: address as usize,
    };
    let mut written = 0;
    if unsafe {
        WriteProcessMemory(
            process,
            address,
            input.as_ptr().cast(),
            input.len(),
            &mut written,
        )
    } == 0
        || written != input.len()
    {
        return Err(error("cannot write remote call input"));
    }
    let start = unsafe {
        std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(function)
    };
    let raw = unsafe {
        CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            Some(start),
            address,
            0,
            std::ptr::null_mut(),
        )
    };
    if raw.is_null() {
        return Err(error("cannot create remote initialization thread"));
    }
    let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
    match unsafe { WaitForSingleObject(thread.as_raw_handle(), 30_000) } {
        WAIT_OBJECT_0 => {
            let mut status = 0;
            if unsafe { GetExitCodeThread(thread.as_raw_handle(), &mut status) } == 0 {
                return Err(error("cannot obtain remote thread result"));
            }
            Ok(status)
        }
        WAIT_TIMEOUT => {
            // The waiter owns both native objects and the borrowed-input allocation.
            // If even the helper cannot spawn, preserve remote storage rather than UAF.
            let work = std::sync::Arc::new(std::sync::Mutex::new(Some((thread, buffer))));
            let keep = work.clone();
            if std::thread::Builder::new()
                .name("hyperhub-remote-cleanup".into())
                .spawn(move || {
                    if let Some((thread, buffer)) = keep.lock().ok().and_then(|mut w| w.take()) {
                        if unsafe { WaitForSingleObject(thread.as_raw_handle(), INFINITE) }
                            == WAIT_OBJECT_0
                        {
                            drop(buffer);
                        } else {
                            std::mem::forget(buffer);
                        }
                    }
                })
                .is_err()
            {
                if let Some((_, buffer)) = work.lock().ok().and_then(|mut w| w.take()) {
                    std::mem::forget(buffer);
                }
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "cleanup_pending: remote initialization has not completed",
            ))
        }
        _ => {
            std::mem::forget(buffer);
            Err(error(
                "cleanup_pending: waiting for remote initialization failed",
            ))
        }
    }
}
pub unsafe fn load(process: HANDLE, pid: u32, path: &Path) -> io::Result<Module> {
    if find_module(pid, path)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "attachment module is already loaded",
        ));
    }
    let units = wide(path.as_os_str())?;
    let bytes = unsafe { std::slice::from_raw_parts(units.as_ptr().cast::<u8>(), units.len() * 2) };
    let function = system_function(pid, c"LoadLibraryW")?;
    let _ = unsafe { call(process, function, bytes) }?;
    find_module(pid, path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "remote loader did not load the attachment module",
        )
    })
}
fn u16_at(data: &[u8], offset: usize) -> io::Result<u16> {
    data.get(offset..offset + 2)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated PE u16"))
}
fn u32_at(data: &[u8], offset: usize) -> io::Result<u32> {
    data.get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated PE u32"))
}
fn rva(data: &[u8], value: u32, sections: usize, count: usize, headers: u32) -> io::Result<usize> {
    if value < headers && (value as usize) < data.len() {
        return Ok(value as usize);
    }
    for i in 0..count {
        let s = sections + i * 40;
        let base = u32_at(data, s + 12)?;
        let size = u32_at(data, s + 16)?;
        let raw = u32_at(data, s + 20)?;
        if let Some(delta) = value.checked_sub(base) {
            if delta < size {
                return (raw as usize)
                    .checked_add(delta as usize)
                    .filter(|o| *o < data.len())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PE RVA overflow"));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unmapped PE RVA",
    ))
}
pub fn export_rva(path: &Path, symbol: &str) -> io::Result<usize> {
    let data = std::fs::read(path)?;
    if data.get(..2) != Some(b"MZ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent is not PE",
        ));
    }
    let pe = u32_at(&data, 0x3c)? as usize;
    if data.get(pe..pe + 4) != Some(b"PE\0\0")
        || u16_at(&data, pe + 4)? != 0x8664
        || u16_at(&data, pe + 24)? != 0x20b
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent must be PE x64",
        ));
    }
    let count = u16_at(&data, pe + 6)? as usize;
    let optional = pe + 24;
    let optional_size = u16_at(&data, pe + 20)? as usize;
    let sections = optional.checked_add(optional_size).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PE optional header size",
        )
    })?;
    let section_end = sections
        .checked_add(count.checked_mul(40).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid PE section count")
        })?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid PE section table"))?;
    if optional_size < 0x70 || section_end > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated PE headers",
        ));
    }
    let headers = u32_at(&data, optional + 0x3c)?;
    if (headers as usize) < section_end || (headers as usize) > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PE header range",
        ));
    }
    if u32_at(&data, optional + 0x6c)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "PE has no export directory",
        ));
    }
    if optional_size < 0x78 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated PE export directory",
        ));
    }
    let export = u32_at(&data, optional + 0x70)?;
    let export_size = u32_at(&data, optional + 0x74)?;
    if export == 0 && export_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "PE has no export directory",
        ));
    }
    if export == 0 || export_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PE export directory range",
        ));
    }
    let at = |value| rva(&data, value, sections, count, headers);
    let table = at(export)?;
    let functions = u32_at(&data, table + 20)? as usize;
    let names = u32_at(&data, table + 24)? as usize;
    if functions > 65536 || names > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PE export count",
        ));
    }
    let addresses = at(u32_at(&data, table + 28)?)?;
    let strings = at(u32_at(&data, table + 32)?)?;
    let ordinals = at(u32_at(&data, table + 36)?)?;
    for i in 0..names {
        let name = at(u32_at(&data, strings + i * 4)?)?;
        let bytes = &data[name..];
        let end = bytes
            .iter()
            .position(|c| *c == 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unterminated PE export"))?;
        if &bytes[..end] == symbol.as_bytes() {
            let ordinal = u16_at(&data, ordinals + i * 2)? as usize;
            if ordinal >= functions {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid PE ordinal",
                ));
            }
            let value = u32_at(&data, addresses + ordinal * 4)?;
            if value >= export && value < export.saturating_add(export_size) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "forwarded agent entrypoint is unsupported",
                ));
            }
            return Ok(value as usize);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "agent attachment entrypoint is missing",
    ))
}
pub unsafe fn start(
    process: HANDLE,
    module: &Module,
    bootstrap: &super::Bootstrap,
) -> io::Result<()> {
    let json = serde_json::to_vec(bootstrap).map_err(io::Error::other)?;
    let mut input = (json.len() as u32).to_be_bytes().to_vec();
    input.extend(json);
    let entry = module
        .base
        .checked_add(export_rva(&module.path, "hyperhub_attachment_start")?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "attachment entry overflow"))?;
    let status = unsafe { call(process, entry, &input) }?;
    if status != 0 {
        return Err(io::Error::other(format!(
            "attachment initialization returned status 0x{status:08x}"
        )));
    }
    Ok(())
}

/// Establish that no application thread is still returning through the native
/// base. Retired hooks/callbacks prevent new entries after this observation.
/// Every suspension increment is paired with exactly one ResumeThread.
pub fn verify_quiescent(pid: u32, module: &Module) -> io::Result<()> {
    use windows_sys::Win32::System::{
        Diagnostics::{
            Debug::{GetThreadContext, CONTEXT, CONTEXT_CONTROL_AMD64},
            ToolHelp::{Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32},
        },
        Threading::{
            OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
            THREAD_SUSPEND_RESUME,
        },
    };
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationThread(
            thread: HANDLE,
            class: u32,
            information: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    struct Suspended(OwnedHandle);
    impl Drop for Suspended {
        fn drop(&mut self) {
            unsafe {
                ResumeThread(self.0.as_raw_handle());
            }
        }
    }
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(error("cannot enumerate target threads for unload"));
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut next = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
    let mut suspended = Vec::new();
    while next != 0 {
        if entry.th32OwnerProcessID == pid {
            let handle = unsafe {
                OpenThread(
                    THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                    0,
                    entry.th32ThreadID,
                )
            };
            if handle.is_null() {
                return Err(error("cannot inspect target thread for unload"));
            }
            let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
            let mut start = 0usize;
            if unsafe {
                NtQueryInformationThread(
                    handle.as_raw_handle(),
                    9,
                    (&mut start as *mut usize).cast(),
                    std::mem::size_of::<usize>() as u32,
                    std::ptr::null_mut(),
                )
            } < 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "target thread start identity is unavailable",
                ));
            }
            if (module.base..module.base.saturating_add(module.size)).contains(&start) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "native-base worker has not exited",
                ));
            }
            if unsafe { SuspendThread(handle.as_raw_handle()) } == u32::MAX {
                return Err(error("cannot quiesce target thread for unload"));
            }
            let guard = Suspended(handle);
            let mut context: CONTEXT = unsafe { std::mem::zeroed() };
            context.ContextFlags = CONTEXT_CONTROL_AMD64;
            if unsafe { GetThreadContext(guard.0.as_raw_handle(), &mut context) } == 0 {
                return Err(error("cannot inspect quiesced thread context"));
            }
            if (module.base..module.base.saturating_add(module.size))
                .contains(&(context.Rip as usize))
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "application thread is still returning through native base",
                ));
            }
            suspended.push(guard);
        }
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        next = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
    }
    if suspended.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "target has no live application threads",
        ));
    }
    // Resume before creating the unload thread: a suspended application thread
    // could own the loader lock. No registered entry into our module remains.
    drop(suspended);
    Ok(())
}
pub unsafe fn unload(process: HANDLE, pid: u32, module: &Module) -> io::Result<bool> {
    verify_quiescent(pid, module)?;
    let entry = module
        .base
        .checked_add(export_rva(&module.path, "hyperhub_attachment_release")?)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "attachment release entry overflow",
            )
        })?;
    let status = unsafe { call(process, entry, &[0]) }?;
    if status != 0 {
        return Err(io::Error::other(format!(
            "native module release returned 0x{status:08x}"
        )));
    }
    Ok(find_module(pid, &module.path)?.is_none())
}

/// Bound an exported system service by the next distinct exported RVA. This
/// derives the interval from the target's actual PE, without OS-version offsets.
fn export_interval(module: &Module, symbol: &str) -> io::Result<std::ops::Range<usize>> {
    let start = export_rva(&module.path, symbol)? as u32;
    let data = std::fs::read(&module.path)?;
    let pe = u32_at(&data, 0x3c)? as usize;
    let optional = pe + 24;
    let sections = optional + u16_at(&data, pe + 20)? as usize;
    let count = u16_at(&data, pe + 6)? as usize;
    let headers = u32_at(&data, optional + 0x3c)?;
    let export = rva(
        &data,
        u32_at(&data, optional + 0x70)?,
        sections,
        count,
        headers,
    )?;
    let functions = u32_at(&data, export + 20)? as usize;
    if functions > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid system export count",
        ));
    }
    let table = rva(&data, u32_at(&data, export + 28)?, sections, count, headers)?;
    let mut end = None;
    for index in 0..functions {
        let value = u32_at(&data, table + index * 4)?;
        if value > start && end.is_none_or(|old| value < old) {
            end = Some(value);
        }
    }
    let end = end.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "system creation service has no bounded export interval",
        )
    })?;
    if end - start > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "system creation service interval cannot be safely bounded",
        ));
    }
    Ok(module.base + start as usize..module.base + end as usize)
}
/// After the Agent's creation-entry gates are installed, wait for calls that
/// entered the native creation service before those gates. Threads are paused
/// only to read their context, then resumed immediately. No loader operation,
/// remote initialization or application lock acquisition runs while paused.
pub fn verify_spawn_quiescence(pid: u32) -> io::Result<()> {
    use windows_sys::Win32::System::{
        Diagnostics::{
            Debug::{GetThreadContext, CONTEXT, CONTEXT_CONTROL_AMD64},
            ToolHelp::{Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32},
        },
        Threading::{
            OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
        },
    };
    let modules = modules(pid)?;
    let ntdll = modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case("ntdll.dll"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "target creation-service module is absent",
            )
        })?;
    let creation = export_interval(ntdll, "NtCreateUserProcess")?;
    struct Suspended(OwnedHandle);
    impl Drop for Suspended {
        fn drop(&mut self) {
            unsafe {
                ResumeThread(self.0.as_raw_handle());
            }
        }
    }
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(error("cannot enumerate target creation threads"));
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut next = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
    while next != 0 {
        if entry.th32OwnerProcessID == pid {
            let raw = unsafe {
                OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                    0,
                    entry.th32ThreadID,
                )
            };
            if raw.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "creation-thread identity changed during preparation",
                ));
            }
            let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
            if unsafe { SuspendThread(handle.as_raw_handle()) } == u32::MAX {
                return Err(error("cannot inspect target creation thread"));
            }
            let guard = Suspended(handle);
            let mut context: CONTEXT = unsafe { std::mem::zeroed() };
            context.ContextFlags = CONTEXT_CONTROL_AMD64;
            let success = unsafe { GetThreadContext(guard.0.as_raw_handle(), &mut context) };
            let context_error = if success == 0 {
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            } else {
                0
            };
            let in_creation = creation.contains(&(context.Rip as usize));
            let known_image = modules.iter().any(|module| {
                (module.base..module.base.saturating_add(module.size))
                    .contains(&(context.Rip as usize))
            });
            drop(guard);
            if success == 0 {
                return Err(io::Error::from_raw_os_error(context_error as i32));
            }
            if in_creation {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "pre-hook process creation is still in flight",
                ));
            }
            if !known_image {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "thread is in an uncertain executable region during tree preparation",
                ));
            }
        }
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        next = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
    }
    Ok(())
}

#[cfg(test)]
mod export_directory_tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "hh-pe-capability-{}-{}.exe",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            Self(path)
        }
        fn check(&self, bytes: &[u8]) -> io::ErrorKind {
            std::fs::write(&self.0, bytes).unwrap();
            export_rva(&self.0, "fork").unwrap_err().kind()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn pe_without_exports() -> Vec<u8> {
        let mut bytes = vec![0; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[0xd4..0xd8].copy_from_slice(&512u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
        bytes
    }
    #[test]
    fn valid_pe_without_export_directory_is_absent_not_invalid() {
        let fixture = Fixture::new();
        let bytes = pe_without_exports();
        assert_eq!(fixture.check(&bytes), io::ErrorKind::NotFound);
        let mut no_directories = bytes;
        no_directories[0x104..0x108].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(fixture.check(&no_directories), io::ErrorKind::NotFound);
    }
    #[test]
    fn truncated_or_malformed_pe_headers_do_not_prove_absent_exports() {
        let fixture = Fixture::new();
        let bytes = pe_without_exports();
        for length in [0, 64, 0x98, 0x110, 511] {
            assert_eq!(
                fixture.check(&bytes[..length]),
                io::ErrorKind::InvalidData,
                "truncated length {length}"
            );
        }
        for (offset, value) in [(0x108, 0x100u32), (0x10c, 40u32)] {
            let mut malformed = bytes.clone();
            malformed[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                fixture.check(&malformed),
                io::ErrorKind::InvalidData,
                "incomplete export directory {offset:x}"
            );
        }
        let mut not_pe = bytes;
        not_pe[..2].copy_from_slice(b"XX");
        assert_eq!(fixture.check(&not_pe), io::ErrorKind::InvalidData);
    }
}

#[cfg(test)]
mod startup_entry_gate_tests {
    use super::*;

    const PE: usize = 0x80;
    const OPTIONAL: usize = PE + 24;
    const SECTION: usize = OPTIONAL + 0xf0;

    fn executable() -> Vec<u8> {
        let mut bytes = vec![0; 0x400];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(PE as u32).to_le_bytes());
        bytes[PE..PE + 4].copy_from_slice(b"PE\0\0");
        bytes[PE + 4..PE + 6].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        bytes[PE + 6..PE + 8].copy_from_slice(&1u16.to_le_bytes());
        bytes[PE + 20..PE + 22].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[OPTIONAL..OPTIONAL + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        bytes[OPTIONAL + 0x10..OPTIONAL + 0x14].copy_from_slice(&0x1010u32.to_le_bytes());
        bytes[OPTIONAL + 0x38..OPTIONAL + 0x3c].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[SECTION + 8..SECTION + 12].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[SECTION + 12..SECTION + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[SECTION + 16..SECTION + 20].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[SECTION + 20..SECTION + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[SECTION + 36..SECTION + 40]
            .copy_from_slice(&(IMAGE_SCN_MEM_EXECUTE | 0x4000_0020).to_le_bytes());
        bytes[0x210..0x212].copy_from_slice(&[0x48, 0x83]);
        bytes
    }

    #[test]
    fn startup_parser_binds_x64_entry_to_executable_disk_bytes() {
        assert_eq!(
            parse_startup_image(&executable()).unwrap(),
            StartupImage {
                pe_offset: PE,
                entry_rva: 0x1010,
                entry_bytes: [0x48, 0x83],
                size_of_image: 0x2000,
                executable_start: 0x1000,
                executable_end: 0x1100,
            }
        );
        let image = parse_startup_image(&executable()).unwrap();
        assert!(verify_startup_entry_bytes([0x48, 0x83], image).is_ok());
        assert_eq!(
            verify_startup_entry_bytes([0x90, 0x90], image)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn startup_parser_rejects_wrong_machine_and_non_executable_entry() {
        let mut wrong_machine = executable();
        wrong_machine[PE + 4..PE + 6].copy_from_slice(&0x14cu16.to_le_bytes());
        assert_eq!(
            parse_startup_image(&wrong_machine).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        let mut non_executable = executable();
        non_executable[SECTION + 36..SECTION + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
        assert_eq!(
            parse_startup_image(&non_executable).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn startup_parser_requires_two_mapped_and_on_disk_entry_bytes() {
        let mut virtual_boundary = executable();
        virtual_boundary[OPTIONAL + 0x10..OPTIONAL + 0x14]
            .copy_from_slice(&0x10ffu32.to_le_bytes());
        assert_eq!(
            parse_startup_image(&virtual_boundary).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut raw_boundary = executable();
        raw_boundary[SECTION + 16..SECTION + 20].copy_from_slice(&0x11u32.to_le_bytes());
        assert_eq!(
            parse_startup_image(&raw_boundary).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn startup_parser_rejects_truncated_headers_and_sections() {
        let bytes = executable();
        for length in [0, 0x40, PE + 4, OPTIONAL + 0x40, SECTION + 39] {
            assert_eq!(
                parse_startup_image(&bytes[..length]).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "truncated length {length:#x}"
            );
        }
    }

    #[test]
    fn gate_bytes_and_state_machine_have_one_release_path() {
        assert_eq!(STARTUP_GATE_BYTES, [0xeb, 0xfe]);
        assert_eq!(STARTUP_RELEASE_COUNTS, [1, 2, 1]);
        assert_eq!(
            entry_replacement([0x48, 0x83], [0x48, 0x83], STARTUP_GATE_BYTES).unwrap(),
            EntryReplacement::Needed
        );
        assert_eq!(
            entry_replacement(STARTUP_GATE_BYTES, [0x48, 0x83], STARTUP_GATE_BYTES).unwrap(),
            EntryReplacement::AlreadyApplied
        );
        assert_eq!(
            entry_replacement([0x90, 0x90], [0x48, 0x83], STARTUP_GATE_BYTES)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(startup_transition(
            StartupGateState::Armed,
            StartupGateState::Running
        ));
        assert!(startup_transition(
            StartupGateState::Running,
            StartupGateState::Held
        ));
        assert!(startup_transition(
            StartupGateState::Held,
            StartupGateState::Released
        ));
        for (from, to) in [
            (StartupGateState::Armed, StartupGateState::Held),
            (StartupGateState::Armed, StartupGateState::Released),
            (StartupGateState::Running, StartupGateState::Released),
            (StartupGateState::Held, StartupGateState::Running),
            (StartupGateState::Released, StartupGateState::Held),
        ] {
            assert!(
                !startup_transition(from, to),
                "unexpected {from:?} -> {to:?}"
            );
        }
    }
}
