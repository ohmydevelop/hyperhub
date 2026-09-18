use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::Security::Authentication::Identity::{
    InitSecurityInterfaceA, InitSecurityInterfaceW,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

use super::adapters::{file::*, network::*, process::*, trust::*};
use super::gum::{
    find_connect_ex, find_export, find_msys_runtime_export, gum_interceptor_begin_transaction,
    gum_interceptor_end_transaction, gum_interceptor_replace, gum_interceptor_replace_fast,
    gum_interceptor_revert, has_msys_runtime, GumInterceptor,
};
use super::{
    ACQUIRE_CREDENTIALS_A, ACQUIRE_CREDENTIALS_W, CERT_GET_CHAIN, CERT_OPEN_SYSTEM_STORE_A,
    CERT_OPEN_SYSTEM_STORE_W, CERT_VERIFY_POLICY, CLOSESOCKET, CONNECT, CONNECTEX,
    CREATE_PROCESS_A, CREATE_PROCESS_INTERNAL_A, CREATE_PROCESS_INTERNAL_W, CREATE_PROCESS_W,
    GETADDRINFO, GETADDRINFOW, INITIALIZE_SECURITY_CONTEXT_A, INITIALIZE_SECURITY_CONTEXT_W,
    IOCTLSOCKET, LDR_LOAD_DLL, MSYS_FORK, MSYS_VFORK, NT_CLOSE, NT_CREATE_FILE, NT_CREATE_SECTION,
    NT_CREATE_USER_PROCESS, NT_DELETE_FILE, NT_DUPLICATE_OBJECT, NT_MAP_VIEW_OF_SECTION,
    NT_OPEN_FILE, NT_READ_FILE, NT_SET_INFORMATION_FILE, NT_WRITE_FILE, RECV, SEND, WSACONNECT,
    WSARECV, WSASEND,
};

#[derive(Clone, Copy)]
enum SecurityEntry {
    AcquireCredentialsA,
    AcquireCredentialsW,
    InitializeSecurityContextA,
    InitializeSecurityContextW,
}

#[derive(Clone, Copy)]
enum TargetResolver {
    Export {
        module: &'static str,
        symbol: &'static str,
    },
    ConnectEx,
    Security(SecurityEntry),
    MsysRuntimeExport {
        symbol: &'static str,
    },
}

#[derive(Clone, Copy)]
pub(super) struct HookDescriptor {
    pub(super) id: u32,
    pub(super) name: &'static str,
    pub(super) semantic_hook: &'static str,
    pub(super) required: bool,
    pub(super) replacement: *mut c_void,
    pub(super) original: &'static AtomicPtr<c_void>,
    resolver: TargetResolver,
}

// Descriptors only contain immutable function addresses and references to thread-safe atomics.
unsafe impl Sync for HookDescriptor {}

impl HookDescriptor {
    const fn export(
        id: u32,
        name: &'static str,
        semantic_hook: &'static str,
        module: &'static str,
        symbol: &'static str,
        replacement: *mut c_void,
        original: &'static AtomicPtr<c_void>,
    ) -> Self {
        Self {
            id,
            name,
            semantic_hook,
            required: true,
            replacement,
            original,
            resolver: TargetResolver::Export { module, symbol },
        }
    }

    const fn connect_ex(replacement: *mut c_void, original: &'static AtomicPtr<c_void>) -> Self {
        Self {
            id: CONNECTEX,
            name: "ConnectEx",
            semantic_hook: "socket.connect",
            required: false,
            replacement,
            original,
            resolver: TargetResolver::ConnectEx,
        }
    }

    const fn msys_runtime_export(
        id: u32,
        name: &'static str,
        symbol: &'static str,
        replacement: *mut c_void,
        original: &'static AtomicPtr<c_void>,
    ) -> Self {
        Self {
            id,
            name,
            semantic_hook: "process.fork",
            required: true,
            replacement,
            original,
            resolver: TargetResolver::MsysRuntimeExport { symbol },
        }
    }

    const fn security(
        id: u32,
        name: &'static str,
        semantic_hook: &'static str,
        entry: SecurityEntry,
        replacement: *mut c_void,
        original: &'static AtomicPtr<c_void>,
    ) -> Self {
        Self {
            id,
            name,
            semantic_hook,
            required: true,
            replacement,
            original,
            resolver: TargetResolver::Security(entry),
        }
    }

    unsafe fn resolve(self) -> Option<*mut c_void> {
        match self.resolver {
            TargetResolver::Export { module, symbol } => find_export(module, symbol),
            TargetResolver::ConnectEx => find_connect_ex(),
            TargetResolver::Security(entry) => resolve_security_entry(entry),
            TargetResolver::MsysRuntimeExport { symbol } => find_msys_runtime_export(symbol),
        }
    }

    unsafe fn applicable(self) -> bool {
        !matches!(self.resolver, TargetResolver::MsysRuntimeExport { .. }) || has_msys_runtime()
    }
}

macro_rules! export_hook {
    ($id:ident, $name:literal, $semantic:literal, $module:literal, $symbol:literal, $replacement:ident, $original:ident) => {
        HookDescriptor::export(
            $id,
            $name,
            $semantic,
            $module,
            $symbol,
            $replacement as *const () as *mut c_void,
            &$original,
        )
    };
}

macro_rules! security_hook {
    ($id:ident, $name:literal, $entry:ident, $replacement:ident, $original:ident) => {
        HookDescriptor::security(
            $id,
            $name,
            "trust.schannel",
            SecurityEntry::$entry,
            $replacement as *const () as *mut c_void,
            &$original,
        )
    };
}

pub(super) static BUILTIN_HOOKS: &[HookDescriptor] = &[
    export_hook!(
        GETADDRINFO,
        "getaddrinfo",
        "dns.resolve",
        "ws2_32.dll",
        "getaddrinfo",
        hook_getaddrinfo,
        ORIGINAL_GETADDRINFO
    ),
    export_hook!(
        GETADDRINFOW,
        "GetAddrInfoW",
        "dns.resolve",
        "ws2_32.dll",
        "GetAddrInfoW",
        hook_getaddrinfo_w,
        ORIGINAL_GETADDRINFOW
    ),
    export_hook!(
        CONNECT,
        "connect",
        "socket.connect",
        "ws2_32.dll",
        "connect",
        hook_connect,
        ORIGINAL_CONNECT
    ),
    export_hook!(
        WSACONNECT,
        "WSAConnect",
        "socket.connect",
        "ws2_32.dll",
        "WSAConnect",
        hook_wsa_connect,
        ORIGINAL_WSACONNECT
    ),
    export_hook!(
        SEND,
        "send",
        "socket.io",
        "ws2_32.dll",
        "send",
        hook_send,
        ORIGINAL_SEND
    ),
    export_hook!(
        RECV,
        "recv",
        "socket.io",
        "ws2_32.dll",
        "recv",
        hook_recv,
        ORIGINAL_RECV
    ),
    export_hook!(
        CLOSESOCKET,
        "closesocket",
        "socket.close",
        "ws2_32.dll",
        "closesocket",
        hook_closesocket,
        ORIGINAL_CLOSESOCKET
    ),
    export_hook!(
        IOCTLSOCKET,
        "ioctlsocket",
        "socket.mode",
        "ws2_32.dll",
        "ioctlsocket",
        hook_ioctlsocket,
        ORIGINAL_IOCTLSOCKET
    ),
    export_hook!(
        WSASEND,
        "WSASend",
        "socket.io",
        "ws2_32.dll",
        "WSASend",
        hook_wsa_send,
        ORIGINAL_WSASEND
    ),
    export_hook!(
        WSARECV,
        "WSARecv",
        "socket.io",
        "ws2_32.dll",
        "WSARecv",
        hook_wsa_recv,
        ORIGINAL_WSARECV
    ),
    HookDescriptor::connect_ex(
        hook_connect_ex as *const () as *mut c_void,
        &ORIGINAL_CONNECTEX,
    ),
    export_hook!(
        CERT_GET_CHAIN,
        "CertGetCertificateChain",
        "trust.cert_chain",
        "crypt32.dll",
        "CertGetCertificateChain",
        hook_cert_get_chain,
        ORIGINAL_CERT_GET_CHAIN
    ),
    export_hook!(
        CERT_VERIFY_POLICY,
        "CertVerifyCertificateChainPolicy",
        "trust.cert_policy",
        "crypt32.dll",
        "CertVerifyCertificateChainPolicy",
        hook_cert_verify_policy,
        ORIGINAL_CERT_VERIFY_POLICY
    ),
    security_hook!(
        ACQUIRE_CREDENTIALS_A,
        "AcquireCredentialsHandleA",
        AcquireCredentialsA,
        hook_acquire_credentials_a,
        ORIGINAL_ACQUIRE_CREDENTIALS_A
    ),
    security_hook!(
        ACQUIRE_CREDENTIALS_W,
        "AcquireCredentialsHandleW",
        AcquireCredentialsW,
        hook_acquire_credentials_w,
        ORIGINAL_ACQUIRE_CREDENTIALS_W
    ),
    security_hook!(
        INITIALIZE_SECURITY_CONTEXT_A,
        "InitializeSecurityContextA",
        InitializeSecurityContextA,
        hook_initialize_security_context_a,
        ORIGINAL_INITIALIZE_SECURITY_CONTEXT_A
    ),
    security_hook!(
        INITIALIZE_SECURITY_CONTEXT_W,
        "InitializeSecurityContextW",
        InitializeSecurityContextW,
        hook_initialize_security_context_w,
        ORIGINAL_INITIALIZE_SECURITY_CONTEXT_W
    ),
    export_hook!(
        CREATE_PROCESS_A,
        "CreateProcessA",
        "process.create",
        "kernel32.dll",
        "CreateProcessA",
        hook_create_process_a,
        ORIGINAL_CREATE_PROCESS_A
    ),
    export_hook!(
        CREATE_PROCESS_W,
        "CreateProcessW",
        "process.create",
        "kernel32.dll",
        "CreateProcessW",
        hook_create_process_w,
        ORIGINAL_CREATE_PROCESS_W
    ),
    export_hook!(
        CREATE_PROCESS_INTERNAL_A,
        "CreateProcessInternalA",
        "process.create",
        "kernelbase.dll",
        "CreateProcessInternalA",
        hook_create_process_internal_a,
        ORIGINAL_CREATE_PROCESS_INTERNAL_A
    ),
    export_hook!(
        CREATE_PROCESS_INTERNAL_W,
        "CreateProcessInternalW",
        "process.create",
        "kernelbase.dll",
        "CreateProcessInternalW",
        hook_create_process_internal_w,
        ORIGINAL_CREATE_PROCESS_INTERNAL_W
    ),
    export_hook!(
        NT_CREATE_USER_PROCESS,
        "NtCreateUserProcess",
        "process.create",
        "ntdll.dll",
        "NtCreateUserProcess",
        hook_nt_create_user_process,
        ORIGINAL_NT_CREATE_USER_PROCESS
    ),
    export_hook!(
        CERT_OPEN_SYSTEM_STORE_A,
        "CertOpenSystemStoreA",
        "trust.root_store",
        "crypt32.dll",
        "CertOpenSystemStoreA",
        hook_cert_open_system_store_a,
        ORIGINAL_CERT_OPEN_SYSTEM_STORE_A
    ),
    export_hook!(
        CERT_OPEN_SYSTEM_STORE_W,
        "CertOpenSystemStoreW",
        "trust.root_store",
        "crypt32.dll",
        "CertOpenSystemStoreW",
        hook_cert_open_system_store_w,
        ORIGINAL_CERT_OPEN_SYSTEM_STORE_W
    ),
    export_hook!(
        NT_CREATE_FILE,
        "NtCreateFile",
        "file.operation",
        "ntdll.dll",
        "NtCreateFile",
        hook_nt_create_file,
        ORIGINAL_NT_CREATE_FILE
    ),
    export_hook!(
        NT_OPEN_FILE,
        "NtOpenFile",
        "file.operation",
        "ntdll.dll",
        "NtOpenFile",
        hook_nt_open_file,
        ORIGINAL_NT_OPEN_FILE
    ),
    export_hook!(
        NT_READ_FILE,
        "NtReadFile",
        "file.operation",
        "ntdll.dll",
        "NtReadFile",
        hook_nt_read_file,
        ORIGINAL_NT_READ_FILE
    ),
    export_hook!(
        NT_WRITE_FILE,
        "NtWriteFile",
        "file.operation",
        "ntdll.dll",
        "NtWriteFile",
        hook_nt_write_file,
        ORIGINAL_NT_WRITE_FILE
    ),
    export_hook!(
        NT_SET_INFORMATION_FILE,
        "NtSetInformationFile",
        "file.operation",
        "ntdll.dll",
        "NtSetInformationFile",
        hook_nt_set_information_file,
        ORIGINAL_NT_SET_INFORMATION_FILE
    ),
    export_hook!(
        NT_DELETE_FILE,
        "NtDeleteFile",
        "file.operation",
        "ntdll.dll",
        "NtDeleteFile",
        hook_nt_delete_file,
        ORIGINAL_NT_DELETE_FILE
    ),
    export_hook!(
        NT_CREATE_SECTION,
        "NtCreateSection",
        "file.operation",
        "ntdll.dll",
        "NtCreateSection",
        hook_nt_create_section,
        ORIGINAL_NT_CREATE_SECTION
    ),
    export_hook!(
        NT_MAP_VIEW_OF_SECTION,
        "NtMapViewOfSection",
        "file.operation",
        "ntdll.dll",
        "NtMapViewOfSection",
        hook_nt_map_view_of_section,
        ORIGINAL_NT_MAP_VIEW_OF_SECTION
    ),
    export_hook!(
        NT_DUPLICATE_OBJECT,
        "NtDuplicateObject",
        "file.operation",
        "ntdll.dll",
        "NtDuplicateObject",
        hook_nt_duplicate_object,
        ORIGINAL_NT_DUPLICATE_OBJECT
    ),
    export_hook!(
        NT_CLOSE,
        "NtClose",
        "file.operation",
        "ntdll.dll",
        "NtClose",
        hook_nt_close,
        ORIGINAL_NT_CLOSE
    ),
    HookDescriptor::msys_runtime_export(
        MSYS_FORK,
        "fork",
        "fork",
        hook_msys_fork as *const () as *mut c_void,
        &ORIGINAL_MSYS_FORK,
    ),
    HookDescriptor::msys_runtime_export(
        MSYS_VFORK,
        "vfork",
        "vfork",
        hook_msys_vfork as *const () as *mut c_void,
        &ORIGINAL_MSYS_VFORK,
    ),
    export_hook!(
        LDR_LOAD_DLL,
        "LdrLoadDll",
        "process.runtime_load",
        "ntdll.dll",
        "LdrLoadDll",
        hook_ldr_load_dll,
        ORIGINAL_LDR_LOAD_DLL
    ),
];

const MSYS_HOOK_WAITING: u32 = 0;
const MSYS_HOOK_REQUESTED: u32 = 1;
const MSYS_HOOK_INSTALLED: u32 = 2;
const MSYS_HOOK_FAILED: u32 = 3;
static DYNAMIC_INTERCEPTOR: AtomicPtr<GumInterceptor> = AtomicPtr::new(null_mut());
static MSYS_RUNTIME_MODULE: AtomicUsize = AtomicUsize::new(0);
static MSYS_HOOK_STATE: AtomicU32 = AtomicU32::new(MSYS_HOOK_WAITING);

#[repr(C)]
struct LdrUnicodeString {
    length: u16,
    _maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct LdrDllLoadedNotificationData {
    _flags: u32,
    _full_dll_name: *const LdrUnicodeString,
    base_dll_name: *const LdrUnicodeString,
    dll_base: *mut c_void,
    _size_of_image: u32,
}

type LdrDllNotificationFn = unsafe extern "system" fn(u32, *const c_void, *mut c_void);
type LdrRegisterDllNotificationFn = unsafe extern "system" fn(
    u32,
    Option<LdrDllNotificationFn>,
    *mut c_void,
    *mut *mut c_void,
) -> i32;

unsafe extern "system" fn msys_runtime_dll_notification(
    reason: u32,
    data: *const c_void,
    _context: *mut c_void,
) {
    const LDR_DLL_NOTIFICATION_REASON_LOADED: u32 = 1;
    if reason != LDR_DLL_NOTIFICATION_REASON_LOADED || data.is_null() {
        return;
    }
    let loaded = &*data.cast::<LdrDllLoadedNotificationData>();
    if loaded.base_dll_name.is_null() || loaded.dll_base.is_null() {
        return;
    }
    let name = &*loaded.base_dll_name;
    if !wide_runtime_name(name.buffer, usize::from(name.length / 2)) {
        return;
    }
    request_msys_runtime_hook_install(loaded.dll_base as HMODULE);
}

unsafe fn wide_runtime_name(buffer: *const u16, length: usize) -> bool {
    if buffer.is_null() {
        return false;
    }
    ["msys-2.0.dll", "cygwin1.dll"].iter().any(|suffix| {
        let bytes = suffix.as_bytes();
        length >= bytes.len()
            && bytes.iter().enumerate().all(|(index, expected)| {
                let actual = *buffer.add(length - bytes.len() + index);
                actual <= u16::from(u8::MAX)
                    && (actual as u8).to_ascii_lowercase() == expected.to_ascii_lowercase()
            })
    })
}

pub(in crate::windows_gum) fn start_msys_runtime_hook_watcher(
    interceptor: *mut GumInterceptor,
) -> bool {
    DYNAMIC_INTERCEPTOR.store(interceptor, Ordering::Release);
    if !ORIGINAL_MSYS_FORK.load(Ordering::Acquire).is_null()
        && !ORIGINAL_MSYS_VFORK.load(Ordering::Acquire).is_null()
    {
        MSYS_HOOK_STATE.store(MSYS_HOOK_INSTALLED, Ordering::Release);
        return true;
    }
    if std::thread::Builder::new()
        .name("hyperhub-msys-hook-loader".into())
        .spawn(|| loop {
            if MSYS_HOOK_STATE.load(Ordering::Acquire) == MSYS_HOOK_WAITING {
                if let Some(module) = unsafe { loaded_msys_runtime_module() } {
                    request_msys_runtime_hook_install(module);
                }
            }
            if MSYS_HOOK_STATE.load(Ordering::Acquire) == MSYS_HOOK_REQUESTED {
                let installed = unsafe { install_loaded_msys_runtime_hooks() };
                MSYS_HOOK_STATE.store(
                    if installed {
                        MSYS_HOOK_INSTALLED
                    } else {
                        MSYS_HOOK_FAILED
                    },
                    Ordering::Release,
                );
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        })
        .is_err()
    {
        MSYS_HOOK_STATE.store(MSYS_HOOK_FAILED, Ordering::Release);
        return false;
    }
    let Some(register) = (unsafe { find_export("ntdll.dll", "LdrRegisterDllNotification") }) else {
        MSYS_HOOK_STATE.store(MSYS_HOOK_FAILED, Ordering::Release);
        return false;
    };
    let register =
        unsafe { std::mem::transmute::<*mut c_void, LdrRegisterDllNotificationFn>(register) };
    let mut cookie = null_mut();
    let status = unsafe {
        register(
            0,
            Some(msys_runtime_dll_notification),
            null_mut(),
            &mut cookie,
        )
    };
    status >= 0 && !cookie.is_null()
}

fn request_msys_runtime_hook_install(module: HMODULE) {
    MSYS_RUNTIME_MODULE.store(module as usize, Ordering::Release);
    let _ = MSYS_HOOK_STATE.compare_exchange(
        MSYS_HOOK_WAITING,
        MSYS_HOOK_REQUESTED,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

unsafe fn loaded_msys_runtime_module() -> Option<HMODULE> {
    const MSYS: [u16; 13] = [109, 115, 121, 115, 45, 50, 46, 48, 46, 100, 108, 108, 0];
    const CYGWIN: [u16; 12] = [99, 121, 103, 119, 105, 110, 49, 46, 100, 108, 108, 0];
    [MSYS.as_ptr(), CYGWIN.as_ptr()]
        .into_iter()
        .map(|name| GetModuleHandleW(name))
        .find(|module| !module.is_null())
}

pub(in crate::windows_gum) fn complete_msys_runtime_hook_install(module: HMODULE) -> bool {
    if MSYS_HOOK_STATE.load(Ordering::Acquire) == MSYS_HOOK_INSTALLED {
        return true;
    }
    request_msys_runtime_hook_install(module);
    for _ in 0..5000 {
        match MSYS_HOOK_STATE.load(Ordering::Acquire) {
            MSYS_HOOK_INSTALLED => return true,
            MSYS_HOOK_FAILED => return false,
            _ => std::thread::sleep(std::time::Duration::from_millis(1)),
        }
    }
    false
}

unsafe fn install_loaded_msys_runtime_hooks() -> bool {
    let interceptor = DYNAMIC_INTERCEPTOR.load(Ordering::Acquire);
    let module = MSYS_RUNTIME_MODULE.load(Ordering::Acquire) as HMODULE;
    if interceptor.is_null() || module.is_null() {
        return false;
    }
    let Some(fork) = GetProcAddress(module, c"fork".as_ptr().cast()) else {
        return false;
    };
    let Some(vfork) = GetProcAddress(module, c"vfork".as_ptr().cast()) else {
        return false;
    };
    let targets = [
        (descriptor(MSYS_FORK).expect("fork descriptor"), fork),
        (descriptor(MSYS_VFORK).expect("vfork descriptor"), vfork),
    ];
    gum_interceptor_begin_transaction(interceptor);
    let mut installed = Vec::<(*mut c_void, &'static HookDescriptor)>::with_capacity(targets.len());
    for (descriptor, target) in targets {
        let target = target as *const () as *mut c_void;
        let mut original = null_mut();
        if install_replacement(interceptor, descriptor, target, &mut original) != 0
            || original.is_null()
        {
            for (target, descriptor) in installed.into_iter().rev() {
                gum_interceptor_revert(interceptor, target);
                descriptor.original.store(null_mut(), Ordering::Release);
            }
            gum_interceptor_end_transaction(interceptor);
            return false;
        }
        descriptor.original.store(original, Ordering::Release);
        installed.push((target, descriptor));
    }
    gum_interceptor_end_transaction(interceptor);
    true
}

pub(super) fn descriptor(hook_id: u32) -> Option<&'static HookDescriptor> {
    BUILTIN_HOOKS
        .iter()
        .find(|descriptor| descriptor.id == hook_id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HookInstallStatus {
    Installed,
    OptionalMissing,
    ResolutionFailed,
    InstallationFailed,
    Skipped,
    RolledBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HookInstallEntry {
    pub(super) id: u32,
    pub(super) name: &'static str,
    pub(super) semantic_hook: &'static str,
    pub(super) required: bool,
    pub(super) status: HookInstallStatus,
}

#[derive(Debug, Default)]
pub(super) struct HookInstallReport {
    pub(super) hooks: Vec<HookInstallEntry>,
}

impl HookInstallReport {
    pub(super) fn success(&self) -> bool {
        self.hooks.iter().all(|hook| {
            matches!(
                hook.status,
                HookInstallStatus::Installed | HookInstallStatus::OptionalMissing
            )
        })
    }

    pub(super) fn count(&self, status: HookInstallStatus) -> usize {
        self.hooks
            .iter()
            .filter(|hook| hook.status == status)
            .count()
    }
}

pub(super) fn effective_hook_installed(hook: &HookInstallEntry) -> bool {
    match hook.id {
        MSYS_FORK => !ORIGINAL_MSYS_FORK.load(Ordering::Acquire).is_null(),
        MSYS_VFORK => !ORIGINAL_MSYS_VFORK.load(Ordering::Acquire).is_null(),
        _ => matches!(
            hook.status,
            HookInstallStatus::Installed | HookInstallStatus::OptionalMissing
        ),
    }
}

struct ResolvedHook {
    descriptor: &'static HookDescriptor,
    target: *mut c_void,
    report_index: usize,
}

pub(super) struct HookManager {
    interceptor: *mut GumInterceptor,
}

impl HookManager {
    pub(super) fn new(interceptor: *mut GumInterceptor) -> Self {
        Self { interceptor }
    }

    pub(super) unsafe fn install_builtin_hooks(&self) -> HookInstallReport {
        let mut report = HookInstallReport::default();
        let mut resolved = Vec::with_capacity(BUILTIN_HOOKS.len());

        // Resolve every symbol before entering the Gum transaction. Some resolvers initialize
        // Winsock or query SSPI tables and must not run while the interceptor is mutating code.
        for descriptor in BUILTIN_HOOKS {
            let status = if !descriptor.applicable() {
                HookInstallStatus::OptionalMissing
            } else if descriptor.replacement.is_null() {
                HookInstallStatus::ResolutionFailed
            } else if let Some(target) = descriptor.resolve() {
                let report_index = report.hooks.len();
                resolved.push(ResolvedHook {
                    descriptor,
                    target,
                    report_index,
                });
                HookInstallStatus::Installed // provisional until the transaction succeeds
            } else if descriptor.required {
                HookInstallStatus::ResolutionFailed
            } else {
                HookInstallStatus::OptionalMissing
            };
            report.hooks.push(HookInstallEntry {
                id: descriptor.id,
                name: descriptor.name,
                semantic_hook: descriptor.semantic_hook,
                required: descriptor.required,
                status,
            });
        }

        if report
            .hooks
            .iter()
            .any(|hook| hook.status == HookInstallStatus::ResolutionFailed)
        {
            for hook in &mut report.hooks {
                if hook.status == HookInstallStatus::Installed {
                    hook.status = HookInstallStatus::Skipped;
                }
            }
            return report;
        }

        gum_interceptor_begin_transaction(self.interceptor);
        let mut installed = Vec::<(&ResolvedHook, *mut c_void)>::new();
        let mut failed = None;
        for hook in &resolved {
            let mut original = null_mut();
            let status = install_replacement(
                self.interceptor,
                hook.descriptor,
                hook.target,
                &mut original,
            );
            if status != 0 || original.is_null() {
                if status == 0 {
                    gum_interceptor_revert(self.interceptor, hook.target);
                }
                report.hooks[hook.report_index].status = HookInstallStatus::InstallationFailed;
                failed = Some(hook.report_index);
                break;
            }
            hook.descriptor.original.store(original, Ordering::Release);
            installed.push((hook, original));
        }

        if failed.is_some() {
            for (hook, _) in installed.iter().rev() {
                gum_interceptor_revert(self.interceptor, hook.target);
                hook.descriptor
                    .original
                    .store(null_mut(), Ordering::Release);
                report.hooks[hook.report_index].status = HookInstallStatus::RolledBack;
            }
            for hook in &resolved {
                if report.hooks[hook.report_index].status == HookInstallStatus::Installed
                    && !installed
                        .iter()
                        .any(|(installed, _)| installed.report_index == hook.report_index)
                {
                    report.hooks[hook.report_index].status = HookInstallStatus::Skipped;
                }
            }
        }
        gum_interceptor_end_transaction(self.interceptor);
        report
    }
}

unsafe fn install_replacement(
    interceptor: *mut GumInterceptor,
    descriptor: &HookDescriptor,
    target: *mut c_void,
    original: *mut *mut c_void,
) -> i32 {
    if matches!(descriptor.id, MSYS_FORK | MSYS_VFORK) {
        gum_interceptor_replace(
            interceptor,
            target,
            descriptor.replacement,
            original,
            std::ptr::null(),
        )
    } else {
        gum_interceptor_replace_fast(
            interceptor,
            target,
            descriptor.replacement,
            original,
            std::ptr::null(),
        )
    }
}

unsafe fn resolve_security_entry(entry: SecurityEntry) -> Option<*mut c_void> {
    match entry {
        SecurityEntry::AcquireCredentialsA | SecurityEntry::InitializeSecurityContextA => {
            let table = InitSecurityInterfaceA();
            if table.is_null() {
                return None;
            }
            let query = (*table).QueryContextAttributesA? as *const () as *mut c_void;
            QUERY_CONTEXT_ATTRIBUTES_A.store(query, Ordering::Release);
            match entry {
                SecurityEntry::AcquireCredentialsA => (*table)
                    .AcquireCredentialsHandleA
                    .map(|function| function as *const () as *mut c_void),
                SecurityEntry::InitializeSecurityContextA => (*table)
                    .InitializeSecurityContextA
                    .map(|function| function as *const () as *mut c_void),
                _ => None,
            }
        }
        SecurityEntry::AcquireCredentialsW | SecurityEntry::InitializeSecurityContextW => {
            let table = InitSecurityInterfaceW();
            if table.is_null() {
                return None;
            }
            let query = (*table).QueryContextAttributesW? as *const () as *mut c_void;
            QUERY_CONTEXT_ATTRIBUTES_W.store(query, Ordering::Release);
            match entry {
                SecurityEntry::AcquireCredentialsW => (*table)
                    .AcquireCredentialsHandleW
                    .map(|function| function as *const () as *mut c_void),
                SecurityEntry::InitializeSecurityContextW => (*table)
                    .InitializeSecurityContextW
                    .map(|function| function as *const () as *mut c_void),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn builtin_descriptors_have_unique_complete_bindings() {
        let mut ids = HashSet::new();
        let mut originals = HashSet::new();
        for descriptor in BUILTIN_HOOKS {
            assert!(ids.insert(descriptor.id), "duplicate id {}", descriptor.id);
            assert!(
                !descriptor.replacement.is_null(),
                "{} replacement",
                descriptor.name
            );
            assert!(
                originals.insert(descriptor.original as *const AtomicPtr<c_void> as usize),
                "{} original slot is reused",
                descriptor.name
            );
            assert!(!descriptor.semantic_hook.is_empty());
            assert_eq!(
                super::descriptor(descriptor.id).map(|value| value.name),
                Some(descriptor.name)
            );
        }
        assert_eq!(BUILTIN_HOOKS.len(), LDR_LOAD_DLL as usize);
        assert!(
            !descriptor(CONNECTEX)
                .expect("ConnectEx descriptor")
                .required
        );
        assert!(descriptor(0).is_none());
        assert!(descriptor(LDR_LOAD_DLL + 1).is_none());
    }

    #[test]
    fn install_report_accepts_only_installed_or_optional_missing_hooks() {
        let report = HookInstallReport {
            hooks: vec![
                HookInstallEntry {
                    id: CONNECT,
                    name: "connect",
                    semantic_hook: "socket.connect",
                    required: true,
                    status: HookInstallStatus::Installed,
                },
                HookInstallEntry {
                    id: CONNECTEX,
                    name: "ConnectEx",
                    semantic_hook: "socket.connect",
                    required: false,
                    status: HookInstallStatus::OptionalMissing,
                },
            ],
        };
        assert!(report.success());

        let failed = HookInstallReport {
            hooks: vec![HookInstallEntry {
                status: HookInstallStatus::RolledBack,
                ..report.hooks[0]
            }],
        };
        assert!(!failed.success());
    }
}
