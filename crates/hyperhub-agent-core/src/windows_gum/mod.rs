use std::ffi::{c_void, CString};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_DLL_INIT_FAILED, HMODULE};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenEventA, SetEvent, EVENT_MODIFY_STATE,
};

mod adapters;
pub(crate) use adapters::network::resolve_native_addresses;
mod capabilities;
pub(crate) mod file_intents;
mod gum;
mod manager;
mod runtime;
mod shared;

pub(crate) use capabilities::lifecycle::{agent_module_path, inherited_child_event_name};
#[cfg(test)]
use gum::hh_gum_replacement;
use gum::{gum_init_embedded, gum_interceptor_obtain, AGENT_MODULE};
use manager::HookManager;
use runtime::*;

use crate::HH_OK;

const SOCKET_ERROR: i32 = -1;
const WSATRY_AGAIN: i32 = 11002;
pub(in crate::windows_gum) const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x1;
const STATUS_DLL_INIT_FAILED: i32 = 0xC000_0142u32 as i32;

pub(in crate::windows_gum) const GETADDRINFO: u32 = 1;
pub(in crate::windows_gum) const GETADDRINFOW: u32 = 2;
pub(in crate::windows_gum) const CONNECT: u32 = 3;
pub(in crate::windows_gum) const WSACONNECT: u32 = 4;
pub(in crate::windows_gum) const SEND: u32 = 5;
pub(in crate::windows_gum) const RECV: u32 = 6;
pub(in crate::windows_gum) const CLOSESOCKET: u32 = 7;
pub(in crate::windows_gum) const IOCTLSOCKET: u32 = 8;
pub(in crate::windows_gum) const WSASEND: u32 = 9;
pub(in crate::windows_gum) const WSARECV: u32 = 10;
pub(in crate::windows_gum) const CONNECTEX: u32 = 11;
pub(in crate::windows_gum) const SENDTO: u32 = 12;
pub(in crate::windows_gum) const RECVFROM: u32 = 13;
pub(in crate::windows_gum) const WSASENDTO: u32 = 14;
pub(in crate::windows_gum) const WSARECVFROM: u32 = 15;
pub(in crate::windows_gum) const CERT_GET_CHAIN: u32 = 16;
pub(in crate::windows_gum) const CERT_VERIFY_POLICY: u32 = 17;
pub(in crate::windows_gum) const ACQUIRE_CREDENTIALS_A: u32 = 18;
pub(in crate::windows_gum) const ACQUIRE_CREDENTIALS_W: u32 = 19;
pub(in crate::windows_gum) const INITIALIZE_SECURITY_CONTEXT_A: u32 = 20;
pub(in crate::windows_gum) const INITIALIZE_SECURITY_CONTEXT_W: u32 = 21;
pub(in crate::windows_gum) const CREATE_PROCESS_A: u32 = 22;
pub(in crate::windows_gum) const CREATE_PROCESS_W: u32 = 23;
pub(in crate::windows_gum) const CREATE_PROCESS_INTERNAL_A: u32 = 24;
pub(in crate::windows_gum) const CREATE_PROCESS_INTERNAL_W: u32 = 25;
pub(in crate::windows_gum) const NT_CREATE_USER_PROCESS: u32 = 26;
pub(in crate::windows_gum) const CERT_OPEN_SYSTEM_STORE_A: u32 = 27;
pub(in crate::windows_gum) const CERT_OPEN_SYSTEM_STORE_W: u32 = 28;
pub(in crate::windows_gum) const NT_CREATE_FILE: u32 = 29;
pub(in crate::windows_gum) const NT_OPEN_FILE: u32 = 30;
pub(in crate::windows_gum) const NT_READ_FILE: u32 = 31;
pub(in crate::windows_gum) const NT_WRITE_FILE: u32 = 32;
pub(in crate::windows_gum) const NT_SET_INFORMATION_FILE: u32 = 33;
pub(in crate::windows_gum) const NT_DELETE_FILE: u32 = 34;
pub(in crate::windows_gum) const NT_CREATE_SECTION: u32 = 35;
pub(in crate::windows_gum) const NT_MAP_VIEW_OF_SECTION: u32 = 36;
pub(in crate::windows_gum) const NT_DUPLICATE_OBJECT: u32 = 37;
pub(in crate::windows_gum) const NT_CLOSE: u32 = 38;
pub(in crate::windows_gum) const MSYS_FORK: u32 = 39;
pub(in crate::windows_gum) const MSYS_VFORK: u32 = 40;
pub(in crate::windows_gum) const LDR_LOAD_DLL: u32 = 41;
pub(in crate::windows_gum) const GETADDRINFOEXA: u32 = 42;
pub(in crate::windows_gum) const GETADDRINFOEXW: u32 = 43;
pub(in crate::windows_gum) const DNSQUERY_A: u32 = 44;
pub(in crate::windows_gum) const DNSQUERY_UTF8: u32 = 45;
pub(in crate::windows_gum) const DNSQUERY_W: u32 = 46;
pub(in crate::windows_gum) const DNSQUERY_EX: u32 = 47;
pub(in crate::windows_gum) const FREE_CREDENTIALS: u32 = 48;
pub(in crate::windows_gum) const DELETE_SECURITY_CONTEXT: u32 = 49;

static ATTACHMENT_RELEASE_STARTED: AtomicBool = AtomicBool::new(false);
static AGENT_STARTED: AtomicBool = AtomicBool::new(false);
static AGENT_OWNER_PID: AtomicU32 = AtomicU32::new(0);
static RUNTIME_GENERATION: AtomicU64 = AtomicU64::new(0);
static EXTERNAL_POSIX_RUNTIME_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn external_posix_runtime_unsupported() -> bool {
    EXTERNAL_POSIX_RUNTIME_UNSUPPORTED.load(Ordering::Acquire)
}

pub(in crate::windows_gum) fn mark_external_posix_runtime_unsupported() {
    if crate::attachment::externally_attached() {
        // May run under the loader lock. Status and the manager publish this
        // monotonic capability loss; no state lock, IPC or allocation here.
        EXTERNAL_POSIX_RUNTIME_UNSUPPORTED.store(true, Ordering::Release);
    }
}

pub(in crate::windows_gum) fn rebuild_after_msys_fork(lease_id: &str) -> Result<(), i32> {
    let current_pid = unsafe { GetCurrentProcessId() };
    if current_pid == AGENT_OWNER_PID.load(Ordering::Acquire) {
        return Err(crate::HH_ERR_PROTOCOL);
    }
    let endpoint =
        std::env::var("HYPERHUB_CONTROL_ENDPOINT").map_err(|_| crate::HH_ERR_PROTOCOL)?;
    let session_id = std::env::var("HYPERHUB_SESSION_ID").map_err(|_| crate::HH_ERR_PROTOCOL)?;
    let token = std::env::var("HYPERHUB_SESSION_TOKEN").map_err(|_| crate::HH_ERR_PROTOCOL)?;
    let mut candidate_registered = false;
    for _ in 0..1000 {
        if crate::control::fork_status_control(&endpoint, &session_id, &token, lease_id).is_ok() {
            candidate_registered = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !candidate_registered {
        return Err(crate::HH_ERR_PROTOCOL);
    }
    let generation = RUNTIME_GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    let deadline = crate::control::StartupDeadline::new();
    let mut rebuilt = crate::runtime::AgentRuntime::default();
    if let Err(error) = rebuilt.initialize_after_fork(&deadline) {
        crate::report_child_injection_failure(
            current_pid,
            current_pid,
            None,
            "fork_runtime_rebuild",
            error as u32,
        );
        return Err(error);
    }
    crate::runtime::replace_state_after_fork(rebuilt);
    crate::attachment::startup::runtime_rebuilt()?;
    crate::engine_call::initialize_thread_slots()?;
    crate::control::initialize_engine_control(deadline)?;
    if rebuild_builtin_plugins_after_fork().is_err() {
        crate::report_child_injection_failure(
            current_pid,
            current_pid,
            None,
            "fork_plugin_rebuild",
            crate::HH_ERR_PROTOCOL as u32,
        );
        return Err(crate::HH_ERR_PROTOCOL);
    }

    let hook_manifest_complete = runtime_manifest()
        .native_hooks
        .iter()
        .all(manager::effective_hook_installed);
    if !hook_manifest_complete {
        crate::report_child_injection_failure(
            current_pid,
            current_pid,
            None,
            "fork_hook_manifest",
            crate::HH_ERR_PROTOCOL as u32,
        );
        return Err(crate::HH_ERR_PROTOCOL);
    }
    let hook_manifest = runtime_manifest()
        .native_hooks
        .iter()
        .filter(|hook| manager::effective_hook_installed(hook))
        .map(|hook| hook.name.to_owned())
        .collect::<Vec<_>>();
    let (endpoint, session_id, token) = {
        let runtime = crate::state().lock().map_err(|_| crate::HH_ERR_PROTOCOL)?;
        (
            runtime.session.control_endpoint.clone(),
            runtime.session.session_id.clone(),
            runtime.session.token.clone(),
        )
    };
    let policy_version = crate::sandbox_version();
    let mut attested = false;
    for _ in 0..1000 {
        if crate::control::attest_fork_child_control(
            &endpoint,
            &session_id,
            &token,
            lease_id,
            generation,
            &hook_manifest,
            policy_version,
        )
        .is_ok()
        {
            attested = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !attested {
        crate::report_child_injection_failure(
            current_pid,
            current_pid,
            None,
            "fork_child_attestation",
            crate::HH_ERR_PROTOCOL as u32,
        );
        return Err(crate::HH_ERR_PROTOCOL);
    }
    AGENT_OWNER_PID.store(current_pid, Ordering::Release);
    if crate::attachment::managed() {
        crate::attachment::mark_native_ready()?;
    }
    crate::subscribe_sandbox();
    Ok(())
}

unsafe fn signal_agent_event(variable: &str) {
    let Ok(name) = std::env::var(variable) else {
        return;
    };
    let Ok(name) = CString::new(name) else {
        return;
    };
    let event = OpenEventA(EVENT_MODIFY_STATE, 0, name.as_ptr().cast());
    if !event.is_null() {
        SetEvent(event);
        CloseHandle(event);
    }
}

unsafe fn signal_inherited_child_event() {
    let Ok(name) = CString::new(inherited_child_event_name(GetCurrentProcessId())) else {
        return;
    };
    let event = OpenEventA(EVENT_MODIFY_STATE, 0, name.as_ptr().cast());
    if !event.is_null() {
        SetEvent(event);
        CloseHandle(event);
    }
}

unsafe extern "system" fn initialize_gum_agent(_: *mut c_void) -> u32 {
    crate::engine_call::background(|| initialize_gum_agent_inner())
}
unsafe fn initialize_gum_agent_inner() -> u32 {
    initialization_log("worker_started");
    if crate::engine_call::initialize_thread_slots().is_err() {
        return ERROR_DLL_INIT_FAILED;
    }
    if crate::hh_agent_abi_version() != crate::ABI_VERSION {
        initialization_log("abi_failed");
        return ERROR_DLL_INIT_FAILED;
    }
    let status = crate::hh_agent_initialize_from_env();
    if status != HH_OK {
        initialization_log(&format!("bootstrap_failed status={status}"));
        return ERROR_DLL_INIT_FAILED;
    }
    initialization_log("bootstrap_complete");
    install_agent_hooks()
}

unsafe fn install_agent_hooks() -> u32 {
    if crate::attachment::startup::check().is_err() {
        return ERROR_DLL_INIT_FAILED;
    }
    if let Err(error) = initialize_builtin_plugins() {
        if crate::attachment::legacy_debug() {
            eprintln!("hyperhub-gum: failed to initialize hook plugins: {error}");
        }
        return ERROR_DLL_INIT_FAILED;
    }
    gum_init_embedded();
    if !adapters::file::warm_memory_queries() {
        return ERROR_DLL_INIT_FAILED;
    }
    initialization_log("gum_initialized");
    let interceptor = gum_interceptor_obtain();
    if interceptor.is_null() {
        return ERROR_DLL_INIT_FAILED;
    }
    let report = HookManager::new(interceptor).install_builtin_hooks();
    initialization_log(&format!("hooks_installed success={}", report.success()));
    if crate::attachment::startup::check().is_err() {
        return ERROR_DLL_INIT_FAILED;
    }
    if !manager::start_msys_runtime_hook_watcher(interceptor) {
        return ERROR_DLL_INIT_FAILED;
    }
    if crate::attachment::legacy_debug() {
        eprintln!(
            "hyperhub-gum: hooks installed={} optional_missing={} resolution_failed={} installation_failed={} skipped={} rolled_back={}",
            report.count(manager::HookInstallStatus::Installed),
            report.count(manager::HookInstallStatus::OptionalMissing),
            report.count(manager::HookInstallStatus::ResolutionFailed),
            report.count(manager::HookInstallStatus::InstallationFailed),
            report.count(manager::HookInstallStatus::Skipped),
            report.count(manager::HookInstallStatus::RolledBack),
        );
        for hook in &report.hooks {
            eprintln!(
                "hyperhub-gum: native_hook id={} name={} semantic={} required={} status={:?}",
                hook.id, hook.name, hook.semantic_hook, hook.required, hook.status
            );
        }
    }
    if !report.success() {
        return ERROR_DLL_INIT_FAILED;
    }
    if let Err(error) = publish_runtime_manifest(&report) {
        if crate::attachment::legacy_debug() {
            eprintln!("hyperhub-gum: failed to publish hook manifest: {error}");
        }
        return ERROR_DLL_INIT_FAILED;
    }
    AGENT_OWNER_PID.store(GetCurrentProcessId(), Ordering::Release);
    RUNTIME_GENERATION.store(1, Ordering::Release);
    if crate::attachment::legacy_debug() {
        let manifest = runtime_manifest();
        eprintln!(
            "hyperhub-gum: plugins={:?} native_hooks={} semantic_hooks={}",
            manifest.plugins,
            manifest.native_hooks.len(),
            manifest.semantic_hooks.len()
        );
        for hook in &manifest.semantic_hooks {
            eprintln!(
                "hyperhub-gum: semantic_hook name={} failure_mode={:?} before={:?} after={:?}",
                hook.name,
                hook.failure_mode,
                hook.before
                    .iter()
                    .map(|callback| callback.plugin_id)
                    .collect::<Vec<_>>(),
                hook.after
                    .iter()
                    .map(|callback| callback.plugin_id)
                    .collect::<Vec<_>>(),
            );
        }
    }
    if !crate::attachment::managed() {
        signal_agent_event("HYPERHUB_LOADED_EVENT");
        signal_agent_event("HYPERHUB_READY_EVENT");
        signal_inherited_child_event();
    }
    // Gum intentionally remains initialized for the injected process lifetime.
    0
}

fn initialization_log(stage: &str) {
    if crate::attachment::managed() {
        return;
    }
    use std::io::Write;
    let line = format!("hyperhub-agent: pid={} stage={stage}\n", unsafe {
        GetCurrentProcessId()
    });
    if crate::attachment::legacy_debug() {
        eprint!("{line}");
    }
    if let Some(path) = std::env::var_os("HYPERHUB_AGENT_INIT_LOG") {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    instance: HMODULE,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    // Loading the Alpha native base is passive. No application environment
    // value can opt an already-running process into hook initialization.
    if reason == 1 {
        AGENT_MODULE.store(instance as usize, Ordering::Release);
    }
    1
}

/// Explicit compatibility entry for a freshly-created legacy launcher child.
/// The caller invokes this only after LoadLibrary has released the loader lock.
#[no_mangle]
pub unsafe extern "system" fn hyperhub_agent_legacy_start(context: *mut c_void) -> u32 {
    if AGENT_STARTED.swap(true, Ordering::AcqRel) {
        return crate::HH_ERR_PROTOCOL as u32;
    }
    initialize_gum_agent(context)
}

/// Runs on a dedicated remote thread after the native loader has released its
/// lock. The remote buffer is a big-endian u32 length followed by JSON bytes.
#[no_mangle]
pub unsafe extern "system" fn hyperhub_attachment_start(context: *mut c_void) -> u32 {
    let _native_initialization = crate::attachment::enter();
    let mut startup = None;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::engine_call::background(|| -> Result<(), i32> {
            use hyperhub_runtime::attachment::InitializationStage as Stage;
            if context.is_null() {
                return Err(crate::HH_ERR_INVALID);
            }
            let header = unsafe { std::slice::from_raw_parts(context.cast::<u8>(), 4) };
            let length =
                u32::from_be_bytes(header.try_into().map_err(|_| crate::HH_ERR_INVALID)?) as usize;
            if length == 0 || length > hyperhub_runtime::attachment::MAX_FRAME {
                return Err(crate::HH_ERR_INVALID);
            }
            let data = unsafe { std::slice::from_raw_parts(context.cast::<u8>().add(4), length) };
            let bootstrap: hyperhub_runtime::attachment::Bootstrap =
                serde_json::from_slice(data).map_err(|_| crate::HH_ERR_PROTOCOL)?;
            if AGENT_STARTED.swap(true, Ordering::AcqRel) {
                return Err(crate::HH_ERR_PROTOCOL);
            }
            startup = Some(
                crate::attachment::bind_metadata_for_startup(&bootstrap, false)?
                    .ok_or(crate::HH_ERR_PROTOCOL)?,
            );
            // Bind rollback before Engine or Hook installation so every later
            // typed failure remains reachable through the same authenticated Host.
            crate::attachment::start_server()?;
            crate::attachment::startup::stage(Stage::Engine)?;
            crate::attachment::initialize_bound(&bootstrap)?;
            crate::attachment::startup::stage(Stage::InstallingHooks)?;
            let status = unsafe { install_agent_hooks() };
            if status != 0 {
                return Err(crate::HH_ERR_PROTOCOL);
            }
            crate::attachment::startup::stage(Stage::AliasCatchup)?;
            crate::attachment::initialize_alias_host()?;
            crate::attachment::mark_native_ready()?;
            if bootstrap.initially_owned && !crate::attachment::logically_detached() {
                crate::attachment::activate_initial_owned()?;
            }
            Ok(())
        })
    }));
    let success = matches!(result, Ok(Ok(())));
    if let Some(startup) = startup {
        startup.finish(success);
    }
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(code)) => code as u32,
        Err(_) => crate::HH_ERR_INVALID as u32,
    }
}

#[no_mangle]
pub unsafe extern "system" fn hyperhub_agent_postfork_start(_context: *mut c_void) -> u32 {
    let result = (|| {
        let endpoint =
            std::env::var("HYPERHUB_CONTROL_ENDPOINT").map_err(|_| crate::HH_ERR_PROTOCOL)?;
        let session_id =
            std::env::var("HYPERHUB_SESSION_ID").map_err(|_| crate::HH_ERR_PROTOCOL)?;
        let token = std::env::var("HYPERHUB_SESSION_TOKEN").map_err(|_| crate::HH_ERR_PROTOCOL)?;
        let lease_id = crate::control::pending_fork_lease_control(&endpoint, &session_id, &token)?;
        rebuild_after_msys_fork(&lease_id)
    })();
    if result.is_ok() {
        0
    } else {
        ERROR_DLL_INIT_FAILED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_do_not_depend_on_original_slots_or_parent_globs() {
        for (name, source) in [
            (
                "gateway-network",
                include_str!("capabilities/gateway/network_redirect.rs"),
            ),
            (
                "gateway-trust",
                include_str!("capabilities/gateway/ca_trust.rs"),
            ),
            (
                "sandbox-network",
                include_str!("capabilities/sandbox/network.rs"),
            ),
            (
                "lifecycle-child",
                include_str!("capabilities/lifecycle/child_process.rs"),
            ),
            (
                "lifecycle-windows",
                include_str!("capabilities/lifecycle/windows.rs"),
            ),
        ] {
            assert!(
                !source.contains("ORIGINAL_"),
                "{name} accesses an original slot"
            );
            assert!(
                !source.contains("use super::super::*")
                    && !source.contains("use crate::windows_gum::*"),
                "{name} uses a parent wildcard import"
            );
        }
        for (name, source) in [
            ("network-adapter", include_str!("adapters/network.rs")),
            ("trust-adapter", include_str!("adapters/trust.rs")),
            ("process-adapter", include_str!("adapters/process.rs")),
        ] {
            assert!(
                !source.contains("use super::super::*"),
                "{name} imports its parent module wholesale"
            );
        }
        let root = include_str!("mod.rs");
        let forbidden = ["use adapters::{", "network::*", "process::*", "trust::*"].concat();
        assert!(!root.contains(&forbidden));
    }

    #[test]
    fn network_context_is_independent_from_sockaddr_storage() {
        let source = include_str!("runtime/contexts/network.rs");
        assert!(!source.contains("SOCKADDR"));
        assert!(!source.contains("original_name"));
        assert!(!source.contains("target_length"));
    }

    #[test]
    fn exposes_only_known_native_replacements() {
        for hook_id in GETADDRINFO..=DELETE_SECURITY_CONTEXT {
            assert!(!hh_gum_replacement(hook_id).is_null());
        }
        assert!(hh_gum_replacement(0).is_null());
        assert!(hh_gum_replacement(u32::MAX).is_null());
    }
}

pub(crate) fn with_host_io<T>(call: impl FnOnce() -> T) -> T {
    let _guard = gum::HookGuard::enter();
    call()
}

pub(crate) fn retire_attachment_callbacks() -> Result<(), String> {
    if capabilities::gateway::compatibility_resources() {
        return Err("retained_schannel_credentials_or_contexts".into());
    }

    unsafe {
        manager::retire_owned_hooks()?;
    }
    if crate::attachment::active_calls() != 0 {
        return Err("active_hook_calls".into());
    }
    unsafe {
        runtime::retire_plugins();
    }
    Ok(())
}

pub(crate) fn finish_attachment_retirement() -> Result<(), String> {
    unsafe { manager::finish_retirement() }
}

/// Called only after the private channel has retired and native/OS callbacks,
/// TLS and Host workers have all left. This function never returns through code
/// in the module being released.
#[no_mangle]
pub unsafe extern "system" fn hyperhub_attachment_release(_context: *mut c_void) -> u32 {
    if !crate::attachment::unload_ready() {
        return crate::HH_ERR_PROTOCOL as u32;
    }
    let module = AGENT_MODULE.load(Ordering::Acquire) as HMODULE;
    if module.is_null() {
        return crate::HH_ERR_PROTOCOL as u32;
    }
    if ATTACHMENT_RELEASE_STARTED.swap(true, Ordering::AcqRel) {
        return crate::HH_ERR_PROTOCOL as u32;
    }
    if crate::attachment::release_retired_storage().is_err() {
        ATTACHMENT_RELEASE_STARTED.store(false, Ordering::Release);
        return crate::HH_ERR_PROTOCOL as u32;
    }
    runtime::release_manifest_storage();
    manager::release_registry_storage();
    capabilities::gateway::release_trust_storage();
    adapters::file::release_handle_metadata();
    windows_sys::Win32::System::LibraryLoader::FreeLibraryAndExitThread(module, 0);
}

/// Read-only recovery probe. It remains usable after the private Host channel
/// closes, including a lost unload ACK; it never starts or stops enforcement.
#[no_mangle]
pub unsafe extern "system" fn hyperhub_attachment_state(_context: *mut c_void) -> u32 {
    0x4855_0000
        | u32::from(crate::attachment::unload_ready())
        | (u32::from(ATTACHMENT_RELEASE_STARTED.load(Ordering::Acquire)) << 1)
        | (u32::from(!crate::attachment::server_running()) << 2)
}
