use std::ffi::{c_void, CString};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_DLL_INIT_FAILED, HMODULE};
use windows_sys::Win32::System::Threading::{
    CreateThread, GetCurrentProcessId, OpenEventA, SetEvent, EVENT_MODIFY_STATE,
};

mod adapters;
mod capabilities;
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
pub(in crate::windows_gum) const CERT_GET_CHAIN: u32 = 12;
pub(in crate::windows_gum) const CERT_VERIFY_POLICY: u32 = 13;
pub(in crate::windows_gum) const ACQUIRE_CREDENTIALS_A: u32 = 14;
pub(in crate::windows_gum) const ACQUIRE_CREDENTIALS_W: u32 = 15;
pub(in crate::windows_gum) const INITIALIZE_SECURITY_CONTEXT_A: u32 = 16;
pub(in crate::windows_gum) const INITIALIZE_SECURITY_CONTEXT_W: u32 = 17;
pub(in crate::windows_gum) const CREATE_PROCESS_A: u32 = 18;
pub(in crate::windows_gum) const CREATE_PROCESS_W: u32 = 19;
pub(in crate::windows_gum) const CREATE_PROCESS_INTERNAL_A: u32 = 20;
pub(in crate::windows_gum) const CREATE_PROCESS_INTERNAL_W: u32 = 21;
pub(in crate::windows_gum) const NT_CREATE_USER_PROCESS: u32 = 22;
pub(in crate::windows_gum) const CERT_OPEN_SYSTEM_STORE_A: u32 = 23;
pub(in crate::windows_gum) const CERT_OPEN_SYSTEM_STORE_W: u32 = 24;
pub(in crate::windows_gum) const NT_CREATE_FILE: u32 = 25;
pub(in crate::windows_gum) const NT_OPEN_FILE: u32 = 26;
pub(in crate::windows_gum) const NT_READ_FILE: u32 = 27;
pub(in crate::windows_gum) const NT_WRITE_FILE: u32 = 28;
pub(in crate::windows_gum) const NT_SET_INFORMATION_FILE: u32 = 29;
pub(in crate::windows_gum) const NT_DELETE_FILE: u32 = 30;
pub(in crate::windows_gum) const NT_CREATE_SECTION: u32 = 31;
pub(in crate::windows_gum) const NT_MAP_VIEW_OF_SECTION: u32 = 32;
pub(in crate::windows_gum) const NT_DUPLICATE_OBJECT: u32 = 33;
pub(in crate::windows_gum) const NT_CLOSE: u32 = 34;
pub(in crate::windows_gum) const MSYS_FORK: u32 = 35;
pub(in crate::windows_gum) const MSYS_VFORK: u32 = 36;
pub(in crate::windows_gum) const LDR_LOAD_DLL: u32 = 37;

static AGENT_STARTED: AtomicBool = AtomicBool::new(false);
static AGENT_OWNER_PID: AtomicU32 = AtomicU32::new(0);
static RUNTIME_GENERATION: AtomicU64 = AtomicU64::new(0);

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
    let mut rebuilt = crate::runtime::AgentRuntime::default();
    if let Err(error) = rebuilt.initialize_after_fork() {
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
    if crate::hh_agent_abi_version() != crate::ABI_VERSION
        || crate::hh_agent_initialize_from_env() != HH_OK
    {
        return ERROR_DLL_INIT_FAILED;
    }
    if let Err(error) = initialize_builtin_plugins() {
        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
            eprintln!("hyperhub-gum: failed to initialize hook plugins: {error}");
        }
        return ERROR_DLL_INIT_FAILED;
    }
    gum_init_embedded();
    let interceptor = gum_interceptor_obtain();
    if interceptor.is_null() {
        return ERROR_DLL_INIT_FAILED;
    }
    let report = HookManager::new(interceptor).install_builtin_hooks();
    if !manager::start_msys_runtime_hook_watcher(interceptor) {
        return ERROR_DLL_INIT_FAILED;
    }
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
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
        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
            eprintln!("hyperhub-gum: failed to publish hook manifest: {error}");
        }
        return ERROR_DLL_INIT_FAILED;
    }
    AGENT_OWNER_PID.store(GetCurrentProcessId(), Ordering::Release);
    RUNTIME_GENERATION.store(1, Ordering::Release);
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
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
    signal_agent_event("HYPERHUB_LOADED_EVENT");
    signal_agent_event("HYPERHUB_READY_EVENT");
    signal_inherited_child_event();
    // Gum intentionally remains initialized for the injected process lifetime.
    0
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    instance: HMODULE,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason != DLL_PROCESS_ATTACH {
        return 1;
    }
    AGENT_MODULE.store(instance as usize, Ordering::Release);
    if adapters::process::is_current_process_msys_fork_bootstrap() {
        return 1;
    }
    if AGENT_STARTED.swap(true, Ordering::AcqRel) {
        return 1;
    }
    let worker = CreateThread(null(), 0, Some(initialize_gum_agent), null(), 0, null_mut());
    if worker.is_null() {
        AGENT_STARTED.store(false, Ordering::Release);
        return 0;
    }
    CloseHandle(worker);
    1
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
        for hook_id in GETADDRINFO..=LDR_LOAD_DLL {
            assert!(!hh_gum_replacement(hook_id).is_null());
        }
        assert!(hh_gum_replacement(0).is_null());
        assert!(hh_gum_replacement(LDR_LOAD_DLL + 1).is_null());
    }
}
