mod adapters;
mod exec_bridge;
pub(crate) mod fork;
mod fork_handoff;
pub(crate) mod gum;
mod manager;
mod mappings;

use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static NATIVE_INSTALL_PID: AtomicU32 = AtomicU32::new(0);
static NATIVE_NEEDS_ARM: AtomicBool = AtomicBool::new(false);
static NATIVE_ARM_CONFIRMED: AtomicBool = AtomicBool::new(false);
static NATIVE_INITIAL_OWNED_PENDING: AtomicBool = AtomicBool::new(false);

fn native_installation_complete() -> Result<(), i32> {
    exec_bridge::initialize_owner();
    if !crate::attachment::managed() {
        return Ok(());
    }
    let bootstrap = crate::attachment::bootstrap().ok_or(crate::HH_ERR_NOT_INITIALIZED)?;
    NATIVE_ARM_CONFIRMED.store(false, Ordering::Release);
    NATIVE_NEEDS_ARM.store(bootstrap.scope_tree, Ordering::Release);
    NATIVE_INITIAL_OWNED_PENDING.store(bootstrap.initially_owned, Ordering::Release);
    NATIVE_INSTALL_PID.store(std::process::id(), Ordering::Release);
    Ok(())
}
pub(super) fn native_arm_confirmed() {
    NATIVE_ARM_CONFIRMED.store(true, Ordering::Release);
}
pub(super) fn native_rearm_begin() {
    if NATIVE_INSTALL_PID.load(Ordering::Acquire) == std::process::id() {
        crate::attachment::clear_native_ready();
        NATIVE_ARM_CONFIRMED.store(false, Ordering::Release);
        NATIVE_NEEDS_ARM.store(true, Ordering::Release);
    }
}
pub(super) fn native_arm_installed() {
    if NATIVE_INSTALL_PID.load(Ordering::Acquire) != std::process::id()
        || !NATIVE_ARM_CONFIRMED.load(Ordering::Acquire)
        || !NATIVE_NEEDS_ARM.load(Ordering::Acquire)
    {
        return;
    }
    NATIVE_NEEDS_ARM.store(false, Ordering::Release);
    finish_native_ready();
}
fn finish_native_ready() {
    if !crate::attachment::managed() {
        return;
    }
    if NATIVE_INSTALL_PID.load(Ordering::Acquire) != std::process::id()
        || NATIVE_NEEDS_ARM.load(Ordering::Acquire)
        || !exec_bridge::confirmed()
    {
        return;
    }
    if crate::attachment::mark_native_ready().is_err() {
        return;
    }
    if NATIVE_INITIAL_OWNED_PENDING.swap(false, Ordering::AcqRel)
        && !crate::attachment::logically_detached()
        && crate::attachment::activate_initial_owned().is_err()
    {
        NATIVE_INITIAL_OWNED_PENDING.store(true, Ordering::Release);
        crate::attachment::clear_native_ready();
        return;
    }
}

// These native-only calls are made by the verified executor's Core script.
// Remove/reinstall additionally reject confirmed/inherited/live generations.
#[no_mangle]
pub extern "C" fn hyperhub_exec_monitor_prepare() -> i32 {
    crate::engine_call::background(|| {
        exec_bridge::prepare();
        crate::attachment::clear_native_ready();
        crate::HH_OK
    })
}
#[no_mangle]
pub extern "C" fn hyperhub_exec_monitor_remove_fresh() -> i32 {
    crate::engine_call::background(|| {
        exec_bridge::remove_fresh().map_or_else(|e| e, |_| crate::HH_OK)
    })
}
#[no_mangle]
pub extern "C" fn hyperhub_exec_monitor_reinstall_fresh() -> i32 {
    crate::engine_call::background(|| {
        exec_bridge::reinstall_fresh().map_or_else(|e| e, |_| crate::HH_OK)
    })
}
#[no_mangle]
pub extern "C" fn hyperhub_exec_monitor_confirm() -> i32 {
    crate::engine_call::background(|| match exec_bridge::confirm() {
        Ok(()) => {
            finish_native_ready();
            crate::HH_OK
        }
        Err(e) => e,
    })
}

pub(crate) fn resolve_native_addresses(
    hostname: &str,
    family: u32,
) -> Result<Vec<crate::NativeDnsAddress>, i32> {
    adapters::native::resolve_native_addresses(hostname, family)
}

pub(crate) fn prepare_activation_transition(
    change: impl FnOnce() -> Result<(), i32>,
) -> Result<(), i32> {
    fork::prepare_activation_transition(change)
}

pub(crate) fn initialize_mapping_probe() -> Result<(), String> {
    let policy = crate::state()
        .lock()
        .map_err(|_| "mapping policy state is unavailable")?
        .sandbox
        .file
        .clone();
    mappings::initialize(policy)
}

#[no_mangle]
pub unsafe extern "C" fn frida_agent_main(data: *const libc::c_char, stay_resident: *mut u32) {
    let result = initialize();
    if let Err(error) = &result {
        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
            eprintln!("hyperhub-gum: Linux Agent initialization failed: {error}");
        }
    }
    let status = match result {
        Ok(()) => {
            if !stay_resident.is_null() {
                stay_resident.write(1);
            }
            "ok".to_string()
        }
        Err(error) => format!("error:{error}"),
    };
    signal_ready(data, &status);
}

/// Frida calls this entry while the fork child remains gated. Child atfork
/// callbacks performed no allocation, IO, logging or module loading.
#[no_mangle]
pub unsafe extern "C" fn frida_fork_agent_main(data: *const libc::c_char, stay_resident: *mut u32) {
    let result = fork::rebuild().map(|()| exec_bridge::initialize_owner());
    let status = match result {
        Ok(()) => {
            if !stay_resident.is_null() {
                stay_resident.write(1);
            }
            "ok".to_owned()
        }
        Err(e) => format!("error:{e}"),
    };
    signal_ready(data, &status);
}

/// The manager publishes a rebuilt child only after its next-fork gate is armed.
#[no_mangle]
pub unsafe extern "C" fn frida_fork_publish_main(
    data: *const libc::c_char,
    stay_resident: *mut u32,
) {
    let result = fork::publish(|| {
        if !stay_resident.is_null() {
            stay_resident.write(1);
        }
        signal_publication_ready(data, b"ok")
    });
    if let Err(error) = result {
        let _ = signal_publication_ready(data, format!("error:{error}").as_bytes());
    }
}

fn initialize() -> Result<(), String> {
    crate::engine_call::initialize_thread_slots()
        .map_err(|code| format!("cannot initialize native TLS slots: {code}"))?;
    if crate::hh_agent_abi_version() != crate::ABI_VERSION {
        return Err("Agent ABI version mismatch".into());
    }
    let status = crate::hh_agent_initialize_from_env();
    if status != crate::HH_OK {
        return Err(format!("Agent bootstrap failed with status {status}"));
    }
    let report = manager::install()?;
    adapters::native::warm_originals();
    exec_bridge::initialize_owner();
    fork::install()?;
    adapters::native::install_hook_report();
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
        eprintln!(
            "hyperhub-gum: Linux hooks installed={} optional_missing={} manifest={}",
            report.installed,
            report.optional_missing.len(),
            manager::manifest().len()
        );
    }
    Ok(())
}

/// Publish complete bytes atomically while the original application thread is
/// still held. The final pathname never exposes a partially written receipt.
unsafe fn signal_publication_ready(
    path: *const libc::c_char,
    bytes: &[u8],
) -> Result<(), &'static str> {
    if path.is_null() {
        return Err("fork publication receipt path is missing");
    }
    let path = CStr::from_ptr(path);
    let mut temporary = path.to_bytes().to_vec();
    temporary.extend_from_slice(b".pending");
    let temporary =
        std::ffi::CString::new(temporary).map_err(|_| "invalid fork publication receipt path")?;
    let fd = libc::syscall(
        libc::SYS_openat,
        libc::AT_FDCWD,
        temporary.as_ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    ) as libc::c_int;
    if fd < 0 {
        return Err("cannot create fork publication receipt");
    }
    let mut offset = 0;
    while offset < bytes.len() {
        let count = libc::syscall(
            libc::SYS_write,
            fd,
            bytes.as_ptr().add(offset),
            bytes.len() - offset,
        );
        if count < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        if count <= 0 {
            libc::syscall(libc::SYS_close, fd);
            libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, temporary.as_ptr(), 0);
            return Err("cannot write fork publication receipt");
        }
        offset += count as usize;
    }
    if libc::syscall(libc::SYS_close, fd) != 0 {
        libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, temporary.as_ptr(), 0);
        return Err("cannot close fork publication receipt");
    }
    if libc::syscall(
        libc::SYS_renameat2,
        libc::AT_FDCWD,
        temporary.as_ptr(),
        libc::AT_FDCWD,
        path.as_ptr(),
        libc::RENAME_NOREPLACE,
    ) != 0
    {
        libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, temporary.as_ptr(), 0);
        return Err("cannot commit fork publication receipt");
    }
    Ok(())
}

unsafe fn signal_ready(path: *const libc::c_char, status: &str) {
    // The controller treats existence as the beginning of a complete receipt,
    // so expose the final pathname only after all bytes and close succeeded.
    // A failed staging write/rename intentionally leaves no success ACK.
    let _ = signal_publication_ready(path, status.as_bytes());
}

pub(crate) fn with_host_io<T>(call: impl FnOnce() -> T) -> T {
    let _guard = adapters::native::HookGuard::enter();
    call()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentEnvelope {
    bootstrap: hyperhub_runtime::attachment::Bootstrap,
    ready_path: String,
    fork_socket: String,
    fork_secret: String,
    runtime_path: String,
}

#[derive(serde::Serialize)]
struct AttachmentNativePin {
    fd: i32,
    device: u64,
    inode: u64,
}
static ATTACHMENT_NATIVE_PIN: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();
fn pin_attachment_runtime(path: &str) -> Result<AttachmentNativePin, String> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    if ATTACHMENT_NATIVE_PIN.get().is_none() {
        let file = std::fs::File::open(path)
            .map_err(|error| format!("cannot pin native attachment runtime: {error}"))?;
        let _ = ATTACHMENT_NATIVE_PIN.set(file);
    }
    let file = ATTACHMENT_NATIVE_PIN
        .get()
        .ok_or("native attachment pin is unavailable")?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    Ok(AttachmentNativePin {
        fd: file.as_raw_fd(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

/// Entry for a manager-authorized live target. No process environment is read
/// for bootstrap and no application stream is used for management output.
#[no_mangle]
pub unsafe extern "C" fn frida_attachment_main(data: *const libc::c_char, stay_resident: *mut u32) {
    attachment_entry(data, stay_resident, false);
}
#[no_mangle]
pub unsafe extern "C" fn frida_attachment_fork_main(
    data: *const libc::c_char,
    stay_resident: *mut u32,
) {
    attachment_entry(data, stay_resident, true);
}
unsafe fn attachment_entry(data: *const libc::c_char, stay_resident: *mut u32, child: bool) {
    let _native_initialization = crate::attachment::enter_allocator();
    if data.is_null() {
        return;
    }
    let bytes = CStr::from_ptr(data).to_bytes();
    if bytes.len() > hyperhub_runtime::attachment::MAX_FRAME {
        return;
    }
    let Ok(envelope) = serde_json::from_slice::<AttachmentEnvelope>(bytes) else {
        return;
    };
    let Ok(ready) = std::ffi::CString::new(envelope.ready_path.as_bytes()) else {
        return;
    };
    if !stay_resident.is_null() {
        stay_resident.write(1);
    }
    let mut startup = None;
    let result = crate::engine_call::background(|| -> Result<AttachmentNativePin, String> {
        use hyperhub_runtime::attachment::InitializationStage as Stage;
        envelope.bootstrap.validate().map_err(|e| e.to_string())?;
        startup = Some(
            crate::attachment::bind_metadata_for_startup(&envelope.bootstrap, child)
                .map_err(|code| format!("attachment metadata binding failed: {code}"))?
                .ok_or("attachment initialization was already dispatched")?,
        );
        // This rollback channel exists before any Engine, pin, registration or
        // Hook mutation. Early child diagnostics never read copied Runtime locks.
        crate::attachment::start_server()
            .map_err(|code| format!("attachment control server failed: {code}"))?;
        let pin = crate::attachment::with_state_mutation(|| {
            crate::attachment::startup::check()
                .map_err(|_| "attachment initialization cancelled")?;
            let pin = pin_attachment_runtime(&envelope.runtime_path)?;
            crate::attachment::startup::set_pin(
                hyperhub_runtime::attachment::InitializationNativePin {
                    fd: pin.fd,
                    device: pin.device,
                    inode: pin.inode,
                },
            );
            Ok(pin)
        })?;
        crate::attachment::startup::check().map_err(|_| "attachment initialization cancelled")?;
        if child {
            crate::attachment::startup::stage(Stage::Engine)
                .map_err(|_| "attachment initialization cancelled")?;
            fork::rebuild()?;
        } else {
            crate::engine_call::initialize_thread_slots()
                .map_err(|code| format!("attachment thread slots failed: {code}"))?;
            crate::attachment::startup::stage(Stage::Registering)
                .map_err(|_| "attachment initialization cancelled")?;
            crate::register_unix_process(
                &envelope.bootstrap.control_endpoint,
                &envelope.bootstrap.session_id,
                &envelope.bootstrap.token,
                &crate::control::StartupDeadline::new(),
            )
            .map_err(|code| format!("attachment member registration failed: {code}"))?;
            crate::attachment::startup::stage(Stage::Engine)
                .map_err(|_| "attachment initialization cancelled")?;
            crate::attachment::initialize_bound(&envelope.bootstrap)
                .map_err(|code| format!("attachment bootstrap failed: {code}"))?;
            crate::attachment::startup::stage(Stage::ForkBroker)
                .map_err(|_| "attachment initialization cancelled")?;
            fork_handoff::initialize_explicit(
                std::ffi::OsStr::new(&envelope.fork_socket),
                &envelope.fork_secret,
            )?;
            crate::attachment::startup::stage(Stage::InstallingHooks)
                .map_err(|_| "attachment initialization cancelled")?;
            manager::install()?;
            adapters::native::warm_originals();
            crate::attachment::startup::stage(Stage::Atfork)
                .map_err(|_| "attachment initialization cancelled")?;
            fork::install()?;
            install_initial_owned_report(&envelope.bootstrap)?;
        }
        crate::attachment::startup::stage(Stage::AliasCatchup)
            .map_err(|_| "attachment initialization cancelled")?;
        crate::attachment::initialize_alias_host()
            .map_err(|code| format!("attachment alias history failed: {code}"))?;
        native_installation_complete()
            .map_err(|code| format!("native attachment readiness failed: {code}"))?;
        crate::attachment::startup::check().map_err(|_| "attachment initialization cancelled")?;
        Ok(pin)
    });
    let mut success = result.is_ok();
    let status = match result {
        Ok(pin) => serde_json::to_string(&serde_json::json!({"status":"ok","native_pin":pin}))
            .unwrap_or_else(|_| "error:cannot encode native pin".into()),
        Err(error) => format!("error:{error}"),
    };
    crate::engine_call::background(|| {
        if success {
            // Detach/cancellation and success publication share the same state gate.
            // The receipt is only a notification: authenticated Status remains the
            // source of recovery metadata if its atomic file publication fails.
            if crate::attachment::with_state_mutation(|| {
                crate::attachment::startup::check()
                    .map_err(|_| "attachment initialization cancelled")?;
                signal_ready(ready.as_ptr(), &status);
                Ok(())
            })
            .is_err()
            {
                success = false;
            }
        } else {
            signal_ready(ready.as_ptr(), &status);
        }
    });
    if let Some(startup) = startup {
        startup.finish(success);
    }
}

fn install_initial_owned_report(
    bootstrap: &hyperhub_runtime::attachment::Bootstrap,
) -> Result<(), String> {
    if !bootstrap.initially_owned
        || crate::attachment::startup::origin()
            != hyperhub_runtime::attachment::InitializationOrigin::Fresh
    {
        return Ok(());
    }
    // Only the fresh launcher owns this environment contract. An external
    // target's existing environment must never enable exit/report files.
    crate::attachment::with_state_mutation(|| {
        crate::attachment::startup::check().map_err(|_| "attachment initialization cancelled")?;
        adapters::native::install_hook_report();
        Ok(())
    })
}

pub(crate) fn retire_attachment_callbacks() -> Result<(), String> {
    // POSIX atfork callbacks and Core-owned return listeners can still execute
    // after policy detachment. Keep their module pinned until a complete,
    // independently verifiable retirement protocol has removed them.
    if fork::callbacks_installed() {
        return Err("registered_fork_callbacks_require_resident_module".into());
    }
    manager::uninstall_owned()
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    #[test]
    fn initialization_ready_uses_atomic_private_receipt_and_staging_failure_leaves_no_ack() {
        use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
        let root =
            std::env::temp_dir().join(format!("hyperhub-init-receipt-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("ready");
        let staging = root.join("ready.pending");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // A staging collision is a real failure, not permission to create a
        // success file by bypassing the checked atomic commit protocol.
        std::fs::write(&staging, b"another pending receipt").unwrap();
        unsafe { signal_ready(name.as_ptr(), "ok") };
        assert!(!path.exists());
        assert_eq!(std::fs::read(&staging).unwrap(), b"another pending receipt");
        std::fs::remove_file(&staging).unwrap();
        let status =
            serde_json::json!({"status":"ok","native_pin_payload":"x".repeat(65536)}).to_string();
        unsafe { signal_ready(name.as_ptr(), &status) };
        assert_eq!(std::fs::read(&path).unwrap(), status.as_bytes());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!staging.exists());
        unsafe { signal_ready(name.as_ptr(), "error:replacement") };
        assert_eq!(std::fs::read(&path).unwrap(), status.as_bytes());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn publication_receipt_is_complete_private_and_never_overwrites_an_existing_ack() {
        use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "hyperhub-fork-receipt-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("receipt");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        unsafe { signal_publication_ready(name.as_ptr(), b"ok") }.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"ok");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(unsafe { signal_publication_ready(name.as_ptr(), b"error:replacement") }.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"ok");
        assert!(!root.join("receipt.pending").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
