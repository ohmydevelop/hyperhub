mod adapters;
pub(crate) mod fork;
mod fork_handoff;
pub(crate) mod gum;
mod manager;

use std::ffi::CStr;

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
    let result = fork::rebuild();
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
    let status = match fork::publish() {
        Ok(()) => {
            if !stay_resident.is_null() {
                stay_resident.write(1);
            }
            "ok".to_owned()
        }
        Err(error) => format!("error:{error}"),
    };
    signal_ready(data, &status);
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

unsafe fn signal_ready(path: *const libc::c_char, status: &str) {
    if path.is_null() {
        return;
    }
    let path = CStr::from_ptr(path);
    let fd = libc::syscall(
        libc::SYS_openat,
        libc::AT_FDCWD,
        path.as_ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    ) as libc::c_int;
    if fd < 0 {
        return;
    }
    let bytes = status.as_bytes();
    let mut written = 0usize;
    while written < bytes.len() {
        let result = libc::syscall(
            libc::SYS_write,
            fd,
            bytes.as_ptr().add(written),
            bytes.len() - written,
        );
        if result <= 0 {
            break;
        }
        written += result as usize;
    }
    let _ = libc::syscall(libc::SYS_close, fd);
}

pub(crate) fn with_host_io<T>(call: impl FnOnce() -> T) -> T {
    let _guard = adapters::native::HookGuard::enter();
    call()
}
