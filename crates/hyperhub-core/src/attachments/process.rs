use super::ProcessIdentity;
use sha2::{Digest, Sha256};
use std::io::Read;

/// Dynamic process identity is deliberately unavailable on other platforms;
/// ordinary Serve and configuration operations must not depend on it.
pub const fn process_attachment_identity_available() -> bool {
    cfg!(any(windows, target_os = "linux"))
}

#[derive(Clone, PartialEq, Eq)]
struct ImageFingerprint {
    length: u64,
    modified: Option<std::time::SystemTime>,
    created: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    ctime: (i64, i64),
    #[cfg(windows)]
    file_identity: (u32, u64),
}
fn image_fingerprint(file: &std::fs::File) -> Result<ImageFingerprint, String> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    let file_identity = {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        (
            information.dwVolumeSerialNumber,
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        )
    };
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    Ok(ImageFingerprint {
        length: m.len(),
        modified: m.modified().ok(),
        created: m.created().ok(),
        #[cfg(unix)]
        device: m.dev(),
        #[cfg(unix)]
        inode: m.ino(),
        #[cfg(unix)]
        ctime: (m.ctime(), m.ctime_nsec()),
        #[cfg(windows)]
        file_identity,
    })
}
fn hash_image(file: &mut std::fs::File) -> Result<String, String> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn inspect_process(pid: u32) -> Result<ProcessIdentity, String> {
    let birth = crate::session::process_start_time(pid)
        .filter(|b| *b != 0)
        .ok_or("cannot identify attachment target creation time")?;
    if process_incarnation_exited(pid, birth) {
        return Err("attachment target process has exited".into());
    }
    let executable = crate::control::process_path(pid).map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    let image = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
    #[cfg(not(target_os = "linux"))]
    let image = executable.clone();
    let mut file =
        std::fs::File::open(image).map_err(|e| format!("cannot pin target executable: {e}"))?;
    let fingerprint = image_fingerprint(&file)?;
    let executable_sha256 = if pid == std::process::id() {
        static OWN_IMAGE: std::sync::Mutex<Option<(ImageFingerprint, String)>> =
            std::sync::Mutex::new(None);
        let mut cache = OWN_IMAGE
            .lock()
            .map_err(|_| "executor fingerprint cache is unavailable")?;
        if let Some((observed, digest)) = cache
            .as_ref()
            .filter(|(observed, _)| observed == &fingerprint)
        {
            let _ = observed;
            digest.clone()
        } else {
            let digest = hash_image(&mut file)?;
            if image_fingerprint(&file)? != fingerprint {
                return Err("executor image changed while hashing".into());
            }
            *cache = Some((fingerprint.clone(), digest.clone()));
            digest
        }
    } else {
        // Reuse only this process's exact pinned executable object, never a
        // target path/mtime cache. This is common for authenticated CLI peers.
        #[cfg(target_os = "linux")]
        let own_path = std::path::PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let own_path = std::env::current_exe().map_err(|e| e.to_string())?;
        let own_file = std::fs::File::open(own_path).map_err(|e| e.to_string())?;
        let digest = if image_fingerprint(&own_file)? == fingerprint {
            inspect_process(std::process::id())?.executable_sha256
        } else {
            hash_image(&mut file)?
        };
        if image_fingerprint(&file)? != fingerprint {
            return Err("target image changed while hashing".into());
        }
        digest
    };
    let owner = process_owner(pid)?;
    if crate::session::process_start_time(pid) != Some(birth)
        || crate::control::process_path(pid).map_err(|e| e.to_string())? != executable
    {
        return Err("target identity changed while inspecting it".into());
    }
    Ok(ProcessIdentity {
        pid,
        birth,
        executable: executable.to_string_lossy().into_owned(),
        executable_sha256,
        owner,
    })
}
/// Validate the actual API-only launcher incarnation. This deliberately does
/// not authenticate executable bytes and must never authorize administrator
/// actions; those paths use verify_process and the password-signed executor.
pub(crate) fn verify_launch_origin(expected: &ProcessIdentity) -> Result<(), String> {
    expected.validate()?;
    let birth = crate::session::process_start_time(expected.pid);
    let executable = crate::control::process_path(expected.pid).map_err(|e| e.to_string())?;
    let owner = process_owner(expected.pid)?;
    if birth != Some(expected.birth)
        || executable.to_string_lossy() != expected.executable
        || owner != expected.owner
        || crate::session::process_start_time(expected.pid) != birth
        || crate::control::process_path(expected.pid).map_err(|e| e.to_string())? != executable
    {
        return Err("owned launcher creation identity, path or owner changed".into());
    }
    Ok(())
}
pub fn verify_process(expected: &ProcessIdentity) -> Result<(), String> {
    expected.validate()?;
    let current = inspect_process(expected.pid)?;
    if &current != expected {
        return Err("target creation identity, executable or owner changed".into());
    }
    Ok(())
}
pub fn verify_manager_creator(creator: &ProcessIdentity) -> Result<(), String> {
    verify_process(creator)?;
    let own = inspect_process(std::process::id())?;
    if creator.owner != own.owner
        || creator.executable_sha256 != own.executable_sha256
        || !crate::control::process_ancestors(own.pid).contains(&creator.pid)
    {
        return Err("private manager bootstrap requires its actual trusted creator".into());
    }
    Ok(())
}
pub fn verify_created_manager(
    creator: &ProcessIdentity,
    child: &ProcessIdentity,
) -> Result<(), String> {
    verify_process(creator)?;
    verify_process(child)?;
    if creator.pid != std::process::id()
        || creator.owner != child.owner
        || creator.executable_sha256 != child.executable_sha256
        || !crate::control::process_ancestors(child.pid).contains(&creator.pid)
    {
        return Err("manager bootstrap is not this creator's actual child executable".into());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn process_owner(pid: u32) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/proc/{pid}"))
        .map(|m| m.uid().to_string())
        .map_err(|e| e.to_string())
}
#[cfg(windows)]
fn process_owner(pid: u32) -> Result<String, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut token = std::ptr::null_mut();
        let ok = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        CloseHandle(process);
        if ok == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let result = (|| {
            let mut n = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut n);
            if n < std::mem::size_of::<TOKEN_USER>() as u32 {
                return Err("target owner token is unavailable".to_string());
            }
            let mut buffer = vec![0usize; (n as usize).div_ceil(std::mem::size_of::<usize>())];
            if GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), n, &mut n) == 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            let mut sid = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let mut count = 0;
            while *sid.add(count) != 0 {
                count += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(sid, count));
            LocalFree(sid.cast());
            Ok(text)
        })();
        CloseHandle(token);
        result
    }
}
#[cfg(not(any(windows, target_os = "linux")))]
fn process_owner(_pid: u32) -> Result<String, String> {
    Err("dynamic attachment is unsupported on this platform".into())
}

pub fn policy_digest(config: &crate::config::Config) -> Result<String, String> {
    let value = serde_json::to_value(crate::config_document::ConfigDocument::from_config(
        &config.redacted(),
    ))
    .map_err(|e| e.to_string())?;
    policy_digest_view(&value)
}
pub fn policy_digest_view(value: &serde_json::Value) -> Result<String, String> {
    Ok(super::digest(
        &serde_json::to_vec(value).map_err(|e| e.to_string())?,
    ))
}

pub fn executor_digest() -> Result<String, String> {
    Ok(inspect_process(std::process::id())?.executable_sha256)
}
pub fn bootstrap_digest(
    bootstrap: &hyperhub_runtime::attachment::Bootstrap,
) -> Result<String, String> {
    Ok(super::digest(
        &serde_json::to_vec(bootstrap).map_err(|e| e.to_string())?,
    ))
}
pub fn verify_execution(
    directory: &std::path::Path,
    execution: &super::Execution,
) -> Result<(), String> {
    let action = &execution.authorization.request.action;
    let recovery = action.recovery();
    if execution.origin != super::Origin::Attach && recovery.is_none() {
        return Err("external manager cannot claim implicit run ownership".into());
    }
    super::verify_authorization(directory, &execution.authorization)?;
    if execution.authorization.manager_claimant.as_ref()
        != Some(&super::manager_operation_claimant()?)
    {
        return Err(
            "manager execution is signed for a different delegated key or incarnation".into(),
        );
    }
    match action {
        super::Action::Attach { spec } if spec == &execution.spec => (),
        super::Action::Detach {
            attachment_id,
            target,
            ..
        } if recovery.is_some()
            && attachment_id == &execution.spec.id
            && execution.spec.target.same_incarnation(target)
            && action.exec_epoch() == execution.spec.exec_epoch =>
        {
            ()
        }
        _ => return Err("manager execution does not match its signed action".into()),
    }
    if execution.authorization.executor_sha256 != executor_digest()? {
        return Err("manager executable differs from administrator authorization".into());
    }
    if execution.authorization.execution_digest.as_deref()
        != Some(bootstrap_digest(&execution.bootstrap)?.as_str())
    {
        return Err("attachment bootstrap differs from administrator authorization".into());
    }
    if execution.authorization.host_binding.as_deref()
        != Some(
            execution
                .bootstrap
                .approval_binding()
                .map_err(|e| e.to_string())?
                .as_str(),
        )
    {
        return Err("Host identity differs from administrator authorization".into());
    }
    if let Some(binding) = recovery {
        binding.manager.validate()?;
        let record = super::load_record(&execution.state_directory)?;
        if record.manager.as_ref() != Some(&binding.manager)
            || !process_incarnation_exited(binding.manager.pid, binding.manager.birth)
            || record.spec.target != execution.spec.target
            || record.spec.scope != execution.spec.scope
            || record.spec.backend != execution.spec.backend
            || record.origin != execution.origin
        {
            return Err(
                "recovery must replace exactly the vanished manager of this recorded target".into(),
            );
        }
    } else if execution.bootstrap.initially_owned {
        return Err("external attachment cannot claim suspended owned-run startup".into());
    }
    if execution.bootstrap.attachment_id != execution.spec.id
        || execution.bootstrap.root_pid != execution.spec.target.pid
        || execution.bootstrap.scope_tree != (execution.spec.scope == super::Scope::Tree)
    {
        return Err("attachment bootstrap scope differs from approved target".into());
    }
    execution.bootstrap.validate().map_err(|e| e.to_string())
}

/// Prove that this exact process incarnation has exited. Query failures are
/// unknown, so they never authorize adoption of another manager's operation.
/// Windows retains creation times while any observer holds a process handle.
pub fn process_incarnation_exited(pid: u32, birth: u64) -> bool {
    if let Some(actual) = crate::session::process_start_time(pid) {
        if actual != birth {
            return true;
        }
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::{
            Foundation::{
                CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, FILETIME, WAIT_OBJECT_0,
            },
            System::Threading::{
                GetProcessTimes, OpenProcess, WaitForSingleObject,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            },
        };
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        );
        if handle.is_null() {
            return GetLastError() == ERROR_INVALID_PARAMETER;
        }
        let mut creation: FILETIME = std::mem::zeroed();
        let mut exit: FILETIME = std::mem::zeroed();
        let mut kernel: FILETIME = std::mem::zeroed();
        let mut user: FILETIME = std::mem::zeroed();
        let read = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
        let actual = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        let gone =
            (read != 0 && actual != birth) || WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
        CloseHandle(handle);
        gone
    }
    #[cfg(not(windows))]
    {
        crate::engine_hosts::EngineHosts::process_is_gone(pid, birth)
    }
}

/// Read only the OS incarnation marker without hashing an executable.
pub fn process_birth(pid: u32) -> Option<u64> {
    crate::session::process_start_time(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exited_manager_fixture() {
        if std::env::var_os("HYPERHUB_TEST_EXITED_MANAGER").is_some() {
            use std::io::Read;
            std::io::stdin().read_exact(&mut [0; 1]).unwrap();
            // 259 is STILL_ACTIVE's value, but is also a legitimate exit code.
            std::process::exit(259);
        }
    }
    #[test]
    #[cfg(any(windows, target_os = "linux"))]
    fn exited_incarnation_is_not_live_while_parent_retains_its_process_handle() {
        use std::io::Write;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "attachments::process::tests::exited_manager_fixture",
            ])
            .env("HYPERHUB_TEST_EXITED_MANAGER", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let birth = process_birth(pid).unwrap();
        assert!(!process_incarnation_exited(pid, birth));
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
        let status = child.wait().unwrap();
        #[cfg(windows)]
        assert_eq!(status.code(), Some(259));
        #[cfg(target_os = "linux")]
        assert_eq!(status.code(), Some(3));
        assert!(process_incarnation_exited(pid, birth));
        #[cfg(windows)]
        assert_eq!(
            process_birth(pid),
            Some(birth),
            "held Windows handle retains the creation marker after exit"
        );
        assert!(inspect_process(pid).is_err());
        drop(child);
    }
    #[test]
    fn pinned_image_cache_identity_distinguishes_equal_length_replacements() {
        let root = std::env::temp_dir().join(format!(
            "hh-image-identity-{}",
            crate::attachments::new_id()
        ));
        std::fs::create_dir(&root).unwrap();
        let a = root.join("a");
        let b = root.join("b");
        std::fs::write(&a, b"first!").unwrap();
        std::fs::write(&b, b"second").unwrap();
        let first = std::fs::File::open(&a).unwrap();
        let second = std::fs::File::open(&b).unwrap();
        assert!(image_fingerprint(&first).unwrap() != image_fingerprint(&second).unwrap());
        drop(first);
        drop(second);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod launch_origin_tests {
    use super::*;
    #[test]
    fn launch_origin_is_not_privileged_code_authentication() {
        let own = inspect_process(std::process::id()).unwrap();
        let mut advertised = own.clone();
        advertised.executable_sha256 = if own.executable_sha256 == "ff".repeat(32) {
            "aa".repeat(32)
        } else {
            "ff".repeat(32)
        };
        verify_launch_origin(&advertised).unwrap();
        assert!(verify_process(&advertised).is_err());
        advertised.birth += 1;
        assert!(verify_launch_origin(&advertised).is_err());
        advertised = own;
        advertised.executable.push_str("-not-the-actual-path");
        assert!(verify_launch_origin(&advertised).is_err());
    }
}
