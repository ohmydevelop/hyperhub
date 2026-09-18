use sha2::{Digest, Sha256};
use std::fs::File;
#[cfg(feature = "embedded-agent")]
use std::fs::OpenOptions;
#[cfg(feature = "embedded-agent")]
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(feature = "embedded-agent")]
include!(concat!(env!("OUT_DIR"), "/embedded_agent_meta.rs"));

#[cfg(feature = "embedded-agent")]
const EMBEDDED_AGENT_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/embedded-agent.bin"));

pub(crate) const fn provider_name() -> &'static str {
    #[cfg(feature = "embedded-agent")]
    {
        "embedded-verified"
    }
    #[cfg(all(not(feature = "embedded-agent"), feature = "external-runtime"))]
    {
        "external-development"
    }
    #[cfg(not(any(feature = "embedded-agent", feature = "external-runtime")))]
    {
        "unavailable"
    }
}

pub(crate) struct AgentRuntime {
    display_path: PathBuf,
    load_path: PathBuf,
    expected_sha256: Option<[u8; 32]>,
    expected_size: Option<usize>,
    _guard: Option<File>,
    _directory_guards: Vec<File>,
}

impl AgentRuntime {
    #[cfg(feature = "external-runtime")]
    pub(crate) fn external(path: &Path) -> Result<Self, String> {
        let path = path
            .canonicalize()
            .map_err(|error| format!("cannot resolve Agent runtime {}: {error}", path.display()))?;
        Ok(Self {
            display_path: path.clone(),
            load_path: path,
            expected_sha256: None,
            expected_size: None,
            _guard: None,
            _directory_guards: Vec::new(),
        })
    }

    #[cfg(feature = "embedded-agent")]
    pub(crate) fn embedded() -> Result<Self, String> {
        if EMBEDDED_AGENT_BYTES.len() != EMBEDDED_AGENT_SIZE {
            return Err("embedded Agent size metadata is inconsistent".into());
        }
        let actual = sha256_bytes(EMBEDDED_AGENT_BYTES);
        if actual != EMBEDDED_AGENT_SHA256 {
            return Err("embedded Agent bytes do not match the compiled SHA-256".into());
        }
        materialize_embedded()
    }

    pub(crate) fn display_path(&self) -> &Path {
        &self.display_path
    }

    pub(crate) fn load_path(&self) -> &Path {
        &self.load_path
    }

    pub(crate) fn verify(&self) -> Result<(), String> {
        let Some(expected) = self.expected_sha256 else {
            return Ok(());
        };
        let expected_size = self.expected_size.expect("embedded Agent records size");
        let guard = self
            ._guard
            .as_ref()
            .ok_or("embedded Agent file guard is missing")?;
        verify_file(guard, expected_size, expected)
    }

    pub(crate) fn integrity_environment(&self) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        match (self.expected_sha256, self.expected_size) {
            (Some(hash), Some(size)) => vec![
                ("HYPERHUB_AGENT_SHA256".into(), hex(&hash).into()),
                ("HYPERHUB_AGENT_SIZE".into(), size.to_string().into()),
            ],
            _ => Vec::new(),
        }
    }
}

#[cfg(feature = "embedded-agent")]
fn materialize_embedded() -> Result<AgentRuntime, String> {
    let hash = hex(&EMBEDDED_AGENT_SHA256);
    let directory = runtime_directory(&hash)?;
    let path = directory.join(EMBEDDED_AGENT_NAME);
    let file = materialize_file(&path, EMBEDDED_AGENT_BYTES)?;
    verify_file(&file, EMBEDDED_AGENT_SIZE, EMBEDDED_AGENT_SHA256)?;

    #[cfg(windows)]
    {
        let directory_guards = lock_windows_runtime_directories(&directory)?;
        Ok(AgentRuntime {
            display_path: path.clone(),
            load_path: path,
            expected_sha256: Some(EMBEDDED_AGENT_SHA256),
            expected_size: Some(EMBEDDED_AGENT_SIZE),
            _guard: Some(file),
            _directory_guards: directory_guards,
        })
    }

    #[cfg(target_os = "linux")]
    {
        let sealed = sealed_memfd(EMBEDDED_AGENT_BYTES)?;
        verify_file(&sealed, EMBEDDED_AGENT_SIZE, EMBEDDED_AGENT_SHA256)?;
        let load_path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            std::os::fd::AsRawFd::as_raw_fd(&sealed)
        ));
        drop(file);
        Ok(AgentRuntime {
            display_path: path,
            load_path,
            expected_sha256: Some(EMBEDDED_AGENT_SHA256),
            expected_size: Some(EMBEDDED_AGENT_SIZE),
            _guard: Some(sealed),
            _directory_guards: Vec::new(),
        })
    }
}

#[cfg(feature = "embedded-agent")]
fn runtime_directory(hash: &str) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or("LOCALAPPDATA is required for the embedded Windows Agent")?;
        let hyperhub = base.join("HyperHub");
        ensure_windows_directory(&hyperhub)?;
        let root = hyperhub.join("runtime");
        ensure_windows_directory(&root)?;
        let directory = root.join(hash);
        ensure_windows_directory(&directory)?;
        Ok(directory)
    }

    #[cfg(target_os = "linux")]
    {
        let uid = unsafe { libc::geteuid() };
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|path| private_linux_directory(path, uid).is_ok())
            .unwrap_or_else(|| PathBuf::from(format!("/tmp/hyperhub-{uid}")));
        ensure_linux_directory(&base, uid)?;
        let hyperhub = base.join("hyperhub");
        ensure_linux_directory(&hyperhub, uid)?;
        let root = hyperhub.join("agent");
        ensure_linux_directory(&root, uid)?;
        let directory = root.join(hash);
        ensure_linux_directory(&directory, uid)?;
        Ok(directory)
    }
}

#[cfg(all(feature = "embedded-agent", windows))]
fn ensure_windows_directory(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    std::fs::create_dir_all(path).map_err(|error| {
        format!(
            "cannot create runtime directory {}: {error}",
            path.display()
        )
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect runtime directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "runtime directory is not a regular directory: {}",
            path.display()
        ));
    }
    secure_windows_directory_acl(path)
}

#[cfg(all(feature = "embedded-agent", windows))]
fn secure_windows_directory_acl(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let sid = current_user_sid_string()?;
    let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;{sid})");
    let sddl = std::ffi::OsStr::new(&sddl)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(format!(
                "cannot create runtime ACL: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut path_wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        path_wide.push(0);
        let result = SetFileSecurityW(
            path_wide.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        LocalFree(descriptor.cast());
        if result == 0 {
            return Err(format!(
                "cannot secure runtime directory {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[cfg(all(feature = "embedded-agent", windows))]
fn current_user_sid_string() -> Result<String, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(format!(
                "cannot open process token: {}",
                std::io::Error::last_os_error()
            ));
        }
        let result = (|| {
            let mut length = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
            if length < std::mem::size_of::<TOKEN_USER>() as u32 {
                return Err(format!(
                    "cannot size user token: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
            if GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            ) == 0
            {
                return Err(format!(
                    "cannot read user token: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            let mut sid = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
                return Err(format!(
                    "cannot stringify user SID: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut count = 0usize;
            while *sid.add(count) != 0 {
                count += 1;
            }
            let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid, count));
            LocalFree(sid.cast());
            Ok(value)
        })();
        CloseHandle(token);
        result
    }
}

#[cfg(all(feature = "embedded-agent", windows))]
fn lock_windows_runtime_directories(directory: &Path) -> Result<Vec<File>, String> {
    let runtime = directory
        .parent()
        .ok_or("runtime hash directory has no parent")?;
    let hyperhub = runtime.parent().ok_or("runtime directory has no parent")?;
    [hyperhub, runtime, directory]
        .into_iter()
        .map(open_windows_directory_locked)
        .collect()
}

#[cfg(all(feature = "embedded-agent", windows))]
fn open_windows_directory_locked(path: &Path) -> Result<File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| format!("cannot lock runtime directory {}: {error}", path.display()))
}

#[cfg(all(feature = "embedded-agent", target_os = "linux"))]
fn ensure_linux_directory(path: &Path, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "runtime path is not a regular directory: {}",
                    path.display()
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|error| {
                format!(
                    "cannot create runtime directory {}: {error}",
                    path.display()
                )
            })?;
        }
        Err(error) => {
            return Err(format!(
                "cannot inspect runtime directory {}: {error}",
                path.display()
            ));
        }
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "cannot secure runtime directory {}: {error}",
            path.display()
        )
    })?;
    private_linux_directory(path, uid)
}

#[cfg(all(feature = "embedded-agent", target_os = "linux"))]
fn private_linux_directory(path: &Path, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect runtime directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "runtime directory is not private: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(feature = "embedded-agent")]
fn materialize_file(path: &Path, bytes: &[u8]) -> Result<File, String> {
    if path.exists() {
        return open_locked(path);
    }
    let parent = path.parent().ok_or("Agent runtime path has no parent")?;
    let temporary = parent.join(format!(
        ".{}.{}-{:016x}.tmp",
        EMBEDDED_AGENT_NAME,
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                format!(
                    "cannot create Agent runtime {}: {error}",
                    temporary.display()
                )
            })?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("cannot secure Agent runtime: {error}"))?;
        }
        file.write_all(bytes)
            .map_err(|error| format!("cannot write Agent runtime: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync Agent runtime: {error}"))?;
        drop(file);
        match std::fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot publish Agent runtime: {error}")),
        }
        open_locked(path)
    })();
    let _ = std::fs::remove_file(&temporary);
    result
}

#[cfg(all(feature = "embedded-agent", windows))]
fn open_locked(path: &Path) -> Result<File, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_SHARE_READ: u32 = 1;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect Agent runtime {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "Agent runtime is not a regular file: {}",
            path.display()
        ));
    }
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|error| format!("cannot lock Agent runtime {}: {error}", path.display()))
}

#[cfg(all(feature = "embedded-agent", target_os = "linux"))]
fn open_locked(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open Agent runtime {}: {error}", path.display()))
}

#[cfg(all(feature = "embedded-agent", target_os = "linux"))]
fn sealed_memfd(bytes: &[u8]) -> Result<File, String> {
    use std::os::fd::FromRawFd;
    let name = std::ffi::CString::new("hyperhub-gum-agent").expect("static memfd name");
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(format!(
            "cannot create sealed Agent memfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .map_err(|error| format!("cannot write Agent memfd: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync Agent memfd: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind Agent memfd: {error}"))?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err(format!(
            "cannot seal Agent memfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

fn verify_file(file: &File, expected_size: usize, expected: [u8; 32]) -> Result<(), String> {
    let mut file = file
        .try_clone()
        .map_err(|error| format!("cannot clone Agent runtime handle: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind Agent runtime: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect Agent runtime: {error}"))?;
    if metadata.len() != expected_size as u64 {
        return Err(format!(
            "Agent runtime size mismatch: expected {expected_size}, got {}",
            metadata.len()
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash Agent runtime: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected {
        return Err(format!(
            "Agent runtime SHA-256 mismatch: expected {}, got {}",
            hex(&expected),
            hex(&actual)
        ));
    }
    Ok(())
}

#[cfg(any(feature = "embedded-agent", test))]
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_expected_content_and_rejects_mutation() {
        let path = std::env::temp_dir().join(format!(
            "hyperhub-agent-integrity-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, b"agent").unwrap();
        let file = File::open(&path).unwrap();
        verify_file(&file, 5, sha256_bytes(b"agent")).unwrap();
        assert!(verify_file(&file, 5, sha256_bytes(b"other")).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "embedded-agent")]
    #[test]
    fn embedded_agent_materializes_and_verifies() {
        let runtime = AgentRuntime::embedded().unwrap();
        runtime.verify().unwrap();
        assert!(runtime.display_path().ends_with(EMBEDDED_AGENT_NAME));
        assert_eq!(runtime.integrity_environment().len(), 2);
    }
}
