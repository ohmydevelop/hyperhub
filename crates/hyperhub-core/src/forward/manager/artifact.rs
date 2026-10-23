use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_EXECUTABLE: u64 = 1024 * 1024 * 1024;
pub(super) struct Root(PathBuf, Mutex<HashMap<PathBuf, usize>>);
struct Lease {
    path: PathBuf,
    root: Arc<Root>,
}
impl Root {
    pub(super) fn directory(&self) -> &Path {
        &self.0
    }
    #[cfg(test)]
    pub(super) fn new() -> io::Result<Arc<Self>> {
        Self::new_authenticated(None)
    }
    pub(super) fn new_authenticated(key: Option<&[u8]>) -> io::Result<Arc<Self>> {
        let mut random = [0; 32];
        rand::fill(&mut random);
        let nonce = if let Some(key) = key {
            let birth = crate::session::process_start_time(std::process::id())
                .filter(|birth| *birth != 0)
                .ok_or_else(|| io::Error::other("cache root owner birth unavailable"))?;
            super::super::cleanup::root_nonce(key, std::process::id(), birth, &random)?
        } else {
            hex(&random[..16])
        };
        let path =
            std::env::temp_dir().join(format!("hyperhub-forward-{}-{}", std::process::id(), nonce));
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        #[cfg(windows)]
        crate::config_store::restrict_file_to_current_user(&path)?;
        let root = Arc::new(Self(path, Mutex::new(HashMap::new())));
        if let Some(key) = key {
            super::super::cleanup::bind_owner(root.directory(), key, random)?;
        }
        Ok(root)
    }
    pub(super) fn install(
        self: &Arc<Self>,
        source: &Path,
        expected: &str,
    ) -> io::Result<Executable> {
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(io::Error::other("invalid forwarding worker SHA-256"));
        }
        let mut source = open_source(source)?;
        let metadata = source.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE {
            return Err(io::Error::other(
                "invalid forwarding worker executable size",
            ));
        }
        let destination = self
            .0
            .join(format!("{expected}{}", std::env::consts::EXE_SUFFIX));
        let lease = {
            let mut leases = self.1.lock().unwrap_or_else(|error| error.into_inner());
            *leases.entry(destination.clone()).or_default() += 1;
            Lease {
                path: destination.clone(),
                root: self.clone(),
            }
        };
        if destination.try_exists()? {
            if digest(&mut source)? != expected {
                return Err(io::Error::other("forwarding worker source hash mismatch"));
            }
        } else {
            let temporary = self.0.join(".prepare");
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options.open(&temporary)?;
            let result = (|| {
                let mut hasher = Sha256::new();
                let mut count = 0u64;
                let mut buffer = [0; 65536];
                loop {
                    let read = source.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    count = count
                        .checked_add(read as u64)
                        .ok_or_else(|| io::Error::other("worker executable size overflow"))?;
                    if count > MAX_EXECUTABLE {
                        return Err(io::Error::other("worker executable exceeds size limit"));
                    }
                    hasher.update(&buffer[..read]);
                    output.write_all(&buffer[..read])?;
                }
                if count != metadata.len() || hex(&hasher.finalize()) != expected {
                    return Err(io::Error::other(
                        "forwarding worker executable hash or size mismatch",
                    ));
                }
                output.sync_all()?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    output.set_permissions(fs::Permissions::from_mode(0o500))?;
                }
                #[cfg(windows)]
                {
                    crate::config_store::restrict_file_to_current_user(&temporary)?;
                    let mut permissions = output.metadata()?.permissions();
                    permissions.set_readonly(true);
                    output.set_permissions(permissions)?;
                }
                Ok(())
            })();
            drop(output);
            if let Err(error) = result {
                remove_file(&temporary);
                return Err(error);
            }
            if let Err(error) = fs::rename(&temporary, &destination) {
                remove_file(&temporary);
                return Err(error);
            }
            #[cfg(unix)]
            File::open(&self.0)?.sync_all()?;
        }
        if fs::symlink_metadata(&destination)?.file_type().is_symlink() {
            return Err(io::Error::other(
                "worker executable must not be a symbolic link",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ);
        }
        let mut file = options.open(&destination)?;
        if !file.metadata()?.is_file()
            || !file.metadata()?.permissions().readonly()
            || digest(&mut file)? != expected
        {
            return Err(io::Error::other(
                "cached worker executable validation failed",
            ));
        }
        Ok(Executable {
            file,
            _path: destination,
            sha256: expected.into(),
            _lease: lease,
        })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut leases = self
            .root
            .1
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(count) = leases.get_mut(&self.path) {
            *count -= 1;
            if *count == 0 {
                leases.remove(&self.path);
                // Serialize removal against a new lease. The executable file
                // guard is declared before this lease and therefore closes
                // first, including the Windows deny-write/delete handle.
                remove_file(&self.path);
            }
        }
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.0) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                    remove_file(&entry.path());
                }
            }
        }
        let _ = fs::remove_dir(&self.0);
    }
}
pub(super) struct Executable {
    file: File,
    _path: PathBuf,
    pub(super) sha256: String,
    _lease: Lease,
}
impl Executable {
    pub(super) fn path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _keep_open = &self.file;
            self._path.clone()
        }
    }
}
pub(super) fn source_digest(path: &Path) -> io::Result<String> {
    digest(&mut open_source(path)?)
}
fn open_source(path: &Path) -> io::Result<File> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::other(
            "worker source must be a regular executable file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(
            "worker source changed to a non-regular file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if file.metadata()?.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(io::Error::other(
                "worker source must not be a reparse point",
            ));
        }
    }
    Ok(file)
}
fn digest(source: &mut File) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    let mut count = 0u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > MAX_EXECUTABLE {
            return Err(io::Error::other("worker executable exceeds size limit"));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn remove_file(path: &Path) {
    #[cfg(windows)]
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        let _ = fs::set_permissions(path, permissions);
    }
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cached_artifact_is_released_after_its_last_owner() {
        let root = Root::new().unwrap();
        let source = root.0.join("fixture-source");
        fs::write(&source, b"task-owned artifact bytes").unwrap();
        let hash = source_digest(&source).unwrap();
        let first = root.install(&source, &hash).unwrap();
        let path = first._path.clone();
        let second = root.install(&source, &hash).unwrap();
        drop(first);
        assert!(path.is_file());
        drop(second);
        assert!(
            !path.exists(),
            "failed or retired candidates must not accumulate cached executables"
        );
        assert!(source.is_file());
        let third = root.install(&source, &hash).unwrap();
        assert!(path.is_file());
        drop(third);
        assert!(!path.exists());
    }
    #[test]
    fn cached_valid_artifact_does_not_hide_a_changed_source() {
        let root = Root::new().unwrap();
        let source = root.0.join("fixture-source");
        fs::write(&source, b"expected bytes").unwrap();
        let hash = source_digest(&source).unwrap();
        let first = root.install(&source, &hash).unwrap();
        fs::write(&source, b"different bytes").unwrap();
        assert!(root.install(&source, &hash).is_err());
        assert!(
            first._path.is_file(),
            "failed second lease must preserve the active artifact"
        );
    }
}
