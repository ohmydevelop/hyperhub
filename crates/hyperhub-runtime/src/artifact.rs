//! Content-addressed module installation. The root must be a Host-owned private
//! directory. Digests provide integrity against damaged/mismatched downloads;
//! they do not authenticate a manifest supplied by an attacker.
use crate::{Error, Manifest};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_MODULE_SIZE: u64 = 512 * 1024 * 1024;
static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

pub struct Artifact {
    manifest: Manifest,
    path: PathBuf,
    // On Windows this handle denies write and delete sharing. On Linux dlopen
    // uses this descriptor, avoiding a path substitution between hash and load.
    file: File,
}

impl Artifact {
    pub fn install(root: &Path, manifest: &Manifest, mut source: impl Read) -> Result<Self, Error> {
        manifest.validate()?;
        if manifest.size > MAX_MODULE_SIZE {
            return Err(Error::Artifact("module exceeds size limit".into()));
        }
        private_directory(root)?;
        let path = root.join(format!(
            "{}{}",
            manifest.sha256,
            std::env::consts::DLL_SUFFIX
        ));
        if path.try_exists().map_err(io_error)? {
            return Self::open(path, manifest);
        }
        let temporary = root.join(format!(
            ".prepare-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(io_error)?;
        let result = (|| {
            let mut hash = Sha256::new();
            let mut count = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = source.read(&mut buffer).map_err(io_error)?;
                if read == 0 {
                    break;
                }
                count = count
                    .checked_add(read as u64)
                    .ok_or(Error::InvalidManifest)?;
                if count > manifest.size {
                    return Err(Error::Artifact("module size mismatch".into()));
                }
                hash.update(&buffer[..read]);
                file.write_all(&buffer[..read]).map_err(io_error)?;
            }
            if count != manifest.size || hex(&hash.finalize()) != manifest.sha256 {
                return Err(Error::Artifact("module digest or size mismatch".into()));
            }
            file.sync_all().map_err(io_error)?;
            let mut permissions = file.metadata().map_err(io_error)?.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                permissions.set_mode(0o400);
            }
            #[cfg(not(unix))]
            permissions.set_readonly(true);
            file.set_permissions(permissions).map_err(io_error)?;
            Ok(())
        })();
        // Close the writer before publishing. A Windows verifier deliberately
        // denies write sharing; publishing a still-open writer races that lock.
        drop(file);
        // Never replace a mapped file. Concurrent writers may install the same
        // digest; validate their object rather than overwriting it.
        let result = result.and_then(|()| install_link(&temporary, &path));
        remove_temporary(&temporary);
        result?;
        #[cfg(unix)]
        File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
        Self::open(path, manifest)
    }

    fn open(path: PathBuf, manifest: &Manifest) -> Result<Self, Error> {
        if !fs::symlink_metadata(&path)
            .map_err(io_error)?
            .file_type()
            .is_file()
        {
            return Err(Error::Artifact("module must be a regular file".into()));
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
            use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
            options.share_mode(FILE_SHARE_READ);
        }
        let mut file = options.open(&path).map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || metadata.len() != manifest.size
            || !metadata.permissions().readonly()
        {
            return Err(Error::Artifact(
                "module must have the declared size and be read-only".into(),
            ));
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut remaining = manifest.size;
        while remaining != 0 {
            let capacity = buffer.len().min(remaining as usize);
            let read = file.read(&mut buffer[..capacity]).map_err(io_error)?;
            if read == 0 {
                return Err(Error::Artifact("module was truncated".into()));
            }
            hash.update(&buffer[..read]);
            remaining -= read as u64;
        }
        if hex(&hash.finalize()) != manifest.sha256 {
            return Err(Error::Artifact("cached module digest mismatch".into()));
        }
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        Ok(Self {
            manifest: manifest.clone(),
            path,
            file,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn duplicate_after_fork(&self) -> Result<Self, Error> {
        Ok(Self {
            manifest: self.manifest.clone(),
            path: self.path.clone(),
            file: self
                .file
                .try_clone()
                .map_err(|e| Error::Artifact(e.to_string()))?,
        })
    }
    /// The old object is deliberately leaked after this child-only ownership
    /// transfer, so its File destructor can never close a reused descriptor.
    #[cfg(target_os = "linux")]
    pub(crate) unsafe fn release_after_fork(&self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::close(self.file.as_raw_fd());
        }
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn load_path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _keep_file_open = &self.file;
            self.path.clone()
        }
    }
}

fn private_directory(root: &Path) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(root).map_err(io_error)?;
    let metadata = fs::symlink_metadata(root).map_err(io_error)?;
    if !metadata.is_dir() {
        return Err(Error::Artifact(
            "module root must be a directory, not a link".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(Error::Artifact(
                "module root must be owned by the Host user with mode 0700".into(),
            ));
        }
    }
    Ok(())
}

fn remove_temporary(path: &Path) {
    // Windows does not unlink a read-only file. This path is a newly-created
    // task-owned link, never the installed object's pathname.
    #[cfg(windows)]
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        let _ = fs::set_permissions(path, permissions);
    }
    let _ = fs::remove_file(path);
}
fn io_error(error: std::io::Error) -> Error {
    Error::Artifact(error.to_string())
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(not(windows))]
fn install_link(temporary: &Path, path: &Path) -> Result<(), Error> {
    match fs::hard_link(temporary, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}
#[cfg(windows)]
fn install_link(temporary: &Path, path: &Path) -> Result<(), Error> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    let source: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // No REPLACE_EXISTING: mapped modules and concurrent installations stay intact.
    if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) } != 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    // An existing destination held by a verifier can produce SHARING_VIOLATION
    // or ACCESS_DENIED before Windows reports ALREADY_EXISTS. Accept only its
    // presence here; Artifact::open still verifies type, permissions and digest.
    if path.try_exists().unwrap_or(false) {
        Ok(())
    } else {
        Err(io_error(error))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn publication_does_not_replace_a_destination_held_by_a_verifier() {
        let root =
            std::env::temp_dir().join(format!("hyperhub-held-reader-{}", std::process::id()));
        let bytes = b"published module";
        let manifest = Manifest {
            version: "1".into(),
            target: "test-target".into(),
            abi: crate::abi::ABI_V1,
            state_schema: 1,
            hooks: 1,
            sha256: hex(&Sha256::digest(bytes)),
            size: bytes.len() as u64,
        };
        let held = Artifact::install(&root, &manifest, &bytes[..]).unwrap();
        let published = held.path().to_owned();
        let candidate = root.join("candidate");
        fs::write(&candidate, b"must not replace the published module").unwrap();
        // Keep the verifier's deny-write/delete handle open during publication.
        install_link(&candidate, &published).unwrap();
        let checked = Artifact::open(published.clone(), &manifest).unwrap();
        assert_eq!(fs::read(&published).unwrap(), bytes);
        assert!(candidate.is_file());
        drop(checked);
        drop(held);
        let mut permissions = fs::metadata(&published).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(published, permissions).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
