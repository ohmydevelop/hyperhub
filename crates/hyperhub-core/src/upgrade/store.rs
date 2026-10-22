use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_JOURNAL: u64 = 8 * 1024 * 1024;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: u32,
    value: String,
    proof: Vec<u8>,
}

pub(crate) struct Store {
    path: PathBuf,
    key: Zeroizing<Vec<u8>>,
    _lock: File,
}
impl Store {
    pub(crate) fn open(directory: &Path, key: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        private_directory(directory)?;
        let lock_path = directory.join("coordinator.lock");
        let lock = match open(&lock_path, true) {
            Ok(file) => {
                crate::config_store::restrict_file_to_current_user(&lock_path)?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => open(&lock_path, false)?,
            Err(error) => return Err(error),
        };
        private_file(&lock)?;
        lock.try_lock().map_err(|error| {
            io::Error::other(format!("upgrade coordinator is already owned: {error}"))
        })?;
        if key.is_empty() {
            return Err(io::Error::other("upgrade journal key is empty"));
        }
        Ok(Self {
            path: directory.join("journal.json"),
            key,
            _lock: lock,
        })
    }
    fn mac(&self, bytes: &[u8]) -> io::Result<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(io::Error::other)?;
        mac.update(b"hyperhub-upgrade-journal-v1\0");
        mac.update(bytes);
        Ok(mac)
    }
    pub(crate) fn load<T: DeserializeOwned>(&self) -> io::Result<Option<T>> {
        let file = match open(&self.path, false) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        private_file(&file)?;
        if file.metadata()?.len() > MAX_JOURNAL {
            return Err(io::Error::other("upgrade journal exceeds limit"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_JOURNAL + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_JOURNAL {
            return Err(io::Error::other("upgrade journal exceeds limit"));
        }
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if envelope.schema != 1 {
            return Err(io::Error::other("unsupported upgrade journal schema"));
        }
        self.mac(envelope.value.as_bytes())?
            .verify_slice(&envelope.proof)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "upgrade journal authentication failed",
                )
            })?;
        serde_json::from_str(&envelope.value)
            .map(Some)
            .map_err(io::Error::other)
    }
    pub(crate) fn save(&self, value: &impl Serialize) -> io::Result<()> {
        let value = serde_json::to_string(value).map_err(io::Error::other)?;
        let proof = self.mac(value.as_bytes())?.finalize().into_bytes().to_vec();
        let bytes = serde_json::to_vec(&Envelope {
            schema: 1,
            value,
            proof,
        })
        .map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_JOURNAL {
            return Err(io::Error::other("upgrade journal exceeds limit"));
        }
        crate::config_store::save_durable_private_bytes(&self.path, &bytes)
            .map_err(io::Error::other)
    }
}

fn open(path: &Path, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        // The lock file remains open, so journal replacement uses a distinct
        // path. Denying delete sharing also prevents lock-file replacement.
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = options.open(path)?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::other("upgrade store symlink rejected"));
    }
    Ok(file)
}
fn private_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("upgrade store is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::other(
                "upgrade store must be private and owned by the current user",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(io::Error::other("upgrade store reparse point rejected"));
        }
    }
    Ok(())
}
fn private_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::other("upgrade journal directory is not private"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "upgrade journal directory must be owned by the current user with mode 0700",
            ));
        }
    }
    #[cfg(windows)]
    crate::config_store::restrict_file_to_current_user(path)?;
    Ok(())
}
