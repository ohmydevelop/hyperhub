use super::{invalid, leaf_hash, FileIdentity, Leaf};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) struct Directory {
    file: File,
    parent: File,
    path: PathBuf,
    name: CString,
}
fn identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        volume: metadata.dev(),
        index: metadata.ino(),
    }
}
fn directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}
impl Directory {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let file = directory(path)?;
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
            return Err(invalid(
                "cache cleanup root is not a private owned directory",
            ));
        }
        let parent = directory(
            path.parent()
                .ok_or_else(|| invalid("cache cleanup root has no parent"))?,
        )?;
        let name = CString::new(
            path.file_name()
                .ok_or_else(|| invalid("cache cleanup root name missing"))?
                .as_bytes(),
        )
        .map_err(io::Error::other)?;
        let result = Self {
            file,
            parent,
            path: path.into(),
            name,
        };
        result.check_path()?;
        Ok(result)
    }
    pub(super) fn identity(&self) -> io::Result<FileIdentity> {
        Ok(identity(&self.file.metadata()?))
    }
    fn check_path(&self) -> io::Result<()> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let expected = self.identity()?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_dev as u64 != expected.volume
            || stat.st_ino as u64 != expected.index
        {
            return Err(invalid("cache cleanup root path identity changed"));
        }
        Ok(())
    }
    fn open_leaf(&self, name: &str) -> io::Result<File> {
        if name != ".owner" && leaf_hash(name).is_none() {
            return Err(invalid("cache cleanup leaf is not a hash name"));
        }
        let name = CString::new(name).map_err(io::Error::other)?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
    fn inspect(&self, name: &str) -> io::Result<Leaf> {
        self.inspect_inner(name, true)
    }
    fn inspect_inner(&self, name: &str, hash_contents: bool) -> io::Result<Leaf> {
        let mut file = self.open_leaf(name)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.len() == 0
            || metadata.len() > 1024 * 1024 * 1024
        {
            return Err(invalid(
                "cache cleanup leaf is not a private single-link executable",
            ));
        }
        if name != ".owner" && !hash_contents {
            return Ok(Leaf {
                name: name.into(),
                identity: identity(&metadata),
                size: metadata.len(),
                sha256: leaf_hash(name)
                    .ok_or_else(|| invalid("cache cleanup leaf name is invalid"))?
                    .into(),
            });
        }
        let mut hash = Sha256::new();
        let mut bytes = [0; 65536];
        let mut size = 0u64;
        loop {
            let count = file.read(&mut bytes)?;
            if count == 0 {
                break;
            }
            size += count as u64;
            if size > metadata.len() {
                return Err(invalid("cache cleanup leaf grew during validation"));
            }
            hash.update(&bytes[..count]);
        }
        let sha256 = hyperhub_runtime::artifact::hex(&hash.finalize());
        if size != metadata.len()
            || (name == ".owner" && size > 4096)
            || (name != ".owner" && leaf_hash(name) != Some(sha256.as_str()))
        {
            return Err(invalid("cache cleanup leaf hash mismatch"));
        }
        Ok(Leaf {
            name: name.into(),
            identity: identity(&metadata),
            size,
            sha256,
        })
    }
    pub(super) fn read_owner(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let file = self.open_leaf(".owner")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 4096 {
            return Err(invalid(
                "cache owner receipt is not a bounded single-link file",
            ));
        }
        file.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(invalid("cache owner receipt exceeds size limit"));
        }
        Ok(bytes)
    }
    pub(super) fn leaves(&self) -> io::Result<Vec<Leaf>> {
        self.list(true)
    }
    pub(super) fn snapshot(&self) -> io::Result<Vec<Leaf>> {
        self.list(false)
    }
    fn list(&self, hash_contents: bool) -> io::Result<Vec<Leaf>> {
        self.check_path()?;
        let mut result = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("cache cleanup leaf name is not UTF-8"))?;
            if result.len() >= 64 {
                return Err(invalid("cache cleanup artifact capacity exceeded"));
            }
            match self.inspect_inner(&name, hash_contents) {
                Ok(leaf) => result.push(leaf),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        self.check_path()?;
        result.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(result)
    }
    pub(super) fn remove(&self, leaves: &[Leaf]) -> io::Result<()> {
        match self.check_path() {
            Ok(()) => {}
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && self.file.metadata()?.nlink() == 0 =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        }
        let current = self.leaves()?;
        if current.iter().any(|leaf| !leaves.contains(leaf)) {
            return Err(invalid("cache cleanup encountered an unapproved object"));
        }
        for current in current {
            // Recheck inode through the anchored directory immediately before
            // unlinkat. No symlink or traversal is followed.
            if self.inspect(&current.name)? != current {
                return Err(invalid("cache cleanup leaf identity changed"));
            }
            let name = CString::new(current.name).map_err(io::Error::other)?;
            if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        match self.check_path() {
            Ok(()) => {}
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && self.file.metadata()?.nlink() == 0 =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        }
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(super) struct Process {
    handle: OwnedFd,
}
impl Process {
    pub(super) fn open(pid: u32, birth: u64) -> io::Result<Option<Self>> {
        if pid == 0 || birth == 0 {
            return Err(invalid("cache cleanup process identity is missing"));
        }
        #[cfg(target_os = "linux")]
        {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            if fd < 0 {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(libc::ESRCH) {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
            let handle = unsafe { OwnedFd::from_raw_fd(fd) };
            if crate::session::process_start_time(pid) != Some(birth) {
                return Err(invalid("cache cleanup process birth changed"));
            }
            Ok(Some(Self { handle }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Do not substitute a bare PID polling loop for an OS process
            // object on platforms that do not provide Linux pidfds.
            let _ = (pid, birth);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cache cleanup process handles are unsupported on this platform",
            ))
        }
    }
    pub(super) fn wait(&self) -> io::Result<()> {
        let mut poll = libc::pollfd {
            fd: self.handle.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut poll, 1, -1) };
            if result > 0 {
                return if poll.revents & libc::POLLIN != 0 {
                    Ok(())
                } else {
                    Err(invalid("cache cleanup process handle wait failed"))
                };
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}
