//! Windows cache retirement uses pinned process and file objects, never PID polling.
use super::{invalid, leaf_hash, FileIdentity, Leaf};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use windows_sys::Win32::{
    Foundation::{
        LocalFree, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, FILETIME, WAIT_OBJECT_0,
    },
    Security::{
        AclSizeInformation,
        Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT},
        GetAce, GetAclInformation, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACE_HEADER,
        ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    },
    Storage::FileSystem::*,
    System::Threading::{
        GetProcessTimes, OpenProcess, WaitForSingleObject, INFINITE,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    },
};

pub(super) struct Directory {
    file: File,
    path: PathBuf,
}
fn info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut value = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(invalid("cache cleanup object is not on a disk filesystem"));
    }
    Ok(value)
}
fn identity(value: &BY_HANDLE_FILE_INFORMATION) -> FileIdentity {
    FileIdentity {
        volume: u64::from(value.dwVolumeSerialNumber),
        index: (u64::from(value.nFileIndexHigh) << 32) | u64::from(value.nFileIndexLow),
    }
}
fn file_info<T: Default>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> io::Result<T> {
    let mut value = T::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            (&mut value as *mut T).cast(),
            std::mem::size_of::<T>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}
fn set_info<T>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS, value: &T) -> io::Result<()> {
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            class,
            (value as *const T).cast(),
            std::mem::size_of::<T>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
struct LocalMemory(*mut core::ffi::c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
// Match the protected, current-user-only DACL installed by artifact::Root.
// Owner SID is deliberately not assumed: elevated Windows tokens can assign
// Administrators ownership while retaining this exact private user DACL.
fn private_root(file: &File) -> io::Result<()> {
    unsafe {
        let mut acl = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let result = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let _descriptor = LocalMemory(descriptor);
        let mut control = 0;
        let mut revision = 0;
        let mut size = ACL_SIZE_INFORMATION::default();
        if acl.is_null()
            || GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
            || control & SE_DACL_PROTECTED == 0
            || GetAclInformation(
                acl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of_val(&size) as u32,
                AclSizeInformation,
            ) == 0
            || size.AceCount != 1
        {
            return Err(invalid("cache cleanup root DACL is not private"));
        }
        let mut ace = std::ptr::null_mut();
        if GetAce(acl, 0, &mut ace) == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = &*ace.cast::<ACE_HEADER>();
        if header.AceType != 0
            || header.AceFlags != 0
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(invalid("cache cleanup root DACL has unexpected ACE data"));
        }
        let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
        if ace.Mask != FILE_ALL_ACCESS {
            return Err(invalid(
                "cache cleanup root DACL has unexpected permissions",
            ));
        }
        let mut sid = std::ptr::null_mut();
        if ConvertSidToStringSidW((&ace.SidStart as *const u32).cast_mut().cast(), &mut sid) == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid = LocalMemory(sid.cast());
        let mut length = 0;
        while *sid.add(length) != 0 {
            length += 1;
        }
        let sid = String::from_utf16(std::slice::from_raw_parts(sid, length))
            .map_err(io::Error::other)?;
        if sid != crate::config_store::current_user_sid_string()? {
            return Err(invalid("cache cleanup root belongs to another user"));
        }
    }
    Ok(())
}
impl Directory {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let value = info(&file)?;
        if value.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || value.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(invalid("cache cleanup root is not a plain directory"));
        }
        private_root(&file)?;
        Ok(Self {
            file,
            path: path.into(),
        })
    }
    pub(super) fn identity(&self) -> io::Result<FileIdentity> {
        Ok(identity(&info(&self.file)?))
    }
    fn check_path(&self) -> io::Result<()> {
        let current = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.path)?;
        let value = info(&current)?;
        if value.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || value.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || identity(&value) != self.identity()?
        {
            return Err(invalid("cache cleanup root path identity changed"));
        }
        Ok(())
    }
    // Enumerate the pinned directory object, not a path that could resolve to
    // another directory. The deny-delete handle prevents moving this root.
    fn names(&self) -> io::Result<Vec<String>> {
        let mut buffer = vec![0u64; 8192];
        let mut names = Vec::new();
        let mut class = FileIdBothDirectoryRestartInfo;
        loop {
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    self.file.as_raw_handle(),
                    class,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * 8) as u32,
                )
            };
            if ok == 0 {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    Ok(names)
                } else {
                    Err(error)
                };
            }
            class = FileIdBothDirectoryInfo;
            let mut offset = 0usize;
            loop {
                let length = buffer.len() * 8;
                let prefix = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                if offset % 8 != 0 || offset + std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>() > length
                {
                    return Err(invalid("cache cleanup directory enumeration is malformed"));
                }
                let entry = unsafe {
                    &*buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_ID_BOTH_DIR_INFO>()
                };
                let bytes = entry.FileNameLength as usize;
                if bytes % 2 != 0 || offset + prefix + bytes > length {
                    return Err(invalid("cache cleanup directory name is malformed"));
                }
                let name =
                    unsafe { std::slice::from_raw_parts(entry.FileName.as_ptr(), bytes / 2) };
                let name = String::from_utf16(name).map_err(io::Error::other)?;
                if name != "." && name != ".." {
                    if (name != ".owner" && leaf_hash(&name).is_none()) || names.len() >= 64 {
                        return Err(invalid(
                            "cache cleanup directory contains an unexpected entry",
                        ));
                    }
                    names.push(name);
                }
                if entry.NextEntryOffset == 0 {
                    break;
                }
                let next = entry.NextEntryOffset as usize;
                if next < prefix + bytes || next > length - offset {
                    return Err(invalid("cache cleanup directory offset is malformed"));
                }
                offset += next;
            }
        }
    }
    fn open_leaf(&self, name: &str, removing: bool) -> io::Result<File> {
        if name != ".owner" && leaf_hash(name).is_none() {
            return Err(invalid("cache cleanup leaf is not a hash name"));
        }
        self.check_path()?;
        let access = FILE_GENERIC_READ
            | if removing {
                DELETE | FILE_WRITE_ATTRIBUTES
            } else {
                0
            };
        OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join(name))
    }
    fn inspect(name: &str, file: &mut File, hash_contents: bool) -> io::Result<Leaf> {
        let value = info(file)?;
        let size = (u64::from(value.nFileSizeHigh) << 32) | u64::from(value.nFileSizeLow);
        if value.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || value.nNumberOfLinks != 1
            || size == 0
            || size
                > if name == ".owner" {
                    4096
                } else {
                    1024 * 1024 * 1024
                }
        {
            return Err(invalid(
                "cache cleanup leaf is not a single-link regular executable",
            ));
        }
        // The parent snapshots its already verified installation without a
        // second full executable read. Admission/removal always hash contents.
        // The small ownership receipt is hashed in every phase.
        if !hash_contents && name != ".owner" {
            return Ok(Leaf {
                name: name.into(),
                identity: identity(&value),
                size,
                sha256: leaf_hash(name)
                    .ok_or_else(|| invalid("cache cleanup leaf is not a hash name"))?
                    .into(),
            });
        }
        let mut hash = Sha256::new();
        let mut bytes = [0; 65536];
        let mut count = 0u64;
        loop {
            let read = file.read(&mut bytes)?;
            if read == 0 {
                break;
            }
            count += read as u64;
            if count > size {
                return Err(invalid("cache cleanup leaf grew during validation"));
            }
            hash.update(&bytes[..read]);
        }
        let sha256 = hyperhub_runtime::artifact::hex(&hash.finalize());
        if count != size || (name != ".owner" && leaf_hash(name) != Some(sha256.as_str())) {
            return Err(invalid("cache cleanup leaf hash mismatch"));
        }
        Ok(Leaf {
            name: name.into(),
            identity: identity(&value),
            size,
            sha256,
        })
    }
    pub(super) fn read_owner(&self) -> io::Result<Vec<u8>> {
        let mut file = self.open_leaf(".owner", false)?;
        let leaf = Self::inspect(".owner", &mut file, true)?;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(leaf.size as usize);
        file.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != leaf.size {
            return Err(invalid("cache cleanup owner receipt size changed"));
        }
        Ok(bytes)
    }
    pub(super) fn leaves(&self) -> io::Result<Vec<Leaf>> {
        self.collect(true)
    }
    pub(super) fn snapshot(&self) -> io::Result<Vec<Leaf>> {
        self.collect(false)
    }
    fn collect(&self, hash_contents: bool) -> io::Result<Vec<Leaf>> {
        self.check_path()?;
        let mut leaves = Vec::new();
        for name in self.names()? {
            match self.open_leaf(&name, false) {
                Ok(mut file) => leaves.push(Self::inspect(&name, &mut file, hash_contents)?),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        self.check_path()?;
        leaves.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(leaves)
    }
    pub(super) fn remove(&self, leaves: &[Leaf]) -> io::Result<()> {
        self.check_path()?;
        // Validate and pin ALL remaining leaves before modifying any object.
        // A replacement/extra entry aborts without partially deleting the job.
        let mut pinned = Vec::new();
        for name in self.names()? {
            let mut file = match self.open_leaf(&name, true) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let current = Self::inspect(&name, &mut file, true)?;
            if !leaves.contains(&current) {
                return Err(invalid("cache cleanup encountered an unapproved object"));
            }
            pinned.push(file);
        }
        self.check_path()?;
        for file in pinned {
            let mut basic: FILE_BASIC_INFO = file_info(&file, FileBasicInfo)?;
            basic.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
            if basic.FileAttributes == 0 {
                basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            }
            set_info(&file, FileBasicInfo, &basic)?;
            set_info(
                &file,
                FileDispositionInfo,
                &FILE_DISPOSITION_INFO { DeleteFile: true },
            )?;
        }
        // Only delete this pinned root, and only while empty. New unknown files
        // cause Windows to reject the disposition; no recursive fallback exists.
        set_info(
            &self.file,
            FileDispositionInfo,
            &FILE_DISPOSITION_INFO { DeleteFile: true },
        )
    }
}

pub(super) struct Process {
    handle: OwnedHandle,
}
impl Process {
    pub(super) fn open(pid: u32, birth: u64) -> io::Result<Option<Self>> {
        if pid == 0 || birth == 0 {
            return Err(invalid("cache cleanup process identity is missing"));
        }
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let actual = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        if actual != birth {
            return Err(invalid("cache cleanup process birth changed"));
        }
        Ok(Some(Self { handle }))
    }
    pub(super) fn wait(&self) -> io::Result<()> {
        if unsafe { WaitForSingleObject(self.handle.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    struct PrivateRoot(PathBuf);
    impl PrivateRoot {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "hh-cache-cleanup-{}-{:032x}",
                std::process::id(),
                rand::random::<u128>()
            ));
            std::fs::create_dir(&root).unwrap();
            crate::config_store::restrict_file_to_current_user(&root).unwrap();
            Self(root)
        }
        fn leaf(&self, bytes: &[u8]) -> PathBuf {
            let hash = hyperhub_runtime::artifact::hex(&Sha256::digest(bytes));
            let path = self.0.join(format!("{hash}.exe"));
            std::fs::write(&path, bytes).unwrap();
            path
        }
    }
    impl Drop for PrivateRoot {
        fn drop(&mut self) {
            if let Ok(entries) = std::fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                        continue;
                    }
                    if let Ok(metadata) = entry.metadata() {
                        let mut permissions = metadata.permissions();
                        permissions.set_readonly(false);
                        let _ = std::fs::set_permissions(entry.path(), permissions);
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn readonly_cache_keeps_existing_deny_delete_guard_until_release() {
        let root = PrivateRoot::new();
        let path = root.leaf(b"verified cache bytes");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        let guard = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap();
        let directory = Directory::open(&root.0).unwrap();
        let leaves = directory.leaves().unwrap();
        assert!(std::fs::rename(&root.0, root.0.with_extension("moved")).is_err());
        assert!(directory.remove(&leaves).is_err());
        assert!(path.exists());
        assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
        drop(guard);
        directory.remove(&leaves).unwrap();
        drop(directory);
        assert!(!root.0.exists());
    }
    #[test]
    fn unknown_entry_aborts_before_deleting_approved_cache() {
        let root = PrivateRoot::new();
        let path = root.leaf(b"approved");
        let directory = Directory::open(&root.0).unwrap();
        let leaves = directory.leaves().unwrap();
        std::fs::write(root.0.join("foreign.txt"), b"keep").unwrap();
        assert!(directory.remove(&leaves).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"approved");
        assert_eq!(std::fs::read(root.0.join("foreign.txt")).unwrap(), b"keep");
    }
    #[test]
    fn replacement_identity_and_hardlinks_are_rejected() {
        let root = PrivateRoot::new();
        let path = root.leaf(b"same content different object");
        let directory = Directory::open(&root.0).unwrap();
        let leaves = directory.leaves().unwrap();
        let old_object = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"same content different object").unwrap();
        assert!(directory.remove(&leaves).is_err());
        assert!(path.exists());
        drop(old_object);
        let other = PrivateRoot::new();
        let link = other.0.join("outside.exe");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(directory.leaves().is_err());
        assert!(directory.remove(&leaves).is_err());
        assert_eq!(
            std::fs::read(link).unwrap(),
            b"same content different object"
        );
    }
    #[test]
    fn owner_receipt_is_the_only_non_hash_leaf_and_remains_identity_bound() {
        let root = PrivateRoot::new();
        let owner = root.0.join(".owner");
        std::fs::write(&owner, b"signed receipt supplied by shared layer").unwrap();
        let directory = Directory::open(&root.0).unwrap();
        assert_eq!(
            directory.read_owner().unwrap(),
            b"signed receipt supplied by shared layer"
        );
        let leaves = directory.leaves().unwrap();
        std::fs::write(&owner, b"tampered receipt").unwrap();
        assert!(directory.remove(&leaves).is_err());
        assert!(owner.exists());
        std::fs::write(&owner, vec![0; 4097]).unwrap();
        assert!(directory.read_owner().is_err());
    }
    #[test]
    fn unprotected_directory_and_hash_mismatch_are_rejected() {
        let root = PrivateRoot::new();
        let foreign = root.0.join("unprotected");
        std::fs::create_dir(&foreign).unwrap();
        assert!(Directory::open(&foreign).is_err());
        std::fs::remove_dir(&foreign).unwrap();
        let path = root.leaf(b"original");
        std::fs::write(&path, b"changed bytes").unwrap();
        let directory = Directory::open(&root.0).unwrap();
        assert!(directory.leaves().is_err());
        assert!(path.exists());
    }
    #[test]
    fn reparse_root_and_leaf_are_rejected() {
        let root = PrivateRoot::new();
        let outside = PrivateRoot::new();
        let link = root.0.join("directory-link");
        // Junctions exercise the reparse boundary under the ordinary-user
        // deployment contract without SeCreateSymbolicLinkPrivilege.
        directory_junction(&outside.0, &link).unwrap();
        assert!(Directory::open(&link).is_err());
        std::fs::remove_dir(&link).unwrap();
        let source = outside.leaf(b"outside bytes");
        let name = source.file_name().unwrap();
        let leaf = root.0.join(name);
        directory_junction(&outside.0, &leaf).unwrap();
        let directory = Directory::open(&root.0).unwrap();
        assert!(directory.leaves().is_err());
        std::fs::remove_dir(&leaf).unwrap();
        // Also cover a file symlink when the test token can create one. The
        // mandatory junction assertions above are never skipped.
        match std::os::windows::fs::symlink_file(&source, &leaf) {
            Ok(()) => {
                assert!(directory.leaves().is_err());
                std::fs::remove_file(&leaf).unwrap();
            }
            Err(error) if error.raw_os_error() == Some(1314) => {
                eprintln!("file symlink requires a privileged token; junction checks completed");
            }
            Err(error) => panic!("cannot create file symlink fixture: {error}"),
        }
        assert_eq!(std::fs::read(&source).unwrap(), b"outside bytes");
    }

    fn directory_junction(target: &Path, link: &Path) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::IO::DeviceIoControl;
        // REPARSE_DATA_BUFFER mount-point layout from MS-FSCC 2.1.2.5.
        const MOUNT_POINT: u32 = 0xa000_0003;
        const SET_REPARSE_POINT: u32 = 0x0009_00a4;
        let path = std::fs::canonicalize(target)?;
        let path: Vec<u16> = path.as_os_str().encode_wide().collect();
        let prefix: Vec<u16> = r"\\?\".encode_utf16().collect();
        let path = path
            .strip_prefix(prefix.as_slice())
            .ok_or_else(|| invalid("junction fixture requires a canonical local Windows path"))?;
        let substitute: Vec<u16> = r"\??\".encode_utf16().chain(path.iter().copied()).collect();
        let length = u16::try_from(substitute.len() * 2)
            .map_err(|_| invalid("junction fixture target is too long"))?;
        let mut data = Vec::new();
        data.extend_from_slice(&MOUNT_POINT.to_le_bytes());
        data.extend_from_slice(&(length + 12).to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // Reserved.
        for field in [0, length, length + 2, 0] {
            data.extend_from_slice(&field.to_le_bytes());
        }
        for unit in substitute.iter().copied().chain([0, 0]) {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::create_dir(link)?;
        let file = OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(link)?;
        let mut returned = 0;
        if unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                SET_REPARSE_POINT,
                data.as_ptr().cast(),
                data.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[test]
    fn process_wait_uses_exact_handle_and_rejects_wrong_birth() {
        const CHILD: &str = "HYPERHUB_CLEANUP_WINDOWS_WAIT_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte).unwrap();
            return;
        }
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = ChildGuard(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "forward::cleanup::platform::tests::process_wait_uses_exact_handle_and_rejects_wrong_birth", "--nocapture"])
            .env(CHILD, "1").stdin(Stdio::piped()).stdout(Stdio::null()).spawn().unwrap());
        let pid = child.0.id();
        let birth = crate::session::process_start_time(pid).unwrap();
        assert!(Process::open(pid, 0).is_err());
        assert!(Process::open(pid, birth + 1).is_err());
        let process = Process::open(pid, birth).unwrap().unwrap();
        let (sent, received) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            sent.send(process.wait()).unwrap();
        });
        assert!(received.recv_timeout(Duration::from_millis(100)).is_err());
        child.0.stdin.take().unwrap().write_all(b"x").unwrap();
        assert!(child.0.wait().unwrap().success());
        received
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        waiter.join().unwrap();
        assert!(Process::open(u32::MAX, 1).unwrap().is_none());
    }
}
