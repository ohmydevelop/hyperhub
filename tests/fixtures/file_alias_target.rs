//! File namespace mutations and content aliases. All inputs are disposable dummy files.
use std::{
    fs,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
};

const DUMMY: &[u8] = b"private-file-alias-fixture\n";

fn emit(case: &str, result: &str) {
    println!("CASE {case} {result}");
    io::stdout().flush().unwrap();
}

fn read_result(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => {
            assert_eq!(bytes, DUMMY, "fixture content changed unexpectedly");
            "readable".into()
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => "denied".into(),
        Err(error) => panic!("unexpected read result for {}: {error}", path.display()),
    }
}

fn opened_read_result(result: io::Result<fs::File>) -> String {
    match result {
        Ok(mut file) => {
            let mut bytes = Vec::new();
            match file.read_to_end(&mut bytes) {
                Ok(_) => {
                    assert_eq!(bytes, DUMMY);
                    "opened:readable".into()
                }
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    "opened:denied".into()
                }
                Err(error) => panic!("unexpected descriptor read: {error}"),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => "denied".into(),
        Err(error) => panic!("unexpected open: {error}"),
    }
}

fn create_read_result(path: &Path) -> String {
    #[cfg(target_os = "linux")]
    {
        use std::{
            ffi::CString,
            os::{fd::FromRawFd, unix::ffi::OsStrExt},
        };
        unsafe extern "C" {
            fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
        }
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let descriptor = unsafe { open(path.as_ptr(), 0x40, 0o600u32) };
        return opened_read_result(if descriptor < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { fs::File::from_raw_fd(descriptor) })
        });
    }
    #[cfg(windows)]
    {
        windows_mapping::create_read_result(path)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        panic!("file-alias fixture requires Linux or Windows");
    }
}

#[cfg(windows)]
mod windows_mapping {
    use super::*;
    use std::{
        ffi::c_void,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        },
    };
    type Handle = *mut c_void;
    const DENIED: i32 = 0xC000_0022u32 as i32;
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root: Handle,
        name: *const UnicodeString,
        attributes: u32,
        security: *const c_void,
        qos: *const c_void,
    }
    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateFile(
            out: *mut Handle,
            access: u32,
            object: *const ObjectAttributes,
            ios: *mut c_void,
            allocation: *const i64,
            attributes: u32,
            share: u32,
            disposition: u32,
            options: u32,
            ea: *const c_void,
            ea_length: u32,
        ) -> i32;
        fn NtCreateSection(
            out: *mut Handle,
            access: u32,
            object: *const c_void,
            size: *const i64,
            protection: u32,
            attributes: u32,
            file: Handle,
        ) -> i32;
        fn NtMapViewOfSection(
            section: Handle,
            process: Handle,
            base: *mut *mut c_void,
            zero: usize,
            commit: usize,
            offset: *const i64,
            size: *mut usize,
            inherit: u32,
            allocation: u32,
            protection: u32,
        ) -> i32;
        fn NtUnmapViewOfSection(process: Handle, base: *mut c_void) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
    }
    pub(super) fn create_read_result(path: &Path) -> String {
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x8000_0000,
                7,
                std::ptr::null(),
                4,
                0x80,
                std::ptr::null_mut(),
            )
        };
        opened_read_result(if handle == -1isize as Handle {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { fs::File::from_raw_handle(handle) })
        })
    }
    pub(super) fn delete_on_close(path: &Path) -> String {
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x0001_0080,
                7,
                std::ptr::null(),
                3,
                0x0400_0080,
                std::ptr::null_mut(),
            )
        };
        if handle == -1isize as Handle {
            let error = io::Error::last_os_error();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            return "denied".into();
        }
        assert_ne!(unsafe { CloseHandle(handle) }, 0);
        assert!(!path.exists(), "delete-on-close did not delete dummy file");
        "opened:deleted".into()
    }
    pub(super) fn supersede(path: &Path) -> String {
        let full = path.canonicalize().unwrap();
        let wide: Vec<u16> = full.as_os_str().encode_wide().collect();
        assert!(
            wide.starts_with(&[92, 92, 63, 92]),
            "expected canonical extended Windows path"
        );
        let name: Vec<u16> = [92, 63, 63, 92]
            .into_iter()
            .chain(wide[4..].iter().copied())
            .collect();
        let unicode = UnicodeString {
            length: (name.len() * 2).try_into().unwrap(),
            maximum_length: (name.len() * 2).try_into().unwrap(),
            buffer: name.as_ptr(),
        };
        let object = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root: std::ptr::null_mut(),
            name: &unicode,
            attributes: 0x40,
            security: std::ptr::null(),
            qos: std::ptr::null(),
        };
        let mut output = std::ptr::null_mut();
        let mut ios = [0usize; 2];
        let status = unsafe {
            NtCreateFile(
                &mut output,
                // NtCreateFile requires explicit SYNCHRONIZE for synchronous
                // options, and FILE_SUPERSEDE requires DELETE on the old file.
                // Retain GENERIC_ALL to exercise combined content rights.
                0x1011_0000,
                &object,
                ios.as_mut_ptr().cast(),
                std::ptr::null(),
                0x80,
                7,
                0,
                0x60,
                std::ptr::null(),
                0,
            )
        };
        if status == DENIED {
            return "denied".into();
        }
        assert_eq!(status, 0, "native supersede status");
        assert_ne!(unsafe { CloseHandle(output) }, 0);
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
        "opened:replaced".into()
    }
    struct Mapping {
        file: fs::File,
        section: Handle,
    }
    impl Drop for Mapping {
        fn drop(&mut self) {
            assert_ne!(unsafe { CloseHandle(self.section) }, 0);
        }
    }
    fn section(file: &fs::File) -> Result<Handle, i32> {
        let mut section = std::ptr::null_mut();
        let status = unsafe {
            NtCreateSection(
                &mut section,
                0xF001F,
                std::ptr::null(),
                std::ptr::null(),
                4,
                0x0800_0000,
                file.as_raw_handle(),
            )
        };
        if status == 0 {
            assert!(!section.is_null());
            Ok(section)
        } else {
            Err(status)
        }
    }
    impl Mapping {
        fn prepare(path: &Path) -> Self {
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            let section = section(&file).expect("allowed mapping warmup");
            Self { file, section }
        }
    }
    fn view(section: Handle, protection: u32, write: bool) -> String {
        let mut base = std::ptr::null_mut();
        let mut size = 0;
        let status = unsafe {
            NtMapViewOfSection(
                section,
                -1isize as Handle,
                &mut base,
                0,
                0,
                std::ptr::null(),
                &mut size,
                2,
                0,
                protection,
            )
        };
        if status == DENIED {
            return "denied".into();
        }
        assert_eq!(status, 0, "native map status");
        assert!(!base.is_null());
        let valid = unsafe {
            let bytes = base.cast::<u8>();
            let matched = DUMMY
                .iter()
                .enumerate()
                .all(|(index, byte)| bytes.add(index).read_volatile() == *byte);
            if write {
                bytes.write_volatile(DUMMY[0] ^ 1);
                assert_eq!(bytes.read_volatile(), DUMMY[0] ^ 1);
                bytes.write_volatile(DUMMY[0]);
            }
            matched
        };
        assert_eq!(unsafe { NtUnmapViewOfSection(-1isize as Handle, base) }, 0);
        assert!(valid, "mapped content differs from dummy bytes");
        if write {
            "read_write".into()
        } else {
            "readable".into()
        }
    }
    pub(super) struct Mappings {
        readable: Mapping,
        writable: Mapping,
        ordinary: Mapping,
    }
    impl Mappings {
        pub(super) fn prepare(root: &Path) -> Self {
            Self {
                readable: Mapping::prepare(&root.join("mapping-read.data")),
                writable: Mapping::prepare(&root.join("mapping-write.data")),
                ordinary: Mapping::prepare(&root.join("ordinary.txt")),
            }
        }
        pub(super) fn policy_ready(root: &Path) -> bool {
            matches!(fs::read(root.join("mapping-read.data")), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
                && matches!(fs::OpenOptions::new().write(true).open(root.join("mapping-write.data")), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        }
        pub(super) fn run(&self) {
            let created = match section(&self.readable.file) {
                Err(DENIED) => "denied".into(),
                Err(status) => panic!("unexpected protected section status {status:#x}"),
                Ok(section) => {
                    let result = format!("created:{}", view(section, 4, false));
                    assert_ne!(unsafe { CloseHandle(section) }, 0);
                    result
                }
            };
            emit("create-rw-read-deny", &created);
            emit("map-rw-read-deny", &view(self.readable.section, 4, false));
            emit("map-copy-read-deny", &view(self.readable.section, 8, false));
            emit("map-rw-write-deny", &view(self.writable.section, 4, false));
            emit("ordinary-map-rw", &view(self.ordinary.section, 4, true));
            emit("ordinary-map-copy", &view(self.ordinary.section, 8, true));
        }
    }
}

fn mutation_result(result: io::Result<()>, alias: &Path) -> String {
    match result {
        Ok(()) => format!("created:{}", read_result(alias)),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => "denied".into(),
        Err(error) => panic!(
            "unexpected mutation result for {}: {error}",
            alias.display()
        ),
    }
}

fn write_result(path: &Path) -> String {
    match fs::write(path, b"unwanted-alias-write\n") {
        Ok(()) => "writable".into(),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => "denied".into(),
        Err(error) => panic!("unexpected write result for {}: {error}", path.display()),
    }
}

fn write_mutation_result(result: io::Result<()>, alias: &Path) -> String {
    match result {
        Ok(()) => format!("created:{}", write_result(alias)),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => "denied".into(),
        Err(error) => panic!("unexpected write alias mutation: {error}"),
    }
}

#[cfg(target_os = "linux")]
fn link_at(root: &Path, source: &str, alias: &str, flags: i32) -> io::Result<()> {
    use std::{ffi::CString, os::fd::AsRawFd};
    unsafe extern "C" {
        fn linkat(
            old_dir: i32,
            old: *const std::ffi::c_char,
            new_dir: i32,
            new: *const std::ffi::c_char,
            flags: i32,
        ) -> i32;
    }
    let directory = fs::File::open(root).unwrap();
    let source = CString::new(source).unwrap();
    let alias = CString::new(alias).unwrap();
    let result = unsafe {
        linkat(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            alias.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn link_empty(root: &Path, descriptor: i32) -> io::Result<()> {
    use std::{ffi::CString, os::fd::AsRawFd};
    unsafe extern "C" {
        fn linkat(
            old_dir: i32,
            old: *const std::ffi::c_char,
            new_dir: i32,
            new: *const std::ffi::c_char,
            flags: i32,
        ) -> i32;
    }
    let directory = fs::File::open(root).unwrap();
    let alias = CString::new("empty.alias").unwrap();
    if unsafe {
        linkat(
            descriptor,
            c"".as_ptr(),
            directory.as_raw_fd(),
            alias.as_ptr(),
            0x1000,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn exchange(root: &Path, source: &str, destination: &str) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    unsafe extern "C" {
        fn renameat2(
            old_dir: i32,
            old: *const std::ffi::c_char,
            new_dir: i32,
            new: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
    }
    let source = CString::new(root.join(source).as_os_str().as_bytes()).unwrap();
    let destination = CString::new(root.join(destination).as_os_str().as_bytes()).unwrap();
    if unsafe { renameat2(-100, source.as_ptr(), -100, destination.as_ptr(), 2) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn bytepath_cases(root: &Path) {
    use std::{
        ffi::{CString, OsString},
        os::{
            fd::AsRawFd,
            unix::ffi::{OsStrExt, OsStringExt},
        },
    };
    unsafe extern "C" {
        fn link(old: *const std::ffi::c_char, new: *const std::ffi::c_char) -> i32;
        fn linkat(
            od: i32,
            old: *const std::ffi::c_char,
            nd: i32,
            new: *const std::ffi::c_char,
            flags: i32,
        ) -> i32;
        fn rename(old: *const std::ffi::c_char, new: *const std::ffi::c_char) -> i32;
        fn renameat(
            od: i32,
            old: *const std::ffi::c_char,
            nd: i32,
            new: *const std::ffi::c_char,
        ) -> i32;
        fn renameat2(
            od: i32,
            old: *const std::ffi::c_char,
            nd: i32,
            new: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
        fn __errno_location() -> *mut i32;
    }
    for route in ["source-deny", "destination-deny", "unknown", "ordinary"] {
        for operation in ["link", "linkat", "rename", "renameat", "renameat2"] {
            let directory = root.join("bytepaths").join(route).join(operation);
            let binary = |name: &[u8]| OsString::from_vec(name.to_vec());
            let source = directory.join(match route {
                "source-deny" => OsString::from("auth.key"),
                "ordinary" => OsString::from("ordinary.data"),
                _ => binary(b"source-\xff.data"),
            });
            let destination = directory.join(match route {
                "destination-deny" => OsString::from("bytepath-destination.key"),
                "ordinary" => OsString::from("ordinary.alias"),
                _ => binary(b"alias-\xff.data"),
            });
            let source_c = CString::new(source.as_os_str().as_bytes()).unwrap();
            let destination_c = CString::new(destination.as_os_str().as_bytes()).unwrap();
            let old_relative = CString::new(source.file_name().unwrap().as_bytes()).unwrap();
            let new_relative = CString::new(destination.file_name().unwrap().as_bytes()).unwrap();
            let parent = fs::File::open(&directory).unwrap();
            let status = unsafe {
                *__errno_location() = 12345;
                let status = match operation {
                    "link" => link(source_c.as_ptr(), destination_c.as_ptr()),
                    "linkat" => linkat(
                        parent.as_raw_fd(),
                        old_relative.as_ptr(),
                        parent.as_raw_fd(),
                        new_relative.as_ptr(),
                        0,
                    ),
                    "rename" => rename(source_c.as_ptr(), destination_c.as_ptr()),
                    "renameat" => renameat(
                        parent.as_raw_fd(),
                        old_relative.as_ptr(),
                        parent.as_raw_fd(),
                        new_relative.as_ptr(),
                    ),
                    "renameat2" => renameat2(
                        parent.as_raw_fd(),
                        old_relative.as_ptr(),
                        parent.as_raw_fd(),
                        new_relative.as_ptr(),
                        0,
                    ),
                    _ => unreachable!(),
                };
                if status == 0 {
                    assert_eq!(
                        *__errno_location(),
                        12345,
                        "namespace success changed caller errno"
                    );
                }
                status
            };
            let result = if status == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            };
            emit(
                &format!("bytepath-{route}-{operation}"),
                &mutation_result(result, &destination),
            );
        }
    }
}

fn main() {
    let root = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("expected private fixture root"),
    );
    #[cfg(windows)]
    if std::env::args_os()
        .nth(2)
        .is_some_and(|mode| mode == "supersede-unmanaged")
    {
        // The driver runs this exact syscall without HyperHub before starting
        // Serve. A policy denial cannot conceal invalid positive-control input.
        let path = root.join("supersede-preflight.data");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"private-supersede-preflight").unwrap();
        drop(file);
        assert_eq!(windows_mapping::supersede(&path), "opened:replaced");
        fs::remove_file(&path).unwrap();
        println!("FILE_ALIAS_SUPERSEDE_PREFLIGHT_OK native_status=0 replaced=true");
        return;
    }
    #[cfg(windows)]
    let mappings = windows_mapping::Mappings::prepare(&root);
    println!("READY {}", std::process::id());
    io::stdout().flush().unwrap();
    let mut command = String::new();
    loop {
        command.clear();
        io::stdin().lock().read_line(&mut command).unwrap();
        #[cfg(windows)]
        if command.trim() == "policy-check" {
            println!(
                "POLICY_{} {}",
                if windows_mapping::Mappings::policy_ready(&root) {
                    "READY"
                } else {
                    "PENDING"
                },
                std::process::id()
            );
            io::stdout().flush().unwrap();
            continue;
        }
        assert_eq!(command.trim(), "go");
        break;
    }

    let bytepath_only = std::env::args_os()
        .nth(2)
        .is_some_and(|mode| mode == "bytepath-only");
    if !bytepath_only {
        // This observation deliberately comes first. A prior deny must not seed an
        // identity cache and make an existing alias appear more protected than it is.
        emit(
            "preexisting-hardlink-first",
            &read_result(&root.join("existing.alias")),
        );
        emit("direct-read", &read_result(&root.join("auth.key")));
        emit(
            "combined-rw-open",
            &opened_read_result(
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(root.join("auth.key")),
            ),
        );
        emit(
            "create-read-open",
            &create_read_result(&root.join("auth.key")),
        );
        emit(
            "allowed-combined-rw-open",
            &opened_read_result(
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(root.join("ordinary.txt")),
            ),
        );
        emit(
            "allowed-create-read-open",
            &create_read_result(&root.join("ordinary.txt")),
        );
        #[cfg(windows)]
        {
            mappings.run();
            emit(
                "delete-on-close",
                &windows_mapping::delete_on_close(&root.join("delete-close.data")),
            );
            emit(
                "supersede",
                &windows_mapping::supersede(&root.join("supersede.data")),
            );
            emit(
                "allowed-delete-on-close",
                &windows_mapping::delete_on_close(&root.join("delete-allowed.data")),
            );
            emit(
                "allowed-supersede",
                &windows_mapping::supersede(&root.join("supersede-allowed.data")),
            );
        }
        emit(
            "write-only-direct-read",
            &read_result(&root.join("write-link.data")),
        );
        emit(
            "write-only-direct-write",
            &write_result(&root.join("write-link.data")),
        );
        emit(
            "write-only-hardlink",
            &write_mutation_result(
                fs::hard_link(
                    root.join("write-link.data"),
                    root.join("write-linked.alias"),
                ),
                &root.join("write-linked.alias"),
            ),
        );
        emit(
            "write-only-rename",
            &write_mutation_result(
                fs::rename(
                    root.join("write-rename.data"),
                    root.join("write-renamed.alias"),
                ),
                &root.join("write-renamed.alias"),
            ),
        );
        let copy = root.join("copy.alias");
        emit(
            "copy",
            &mutation_result(fs::copy(root.join("auth.key"), &copy).map(|_| ()), &copy),
        );
        let renamed = root.join("rename.alias");
        emit(
            "rename",
            &mutation_result(fs::rename(root.join("rename.key"), &renamed), &renamed),
        );
        let linked = root.join("managed.alias");
        emit(
            "hardlink",
            &mutation_result(fs::hard_link(root.join("auth.key"), &linked), &linked),
        );
        #[cfg(target_os = "linux")]
        {
            emit(
                "exact-directory-alias-hardlink",
                &mutation_result(
                    fs::hard_link(
                        root.join("exact-directory.symlink/protected.data"),
                        root.join("exact-linked.alias"),
                    ),
                    &root.join("exact-linked.alias"),
                ),
            );
            emit(
                "exact-directory-alias-rename",
                &mutation_result(
                    fs::rename(
                        root.join("exact-directory.symlink/protected.data"),
                        root.join("exact-renamed.alias"),
                    ),
                    &root.join("exact-renamed.alias"),
                ),
            );
            emit(
                "rename-exchange",
                &mutation_result(
                    exchange(&root, "exchange-ordinary.txt", "exchange.key"),
                    &root.join("exchange-ordinary.txt"),
                ),
            );
            emit(
                "rename-exchange-source-create",
                &mutation_result(
                    exchange(&root, "exchange-create.key", "exchange-create-ordinary.txt"),
                    &root.join("exchange-create-ordinary.txt"),
                ),
            );
            emit(
                "allowed-rename-exchange",
                &mutation_result(
                    exchange(&root, "ordinary.txt", "exchange-create-ordinary.txt"),
                    &root.join("ordinary.txt"),
                ),
            );
            emit(
                "linkat-dirfd",
                &mutation_result(
                    link_at(&root, "auth.key", "dirfd.alias", 0),
                    &root.join("dirfd.alias"),
                ),
            );
            // AT_SYMLINK_FOLLOW tests the source referent rather than its new name.
            emit(
                "linkat-follow",
                &mutation_result(
                    link_at(&root, "source.symlink", "follow.alias", 0x400),
                    &root.join("follow.alias"),
                ),
            );
            emit(
                "linkat-nofollow",
                &mutation_result(
                    link_at(&root, "source.symlink", "nofollow.alias", 0),
                    &root.join("nofollow.alias"),
                ),
            );
            emit(
                "directory-symlink-read",
                &read_result(&root.join("directory.symlink/../auth.key")),
            );
            emit(
                "directory-symlink-hardlink",
                &mutation_result(
                    fs::hard_link(
                        root.join("directory.symlink/../auth.key"),
                        root.join("directory.alias"),
                    ),
                    &root.join("directory.alias"),
                ),
            );
            let inherited = std::env::var("HH_ALIAS_INHERITED_FD")
                .unwrap()
                .parse()
                .unwrap();
            emit(
                "inherited-proc-fd-read",
                &read_result(&PathBuf::from(format!("/proc/self/fd/{inherited}"))),
            );
            let empty = link_empty(&root, inherited);
            if std::env::var("HH_ALIAS_EMPTY_SUPPORTED").unwrap() == "true" {
                emit(
                    "linkat-empty",
                    &mutation_result(empty, &root.join("empty.alias")),
                );
            } else {
                assert!(
                    empty.is_err(),
                    "unsupported empty-path operation unexpectedly succeeded"
                );
                emit("linkat-empty", "unsupported-by-unmanaged-preflight");
            }
        }
        #[cfg(unix)]
        emit("symlink-read", &read_result(&root.join("source.symlink")));
        #[cfg(unix)]
        emit(
            "lexical-symlink-read",
            &read_result(&root.join("lexical.key")),
        );
        let allowed = root.join("allowed.alias");
        emit(
            "allowed-hardlink",
            &mutation_result(fs::hard_link(root.join("ordinary.txt"), &allowed), &allowed),
        );
        let renamed_allowed = root.join("allowed-rename.alias");
        emit(
            "allowed-rename",
            &mutation_result(
                fs::rename(root.join("ordinary-rename.txt"), &renamed_allowed),
                &renamed_allowed,
            ),
        );
        #[cfg(target_os = "linux")]
        emit(
            "allowed-linkat",
            &mutation_result(
                link_at(&root, "ordinary.txt", "allowed-dirfd.alias", 0),
                &root.join("allowed-dirfd.alias"),
            ),
        );
    }
    #[cfg(target_os = "linux")]
    bytepath_cases(&root);
    println!("DONE");
    io::stdout().flush().unwrap();
    command.clear();
    io::stdin().lock().read_line(&mut command).unwrap();
    assert_eq!(command.trim(), "quit");
}
