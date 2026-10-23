//! File namespace mutations and content aliases. All inputs are disposable dummy files.
use std::{
    fs,
    io::{self, BufRead, Write},
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
        fn linkat(old_dir: i32, old: *const i8, new_dir: i32, new: *const i8, flags: i32) -> i32;
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
        fn linkat(old_dir: i32, old: *const i8, new_dir: i32, new: *const i8, flags: i32) -> i32;
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
fn exchange(root: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    unsafe extern "C" {
        fn renameat2(old_dir: i32, old: *const i8, new_dir: i32, new: *const i8, flags: u32)
            -> i32;
    }
    let source = CString::new(root.join("exchange-ordinary.txt").as_os_str().as_bytes()).unwrap();
    let destination = CString::new(root.join("exchange.key").as_os_str().as_bytes()).unwrap();
    if unsafe { renameat2(-100, source.as_ptr(), -100, destination.as_ptr(), 2) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn main() {
    let root = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("expected private fixture root"),
    );
    println!("READY {}", std::process::id());
    io::stdout().flush().unwrap();
    let mut command = String::new();
    io::stdin().lock().read_line(&mut command).unwrap();
    assert_eq!(command.trim(), "go");

    // This observation deliberately comes first. A prior deny must not seed an
    // identity cache and make an existing alias appear more protected than it is.
    emit(
        "preexisting-hardlink-first",
        &read_result(&root.join("existing.alias")),
    );
    emit("direct-read", &read_result(&root.join("auth.key")));
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
            &mutation_result(exchange(&root), &root.join("exchange-ordinary.txt")),
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
    println!("DONE");
    io::stdout().flush().unwrap();
    command.clear();
    io::stdin().lock().read_line(&mut command).unwrap();
    assert_eq!(command.trim(), "quit");
}
