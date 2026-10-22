//! Native fork ownership regression, executed in its own source-built process.
//! A DSO thread owns the real regex-cache mutex at the exact fork boundary.
use hyperhub_engine::runtime::{Runtime, Settings};
use hyperhub_engine::{
    contract::*,
    management::{self, Command, Reply},
};
use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
    path::PathBuf,
    time::Duration,
};
unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn alarm(seconds: u32) -> u32;
}
fn decide(lease: &hyperhub_engine::runtime::Lease) -> String {
    hyperhub_engine::policy(
        lease,
        FILE_POLICY,
        &PolicyInput {
            snapshot: [("default_action", "pass")].into_iter().collect(),
            target: "/isolated/engine-policy-deny".into(),
            operation: "read".into(),
            command_line: String::new(),
        },
    )
    .unwrap()
    .action
}
fn apply(runtime: &Runtime, command: Command) {
    if let Reply::Error { message, .. } = unsafe { management::execute(runtime, command) } {
        panic!("{message}");
    }
}
fn loaded(hash: &str) -> bool {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .contains(hash)
}
fn main() {
    unsafe {
        alarm(20);
    }
    let args: Vec<_> = std::env::args_os().collect();
    let module = PathBuf::from(&args[1]);
    let cache = PathBuf::from(&args[2]);
    let version = args[3].to_str().unwrap();
    let bytes = std::fs::read(&module).unwrap();
    let manifest = hyperhub_engine::manifest(&bytes, version);
    let runtime = hyperhub_engine::resident_with(Settings {
        health_window: Duration::ZERO,
        ..Settings::default()
    });
    let old = runtime.acquire();
    apply(
        &runtime,
        Command::Prepare {
            id: "fork-group".into(),
            manifest: manifest.clone(),
            source: module.clone(),
            cache: cache.clone(),
        },
    );
    apply(
        &runtime,
        Command::CommitHeld {
            id: "fork-group".into(),
        },
    );
    let current = runtime.acquire();
    assert_eq!(decide(&old), "pass");
    assert_eq!(decide(&current), "deny");
    let cached = cache.join(format!(
        "{}{}",
        manifest.sha256,
        std::env::consts::DLL_SUFFIX
    ));
    let library = unsafe { libloading::Library::new(&cached) }.unwrap();
    let hold = unsafe {
        *library
            .get::<unsafe extern "C" fn(i32, i32)>(b"hh_fixture_hold_cache\0")
            .unwrap()
    };
    let (mut ready_read, ready_write) = std::os::unix::net::UnixStream::pair().unwrap();
    let (release_read, mut release_write) = std::os::unix::net::UnixStream::pair().unwrap();
    let blocked = std::thread::spawn(move || unsafe {
        hold(ready_write.as_raw_fd(), release_read.as_raw_fd())
    });
    let mut byte = [0];
    ready_read.read_exact(&mut byte).unwrap();
    let frozen = runtime.freeze_fork().unwrap();
    let pid = unsafe { fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            alarm(10);
        }
        let original_thread = std::thread::current().id();
        let raw_guard = Box::into_raw(Box::new(frozen)) as usize;
        let result = std::thread::spawn(move || {
            assert_ne!(
                std::thread::current().id(),
                original_thread,
                "rebuild must model Frida's separate child thread"
            );
            let frozen = unsafe {
                *Box::from_raw(
                    raw_guard as *mut hyperhub_engine::runtime::generation::ForkGuard<'static>,
                )
            };

            let image = unsafe { frozen.into_child_image() };
            let rebased = unsafe { image.rebuild() }.unwrap();
            let old = rebased.rebind(&old).unwrap();
            let current = rebased.rebind(&current).unwrap();
            let child_runtime = rebased.runtime.clone();
            drop(rebased);
            // This independent diagnostic dlopen reference also belongs to the copied
            // parent. Release it so reclamation must remove the sole actual native DSO.
            drop(library);
            assert_eq!(decide(&old), "pass");
            assert_eq!(decide(&current), "deny");
            assert_eq!(child_runtime.snapshot().unwrap().retired[0].references, 1);
            assert!(loaded(&manifest.sha256));
            child_runtime
                .rollback("fork-group", "child rollback")
                .unwrap();
            assert_eq!(decide(&child_runtime.acquire()), "pass");
            assert!(loaded(&manifest.sha256));
            drop(current);
            child_runtime.observe().unwrap();
            assert!(
                !loaded(&manifest.sha256),
                "retired native code leaked in fork child"
            );
            assert!(child_runtime.snapshot().unwrap().retired.is_empty());
        })
        .join();
        unsafe { _exit(if result.is_ok() { 0 } else { 3 }) }
    }
    drop(frozen);
    release_write.write_all(&[1]).unwrap();
    blocked.join().unwrap();
    let mut status = 0;
    assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0, "fork child failed");
    assert_eq!(
        decide(&runtime.acquire()),
        "deny",
        "child ownership transfer changed parent"
    );
    runtime.rollback("fork-group", "parent cleanup").unwrap();
    drop(current);
    drop(old);
    runtime.observe().unwrap();
    println!("NATIVE_FORK_OK pid={}", std::process::id());
}
