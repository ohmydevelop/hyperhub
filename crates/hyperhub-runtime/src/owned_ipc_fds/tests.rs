use super::*;
use std::process::Command;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;

// Fork never returns into the multi-threaded cargo test harness in a child.
// Each mode runs in its own executable process, and fork children only use raw
// syscalls for synchronization and _exit; the lifecycle mode additionally
// exercises copied-wrapper Drop and fresh socket creation after child reset.
// The atfork child callback itself performs no allocation or destructors.
#[test]
fn owned_ipc_fork_lifecycle() {
    const MODE: &str = "HYPERHUB_OWNED_IPC_TEST";
    if let Ok(mode) = std::env::var(MODE) {
        match mode.as_str() {
            "lifecycle" => lifecycle(),
            "concurrent" => concurrent(),
            "capacity" => capacity(),
            _ => panic!("unknown owned IPC regression mode"),
        }
        return;
    }
    for mode in ["lifecycle", "concurrent", "capacity"] {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "owned_ipc_fds::tests::owned_ipc_fork_lifecycle",
                "--nocapture",
            ])
            .env(MODE, mode)
            .status()
            .unwrap();
        assert!(status.success(), "owned IPC mode {mode}: {status}");
    }
}
unsafe extern "C" fn prepare() {
    unsafe { fork_prepare() };
}
unsafe extern "C" fn parent() {
    unsafe { fork_parent() };
}
unsafe extern "C" fn child() {
    unsafe { fork_child() };
}
fn install() {
    assert_eq!(
        unsafe { libc::pthread_atfork(Some(prepare), Some(parent), Some(child)) },
        0
    );
}
fn valid(fd: RawFd) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}
fn wait(pid: libc::pid_t) {
    let mut status = 0;
    assert!(pid > 0);
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}
fn lifecycle() {
    install();
    let directory = std::env::temp_dir().join(format!("hyperhub-owned-ipc-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("host.sock");
    let listener = IpcListener::bind(&path).unwrap();
    let public_path = directory.join("public.sock");
    std::fs::set_permissions(&directory, {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o700)
    })
    .unwrap();
    let public_listener = crate::attachment::Listener::bind(public_path.to_str().unwrap()).unwrap();
    let control = IpcStream::connect(path.to_str().unwrap()).unwrap();
    let accepted = listener.accept().unwrap();
    let listener_fd = listener.ownership.fd;
    let control_fd = control.ownership.fd;
    let accepted_fd = accepted.ownership.fd;
    let (business, mut peer) = UnixStream::pair().unwrap();
    let business_fd = business.as_raw_fd();
    let peer_fd = peer.as_raw_fd();
    let enrolled = SLOTS
        .iter()
        .filter(|slot| slot.fd.load(Ordering::Relaxed) >= 0)
        .count();
    assert!(IpcStream::connect(directory.join("absent.sock").to_str().unwrap()).is_err());
    assert!(IpcListener::bind(&path).is_err());
    assert!(path.exists());
    assert_eq!(
        SLOTS
            .iter()
            .filter(|slot| slot.fd.load(Ordering::Relaxed) >= 0)
            .count(),
        enrolled
    );
    let child = unsafe { libc::fork() };
    if child == 0 {
        let mut ok = !valid(listener_fd)
            && !valid(control_fd)
            && !valid(accepted_fd)
            && valid(business_fd)
            && valid(peer_fd)
            && !control.is_current();
        // Reuse the exact old descriptor, then explicitly drop copied wrappers.
        // The child's stale owners must not close it or unlink the parent's path.
        ok &= unsafe { libc::dup2(business_fd, control_fd) } == control_fd;
        drop(control);
        drop(accepted);
        // Listener's wrapper has no path cleanup; runtime Listener separately
        // guards unlink with the same ownership check.
        drop(listener);
        drop(public_listener);
        ok &= valid(control_fd);
        // A fresh registration is allowed immediately after the child reset.
        match IpcStream::socket() {
            Ok(fresh) => {
                ok &= fresh.is_current();
                drop(fresh);
            }
            Err(_) => ok = false,
        }
        let byte = if ok { 0x7b_u8 } else { 0_u8 };
        unsafe { libc::write(control_fd, (&byte as *const u8).cast(), 1) };
        // Remain alive while the parent checks that its control endpoints work.
        let mut reply = 0_u8;
        ok &= unsafe { libc::read(business_fd, (&mut reply as *mut u8).cast(), 1) } == 1
            && reply == 0x42;
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut result = [0];
    peer.read_exact(&mut result).unwrap();
    assert_eq!(result, [0x7b]);
    assert!(path.exists());
    assert!(
        public_path.exists(),
        "copied listener must not unlink the parent endpoint"
    );
    assert!(valid(listener_fd) && valid(control_fd) && valid(accepted_fd));
    let mut control = control;
    let mut accepted = accepted;
    control.write_all(b"p").unwrap();
    let mut byte = [0];
    accepted.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"p");
    // Parent retirement must produce EOF even while the ordinary fork child is
    // alive, as EngineHost enrollment relies on the same stream lifetime.
    drop(control);
    accepted
        .get()
        .unwrap()
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert_eq!(accepted.read(&mut byte).unwrap(), 0);
    peer.write_all(&[0x42]).unwrap();
    wait(child);
    drop((listener, accepted, public_listener));
    assert!(!public_path.exists());
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
fn concurrent() {
    install();
    let stop = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let stop = stop.clone();
        workers.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let socket = IpcStream::socket().unwrap();
                assert!(socket.is_current());
                drop(socket);
            }
        }));
    }
    let (business, _peer) = UnixStream::pair().unwrap();
    let business_fd = business.as_raw_fd();
    for _ in 0..64 {
        let child = unsafe { libc::fork() };
        if child == 0 {
            let empty = SLOTS
                .iter()
                .all(|slot| slot.fd.load(Ordering::Relaxed) == -1);
            let ok = empty && valid(business_fd) && OWNER.load(Ordering::Relaxed) == 0;
            unsafe { libc::_exit(if ok { 0 } else { 2 }) };
        }
        wait(child);
    }
    stop.store(true, Ordering::Release);
    for worker in workers {
        worker.join().unwrap();
    }
}
fn capacity() {
    // Occupy slots with sentinels, without consuming thousands of OS FDs or
    // depending on the host's RLIMIT_NOFILE. register must close its failed FD.
    let _fence = Fence::enter();
    for slot in &SLOTS {
        slot.fd.store(i32::MAX, Ordering::Relaxed);
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);
    let result = Ownership::register(fd);
    assert!(matches!(result, Err(ref error) if error.raw_os_error() == Some(libc::EMFILE)));
    assert!(!valid(fd));
    for slot in &SLOTS {
        slot.fd.store(-1, Ordering::Relaxed);
    }
    // Same-thread re-entry is deliberately permitted, including a nested fence.
    let nested = Fence::enter();
    assert_eq!(DEPTH.load(Ordering::Relaxed), 2);
    drop(nested);
    assert_eq!(DEPTH.load(Ordering::Relaxed), 1);
}
