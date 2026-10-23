//! Deterministic failed-process-fork target. Threads and shared-VM helpers stay
//! available so Frida can recover and unload after libc fork returns EAGAIN.
//! This fixture never changes resource limits or accesses the network.
#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod native {
    use std::ffi::{c_int, c_ulong};
    use std::io::{self, BufRead, Write};
    use std::path::{Path, PathBuf};

    #[repr(C)]
    struct Filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct Program {
        len: u16,
        filters: *const Filter,
    }

    unsafe extern "C" {
        fn prctl(option: c_int, ...) -> c_int;
        fn fork() -> c_int;
        fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        fn _exit(status: c_int) -> !;
        fn __errno_location() -> *mut c_int;
    }

    fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> Filter {
        Filter { code, jt, jf, k }
    }

    fn install() {
        #[cfg(target_arch = "x86_64")]
        let (architecture, clone, other_process_calls) = (0xc000_003e, 56, &[57, 58][..]);
        #[cfg(target_arch = "aarch64")]
        let (architecture, clone, other_process_calls) = (0xc000_00b7, 220, &[][..]);

        const EAGAIN: u32 = 11;
        const CLONE_VM: u32 = 0x0000_0100;
        const DENY: u32 = 0x0005_0000 | EAGAIN;
        const ALLOW: u32 = 0x7fff_0000;
        // seccomp_data has nr at offset0, arch at4, and args[0] at16.
        // These are the native Linux UAPI layouts for both supported targets.
        let mut filter = vec![
            instruction(0x20, 0, 0, 4),
            instruction(0x15, 1, 0, architecture),
            instruction(0x06, 0, 0, 0x8000_0000),
            instruction(0x20, 0, 0, 0),
        ];
        for number in other_process_calls {
            filter.push(instruction(0x15, 0, 1, *number));
            filter.push(instruction(0x06, 0, 0, DENY));
        }
        filter.extend([
            instruction(0x15, 0, 3, clone),
            instruction(0x20, 0, 0, 16),
            instruction(0x45, 1, 0, CLONE_VM),
            instruction(0x06, 0, 0, DENY),
            instruction(0x06, 0, 0, ALLOW),
        ]);
        let program = Program {
            len: filter.len().try_into().unwrap(),
            filters: filter.as_ptr(),
        };
        // Keep pthread clones and Gum's separate-process shared-VM ptrace helper
        // available. Gum17.17 uses CLONE_VM | CLONE_SETTLS without CLONE_THREAD
        // in gum_linux_modify_thread; ordinary libc fork has no CLONE_VM.
        // Only this process and its future threads inherit the filter. clone3
        // remains allowed: classic BPF cannot inspect its pointed-to arguments.
        // The actual fork assertion below rejects a changed libc syscall path.
        let result = unsafe { prctl(38, 1 as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong) };
        let error = unsafe { *__errno_location() };
        assert_eq!(result, 0, "private no_new_privs failed with errno {error}");
        let result = unsafe { prctl(22, 2 as c_ulong, &program as *const Program) };
        let error = unsafe { *__errno_location() };
        assert_eq!(result, 0, "private seccomp setup failed with errno {error}");
        println!("FILTER_READY {}", std::process::id());
    }

    fn file(path: &Path) {
        let bytes = std::fs::read(path).expect("controlled allowed file must stay readable");
        println!("FILE_OK {} {}", std::process::id(), bytes.len());
    }

    fn thread() {
        let caller = std::thread::current().id();
        let created = std::thread::spawn(move || {
            assert_ne!(std::thread::current().id(), caller);
            37
        });
        assert_eq!(created.join().unwrap(), 37);
        println!("THREAD_OK {}", std::process::id());
    }

    fn failed_fork() {
        let result = unsafe { fork() };
        let error = unsafe { *__errno_location() };
        if result == 0 {
            // A changed libc implementation must fail this test, without
            // allowing an unexpected child to continue the command protocol.
            unsafe { _exit(125) };
        }
        if result > 0 {
            let mut status = 0;
            unsafe { waitpid(result, &mut status, 0) };
        }
        assert_eq!(result, -1, "private seccomp did not reject process fork");
        assert_eq!(error, 11, "failed libc fork must preserve Linux EAGAIN");
        println!("FORK_EAGAIN {} {error}", std::process::id());
    }

    pub fn run() {
        let mut arguments = std::env::args_os().skip(1);
        let mode = arguments.next().expect("allowed file path or noop-child");
        if mode == "noop-child" {
            let path = PathBuf::from(
                std::env::var_os("HH_FAILED_FORK_FILE")
                    .expect("self-driven case requires HH_FAILED_FORK_FILE"),
            );
            file(&path);
            install();
            thread();
            failed_fork();
            failed_fork();
            file(&path);
            println!("FAILED_FORK_CASE_PASS");
            io::stdout().flush().unwrap();
            return;
        }

        let path = PathBuf::from(mode);
        let mut installed = false;
        println!("TARGET_PID {}", std::process::id());
        io::stdout().flush().unwrap();
        for line in io::stdin().lock().lines() {
            match line.unwrap().as_str() {
                "file" => file(&path),
                "install" => {
                    assert!(!installed, "install the private filter exactly once");
                    install();
                    installed = true;
                }
                "thread" => thread(),
                "fail-fork" => {
                    assert!(installed, "install the private filter before fork");
                    failed_fork();
                }
                "quit" => {
                    println!("TARGET_DONE {}", std::process::id());
                    io::stdout().flush().unwrap();
                    return;
                }
                _ => panic!("unexpected failed-fork fixture command"),
            }
            io::stdout().flush().unwrap();
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    native::run();
}

#[cfg(not(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn main() {
    panic!("failed-fork fixture requires native Linux x86_64 or AArch64");
}
