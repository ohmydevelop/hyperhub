//! Persistent native target: real sockets, file access, process creation, and
//! children that independently exercise the current processing generation.
use std::io::{self, BufRead, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
#[cfg(unix)]
struct ForkChild {
    pid: i32,
    control: std::os::unix::net::UnixStream,
}
#[cfg(unix)]
fn fork_command(child: &mut ForkChild, command: &str) -> Vec<String> {
    writeln!(child.control, "{command}").unwrap();
    child.control.flush().unwrap();
    let mut lines = Vec::new();
    let mut reader = io::BufReader::new(&mut child.control);
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line == "FORK_END\n" {
            break;
        }
        assert!(line.starts_with("FORK_POLICY "));
        lines.push(line);
    }
    assert!(!lines.is_empty());
    lines
}
#[cfg(unix)]
fn finish_forks(children: Vec<ForkChild>) {
    unsafe extern "C" {
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    }
    for mut child in children {
        child.control.write_all(b"quit\n").unwrap();
        let mut status = 0;
        assert_eq!(unsafe { waitpid(child.pid, &mut status, 0) }, child.pid);
        assert_eq!(status, 0);
    }
}
#[cfg(unix)]
fn fork_target(path: &str, streams: &mut [TcpStream]) -> ForkChild {
    unsafe extern "C" {
        fn fork() -> i32;
    }
    let (parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    let pid = unsafe { fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        drop(parent);
        let mut output = child.try_clone().unwrap();
        let mut nested = Vec::new();
        for command in io::BufReader::new(child).lines() {
            let command = command.unwrap();
            if command == "quit" {
                finish_forks(nested);
                std::process::exit(0);
            }
            if let Some(path) = command.strip_prefix("nested ") {
                let mut next = fork_target(path, streams);
                for line in fork_command(&mut next, "check") {
                    output.write_all(line.as_bytes()).unwrap();
                }
                nested.push(next);
            } else {
                assert_eq!(command, "check");
                for stream in &mut *streams {
                    stream.write_all(b"ping").unwrap();
                    let mut reply = [0; 4];
                    stream.read_exact(&mut reply).unwrap();
                    assert_eq!(&reply, b"ping");
                }
                writeln!(
                    output,
                    "FORK_POLICY {} {}",
                    std::process::id(),
                    std::fs::read(path).is_ok()
                )
                .unwrap();
                for child in &mut nested {
                    for line in fork_command(child, "check") {
                        output.write_all(line.as_bytes()).unwrap();
                    }
                }
            }
            output.write_all(b"FORK_END\n").unwrap();
            output.flush().unwrap();
        }
        std::process::exit(1);
    }
    drop(child);
    ForkChild {
        pid,
        control: parent,
    }
}
#[cfg(target_os = "linux")]
fn fork_exec_target(path: &str, expected: &str) {
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn fork() -> i32;
        fn execv(path: *const std::ffi::c_char, argv: *const *const std::ffi::c_char) -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(status: i32) -> !;
        fn __errno_location() -> *mut i32;
        fn write(fd: i32, bytes: *const u8, length: usize) -> isize;
    }
    // Prepare every argument before fork. The child immediately replaces its
    // image instead of going through Rust Command's posix_spawn path.
    let executable =
        std::ffi::CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes()).unwrap();
    let path = std::ffi::CString::new(path).unwrap();
    let expected = std::ffi::CString::new(expected).unwrap();
    let arguments = [
        executable.as_ptr(),
        c"fork-exec-child".as_ptr(),
        path.as_ptr(),
        expected.as_ptr(),
        std::ptr::null(),
    ];
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            execv(executable.as_ptr(), arguments.as_ptr());
            let error = *__errno_location();
            let mut message = *b"fork exec errno=000\n";
            message[16] = b'0' + ((error / 100) % 10) as u8;
            message[17] = b'0' + ((error / 10) % 10) as u8;
            message[18] = b'0' + (error % 10) as u8;
            write(2, message.as_ptr(), message.len());
            _exit(127);
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
    println!("FORK_EXEC_STATUS {} {child} {status}", std::process::id());
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).is_some_and(|s| s == "noop-child") {
        return;
    }
    if args.get(1).is_some_and(|s| s == "business-exit-child") {
        std::process::exit(args[2].parse().unwrap());
    }
    #[cfg(target_os = "linux")]
    if args.get(1).is_some_and(|s| s == "signal-child") {
        unsafe extern "C" {
            fn strlen(value: *const std::ffi::c_char) -> usize;
        }
        // Fault in native code; a synthetic raise may be handled and return.
        unsafe {
            std::hint::black_box(strlen(std::ptr::null()));
        }
        std::process::exit(99);
    }
    if args.get(1).is_some_and(|s| s == "policy-child") {
        println!(
            "CHILD_POLICY {} {}",
            std::process::id(),
            std::fs::read(&args[2]).is_ok()
        );
        return;
    }
    if args.get(1).is_some_and(|s| s == "fork-exec-child") {
        let allowed = std::fs::read(&args[2]).is_ok();
        println!("FORK_EXEC_POLICY {} {allowed}", std::process::id());
        std::process::exit(if allowed.to_string() == args[3] { 0 } else { 2 });
    }
    println!("TARGET_PID {}", std::process::id());
    io::stdout().flush().unwrap();
    let mut streams: Vec<TcpStream> = Vec::new();
    #[cfg(target_os = "linux")]
    if args.get(1).is_some_and(|s| s == "inherited-sockets") {
        use std::os::fd::FromRawFd;
        for fd in args[2].split(',') {
            streams.push(unsafe { TcpStream::from_raw_fd(fd.parse().unwrap()) });
        }
        for stream in &mut streams {
            stream.write_all(b"ping").unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"ping");
        }
        println!("EXEC_SOCKETS {} {}", std::process::id(), streams.len());
        io::stdout().flush().unwrap();
    }
    #[cfg(unix)]
    let mut fork_children: Vec<ForkChild> = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        if line == "exec-sockets" {
            #[cfg(target_os = "linux")]
            {
                use std::os::{fd::AsRawFd, unix::process::CommandExt};
                unsafe extern "C" {
                    fn fcntl(fd: i32, command: i32, ...) -> i32;
                }
                let mut inherited = Vec::new();
                for stream in &streams {
                    let fd = stream.as_raw_fd();
                    // Linux F_GETFD/F_SETFD and FD_CLOEXEC. Keep only the
                    // explicit live business descriptors across this exec.
                    let flags = unsafe { fcntl(fd, 1) };
                    assert!(flags >= 0);
                    assert_eq!(unsafe { fcntl(fd, 2, flags & !1) }, 0);
                    inherited.push(fd.to_string());
                }
                assert!(!inherited.is_empty());
                let error = std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("inherited-sockets")
                    .arg(inherited.join(","))
                    .exec();
                panic!("exec with inherited business sockets failed: {error}");
            }
        } else if let Some(path) = line.strip_prefix("loader ") {
            #[cfg(target_os = "linux")]
            unsafe {
                #[link(name = "dl")]
                unsafe extern "C" {
                    fn dlopen(path: *const std::ffi::c_char, flags: i32) -> *mut std::ffi::c_void;
                    fn dlsym(
                        handle: *mut std::ffi::c_void,
                        name: *const std::ffi::c_char,
                    ) -> *mut std::ffi::c_void;
                    fn dlclose(handle: *mut std::ffi::c_void) -> i32;
                }
                let path = std::ffi::CString::new(path).unwrap();
                let module = dlopen(path.as_ptr(), 2);
                assert!(!module.is_null(), "native loader probe must load");
                let symbol = dlsym(module, c"hh_loader_probe_ok".as_ptr());
                assert!(!symbol.is_null());
                let check: unsafe extern "C" fn() -> i32 = std::mem::transmute(symbol);
                let passed = check() == 1;
                assert_eq!(dlclose(module), 0);
                println!("LOADER_POLICY {} {passed}", std::process::id());
            }
        } else if let Some(path) = line.strip_prefix("file ") {
            println!(
                "FILE_POLICY {} {}",
                std::process::id(),
                std::fs::read(path).is_ok()
            );
        } else if line == "signal-child" {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::process::ExitStatusExt;
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("signal-child")
                    .status()
                    .unwrap();
                assert_eq!(status.signal(), Some(11));
                println!("SIGNAL_EXIT {} 11", std::process::id());
            }
        } else if let Some(code) = line.strip_prefix("business-exit ") {
            let code: i32 = code.parse().unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("business-exit-child")
                .arg(code.to_string())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(code));
            println!("BUSINESS_EXIT {} {code}", std::process::id());
        } else if let Some(path) = line.strip_prefix("process ") {
            let result = std::process::Command::new(path).arg("noop-child").status();
            if let Err(error) = &result {
                eprintln!(
                    "PROCESS_LAUNCH_ERROR {} {:?}",
                    std::process::id(),
                    error.raw_os_error()
                );
            }
            let allowed = result.is_ok_and(|status| status.success());
            println!("PROCESS_POLICY {} {allowed}", std::process::id());
        } else if let Some(path) = line.strip_prefix("child ") {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("policy-child")
                .arg(path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8(output.stdout).unwrap());
        } else if let Some(request) = line.strip_prefix("fork-exec ") {
            #[cfg(target_os = "linux")]
            {
                let (expected, path) = request.split_once(' ').unwrap();
                fork_exec_target(path, expected);
            }
        } else if cfg!(unix) && line.starts_with("fork ") {
            #[cfg(unix)]
            {
                let mut child = fork_target(line.strip_prefix("fork ").unwrap(), &mut streams);
                for line in fork_command(&mut child, "check") {
                    print!("{line}");
                }
                fork_children.push(child);
            }
        } else if cfg!(unix) && line.starts_with("fork-nested ") {
            #[cfg(unix)]
            {
                let command = format!("nested {}", line.strip_prefix("fork-nested ").unwrap());
                for line in fork_command(fork_children.first_mut().unwrap(), &command) {
                    print!("{line}");
                }
            }
        } else if line == "orphan" {
            #[cfg(unix)]
            {
                unsafe extern "C" {
                    fn fork() -> i32;
                }
                let child = unsafe { fork() };
                assert!(child >= 0);
                if child > 0 {
                    println!("ORPHAN_PID {child}");
                    io::stdout().flush().unwrap();
                    std::process::exit(0);
                }
            }
        } else if line == "fork-check" {
            #[cfg(unix)]
            for child in &mut fork_children {
                for line in fork_command(child, "check") {
                    print!("{line}");
                }
            }
        } else {
            match line.as_str() {
                "open" => {
                    streams.push(TcpStream::connect((Ipv4Addr::LOCALHOST, 31415)).unwrap());
                }
                "quit" => break,
                "ping" => {}
                _ => panic!("unexpected fixture command"),
            }
        }
        for stream in &mut streams {
            stream.write_all(b"ping").unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"ping");
        }
        println!("TARGET_OK {} {}", std::process::id(), streams.len());
        io::stdout().flush().unwrap();
    }
    #[cfg(unix)]
    finish_forks(fork_children);
}
