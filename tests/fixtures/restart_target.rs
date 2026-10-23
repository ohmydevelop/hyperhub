//! Persistent executor used by the Serve restart Suite. No real credentials.
use std::{
    fs,
    io::{self, BufRead, Read, Write},
    net::{Shutdown, TcpStream},
    process::{Command, Stdio},
    time::Duration,
};

#[cfg(windows)]
fn anonymous_memory_probe() {
    use std::ffi::c_void;
    type Handle = *mut c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileMappingW(
            file: Handle,
            attributes: *const c_void,
            protection: u32,
            high: u32,
            low: u32,
            name: *const u16,
        ) -> Handle;
        fn MapViewOfFile(
            mapping: Handle,
            access: u32,
            high: u32,
            low: u32,
            bytes: usize,
        ) -> *mut c_void;
        fn UnmapViewOfFile(base: *const c_void) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }
    unsafe {
        let mapping = CreateFileMappingW(
            -1_isize as Handle,
            std::ptr::null(),
            4,
            0,
            4096,
            std::ptr::null(),
        );
        assert!(
            !mapping.is_null(),
            "pagefile mapping: {}",
            io::Error::last_os_error()
        );
        let base = MapViewOfFile(mapping, 6, 0, 0, 4096);
        if base.is_null() {
            let error = io::Error::last_os_error();
            CloseHandle(mapping);
            panic!("pagefile map view: {error}");
        }
        base.cast::<u64>().write_volatile(0x1234_5678_9ABC_DEF0);
        let readback = base.cast::<u64>().read_volatile();
        let unmapped = UnmapViewOfFile(base);
        let closed = CloseHandle(mapping);
        assert_eq!(readback, 0x1234_5678_9ABC_DEF0);
        assert_ne!(unmapped, 0, "unmap pagefile view");
        assert_ne!(closed, 0, "close pagefile mapping");
    }
    eprintln!(
        "RESTART_MEMORY_DOMAIN_OK {} pagefile=read_write",
        std::process::id()
    );
}

#[cfg(windows)]
mod spawn_diagnostics {
    use super::*;
    use std::{ffi::c_void, sync::mpsc, time::Instant};

    type Handle = *mut c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn CreatePipe(
            read: *mut Handle,
            write: *mut Handle,
            security: *const c_void,
            size: u32,
        ) -> i32;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn GetFileType(handle: Handle) -> u32;
        fn GetLastError() -> u32;
        fn SetLastError(error: u32);
        fn CloseHandle(handle: Handle) -> i32;
    }

    unsafe fn handle_type(handle: Handle) -> String {
        SetLastError(0);
        let kind = GetFileType(handle);
        let error = GetLastError();
        format!("handle={handle:p} type={kind} type_error={error}")
    }

    fn raw_stdio() {
        unsafe {
            let mut read = std::ptr::null_mut();
            let mut write = std::ptr::null_mut();
            SetLastError(0);
            let result = CreatePipe(&mut read, &mut write, std::ptr::null(), 0);
            let error = GetLastError();
            eprintln!(
                "RESTART_SPAWN_DIAG stage=create_pipe result={result} error={error} read=[{}] write=[{}]",
                handle_type(read),
                handle_type(write)
            );
            if !read.is_null() && read != -1_isize as Handle {
                CloseHandle(read);
            }
            if !write.is_null() && write != -1_isize as Handle && write != read {
                CloseHandle(write);
            }
            let name: Vec<u16> = "NUL".encode_utf16().chain(Some(0)).collect();
            for (label, access) in [("nul_read", 0x8000_0000), ("nul_write", 0x4000_0000)] {
                SetLastError(0);
                let handle = CreateFileW(
                    name.as_ptr(),
                    access,
                    3,
                    std::ptr::null(),
                    3,
                    0x80,
                    std::ptr::null_mut(),
                );
                let error = GetLastError();
                eprintln!(
                    "RESTART_SPAWN_DIAG stage={label} opened={} error={error} {}",
                    !handle.is_null() && handle != -1_isize as Handle,
                    handle_type(handle)
                );
                if handle != -1_isize as Handle && !handle.is_null() {
                    CloseHandle(handle);
                }
            }
        }
    }

    fn child(profile: &'static str) {
        let (send, receive) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name(format!("hh-restart-{profile}"))
            .spawn(move || {
                let mut command = Command::new("cmd.exe");
                command.args(["/D", "/C", "exit 0"]);
                if profile == "null" {
                    command
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                } else {
                    command
                        .stdin(Stdio::inherit())
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit());
                }
                let result = match command.spawn() {
                    Err(error) => format!(
                        "spawn_error={:?} kind={:?}",
                        error.raw_os_error(),
                        error.kind()
                    ),
                    Ok(mut child) => {
                        let pid = child.id();
                        let deadline = Instant::now() + Duration::from_secs(3);
                        loop {
                            match child.try_wait() {
                                Ok(Some(status)) => break format!("pid={pid} status={status}"),
                                Err(error) => {
                                    let _ = child.kill();
                                    let _ = child.wait();
                                    break format!(
                                        "pid={pid} wait_error={:?}",
                                        error.raw_os_error()
                                    );
                                }
                                Ok(None) if Instant::now() >= deadline => {
                                    let _ = child.kill();
                                    let _ = child.wait();
                                    break format!("pid={pid} wait_timeout=true");
                                }
                                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                            }
                        }
                    }
                };
                let _ = send.send(result);
            });
        let result = match thread {
            Ok(_) => receive
                .recv_timeout(Duration::from_secs(4))
                .unwrap_or_else(|error| format!("diagnostic_timeout={error}")),
            Err(error) => format!("diagnostic_thread_error={:?}", error.raw_os_error()),
        };
        eprintln!("RESTART_SPAWN_DIAG stage=cmd_{profile} {result}");
    }

    pub(super) fn failed_output(error: io::Error) -> ! {
        eprintln!(
            "RESTART_SPAWN_DIAG stage=required_output pid={} original_error={:?} kind={:?}",
            std::process::id(),
            error.raw_os_error(),
            error.kind()
        );
        raw_stdio();
        child("inherited");
        child("null");
        // Failure-only best-effort drain for the existing asynchronous audit.
        // Keep the original probe deadline and original failure unchanged.
        std::thread::sleep(Duration::from_millis(250));
        panic!("required shell output failed: {error}");
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let mode = args[1].to_str().unwrap();
    if mode == "orphan" {
        let mut child = Command::new(&args[0]);
        child.arg("child").args(&args[2..]);
        child
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        child.spawn().unwrap();
        return;
    }
    #[cfg(unix)]
    if mode == "exec" {
        use std::os::unix::process::CommandExt;
        // The original root lives on as a different executable. Its shell then
        // starts the protocol executor, so both root and child must be restored.
        let error = Command::new("/bin/sh")
            .args([
                "-c",
                "\"$1\" child \"$2\" \"$3\" \"$4\"; exit $?",
                "restart-shell",
            ])
            .arg(&args[0])
            .args(&args[2..])
            .exec();
        panic!("root exec failed: {error}");
    }
    #[cfg(windows)]
    anonymous_memory_probe();
    println!("READY {}", std::process::id());
    io::stdout().flush().unwrap();
    let mut stream: Option<TcpStream> = None;
    for line in io::stdin().lock().lines() {
        match line.unwrap().as_str() {
            "quit" => return,
            command if command.starts_with("stream-open ") => {
                assert!(stream.is_none(), "persistent stream must only open once");
                let connection =
                    TcpStream::connect(command.strip_prefix("stream-open ").unwrap()).unwrap();
                connection
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                connection
                    .set_write_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                println!(
                    "STREAM_OPEN {} local={}",
                    std::process::id(),
                    connection.local_addr().unwrap()
                );
                stream = Some(connection);
                io::stdout().flush().unwrap();
            }
            "stream-ping" => {
                let connection = stream.as_mut().unwrap();
                let message = b"persistent-stream";
                connection.write_all(message).unwrap();
                let mut echoed = [0; 17];
                connection.read_exact(&mut echoed).unwrap();
                assert_eq!(&echoed, message);
                println!(
                    "STREAM_OK {} local={}",
                    std::process::id(),
                    connection.local_addr().unwrap()
                );
                io::stdout().flush().unwrap();
            }
            "stream-close" => {
                stream.take().unwrap().shutdown(Shutdown::Both).unwrap();
                println!("STREAM_CLOSED {}", std::process::id());
                io::stdout().flush().unwrap();
            }
            #[cfg(target_os = "linux")]
            operation @ ("allowed-marker" | "blocked-spawn") => {
                use std::os::unix::process::ExitStatusExt;
                println!("SPAWN_STARTED {}", std::process::id());
                io::stdout().flush().unwrap();
                let mut child = Command::new("/bin/sh")
                    .args(["-c", "printf child-ran > \"$1\"", "marker-shell"])
                    .arg(&args[5])
                    .spawn()
                    .expect("original posix_spawn must report creation success");
                let child_pid = child.id();
                println!("SPAWN_CREATED {} {child_pid}", std::process::id());
                io::stdout().flush().unwrap();
                let status = child.wait().unwrap();
                if operation == "allowed-marker" {
                    assert!(status.success(), "online marker child failed: {status}");
                    println!("MARKER_ALLOWED {} child={child_pid}", std::process::id());
                } else {
                    assert_eq!(
                        status.signal(),
                        Some(9),
                        "unenrolled child must be terminated by the enforcement gate"
                    );
                    println!("BLOCKED {} child={child_pid} signal=9", std::process::id());
                }
                io::stdout().flush().unwrap();
            }
            operation @ ("probe" | "outage-probe") => {
                if operation == "outage-probe" {
                    println!("PROBE_STARTED {}", std::process::id());
                    io::stdout().flush().unwrap();
                }
                let blocked = fs::read(&args[2]).unwrap_err();
                assert_eq!(blocked.kind(), io::ErrorKind::PermissionDenied);
                assert_eq!(fs::read(&args[3]).unwrap(), b"allowed fixture bytes");
                let changed = match fs::read(&args[4]) {
                    Ok(bytes) => {
                        assert_eq!(bytes, b"changed fixture bytes");
                        "allow"
                    }
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                        "deny"
                    }
                };
                #[cfg(unix)]
                let output = Command::new("/bin/sh")
                    .args(["-c", "printf shell-ok"])
                    .output()
                    .unwrap();
                #[cfg(windows)]
                let output = Command::new("cmd.exe")
                    .args(["/D", "/C", "echo shell-ok"])
                    .output()
                    .unwrap_or_else(|error| spawn_diagnostics::failed_output(error));
                assert!(
                    output.status.success(),
                    "child status {:?}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(
                    String::from_utf8(output.stdout).unwrap().trim_end(),
                    "shell-ok"
                );
                println!(
                    "OK {} blocked=deny allowed=allow changed={changed} shell=ok",
                    std::process::id()
                );
                io::stdout().flush().unwrap();
            }
            other => panic!("unknown restart operation {other}"),
        }
    }
}
