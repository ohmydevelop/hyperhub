//! A real terminal application. Control uses a separate local socket so raw
//! keyboard input and VT output cannot be confused with the test protocol.
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[cfg(unix)]
mod terminal {
    use super::*;
    pub struct Guard(libc::termios);
    pub fn mode() -> io::Result<Vec<u64>> {
        unsafe {
            let mut mode = std::mem::zeroed();
            if libc::isatty(0) != 1 || libc::isatty(1) != 1 || libc::tcgetattr(0, &mut mode) != 0 {
                return Err(io::Error::other("fixture requires a real terminal"));
            }
            let mode: libc::termios = mode;
            let mut result = vec![
                mode.c_iflag as u64,
                mode.c_oflag as u64,
                mode.c_cflag as u64,
                mode.c_lflag as u64,
                libc::tcgetpgrp(0) as u64,
                libc::getpgrp() as u64,
            ];
            result.extend(mode.c_cc.iter().map(|value| u64::from(*value)));
            Ok(result)
        }
    }
    impl Guard {
        pub fn enter() -> io::Result<Self> {
            mode()?;
            unsafe {
                let mut original = std::mem::zeroed();
                if libc::tcgetattr(0, &mut original) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut raw = original;
                libc::cfmakeraw(&mut raw);
                if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // Only this disposable fixture grants debugger access. The
                // runner never changes the host's ptrace policy.
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0) != 0 {
                    libc::tcsetattr(0, libc::TCSANOW, &original);
                    return Err(io::Error::last_os_error());
                }
                Ok(Self(original))
            }
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, &self.0);
            }
        }
    }
}

#[cfg(windows)]
mod terminal {
    use super::*;
    use windows_sys::Win32::System::Console::*;
    pub struct Guard(u32, u32);
    pub fn mode() -> io::Result<Vec<u64>> {
        unsafe {
            let mut input = 0;
            let mut output = 0;
            if GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut input) == 0
                || GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mut output) == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(vec![input.into(), output.into()])
        }
    }
    impl Guard {
        pub fn enter() -> io::Result<Self> {
            let before = mode()?;
            unsafe {
                let input = before[0] as u32;
                let output = before[1] as u32;
                let raw = (input
                    & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT;
                if SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), raw) == 0 {
                    return Err(io::Error::last_os_error());
                }
                if SetConsoleMode(
                    GetStdHandle(STD_OUTPUT_HANDLE),
                    output | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                ) == 0
                {
                    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), input);
                    return Err(io::Error::last_os_error());
                }
                Ok(Self(input, output))
            }
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), self.0);
                SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), self.1);
            }
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|value| value == "--worker") {
        if args.len() != 4 {
            return Err(io::Error::other(
                "worker requires ready file, dummy file and supervisor PID",
            ));
        }
        return worker(
            &args[1],
            &args[2],
            args[3]
                .to_string_lossy()
                .parse()
                .map_err(io::Error::other)?,
        );
    }
    if args.len() != 2 {
        return Err(io::Error::other("ready file and dummy file required"));
    }
    // Keep a shell-like owner alive to check terminal modes after the actual
    // UI exits. This detects damage hidden by closing the whole pseudoconsole.
    let before = terminal::mode()?;
    let status = std::process::Command::new(std::env::current_exe()?)
        .arg("--worker")
        .arg(&args[0])
        .arg(&args[1])
        .arg(std::process::id().to_string())
        .status()?;
    let restored = terminal::mode()? == before;
    let completed = std::path::PathBuf::from(&args[0]).with_extension("completed");
    let staging = completed.with_extension("pending-completion");
    std::fs::write(
        &staging,
        serde_json::to_vec(&serde_json::json!({
            "terminal_restored_after_worker_exit": restored,
            "worker_exit_code": status.code(),
        }))?,
    )?;
    std::fs::rename(staging, completed)?;
    std::process::exit(if restored && status.code() == Some(37) {
        37
    } else {
        71
    })
}

fn worker(
    ready: &std::ffi::OsStr,
    secret: &std::ffi::OsStr,
    supervisor_pid: u32,
) -> io::Result<()> {
    let terminal = terminal::Guard::enter()?;
    let initial_mode = terminal::mode()?;
    let cwd = std::env::current_dir()?;
    let home = std::env::var_os("HOME");
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let received = Arc::new(Mutex::new(Vec::<u8>::new()));
    let captured = received.clone();
    std::thread::spawn(move || {
        let mut buffer = [0; 64];
        let mut stdin = io::stdin().lock();
        loop {
            match stdin.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(size) => {
                    let count = {
                        let mut bytes = captured.lock().unwrap();
                        bytes.extend_from_slice(&buffer[..size]);
                        bytes.len()
                    };
                    let mut output = io::stdout().lock();
                    let _ = write!(output, "\x1b[2K\rkeys={count}\r\n");
                    let _ = output.flush();
                }
            }
        }
    });
    write!(io::stdout(), "\x1b[?1049h\x1b[2Jterminal-ready\r\n")?;
    io::stdout().flush()?;
    let ready = std::path::PathBuf::from(ready);
    let staging = ready.with_extension("pending");
    std::fs::write(
        &staging,
        serde_json::to_vec(&serde_json::json!({
            "pid": std::process::id(), "port": listener.local_addr()?.port(),
            "supervisor_pid": supervisor_pid,
        }))?,
    )?;
    std::fs::rename(staging, ready)?;
    for connection in listener.incoming() {
        let mut connection = connection?;
        let mut command = String::new();
        BufReader::new(&connection).read_line(&mut command)?;
        let reply = match command.trim() {
            "snapshot" => {
                let bytes = received.lock().unwrap();
                serde_json::json!({
                    "pid": std::process::id(), "terminal": true,
                    "mode_preserved": terminal::mode()? == initial_mode,
                    "cwd_preserved": std::env::current_dir()? == cwd,
                    "home_preserved": std::env::var_os("HOME") == home,
                    "received_hex": bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                })
            }
            "read" => match std::fs::read(&secret) {
                Ok(_) => serde_json::json!({"read_allowed": true}),
                Err(error) => {
                    serde_json::json!({"read_allowed": false, "error": error.raw_os_error()})
                }
            },
            command if command.starts_with("render ") => {
                let nonce = &command[7..];
                if nonce.len() != 32 || !nonce.bytes().all(|value| value.is_ascii_hexdigit()) {
                    return Err(io::Error::other("invalid render marker"));
                }
                let mut output = io::stdout().lock();
                write!(output, "\r\nTARGET-RENDER:{nonce}\r\n")?;
                output.flush()?;
                serde_json::json!({"rendered":nonce})
            }
            "exit" => {
                writeln!(connection, "{{\"exiting\":true}}")?;
                break;
            }
            _ => return Err(io::Error::other("unknown fixture command")),
        };
        writeln!(connection, "{reply}")?;
    }
    write!(io::stdout(), "\x1b[?1049l")?;
    io::stdout().flush()?;
    drop(terminal);
    std::process::exit(37)
}
