use std::ffi::{CString, OsString};
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const INTERNAL_COMMAND: &str = "__hyperhub_pty_launcher";
const FRAME_INPUT: u8 = 0;
const FRAME_RESIZE: u8 = 1;
const FRAME_EOF: u8 = 2;

pub fn run_internal(args: &[OsString]) -> Option<Result<i32, String>> {
    (args.first().is_some_and(|value| value == INTERNAL_COMMAND)).then(|| run_launcher(&args[1..]))
}

pub struct PtyClient {
    listener: UnixListener,
    directory: PathBuf,
    socket: PathBuf,
    target: OsString,
    argv0: OsString,
    args: Vec<OsString>,
    initial_size: (u16, u16),
}

impl PtyClient {
    pub fn for_terminal(
        target: &OsString,
        argv0: &OsString,
        args: &[OsString],
    ) -> Result<Option<Self>, String> {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Ok(None);
        }
        let initial_size = terminal_size(libc::STDOUT_FILENO)?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hyperhub-pty-{}-{}-{nonce}",
            unsafe { libc::geteuid() },
            std::process::id()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|error| {
                format!(
                    "cannot create PTY directory {}: {error}",
                    directory.display()
                )
            })?;
        let socket = directory.join("relay.sock");
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_dir(&directory);
                return Err(format!(
                    "cannot bind PTY relay {}: {error}",
                    socket.display()
                ));
            }
        };
        if let Err(error) = listener.set_nonblocking(true) {
            let _ = fs::remove_file(&socket);
            let _ = fs::remove_dir(&directory);
            return Err(format!("cannot configure PTY relay: {error}"));
        }
        Ok(Some(Self {
            listener,
            directory,
            socket,
            target: target.clone(),
            argv0: argv0.clone(),
            args: args.to_vec(),
            initial_size,
        }))
    }

    pub fn launch_command(&self) -> (OsString, Vec<OsString>) {
        let executable = std::env::current_exe()
            .expect("the running HyperHub executable has already been resolved");
        (
            executable.into_os_string(),
            launcher_arguments(
                &self.socket,
                self.initial_size,
                &self.target,
                &self.argv0,
                &self.args,
            ),
        )
    }

    pub fn relay(&mut self, root_pid: u32, start_time: u64) -> Result<i32, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match self.listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if !root_exists(root_pid, start_time) {
                        return wait_for_root(root_pid, start_time);
                    }
                    if Instant::now() >= deadline {
                        kill_root(root_pid, start_time);
                        let _ = wait_for_root(root_pid, start_time);
                        return Err("timed out waiting for the Linux PTY launcher".into());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    kill_root(root_pid, start_time);
                    let _ = wait_for_root(root_pid, start_time);
                    return Err(format!("cannot accept PTY relay: {error}"));
                }
            }
        };
        if let Err(error) = relay_terminal(&mut stream) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            kill_root(root_pid, start_time);
            let _ = wait_for_root(root_pid, start_time);
            return Err(error);
        }
        wait_for_root(root_pid, start_time)
    }
}

impl Drop for PtyClient {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir(&self.directory);
    }
}

struct TerminalMode {
    fd: RawFd,
    original: libc::termios,
}

impl TerminalMode {
    fn raw(fd: RawFd) -> Result<Self, String> {
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(format!(
                "cannot read terminal mode: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(format!(
                "cannot enter terminal raw mode: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { fd, original })
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

fn relay_terminal(stream: &mut UnixStream) -> Result<(), String> {
    let _mode = TerminalMode::raw(libc::STDIN_FILENO)?;
    let mut last_size = terminal_size(libc::STDOUT_FILENO)?;
    send_resize(stream, last_size)?;
    let socket = stream.as_raw_fd();
    let mut stdin_open = true;
    loop {
        let mut descriptors = [
            libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: if stdin_open { libc::POLLIN } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: socket,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, 100) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(format!("PTY relay poll failed: {error}"));
            }
        }
        let size = terminal_size(libc::STDOUT_FILENO)?;
        if size != last_size {
            send_resize(stream, size)?;
            last_size = size;
        }
        if descriptors[0].revents & libc::POLLIN != 0 {
            let mut buffer = [0u8; 8192];
            let read =
                unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
            if read > 0 {
                send_frame(stream, FRAME_INPUT, &buffer[..read as usize])?;
            } else if read == 0 {
                send_frame(stream, FRAME_EOF, &[])?;
                stdin_open = false;
            }
        }
        if stdin_open
            && descriptors[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        {
            send_frame(stream, FRAME_EOF, &[])?;
            stdin_open = false;
        }
        if descriptors[1].revents & libc::POLLIN != 0 {
            let mut buffer = [0u8; 8192];
            let read = stream
                .read(&mut buffer)
                .map_err(|error| format!("cannot read PTY output: {error}"))?;
            if read == 0 {
                return Ok(());
            }
            write_all_fd(libc::STDOUT_FILENO, &buffer[..read])?;
        }
        if descriptors[1].revents & libc::POLLIN == 0
            && descriptors[1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Ok(());
        }
    }
}

fn launcher_arguments(
    socket: &Path,
    initial_size: (u16, u16),
    target: &OsString,
    argv0: &OsString,
    args: &[OsString],
) -> Vec<OsString> {
    let mut launcher_args = vec![
        INTERNAL_COMMAND.into(),
        socket.as_os_str().to_owned(),
        initial_size.0.to_string().into(),
        initial_size.1.to_string().into(),
        target.clone(),
        argv0.clone(),
    ];
    launcher_args.extend(args.iter().cloned());
    launcher_args
}

fn run_launcher(args: &[OsString]) -> Result<i32, String> {
    let socket = args.first().ok_or("PTY launcher requires a relay socket")?;
    let rows = parse_size(args.get(1), "rows")?;
    let columns = parse_size(args.get(2), "columns")?;
    let target = args.get(3).ok_or("PTY launcher requires a target")?;
    let argv0 = args.get(4).ok_or("PTY launcher requires argv[0]")?;
    let target_args = &args[5..];
    let program = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| "PTY target contains a NUL byte".to_string())?;
    let mut argv = Vec::with_capacity(target_args.len() + 1);
    let argv0 = CString::new(argv0.as_os_str().as_bytes())
        .map_err(|_| "PTY argv[0] contains a NUL byte".to_string())?;
    argv.push(argv0);
    for arg in target_args {
        argv.push(
            CString::new(arg.as_os_str().as_bytes())
                .map_err(|_| "PTY target argument contains a NUL byte".to_string())?,
        );
    }
    let mut pointers = argv.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    pointers.push(std::ptr::null());
    let mut stream = UnixStream::connect(Path::new(socket))
        .map_err(|error| format!("cannot connect PTY relay: {error}"))?;
    let mut master = 0;
    let mut slave = 0;
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &libc::winsize {
                ws_row: rows,
                ws_col: columns,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
    } != 0
    {
        return Err(format!(
            "cannot allocate PTY: {}",
            std::io::Error::last_os_error()
        ));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(format!(
            "cannot fork PTY target: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        unsafe {
            libc::close(master);
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            if libc::getppid() == 1 {
                libc::_exit(126);
            }
            if libc::setsid() < 0 || libc::ioctl(slave, libc::TIOCSCTTY, 0) < 0 {
                libc::_exit(126);
            }
            for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
                if libc::dup2(slave, fd) < 0 {
                    libc::_exit(126);
                }
            }
            if slave > libc::STDERR_FILENO {
                libc::close(slave);
            }
        }
        unsafe {
            libc::execv(program.as_ptr(), pointers.as_ptr());
            libc::_exit(127)
        }
    }
    unsafe { libc::close(slave) };
    let result = relay_launcher(&mut stream, master, pid);
    if result.is_err() {
        terminate_group(pid);
        let _ = wait_child(pid);
    }
    unsafe { libc::close(master) };
    result
}

fn parse_size(value: Option<&OsString>, name: &str) -> Result<u16, String> {
    value
        .ok_or_else(|| format!("PTY launcher requires terminal {name}"))?
        .to_string_lossy()
        .parse()
        .map_err(|_| format!("PTY launcher received invalid terminal {name}"))
}

fn relay_launcher(
    stream: &mut UnixStream,
    master: RawFd,
    child: libc::pid_t,
) -> Result<i32, String> {
    loop {
        let mut descriptors = [
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let polled = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, 100) };
        if polled < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            terminate_group(child);
            return Err(format!(
                "PTY launcher poll failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if descriptors[0].revents & libc::POLLIN != 0 {
            if !receive_frame(stream, master)? {
                terminate_group(child);
                return wait_child(child);
            }
        }
        if descriptors[0].revents & libc::POLLIN == 0
            && descriptors[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        {
            terminate_group(child);
            return wait_child(child);
        }
        if descriptors[1].revents & libc::POLLIN != 0 {
            let mut buffer = [0u8; 8192];
            let read = unsafe { libc::read(master, buffer.as_mut_ptr().cast(), buffer.len()) };
            if read > 0 {
                stream
                    .write_all(&buffer[..read as usize])
                    .map_err(|error| format!("cannot forward PTY output: {error}"))?;
            }
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            drain_master(stream, master)?;
            return Ok(decode_status(status));
        }
    }
}

fn receive_frame(stream: &mut UnixStream, master: RawFd) -> Result<bool, String> {
    let mut header = [0u8; 5];
    if let Err(error) = stream.read_exact(&mut header) {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(false);
        }
        return Err(format!("cannot read PTY input frame: {error}"));
    }
    let length = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
    if length > 65_536 {
        return Err("PTY input frame is too large".into());
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|error| format!("cannot read PTY input: {error}"))?;
    match header[0] {
        FRAME_INPUT => write_all_fd(master, &payload).map(|_| true),
        FRAME_RESIZE if payload.len() == 4 => {
            let size = libc::winsize {
                ws_row: u16::from_be_bytes([payload[0], payload[1]]),
                ws_col: u16::from_be_bytes([payload[2], payload[3]]),
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            if unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &size) } < 0 {
                return Err(format!(
                    "cannot resize PTY: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(true)
        }
        FRAME_EOF if payload.is_empty() => Ok(false),
        _ => Err("invalid PTY input frame".into()),
    }
}

fn send_frame(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> Result<(), String> {
    let mut header = [0u8; 5];
    header[0] = kind;
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    stream
        .write_all(&header)
        .and_then(|_| stream.write_all(payload))
        .map_err(|error| format!("cannot write PTY input: {error}"))
}

fn send_resize(stream: &mut UnixStream, size: (u16, u16)) -> Result<(), String> {
    let payload = [size.0.to_be_bytes(), size.1.to_be_bytes()].concat();
    send_frame(stream, FRAME_RESIZE, &payload)
}

fn terminal_size(fd: RawFd) -> Result<(u16, u16), String> {
    let mut size = unsafe { std::mem::zeroed::<libc::winsize>() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } != 0 {
        return Err(format!(
            "cannot read terminal size: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((size.ws_row, size.ws_col))
}

fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error.to_string());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn drain_master(stream: &mut UnixStream, master: RawFd) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(master, libc::F_GETFL) };
    unsafe { libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    loop {
        let mut buffer = [0u8; 8192];
        let read = unsafe { libc::read(master, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read <= 0 {
            return Ok(());
        }
        stream
            .write_all(&buffer[..read as usize])
            .map_err(|error| error.to_string())?;
    }
}

fn terminate_group(child: libc::pid_t) {
    unsafe {
        if libc::kill(-child, libc::SIGKILL) != 0 {
            libc::kill(child, libc::SIGKILL);
        }
    }
}

fn wait_child(child: libc::pid_t) -> Result<i32, String> {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            return Ok(decode_status(status));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error.to_string());
        }
    }
}

fn decode_status(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

fn root_exists(pid: u32, start_time: u64) -> bool {
    super::launcher::process_exists(pid, Some(start_time))
}

fn kill_root(pid: u32, start_time: u64) {
    if root_exists(pid, start_time) {
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
}

fn wait_for_root(pid: u32, start_time: u64) -> Result<i32, String> {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
        if waited == pid as i32 {
            return Ok(decode_status(status));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            while root_exists(pid, start_time) {
                std::thread::sleep(Duration::from_millis(10));
            }
            return Ok(0);
        }
        return Err(format!("cannot wait for PTY launcher {pid}: {error}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_arguments_preserve_target_argv0_and_arguments() {
        let args = launcher_arguments(
            Path::new("/tmp/relay.sock"),
            (24, 80),
            &OsString::from("/bin/bash"),
            &OsString::from("bash"),
            &[
                OsString::from("-i"),
                OsString::from("-c"),
                OsString::from("echo ok"),
            ],
        );
        assert_eq!(args[0], INTERNAL_COMMAND);
        assert_eq!(args[1], "/tmp/relay.sock");
        assert_eq!(args[2], "24");
        assert_eq!(args[3], "80");
        assert_eq!(args[4], "/bin/bash");
        assert_eq!(args[5], "bash");
        assert_eq!(&args[6..], ["-i", "-c", "echo ok"]);
    }

    #[test]
    fn status_decoding_preserves_exit_and_signal_codes() {
        assert_eq!(decode_status(7 << 8), 7);
        assert_eq!(decode_status(libc::SIGTERM), 128 + libc::SIGTERM);
    }
}
