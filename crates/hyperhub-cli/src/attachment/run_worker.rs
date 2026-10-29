//! The persistent Linux launcher owns the target from its creation. Its foreground
//! wrapper receives the original root status while this worker drains descendants.
use super::*;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

static NOTIFIER: OnceLock<Mutex<std::fs::File>> = OnceLock::new();
static REPORTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn notify_owned_run_root_exit(status: i32) -> Result<(), String> {
    let Some(pipe) = NOTIFIER.get() else {
        return Ok(());
    };
    if REPORTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(());
    }
    let mut pipe = pipe
        .lock()
        .map_err(|_| "owned-run status pipe is unavailable")?;
    writeln!(pipe, "{status}")
        .and_then(|_| pipe.flush())
        .map_err(|e| e.to_string())
}
pub(crate) fn run_worker(run: crate::RunConfig, fd: i32) -> Result<i32, String> {
    if fd < 3 {
        return Err("private run worker requires an inherited status pipe".into());
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_WRONLY
        || unsafe { libc::fstat(fd, &mut metadata) } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFIFO
    {
        return Err("private run worker status descriptor is not a write-only pipe".into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    NOTIFIER
        .set(Mutex::new(unsafe { std::fs::File::from_raw_fd(fd) }))
        .map_err(|_| "owned-run worker initialized twice")?;
    let result = crate::run_target(run);
    let _ = notify_owned_run_root_exit(result.as_ref().copied().unwrap_or(2));
    result
}
pub(crate) fn spawn_worker(run: &crate::RunConfig) -> Result<i32, String> {
    let console_guard = crate::password::ConsoleModeGuard::capture();
    let result = spawn_worker_inner(run);
    if !console_guard.restore() {
        eprintln!("hyperhub: warning: failed to restore console mode after root exit");
    }
    result
}
fn spawn_worker_inner(run: &crate::RunConfig) -> Result<i32, String> {
    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let read = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
    let write = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
    let inherited = write.as_raw_fd();
    let mut command = ProcessCommand::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command.arg("owned-run-worker").arg(inherited.to_string());
    if let Some(runtime) = &run.runtime {
        command.arg("--runtime").arg(runtime);
    }
    if let Some(backend) = &run.backend {
        command.arg("--backend").arg(backend);
    }
    command.arg("--").arg(&run.target).args(&run.target_args);
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(inherited, libc::F_SETFD, 0) < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    drop(write);
    let mut line = String::new();
    let count = BufReader::new(read)
        .take(32)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if count == 0 {
        let status = child.wait().map_err(|e| e.to_string())?;
        use std::os::unix::process::ExitStatusExt;
        return Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)));
    }
    line.trim()
        .parse::<i32>()
        .map_err(|_| "owned-run worker returned an invalid root status".into())
}
