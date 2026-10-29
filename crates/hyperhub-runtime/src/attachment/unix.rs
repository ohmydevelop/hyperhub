use super::*;
use crate::owned_ipc_fds::{IpcListener, IpcStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
pub(super) struct Stream {
    stream: IpcStream,
    deadline: Instant,
}
impl Stream {
    fn timeout(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "attachment frame deadline expired")
            })
    }
}
impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.get()?.set_read_timeout(Some(self.timeout()?))?;
        self.stream.read(bytes)
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream
            .get()?
            .set_write_timeout(Some(self.timeout()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
pub(super) fn connect(endpoint: &str) -> io::Result<Stream> {
    Ok(Stream {
        stream: IpcStream::connect(endpoint)?,
        deadline: Instant::now() + Duration::from_secs(3),
    })
}
pub(super) struct Listener {
    listener: IpcListener,
    path: std::path::PathBuf,
}
impl Listener {
    pub(super) fn bind(endpoint: &str) -> io::Result<Self> {
        let path = Path::new(endpoint);
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "attachment endpoint must be absolute",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing attachment endpoint directory",
            )
        })?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "attachment endpoint directory must be private",
            ));
        }
        // Never unlink a pre-existing endpoint or follow a symlink supplied by another process.
        let listener = IpcListener::bind(path)?;
        let value = Self {
            listener,
            path: path.to_owned(),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        value.listener.get()?.set_nonblocking(true)?;
        Ok(value)
    }
    pub(super) fn run(
        self,
        stop: &AtomicBool,
        callback: impl Fn(serde_json::Value) -> serde_json::Value,
    ) -> io::Result<()> {
        self.run_with_peer(stop, |value, _| callback(value))
    }
    pub(super) fn run_with_peer(
        self,
        stop: &AtomicBool,
        callback: impl Fn(serde_json::Value, u32) -> serde_json::Value,
    ) -> io::Result<()> {
        while !stop.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok(stream) => {
                    let mut stream = Stream {
                        stream,
                        deadline: Instant::now() + Duration::from_secs(3),
                    };
                    if let Ok(peer) = peer_pid(&stream) {
                        let _ = handle_raw_with_peer(&mut stream, peer, &callback);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if self.listener.is_current() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(super) fn verify_peer(stream: &Stream, pid: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.stream.get()?.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if size as usize != std::mem::size_of::<libc::ucred>()
            || credentials.pid <= 0
            || credentials.pid as u32 != pid
            || credentials.uid != unsafe { libc::geteuid() }
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "attachment Host OS peer identity mismatch",
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, pid);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "attachment OS peer identity is unsupported on this platform",
        ))
    }
}

fn peer_pid(stream: &Stream) -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.stream.get()?.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if size as usize != std::mem::size_of::<libc::ucred>()
            || credentials.pid <= 0
            || credentials.uid != unsafe { libc::geteuid() }
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "attachment client OS identity rejected",
            ));
        }
        Ok(credentials.pid as u32)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        Ok(0)
    }
}
