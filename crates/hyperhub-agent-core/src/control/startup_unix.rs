use hyperhub_runtime::owned_ipc_fds::IpcStream;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::time::Instant;

pub(crate) struct Stream {
    stream: IpcStream,
    deadline: Option<Instant>,
}

impl Stream {
    pub(super) fn connect(endpoint: &str, deadline: Instant) -> io::Result<Self> {
        let path = endpoint.as_bytes();
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if path.contains(&0) || path.len() >= address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid control socket path",
            ));
        }
        address.sun_family = libc::AF_UNIX as _;
        for (output, input) in address.sun_path.iter_mut().zip(path) {
            *output = *input as _;
        }
        let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        {
            address.sun_len = length as _;
        }
        let stream = IpcStream::socket()?;
        stream.get()?.set_nonblocking(true)?;
        let fd = stream.get()?.as_raw_fd();
        let connected = unsafe {
            libc::connect(
                fd,
                (&address as *const libc::sockaddr_un).cast(),
                length as _,
            )
        };
        let value = Self {
            stream,
            deadline: Some(deadline),
        };
        if connected < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error);
            }
            value.wait(libc::POLLOUT)?;
            if let Some(error) = value.stream.get()?.take_error()? {
                return Err(error);
            }
        }
        Ok(value)
    }

    pub(crate) fn clear_deadline(&mut self) -> io::Result<()> {
        self.deadline = None;
        Ok(())
    }

    fn wait(&self, event: libc::c_short) -> io::Result<()> {
        loop {
            let timeout = match self.deadline {
                Some(deadline) => {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .filter(|d| !d.is_zero())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::TimedOut, "Agent bootstrap timed out")
                        })?;
                    remaining
                        .as_millis()
                        .saturating_add(1)
                        .min(i32::MAX as u128) as i32
                }
                None if crate::attachment::managed() => 100,
                None => -1,
            };
            let mut descriptor = libc::pollfd {
                fd: self.stream.get()?.as_raw_fd(),
                events: event,
                revents: 0,
            };
            match unsafe { libc::poll(&mut descriptor, 1, timeout) } {
                count if count > 0 => return Ok(()),
                0 if self.deadline.is_none() && crate::attachment::managed() => {
                    if crate::attachment::stopping_background() {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "attachment control retired",
                        ));
                    }
                    continue;
                }
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Agent bootstrap timed out",
                    ))
                }
                _ => {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            self.wait(libc::POLLIN)?;
            match self.stream.read(buffer) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            self.wait(libc::POLLOUT)?;
            match self.stream.write(buffer) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
