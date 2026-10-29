//! Bounded transport recovery for suspended Agent bootstrap only.
use super::{AgentControlRequest, AgentControlResponse};
use crate::{CONTROL_MAX_FRAME, HH_ERR_PROTOCOL};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

#[cfg(unix)]
#[path = "startup_unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "startup_windows.rs"]
mod platform;

#[derive(Clone, Copy)]
pub(crate) struct StartupDeadline(Instant);

impl StartupDeadline {
    pub(crate) fn new() -> Self {
        Self(Instant::now() + Duration::from_secs(30))
    }
    /// The synchronous Host reply has a three-second transport budget.
    /// Trust, Engine and alias preparation share this shorter deadline.
    pub(crate) fn host_command() -> Self {
        Self(Instant::now() + Duration::from_secs(2))
    }

    pub(crate) fn remaining(&self) -> io::Result<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Agent bootstrap timed out"))
    }

    pub(crate) fn retry<T>(&self, mut call: impl FnMut() -> io::Result<T>) -> io::Result<T> {
        loop {
            self.remaining()?;
            match call() {
                Ok(value) => {
                    self.remaining()?;
                    return Ok(value);
                }
                Err(error) if transient(&error) => {
                    std::thread::sleep(self.remaining()?.min(Duration::from_millis(20)));
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn connect(&self, endpoint: &str) -> io::Result<StartupStream> {
        self.remaining()?;
        platform::Stream::connect(endpoint, self.0)
    }

    pub(crate) fn exchange(
        &self,
        endpoint: &str,
        request: &AgentControlRequest<'_>,
    ) -> Result<AgentControlResponse, i32> {
        let payload = serde_json::to_vec(request).map_err(|_| HH_ERR_PROTOCOL)?;
        if payload.len() > CONTROL_MAX_FRAME {
            return Err(HH_ERR_PROTOCOL);
        }
        self.retry(|| {
            let mut stream = self.connect(endpoint)?;
            stream.write_all(&(payload.len() as u32).to_be_bytes())?;
            stream.write_all(&payload)?;
            stream.flush()?;
            let mut length = [0; 4];
            stream.read_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            if length > CONTROL_MAX_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control frame too large",
                ));
            }
            let mut response = vec![0; length];
            stream.read_exact(&mut response)?;
            serde_json::from_slice(&response)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid control response"))
        })
        .map_err(|_| HH_ERR_PROTOCOL)
    }
}

pub(crate) type StartupStream = platform::Stream;

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
    ) || cfg!(windows) && matches!(error.raw_os_error(), Some(121 | 231 | 232 | 233))
}

#[cfg(test)]
mod tests;
