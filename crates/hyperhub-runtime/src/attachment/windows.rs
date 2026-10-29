use super::*;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
    System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_NOWAIT, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    },
};
#[path = "client_windows.rs"]
mod client;
pub(super) fn connect(endpoint: &str) -> io::Result<client::Stream> {
    connect_until(endpoint, Instant::now() + Duration::from_secs(3))
}
fn connect_until(endpoint: &str, deadline: Instant) -> io::Result<client::Stream> {
    loop {
        match client::Stream::connect(endpoint, deadline) {
            Ok(stream) => return Ok(stream),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|time| !time.is_zero())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "attachment pipe instance stayed busy until its deadline",
                        )
                    })?;
                std::thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            // Missing endpoints and real access/transport errors are final.
            // In particular, discovery must not wait for every unhooked PID.
            Err(error) => return Err(error),
        }
    }
}
pub(super) struct Listener {
    handle: OwnedHandle,
}
impl Listener {
    pub(super) fn bind(endpoint: &str) -> io::Result<Self> {
        if !endpoint.starts_with(r"\\.\pipe\")
            || endpoint.len() <= 9
            || endpoint[9..].contains(['\\', '/'])
            || endpoint.contains('\0')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid attachment pipe name",
            ));
        }
        let name: Vec<u16> = endpoint.encode_utf16().chain(Some(0)).collect();
        let sddl: Vec<u16> = "D:P(A;;GA;;;OW)(A;;GA;;;SY)"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                32768,
                32768,
                0,
                &attributes,
            )
        };
        unsafe {
            LocalFree(descriptor);
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle: unsafe { OwnedHandle::from_raw_handle(handle) },
        })
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
            let connected =
                unsafe { ConnectNamedPipe(self.handle.as_raw_handle(), std::ptr::null_mut()) };
            let error = if connected == 0 {
                unsafe { GetLastError() }
            } else {
                // PIPE_NOWAIT success only rearms a disconnected instance.
                // Only ERROR_PIPE_CONNECTED establishes an actual client.
                ERROR_PIPE_LISTENING
            };
            match error {
                ERROR_PIPE_CONNECTED => {
                    let mut stream = PipeStream {
                        handle: &self.handle,
                        deadline: Instant::now() + Duration::from_secs(3),
                    };
                    let mut peer = 0;
                    if unsafe {
                        windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId(
                            stream.handle.as_raw_handle(),
                            &mut peer,
                        )
                    } != 0
                        && peer != 0
                    {
                        if super::handle_raw_with_peer(&mut stream, peer, &callback).is_ok() {
                            // DisconnectNamedPipe discards unread response bytes.
                            // The one-request client closes after reading its frame;
                            // wait for that close within the original I/O deadline.
                            // FlushFileBuffers would wait without a deadline.
                            let _ = stream.wait_for_client_close();
                        }
                    }
                    unsafe {
                        DisconnectNamedPipe(self.handle.as_raw_handle());
                    }
                }
                ERROR_PIPE_LISTENING => std::thread::sleep(Duration::from_millis(10)),
                ERROR_NO_DATA => unsafe {
                    DisconnectNamedPipe(self.handle.as_raw_handle());
                },
                _ => return Err(io::Error::from_raw_os_error(error as i32)),
            }
        }
        Ok(())
    }
}
struct PipeStream<'a> {
    handle: &'a OwnedHandle,
    deadline: Instant,
}
impl PipeStream<'_> {
    fn wait_for_client_close(&mut self) -> io::Result<()> {
        let mut byte = [0];
        if self.read(&mut byte)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected data after attachment request",
            ));
        }
        Ok(())
    }
    fn wait(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "attachment pipe I/O timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }
}
impl Read for PipeStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let mut count = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle.as_raw_handle(),
                    bytes.as_mut_ptr(),
                    bytes.len().min(u32::MAX as usize) as u32,
                    &mut count,
                    std::ptr::null_mut(),
                )
            };
            if ok != 0 {
                return Ok(count as usize);
            }
            match unsafe { GetLastError() } {
                ERROR_NO_DATA => self.wait()?,
                ERROR_BROKEN_PIPE => return Ok(0),
                e => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
    }
}
impl Write for PipeStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let mut count = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle.as_raw_handle(),
                    bytes.as_ptr(),
                    bytes.len().min(u32::MAX as usize) as u32,
                    &mut count,
                    std::ptr::null_mut(),
                )
            };
            if ok != 0 {
                if count > 0 {
                    return Ok(count as usize);
                }
                self.wait()?;
                continue;
            }
            let e = unsafe { GetLastError() };
            if e == ERROR_NO_DATA {
                self.wait()?;
            } else {
                return Err(io::Error::from_raw_os_error(e as i32));
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn verify_peer(stream: &client::Stream, pid: u32) -> io::Result<()> {
    if stream.server_pid()? != pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "attachment Host OS peer identity mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
