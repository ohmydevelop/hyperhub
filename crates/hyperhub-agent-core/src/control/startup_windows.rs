//! Local named-pipe bootstrap I/O with one absolute startup deadline.
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Instant;
use windows_sys::Win32::{
    Foundation::{
        GetLastError, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING},
    System::{
        Threading::{CreateEventW, WaitForSingleObject, INFINITE},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

pub(crate) struct Stream {
    pipe: OwnedHandle,
    deadline: Option<Instant>,
}

enum Buffer<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

fn timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "Agent bootstrap timed out")
}

impl Stream {
    pub(super) fn connect(endpoint: &str, deadline: Instant) -> io::Result<Self> {
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        if !endpoint
            .get(..9)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\.\pipe\"))
            || endpoint.len() <= 9
            || endpoint[9..].contains(['\\', '/'])
            || endpoint.encode_utf16().any(|unit| unit == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid control pipe name",
            ));
        }
        let name: Vec<_> = endpoint.encode_utf16().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            pipe: unsafe { OwnedHandle::from_raw_handle(handle) },
            deadline: Some(deadline),
        })
    }

    pub(crate) fn clear_deadline(&mut self) -> io::Result<()> {
        // Read/Write never return with outstanding I/O, so this also safely
        // switches an enrolled Host to its existing long-lived control loop.
        self.deadline = None;
        Ok(())
    }

    fn wait_ms(&self) -> io::Result<u32> {
        match self.deadline {
            None => Ok(INFINITE),
            Some(deadline) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or_else(timeout)?;
                if remaining.is_zero() {
                    return Err(timeout());
                }
                Ok(remaining
                    .as_millis()
                    .saturating_add(1)
                    .min(u128::from(INFINITE - 1)) as u32)
            }
        }
    }

    fn transfer(&mut self, buffer: Buffer<'_>) -> io::Result<usize> {
        self.wait_ms()?;
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
        operation.hEvent = event;
        let pipe = self.pipe.as_raw_handle();
        let mut transferred = 0;
        let result = unsafe {
            match buffer {
                Buffer::Read(bytes) => ReadFile(
                    pipe,
                    bytes.as_mut_ptr(),
                    bytes.len().min(u32::MAX as usize) as u32,
                    &mut transferred,
                    &mut operation,
                ),
                Buffer::Write(bytes) => WriteFile(
                    pipe,
                    bytes.as_ptr(),
                    bytes.len().min(u32::MAX as usize) as u32,
                    &mut transferred,
                    &mut operation,
                ),
            }
        };
        if result != 0 {
            return Ok(transferred as usize);
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let result = (|| match unsafe { WaitForSingleObject(event, self.wait_ms()?) } {
            WAIT_OBJECT_0 => {
                if unsafe { GetOverlappedResult(pipe, &operation, &mut transferred, 0) } != 0 {
                    Ok(transferred as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            }
            WAIT_TIMEOUT => Err(timeout()),
            _ => Err(io::Error::last_os_error()),
        })();
        if result.is_err() {
            // CancelIoEx requests cancellation; it does not complete it. Drain
            // the exact operation before its OVERLAPPED, event or borrowed
            // caller buffer can be freed. ERROR_NOT_FOUND is a completion race.
            // https://learn.microsoft.com/windows/win32/api/ioapiset/nf-ioapiset-cancelioex
            unsafe {
                CancelIoEx(pipe, &operation);
                GetOverlappedResult(pipe, &operation, &mut transferred, 1);
            }
        }
        result
    }
}

impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.transfer(Buffer::Read(bytes))
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.transfer(Buffer::Write(bytes))
    }

    fn flush(&mut self) -> io::Result<()> {
        // WriteFile is unbuffered here. FlushFileBuffers would wait for the
        // remote reader and would escape the startup deadline.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use windows_sys::Win32::{
        Foundation::ERROR_PIPE_CONNECTED,
        Storage::FileSystem::PIPE_ACCESS_DUPLEX,
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
    };

    fn connected(deadline: Instant) -> (Stream, OwnedHandle) {
        let endpoint = format!(
            r"\\.\pipe\hyperhub-startup-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        );
        let name: Vec<_> = endpoint.encode_utf16().chain(Some(0)).collect();
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(pipe, INVALID_HANDLE_VALUE);
        let server = unsafe { OwnedHandle::from_raw_handle(pipe) };
        let client = Stream::connect(&endpoint, deadline).unwrap();
        let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
        let result = unsafe { ConnectNamedPipe(pipe, &mut operation) };
        if result == 0 {
            let error = unsafe { GetLastError() };
            if error == ERROR_IO_PENDING {
                let mut count = 0;
                assert_ne!(
                    unsafe { GetOverlappedResult(pipe, &operation, &mut count, 1) },
                    0
                );
            } else {
                assert_eq!(error, ERROR_PIPE_CONNECTED);
            }
        }
        (client, server)
    }

    #[test]
    fn silent_pipe_read_cancels_and_reaps_the_overlapped_operation() {
        let began = Instant::now();
        let (mut stream, _server) = connected(began + Duration::from_millis(150));
        assert_eq!(
            stream.read(&mut [0; 4]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(began.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn bootstrap_connect_rejects_remote_and_device_endpoints() {
        for endpoint in [
            r"\\remote\pipe\control",
            r"\\.\other\control",
            r"\\.\pipe\",
            r"\\.\pipe\nested\control",
        ] {
            let error = Stream::connect(endpoint, Instant::now() + Duration::from_secs(1))
                .err()
                .expect("nonlocal endpoint must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn pipe_backpressure_cannot_exceed_the_startup_write_deadline() {
        let began = Instant::now();
        let (mut stream, _server) = connected(began + Duration::from_millis(150));
        assert_eq!(
            stream
                .write_all(&vec![0; 8 * 1024 * 1024])
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(began.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn enrolled_pipe_can_clear_the_expired_startup_deadline() {
        let (mut stream, server) = connected(Instant::now() + Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            stream.write(&[1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        stream.clear_deadline().unwrap();
        assert_eq!(stream.write(&[1]).unwrap(), 1);
        drop(server);
    }
}
