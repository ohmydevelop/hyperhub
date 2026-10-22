use super::{invalid, Wire, MAX_FRAME};
use hyperhub_runtime::handoff;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use windows_sys::Win32::System::{
    Threading::{GetCurrentThreadId, OpenThread, THREAD_TERMINATE},
    IO::CancelSynchronousIo,
};

const MAGIC: &[u8; 4] = b"HHW1";
const HEADER: usize = 12;

pub(super) struct Sender {
    pipe: Box<dyn Write + Send>,
    peer_pid: Option<u32>,
    control: Control,
}
pub(super) struct Receiver {
    pipe: Box<dyn Read + Send>,
    control: Control,
}
#[derive(Clone)]
pub(super) struct Control(Arc<Shared>);
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    // Keep the child process object alive even if the caller drops Child first.
    // Its PID cannot be recycled while WSADuplicateSocket still targets it.
    _peer_process: Option<OwnedHandle>,
}
struct State {
    closed: bool,
    next: u64,
    active: Vec<(u64, OwnedHandle)>,
}
struct Operation {
    control: Control,
    id: u64,
}
impl Drop for Operation {
    fn drop(&mut self) {
        let mut state = self
            .control
            .0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state.active.retain(|(id, _)| *id != self.id);
        self.control.0.changed.notify_all();
    }
}
impl Control {
    fn new(peer_process: Option<OwnedHandle>) -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(State {
                closed: false,
                next: 0,
                active: Vec::new(),
            }),
            changed: Condvar::new(),
            _peer_process: peer_process,
        }))
    }
    pub(super) fn check(&self) -> io::Result<()> {
        if self
            .0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closed
        {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker channel is closed",
            ))
        } else {
            Ok(())
        }
    }
    fn operation(&self) -> io::Result<Operation> {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker channel is closed",
            ));
        }
        let raw = unsafe { OpenThread(THREAD_TERMINATE, 0, GetCurrentThreadId()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("worker IO sequence exhausted"))?;
        let id = state.next;
        state.active.push((id, handle));
        Ok(Operation {
            control: self.clone(),
            id,
        })
    }
    pub(super) fn shutdown(&self) {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        // The owned thread handles remain valid through cancellation. Repeating
        // cancellation covers the interval between registration and entering a
        // synchronous ReadFile/WriteFile. Do not take sender/receiver locks here.
        while !state.active.is_empty() {
            for (_, handle) in &state.active {
                unsafe {
                    CancelSynchronousIo(handle.as_raw_handle().cast());
                }
            }
            state = self
                .0
                .changed
                .wait_timeout(state, Duration::from_millis(10))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}
impl Sender {
    pub(super) fn close(&mut self) {
        self.pipe = Box::new(io::sink());
    }
    pub(super) fn send(&mut self, payload: &[u8], socket: Option<&TcpStream>) -> io::Result<()> {
        let offer = match socket {
            Some(socket) => Some(handoff::duplicate(
                socket,
                self.peer_pid
                    .ok_or_else(|| invalid("worker cannot send a socket to ingress"))?,
            )?),
            None => None,
        };
        let socket_bytes = offer.as_ref().map_or(&[][..], |offer| offer.as_bytes());
        let mut header = [0; HEADER];
        header[..4].copy_from_slice(MAGIC);
        header[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header[8..12].copy_from_slice(&(socket_bytes.len() as u32).to_le_bytes());
        let _operation = self.control.operation()?;
        write_all(&mut *self.pipe, &self.control, &header)?;
        write_all(&mut *self.pipe, &self.control, socket_bytes)?;
        write_all(&mut *self.pipe, &self.control, payload)?;
        self.pipe.flush()
    }
}
impl Receiver {
    pub(super) fn close(&mut self) {
        self.pipe = Box::new(io::empty());
    }
    pub(super) fn receive(&mut self) -> io::Result<(Vec<u8>, Option<TcpStream>)> {
        let _operation = self.control.operation()?;
        let mut header = [0; HEADER];
        read_exact(&mut *self.pipe, &self.control, &mut header)?;
        if &header[..4] != MAGIC {
            return Err(invalid("invalid worker frame header"));
        }
        let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let socket_length = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        if length == 0
            || length > MAX_FRAME
            || (socket_length != 0 && socket_length != handoff::SocketOffer::WIRE_SIZE)
        {
            return Err(invalid("invalid worker frame size"));
        }
        let mut socket_bytes = vec![0; socket_length];
        read_exact(&mut *self.pipe, &self.control, &mut socket_bytes)?;
        let socket = if socket_length == 0 {
            None
        } else {
            Some(handoff::import(&handoff::SocketOffer::from_bytes(
                &socket_bytes,
            )?)?)
        };
        let mut payload = vec![0; length];
        read_exact(&mut *self.pipe, &self.control, &mut payload)?;
        Ok((payload, socket))
    }
}
// Check closure between individual IO calls, including Interrupted retries.
// Using Read::read_exact/Write::write_all here could retry an aborted operation
// without observing the shutdown flag on a platform that maps it to Interrupted.
fn read_exact(reader: &mut dyn Read, control: &Control, mut bytes: &mut [u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        control.check()?;
        match reader.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "worker pipe closed during a frame",
                ))
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn write_all(writer: &mut dyn Write, control: &Control, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        control.check()?;
        match writer.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "worker pipe did not accept a frame",
                ))
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn attach(
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    peer_pid: Option<u32>,
    peer_process: Option<OwnedHandle>,
) -> Wire {
    let control = Control::new(peer_process);
    Wire::new(
        Sender {
            pipe: writer,
            peer_pid,
            control: control.clone(),
        },
        Receiver {
            pipe: reader,
            control: control.clone(),
        },
        control,
    )
}
pub(super) fn spawn(command: &mut Command) -> io::Result<(Wire, Child)> {
    command.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = command.spawn()?;
    let peer_process =
        match unsafe { BorrowedHandle::borrow_raw(child.as_raw_handle()) }.try_clone_to_owned() {
            Ok(handle) => handle,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
    let reader = child
        .stdout
        .take()
        .ok_or_else(|| invalid("worker stdout pipe missing"))?;
    let writer = child
        .stdin
        .take()
        .ok_or_else(|| invalid("worker stdin pipe missing"))?;
    let wire = attach(
        Box::new(reader),
        Box::new(writer),
        Some(child.id()),
        Some(peer_process),
    );
    Ok((wire, child))
}
pub(super) fn from_stdio() -> io::Result<Wire> {
    let input = std::io::stdin();
    let output = std::io::stdout();
    // Duplicate handles once, then use raw files. Rust stdout buffering and test
    // harness capture must never become part of the worker protocol.
    let reader = File::from(
        unsafe { BorrowedHandle::borrow_raw(input.as_raw_handle()) }.try_clone_to_owned()?,
    );
    let writer = File::from(
        unsafe { BorrowedHandle::borrow_raw(output.as_raw_handle()) }.try_clone_to_owned()?,
    );
    Ok(attach(Box::new(reader), Box::new(writer), None, None))
}

#[cfg(test)]
pub(super) fn test_pair() -> (Wire, Wire) {
    use windows_sys::Win32::System::Pipes::CreatePipe;
    fn pipe() -> (File, File) {
        let mut reader = std::ptr::null_mut();
        let mut writer = std::ptr::null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null(), 0) },
            0
        );
        unsafe {
            (
                File::from_raw_handle(reader.cast()),
                File::from_raw_handle(writer.cast()),
            )
        }
    }
    let (left_reader, right_writer) = pipe();
    let (right_reader, left_writer) = pipe();
    (
        attach(
            Box::new(left_reader),
            Box::new(left_writer),
            Some(std::process::id()),
            None,
        ),
        attach(
            Box::new(right_reader),
            Box::new(right_writer),
            Some(std::process::id()),
            None,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_pipe_io_observes_shutdown_before_retry() {
        struct InterruptedPipe(Control);
        impl Read for InterruptedPipe {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.0 .0.state.lock().unwrap().closed = true;
                Err(io::ErrorKind::Interrupted.into())
            }
        }
        impl Write for InterruptedPipe {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0 .0.state.lock().unwrap().closed = true;
                Err(io::ErrorKind::Interrupted.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let control = Control::new(None);
        let mut pipe = InterruptedPipe(control.clone());
        assert_eq!(
            read_exact(&mut pipe, &control, &mut [0])
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        let control = Control::new(None);
        let mut pipe = InterruptedPipe(control.clone());
        assert_eq!(
            write_all(&mut pipe, &control, &[0]).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn malformed_sizes_and_headers_are_rejected_before_allocation() {
        for (magic, length, socket_length) in [
            (*b"BAD!", 1u32, 0u32),
            (*MAGIC, 0, 0),
            (*MAGIC, MAX_FRAME as u32 + 1, 0),
            (*MAGIC, 1, handoff::SocketOffer::WIRE_SIZE as u32 + 1),
        ] {
            let (left, right) = test_pair();
            let mut header = magic.to_vec();
            header.extend_from_slice(&length.to_le_bytes());
            header.extend_from_slice(&socket_length.to_le_bytes());
            left.inner
                .sender
                .lock()
                .unwrap()
                .pipe
                .write_all(&header)
                .unwrap();
            assert!(right.receive::<String>().is_err());
            assert!(right.receive::<String>().is_err());
        }
    }
}
