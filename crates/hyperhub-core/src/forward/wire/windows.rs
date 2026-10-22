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
    IO::{CancelIoEx, CancelSynchronousIo},
};

const MAGIC: &[u8; 4] = b"HHW1";
const HEADER: usize = 12;

trait WritePipe: Write + AsRawHandle + Send {}
impl<T: Write + AsRawHandle + Send> WritePipe for T {}
trait ReadPipe: Read + AsRawHandle + Send {}
impl<T: Read + AsRawHandle + Send> ReadPipe for T {}

pub(super) struct Sender {
    pipe: Option<Box<dyn WritePipe>>,
    peer_pid: Option<u32>,
    control: Control,
}
pub(super) struct Receiver {
    pipe: Option<Box<dyn ReadPipe>>,
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
    active: Vec<ActiveIo>,
}
struct ActiveIo {
    id: u64,
    thread: OwnedHandle,
    // The exact handle used by IO, not a separately duplicated handle.
    // with_operation retains the pipe borrow until its Operation is removed.
    pipe: usize,
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
        state.active.retain(|operation| operation.id != self.id);
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
    fn with_operation<P: AsRawHandle + ?Sized, T>(
        &self,
        pipe: &mut P,
        io: impl FnOnce(&mut P) -> io::Result<T>,
    ) -> io::Result<T> {
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
        state.active.push(ActiveIo {
            id,
            thread: handle,
            pipe: pipe.as_raw_handle() as usize,
        });
        drop(state);
        // The guard cannot escape this scope. The original pipe stays borrowed
        // through native IO completion (including Rust's overlapped APC wait),
        // and is never closed/reused while shutdown can access its raw handle.
        let _operation = Operation {
            control: self.clone(),
            id,
        };
        io(pipe)
    }
    pub(super) fn shutdown(&self) {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        // Rust ChildStdin/ChildStdout use overlapped IO even though their Read
        // and Write methods block. CancelSynchronousIo alone cannot wake them.
        // Retain both the exact pipe and owned thread handle through completion;
        // from_stdio's File IO remains synchronous. Repeat both cancellation
        // forms to cover registration racing actual IO submission. Do not take
        // sender/receiver locks here or close handles before Operation drops.
        while !state.active.is_empty() {
            for operation in &state.active {
                unsafe {
                    CancelIoEx(operation.pipe as _, std::ptr::null());
                    CancelSynchronousIo(operation.thread.as_raw_handle().cast());
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
        self.pipe.take();
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
        let pipe = self.pipe.as_deref_mut().ok_or_else(closed)?;
        self.control.with_operation(pipe, |pipe| {
            write_all(pipe, &self.control, &header)?;
            write_all(pipe, &self.control, socket_bytes)?;
            write_all(pipe, &self.control, payload)?;
            pipe.flush()
        })
    }
}
impl Receiver {
    pub(super) fn close(&mut self) {
        self.pipe.take();
    }
    pub(super) fn receive(&mut self) -> io::Result<(Vec<u8>, Option<TcpStream>)> {
        let pipe = self.pipe.as_deref_mut().ok_or_else(closed)?;
        self.control.with_operation(pipe, |pipe| {
            let mut header = [0; HEADER];
            read_exact(pipe, &self.control, &mut header)?;
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
            read_exact(pipe, &self.control, &mut socket_bytes)?;
            let socket = if socket_length == 0 {
                None
            } else {
                Some(handoff::import(&handoff::SocketOffer::from_bytes(
                    &socket_bytes,
                )?)?)
            };
            let mut payload = vec![0; length];
            read_exact(pipe, &self.control, &mut payload)?;
            Ok((payload, socket))
        })
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "worker pipe is closed")
}
// Check closure between individual IO calls, including Interrupted retries.
// Using Read::read_exact/Write::write_all here could retry an aborted operation
// without observing the shutdown flag on a platform that maps it to Interrupted.
fn read_exact<R: Read + ?Sized>(
    reader: &mut R,
    control: &Control,
    mut bytes: &mut [u8],
) -> io::Result<()> {
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
fn write_all<W: Write + ?Sized>(
    writer: &mut W,
    control: &Control,
    mut bytes: &[u8],
) -> io::Result<()> {
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
    reader: Box<dyn ReadPipe>,
    writer: Box<dyn WritePipe>,
    peer_pid: Option<u32>,
    peer_process: Option<OwnedHandle>,
) -> Wire {
    let control = Control::new(peer_process);
    Wire::new(
        Sender {
            pipe: Some(writer),
            peer_pid,
            control: control.clone(),
        },
        Receiver {
            pipe: Some(reader),
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
    fn shutdown_cancels_real_child_stdio_overlapped_reads_and_writes() {
        struct SilentChild {
            child: Child,
            directory: std::path::PathBuf,
        }
        impl Drop for SilentChild {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let _ = std::fs::remove_dir_all(&self.directory);
            }
        }
        let directory = std::env::temp_dir().join(format!(
            "hh-wire-overlapped-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let marker = directory.join("entered");
        let binary = directory.join("silent-worker.exe");
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/forward_worker_silent.rs");
        let output = Command::new("rustc")
            .args(["--edition=2021", "--crate-name", "forward_worker_silent"])
            .arg(source)
            .arg("-o")
            .arg(&binary)
            .env("HH_SILENT_WORKER_MARKER", &marker)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut command = Command::new(&binary);
        command.arg("forward-worker");
        let (wire, child) = spawn(&mut command).unwrap();
        let mut child = SilentChild { child, directory };
        let sender = wire.clone();
        let receiver = wire.clone();
        let (sent, sending) = std::sync::mpsc::channel();
        let (received, receiving) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            sent.send(sender.send(&"x".repeat(MAX_FRAME - 2), None).is_err())
                .unwrap();
        });
        let reader = std::thread::spawn(move || {
            received
                .send(receiver.receive::<String>().is_err())
                .unwrap();
        });
        let started = std::time::Instant::now();
        loop {
            let active = wire.inner.control.0.state.lock().unwrap().active.len();
            if marker.is_file() && active == 2 {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "both real stdio operations did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(child.child.try_wait().unwrap().is_none());
        let closer = wire.clone();
        let (closed, closing) = std::sync::mpsc::channel();
        let shutdown = std::thread::spawn(move || {
            closer.shutdown();
            closed.send(()).unwrap();
        });
        let result = closing.recv_timeout(Duration::from_secs(5));
        if result.is_err() {
            // Reap the bounded fixture before reporting a regression, so a
            // broken cancellation implementation cannot leave blocked threads.
            let _ = child.child.kill();
            let _ = child.child.wait();
        }
        assert!(sending.recv_timeout(Duration::from_secs(5)).unwrap());
        assert!(receiving.recv_timeout(Duration::from_secs(5)).unwrap());
        writer.join().unwrap();
        reader.join().unwrap();
        shutdown.join().unwrap();
        assert!(
            result.is_ok(),
            "shutdown did not cancel real overlapped stdio within 5 seconds"
        );
        assert!(
            child.child.try_wait().unwrap().is_none(),
            "cancellation waited for the live child to exit"
        );
        assert!(wire.is_closed());
    }

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
                .as_mut()
                .unwrap()
                .write_all(&header)
                .unwrap();
            assert!(right.receive::<String>().is_err());
            assert!(right.receive::<String>().is_err());
        }
    }
}
