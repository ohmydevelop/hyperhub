use super::{invalid, Wire, MAX_FRAME};
use hyperhub_runtime::handoff;
use std::io;
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const MAGIC: &[u8; 4] = b"HHW1";
const HEADER: usize = 13;
const CHUNK: usize = handoff::MAX_PAYLOAD - HEADER;

pub(super) struct Sender(UnixDatagram);
pub(super) struct Receiver(UnixDatagram);
pub(super) struct Control {
    socket: UnixDatagram,
    closed: Arc<AtomicBool>,
}
impl Control {
    pub(super) fn check(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker channel is closed",
            ))
        } else {
            Ok(())
        }
    }
    pub(super) fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        unsafe {
            libc::shutdown(self.socket.as_raw_fd(), libc::SHUT_RDWR);
        }
    }
}
impl Sender {
    pub(super) fn close(&mut self) {}
    pub(super) fn send(&mut self, payload: &[u8], socket: Option<&TcpStream>) -> io::Result<()> {
        for (index, bytes) in payload.chunks(CHUNK).enumerate() {
            let offset = index * CHUNK;
            let mut packet = Vec::with_capacity(HEADER + bytes.len());
            packet.extend_from_slice(MAGIC);
            packet.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            packet.extend_from_slice(&(offset as u32).to_le_bytes());
            packet.push(u8::from(socket.is_some()));
            packet.extend_from_slice(bytes);
            handoff::send_packet(&self.0, if offset == 0 { socket } else { None }, &packet)?;
        }
        Ok(())
    }
}
impl Receiver {
    pub(super) fn close(&mut self) {}
    pub(super) fn receive(&mut self) -> io::Result<(Vec<u8>, Option<TcpStream>)> {
        let mut payload = Vec::new();
        let mut socket = None;
        let mut expected = None;
        loop {
            let (offered, packet) = match handoff::receive_packet(&self.0) {
                Ok(packet) => packet,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    // Closing a SOCK_DGRAM peer does not produce EOF. A private
                    // nonblocking heartbeat detects that closure without path
                    // lookup or a PID-reuse race. It can appear between chunks.
                    let mut heartbeat = [0; HEADER];
                    heartbeat[..4].copy_from_slice(MAGIC);
                    let sent = unsafe {
                        libc::send(
                            self.0.as_raw_fd(),
                            heartbeat.as_ptr().cast(),
                            heartbeat.len(),
                            libc::MSG_DONTWAIT,
                        )
                    };
                    if sent < 0 {
                        let error = io::Error::last_os_error();
                        if !matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) {
                            return Err(error);
                        }
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            if packet.len() == HEADER
                && &packet[..4] == MAGIC
                && packet[4..].iter().all(|byte| *byte == 0)
            {
                if offered.is_some() {
                    return Err(invalid("worker heartbeat carried a descriptor"));
                }
                continue;
            }
            if packet.len() <= HEADER || &packet[..4] != MAGIC {
                return Err(invalid("invalid worker packet header"));
            }
            let total = u32::from_le_bytes(packet[4..8].try_into().unwrap()) as usize;
            let offset = u32::from_le_bytes(packet[8..12].try_into().unwrap()) as usize;
            let has_socket = packet[12];
            let bytes = &packet[HEADER..];
            if total == 0
                || total > MAX_FRAME
                || offset != payload.len()
                || has_socket > 1
                || expected.is_some_and(|previous| previous != (total, has_socket))
                || bytes.len() > total.saturating_sub(offset)
                || (offset == 0 && offered.is_some() != (has_socket == 1))
                || (offset != 0 && offered.is_some())
            {
                return Err(invalid(
                    "invalid worker packet length, offset or descriptor",
                ));
            }
            if offset == 0 {
                payload.reserve(total);
                socket = offered;
                expected = Some((total, has_socket));
            }
            payload.extend_from_slice(bytes);
            if payload.len() == total {
                return Ok((payload, socket));
            }
        }
    }
}
fn attach(socket: UnixDatagram) -> io::Result<Wire> {
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok(Wire::new(
        Sender(socket.try_clone()?),
        Receiver(socket.try_clone()?),
        Control {
            socket,
            closed: Arc::new(AtomicBool::new(false)),
        },
    ))
}
pub(super) fn spawn(command: &mut Command) -> io::Result<(Wire, Child)> {
    let (parent, child) = UnixDatagram::pair()?;
    let wire = attach(parent)?;
    command
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::null());
    let child = command.spawn();
    // Command retains its configured Stdio after spawn; release its duplicate
    // immediately so EOF/liveness does not depend on the caller dropping Command.
    command.stdin(Stdio::null());
    Ok((wire, child?))
}
pub(super) fn from_stdio() -> io::Result<Wire> {
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { UnixDatagram::from_raw_fd(fd) };
    // Reject a normal pipe, stream socket or unconnected/listening endpoint.
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if kind != libc::SOCK_DGRAM {
        return Err(invalid("worker stdin is not a datagram channel"));
    }
    socket.peer_addr()?;
    attach(socket)
}

#[cfg(test)]
pub(super) fn test_pair() -> (Wire, Wire) {
    let (left, right) = UnixDatagram::pair().unwrap();
    (attach(left).unwrap(), attach(right).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::time::Duration;

    fn packet(total: usize, offset: usize, flag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        out.push(flag);
        out.extend_from_slice(bytes);
        out
    }
    #[test]
    fn heartbeat_between_chunks_preserves_reassembly() {
        let (left, right) = UnixDatagram::pair().unwrap();
        let wire = attach(right).unwrap();
        handoff::send_packet(&left, None, &packet(3, 0, 0, b"\"")).unwrap();
        handoff::send_packet(&left, None, &packet(0, 0, 0, b"")).unwrap();
        handoff::send_packet(&left, None, &packet(3, 1, 0, b"x\"")).unwrap();
        assert_eq!(wire.receive::<String>().unwrap().0, "x");
    }

    #[test]
    fn invalid_sizes_offsets_flags_and_late_descriptors_close_offers() {
        for variant in 0..8 {
            let (left, right) = UnixDatagram::pair().unwrap();
            let wire = attach(right).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let (server, _) = listener.accept().unwrap();
            let frames = match variant {
                0 => vec![(packet(MAX_FRAME + 1, 0, 1, b"x"), true)],
                1 => vec![(packet(0, 0, 1, b"x"), true)],
                2 => vec![(packet(1, 1, 1, b"x"), true)],
                3 => vec![(packet(1, 0, 0, b"x"), true)],
                4 => vec![(packet(1, 0, 2, b"x"), true)],
                5 => vec![
                    (packet(2, 0, 0, b"x"), false),
                    (packet(2, 1, 0, b"x"), true),
                ],
                6 => vec![
                    (packet(2, 0, 1, b"x"), true),
                    (packet(3, 1, 1, b"x"), false),
                ],
                7 => vec![(packet(0, 0, 0, b""), true)],
                _ => unreachable!(),
            };
            for (bytes, socket) in frames {
                handoff::send_packet(&left, socket.then_some(&server), &bytes).unwrap();
            }
            assert!(wire.receive::<String>().is_err(), "variant {variant}");
            assert!(wire.receive::<String>().is_err());
            drop(server);
            assert_eq!(
                client.read(&mut [0]).unwrap(),
                0,
                "descriptor leaked in variant {variant}"
            );
        }
    }
}
