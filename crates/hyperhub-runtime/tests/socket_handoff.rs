use hyperhub_runtime::handoff;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const CHILD_MARKER: &str = "HH_TEST_SOCKET_WORKER";
const READY: &str = "HH_SOCKET_READY";

// This source fixture is also an exact-filtered child test in a separate process.
// No credentials or real HyperHub services are used. The parent test supplies a
// private inherited channel, then transfers one accepted local TCP connection.
#[test]
fn socket_worker_child() {
    let Ok(version) = std::env::var(CHILD_MARKER) else {
        return;
    };
    #[cfg(unix)]
    let (mut socket, control) = {
        use std::os::fd::FromRawFd;
        use std::os::unix::net::UnixDatagram;
        let fd = unsafe { libc::dup(libc::STDIN_FILENO) };
        assert!(fd >= 0);
        let control = unsafe { UnixDatagram::from_raw_fd(fd) };
        control
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let (socket, id) = handoff::receive(&control).unwrap();
        assert_eq!(id, version.as_bytes());
        (socket, control)
    };
    #[cfg(windows)]
    let mut socket = {
        let mut bytes = vec![0; handoff::SocketOffer::WIRE_SIZE];
        std::io::stdin().read_exact(&mut bytes).unwrap();
        handoff::import(&handoff::SocketOffer::from_bytes(&bytes).unwrap()).unwrap()
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    println!("{READY}");
    std::io::stdout().flush().unwrap();
    let mut grant = [0];
    #[cfg(unix)]
    assert_eq!(control.recv(&mut grant).unwrap(), 1);
    #[cfg(windows)]
    std::io::stdin().read_exact(&mut grant).unwrap();
    assert_eq!(grant, [1]);
    // Only the explicit grant permits connection IO.
    loop {
        let mut message = [0; 8];
        match socket.read_exact(&mut message) {
            Ok(()) => {
                socket.write_all(version.as_bytes()).unwrap();
                socket.write_all(&message).unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => panic!("worker IO failed: {error}"),
        }
    }
}

struct Worker {
    child: Child,
    // Keep the pipe draining so the test harness can print its final result.
    stdout: std::thread::JoinHandle<()>,
}
impl Worker {
    fn start(socket: &TcpStream, version: &str) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("socket_worker_child")
            .arg("--nocapture")
            .env(CHILD_MARKER, version)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        #[cfg(unix)]
        let parent_channel = {
            use std::os::fd::OwnedFd;
            use std::os::unix::net::UnixDatagram;
            let (parent, child) = UnixDatagram::pair().unwrap();
            command.stdin(Stdio::from(OwnedFd::from(child)));
            parent
        };
        #[cfg(windows)]
        command.stdin(Stdio::piped());
        let mut child = command.spawn().unwrap();
        #[cfg(unix)]
        handoff::send(&parent_channel, socket, version.as_bytes()).unwrap();
        #[cfg(windows)]
        {
            let offer = handoff::duplicate(socket, child.id()).unwrap();
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(offer.as_bytes())
                .unwrap();
        }
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let stdout = std::thread::spawn(move || {
            let mut sent = false;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() != 0 {
                if !sent && line.contains(READY) {
                    let _ = ready_tx.send(());
                    sent = true;
                }
                line.clear();
            }
        });
        if let Err(error) = ready_rx.recv_timeout(Duration::from_secs(15)) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("worker did not acknowledge socket: {error}");
        }
        #[cfg(unix)]
        assert_eq!(parent_channel.send(&[1]).unwrap(), 1);
        #[cfg(windows)]
        child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
        Self { child, stdout }
    }
    fn finish(mut self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("worker did not drain");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.stdout.join().unwrap();
    }
}
fn connect(listener: &TcpListener) -> (TcpStream, TcpStream) {
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}
fn exchange(client: &mut TcpStream, version: u8, sequence: u64) {
    client.write_all(&sequence.to_le_bytes()).unwrap();
    let mut response = [0; 9];
    client.read_exact(&mut response).unwrap();
    assert_eq!(response[0], version);
    assert_eq!(&response[1..], sequence.to_le_bytes());
}

#[test]
fn accepted_streams_survive_handoff_and_old_workers_drain_alongside_new_workers() {
    let ingress_pid = std::process::id();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut old_client, old_server) = connect(&listener);
    let old = Worker::start(&old_server, "1");
    let old_pid = old.child.id();
    drop(old_server);
    exchange(&mut old_client, b'1', 100);
    let (mut new_client, new_server) = connect(&listener);
    let new = Worker::start(&new_server, "2");
    assert_ne!(old_pid, new.child.id());
    drop(new_server);
    for sequence in 101..=132 {
        exchange(&mut old_client, b'1', sequence);
        exchange(&mut new_client, b'2', sequence);
    }
    assert_eq!(std::process::id(), ingress_pid);
    drop(new_client);
    new.finish();
    exchange(&mut old_client, b'1', 133);
    drop(old_client);
    old.finish();
}

#[cfg(unix)]
#[test]
fn empty_missing_or_oversized_socket_offers_are_rejected() {
    use std::os::unix::net::UnixDatagram;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (_client, server) = connect(&listener);
    let (left, right) = UnixDatagram::pair().unwrap();
    assert!(handoff::send(&left, &server, &[]).is_err());
    assert!(handoff::send(&left, &server, &vec![0; 16 * 1024 + 1]).is_err());
    left.send(b"no fd").unwrap();
    assert!(handoff::receive(&right).is_err());
    handoff::send(&left, &server, b"next-valid-offer").unwrap();
    let (received, bytes) = handoff::receive(&right).unwrap();
    assert_eq!(received.peer_addr().unwrap(), server.peer_addr().unwrap());
    assert_eq!(bytes, b"next-valid-offer");
    use std::os::fd::AsRawFd;
    assert_ne!(
        unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
}

#[cfg(unix)]
fn malformed_offer(
    channel: &std::os::unix::net::UnixDatagram,
    socket: &TcpStream,
    copies: usize,
    payload: &[u8],
) {
    use std::mem::{size_of, zeroed};
    use std::os::fd::AsRawFd;
    let space = unsafe { libc::CMSG_SPACE((copies * size_of::<libc::c_int>()) as _) } as usize;
    let mut control = vec![0usize; space.div_ceil(size_of::<usize>())];
    let mut vector = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN((copies * size_of::<libc::c_int>()) as _) as _;
        for index in 0..copies {
            libc::CMSG_DATA(header)
                .cast::<libc::c_int>()
                .add(index)
                .write_unaligned(socket.as_raw_fd());
        }
        assert_eq!(
            libc::sendmsg(channel.as_raw_fd(), &message, 0),
            payload.len() as isize
        );
    }
}
#[cfg(unix)]
#[test]
fn malformed_and_truncated_offers_close_every_received_socket_reference() {
    use std::os::unix::net::UnixDatagram;
    for (copies, length) in [(2, 1), (32, 1), (1, 16 * 1024 + 1), (1, 0)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut client, server) = connect(&listener);
        let (left, right) = UnixDatagram::pair().unwrap();
        malformed_offer(&left, &server, copies, &vec![42; length]);
        assert!(handoff::receive(&right).is_err());
        drop(server);
        // If any received reference leaked, this read times out instead of EOF.
        // This checks a kernel side effect without relying on fd counts that
        // unrelated concurrent tests can change.
        assert_eq!(
            client.read(&mut [0]).unwrap(),
            0,
            "leaked {copies}-fd/{length}-byte offer"
        );
    }
}

#[cfg(windows)]
#[test]
fn winsock_offer_has_a_fixed_size_and_preserves_initialized_wire_bytes() {
    assert!(handoff::SocketOffer::from_bytes(&[]).is_err());
    let bytes: Vec<_> = (0..handoff::SocketOffer::WIRE_SIZE)
        .map(|i| i as u8)
        .collect();
    let offer = handoff::SocketOffer::from_bytes(&bytes).unwrap();
    assert_eq!(offer.as_bytes(), bytes);
}
