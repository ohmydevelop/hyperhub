use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn maximum_frame_chunks_and_concurrent_senders_do_not_interleave() {
    let (left, right) = platform::test_pair();
    let read = std::thread::spawn(move || {
        let (payload, socket) = right.receive::<String>().unwrap();
        assert_eq!(payload.len(), MAX_FRAME - 2);
        assert!(payload.bytes().all(|byte| byte == b'x'));
        assert!(socket.is_none());
        let mut values = Vec::new();
        for _ in 0..16 {
            let (value, socket) = right.receive::<u64>().unwrap();
            assert!(socket.is_none());
            values.push(value);
        }
        values.sort_unstable();
        assert_eq!(values, (0..16).collect::<Vec<_>>());
        right.send(&"done", None).unwrap();
    });
    assert!(left.send(&"x".repeat(MAX_FRAME), None).is_err());
    left.send(&"x".repeat(MAX_FRAME - 2), None).unwrap();
    let mut senders = Vec::new();
    for value in 0..16u64 {
        let sender = left.clone();
        senders.push(std::thread::spawn(move || {
            sender.send(&value, None).unwrap()
        }));
    }
    for sender in senders {
        sender.join().unwrap();
    }
    assert_eq!(left.receive::<String>().unwrap().0, "done");
    read.join().unwrap();
}

#[test]
fn transferred_tcp_waits_for_explicit_grant_and_survives_sender_close() {
    let (left, right) = platform::test_pair();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let worker = std::thread::spawn(move || {
        let (offer, socket) = right.receive::<String>().unwrap();
        assert_eq!(offer, "offer");
        let mut socket = socket.unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        right.send(&"ready", None).unwrap();
        assert_eq!(right.receive::<String>().unwrap().0, "grant");
        let mut bytes = [0; 4];
        socket.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ping");
        socket.write_all(b"pong").unwrap();
    });
    left.send(&"offer", Some(&server)).unwrap();
    assert_eq!(left.receive::<String>().unwrap().0, "ready");
    drop(server);
    left.send(&"grant", None).unwrap();
    client.write_all(b"ping").unwrap();
    let mut bytes = [0; 4];
    client.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"pong");
    worker.join().unwrap();
}

#[test]
fn shutdown_wakes_blocked_reader_and_prevents_future_operations() {
    let (left, _right) = platform::test_pair();
    let reader = left.clone();
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || tx.send(reader.receive::<u64>().is_err()).unwrap());
    // Exercise both shutdown-before-native-read and shutdown-during-native-read.
    left.shutdown();
    assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
    assert!(left.send(&1, None).is_err());
    assert!(left.receive::<u64>().is_err());
    join.join().unwrap();
}

#[test]
fn shutdown_wakes_active_reader() {
    let (left, _right) = platform::test_pair();
    let reader = left.clone();
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || tx.send(reader.receive::<u64>().is_err()).unwrap());
    std::thread::sleep(Duration::from_millis(20));
    left.shutdown();
    assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
    join.join().unwrap();
}

#[cfg(unix)]
#[test]
fn private_inherited_endpoint_moves_real_tcp_across_processes() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "forward::wire::tests::inherited_worker_child",
            "--nocapture",
        ])
        .env("HH_WIRE_TEST_CHILD", "1");
    let (wire, mut child) = spawn(&mut command).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (server, _) = listener.accept().unwrap();
    wire.send(&"offer", Some(&server)).unwrap();
    assert_eq!(wire.receive::<String>().unwrap().0, "ready");
    wire.send(&"grant", None).unwrap();
    drop(server);
    client.write_all(b"ping").unwrap();
    let mut bytes = [0; 4];
    client.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"pong");
    wire.shutdown();
    assert!(child.wait().unwrap().success());
}

#[cfg(unix)]
#[test]
fn inherited_worker_child() {
    if std::env::var_os("HH_WIRE_TEST_CHILD").is_none() {
        return;
    }
    let wire = from_stdio().unwrap();
    let (frame, socket) = wire.receive::<String>().unwrap();
    assert_eq!(frame, "offer");
    let mut socket = socket.unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    wire.send(&"ready", None).unwrap();
    assert_eq!(wire.receive::<String>().unwrap().0, "grant");
    let mut bytes = [0; 4];
    socket.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ping");
    socket.write_all(b"pong").unwrap();
}

#[test]
fn peer_exit_wakes_receiver_without_a_public_liveness_endpoint() {
    let (left, right) = platform::test_pair();
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || tx.send(left.receive::<String>().is_err()).unwrap());
    drop(right);
    assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
    join.join().unwrap();
}

#[cfg(unix)]
#[test]
fn child_process_exit_wakes_parent_receiver() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "forward::wire::tests::peer_exit_worker_child",
            "--nocapture",
        ])
        .env("HH_WIRE_TEST_EXIT", "1");
    let (wire, mut child) = spawn(&mut command).unwrap();
    assert_eq!(wire.receive::<String>().unwrap().0, "ready");
    wire.send(&"exit", None).unwrap();
    assert!(wire.receive::<String>().is_err());
    assert!(child.wait().unwrap().success());
}

#[cfg(unix)]
#[test]
fn peer_exit_worker_child() {
    if std::env::var_os("HH_WIRE_TEST_EXIT").is_none() {
        return;
    }
    unsafe {
        libc::alarm(15);
    }
    let wire = from_stdio().unwrap();
    wire.send(&"ready", None).unwrap();
    assert_eq!(wire.receive::<String>().unwrap().0, "exit");
    std::process::exit(0);
}

#[cfg(unix)]
#[test]
fn parent_process_exit_wakes_worker_receiver() {
    let unique = format!(
        "hh-wire-parent-exit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let directory = std::env::temp_dir().join(unique);
    std::fs::create_dir(&directory).unwrap();
    let result = directory.join("result");
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "forward::wire::tests::peer_exit_parent_child",
            "--nocapture",
        ])
        .env("HH_WIRE_TEST_PARENT_EXIT", &result)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !result.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let observed = std::fs::read_to_string(&result).unwrap();
    assert_eq!(observed, "parent channel closed");
    std::fs::remove_file(result).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn peer_exit_parent_child() {
    let Some(path) = std::env::var_os("HH_WIRE_TEST_PARENT_EXIT") else {
        return;
    };
    unsafe {
        libc::alarm(15);
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "forward::wire::tests::orphan_worker_child",
            "--nocapture",
        ])
        .env("HH_WIRE_TEST_ORPHAN_RESULT", path);
    let (wire, _child) = spawn(&mut command).unwrap();
    assert_eq!(wire.receive::<String>().unwrap().0, "ready");
    // Exit without running destructors: this must be kernel peer-closure
    // detection rather than Wire::shutdown or Rust drop behavior.
    std::process::exit(0);
}

#[cfg(unix)]
#[test]
fn orphan_worker_child() {
    let Some(path) = std::env::var_os("HH_WIRE_TEST_ORPHAN_RESULT") else {
        return;
    };
    unsafe {
        libc::alarm(15);
    }
    let wire = from_stdio().unwrap();
    wire.send(&"ready", None).unwrap();
    assert!(wire.receive::<String>().is_err());
    std::fs::write(path, "parent channel closed").unwrap();
}

#[test]
fn shutdown_wakes_writer_when_peer_stops_reading() {
    let (left, _right) = platform::test_pair();
    let sender = left.clone();
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || {
        tx.send(sender.send(&"x".repeat(MAX_FRAME - 2), None).is_err())
            .unwrap()
    });
    std::thread::sleep(Duration::from_millis(20));
    left.shutdown();
    assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
    join.join().unwrap();
}
