//! Completes only the private version handshake, then stops consuming control
//! messages. It never receives or uses a business socket. It exits after 36s as
//! a bounded cleanup fallback when testing a broken parent health watchdog.
fn field<'a>(json: &'a str, name: &str) -> &'a str {
    let tail = json.split_once(&format!("\"{name}\":")).unwrap().1;
    if let Some(tail) = tail.strip_prefix('"') {
        &tail[..tail.find('"').unwrap()]
    } else {
        &tail[..tail.find([',', '}']).unwrap()]
    }
}
fn boot(payload: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(payload).unwrap();
    assert_eq!(field(text, "type"), "bootstrap");
    format!("{{\"type\":\"booted\",\"protocol\":{},\"parent_pid\":{},\"worker_pid\":{},\"generation\":{},\"nonce\":\"{}\",\"version\":\"{}\"}}",field(text,"protocol"),field(text,"parent_pid"),std::process::id(),field(text,"generation"),field(text,"nonce"),env!("HH_TEST_WORKER_VERSION")).into_bytes()
}
#[cfg(unix)]
fn handshake() {
    use std::os::fd::FromRawFd;
    let socket = unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(0) };
    let mut payload = Vec::new();
    loop {
        let mut packet = [0u8; 16384];
        let count = socket.recv(&mut packet).unwrap();
        assert!(count > 13);
        assert_eq!(&packet[..4], b"HHW1");
        let total = u32::from_le_bytes(packet[4..8].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(packet[8..12].try_into().unwrap()) as usize;
        assert!(total <= 2 * 1024 * 1024);
        assert_eq!(offset, payload.len());
        assert_eq!(packet[12], 0);
        payload.extend_from_slice(&packet[13..count]);
        if payload.len() == total {
            break;
        }
    }
    let reply = boot(&payload);
    let mut packet = b"HHW1".to_vec();
    packet.extend_from_slice(&(reply.len() as u32).to_le_bytes());
    packet.extend_from_slice(&0u32.to_le_bytes());
    packet.push(0);
    packet.extend(reply);
    socket.send(&packet).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(36));
}
#[cfg(windows)]
fn handshake() {
    use std::io::{Read, Write};
    let mut header = [0u8; 12];
    let mut input = std::io::stdin().lock();
    input.read_exact(&mut header).unwrap();
    assert_eq!(&header[..4], b"HHW1");
    assert_eq!(&header[8..12], &[0; 4]);
    let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    assert!(length <= 2 * 1024 * 1024);
    let mut payload = vec![0; length];
    input.read_exact(&mut payload).unwrap();
    let reply = boot(&payload);
    header[4..8].copy_from_slice(&(reply.len() as u32).to_le_bytes());
    let mut output = std::io::stdout().lock();
    output.write_all(&header).unwrap();
    output.write_all(&reply).unwrap();
    output.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(36));
}
fn main() {
    assert_eq!(std::env::args().nth(1).as_deref(), Some("forward-worker"));
    handshake();
}
