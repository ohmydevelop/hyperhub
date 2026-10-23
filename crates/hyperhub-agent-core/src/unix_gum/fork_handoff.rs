//! The fork child uses only fixed buffers and raw syscalls until Frida recovers.
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

static CLIENT: OnceLock<Client> = OnceLock::new();
const REQUEST_LEN: usize = 70;
const REPLY_LEN: usize = 33;
const BEGIN: u8 = 1;
const CANDIDATE: u8 = 2;
const CANCEL: u8 = 3;
const READY: u8 = 4;
const PARENT_ATTACHED: u8 = 5;

struct Client {
    address: libc::sockaddr_un,
    address_len: libc::socklen_t,
    secret: [u8; 32],
}

pub(super) fn initialize() -> Result<(), String> {
    if CLIENT.get().is_some() {
        return Ok(());
    }
    let path =
        std::env::var_os("HYPERHUB_FORK_HANDOFF_SOCKET").ok_or("missing fork handoff socket")?;
    let secret =
        std::env::var("HYPERHUB_FORK_HANDOFF_SECRET").map_err(|_| "missing fork handoff secret")?;
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err("invalid fork handoff socket path".into());
    }
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    let secret = decode_secret(&secret).ok_or("invalid fork handoff secret")?;
    CLIENT
        .set(Client {
            address,
            address_len: (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1)
                as libc::socklen_t,
            secret,
        })
        .map_err(|_| "fork handoff client initialized twice".to_owned())
}

fn decode_secret(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut decoded = [0; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

pub(super) fn begin() -> Result<[u8; 32], ()> {
    unsafe { exchange(BEGIN, &[0; 32]) }
}

pub(super) unsafe fn claim(lease: &[u8; 32]) -> Result<(), ()> {
    exchange(CANDIDATE, lease).map(|_| ())
}

pub(super) unsafe fn cancel(lease: &[u8; 32]) -> Result<(), ()> {
    exchange(CANCEL, lease).map(|_| ())
}

pub(super) unsafe fn ready(lease: &[u8; 32]) -> Result<(), ()> {
    exchange(READY, lease).map(|_| ())
}

pub(super) unsafe fn await_attachment(lease: &[u8; 32]) -> Result<(), ()> {
    let deadline = monotonic_ms()? + 10_000;
    loop {
        let now = monotonic_ms()?;
        if now >= deadline {
            return Err(());
        }
        let status = exchange_until(PARENT_ATTACHED, lease, deadline.min(now + 2_000))?;
        if &status == lease {
            return Ok(());
        }
        let interval = libc::timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        libc::syscall(
            libc::SYS_nanosleep,
            &interval,
            std::ptr::null_mut::<libc::timespec>(),
        );
    }
}

pub(super) unsafe fn monotonic_ms() -> Result<i64, ()> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_MONOTONIC, &mut now) != 0 {
        return Err(());
    }
    Ok(now.tv_sec * 1_000 + now.tv_nsec / 1_000_000)
}

unsafe fn wait(fd: libc::c_int, events: libc::c_short, deadline: i64) -> Result<(), ()> {
    loop {
        let remaining = deadline - monotonic_ms()?;
        if remaining <= 0 {
            return Err(());
        }
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let timeout = libc::timespec {
            tv_sec: remaining / 1_000,
            tv_nsec: (remaining % 1_000) * 1_000_000,
        };
        let result = libc::syscall(
            libc::SYS_ppoll,
            &mut poll,
            1usize,
            &timeout,
            std::ptr::null::<libc::sigset_t>(),
            0usize,
        );
        if result > 0 && poll.revents & events != 0 {
            return Ok(());
        }
        if result < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        return Err(());
    }
}

unsafe fn exchange(op: u8, lease: &[u8; 32]) -> Result<[u8; 32], ()> {
    let deadline = monotonic_ms()? + 2_000;
    exchange_until(op, lease, deadline)
}

unsafe fn exchange_until(op: u8, lease: &[u8; 32], deadline: i64) -> Result<[u8; 32], ()> {
    let client = CLIENT.get().ok_or(())?;
    let fd = libc::syscall(
        libc::SYS_socket,
        libc::AF_UNIX,
        libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        0,
    ) as libc::c_int;
    if fd < 0 {
        return Err(());
    }
    let result = (|| {
        if libc::syscall(
            libc::SYS_connect,
            fd,
            &client.address as *const libc::sockaddr_un,
            client.address_len,
        ) != 0
        {
            if *libc::__errno_location() != libc::EINPROGRESS {
                return Err(());
            }
            wait(fd, libc::POLLOUT, deadline)?;
            let mut error = 0i32;
            let mut length = std::mem::size_of_val(&error) as libc::socklen_t;
            if libc::syscall(
                libc::SYS_getsockopt,
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut error,
                &mut length,
            ) != 0
                || error != 0
            {
                return Err(());
            }
        }
        let mut request = [0u8; REQUEST_LEN];
        request[..4].copy_from_slice(b"HHFH");
        request[4] = 1;
        request[5] = op;
        request[6..38].copy_from_slice(&client.secret);
        request[38..].copy_from_slice(lease);
        let mut offset = 0;
        while offset < request.len() {
            wait(fd, libc::POLLOUT, deadline)?;
            let written = libc::syscall(
                libc::SYS_sendto,
                fd,
                request.as_ptr().add(offset),
                request.len() - offset,
                libc::MSG_NOSIGNAL,
                std::ptr::null::<libc::sockaddr>(),
                0,
            );
            if written > 0 {
                offset += written as usize;
            } else if written == 0
                || !matches!(*libc::__errno_location(), libc::EINTR | libc::EAGAIN)
            {
                return Err(());
            }
        }
        let mut reply = [0u8; REPLY_LEN];
        offset = 0;
        while offset < reply.len() {
            wait(fd, libc::POLLIN, deadline)?;
            let read = libc::syscall(
                libc::SYS_recvfrom,
                fd,
                reply.as_mut_ptr().add(offset),
                reply.len() - offset,
                0,
                std::ptr::null_mut::<libc::sockaddr>(),
                std::ptr::null_mut::<libc::socklen_t>(),
            );
            if read > 0 {
                offset += read as usize;
            } else if read == 0 || !matches!(*libc::__errno_location(), libc::EINTR | libc::EAGAIN)
            {
                return Err(());
            }
        }
        // Complete can race either status request. Complete requires attachment,
        // so the original parent may return. A child's Ready notification never
        // releases its application thread: it must observe separate publication.
        if matches!(op, READY | PARENT_ATTACHED)
            && reply[0] == 5
            && reply[1..].iter().all(|byte| *byte == 0)
        {
            return Ok(*lease);
        }
        if op == PARENT_ATTACHED && reply[0] == 8 && reply[1..].iter().all(|byte| *byte == 0) {
            return Ok([0; 32]);
        }
        if reply[0] != 0 || reply[1..].iter().all(|byte| *byte == 0) {
            return Err(());
        }
        let received: [u8; 32] = reply[1..].try_into().map_err(|_| ())?;
        if op != BEGIN && &received != lease {
            return Err(());
        }
        Ok(received)
    })();
    libc::syscall(libc::SYS_close, fd);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn handoff_secret_requires_exact_hex_bytes() {
        assert_eq!(decode_secret(&"ab".repeat(32)), Some([0xab; 32]));
        assert!(decode_secret(&"a".repeat(63)).is_none());
        assert!(decode_secret(&"gg".repeat(32)).is_none());
        assert!(decode_secret(&"é".repeat(32)).is_none());
    }

    #[test]
    fn raw_handoff_messages_preserve_capabilities_and_check_replies() {
        let directory = std::env::temp_dir().join(format!(
            "hfc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("s");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (destination, source) in address.sun_path.iter_mut().zip(path.as_os_str().as_bytes()) {
            *destination = *source as libc::c_char;
        }
        assert!(CLIENT
            .set(Client {
                address,
                address_len: (std::mem::size_of::<libc::sa_family_t>()
                    + path.as_os_str().as_bytes().len()
                    + 1) as libc::socklen_t,
                secret: [0x42; 32],
            })
            .is_ok());
        let server = std::thread::spawn(move || {
            for (op, status, reply_lease) in [
                (BEGIN, 0, [0x24; 32]),
                (CANDIDATE, 0, [0x24; 32]),
                (PARENT_ATTACHED, 8, [0; 32]),
                (PARENT_ATTACHED, 0, [0x24; 32]),
                (READY, 5, [0; 32]),
                (CANCEL, 0, [0x24; 32]),
                (READY, 5, [0x24; 32]),
                (CANDIDATE, 1, [0; 32]),
            ] {
                let (mut connection, _) = listener.accept().unwrap();
                connection
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0; REQUEST_LEN];
                connection.read_exact(&mut request).unwrap();
                assert_eq!(&request[..4], b"HHFH");
                assert_eq!(request[4], 1);
                assert_eq!(request[5], op);
                assert_eq!(request[6..38], [0x42; 32]);
                assert_eq!(
                    request[38..],
                    if op == BEGIN { [0; 32] } else { [0x24; 32] }
                );
                let mut reply = [0; REPLY_LEN];
                reply[0] = status;
                reply[1..].copy_from_slice(&reply_lease);
                connection.write_all(&reply).unwrap();
            }
        });
        assert_eq!(begin(), Ok([0x24; 32]));
        assert_eq!(unsafe { claim(&[0x24; 32]) }, Ok(()));
        assert_eq!(unsafe { await_attachment(&[0x24; 32]) }, Ok(()));
        assert_eq!(unsafe { ready(&[0x24; 32]) }, Ok(()));
        assert_eq!(unsafe { cancel(&[0x24; 32]) }, Ok(()));
        assert!(unsafe { ready(&[0x24; 32]) }.is_err());
        assert!(unsafe { claim(&[0x24; 32]) }.is_err());
        server.join().unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
