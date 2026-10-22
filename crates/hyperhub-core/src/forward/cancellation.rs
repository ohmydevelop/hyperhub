//! Explicit close marker shared by duplicated accepted TCP sockets.
//!
//! HyperHub exclusively owns SO_KEEPALIVE on the accepted ingress socket. It is
//! false throughout business IO and becomes true immediately before an explicit
//! cancellation or completed forwarding shutdown. Remote FINs never set it.
use std::io;
use std::net::{Shutdown, TcpStream};

pub(super) fn initialize(stream: &TcpStream) -> io::Result<()> {
    option(stream, Some(false))?;
    if option(stream, None)? {
        return Err(io::Error::other(
            "forwarding socket close marker could not be initialized",
        ));
    }
    Ok(())
}
pub(super) fn mark_closed(stream: &TcpStream) -> io::Result<()> {
    let marked = option(stream, Some(true));
    let closed = stream.shutdown(Shutdown::Both).or_else(|error| {
        if error.kind() == io::ErrorKind::NotConnected {
            Ok(())
        } else {
            Err(error)
        }
    });
    marked.and(closed)
}
pub(super) fn locally_closed(stream: &TcpStream) -> bool {
    option(stream, None).unwrap_or(true)
}

#[cfg(unix)]
fn option(stream: &TcpStream, set: Option<bool>) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    let mut value: libc::c_int = i32::from(set.unwrap_or(false));
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    let result = if set.is_some() {
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                (&value as *const libc::c_int).cast(),
                length,
            )
        }
    } else {
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                (&mut value as *mut libc::c_int).cast(),
                &mut length,
            )
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length != std::mem::size_of_val(&value) as libc::socklen_t {
        return Err(io::Error::other(
            "invalid forwarding socket close marker size",
        ));
    }
    Ok(value != 0)
}
#[cfg(windows)]
fn option(stream: &TcpStream, set: Option<bool>) -> io::Result<bool> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        getsockopt, setsockopt, WSAGetLastError, SOL_SOCKET, SO_KEEPALIVE,
    };
    let mut value: i32 = i32::from(set.unwrap_or(false));
    let mut length = std::mem::size_of_val(&value) as i32;
    let result = if set.is_some() {
        unsafe {
            setsockopt(
                stream.as_raw_socket() as _,
                SOL_SOCKET,
                SO_KEEPALIVE,
                (&value as *const i32).cast(),
                length,
            )
        }
    } else {
        unsafe {
            getsockopt(
                stream.as_raw_socket() as _,
                SOL_SOCKET,
                SO_KEEPALIVE,
                (&mut value as *mut i32).cast(),
                &mut length,
            )
        }
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if length != std::mem::size_of_val(&value) as i32 {
        return Err(io::Error::other(
            "invalid forwarding socket close marker size",
        ));
    }
    Ok(value != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        initialize(&server).unwrap();
        (client, server)
    }
    #[test]
    fn explicit_marker_is_shared_by_socket_duplicates() {
        let (_client, server) = pair();
        let duplicate = server.try_clone().unwrap();
        assert!(!locally_closed(&server));
        assert!(!locally_closed(&duplicate));
        mark_closed(&duplicate).unwrap();
        assert!(locally_closed(&server));
    }
    #[test]
    fn remote_half_close_preserves_response_and_does_not_set_marker() {
        let (mut client, mut server) = pair();
        client.shutdown(Shutdown::Write).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(server.read(&mut [0]).unwrap(), 0);
        assert!(!locally_closed(&server));
        server.write_all(b"response").unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"response");
    }
    #[test]
    fn both_direction_fins_with_buffered_upload_are_not_explicit_cancellation() {
        let (mut client, mut server) = pair();
        server.shutdown(Shutdown::Write).unwrap();
        client.write_all(b"queued-upload").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert!(server.peek(&mut [0; 32]).unwrap() > 0);
        assert!(!locally_closed(&server));
        let mut request = Vec::new();
        server.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"queued-upload");
        assert!(!locally_closed(&server));
        mark_closed(&server).unwrap();
        assert!(locally_closed(&server));
    }
    #[test]
    fn marker_queries_never_consume_or_send_application_bytes() {
        let (mut client, mut server) = pair();
        client.write_all(b"request").unwrap();
        for _ in 0..32 {
            assert!(!locally_closed(&server));
        }
        let mut request = [0; 7];
        server.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"request");
        client
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        assert!(matches!(
            client.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
    }
}
