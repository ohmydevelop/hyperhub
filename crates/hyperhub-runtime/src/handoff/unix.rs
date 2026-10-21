use std::io;
use std::mem::{self, size_of};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;

pub const MAX_PAYLOAD: usize = 16 * 1024;
const MAX_FDS: usize = 16;

// usize storage provides the required cmsghdr alignment on 32/64-bit targets.
fn control_buffer(bytes: usize) -> Vec<usize> {
    vec![0; bytes.div_ceil(size_of::<usize>())]
}

/// Send an offer on a private connected datagram socket. Only the recipient of
/// that connected endpoint can receive the descriptor. Payloads are bounded and
/// datagrams preserve the descriptor/payload association under concurrency.
pub fn send(channel: &UnixDatagram, stream: &TcpStream, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid socket-offer payload size",
        ));
    }
    let mut vector = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let space = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as _) } as usize;
    let mut control = control_buffer(space);
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as _) as _;
        libc::CMSG_DATA(header)
            .cast::<libc::c_int>()
            .write_unaligned(stream.as_raw_fd());
    }
    loop {
        let result = unsafe { libc::sendmsg(channel.as_raw_fd(), &message, 0) };
        if result == payload.len() as isize {
            return Ok(());
        }
        if result >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "incomplete socket offer",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Receive one socket offer. All unexpected descriptors are owned immediately
/// and closed on rejection, including truncated/malformed offers.
pub fn receive(channel: &UnixDatagram) -> io::Result<(TcpStream, Vec<u8>)> {
    let mut payload = vec![0; MAX_PAYLOAD];
    let mut vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let space = unsafe { libc::CMSG_SPACE((MAX_FDS * size_of::<libc::c_int>()) as _) } as usize;
    let mut control = control_buffer(space);
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    let count = loop {
        let result = unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, flags) };
        if result >= 0 {
            break result as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        message.msg_controllen = space as _;
    };
    let mut descriptors = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        unsafe {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let base = libc::CMSG_LEN(0) as usize;
                let bytes = ((*header).cmsg_len as usize).saturating_sub(base);
                for index in 0..bytes / size_of::<libc::c_int>() {
                    let fd = libc::CMSG_DATA(header)
                        .cast::<libc::c_int>()
                        .add(index)
                        .read_unaligned();
                    descriptors.push(OwnedFd::from_raw_fd(fd));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if count == 0
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || descriptors.len() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket offer must contain one descriptor and a complete payload",
        ));
    }
    let descriptor = descriptors.pop().unwrap();
    // Also verify CLOEXEC on non-Linux systems and inherited descriptors.
    let fd_flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    if fd_flags < 0
        || unsafe {
            libc::fcntl(
                descriptor.as_raw_fd(),
                libc::F_SETFD,
                fd_flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let stream = TcpStream::from(descriptor);
    // A valid fd is not necessarily a TCP stream. Validate before granting IO.
    stream.peer_addr()?;
    let mut socket_type: libc::c_int = 0;
    let mut size = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut size,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if socket_type != libc::SOCK_STREAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "offered descriptor is not a TCP stream",
        ));
    }
    payload.truncate(count);
    Ok((stream, payload))
}
