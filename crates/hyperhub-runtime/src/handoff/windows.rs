use std::io;
use std::mem::{self, size_of};
use std::net::TcpStream;
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::sync::OnceLock;
use windows_sys::Win32::Networking::WinSock::{
    WSADuplicateSocketW, WSAGetLastError, WSASocketW, WSAStartup, INVALID_SOCKET, SOCKET_ERROR,
    WSADATA, WSAPROTOCOL_INFOW, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
};

/// Opaque same-architecture Winsock protocol bytes. Send only to the authenticated
/// process whose PID was passed to `duplicate`. Not a public network format.
/// Aligned byte storage avoids reading uninitialized Rust structure padding.
pub struct SocketOffer {
    buffer: Box<[usize]>,
}
impl SocketOffer {
    pub const WIRE_SIZE: usize = size_of::<WSAPROTOCOL_INFOW>();
    fn empty() -> Self {
        Self {
            buffer: vec![0; Self::WIRE_SIZE.div_ceil(size_of::<usize>())].into_boxed_slice(),
        }
    }
    fn pointer(&self) -> *const WSAPROTOCOL_INFOW {
        self.buffer.as_ptr().cast()
    }
    pub fn as_bytes(&self) -> &[u8] {
        // Storage starts zeroed and Winsock writes directly into it. The buffer
        // never moves its underlying bytes through a padded Rust value.
        unsafe { std::slice::from_raw_parts(self.buffer.as_ptr().cast(), Self::WIRE_SIZE) }
    }
    /// Parse an offer received from the trusted ingress on a private channel.
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != Self::WIRE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Winsock socket-offer size",
            ));
        }
        let mut offer = Self::empty();
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                offer.buffer.as_mut_ptr().cast(),
                bytes.len(),
            );
        }
        Ok(offer)
    }
}
fn initialize_winsock() -> io::Result<()> {
    // A fresh worker may not yet have constructed a std::net socket. Own one
    // process-lifetime Winsock reference independently of the standard library.
    static STARTUP: OnceLock<i32> = OnceLock::new();
    let result = *STARTUP.get_or_init(|| {
        let mut data = unsafe { mem::zeroed::<WSADATA>() };
        unsafe { WSAStartup(0x0202, &mut data) }
    });
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}
pub fn duplicate(stream: &TcpStream, worker_pid: u32) -> io::Result<SocketOffer> {
    initialize_winsock()?;
    let mut offer = SocketOffer::empty();
    if unsafe {
        WSADuplicateSocketW(
            stream.as_raw_socket() as _,
            worker_pid,
            offer.buffer.as_mut_ptr().cast(),
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(offer)
}
/// The current process must be the recipient of this authenticated offer. Wait
/// for the ingress ownership grant before using the returned stream.
pub fn import(offer: &SocketOffer) -> io::Result<TcpStream> {
    initialize_winsock()?;
    let socket = unsafe {
        WSASocketW(
            -1,
            -1,
            -1,
            offer.pointer(),
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if socket == INVALID_SOCKET {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let stream = unsafe { TcpStream::from_raw_socket(socket as _) };
    stream.peer_addr()?;
    Ok(stream)
}
