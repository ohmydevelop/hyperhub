#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
#[path = "windows_exception_diagnostics.rs"]
mod diagnostics;

#[cfg(windows)]
#[path = "windows_fls_teardown.rs"]
mod fls_teardown;

#[cfg(windows)]
mod probe {
    use std::mem::{size_of, zeroed};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::Networking::WinSock::*;
    use windows_sys::Win32::System::Threading::{CreateEventW, SleepEx, WaitForSingleObject};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    // The callback identity belongs to each request. Global completion flags
    // would hide cross-request delivery when requests run concurrently.
    #[repr(C)]
    struct Request {
        overlapped: OVERLAPPED,
        completed: AtomicBool,
        status: AtomicU32,
        identity: AtomicUsize,
    }

    unsafe extern "system" fn completed(error: u32, _: u32, overlapped: *const OVERLAPPED) {
        let request = &*overlapped.cast::<Request>();
        request
            .identity
            .store(overlapped as usize, Ordering::Release);
        request.status.store(error, Ordering::Release);
        request.completed.store(true, Ordering::Release);
    }

    unsafe fn exchange(socket: SOCKET, already_sent: bool) {
        let payload = b"windows-hook-local-echo";
        if !already_sent {
            assert_eq!(
                send(socket, payload.as_ptr(), payload.len() as i32, 0),
                payload.len() as i32
            );
        }
        let mut reply = vec![0; payload.len()];
        let mut offset = 0;
        while offset < reply.len() {
            let count = recv(
                socket,
                reply[offset..].as_mut_ptr(),
                (reply.len() - offset) as i32,
                0,
            );
            assert!(count > 0, "recv error={}", WSAGetLastError());
            offset += count as usize;
        }
        assert_eq!(&reply, payload);
    }

    unsafe fn dns(mode: &str, port: u16) {
        let name: Vec<u16> = "localhost\0".encode_utf16().collect();
        let service: Vec<u16> = format!("{port}\0").encode_utf16().collect();
        let mut hints: ADDRINFOEXW = zeroed();
        hints.ai_family = AF_INET as i32;
        hints.ai_socktype = SOCK_STREAM;
        let mut result = null_mut();
        let callback = mode == "dns-callback" || mode == "dns-cancel-callback";
        let cancelled = mode.starts_with("dns-cancel");
        let event = CreateEventW(null(), 1, 0, null());
        assert!(!event.is_null());
        let mut request = Request {
            overlapped: zeroed(),
            completed: AtomicBool::new(false),
            status: AtomicU32::new(u32::MAX),
            identity: AtomicUsize::new(0),
        };
        if !callback {
            request.overlapped.hEvent = event;
        }
        let overlapped = &mut request.overlapped as *mut OVERLAPPED;
        let mut handle = null_mut();
        let status = GetAddrInfoExW(
            name.as_ptr(),
            service.as_ptr(),
            NS_DNS,
            null(),
            &hints,
            &mut result,
            null(),
            overlapped,
            if callback { Some(completed) } else { None },
            &mut handle,
        );
        assert!(
            status == 0 || status == WSA_IO_PENDING,
            "resolve status={status}"
        );
        if status == WSA_IO_PENDING && !callback {
            let progress = GetAddrInfoExOverlappedResult(overlapped);
            assert!(
                progress == WSAEINPROGRESS || progress == 0,
                "invalid pending accessor status={progress}"
            );
        }
        if cancelled && status == WSA_IO_PENDING && !handle.is_null() {
            let cancel_status = GetAddrInfoExCancel(&handle);
            // Completion can win the cancellation race. Either terminal result is valid.
            assert!(
                cancel_status == 0 || cancel_status == WSA_INVALID_HANDLE,
                "unexpected cancel status={cancel_status}"
            );
            println!("cancel_status={cancel_status}");
        }
        if status == WSA_IO_PENDING {
            if callback {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !request.completed.load(Ordering::Acquire)
                    && std::time::Instant::now() < deadline
                {
                    SleepEx(10, 1);
                }
                assert!(
                    request.completed.load(Ordering::Acquire),
                    "completion callback missing"
                );
                assert_eq!(
                    request.identity.load(Ordering::Acquire),
                    overlapped as usize
                );
            } else if mode == "dns-cancel-poll" {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while GetAddrInfoExOverlappedResult(overlapped) == WSAEINPROGRESS
                    && std::time::Instant::now() < deadline
                {
                    std::thread::yield_now();
                }
            } else {
                assert_eq!(
                    WaitForSingleObject(event, 10000),
                    WAIT_OBJECT_0,
                    "completion event missing"
                );
            }
        }
        if !callback {
            assert_eq!((*overlapped).hEvent, event, "caller event identity changed");
        }
        let terminal = if callback && status == WSA_IO_PENDING {
            request.status.load(Ordering::Acquire) as i32
        } else if mode == "dns-poll" {
            (*overlapped).Internal as i32
        } else {
            GetAddrInfoExOverlappedResult(overlapped)
        };
        if cancelled {
            assert!(
                terminal == 0 || terminal == WSA_E_CANCELLED || terminal == WSA_OPERATION_ABORTED,
                "unexpected cancellation result={terminal}"
            );
            println!("dns=terminal status={terminal}");
        } else {
            assert_eq!(terminal, 0);
            assert!(!result.is_null());
            let socket = socket((*result).ai_family, SOCK_STREAM, IPPROTO_TCP);
            assert_ne!(socket, INVALID_SOCKET);
            assert_eq!(
                connect(socket, (*result).ai_addr, (*result).ai_addrlen as i32),
                0
            );
            exchange(socket, false);
            closesocket(socket);
            println!("dns=ok mode={mode} native_status={status}");
        }
        if !result.is_null() {
            eprintln!("dns_cleanup stage=free_results");
            FreeAddrInfoExW(result);
        }
        eprintln!("dns_cleanup stage=close_event");
        assert_ne!(CloseHandle(event), 0);
    }

    unsafe fn connect_ex(mode: &str, port: u16) {
        let socket = WSASocketW(
            AF_INET as i32,
            SOCK_STREAM,
            IPPROTO_TCP,
            null(),
            0,
            WSA_FLAG_OVERLAPPED,
        );
        assert_ne!(socket, INVALID_SOCKET);
        let mut local: SOCKADDR_IN = zeroed();
        local.sin_family = AF_INET;
        assert_eq!(
            bind(
                socket,
                (&local as *const SOCKADDR_IN).cast(),
                size_of::<SOCKADDR_IN>() as i32
            ),
            0
        );
        let mut function: LPFN_CONNECTEX = None;
        let mut returned = 0;
        assert_eq!(
            WSAIoctl(
                socket,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&WSAID_CONNECTEX as *const windows_sys::core::GUID).cast(),
                size_of::<windows_sys::core::GUID>() as u32,
                (&mut function as *mut LPFN_CONNECTEX).cast(),
                size_of::<LPFN_CONNECTEX>() as u32,
                &mut returned,
                null_mut(),
                None
            ),
            0
        );
        let mut target: SOCKADDR_IN = zeroed();
        target.sin_family = AF_INET;
        target.sin_port = port.to_be();
        target.sin_addr.S_un.S_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let event = CreateEventW(null(), 1, 0, null());
        assert!(!event.is_null());
        let mut overlapped: OVERLAPPED = zeroed();
        overlapped.hEvent = event;
        let payload = b"windows-hook-local-echo";
        let initial = mode == "connectex-data";
        let mut sent = 0;
        let result = function.unwrap()(
            socket,
            (&target as *const SOCKADDR_IN).cast(),
            size_of::<SOCKADDR_IN>() as i32,
            if initial {
                payload.as_ptr().cast()
            } else {
                null()
            },
            if initial { payload.len() as u32 } else { 0 },
            &mut sent,
            &mut overlapped,
        );
        let error = WSAGetLastError();
        if result == 0 && error == WSAEOPNOTSUPP && initial {
            println!("connectex=unsupported-initial-data");
        } else {
            if result == 0 {
                assert_eq!(error, WSA_IO_PENDING);
                assert_eq!(WaitForSingleObject(event, 10000), WAIT_OBJECT_0);
                let mut flags = 0;
                assert_ne!(
                    WSAGetOverlappedResult(socket, &overlapped, &mut sent, 0, &mut flags),
                    0
                );
            }
            assert_eq!(
                setsockopt(socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, null(), 0),
                0
            );
            exchange(socket, initial);
            println!("connectex=ok mode={mode}");
        }
        closesocket(socket);
        CloseHandle(event);
    }

    unsafe fn error_semantics(port: u16, denied_file: &str, expect_denied: bool) {
        use std::io::{Read, Write};
        use std::net::{Ipv4Addr, SocketAddr, TcpStream};

        let mut stream = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            std::time::Duration::from_secs(10),
        )
        .unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        stream.write_all(b"error-semantics-echo").unwrap();
        let mut reply = [0; 20];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"error-semantics-echo");
        drop(stream);

        let mut byte = 0;
        assert_eq!(recv(INVALID_SOCKET, &mut byte, 1, 0), SOCKET_ERROR);
        assert_eq!(WSAGetLastError(), WSAENOTSOCK);
        let mut nonblocking = 1;
        assert_eq!(
            ioctlsocket(INVALID_SOCKET, FIONBIO, &mut nonblocking),
            SOCKET_ERROR
        );
        assert_eq!(WSAGetLastError(), WSAENOTSOCK);

        let missing =
            std::path::Path::new(denied_file).with_file_name("hyperhub-missing-error-fixture.exe");
        assert!(!missing.exists(), "missing-file fixture must not exist");
        assert_eq!(
            std::fs::File::open(&missing).unwrap_err().raw_os_error(),
            Some(2)
        );
        assert_eq!(
            std::process::Command::new(&missing)
                .status()
                .unwrap_err()
                .raw_os_error(),
            Some(2)
        );
        match std::fs::File::open(denied_file) {
            Ok(_) => assert!(!expect_denied),
            Err(error) => {
                assert!(expect_denied);
                assert_eq!(error.raw_os_error(), Some(5));
            }
        }
        println!("error_semantics=ok connect_timeout=true invalid_socket=10038 missing_file=2 missing_process=2 denied={expect_denied}");
    }

    pub unsafe fn run() {
        super::diagnostics::install();
        let mut data: WSADATA = zeroed();
        assert_eq!(WSAStartup(0x202, &mut data), 0);
        let arguments: Vec<String> = std::env::args().collect();
        let mode = &arguments[1];
        let port = arguments[2].parse().unwrap();
        if mode == "fls-teardown" {
            super::fls_teardown::run(port, &arguments[3], arguments[4] == "deny");
        } else if mode == "error-semantics" {
            error_semantics(port, &arguments[3], arguments[4] == "deny");
        } else if mode == "dns-cancel-concurrent" {
            // Each thread reuses caller storage only after its own completion.
            // A barrier overlaps native entry, cancellation and callback exit;
            // it does not add synchronization inside the observed Hooks.
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
            std::thread::scope(|scope| {
                for thread in 0..4 {
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        for index in 0..64 {
                            barrier.wait();
                            let mode = ["dns-cancel", "dns-cancel-callback", "dns-cancel-poll"]
                                [(thread + index) % 3];
                            dns(mode, port);
                        }
                    });
                }
            });
        } else if mode.starts_with("dns-") {
            // Release Winsock immediately after repeated completed requests.
            for _ in 0..if mode.starts_with("dns-cancel") {
                64
            } else {
                1
            } {
                dns(mode, port);
            }
        } else {
            connect_ex(mode, port);
        }
        eprintln!("dns_cleanup stage=wsa_cleanup");
        assert_eq!(WSACleanup(), 0);
        eprintln!("dns_cleanup stage=done");
    }
}

#[cfg(windows)]
fn main() {
    unsafe { probe::run() }
}
