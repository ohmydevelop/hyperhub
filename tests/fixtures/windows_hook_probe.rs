#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
mod probe {
    use std::mem::{size_of, zeroed};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::Networking::WinSock::*;
    use windows_sys::Win32::System::Threading::{CreateEventW, SleepEx, WaitForSingleObject};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    static COMPLETED: AtomicBool = AtomicBool::new(false);
    static COMPLETION_STATUS: AtomicU32 = AtomicU32::new(u32::MAX);

    unsafe extern "system" fn completed(error: u32, _: u32, _: *const OVERLAPPED) {
        COMPLETION_STATUS.store(error, Ordering::Release);
        COMPLETED.store(true, Ordering::Release);
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
        let callback = mode == "dns-callback";
        let event = CreateEventW(null(), 1, 0, null());
        assert!(!event.is_null());
        let mut overlapped: OVERLAPPED = zeroed();
        if !callback {
            overlapped.hEvent = event;
        }
        let mut handle = null_mut();
        let status = GetAddrInfoExW(
            name.as_ptr(),
            service.as_ptr(),
            NS_DNS,
            null(),
            &hints,
            &mut result,
            null(),
            &overlapped,
            if callback { Some(completed) } else { None },
            &mut handle,
        );
        assert!(
            status == 0 || status == WSA_IO_PENDING,
            "resolve status={status}"
        );
        if mode == "dns-cancel" && status == WSA_IO_PENDING && !handle.is_null() {
            let cancel_status = GetAddrInfoExCancel(&handle);
            // Completion can win the cancellation race. Either terminal result is valid.
            println!("cancel_status={cancel_status}");
        }
        if status == WSA_IO_PENDING {
            if callback {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !COMPLETED.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    SleepEx(10, 1);
                }
                assert!(
                    COMPLETED.load(Ordering::Acquire),
                    "completion callback missing"
                );
                assert_eq!(COMPLETION_STATUS.load(Ordering::Acquire), 0);
            } else {
                assert_eq!(
                    WaitForSingleObject(event, 10000),
                    WAIT_OBJECT_0,
                    "completion event missing"
                );
            }
        }
        let terminal = GetAddrInfoExOverlappedResult(&overlapped);
        if mode == "dns-cancel" {
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
            FreeAddrInfoExW(result);
        }
        CloseHandle(event);
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

    pub unsafe fn run() {
        let mut data: WSADATA = zeroed();
        assert_eq!(WSAStartup(0x202, &mut data), 0);
        let arguments: Vec<String> = std::env::args().collect();
        let mode = &arguments[1];
        let port = arguments[2].parse().unwrap();
        if mode.starts_with("dns-") {
            dns(mode, port);
        } else {
            connect_ex(mode, port);
        }
        WSACleanup();
    }
}

#[cfg(windows)]
fn main() {
    unsafe { probe::run() }
}
