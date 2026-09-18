use crate::windows_gum::gum::{find_export, hook_result, original, HookGuard, INSIDE_HOOK};
use crate::windows_gum::shared::*;
pub(in crate::windows_gum) type GetAddrInfoFn = unsafe extern "system" fn(
    *const c_char,
    *const c_char,
    *const ADDRINFOA,
    *mut *mut ADDRINFOA,
) -> i32;
pub(in crate::windows_gum) type GetAddrInfoWFn =
    unsafe extern "system" fn(*const u16, *const u16, *const ADDRINFOW, *mut *mut ADDRINFOW) -> i32;
pub(in crate::windows_gum) type ConnectFn =
    unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;
pub(in crate::windows_gum) type WsaConnectFn = unsafe extern "system" fn(
    SOCKET,
    *const SOCKADDR,
    i32,
    *const WSABUF,
    *mut WSABUF,
    *const QOS,
    *const QOS,
) -> i32;
pub(in crate::windows_gum) type SendFn =
    unsafe extern "system" fn(SOCKET, *const u8, i32, i32) -> i32;
pub(in crate::windows_gum) type RecvFn =
    unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;
pub(in crate::windows_gum) type CloseSocketFn = unsafe extern "system" fn(SOCKET) -> i32;
pub(in crate::windows_gum) type IoctlSocketFn =
    unsafe extern "system" fn(SOCKET, i32, *mut u32) -> i32;
pub(in crate::windows_gum) type WsaSendFn = unsafe extern "system" fn(
    SOCKET,
    *const WSABUF,
    u32,
    *mut u32,
    u32,
    *mut OVERLAPPED,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;
pub(in crate::windows_gum) type WsaRecvFn = unsafe extern "system" fn(
    SOCKET,
    *const WSABUF,
    u32,
    *mut u32,
    *mut u32,
    *mut OVERLAPPED,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;
pub(in crate::windows_gum) type ConnectExFn = unsafe extern "system" fn(
    SOCKET,
    *const SOCKADDR,
    i32,
    *const c_void,
    u32,
    *mut u32,
    *mut OVERLAPPED,
) -> i32;
pub(in crate::windows_gum) static ORIGINAL_GETADDRINFO: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_GETADDRINFOW: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CONNECT: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_WSACONNECT: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_SEND: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_RECV: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CLOSESOCKET: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_IOCTLSOCKET: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_WSASEND: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_WSARECV: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CONNECTEX: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());

pub(in crate::windows_gum) unsafe extern "system" fn hook_getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const ADDRINFOA,
    result: *mut *mut ADDRINFOA,
) -> i32 {
    let Some(original) = original!(ORIGINAL_GETADDRINFO, GetAddrInfoFn) else {
        return WSATRY_AGAIN;
    };
    if node.is_null() || result.is_null() || INSIDE_HOOK.with(Cell::get) {
        return original(node, service, hints, result);
    }
    hook_result(
        None,
        || original(node, service, hints, result),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(node, service, hints, result);
            };
            let Ok(hostname) = CStr::from_ptr(node).to_str() else {
                return original(node, service, hints, result);
            };
            if hostname.parse::<IpAddr>().is_ok() {
                return original(node, service, hints, result);
            }
            let family = if hints.is_null() {
                AF_UNSPEC as i32
            } else {
                (*hints).ai_family
            };
            if !matches!(family, x if x == AF_UNSPEC as i32 || x == AF_INET as i32 || x == AF_INET6 as i32)
            {
                return original(node, service, hints, result);
            }
            let mut context = DnsContext {
                hostname: hostname.to_owned(),
                family,
                replacement: None,
                denied_error: None,
            };
            runtime().dns.dispatch(&mut context, |_| (), |_, _, _| ());
            if let Some(error) = context.denied_error {
                return error;
            }
            let Some((fake, resolved_family)) = context.replacement else {
                return WSATRY_AGAIN;
            };
            let Ok(fake) = CString::new(fake) else {
                return WSATRY_AGAIN;
            };
            let mut numeric = if hints.is_null() {
                ADDRINFOA::default()
            } else {
                *hints
            };
            numeric.ai_family = resolved_family;
            numeric.ai_flags |= AI_NUMERICHOST as i32;
            numeric.ai_flags &= !(AI_CANONNAME as i32);
            original(fake.as_ptr(), service, &numeric, result)
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_getaddrinfo_w(
    node: *const u16,
    service: *const u16,
    hints: *const ADDRINFOW,
    result: *mut *mut ADDRINFOW,
) -> i32 {
    let Some(original) = original!(ORIGINAL_GETADDRINFOW, GetAddrInfoWFn) else {
        return WSATRY_AGAIN;
    };
    if node.is_null() || result.is_null() || INSIDE_HOOK.with(Cell::get) {
        return original(node, service, hints, result);
    }
    hook_result(
        None,
        || original(node, service, hints, result),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(node, service, hints, result);
            };
            let hostname = wide_string(node);
            if hostname.is_empty() || hostname.parse::<IpAddr>().is_ok() {
                return original(node, service, hints, result);
            }
            let family = if hints.is_null() {
                AF_UNSPEC as i32
            } else {
                (*hints).ai_family
            };
            if !matches!(family, x if x == AF_UNSPEC as i32 || x == AF_INET as i32 || x == AF_INET6 as i32)
            {
                return original(node, service, hints, result);
            }
            let mut context = DnsContext {
                hostname,
                family,
                replacement: None,
                denied_error: None,
            };
            runtime().dns.dispatch(&mut context, |_| (), |_, _, _| ());
            if let Some(error) = context.denied_error {
                return error;
            }
            let Some((fake, resolved_family)) = context.replacement else {
                return WSATRY_AGAIN;
            };
            let mut fake_wide = fake.encode_utf16().collect::<Vec<_>>();
            fake_wide.push(0);
            let mut numeric = if hints.is_null() {
                ADDRINFOW::default()
            } else {
                *hints
            };
            numeric.ai_family = resolved_family;
            numeric.ai_flags |= AI_NUMERICHOST as i32;
            numeric.ai_flags &= !(AI_CANONNAME as i32);
            original(fake_wide.as_ptr(), service, &numeric, result)
        },
    )
}

pub(in crate::windows_gum) unsafe fn wide_string(value: *const u16) -> String {
    let mut length = 0;
    while *value.add(length) != 0 && length < 32_768 {
        length += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_connect(
    socket: SOCKET,
    name: *const SOCKADDR,
    length: i32,
) -> i32 {
    let Some(original) = original!(ORIGINAL_CONNECT, ConnectFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(socket, name, length);
    }
    hook_result(
        Some(socket),
        || original(socket, name, length),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(socket, name, length);
            };
            let (family, target) = socket_target_from_sockaddr(name, length);
            let mut context = ConnectContext::new(ConnectKind::Blocking, socket, family, target);
            let mut storage = SOCKADDR_STORAGE::default();
            let result = runtime().connect.dispatch(
                &mut context,
                |context| {
                    let (target, target_length) =
                        effective_sockaddr(context, name, length, &mut storage);
                    context.result = original(context.socket, target, target_length);
                    context.error = WSAGetLastError();
                    context.result
                },
                |context, _, _| {
                    WSASetLastError(context.denied_error.unwrap_or(WSAECONNRESET));
                    context.denied_result()
                },
            );
            finish_connect(&context, result)
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_wsa_connect(
    socket: SOCKET,
    name: *const SOCKADDR,
    length: i32,
    caller: *const WSABUF,
    callee: *mut WSABUF,
    send_qos: *const QOS,
    recv_qos: *const QOS,
) -> i32 {
    let Some(original) = original!(ORIGINAL_WSACONNECT, WsaConnectFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(socket, name, length, caller, callee, send_qos, recv_qos);
    }
    hook_result(
        Some(socket),
        || original(socket, name, length, caller, callee, send_qos, recv_qos),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(socket, name, length, caller, callee, send_qos, recv_qos);
            };
            let (family, target) = socket_target_from_sockaddr(name, length);
            let mut context = ConnectContext::new(ConnectKind::Blocking, socket, family, target);
            let mut storage = SOCKADDR_STORAGE::default();
            let result = runtime().connect.dispatch(
                &mut context,
                |context| {
                    let (target, target_length) =
                        effective_sockaddr(context, name, length, &mut storage);
                    context.result = original(
                        context.socket,
                        target,
                        target_length,
                        caller,
                        callee,
                        send_qos,
                        recv_qos,
                    );
                    context.error = WSAGetLastError();
                    context.result
                },
                |context, _, _| {
                    WSASetLastError(context.denied_error.unwrap_or(WSAECONNRESET));
                    context.denied_result()
                },
            );
            finish_connect(&context, result)
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_connect_ex(
    socket: SOCKET,
    name: *const SOCKADDR,
    length: i32,
    send_buffer: *const c_void,
    send_length: u32,
    bytes_sent: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> i32 {
    let Some(original) = original!(ORIGINAL_CONNECTEX, ConnectExFn) else {
        return 0;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(
            socket,
            name,
            length,
            send_buffer,
            send_length,
            bytes_sent,
            overlapped,
        );
    }
    hook_result(
        Some(socket),
        || {
            original(
                socket,
                name,
                length,
                send_buffer,
                send_length,
                bytes_sent,
                overlapped,
            )
        },
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(
                    socket,
                    name,
                    length,
                    send_buffer,
                    send_length,
                    bytes_sent,
                    overlapped,
                );
            };
            let (family, target) = socket_target_from_sockaddr(name, length);
            let mut context = ConnectContext::new(ConnectKind::Extended, socket, family, target);
            let mut storage = SOCKADDR_STORAGE::default();
            let result = runtime().connect.dispatch(
                &mut context,
                |context| {
                    let (target, target_length) =
                        effective_sockaddr(context, name, length, &mut storage);
                    context.result = original(
                        context.socket,
                        target,
                        target_length,
                        send_buffer,
                        send_length,
                        bytes_sent,
                        overlapped,
                    );
                    context.error = WSAGetLastError();
                    context.result
                },
                |context, _, _| {
                    WSASetLastError(context.denied_error.unwrap_or(WSAECONNRESET));
                    context.denied_result()
                },
            );
            if let Some(error) = context.denied_error {
                WSASetLastError(error);
            } else {
                WSASetLastError(context.error);
            }
            result
        },
    )
}

pub(in crate::windows_gum) unsafe fn socket_ready(
    socket: SOCKET,
    read: bool,
    timeout_ms: i32,
) -> bool {
    let Some(select) = find_export("ws2_32.dll", "select") else {
        return false;
    };
    let select: unsafe extern "system" fn(
        i32,
        *mut FD_SET,
        *mut FD_SET,
        *mut FD_SET,
        *const TIMEVAL,
    ) -> i32 = std::mem::transmute(select);
    let mut set = FD_SET {
        fd_count: 1,
        fd_array: [socket; 64],
    };
    let timeout = TIMEVAL {
        tv_sec: timeout_ms / 1000,
        tv_usec: (timeout_ms % 1000) * 1000,
    };
    let (readfds, writefds) = if read {
        (&mut set as *mut FD_SET, null_mut())
    } else {
        (null_mut(), &mut set as *mut FD_SET)
    };
    let result = select(0, readfds, writefds, null_mut(), &timeout);

    result > 0
}

pub(in crate::windows_gum) unsafe fn socket_target_from_sockaddr(
    requested: *const SOCKADDR,
    length: i32,
) -> (Option<i32>, Option<crate::FirewallConnectTarget>) {
    if requested.is_null() || length < 4 {
        return (None, None);
    }
    let bytes = std::slice::from_raw_parts(requested.cast::<u8>(), length as usize);
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    let (address, port) = if family == AF_INET as i32 && bytes.len() >= 16 {
        (&bytes[4..8], u16::from_be_bytes([bytes[2], bytes[3]]))
    } else if family == AF_INET6 as i32 && bytes.len() >= 28 {
        (&bytes[8..24], u16::from_be_bytes([bytes[2], bytes[3]]))
    } else {
        return (None, None);
    };
    (
        Some(family),
        crate::firewall_connect_target(family, address, port),
    )
}

unsafe fn effective_sockaddr(
    context: &ConnectContext,
    original: *const SOCKADDR,
    original_length: i32,
    storage: &mut SOCKADDR_STORAGE,
) -> (*const SOCKADDR, i32) {
    if !context.is_proxy_redirected() {
        return (original, original_length);
    }
    let Some(target) = context.destination() else {
        return (original, original_length);
    };
    let output = std::slice::from_raw_parts_mut(
        (storage as *mut SOCKADDR_STORAGE).cast::<u8>(),
        std::mem::size_of::<SOCKADDR_STORAGE>(),
    );
    output.fill(0);
    match (context.source_family(), target.ip) {
        (Some(family), IpAddr::V4(ip)) if family == AF_INET6 as i32 => {
            output[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            output[2..4].copy_from_slice(&target.port.to_be_bytes());
            output[18..20].copy_from_slice(&[0xff, 0xff]);
            output[20..24].copy_from_slice(&ip.octets());
            ((storage as *mut SOCKADDR_STORAGE).cast::<SOCKADDR>(), 28)
        }
        (_, IpAddr::V4(ip)) => {
            output[..2].copy_from_slice(&AF_INET.to_ne_bytes());
            output[2..4].copy_from_slice(&target.port.to_be_bytes());
            output[4..8].copy_from_slice(&ip.octets());
            ((storage as *mut SOCKADDR_STORAGE).cast::<SOCKADDR>(), 16)
        }
        (_, IpAddr::V6(ip)) => {
            output[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            output[2..4].copy_from_slice(&target.port.to_be_bytes());
            output[8..24].copy_from_slice(&ip.octets());
            ((storage as *mut SOCKADDR_STORAGE).cast::<SOCKADDR>(), 28)
        }
    }
}

unsafe fn finish_connect(context: &ConnectContext, result: i32) -> i32 {
    if let Some(error) = context.denied_error {
        WSASetLastError(error);
        return result;
    }
    if context.ensure_handshake_blocking {
        let connected = if result == SOCKET_ERROR && context.error == WSAEWOULDBLOCK {
            socket_ready(context.socket, false, 5000)
        } else {
            result != SOCKET_ERROR
        };
        if connected {
            ensure_handshake_blocking(context.socket);
        }
    }
    WSASetLastError(context.error);
    result
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_send(
    socket: SOCKET,
    buffer: *const u8,
    length: i32,
    flags: i32,
) -> i32 {
    let Some(original) = original!(ORIGINAL_SEND, SendFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(socket, buffer, length, flags);
    }
    hook_result(
        Some(socket),
        || original(socket, buffer, length, flags),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(socket, buffer, length, flags);
            };
            let mut context = SocketIoContext {
                socket,
                direction: SocketIoDirection::Send,
                ensure_gateway_handshake: false,
            };
            runtime().socket_io.dispatch(
                &mut context,
                |context| {
                    with_gateway_handshake(context, || original(socket, buffer, length, flags))
                },
                |_, _, _| {
                    WSASetLastError(WSAECONNRESET);
                    SOCKET_ERROR
                },
            )
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_recv(
    socket: SOCKET,
    buffer: *mut u8,
    length: i32,
    flags: i32,
) -> i32 {
    let Some(original) = original!(ORIGINAL_RECV, RecvFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(socket, buffer, length, flags);
    }
    hook_result(
        Some(socket),
        || original(socket, buffer, length, flags),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(socket, buffer, length, flags);
            };
            let mut context = SocketIoContext {
                socket,
                direction: SocketIoDirection::Receive,
                ensure_gateway_handshake: false,
            };
            runtime().socket_io.dispatch(
                &mut context,
                |context| {
                    with_gateway_handshake(context, || original(socket, buffer, length, flags))
                },
                |_, _, _| {
                    WSASetLastError(WSAECONNRESET);
                    SOCKET_ERROR
                },
            )
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_wsa_send(
    socket: SOCKET,
    buffers: *const WSABUF,
    count: u32,
    sent: *mut u32,
    flags: u32,
    overlapped: *mut OVERLAPPED,
    completion: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    let Some(original) = original!(ORIGINAL_WSASEND, WsaSendFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(socket, buffers, count, sent, flags, overlapped, completion);
    }
    hook_result(
        Some(socket),
        || original(socket, buffers, count, sent, flags, overlapped, completion),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(socket, buffers, count, sent, flags, overlapped, completion);
            };
            let mut context = SocketIoContext {
                socket,
                direction: SocketIoDirection::Send,
                ensure_gateway_handshake: false,
            };
            runtime().socket_io.dispatch(
                &mut context,
                |context| {
                    with_gateway_handshake(context, || {
                        original(socket, buffers, count, sent, flags, overlapped, completion)
                    })
                },
                |_, _, _| {
                    WSASetLastError(WSAECONNRESET);
                    SOCKET_ERROR
                },
            )
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_wsa_recv(
    socket: SOCKET,
    buffers: *const WSABUF,
    count: u32,
    received: *mut u32,
    flags: *mut u32,
    overlapped: *mut OVERLAPPED,
    completion: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    let Some(original) = original!(ORIGINAL_WSARECV, WsaRecvFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(
            socket, buffers, count, received, flags, overlapped, completion,
        );
    }
    hook_result(
        Some(socket),
        || {
            original(
                socket, buffers, count, received, flags, overlapped, completion,
            )
        },
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(
                    socket, buffers, count, received, flags, overlapped, completion,
                );
            };
            let mut context = SocketIoContext {
                socket,
                direction: SocketIoDirection::Receive,
                ensure_gateway_handshake: false,
            };
            runtime().socket_io.dispatch(
                &mut context,
                |context| {
                    with_gateway_handshake(context, || {
                        original(
                            socket, buffers, count, received, flags, overlapped, completion,
                        )
                    })
                },
                |_, _, _| {
                    WSASetLastError(WSAECONNRESET);
                    SOCKET_ERROR
                },
            )
        },
    )
}

unsafe fn with_gateway_handshake(context: &SocketIoContext, original: impl FnOnce() -> i32) -> i32 {
    if context.ensure_gateway_handshake && !ensure_handshake(context.socket) {
        WSASetLastError(WSAECONNRESET);
        SOCKET_ERROR
    } else {
        original()
    }
}

pub(in crate::windows_gum) unsafe fn ensure_handshake(socket: SOCKET) -> bool {
    let state = hh_agent_handshake_complete(socket as u64);

    if state == 1 || state < 0 {
        return true;
    }
    let was_nonblocking = hh_agent_socket_nonblocking(socket as u64) == 1;
    let ioctl = original!(ORIGINAL_IOCTLSOCKET, IoctlSocketFn);
    if was_nonblocking {
        let Some(ioctl) = ioctl else {
            return false;
        };
        let mut blocking = 0;
        if ioctl(socket, FIONBIO, &mut blocking) == SOCKET_ERROR {
            return false;
        }
    }
    let mut ok = true;
    for phase in 0..3 {
        if !exchange_phase(socket, phase) {
            ok = false;
            break;
        }
    }
    if was_nonblocking {
        let mut nonblocking = 1;
        if ioctl.expect("checked above")(socket, FIONBIO, &mut nonblocking) == SOCKET_ERROR {
            ok = false;
        }
    }

    ok && hh_agent_set_handshake_complete(socket as u64) == HH_OK
}

pub(in crate::windows_gum) unsafe fn ensure_handshake_blocking(socket: SOCKET) -> bool {
    let state = hh_agent_handshake_complete(socket as u64);

    if state == 1 || state < 0 {
        return true;
    }
    let mut ok = true;
    for phase in 0..3 {
        if !exchange_phase(socket, phase) {
            ok = false;
            break;
        }
    }

    ok && hh_agent_set_handshake_complete(socket as u64) == HH_OK
}

pub(in crate::windows_gum) unsafe fn exchange_phase(socket: SOCKET, phase: u32) -> bool {
    let mut request = [0_u8; 1024];
    let mut request_length = 0;
    if hh_agent_build_handshake(
        socket as u64,
        phase,
        request.as_mut_ptr(),
        request.len(),
        &mut request_length,
    ) != HH_OK
        || !send_all(socket, &request[..request_length])
    {
        return false;
    }
    if phase < 2 {
        let mut reply = [0_u8; 2];
        return recv_all(socket, &mut reply)
            && hh_agent_validate_handshake_reply(phase, reply.as_ptr(), reply.len()) == HH_OK;
    }
    let mut head = [0_u8; 4];
    if !recv_all(socket, &mut head) || head[0] != 5 || head[1] != 0 {
        return false;
    }
    let tail_length = match head[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut domain_length = [0_u8; 1];
            if !recv_all(socket, &mut domain_length) {
                return false;
            }
            domain_length[0] as usize + 2
        }
        _ => return false,
    };
    let mut tail = [0_u8; 258];
    if tail_length > tail.len() || !recv_all(socket, &mut tail[..tail_length]) {
        return false;
    }
    let validation = [head[0], head[1], head[2], head[3], 0];
    let ok =
        hh_agent_validate_handshake_reply(phase, validation.as_ptr(), validation.len()) == HH_OK;

    ok
}

pub(in crate::windows_gum) unsafe fn send_all(socket: SOCKET, mut data: &[u8]) -> bool {
    let Some(send) = original!(ORIGINAL_WSASEND, WsaSendFn) else {
        return false;
    };
    while !data.is_empty() {
        let mut buffer = WSABUF {
            len: data.len().min(u32::MAX as usize) as u32,
            buf: data.as_ptr() as *mut u8,
        };
        let mut sent = 0u32;
        let result = send(socket, &mut buffer, 1, &mut sent, 0, null_mut(), None);
        let errno = WSAGetLastError();
        if result == 0 && sent > 0 {
            data = &data[sent as usize..];
        } else if errno == WSAEWOULDBLOCK && socket_ready(socket, false, 5000) {
            continue;
        } else {
            return false;
        }
    }
    true
}

pub(in crate::windows_gum) unsafe fn recv_all(socket: SOCKET, mut data: &mut [u8]) -> bool {
    let Some(recv) = original!(ORIGINAL_WSARECV, WsaRecvFn) else {
        return false;
    };
    while !data.is_empty() {
        let mut buffer = WSABUF {
            len: data.len().min(u32::MAX as usize) as u32,
            buf: data.as_mut_ptr(),
        };
        let mut received = 0u32;
        let mut flags = 0u32;
        let result = recv(
            socket,
            &mut buffer,
            1,
            &mut received,
            &mut flags,
            null_mut(),
            None,
        );
        let errno = WSAGetLastError();
        if result == 0 && received > 0 {
            let (_, remaining) = data.split_at_mut(received as usize);
            data = remaining;
        } else if errno == WSAEWOULDBLOCK && socket_ready(socket, true, 5000) {
            continue;
        } else {
            return false;
        }
    }
    true
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_closesocket(socket: SOCKET) -> i32 {
    let Some(original) = original!(ORIGINAL_CLOSESOCKET, CloseSocketFn) else {
        return SOCKET_ERROR;
    };
    let mut context = SocketCloseContext {
        socket,
        result: SOCKET_ERROR,
    };
    runtime().socket_close.dispatch(
        &mut context,
        |context| {
            context.result = original(context.socket);
            context.result
        },
        |_, _, _| SOCKET_ERROR,
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_ioctlsocket(
    socket: SOCKET,
    command: i32,
    argument: *mut u32,
) -> i32 {
    let Some(original) = original!(ORIGINAL_IOCTLSOCKET, IoctlSocketFn) else {
        return SOCKET_ERROR;
    };
    let mut context = SocketModeContext {
        socket,
        command,
        argument,
        result: SOCKET_ERROR,
    };
    runtime().socket_mode.dispatch(
        &mut context,
        |context| {
            context.result = original(context.socket, context.command, context.argument);
            context.result
        },
        |_, _, _| SOCKET_ERROR,
    )
}
