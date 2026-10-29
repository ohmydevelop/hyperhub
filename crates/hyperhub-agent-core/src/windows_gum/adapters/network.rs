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
pub(in crate::windows_gum) type GetAddrInfoExAFn = unsafe extern "system" fn(
    *const u8,
    *const u8,
    u32,
    *const GUID,
    *const ADDRINFOEXA,
    *mut *mut ADDRINFOEXA,
    *const TIMEVAL,
    *const OVERLAPPED,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    *mut HANDLE,
) -> i32;
pub(in crate::windows_gum) type GetAddrInfoExWFn = unsafe extern "system" fn(
    *const u16,
    *const u16,
    u32,
    *const GUID,
    *const ADDRINFOEXW,
    *mut *mut ADDRINFOEXW,
    *const TIMEVAL,
    *const OVERLAPPED,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    *mut HANDLE,
) -> i32;
pub(in crate::windows_gum) type DnsQueryAFn = unsafe extern "system" fn(
    *const u8,
    DNS_TYPE,
    DNS_QUERY_OPTIONS,
    *mut c_void,
    *mut *mut DNS_RECORDA,
    *mut *mut c_void,
) -> u32;
pub(in crate::windows_gum) type DnsQueryWFn = unsafe extern "system" fn(
    *const u16,
    DNS_TYPE,
    DNS_QUERY_OPTIONS,
    *mut c_void,
    *mut *mut DNS_RECORDA,
    *mut *mut c_void,
) -> u32;
pub(in crate::windows_gum) type DnsQueryExFn = unsafe extern "system" fn(
    *const DNS_QUERY_REQUEST,
    *mut DNS_QUERY_RESULT,
    *mut DNS_QUERY_CANCEL,
) -> i32;
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
pub(in crate::windows_gum) type SendToFn =
    unsafe extern "system" fn(SOCKET, *const u8, i32, i32, *const SOCKADDR, i32) -> i32;
pub(in crate::windows_gum) type RecvFromFn =
    unsafe extern "system" fn(SOCKET, *mut u8, i32, i32, *mut SOCKADDR, *mut i32) -> i32;
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
pub(in crate::windows_gum) type WsaSendToFn = unsafe extern "system" fn(
    SOCKET,
    *const WSABUF,
    u32,
    *mut u32,
    u32,
    *const SOCKADDR,
    i32,
    *mut OVERLAPPED,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;
pub(in crate::windows_gum) type WsaRecvFromFn = unsafe extern "system" fn(
    SOCKET,
    *const WSABUF,
    u32,
    *mut u32,
    *mut u32,
    *mut SOCKADDR,
    *mut i32,
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
pub(in crate::windows_gum) static ORIGINAL_GETADDRINFOEXA: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_GETADDRINFOEXW: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_DNSQUERY_A: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_DNSQUERY_UTF8: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_DNSQUERY_W: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_DNSQUERY_EX: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CONNECT: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_WSACONNECT: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_SEND: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_RECV: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_SENDTO: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_RECVFROM: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CLOSESOCKET: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_IOCTLSOCKET: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_WSASEND: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_WSARECV: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_WSASENDTO: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_WSARECVFROM: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CONNECTEX: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());

/// Call the target's original resolver once, at a synchronous DNS boundary.
/// It may legitimately return an externally managed fake/TUN address.
pub(crate) fn resolve_native_addresses(
    hostname: &str,
    family: u32,
) -> Result<Vec<crate::NativeDnsAddress>, i32> {
    let _error = crate::engine_call::WindowsLastErrorGuard::capture();
    crate::engine_call::background(|| unsafe {
        if let Some(answers) = super::native_dns::resolve_current() {
            return answers;
        }
        let original = original!(ORIGINAL_GETADDRINFOW, GetAddrInfoWFn)
            .or_else(|| {
                find_export("ws2_32.dll", "GetAddrInfoW")
                    .map(|value| std::mem::transmute::<*mut c_void, GetAddrInfoWFn>(value))
            })
            .ok_or(crate::HH_ERR_PROTOCOL)?;
        let name = hostname.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut hints = ADDRINFOW::default();
        hints.ai_family = if family == 6 {
            AF_INET6 as i32
        } else {
            AF_INET as i32
        };
        let mut result = null_mut();
        let status = original(name.as_ptr(), null(), &hints, &mut result);
        if status != 0 {
            return Err(status);
        }
        let mut answers = Vec::new();
        let mut cursor = result;
        while let Some(value) = cursor.as_ref() {
            let Some((copy, length)) = copy_sockaddr(value.ai_addr, value.ai_addrlen as i32) else {
                cursor = value.ai_next;
                continue;
            };
            let (_, target) =
                socket_target_from_sockaddr((&copy as *const SOCKADDR_STORAGE).cast(), length);
            if let Some(target) = target {
                let (scope_id, flowinfo) = if target.ip.is_ipv6() && value.ai_addrlen >= 28 {
                    let bytes = std::slice::from_raw_parts(
                        (&copy as *const SOCKADDR_STORAGE).cast::<u8>(),
                        length as usize,
                    );
                    (
                        u32::from_ne_bytes(bytes[24..28].try_into().unwrap()),
                        u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
                    )
                } else {
                    (0, 0)
                };
                let answer = crate::NativeDnsAddress {
                    ip: target.ip,
                    scope_id,
                    flowinfo,
                };
                answers.push(answer);
            }
            cursor = value.ai_next;
        }
        windows_sys::Win32::Networking::WinSock::FreeAddrInfoW(result);
        Ok(answers)
    })
}
unsafe fn record_address(hostname: &str, address: *const SOCKADDR, length: i32) -> i32 {
    let Some((copy, length)) = copy_sockaddr(address, length) else {
        return crate::HH_ERR_INVALID;
    };
    let (_, target) =
        socket_target_from_sockaddr((&copy as *const SOCKADDR_STORAGE).cast(), length);
    let Some(target) = target else {
        return HH_OK;
    };
    let Ok(name) = CString::new(hostname) else {
        return crate::HH_ERR_INVALID;
    };
    let bytes = match target.ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    hh_agent_record_dns(
        name.as_ptr(),
        if bytes.len() == 4 { 4 } else { 6 },
        bytes.as_ptr(),
        bytes.len(),
    )
}
macro_rules! record_addrinfo {
    ($name:ident,$ty:ty) => {
        unsafe fn $name(hostname: &str, mut result: *mut $ty) -> i32 {
            while let Some(value) = result.as_ref() {
                let status = record_address(hostname, value.ai_addr, value.ai_addrlen as i32);
                if status == crate::HH_ERR_ALIAS_CONFLICT {
                    return status;
                }
                result = value.ai_next;
            }
            HH_OK
        }
    };
}
record_addrinfo!(record_addrinfo_a, ADDRINFOA);
record_addrinfo!(record_addrinfo_w, ADDRINFOW);
record_addrinfo!(record_addrinfo_ex_w, ADDRINFOEXW);
record_addrinfo!(record_addrinfo_ex_a, ADDRINFOEXA);
fn allow_native_dns(hostname: &str) -> Result<(), i32> {
    if crate::engine_call::host_background() {
        return Ok(());
    }
    let mut context = DnsContext {
        hostname: hostname.into(),
        family: AF_UNSPEC as i32,
        synthesize: false,
        replacement: None,
        denied_error: None,
    };
    runtime().dns.dispatch(&mut context, |_| (), |_, _, _| ());
    context.denied_error.map_or(Ok(()), Err)
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const ADDRINFOA,
    result: *mut *mut ADDRINFOA,
) -> i32 {
    let entry_error = windows_sys::Win32::Foundation::GetLastError();
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_GETADDRINFO, GetAddrInfoFn) else {
        return WSATRY_AGAIN;
    };
    if node.is_null() || result.is_null() || INSIDE_HOOK.with(Cell::get) {
        return super::native_dns::call_original(entry_error, || {
            original(node, service, hints, result)
        });
    }
    hook_result(
        None,
        || super::native_dns::call_original(entry_error, || original(node, service, hints, result)),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
            };
            let Ok(hostname) = CStr::from_ptr(node).to_str() else {
                return super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
            };
            if hostname.parse::<IpAddr>().is_ok() {
                return super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
            }
            if hints
                .as_ref()
                .is_some_and(|hints| hints.ai_flags & AI_NUMERICHOST as i32 != 0)
            {
                return super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
            }
            let family = if hints.is_null() {
                AF_UNSPEC as i32
            } else {
                (*hints).ai_family
            };
            if !matches!(family, x if x == AF_UNSPEC as i32 || x == AF_INET as i32 || x == AF_INET6 as i32)
            {
                return super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
            }
            let mut context = DnsContext {
                hostname: hostname.to_owned(),
                family,
                synthesize: true,
                replacement: None,
                denied_error: None,
            };
            let (_, native_error) = super::native_dns::with_query(
                super::native_dns::NativeQuery::A {
                    call: original,
                    entry_error,
                    node,
                    service,
                    hints,
                },
                || runtime().dns.dispatch(&mut context, |_| (), |_, _, _| ()),
            );
            if let Some(error) = context.denied_error {
                return error;
            }
            let Some((fake, resolved_family)) = context.replacement else {
                if crate::attachment::enforcing() && context.synthesize {
                    return WSATRY_AGAIN;
                }
                let status = super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
                let _original_error = crate::engine_call::WindowsLastErrorGuard::capture();
                if status == 0
                    && record_addrinfo_a(hostname, *result) == crate::HH_ERR_ALIAS_CONFLICT
                {
                    windows_sys::Win32::Networking::WinSock::freeaddrinfo(*result);
                    *result = null_mut();
                    return WSATRY_AGAIN;
                }
                return status;
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
            let status = super::native_dns::call_original(entry_error, || {
                original(fake.as_ptr(), service, &numeric, result)
            });
            if status == 0 {
                if let Some(error) = native_error {
                    windows_sys::Win32::Foundation::SetLastError(error);
                }
            }
            status
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_getaddrinfo_w(
    node: *const u16,
    service: *const u16,
    hints: *const ADDRINFOW,
    result: *mut *mut ADDRINFOW,
) -> i32 {
    let entry_error = windows_sys::Win32::Foundation::GetLastError();
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_GETADDRINFOW, GetAddrInfoWFn) else {
        return WSATRY_AGAIN;
    };
    if node.is_null() || result.is_null() || INSIDE_HOOK.with(Cell::get) {
        return super::native_dns::call_original(entry_error, || {
            original(node, service, hints, result)
        });
    }
    hook_result(
        None,
        || super::native_dns::call_original(entry_error, || original(node, service, hints, result)),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
            };
            let hostname = wide_string(node);
            if hostname.is_empty() || hostname.parse::<IpAddr>().is_ok() {
                return super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
            }
            if hints
                .as_ref()
                .is_some_and(|hints| hints.ai_flags & AI_NUMERICHOST as i32 != 0)
            {
                return super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
            }
            let family = if hints.is_null() {
                AF_UNSPEC as i32
            } else {
                (*hints).ai_family
            };
            if !matches!(family, x if x == AF_UNSPEC as i32 || x == AF_INET as i32 || x == AF_INET6 as i32)
            {
                return super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
            }
            let mut context = DnsContext {
                hostname: hostname.clone(),
                family,
                synthesize: true,
                replacement: None,
                denied_error: None,
            };
            let (_, native_error) = super::native_dns::with_query(
                super::native_dns::NativeQuery::W {
                    call: original,
                    entry_error,
                    node,
                    service,
                    hints,
                },
                || runtime().dns.dispatch(&mut context, |_| (), |_, _, _| ()),
            );
            if let Some(error) = context.denied_error {
                return error;
            }
            let Some((fake, resolved_family)) = context.replacement else {
                if crate::attachment::enforcing() && context.synthesize {
                    return WSATRY_AGAIN;
                }
                let status = super::native_dns::call_original(entry_error, || {
                    original(node, service, hints, result)
                });
                let _original_error = crate::engine_call::WindowsLastErrorGuard::capture();
                if status == 0
                    && record_addrinfo_w(&hostname, *result) == crate::HH_ERR_ALIAS_CONFLICT
                {
                    windows_sys::Win32::Networking::WinSock::FreeAddrInfoW(*result);
                    *result = null_mut();
                    return WSATRY_AGAIN;
                }
                return status;
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
            let status = super::native_dns::call_original(entry_error, || {
                original(fake_wide.as_ptr(), service, &numeric, result)
            });
            if status == 0 {
                if let Some(error) = native_error {
                    windows_sys::Win32::Foundation::SetLastError(error);
                }
            }
            status
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_getaddrinfo_ex_a(
    node: *const u8,
    service: *const u8,
    namespace: u32,
    namespace_id: *const GUID,
    hints: *const ADDRINFOEXA,
    result: *mut *mut ADDRINFOEXA,
    timeout: *const TIMEVAL,
    overlapped: *const OVERLAPPED,
    completion: LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    name_handle: *mut HANDLE,
) -> i32 {
    let entry_error = windows_sys::Win32::Foundation::GetLastError();
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_GETADDRINFOEXA, GetAddrInfoExAFn) else {
        return WSATRY_AGAIN;
    };
    if node.is_null() || result.is_null() || INSIDE_HOOK.with(Cell::get) {
        return super::native_dns::call_original(entry_error, || {
            original(
                node,
                service,
                namespace,
                namespace_id,
                hints,
                result,
                timeout,
                overlapped,
                completion,
                name_handle,
            )
        });
    }
    hook_result(
        None,
        || {
            super::native_dns::call_original(entry_error, || {
                original(
                    node,
                    service,
                    namespace,
                    namespace_id,
                    hints,
                    result,
                    timeout,
                    overlapped,
                    completion,
                    name_handle,
                )
            })
        },
        || {
            let Some(_guard) = HookGuard::enter() else {
                return super::native_dns::call_original(entry_error, || {
                    original(
                        node,
                        service,
                        namespace,
                        namespace_id,
                        hints,
                        result,
                        timeout,
                        overlapped,
                        completion,
                        name_handle,
                    )
                });
            };
            let Ok(hostname) = CStr::from_ptr(node.cast()).to_str() else {
                return WSATRY_AGAIN;
            };
            if hostname.parse::<IpAddr>().is_ok() {
                return super::native_dns::call_original(entry_error, || {
                    original(
                        node,
                        service,
                        namespace,
                        namespace_id,
                        hints,
                        result,
                        timeout,
                        overlapped,
                        completion,
                        name_handle,
                    )
                });
            }
            if hints
                .as_ref()
                .is_some_and(|hints| hints.ai_flags & AI_NUMERICHOST as i32 != 0)
            {
                return super::native_dns::call_original(entry_error, || {
                    original(
                        node,
                        service,
                        namespace,
                        namespace_id,
                        hints,
                        result,
                        timeout,
                        overlapped,
                        completion,
                        name_handle,
                    )
                });
            }
            let family = hints
                .as_ref()
                .map_or(AF_UNSPEC as i32, |value| value.ai_family);
            let mut context = DnsContext {
                hostname: hostname.to_owned(),
                family,
                synthesize: overlapped.is_null()
                    && completion.is_none()
                    && matches!(namespace, 0 | 12),
                replacement: None,
                denied_error: None,
            };
            let (_, native_error) = super::native_dns::with_query(
                super::native_dns::NativeQuery::ExA {
                    call: original,
                    entry_error,
                    node,
                    service,
                    namespace,
                    namespace_id,
                    hints,
                    timeout,
                    name_handle,
                },
                || runtime().dns.dispatch(&mut context, |_| (), |_, _, _| ()),
            );
            if let Some(error) = context.denied_error {
                return error;
            }
            let Some((fake, resolved_family)) = context.replacement else {
                if crate::attachment::enforcing() && context.synthesize {
                    return WSATRY_AGAIN;
                }
                let status = super::native_dns::call_original(entry_error, || {
                    original(
                        node,
                        service,
                        namespace,
                        namespace_id,
                        hints,
                        result,
                        timeout,
                        overlapped,
                        completion,
                        name_handle,
                    )
                });
                let _original_error = crate::engine_call::WindowsLastErrorGuard::capture();
                if status == 0
                    && record_addrinfo_ex_a(hostname, *result) == crate::HH_ERR_ALIAS_CONFLICT
                {
                    windows_sys::Win32::Networking::WinSock::FreeAddrInfoEx(*result);
                    *result = null_mut();
                    return WSATRY_AGAIN;
                }
                return status;
            };
            let Ok(fake) = CString::new(fake) else {
                return WSATRY_AGAIN;
            };
            let mut numeric = hints.as_ref().copied().unwrap_or_default();
            numeric.ai_family = resolved_family;
            numeric.ai_flags |= AI_NUMERICHOST as i32;
            numeric.ai_flags &= !(AI_CANONNAME as i32);
            let status = super::native_dns::call_original(entry_error, || {
                original(
                    fake.as_ptr().cast(),
                    service,
                    namespace,
                    namespace_id,
                    &numeric,
                    result,
                    timeout,
                    overlapped,
                    completion,
                    name_handle,
                )
            });
            if status == 0 {
                if let Some(error) = native_error {
                    windows_sys::Win32::Foundation::SetLastError(error);
                }
            }
            status
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_getaddrinfo_ex_w(
    node: *const u16,
    service: *const u16,
    namespace: u32,
    namespace_id: *const GUID,
    hints: *const ADDRINFOEXW,
    result: *mut *mut ADDRINFOEXW,
    timeout: *const TIMEVAL,
    overlapped: *const OVERLAPPED,
    completion: LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    name_handle: *mut HANDLE,
) -> i32 {
    let entry_error = windows_sys::Win32::Foundation::GetLastError();
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_GETADDRINFOEXW, GetAddrInfoExWFn) else {
        return WSATRY_AGAIN;
    };
    if !overlapped.is_null() || completion.is_some() {
        return super::async_dns::resolve(
            original,
            node,
            service,
            namespace,
            namespace_id,
            hints,
            result,
            timeout,
            overlapped,
            completion,
            name_handle,
        );
    }
    if node.is_null() || result.is_null() || INSIDE_HOOK.with(Cell::get) {
        return super::native_dns::call_original(entry_error, || {
            original(
                node,
                service,
                namespace,
                namespace_id,
                hints,
                result,
                timeout,
                overlapped,
                completion,
                name_handle,
            )
        });
    }
    hook_result(
        None,
        || {
            super::native_dns::call_original(entry_error, || {
                original(
                    node,
                    service,
                    namespace,
                    namespace_id,
                    hints,
                    result,
                    timeout,
                    overlapped,
                    completion,
                    name_handle,
                )
            })
        },
        || {
            let Some(_guard) = HookGuard::enter() else {
                return WSATRY_AGAIN;
            };
            let hostname = wide_string(node);
            if hostname.is_empty() || hostname.parse::<IpAddr>().is_ok() {
                return super::native_dns::call_original(entry_error, || {
                    original(
                        node,
                        service,
                        namespace,
                        namespace_id,
                        hints,
                        result,
                        timeout,
                        overlapped,
                        completion,
                        name_handle,
                    )
                });
            }
            if hints
                .as_ref()
                .is_some_and(|hints| hints.ai_flags & AI_NUMERICHOST as i32 != 0)
            {
                return super::native_dns::call_original(entry_error, || {
                    original(
                        node,
                        service,
                        namespace,
                        namespace_id,
                        hints,
                        result,
                        timeout,
                        overlapped,
                        completion,
                        name_handle,
                    )
                });
            }
            let family = hints
                .as_ref()
                .map_or(AF_UNSPEC as i32, |value| value.ai_family);
            let mut context = DnsContext {
                hostname: hostname.clone(),
                family,
                synthesize: matches!(namespace, 0 | 12),
                replacement: None,
                denied_error: None,
            };
            let (_, native_error) = super::native_dns::with_query(
                super::native_dns::NativeQuery::ExW {
                    call: original,
                    entry_error,
                    node,
                    service,
                    namespace,
                    namespace_id,
                    hints,
                    timeout,
                    name_handle,
                },
                || runtime().dns.dispatch(&mut context, |_| (), |_, _, _| ()),
            );
            if let Some(error) = context.denied_error {
                return error;
            }
            let Some((fake, resolved_family)) = context.replacement else {
                if crate::attachment::enforcing() && context.synthesize {
                    return WSATRY_AGAIN;
                }
                let status = super::native_dns::call_original(entry_error, || {
                    original(
                        node,
                        service,
                        namespace,
                        namespace_id,
                        hints,
                        result,
                        timeout,
                        overlapped,
                        completion,
                        name_handle,
                    )
                });
                let _original_error = crate::engine_call::WindowsLastErrorGuard::capture();
                if status == 0
                    && record_addrinfo_ex_w(&hostname, *result) == crate::HH_ERR_ALIAS_CONFLICT
                {
                    windows_sys::Win32::Networking::WinSock::FreeAddrInfoExW(*result);
                    *result = null_mut();
                    return WSATRY_AGAIN;
                }
                return status;
            };
            let mut fake_wide = fake.encode_utf16().collect::<Vec<_>>();
            fake_wide.push(0);
            let mut numeric = hints.as_ref().copied().unwrap_or_default();
            numeric.ai_family = resolved_family;
            numeric.ai_flags |= AI_NUMERICHOST as i32;
            numeric.ai_flags &= !(AI_CANONNAME as i32);
            let status = super::native_dns::call_original(entry_error, || {
                original(
                    fake_wide.as_ptr(),
                    service,
                    namespace,
                    namespace_id,
                    &numeric,
                    result,
                    timeout,
                    overlapped,
                    completion,
                    name_handle,
                )
            });
            if status == 0 {
                if let Some(error) = native_error {
                    windows_sys::Win32::Foundation::SetLastError(error);
                }
            }
            status
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

unsafe fn record_dns_query_results(hostname: &str, mut record: *mut DNS_RECORDA) -> i32 {
    if crate::engine_call::host_background() {
        return HH_OK;
    }
    let Ok(hostname) = CString::new(hostname) else {
        return crate::HH_ERR_INVALID;
    };
    while let Some(current) = record.as_ref() {
        match current.wType {
            DNS_TYPE_A => {
                let address = current.Data.A.IpAddress.to_ne_bytes();
                if hh_agent_record_dns(hostname.as_ptr(), 4, address.as_ptr(), address.len())
                    == crate::HH_ERR_ALIAS_CONFLICT
                {
                    return crate::HH_ERR_ALIAS_CONFLICT;
                }
            }
            DNS_TYPE_AAAA => {
                let address = current.Data.AAAA.Ip6Address.IP6Byte;
                if hh_agent_record_dns(hostname.as_ptr(), 6, address.as_ptr(), address.len())
                    == crate::HH_ERR_ALIAS_CONFLICT
                {
                    return crate::HH_ERR_ALIAS_CONFLICT;
                }
            }
            _ => {}
        }
        record = current.pNext;
    }
    HH_OK
}
unsafe fn reject_dns_records(results: *mut *mut DNS_RECORDA) {
    if !results.is_null() && !(*results).is_null() {
        windows_sys::Win32::NetworkManagement::Dns::DnsFree(
            (*results).cast(),
            windows_sys::Win32::NetworkManagement::Dns::DnsFreeRecordList,
        );
        *results = null_mut();
    }
}

unsafe fn dns_query_a_impl(
    original: DnsQueryAFn,
    name: *const u8,
    query_type: DNS_TYPE,
    options: DNS_QUERY_OPTIONS,
    extra: *mut c_void,
    results: *mut *mut DNS_RECORDA,
    reserved: *mut *mut c_void,
) -> u32 {
    let entry_error = windows_sys::Win32::Foundation::GetLastError();
    if !name.is_null() {
        if let Ok(hostname) = CStr::from_ptr(name.cast()).to_str() {
            if let Err(error) = allow_native_dns(hostname) {
                return error as u32;
            }
        }
    }
    let status = super::native_dns::call_original(entry_error, || {
        original(name, query_type, options, extra, results, reserved)
    });
    let _original_error = crate::engine_call::WindowsLastErrorGuard::capture();
    if status == 0 && !name.is_null() && !results.is_null() {
        if let Ok(hostname) = CStr::from_ptr(name.cast()).to_str() {
            if record_dns_query_results(hostname, *results) == crate::HH_ERR_ALIAS_CONFLICT {
                reject_dns_records(results);
                return WSATRY_AGAIN as u32;
            }
        }
    }
    status
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_dns_query_a(
    name: *const u8,
    query_type: DNS_TYPE,
    options: DNS_QUERY_OPTIONS,
    extra: *mut c_void,
    results: *mut *mut DNS_RECORDA,
    reserved: *mut *mut c_void,
) -> u32 {
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_DNSQUERY_A, DnsQueryAFn) else {
        return WSATRY_AGAIN as u32;
    };
    dns_query_a_impl(
        original, name, query_type, options, extra, results, reserved,
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_dns_query_utf8(
    name: *const u8,
    query_type: DNS_TYPE,
    options: DNS_QUERY_OPTIONS,
    extra: *mut c_void,
    results: *mut *mut DNS_RECORDA,
    reserved: *mut *mut c_void,
) -> u32 {
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_DNSQUERY_UTF8, DnsQueryAFn) else {
        return WSATRY_AGAIN as u32;
    };
    dns_query_a_impl(
        original, name, query_type, options, extra, results, reserved,
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_dns_query_w(
    name: *const u16,
    query_type: DNS_TYPE,
    options: DNS_QUERY_OPTIONS,
    extra: *mut c_void,
    results: *mut *mut DNS_RECORDA,
    reserved: *mut *mut c_void,
) -> u32 {
    let entry_error = windows_sys::Win32::Foundation::GetLastError();
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_DNSQUERY_W, DnsQueryWFn) else {
        return WSATRY_AGAIN as u32;
    };
    if !name.is_null() {
        if let Err(error) = allow_native_dns(&wide_string(name)) {
            return error as u32;
        }
    }
    let status = super::native_dns::call_original(entry_error, || {
        original(name, query_type, options, extra, results, reserved)
    });
    let _original_error = crate::engine_call::WindowsLastErrorGuard::capture();
    if status == 0 && !name.is_null() && !results.is_null() {
        if record_dns_query_results(&wide_string(name), *results) == crate::HH_ERR_ALIAS_CONFLICT {
            reject_dns_records(results);
            return WSATRY_AGAIN as u32;
        }
    }
    status
}

struct DnsQueryExContext {
    _attachment_pending: crate::attachment::CallGuard,
    engine: hyperhub_runtime::Lease,
    hostname: String,
    callback: PDNS_QUERY_COMPLETION_ROUTINE,
    callback_context: usize,
    callback_called: AtomicBool,
}

unsafe extern "system" fn dns_query_ex_completion(
    context: *const c_void,
    results: *mut DNS_QUERY_RESULT,
) {
    let _attachment_call = crate::attachment::enter();
    let original_error = crate::engine_call::WindowsLastErrorGuard::capture();
    let context = Arc::from_raw(context.cast::<DnsQueryExContext>());
    context.callback_called.store(true, Ordering::Release);
    if let Some(results) = results.as_mut() {
        let _guard = HookGuard::enter();
        let _engine = crate::engine_call::EngineCallGuard::with_lease(context.engine.clone());
        if results.QueryStatus == 0
            && record_dns_query_results(&context.hostname, results.pQueryRecords)
                == crate::HH_ERR_ALIAS_CONFLICT
        {
            reject_dns_records(&mut results.pQueryRecords);
            results.QueryStatus = WSATRY_AGAIN;
        }
    }
    drop(original_error);
    if let Some(callback) = context.callback {
        let inside = INSIDE_HOOK.with(|value| value.replace(false));
        callback(context.callback_context as *const c_void, results);
        INSIDE_HOOK.with(|value| value.set(inside));
    }
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_dns_query_ex(
    request: *const DNS_QUERY_REQUEST,
    results: *mut DNS_QUERY_RESULT,
    cancel: *mut DNS_QUERY_CANCEL,
) -> i32 {
    let entry_error = windows_sys::Win32::Foundation::GetLastError();
    let _attachment_call = crate::attachment::enter();
    const ERROR_IO_PENDING: i32 = 997;
    let Some(original) = original!(ORIGINAL_DNSQUERY_EX, DnsQueryExFn) else {
        return WSATRY_AGAIN;
    };
    let Some(request) = request.as_ref() else {
        return super::native_dns::call_original(entry_error, || {
            original(request, results, cancel)
        });
    };
    if request.QueryName.is_null()
        || INSIDE_HOOK.with(Cell::get)
        || crate::engine_call::host_background()
    {
        return super::native_dns::call_original(entry_error, || {
            original(request, results, cancel)
        });
    }
    let Some(_guard) = HookGuard::enter() else {
        return super::native_dns::call_original(entry_error, || {
            original(request, results, cancel)
        });
    };
    let Some(engine) = crate::state()
        .lock()
        .ok()
        .and_then(|core| crate::engine_call::calling(&core.engine).ok())
    else {
        return windows_sys::Win32::Networking::WinSock::WSAENOBUFS;
    };
    let hostname = wide_string(request.QueryName);
    if let Err(error) = allow_native_dns(&hostname) {
        return error;
    }
    let context = Arc::new(DnsQueryExContext {
        _attachment_pending: crate::attachment::enter(),
        engine,
        hostname: hostname.clone(),
        callback: request.pQueryCompletionCallback,
        callback_context: request.pQueryContext as usize,
        callback_called: AtomicBool::new(false),
    });
    let callback_context = Arc::into_raw(context.clone());
    let mut request_v1 = *request;
    request_v1.pQueryCompletionCallback = Some(dns_query_ex_completion);
    request_v1.pQueryContext = callback_context.cast_mut().cast();
    let mut status = if request.Version >= 3 {
        let mut request_v3 = *((request as *const DNS_QUERY_REQUEST).cast::<DNS_QUERY_REQUEST3>());
        request_v3.pQueryCompletionCallback = Some(dns_query_ex_completion);
        request_v3.pQueryContext = callback_context.cast_mut().cast();
        super::native_dns::call_original(entry_error, || {
            original(
                (&request_v3 as *const DNS_QUERY_REQUEST3).cast(),
                results,
                cancel,
            )
        })
    } else {
        super::native_dns::call_original(entry_error, || original(&request_v1, results, cancel))
    };
    let _original_error = crate::engine_call::WindowsLastErrorGuard::capture();
    if status != ERROR_IO_PENDING {
        if !context.callback_called.load(Ordering::Acquire) {
            drop(Arc::from_raw(callback_context));
        }
        if let Some(results) = results
            .as_mut()
            .filter(|_| !context.callback_called.load(Ordering::Acquire))
        {
            if status == 0
                && record_dns_query_results(&hostname, results.pQueryRecords)
                    == crate::HH_ERR_ALIAS_CONFLICT
            {
                reject_dns_records(&mut results.pQueryRecords);
                results.QueryStatus = WSATRY_AGAIN;
                status = WSATRY_AGAIN;
            }
        }
    }
    status
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_connect(
    socket: SOCKET,
    name: *const SOCKADDR,
    length: i32,
) -> i32 {
    let _attachment_call = crate::attachment::enter();
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
            let Some((copy, copied_length)) = copy_sockaddr(name, length) else {
                return original(socket, name, length);
            };
            let (family, target) = socket_target_from_sockaddr(
                (&copy as *const SOCKADDR_STORAGE).cast(),
                copied_length,
            );
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
    let _attachment_call = crate::attachment::enter();
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
            let Some((copy, copied_length)) = copy_sockaddr(name, length) else {
                return original(socket, name, length, caller, callee, send_qos, recv_qos);
            };
            let (family, target) = socket_target_from_sockaddr(
                (&copy as *const SOCKADDR_STORAGE).cast(),
                copied_length,
            );
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
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_CONNECTEX, ConnectExFn) else {
        return 0;
    };
    if !INSIDE_HOOK.with(Cell::get) && !send_buffer.is_null() && send_length != 0 {
        WSASetLastError(windows_sys::Win32::Networking::WinSock::WSAEOPNOTSUPP);
        return 0;
    }
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
            let Some((copy, copied_length)) = copy_sockaddr(name, length) else {
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
            let (family, target) = socket_target_from_sockaddr(
                (&copy as *const SOCKADDR_STORAGE).cast(),
                copied_length,
            );
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

/// Copy only a validated native sockaddr width. Invalid or inaccessible caller
/// buffers are left to the original API, which chooses its own WSA error.
/// The SDK probe cannot replace the caller's error or dereference PROT_NONE.
pub(in crate::windows_gum) unsafe fn copy_sockaddr(
    requested: *const SOCKADDR,
    length: i32,
) -> Option<(SOCKADDR_STORAGE, i32)> {
    let _error = crate::engine_call::WindowsLastErrorGuard::capture();
    if requested.is_null() || length < 2 {
        return None;
    }
    let mut storage = SOCKADDR_STORAGE::default();
    let mut copied = 0usize;
    let process = windows_sys::Win32::System::Threading::GetCurrentProcess();
    if windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
        process,
        requested.cast(),
        (&mut storage as *mut SOCKADDR_STORAGE).cast(),
        2,
        &mut copied,
    ) == 0
        || copied != 2
    {
        return None;
    }
    let bytes = std::slice::from_raw_parts((&storage as *const SOCKADDR_STORAGE).cast::<u8>(), 2);
    let needed = match u16::from_ne_bytes([bytes[0], bytes[1]]) {
        AF_INET => 16,
        AF_INET6 => 28,
        _ => return None,
    };
    if length < needed {
        return None;
    }
    if windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
        process,
        requested.cast(),
        (&mut storage as *mut SOCKADDR_STORAGE).cast(),
        needed as usize,
        &mut copied,
    ) == 0
        || copied != needed as usize
    {
        return None;
    }
    Some((storage, needed))
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
    if !context.is_redirected() {
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
            output[4..8].copy_from_slice(&context.native_flow.to_ne_bytes());
            output[24..28].copy_from_slice(&context.native_scope.to_ne_bytes());
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
    let _attachment_call = crate::attachment::enter();
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
    let _attachment_call = crate::attachment::enter();
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

pub(in crate::windows_gum) unsafe extern "system" fn hook_sendto(
    socket: SOCKET,
    buffer: *const u8,
    length: i32,
    flags: i32,
    address: *const SOCKADDR,
    address_length: i32,
) -> i32 {
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_SENDTO, SendToFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(socket, buffer, length, flags, address, address_length);
    }
    hook_result(
        Some(socket),
        || original(socket, buffer, length, flags, address, address_length),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(socket, buffer, length, flags, address, address_length);
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
                        original(socket, buffer, length, flags, address, address_length)
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

pub(in crate::windows_gum) unsafe extern "system" fn hook_recvfrom(
    socket: SOCKET,
    buffer: *mut u8,
    length: i32,
    flags: i32,
    address: *mut SOCKADDR,
    address_length: *mut i32,
) -> i32 {
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_RECVFROM, RecvFromFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(socket, buffer, length, flags, address, address_length);
    }
    hook_result(
        Some(socket),
        || original(socket, buffer, length, flags, address, address_length),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(socket, buffer, length, flags, address, address_length);
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
                        original(socket, buffer, length, flags, address, address_length)
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

pub(in crate::windows_gum) unsafe extern "system" fn hook_wsa_send(
    socket: SOCKET,
    buffers: *const WSABUF,
    count: u32,
    sent: *mut u32,
    flags: u32,
    overlapped: *mut OVERLAPPED,
    completion: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    let _attachment_call = crate::attachment::enter();
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
    let _attachment_call = crate::attachment::enter();
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

pub(in crate::windows_gum) unsafe extern "system" fn hook_wsa_sendto(
    socket: SOCKET,
    buffers: *const WSABUF,
    count: u32,
    sent: *mut u32,
    flags: u32,
    address: *const SOCKADDR,
    address_length: i32,
    overlapped: *mut OVERLAPPED,
    completion: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_WSASENDTO, WsaSendToFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(
            socket,
            buffers,
            count,
            sent,
            flags,
            address,
            address_length,
            overlapped,
            completion,
        );
    }
    hook_result(
        Some(socket),
        || {
            original(
                socket,
                buffers,
                count,
                sent,
                flags,
                address,
                address_length,
                overlapped,
                completion,
            )
        },
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(
                    socket,
                    buffers,
                    count,
                    sent,
                    flags,
                    address,
                    address_length,
                    overlapped,
                    completion,
                );
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
                        original(
                            socket,
                            buffers,
                            count,
                            sent,
                            flags,
                            address,
                            address_length,
                            overlapped,
                            completion,
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

pub(in crate::windows_gum) unsafe extern "system" fn hook_wsa_recvfrom(
    socket: SOCKET,
    buffers: *const WSABUF,
    count: u32,
    received: *mut u32,
    flags: *mut u32,
    address: *mut SOCKADDR,
    address_length: *mut i32,
    overlapped: *mut OVERLAPPED,
    completion: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    let _attachment_call = crate::attachment::enter();
    let Some(original) = original!(ORIGINAL_WSARECVFROM, WsaRecvFromFn) else {
        return SOCKET_ERROR;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(
            socket,
            buffers,
            count,
            received,
            flags,
            address,
            address_length,
            overlapped,
            completion,
        );
    }
    hook_result(
        Some(socket),
        || {
            original(
                socket,
                buffers,
                count,
                received,
                flags,
                address,
                address_length,
                overlapped,
                completion,
            )
        },
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(
                    socket,
                    buffers,
                    count,
                    received,
                    flags,
                    address,
                    address_length,
                    overlapped,
                    completion,
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
                            socket,
                            buffers,
                            count,
                            received,
                            flags,
                            address,
                            address_length,
                            overlapped,
                            completion,
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
            && hh_agent_validate_socket_handshake_reply(
                socket as u64,
                phase,
                reply.as_ptr(),
                reply.len(),
            ) == HH_OK;
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
    let ok = hh_agent_validate_socket_handshake_reply(
        socket as u64,
        phase,
        validation.as_ptr(),
        validation.len(),
    ) == HH_OK;

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
    let _attachment_call = crate::attachment::enter();
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
    let _attachment_call = crate::attachment::enter();
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
