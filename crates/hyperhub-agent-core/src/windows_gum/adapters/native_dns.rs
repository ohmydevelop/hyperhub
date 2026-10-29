//! Stack-scoped original DNS query context. The private prefetch reuses the
//! caller's real resolver, hints, namespace and timeout before publishing an
//! issued alias. A numeric publication query does not replace those semantics.
use super::network::*;
use crate::windows_gum::shared::*;
use std::cell::Cell;
#[derive(Clone, Copy)]
pub(in crate::windows_gum) enum NativeQuery {
    A {
        call: GetAddrInfoFn,
        entry_error: u32,
        node: *const c_char,
        service: *const c_char,
        hints: *const ADDRINFOA,
    },
    W {
        call: GetAddrInfoWFn,
        entry_error: u32,
        node: *const u16,
        service: *const u16,
        hints: *const ADDRINFOW,
    },
    ExA {
        call: GetAddrInfoExAFn,
        entry_error: u32,
        node: *const u8,
        service: *const u8,
        namespace: u32,
        namespace_id: *const GUID,
        hints: *const ADDRINFOEXA,
        timeout: *const TIMEVAL,
        name_handle: *mut HANDLE,
    },
    ExW {
        call: GetAddrInfoExWFn,
        entry_error: u32,
        node: *const u16,
        service: *const u16,
        namespace: u32,
        namespace_id: *const GUID,
        hints: *const ADDRINFOEXW,
        timeout: *const TIMEVAL,
        name_handle: *mut HANDLE,
    },
}
pub(in crate::windows_gum) fn call_original<T>(entry_error: u32, call: impl FnOnce() -> T) -> T {
    unsafe {
        windows_sys::Win32::Foundation::SetLastError(entry_error);
    }
    call()
}
thread_local! {static QUERY:Cell<Option<NativeQuery>>=const{Cell::new(None)};static OUTCOME:Cell<Option<u32>>=const{Cell::new(None)};}
struct QueryGuard(Option<NativeQuery>, Option<u32>);
impl Drop for QueryGuard {
    fn drop(&mut self) {
        QUERY.with(|slot| slot.set(self.0));
        OUTCOME.with(|slot| slot.set(self.1));
    }
}
pub(in crate::windows_gum) fn with_query<T>(
    query: NativeQuery,
    call: impl FnOnce() -> T,
) -> (T, Option<u32>) {
    let _guard = QueryGuard(
        QUERY.with(|slot| slot.replace(Some(query))),
        OUTCOME.with(|slot| slot.replace(None)),
    );
    let value = call();
    (value, OUTCOME.with(Cell::get))
}
unsafe fn address(pointer: *const SOCKADDR, length: usize) -> Option<crate::NativeDnsAddress> {
    let (copy, length) = copy_sockaddr(pointer, i32::try_from(length).ok()?)?;
    let pointer = (&copy as *const SOCKADDR_STORAGE).cast::<SOCKADDR>();
    let length = length as usize;
    let (_, target) = socket_target_from_sockaddr(pointer, length as i32);
    let target = target?;
    let (scope_id, flowinfo) = if target.ip.is_ipv6() && length >= 28 {
        let bytes = std::slice::from_raw_parts(pointer.cast::<u8>(), length);
        (
            u32::from_ne_bytes(bytes[24..28].try_into().ok()?),
            u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
        )
    } else {
        (0, 0)
    };
    Some(crate::NativeDnsAddress {
        ip: target.ip,
        scope_id,
        flowinfo,
    })
}
macro_rules! collect {
    ($root:expr,$free:path) => {{
        OUTCOME.with(|slot| slot.set(Some(windows_sys::Win32::Foundation::GetLastError())));
        let root = $root;
        let mut cursor = root;
        let mut addresses = Vec::new();
        while let Some(value) = cursor.as_ref() {
            if let Some(address) = address(value.ai_addr, value.ai_addrlen as usize) {
                addresses.push(address);
            }
            cursor = value.ai_next;
        }
        if !root.is_null() {
            $free(root);
        }
        Ok(addresses)
    }};
}
pub(in crate::windows_gum) fn resolve_current() -> Option<Result<Vec<crate::NativeDnsAddress>, i32>>
{
    let query = QUERY.with(Cell::get)?;
    Some(unsafe {
        match query {
            NativeQuery::A {
                call,
                entry_error,
                node,
                service,
                hints,
            } => {
                windows_sys::Win32::Foundation::SetLastError(entry_error);
                let mut result = null_mut();
                let status = call(node, service, hints, &mut result);
                if status != 0 {
                    OUTCOME.with(|slot| {
                        slot.set(Some(windows_sys::Win32::Foundation::GetLastError()))
                    });
                    Err(status)
                } else {
                    collect!(
                        result,
                        windows_sys::Win32::Networking::WinSock::freeaddrinfo
                    )
                }
            }
            NativeQuery::W {
                call,
                entry_error,
                node,
                service,
                hints,
            } => {
                windows_sys::Win32::Foundation::SetLastError(entry_error);
                let mut result = null_mut();
                let status = call(node, service, hints, &mut result);
                if status != 0 {
                    OUTCOME.with(|slot| {
                        slot.set(Some(windows_sys::Win32::Foundation::GetLastError()))
                    });
                    Err(status)
                } else {
                    collect!(
                        result,
                        windows_sys::Win32::Networking::WinSock::FreeAddrInfoW
                    )
                }
            }
            NativeQuery::ExA {
                call,
                entry_error,
                node,
                service,
                namespace,
                namespace_id,
                hints,
                timeout,
                name_handle,
            } => {
                windows_sys::Win32::Foundation::SetLastError(entry_error);
                let mut result = null_mut();
                let status = call(
                    node,
                    service,
                    namespace,
                    namespace_id,
                    hints,
                    &mut result,
                    timeout,
                    null(),
                    None,
                    name_handle,
                );
                if status != 0 {
                    OUTCOME.with(|slot| {
                        slot.set(Some(windows_sys::Win32::Foundation::GetLastError()))
                    });
                    Err(status)
                } else {
                    collect!(
                        result,
                        windows_sys::Win32::Networking::WinSock::FreeAddrInfoEx
                    )
                }
            }
            NativeQuery::ExW {
                call,
                entry_error,
                node,
                service,
                namespace,
                namespace_id,
                hints,
                timeout,
                name_handle,
            } => {
                windows_sys::Win32::Foundation::SetLastError(entry_error);
                let mut result = null_mut();
                let status = call(
                    node,
                    service,
                    namespace,
                    namespace_id,
                    hints,
                    &mut result,
                    timeout,
                    null(),
                    None,
                    name_handle,
                );
                if status != 0 {
                    OUTCOME.with(|slot| {
                        slot.set(Some(windows_sys::Win32::Foundation::GetLastError()))
                    });
                    Err(status)
                } else {
                    collect!(
                        result,
                        windows_sys::Win32::Networking::WinSock::FreeAddrInfoExW
                    )
                }
            }
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "system" fn probe(
        node: *const u16,
        service: *const u16,
        hints: *const ADDRINFOW,
        result: *mut *mut ADDRINFOW,
    ) -> i32 {
        assert_eq!(windows_sys::Win32::Foundation::GetLastError(), 0x5a37);
        assert_eq!(node as usize, 0x1234);
        assert_eq!(service as usize, 0x5678);
        assert_eq!((*hints).ai_flags, 0x412);
        assert_eq!((*hints).ai_family, AF_INET6 as i32);
        assert_eq!((*hints).ai_socktype, 2);
        assert_eq!((*hints).ai_protocol, 17);
        *result = null_mut();
        CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }
    #[test]
    fn exact_original_hints_and_query_are_scoped_to_the_wrapper() {
        let mut hints = ADDRINFOW::default();
        hints.ai_flags = 0x412;
        hints.ai_family = AF_INET6 as i32;
        hints.ai_socktype = 2;
        hints.ai_protocol = 17;
        assert!(resolve_current().is_none());
        with_query(
            NativeQuery::W {
                call: probe,
                entry_error: 0x5a37,
                node: 0x1234usize as *const u16,
                service: 0x5678usize as *const u16,
                hints: &hints,
            },
            || assert!(resolve_current().unwrap().unwrap().is_empty()),
        );
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert!(resolve_current().is_none());
    }
}
