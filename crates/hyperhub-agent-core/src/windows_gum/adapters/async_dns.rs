//! Keep the native overlapped request and completion mechanisms intact. Record
//! actual addresses before handing callback/results back to the application.
use super::network::{socket_target_from_sockaddr, wide_string, GetAddrInfoExWFn};
use crate::windows_gum::gum::{original, HookGuard, INSIDE_HOOK};
use crate::windows_gum::shared::*;
use windows_sys::Win32::Networking::WinSock::{WSAENOBUFS, WSA_IO_INCOMPLETE, WSA_IO_PENDING};

#[derive(Clone)]
struct Pending {
    hostname: String,
    result: usize,
    callback: LPLOOKUPSERVICE_COMPLETION_ROUTINE,
}

fn pending() -> &'static Mutex<HashMap<usize, Pending>> {
    static REQUESTS: OnceLock<Mutex<HashMap<usize, Pending>>> = OnceLock::new();
    REQUESTS.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe fn record(request: &Pending, status: i32) {
    if status != 0 || request.result == 0 {
        return;
    }
    let Ok(hostname) = CString::new(request.hostname.as_str()) else {
        return;
    };
    let mut address = *(request.result as *const *mut ADDRINFOEXW);
    while let Some(value) = address.as_ref() {
        let (family, target) = socket_target_from_sockaddr(value.ai_addr, value.ai_addrlen as i32);
        if let (Some(family), Some(target)) = (family, target) {
            let bytes = match target.ip {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let family = if family == AF_INET6 as i32 { 6 } else { 4 };
            let _ = hh_agent_record_dns(hostname.as_ptr(), family, bytes.as_ptr(), bytes.len());
        }
        address = value.ai_next;
    }
}

unsafe extern "system" fn completion(status: u32, bytes: u32, overlapped: *const OVERLAPPED) {
    let request = pending()
        .lock()
        .ok()
        .and_then(|mut requests| requests.remove(&(overlapped as usize)));
    if let Some(request) = request {
        record(&request, status as i32);
        if let Some(callback) = request.callback {
            // A synchronous native completion may run inside the original Hook.
            // User code must still receive the ordinary instrumented environment.
            let inside = INSIDE_HOOK.with(|value| value.replace(false));
            callback(status, bytes, overlapped);
            INSIDE_HOOK.with(|value| value.set(inside));
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn resolve(
    original: GetAddrInfoExWFn,
    node: *const u16,
    service: *const u16,
    namespace: u32,
    namespace_id: *const GUID,
    hints: *const ADDRINFOEXW,
    result: *mut *mut ADDRINFOEXW,
    timeout: *const TIMEVAL,
    overlapped: *const OVERLAPPED,
    callback: LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    handle: *mut HANDLE,
) -> i32 {
    if node.is_null() || result.is_null() || overlapped.is_null() || INSIDE_HOOK.with(Cell::get) {
        return original(
            node,
            service,
            namespace,
            namespace_id,
            hints,
            result,
            timeout,
            overlapped,
            callback,
            handle,
        );
    }
    let Some(_guard) = HookGuard::enter() else {
        return original(
            node,
            service,
            namespace,
            namespace_id,
            hints,
            result,
            timeout,
            overlapped,
            callback,
            handle,
        );
    };
    let request = Pending {
        hostname: wide_string(node),
        result: result as usize,
        callback,
    };
    if request.hostname.parse::<IpAddr>().is_ok() {
        return original(
            node,
            service,
            namespace,
            namespace_id,
            hints,
            result,
            timeout,
            overlapped,
            callback,
            handle,
        );
    }
    // Asynchronous native resolution must retain the same DNS policy boundary
    // as getaddrinfo and synchronous GetAddrInfoExW before emitting a query.
    let mut context = DnsContext {
        hostname: request.hostname.clone(),
        family: hints
            .as_ref()
            .map_or(AF_UNSPEC as i32, |value| value.ai_family),
        replacement: None,
        denied_error: None,
    };
    runtime().dns.dispatch(&mut context, |_| (), |_, _, _| ());
    if let Some(error) = context.denied_error {
        return error;
    }
    if context.replacement.is_none() {
        return WSATRY_AGAIN;
    }
    {
        let Ok(mut requests) = pending().lock() else {
            return WSAENOBUFS;
        };
        // Never overwrite a still-owned completion identity or grow without bound.
        if requests.len() >= 4096 || requests.contains_key(&(overlapped as usize)) {
            return WSAENOBUFS;
        }
        requests.insert(overlapped as usize, request.clone());
    }
    let status = original(
        node,
        service,
        namespace,
        namespace_id,
        hints,
        result,
        timeout,
        overlapped,
        callback.map(|_| completion as unsafe extern "system" fn(_, _, _)),
        handle,
    );
    if let Ok(mut requests) = pending().lock() {
        // An inline callback can already have handed the result to user code,
        // including freeing it. Only inspect a result we still own, under the
        // same lock used to transfer ownership to the completion trampoline.
        if status == 0 {
            if let Some(request) = requests.get(&(overlapped as usize)) {
                record(request, status);
            }
        }
        // Native contract: completion is delivered only for WSA_IO_PENDING.
        // Immediate success/failure remains the caller's synchronous result.
        if status != WSA_IO_PENDING {
            requests.remove(&(overlapped as usize));
        }
    }
    status
}

type ResultFn = unsafe extern "system" fn(*const OVERLAPPED) -> i32;
pub(in crate::windows_gum) static ORIGINAL_GETADDRINFOEX_RESULT: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());

pub(in crate::windows_gum) unsafe extern "system" fn hook_getaddrinfo_ex_result(
    overlapped: *const OVERLAPPED,
) -> i32 {
    let Some(original) = original!(ORIGINAL_GETADDRINFOEX_RESULT, ResultFn) else {
        return WSATRY_AGAIN;
    };
    let status = original(overlapped);
    if status != WSA_IO_PENDING && status != WSA_IO_INCOMPLETE {
        let request = pending().lock().ok().and_then(|mut requests| {
            // Callback requests are released by their native callback, including cancellation.
            if requests
                .get(&(overlapped as usize))
                .is_some_and(|value| value.callback.is_none())
            {
                requests.remove(&(overlapped as usize))
            } else {
                None
            }
        });
        if let Some(request) = request {
            record(&request, status);
        }
    }
    status
}
