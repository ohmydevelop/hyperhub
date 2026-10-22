//! Keep the native overlapped request and completion mechanisms intact. Record
//! actual addresses before handing callback/results back to the application.
use super::network::{socket_target_from_sockaddr, wide_string, GetAddrInfoExWFn};
use crate::windows_gum::gum::{HookGuard, INSIDE_HOOK};
use crate::windows_gum::shared::*;
use std::cell::UnsafeCell;
use std::sync::Arc;
use windows_sys::Win32::Networking::WinSock::{
    WSAEINPROGRESS, WSAEINVAL, WSAENOBUFS, WSA_IO_PENDING,
};
use windows_sys::Win32::System::Threading::SetEvent;

struct Pending {
    engine: hyperhub_runtime::Lease,
    hostname: String,
    result: usize,
    callback: LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    caller: usize,
    event: usize,
    shadow: Option<UnsafeCell<OVERLAPPED>>,
}

// Native code owns writes to shadow until completion. The callback (or immediate
// return path) reads it only after native completion, before notifying the caller.
unsafe impl Send for Pending {}
unsafe impl Sync for Pending {}

impl Pending {
    fn native_overlapped(&self) -> *const OVERLAPPED {
        self.shadow
            .as_ref()
            .map_or(self.caller as *const OVERLAPPED, |value| value.get())
    }

    unsafe fn publish_pending(&self) {
        if self.shadow.is_some() {
            // The async call returns WSA_IO_PENDING, but its status accessor
            // reports WSAEINPROGRESS until completion. Keep both contracts.
            (*(self.caller as *mut OVERLAPPED)).Internal = WSAEINPROGRESS as usize;
        }
    }

    unsafe fn publish_event(&self, status: Option<i32>, notify: bool) {
        if let Some(shadow) = &self.shadow {
            let mut value = std::ptr::read(shadow.get());
            if let Some(status) = status {
                value.Internal = status as usize;
            }
            value.hEvent = self.event as HANDLE;
            std::ptr::write(self.caller as *mut OVERLAPPED, value);
            // Publish addresses and status before releasing an event waiter.
            if notify {
                SetEvent(self.event as HANDLE);
            }
        }
    }
}

fn pending() -> &'static Mutex<HashMap<usize, Arc<Pending>>> {
    static REQUESTS: OnceLock<Mutex<HashMap<usize, Arc<Pending>>>> = OnceLock::new();
    REQUESTS.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe fn record(request: &Pending, status: i32) {
    if status != 0 || request.result == 0 {
        return;
    }
    let _guard = HookGuard::enter();
    let _engine = crate::engine_call::EngineCallGuard::with_lease(request.engine.clone());
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
        request.publish_event(Some(status as i32), true);
        if let Some(callback) = request.callback {
            // A synchronous native completion may run inside the original Hook.
            // User code must still receive the ordinary instrumented environment.
            let inside = INSIDE_HOOK.with(|value| value.replace(false));
            callback(status, bytes, request.caller as *const OVERLAPPED);
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
    // Windows requires either a callback with hEvent=NULL or a manual-reset
    // event without a callback. Reject invalid combinations without a query.
    let event = (*overlapped).hEvent;
    if callback.is_some() == !event.is_null() {
        return WSAEINVAL;
    }
    let shadow = if callback.is_none() {
        let mut value = std::ptr::read(overlapped);
        value.hEvent = null_mut();
        Some(UnsafeCell::new(value))
    } else {
        None
    };
    let Some(engine) = crate::state()
        .lock()
        .ok()
        .and_then(|core| crate::engine_call::calling(&core.engine).ok())
    else {
        return WSAENOBUFS;
    };
    let request = Arc::new(Pending {
        engine,
        hostname: wide_string(node),
        result: result as usize,
        callback,
        caller: overlapped as usize,
        event: event as usize,
        shadow,
    });
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
    let key = request.native_overlapped() as usize;
    {
        let Ok(mut requests) = pending().lock() else {
            return WSAENOBUFS;
        };
        // Never overwrite a still-owned completion identity or grow without bound.
        if requests.len() >= 4096
            || requests
                .values()
                .any(|value| value.caller == request.caller)
        {
            return WSAENOBUFS;
        }
        requests.insert(key, Arc::clone(&request));
    }
    request.publish_pending();
    let status = original(
        node,
        service,
        namespace,
        namespace_id,
        hints,
        result,
        timeout,
        request.native_overlapped(),
        Some(completion),
        handle,
    );
    if let Ok(mut requests) = pending().lock() {
        // An inline callback can already have handed the result to user code,
        // including freeing it. Only inspect a result we still own, under the
        // same lock used to transfer ownership to the completion trampoline.
        // Native contract: completion is delivered only for WSA_IO_PENDING.
        // Immediate success/failure remains the caller's synchronous result.
        if status != WSA_IO_PENDING
            && requests
                .get(&key)
                .is_some_and(|value| Arc::ptr_eq(value, &request))
        {
            record(&request, status);
            request.publish_event((status == 0).then_some(status), status == 0);
            requests.remove(&key);
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::Networking::WinSock::{GetAddrInfoExOverlappedResult, WSA_E_CANCELLED};
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    #[test]
    fn event_completion_publishes_native_status_and_preserves_event() {
        unsafe {
            for status in [0, WSA_E_CANCELLED] {
                let event = CreateEventW(null(), 1, 0, null());
                assert!(!event.is_null());
                let mut caller: OVERLAPPED = std::mem::zeroed();
                caller.hEvent = event;
                caller.Internal = WSA_IO_PENDING as usize;
                let request = Arc::new(Pending {
                    engine: hyperhub_engine::resident().acquire(),
                    hostname: "localhost".into(),
                    result: 0,
                    callback: None,
                    caller: (&mut caller as *mut OVERLAPPED) as usize,
                    event: event as usize,
                    shadow: Some(UnsafeCell::new(std::mem::zeroed())),
                });
                request.publish_pending();
                assert_eq!(GetAddrInfoExOverlappedResult(&caller), WSAEINPROGRESS);
                let native = request.native_overlapped();
                pending().lock().unwrap().insert(native as usize, request);
                completion(status as u32, 0, native);
                assert_eq!(WaitForSingleObject(event, 0), WAIT_OBJECT_0);
                assert_eq!(caller.hEvent, event);
                assert_eq!(GetAddrInfoExOverlappedResult(&caller), status);
                assert!(!pending().lock().unwrap().contains_key(&(native as usize)));
                CloseHandle(event);
            }
        }
    }

    unsafe extern "system" fn user_callback(_: u32, bytes: u32, caller: *const OVERLAPPED) {
        if !INSIDE_HOOK.with(Cell::get) {
            (*(caller as *mut OVERLAPPED)).Internal = bytes as usize;
        }
    }

    #[test]
    fn callback_receives_caller_identity_outside_hook_guard() {
        unsafe {
            let mut caller: OVERLAPPED = std::mem::zeroed();
            let address = (&mut caller as *mut OVERLAPPED) as usize;
            pending().lock().unwrap().insert(
                address,
                Arc::new(Pending {
                    engine: hyperhub_engine::resident().acquire(),
                    hostname: "localhost".into(),
                    result: 0,
                    callback: Some(user_callback),
                    caller: address,
                    event: 0,
                    shadow: None,
                }),
            );
            INSIDE_HOOK.with(|value| value.set(true));
            completion(1, 123, address as *const OVERLAPPED);
            let restored = INSIDE_HOOK.with(|value| value.replace(false));
            assert!(restored);
            assert_eq!(caller.Internal, 123);
            assert!(!pending().lock().unwrap().contains_key(&address));
        }
    }

    #[test]
    fn immediate_error_restores_overlapped_without_notification() {
        unsafe {
            let event = CreateEventW(null(), 1, 0, null());
            assert!(!event.is_null());
            let mut caller: OVERLAPPED = std::mem::zeroed();
            caller.Internal = 123;
            caller.hEvent = event;
            let request = Pending {
                engine: hyperhub_engine::resident().acquire(),
                hostname: "localhost".into(),
                result: 0,
                callback: None,
                caller: (&mut caller as *mut OVERLAPPED) as usize,
                event: event as usize,
                shadow: Some(UnsafeCell::new(std::ptr::read(&caller))),
            };
            request.publish_pending();
            assert_eq!(GetAddrInfoExOverlappedResult(&caller), WSAEINPROGRESS);
            request.publish_event(None, false);
            assert_eq!(caller.Internal, 123);
            assert_eq!(WaitForSingleObject(event, 0), WAIT_TIMEOUT);
            CloseHandle(event);
        }
    }
}
