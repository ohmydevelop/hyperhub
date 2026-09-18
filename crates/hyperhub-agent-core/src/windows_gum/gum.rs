use std::cell::Cell;
use std::ffi::{c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use windows_sys::Win32::Networking::WinSock::{
    closesocket, WSACleanup, WSAIoctl, WSASocketW, WSAStartup, AF_INET, INVALID_SOCKET,
    IPPROTO_TCP, SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKET, SOCK_STREAM, WSADATA, WSAID_CONNECTEX,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

use crate::{hh_agent_close_socket, HH_OK};

use super::manager;

macro_rules! original {
    ($slot:ident, $ty:ty) => {{
        let pointer = $slot.load(Ordering::Acquire);
        if pointer.is_null() {
            None
        } else {
            Some(std::mem::transmute::<*mut c_void, $ty>(pointer))
        }
    }};
}
pub(in crate::windows_gum) use original;

pub(in crate::windows_gum) unsafe fn find_export(
    module_name: &str,
    symbol_name: &str,
) -> Option<*mut c_void> {
    let module_name = CString::new(module_name).ok()?;
    let symbol_name = CString::new(symbol_name).ok()?;
    let mut module = GetModuleHandleA(module_name.as_ptr().cast());
    if module.is_null() {
        module = LoadLibraryA(module_name.as_ptr().cast());
    }
    if module.is_null() {
        return None;
    }
    GetProcAddress(module, symbol_name.as_ptr().cast())
        .map(|function| function as *const () as *mut c_void)
}

pub(in crate::windows_gum) unsafe fn find_msys_runtime_export(
    symbol_name: &str,
) -> Option<*mut c_void> {
    let symbol_name = CString::new(symbol_name).ok()?;
    for module_name in ["msys-2.0.dll", "cygwin1.dll"] {
        let module_name = CString::new(module_name).ok()?;
        let module = GetModuleHandleA(module_name.as_ptr().cast());
        if module.is_null() {
            continue;
        }
        if let Some(function) = GetProcAddress(module, symbol_name.as_ptr().cast()) {
            return Some(function as *const () as *mut c_void);
        }
    }
    None
}

pub(in crate::windows_gum) unsafe fn has_msys_runtime() -> bool {
    ["msys-2.0.dll", "cygwin1.dll"].iter().any(|name| {
        CString::new(*name)
            .ok()
            .is_some_and(|name| !GetModuleHandleA(name.as_ptr().cast()).is_null())
    })
}

pub(in crate::windows_gum) unsafe fn find_connect_ex() -> Option<*mut c_void> {
    let mut data = WSADATA::default();
    if WSAStartup(0x0202, &mut data) != 0 {
        return None;
    }
    let socket = WSASocketW(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP, null(), 0, 0);
    if socket == INVALID_SOCKET {
        WSACleanup();
        return None;
    }
    let mut connect_ex: *mut c_void = null_mut();
    let mut written = 0;
    let connect_ex_id = WSAID_CONNECTEX;
    let result = WSAIoctl(
        socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        std::ptr::addr_of!(connect_ex_id).cast::<c_void>(),
        std::mem::size_of_val(&connect_ex_id) as u32,
        (&mut connect_ex as *mut *mut c_void).cast(),
        std::mem::size_of::<*mut c_void>() as u32,
        &mut written,
        null_mut(),
        None,
    );
    closesocket(socket);
    WSACleanup();
    (result == 0 && !connect_ex.is_null()).then_some(connect_ex)
}

pub(in crate::windows_gum) static AGENT_MODULE: AtomicUsize = AtomicUsize::new(0);
pub(in crate::windows_gum) static CHILD_EVENT_ID: AtomicU64 = AtomicU64::new(1);

#[repr(C)]
pub(in crate::windows_gum) struct GumInterceptor {
    _private: [u8; 0],
}

#[link(name = "frida-gum", kind = "static")]
extern "C" {
    pub(in crate::windows_gum) fn gum_init_embedded();
    pub(in crate::windows_gum) fn gum_interceptor_obtain() -> *mut GumInterceptor;
    pub(in crate::windows_gum) fn gum_interceptor_replace_fast(
        interceptor: *mut GumInterceptor,
        function_address: *mut c_void,
        replacement_function: *mut c_void,
        original_function: *mut *mut c_void,
        options: *const c_void,
    ) -> i32;
    pub(in crate::windows_gum) fn gum_interceptor_replace(
        interceptor: *mut GumInterceptor,
        function_address: *mut c_void,
        replacement_function: *mut c_void,
        original_function: *mut *mut c_void,
        options: *const c_void,
    ) -> i32;
    pub(in crate::windows_gum) fn gum_interceptor_begin_transaction(
        interceptor: *mut GumInterceptor,
    );
    pub(in crate::windows_gum) fn gum_interceptor_end_transaction(interceptor: *mut GumInterceptor);
    pub(in crate::windows_gum) fn gum_interceptor_revert(
        interceptor: *mut GumInterceptor,
        function_address: *mut c_void,
    );
}

thread_local! {
    pub(in crate::windows_gum) static INSIDE_HOOK: Cell<bool> = const { Cell::new(false) };
}

pub(in crate::windows_gum) struct HookGuard;

impl HookGuard {
    pub(in crate::windows_gum) fn enter() -> Option<Self> {
        INSIDE_HOOK.with(|inside| {
            if inside.replace(true) {
                None
            } else {
                Some(Self)
            }
        })
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        INSIDE_HOOK.with(|inside| inside.set(false));
    }
}

fn original_slot(hook_id: u32) -> Option<&'static AtomicPtr<c_void>> {
    manager::descriptor(hook_id).map(|descriptor| descriptor.original)
}

#[no_mangle]
pub extern "C" fn hh_gum_replacement(hook_id: u32) -> *mut c_void {
    manager::descriptor(hook_id)
        .map(|descriptor| descriptor.replacement)
        .unwrap_or(null_mut())
}

#[no_mangle]
pub extern "C" fn hh_gum_set_original(hook_id: u32, pointer: *mut c_void) -> i32 {
    let Some(slot) = original_slot(hook_id) else {
        return -1;
    };
    if pointer.is_null() {
        return -1;
    }
    slot.store(pointer, Ordering::Release);
    HH_OK
}

pub(in crate::windows_gum) unsafe fn hook_result<F, T>(
    socket: Option<SOCKET>,
    fallback: F,
    body: impl FnOnce() -> T,
) -> T
where
    F: FnOnce() -> T,
{
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => {
            if let Some(socket) = socket {
                hh_agent_close_socket(socket as u64);
            }
            fallback()
        }
    }
}
