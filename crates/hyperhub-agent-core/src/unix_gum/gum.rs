#![cfg(all(target_os = "linux", feature = "gum-agent"))]
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CString};
use std::sync::{Mutex, OnceLock};

#[repr(C)]
pub struct GumInterceptor {
    _private: [u8; 0],
}
#[repr(C)]
pub struct GumInvocationListener {
    _private: [u8; 0],
}
#[repr(C)]
pub struct GumInvocationContext {
    _private: [u8; 0],
}
pub type GumInvocationCallback = unsafe extern "C" fn(*mut GumInvocationContext, *mut c_void);
#[link(name = "frida-gum", kind = "static")]
extern "C" {
    fn gum_init_embedded();
    fn gum_interceptor_obtain() -> *mut GumInterceptor;
    fn gum_interceptor_begin_transaction(interceptor: *mut GumInterceptor);
    fn gum_interceptor_end_transaction(interceptor: *mut GumInterceptor);
    fn gum_interceptor_replace(
        interceptor: *mut GumInterceptor,
        function_address: *mut c_void,
        replacement_function: *mut c_void,
        original_function: *mut *mut c_void,
        options: *const c_void,
    ) -> i32;
    fn gum_interceptor_replace_fast(
        interceptor: *mut GumInterceptor,
        function_address: *mut c_void,
        replacement_function: *mut c_void,
        original_function: *mut *mut c_void,
        options: *const c_void,
    ) -> i32;
    fn gum_interceptor_revert(interceptor: *mut GumInterceptor, function_address: *mut c_void);
    fn gum_make_call_listener(
        on_enter: Option<GumInvocationCallback>,
        on_leave: Option<GumInvocationCallback>,
        data: *mut c_void,
        data_destroy: *const c_void,
    ) -> *mut GumInvocationListener;
    fn gum_interceptor_attach(
        interceptor: *mut GumInterceptor,
        target: *mut c_void,
        listener: *mut GumInvocationListener,
        options: *const c_void,
    ) -> i32;
    fn gum_interceptor_detach(
        interceptor: *mut GumInterceptor,
        listener: *mut GumInvocationListener,
    );
    fn gum_invocation_context_get_nth_argument(
        context: *mut GumInvocationContext,
        n: u32,
    ) -> *mut c_void;
    fn gum_invocation_context_replace_nth_argument(
        context: *mut GumInvocationContext,
        n: u32,
        value: *mut c_void,
    );
    fn gum_invocation_context_get_return_value(context: *mut GumInvocationContext) -> *mut c_void;
    fn gum_invocation_context_replace_return_value(
        context: *mut GumInvocationContext,
        value: *mut c_void,
    );
    fn gum_invocation_context_get_listener_invocation_data(
        context: *mut GumInvocationContext,
        required_size: usize,
    ) -> *mut c_void;
    fn gum_module_find_global_export_by_name(symbol_name: *const c_char) -> *mut c_void;
}
static ORIGINALS: OnceLock<Mutex<HashMap<&'static str, usize>>> = OnceLock::new();
fn originals() -> &'static Mutex<HashMap<&'static str, usize>> {
    ORIGINALS.get_or_init(|| Mutex::new(HashMap::new()))
}
pub fn original(symbol: &str) -> Option<*mut c_void> {
    originals()
        .lock()
        .ok()?
        .get(symbol)
        .copied()
        .map(|p| p as *mut c_void)
}
pub fn set_original(symbol: &'static str, pointer: *mut c_void) -> Result<(), String> {
    originals()
        .lock()
        .map_err(|_| "original map poisoned".to_string())?
        .insert(symbol, pointer as usize);
    Ok(())
}
pub unsafe fn initialize() -> Result<*mut GumInterceptor, String> {
    gum_init_embedded();
    let interceptor = gum_interceptor_obtain();
    if interceptor.is_null() {
        Err("gum_interceptor_obtain returned null".into())
    } else {
        Ok(interceptor)
    }
}
pub unsafe fn find_export(symbol: &str) -> Option<*mut c_void> {
    let symbol = CString::new(symbol).ok()?;
    let pointer = gum_module_find_global_export_by_name(symbol.as_ptr());
    (!pointer.is_null()).then_some(pointer)
}
pub unsafe fn begin(interceptor: *mut GumInterceptor) {
    gum_interceptor_begin_transaction(interceptor)
}
pub unsafe fn end(interceptor: *mut GumInterceptor) {
    gum_interceptor_end_transaction(interceptor)
}
pub unsafe fn replace(
    interceptor: *mut GumInterceptor,
    target: *mut c_void,
    replacement: *mut c_void,
) -> Result<*mut c_void, i32> {
    let mut original = std::ptr::null_mut();
    let mut status = gum_interceptor_replace_fast(
        interceptor,
        target,
        replacement,
        &mut original,
        std::ptr::null(),
    );
    if status == -1 {
        original = std::ptr::null_mut();
        status = gum_interceptor_replace(
            interceptor,
            target,
            replacement,
            &mut original,
            std::ptr::null(),
        );
    }
    if status == 0 && !original.is_null() {
        Ok(original)
    } else {
        Err(status)
    }
}
pub unsafe fn revert(interceptor: *mut GumInterceptor, target: *mut c_void) {
    gum_interceptor_revert(interceptor, target)
}

pub unsafe fn make_call_listener(
    on_enter: GumInvocationCallback,
    on_leave: GumInvocationCallback,
    data: *mut c_void,
) -> Result<*mut GumInvocationListener, String> {
    let listener = gum_make_call_listener(Some(on_enter), Some(on_leave), data, std::ptr::null());
    if listener.is_null() {
        Err("gum_make_call_listener returned null".into())
    } else {
        Ok(listener)
    }
}
pub unsafe fn attach(
    interceptor: *mut GumInterceptor,
    target: *mut c_void,
    listener: *mut GumInvocationListener,
) -> Result<(), i32> {
    let status = gum_interceptor_attach(interceptor, target, listener, std::ptr::null());
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}
pub unsafe fn detach(interceptor: *mut GumInterceptor, listener: *mut GumInvocationListener) {
    gum_interceptor_detach(interceptor, listener)
}
pub unsafe fn argument(context: *mut GumInvocationContext, index: u32) -> *mut c_void {
    gum_invocation_context_get_nth_argument(context, index)
}
pub unsafe fn replace_argument(context: *mut GumInvocationContext, index: u32, value: *mut c_void) {
    gum_invocation_context_replace_nth_argument(context, index, value)
}
pub unsafe fn return_value(context: *mut GumInvocationContext) -> *mut c_void {
    gum_invocation_context_get_return_value(context)
}
pub unsafe fn replace_return_value(context: *mut GumInvocationContext, value: *mut c_void) {
    gum_invocation_context_replace_return_value(context, value)
}
pub unsafe fn invocation_data<T>(context: *mut GumInvocationContext) -> *mut T {
    gum_invocation_context_get_listener_invocation_data(context, std::mem::size_of::<T>()).cast()
}
