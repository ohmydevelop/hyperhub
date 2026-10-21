pub const ABI_VERSION: u32 = 0x0002_0000;
pub const HH_OK: i32 = 0;
pub const HH_BYPASS: i32 = 1;
pub const HH_ERR_INVALID: i32 = -1;
pub const HH_ERR_NOT_INITIALIZED: i32 = -2;
pub const HH_ERR_BUFFER_TOO_SMALL: i32 = -3;
pub const HH_ERR_PROTOCOL: i32 = -4;
pub(crate) const CONTROL_MAX_FRAME: usize = 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HhConnectPlan {
    pub struct_size: u32,
    pub should_intercept: u32,
    pub proxy_family: i32,
    pub proxy_port: u16,
    pub reserved: u16,
    pub proxy_address: [u8; 16],
    pub connection_id: u64,
}

impl Default for HhConnectPlan {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>() as u32,
            should_intercept: 0,
            proxy_family: 0,
            proxy_port: 0,
            reserved: 0,
            proxy_address: [0; 16],
            connection_id: 0,
        }
    }
}

use std::ffi::{c_char, CStr};
use std::net::IpAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use crate::{resolve_fake_control, state};

fn ffi_result<F>(f: F) -> i32
where
    F: FnOnce() -> Result<i32, i32>,
{
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or(Err(HH_ERR_INVALID))
        .unwrap_or_else(|error| error)
}

unsafe fn bytes<'a>(pointer: *const u8, length: usize) -> Result<&'a [u8], i32> {
    if pointer.is_null() || length == 0 {
        return Err(HH_ERR_INVALID);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

#[no_mangle]
pub extern "C" fn hh_agent_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub extern "C" fn hh_agent_initialize_from_env() -> i32 {
    ffi_result(|| {
        state()
            .lock()
            .map_err(|_| HH_ERR_INVALID)?
            .initialize_from_env()?;
        Ok(HH_OK)
    })
}

/// In-process management for the resident Host. External transports must first
/// authenticate the coordinator. Native target code already has process access.
/// No configuration key or session credential is accepted or returned here.
#[no_mangle]
pub unsafe extern "C" fn hh_agent_engine_control(
    input: *const u8,
    length: usize,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_result(|| {
        if written.is_null() {
            return Err(HH_ERR_INVALID);
        }
        unsafe {
            written.write(0);
        }
        if output.is_null() || capacity < hyperhub_engine::management::MIN_REPLY {
            unsafe {
                written.write(hyperhub_engine::management::MIN_REPLY);
            }
            return Err(HH_ERR_BUFFER_TOO_SMALL);
        }
        if length > hyperhub_engine::management::MAX_COMMAND {
            return Err(HH_ERR_INVALID);
        }
        let input = unsafe { bytes(input, length)? };
        let command = serde_json::from_slice(input).map_err(|_| HH_ERR_INVALID)?;
        // Release process-state locking before loading, health checks or GC.
        let engine = state().lock().map_err(|_| HH_ERR_INVALID)?.engine.clone();
        let reply = crate::engine_call::trusted_io(|| unsafe {
            hyperhub_engine::management::execute(&engine, command)
        });
        let payload = serde_json::to_vec(&reply).map_err(|_| HH_ERR_PROTOCOL)?;
        unsafe {
            written.write(payload.len());
        }
        if payload.len() > capacity {
            return Err(HH_ERR_BUFFER_TOO_SMALL);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), output, payload.len());
        }
        Ok(HH_OK)
    })
}

#[no_mangle]
pub extern "C" fn hh_agent_is_initialized() -> i32 {
    state()
        .lock()
        .map(|core| i32::from(core.session.initialized))
        .unwrap_or(HH_ERR_INVALID)
}

#[no_mangle]
pub unsafe extern "C" fn hh_agent_tls_ca_der(
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_result(|| {
        if written.is_null() {
            return Err(HH_ERR_INVALID);
        }
        let core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        unsafe { written.write(core.trust.tls_ca_der.len()) };
        if output.is_null() || capacity < core.trust.tls_ca_der.len() {
            return Err(HH_ERR_BUFFER_TOO_SMALL);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                core.trust.tls_ca_der.as_ptr(),
                output,
                core.trust.tls_ca_der.len(),
            );
        }
        Ok(HH_OK)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hh_agent_tls_ca_path(
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_result(|| {
        if written.is_null() {
            return Err(HH_ERR_INVALID);
        }
        let core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        let value = core.trust.tls_ca_path.as_bytes();
        unsafe { written.write(value.len() + 1) };
        if output.is_null() || capacity <= value.len() {
            return Err(HH_ERR_BUFFER_TOO_SMALL);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len());
            output.add(value.len()).write(0);
        }
        Ok(HH_OK)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hh_agent_resolve_name(
    hostname: *const c_char,
    requested_family: u32,
    output_family: *mut u32,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_result(|| {
        if hostname.is_null() || output_family.is_null() || output.is_null() || written.is_null() {
            return Err(HH_ERR_INVALID);
        }
        let hostname = unsafe { CStr::from_ptr(hostname) }
            .to_str()
            .map_err(|_| HH_ERR_INVALID)?;
        let family = match requested_family {
            0 | 4 => 4,
            6 => 6,
            _ => return Err(HH_ERR_INVALID),
        };
        let (endpoint, session_id, token) = {
            let core = state().lock().map_err(|_| HH_ERR_INVALID)?;
            if !core.session.initialized {
                return Err(HH_ERR_NOT_INITIALIZED);
            }
            (
                core.session.control_endpoint.clone(),
                core.session.session_id.clone(),
                core.session.token.clone(),
            )
        };
        let address = resolve_fake_control(&endpoint, &session_id, &token, hostname, family)?;
        let bytes: Vec<u8> = match address {
            IpAddr::V4(address) => {
                unsafe { output_family.write(4) };
                address.octets().to_vec()
            }
            IpAddr::V6(address) => {
                unsafe { output_family.write(6) };
                address.octets().to_vec()
            }
        };
        if capacity < bytes.len() {
            return Err(HH_ERR_BUFFER_TOO_SMALL);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
            written.write(bytes.len());
        }
        Ok(HH_OK)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hh_agent_record_dns(
    hostname: *const c_char,
    _family: i32,
    address: *const u8,
    address_length: usize,
) -> i32 {
    ffi_result(|| {
        if hostname.is_null() {
            return Err(HH_ERR_INVALID);
        }
        let hostname = unsafe { CStr::from_ptr(hostname) }
            .to_str()
            .map_err(|_| HH_ERR_INVALID)?
            .to_owned();
        if hostname.is_empty() {
            return Err(HH_ERR_INVALID);
        }
        let address = unsafe { bytes(address, address_length)? };
        let mut core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        // Keep the ABI argument, but derive identity from the address itself:
        // adapters use both protocol versions (4/6) and native AF_* values.
        core.record_dns(hostname, address)?;
        Ok(HH_OK)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hh_agent_prepare_connect(
    socket: u64,
    family: i32,
    address: *const u8,
    address_length: usize,
    port: u16,
    plan: *mut HhConnectPlan,
) -> i32 {
    ffi_result(|| {
        if plan.is_null() {
            return Err(HH_ERR_INVALID);
        }
        let address = unsafe { bytes(address, address_length)? };
        let result = state()
            .lock()
            .map_err(|_| HH_ERR_INVALID)?
            .prepare_connect(socket, family, address, port)?;
        unsafe { plan.write(result) };
        Ok(if result.should_intercept == 0 {
            HH_BYPASS
        } else {
            HH_OK
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn hh_agent_build_handshake(
    socket: u64,
    phase: u32,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_result(|| {
        if written.is_null() {
            return Err(HH_ERR_INVALID);
        }
        let payload = state()
            .lock()
            .map_err(|_| HH_ERR_INVALID)?
            .handshake(socket, phase)?;
        unsafe { written.write(payload.len()) };
        if output.is_null() || capacity < payload.len() {
            return Err(HH_ERR_BUFFER_TOO_SMALL);
        }
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), output, payload.len()) };
        Ok(HH_OK)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hh_agent_validate_handshake_reply(
    phase: u32,
    input: *const u8,
    length: usize,
) -> i32 {
    ffi_result(|| {
        let input = unsafe { bytes(input, length)? };
        let engine = state().lock().map_err(|_| HH_ERR_INVALID)?.engine.clone();
        hyperhub_engine::validate_reply(
            &crate::engine_call::calling(&engine)?,
            phase,
            input,
            false,
        )
        .map_err(crate::engine_error)?;
        Ok(HH_OK)
    })
}

/// Socket-specific validation keeps all handshake phases on the connection's
/// original Engine, even if a compatible upgrade commits between phases.
#[no_mangle]
pub unsafe extern "C" fn hh_agent_validate_socket_handshake_reply(
    socket: u64,
    phase: u32,
    input: *const u8,
    length: usize,
) -> i32 {
    ffi_result(|| {
        let input = unsafe { bytes(input, length)? };
        let lease = state()
            .lock()
            .map_err(|_| HH_ERR_INVALID)?
            .gateway
            .sockets
            .get(&socket)
            .ok_or(HH_ERR_INVALID)?
            .engine
            .clone();
        hyperhub_engine::validate_reply(&lease, phase, input, false)
            .map_err(crate::engine_error)?;
        Ok(HH_OK)
    })
}

#[no_mangle]
pub extern "C" fn hh_agent_note_io(socket: u64, result: i64) -> i32 {
    ffi_result(|| {
        let mut core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        let socket = core
            .gateway
            .sockets
            .get_mut(&socket)
            .ok_or(HH_ERR_INVALID)?;
        socket.last_io_result = result;
        Ok(HH_OK)
    })
}

#[no_mangle]
pub extern "C" fn hh_agent_note_wait(socket: u64, ready_mask: u32) -> i32 {
    ffi_result(|| {
        let mut core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        let socket = core
            .gateway
            .sockets
            .get_mut(&socket)
            .ok_or(HH_ERR_INVALID)?;
        socket.ready_mask = ready_mask;
        Ok(HH_OK)
    })
}

#[no_mangle]
pub extern "C" fn hh_agent_note_nonblocking(socket: u64, nonblocking: u32) -> i32 {
    ffi_result(|| {
        let mut core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        if nonblocking != 0 {
            core.gateway.nonblocking_sockets.insert(socket);
        } else {
            core.gateway.nonblocking_sockets.remove(&socket);
        }
        if let Some(socket) = core.gateway.sockets.get_mut(&socket) {
            socket.nonblocking = nonblocking != 0;
        }
        Ok(HH_OK)
    })
}

#[no_mangle]
pub extern "C" fn hh_agent_socket_nonblocking(socket: u64) -> i32 {
    ffi_result(|| {
        let core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        Ok(core.gateway.sockets.get(&socket).map_or_else(
            || i32::from(core.gateway.nonblocking_sockets.contains(&socket)),
            |socket| i32::from(socket.nonblocking),
        ))
    })
}

#[no_mangle]
pub extern "C" fn hh_agent_handshake_complete(socket: u64) -> i32 {
    state()
        .lock()
        .ok()
        .and_then(|core| {
            core.gateway
                .sockets
                .get(&socket)
                .map(|socket| socket.handshake_complete)
        })
        .map(i32::from)
        .unwrap_or(HH_ERR_INVALID)
}

#[no_mangle]
pub extern "C" fn hh_agent_set_handshake_complete(socket: u64) -> i32 {
    ffi_result(|| {
        let mut core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        let socket = core
            .gateway
            .sockets
            .get_mut(&socket)
            .ok_or(HH_ERR_INVALID)?;
        socket.handshake_complete = true;
        Ok(HH_OK)
    })
}

#[no_mangle]
pub extern "C" fn hh_agent_close_socket(socket: u64) -> i32 {
    ffi_result(|| {
        let mut core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        core.gateway.nonblocking_sockets.remove(&socket);
        let removed = core.gateway.sockets.remove(&socket);
        Ok(if removed.is_some() { HH_OK } else { HH_BYPASS })
    })
}

#[no_mangle]
pub extern "C" fn hh_agent_dup_socket(source: u64, destination: u64) -> i32 {
    ffi_result(|| {
        let mut core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        let is_nonblocking = core.gateway.nonblocking_sockets.contains(&source);
        let source_state = core
            .gateway
            .sockets
            .get(&source)
            .cloned()
            .ok_or(HH_ERR_INVALID)?;
        core.gateway.sockets.insert(destination, source_state);
        if is_nonblocking {
            core.gateway.nonblocking_sockets.insert(destination);
        }
        Ok(HH_OK)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hh_agent_redirect_path(
    input: *const c_char,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_result(|| {
        if input.is_null() || written.is_null() {
            return Err(HH_ERR_INVALID);
        }
        let input = unsafe { CStr::from_ptr(input) }
            .to_str()
            .map_err(|_| HH_ERR_INVALID)?;
        let mut core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        let Some(replacement) = core.trust.redirect_ca_bundle(input) else {
            unsafe { written.write(0) };
            return Ok(HH_BYPASS);
        };
        let value = replacement.as_bytes();
        unsafe { written.write(value.len() + 1) };
        if output.is_null() || capacity <= value.len() {
            return Err(HH_ERR_BUFFER_TOO_SMALL);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len());
            output.add(value.len()).write(0);
        }
        Ok(HH_OK)
    })
}
