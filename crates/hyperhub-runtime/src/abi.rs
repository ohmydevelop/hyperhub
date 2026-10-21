//! V1 stateless engine ABI. Modules may read Host state only through Host services.
//!
//! Buffers and their allocation remain owned by the caller. Implementations must
//! not retain pointers, unwind, create unmanaged threads, or change native hooks.
//! A Host service that starts asynchronous work must retain the calling lease
//! until completion/cancellation, before allowing a module to be retired.
use std::ffi::c_void;

pub const ABI_V1: u32 = 0x0001_0000;
pub const OK: i32 = 0;
pub const INVALID: i32 = -1;
pub const BUFFER_TOO_SMALL: i32 = -2;
pub const UNSUPPORTED: i32 = -3;
pub const FAILED: i32 = -4;
pub const ENTRY_SYMBOL: &[u8] = b"hh_engine_v1\0";

/// Operation numbers and byte encodings are part of each Host's state schema.
/// `written` must always be set, including on error. Calls have no implicit retry:
/// BUFFER_TOO_SMALL must not repeat an operation with side effects.
pub type Invoke = unsafe extern "C" fn(
    host: *const HostServices,
    operation: u32,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_capacity: usize,
    written: *mut usize,
) -> i32;

pub type HostCall = unsafe extern "C" fn(
    context: *mut c_void,
    operation: u32,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_capacity: usize,
    written: *mut usize,
) -> i32;

#[repr(C)]
pub struct HostServices {
    pub struct_size: u32,
    pub abi: u32,
    pub context: *mut c_void,
    pub call: Option<HostCall>,
}

/// The table is immutable and remains valid until the library is unloaded.
/// A minor version extension must retain the complete V1 prefix.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EngineApi {
    pub struct_size: u32,
    pub abi: u32,
    pub state_schema: u32,
    pub reserved: u32,
    pub hooks: u64,
    /// SHA-256 of the UTF-8 release version. Compare before invoking code.
    pub version_hash: [u8; 32],
    pub invoke: Option<Invoke>,
    /// Must be a bounded, side-effect-free check. Cannot catch native faults.
    pub health: Option<unsafe extern "C" fn() -> i32>,
}

pub type Entry = unsafe extern "C" fn() -> *const EngineApi;
