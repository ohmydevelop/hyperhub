//! Standalone native engine fixture. Built by the runtime integration suite.
#![allow(dead_code)]
#[path = "../../crates/hyperhub-runtime/src/abi.rs"]
mod abi;
use std::sync::atomic::{AtomicBool, Ordering};

static HEALTHY: AtomicBool = AtomicBool::new(true);
const fn version_hash() -> [u8; 32] {
    let text = env!("HH_FIXTURE_VERSION_HASH").as_bytes();
    let mut output = [0; 32];
    let mut index = 0;
    while index < 32 {
        let hi = digit(text[index * 2]);
        let lo = digit(text[index * 2 + 1]);
        output[index] = hi * 16 + lo;
        index += 1;
    }
    output
}
const fn digit(b: u8) -> u8 { if b <= b'9' { b - b'0' } else { b - b'a' + 10 } }
unsafe extern "C" fn health() -> i32 {
    if HEALTHY.load(Ordering::Acquire) { abi::OK } else { abi::FAILED }
}
unsafe extern "C" fn invoke(
    host: *const abi::HostServices, operation: u32, input: *const u8, length: usize,
    output: *mut u8, capacity: usize, written: *mut usize,
) -> i32 {
    unsafe { written.write(0); }
    match operation {
        0 => {
            if capacity < 8 { return abi::BUFFER_TOO_SMALL; }
            let input = unsafe { std::slice::from_raw_parts(input, length) };
            let seed = if cfg!(engine_v2) { 200u64 } else { 100u64 };
            let answer = input.iter().map(|b| *b as u64).sum::<u64>() + seed;
            unsafe {
                std::ptr::copy_nonoverlapping(answer.to_le_bytes().as_ptr(), output, 8);
                written.write(8);
            }
            abi::OK
        }
        1 if !host.is_null() => {
            let services = unsafe { &*host };
            unsafe { services.call.unwrap()(services.context, 7, input, length, output, capacity, written) }
        }
        2 => { HEALTHY.store(false, Ordering::Release); abi::OK }
        3 => { unsafe { written.write(capacity + 1); } abi::OK }
        _ => abi::UNSUPPORTED,
    }
}
static API: abi::EngineApi = abi::EngineApi {
    struct_size: std::mem::size_of::<abi::EngineApi>() as u32,
    abi: if cfg!(incompatible_abi) { 0xffff_0000 } else { abi::ABI_V1 },
    state_schema: 1, reserved: 0, hooks: 3, version_hash: version_hash(),
    invoke: Some(invoke), health: Some(health),
};
#[no_mangle]
pub extern "C" fn hh_engine_v1() -> *const abi::EngineApi { &API }
