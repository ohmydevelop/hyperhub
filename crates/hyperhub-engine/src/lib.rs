//! Stateless network processing shared by the initial resident fallback and the
//! independently built native Engine. Session/socket/DNS ownership stays in Host.
pub mod contract;
pub mod management;
mod operations;

use hyperhub_runtime::{abi, Engine, Lease, Manifest, Runtime, Settings};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

pub use contract::TargetAddress;
pub const TARGET: &str = env!("HYPERHUB_ENGINE_TARGET");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn manifest(bytes: &[u8], version: &str) -> Manifest {
    Manifest {
        version: version.into(),
        target: TARGET.into(),
        abi: abi::ABI_V1,
        state_schema: contract::STATE_SCHEMA,
        hooks: contract::NETWORK_OPERATIONS,
        sha256: hyperhub_runtime::artifact::hex(&Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}
struct Builtin {
    manifest: Manifest,
}
impl Engine for Builtin {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn health(&self) -> bool {
        true
    }
    fn invoke(
        &self,
        _: &Lease,
        operation: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, i32> {
        copy_result(operation, input, output)
    }
}
/// The fallback identity is logical, not a downloadable artifact digest. Native
/// candidates must instead use the exact file bytes from the trusted bundle.
pub fn resident() -> Arc<Runtime> {
    resident_with(Settings::default())
}
pub fn resident_with(settings: Settings) -> Arc<Runtime> {
    Arc::new(
        Runtime::new(
            Arc::new(Builtin {
                manifest: manifest(b"resident-network-v1", VERSION),
            }),
            settings,
        )
        .expect("valid built-in Engine"),
    )
}
pub fn call(lease: &Lease, operation: u32, request: &impl Serialize) -> Result<Vec<u8>, i32> {
    let input = serde_json::to_vec(request).map_err(|_| contract::INVALID)?;
    if input.len() > contract::MAX_REQUEST {
        return Err(contract::INVALID);
    }
    let mut output = vec![0; contract::MAX_RESPONSE];
    let count = lease.invoke(operation, &input, &mut output)?;
    if count > output.len() {
        return Err(contract::CAPACITY);
    }
    output.truncate(count);
    Ok(output)
}
pub fn normalize(lease: &Lease, name: &str) -> Result<String, i32> {
    let output = call(lease, contract::NORMALIZE_DNS, &name)?;
    serde_json::from_slice(&output).map_err(|_| contract::INVALID)
}
pub fn connect(
    lease: &Lease,
    request: &contract::ConnectInput,
) -> Result<contract::ConnectOutput, i32> {
    let output = call(lease, contract::PLAN_CONNECT, request)?;
    serde_json::from_slice(&output).map_err(|_| contract::INVALID)
}
pub fn handshake(lease: &Lease, request: &contract::HandshakeInput) -> Result<Vec<u8>, i32> {
    call(lease, contract::BUILD_HANDSHAKE, request)
}
pub fn validate_reply(
    lease: &Lease,
    phase: u32,
    bytes: &[u8],
    header_only: bool,
) -> Result<(), i32> {
    call(
        lease,
        contract::VALIDATE_REPLY,
        &contract::ReplyInput {
            phase,
            bytes: bytes.into(),
            header_only,
        },
    )
    .map(|_| ())
}
fn copy_result(operation: u32, input: &[u8], output: &mut [u8]) -> Result<usize, i32> {
    let bytes = operations::execute(operation, input)?;
    if bytes.len() > output.len() {
        return Err(contract::CAPACITY);
    }
    output[..bytes.len()].copy_from_slice(&bytes);
    Ok(bytes.len())
}
unsafe extern "C" fn invoke(
    _: *const abi::HostServices,
    operation: u32,
    input: *const u8,
    length: usize,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if written.is_null() {
        return contract::INVALID;
    }
    unsafe {
        written.write(0);
    }
    if (input.is_null() && length != 0)
        || (output.is_null() && capacity != 0)
        || length > contract::MAX_REQUEST
        || capacity > isize::MAX as usize
    {
        return contract::INVALID;
    }
    std::panic::catch_unwind(|| {
        let input = if length == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(input, length) }
        };
        let output = if capacity == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(output, capacity) }
        };
        match copy_result(operation, input, output) {
            Ok(count) => {
                unsafe {
                    written.write(count);
                }
                abi::OK
            }
            Err(error) => error,
        }
    })
    .unwrap_or(abi::FAILED)
}
unsafe extern "C" fn health() -> i32 {
    abi::OK
}
#[no_mangle]
pub extern "C" fn hh_engine_v1() -> *const abi::EngineApi {
    static TABLE: OnceLock<abi::EngineApi> = OnceLock::new();
    TABLE.get_or_init(|| abi::EngineApi {
        struct_size: std::mem::size_of::<abi::EngineApi>() as u32,
        abi: abi::ABI_V1,
        state_schema: contract::STATE_SCHEMA,
        reserved: 0,
        hooks: contract::NETWORK_OPERATIONS,
        version_hash: Sha256::digest(VERSION.as_bytes()).into(),
        invoke: Some(invoke),
        health: Some(health),
    })
}
