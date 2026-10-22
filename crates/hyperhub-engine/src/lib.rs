//! Stateless network processing shared by the initial resident fallback and the
//! independently built native Engine. Session/socket/DNS ownership stays in Host.
pub mod bootstrap;
pub mod contract;
pub mod host;
pub mod management;
pub use hyperhub_runtime as runtime;
mod operations;
mod policy;
mod sanitizer;
mod trust;

use hyperhub_runtime::{abi, Engine, Lease, Manifest, Runtime, Settings};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

pub use contract::TargetAddress;
pub const TARGET: &str = env!("HYPERHUB_ENGINE_TARGET");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
include!(concat!(env!("OUT_DIR"), "/native_base.rs"));

pub fn manifest(bytes: &[u8], version: &str) -> Manifest {
    Manifest {
        version: version.into(),
        target: TARGET.into(),
        abi: abi::ABI_V1,
        state_schema: contract::STATE_SCHEMA,
        hooks: contract::REQUIRED_OPERATIONS,
        sha256: hyperhub_runtime::artifact::hex(&Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}
struct Builtin {
    manifest: Manifest,
    epoch: u64,
}
impl Builtin {
    fn new(manifest: Manifest) -> Self {
        Self {
            manifest,
            epoch: policy::retain().expect("resident module ownership"),
        }
    }
}
impl Drop for Builtin {
    fn drop(&mut self) {
        let _ = policy::release(self.epoch);
    }
}
impl Engine for Builtin {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn health(&self) -> bool {
        true
    }
    #[cfg(target_os = "linux")]
    unsafe fn fork_copy(&self) -> Result<Arc<dyn Engine>, hyperhub_runtime::Error> {
        Ok(Arc::new(Builtin::new(self.manifest.clone())))
    }
    #[cfg(target_os = "linux")]
    fn fork_module_key(&self) -> usize {
        policy::reset_after_fork as *const () as usize
    }
    #[cfg(target_os = "linux")]
    unsafe fn fork_reset(&self) -> Result<(), hyperhub_runtime::Error> {
        policy::reset_after_fork();
        Ok(())
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
            Arc::new(Builtin::new(manifest(b"resident-capabilities-v2", VERSION))),
            settings,
        )
        .expect("valid built-in Engine"),
    )
}
pub fn call(lease: &Lease, operation: u32, request: &impl Serialize) -> Result<Vec<u8>, i32> {
    let input = serde_json::to_vec(request).map_err(|_| contract::INVALID)?;
    if input.len() > contract::MAX_POLICY_REQUEST {
        return Err(contract::INVALID);
    }
    let capacity = if operation == contract::SANITIZE_ACTION {
        input
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(contract::MAX_RESPONSE))
            .ok_or(contract::CAPACITY)?
    } else {
        contract::MAX_RESPONSE
    };
    let mut output = vec![0; capacity];
    let count = match lease.invoke(operation, &input, &mut output) {
        Err(contract::CAPACITY)
            if matches!(
                operation,
                contract::FILE_POLICY | contract::PROCESS_POLICY | contract::FIREWALL_POLICY
            ) =>
        {
            // Pure decisions can repeat configured IDs in their output. Keep
            // the normal 4K buffer and retry only these side-effect-free byte
            // operations, exactly once through the same pinned generation.
            let maximum = input
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(contract::MAX_RESPONSE))
                .ok_or(contract::CAPACITY)?;
            output.resize(maximum, 0);
            lease.invoke(operation, &input, &mut output)?
        }
        result => result?,
    };
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
pub fn policy(
    lease: &Lease,
    operation: u32,
    input: &contract::PolicyInput,
) -> Result<contract::PolicyDecision, i32> {
    let output = call(lease, operation, input)?;
    serde_json::from_slice(&output).map_err(|_| contract::INVALID)
}
pub fn firewall(
    lease: &Lease,
    input: &contract::FirewallInput,
) -> Result<contract::PolicyDecision, i32> {
    let output = call(lease, contract::FIREWALL_POLICY, input)?;
    serde_json::from_slice(&output).map_err(|_| contract::INVALID)
}
pub fn child_plan(lease: &Lease, input: &contract::ChildInput) -> Result<contract::ChildPlan, i32> {
    let output = call(lease, contract::CHILD_PLAN, input)?;
    serde_json::from_slice(&output).map_err(|_| contract::INVALID)
}
/// Binary framing keeps large PEM bundles bounded without JSON expansion:
/// little-endian extension length and root length, followed by extension, root,
/// and source bytes. The module returns a complete bundle or an empty rejection.
pub fn trust_bundle(
    lease: &Lease,
    extension: &str,
    source: &[u8],
    root: &[u8],
) -> Result<Vec<u8>, i32> {
    let length = 8usize
        .checked_add(extension.len())
        .and_then(|n| n.checked_add(root.len()))
        .and_then(|n| n.checked_add(source.len()))
        .ok_or(contract::CAPACITY)?;
    if length > contract::MAX_TRUST_REQUEST || extension.len() > 16 || root.len() > 1024 * 1024 {
        return Err(contract::CAPACITY);
    }
    let mut input = Vec::with_capacity(length);
    input.extend_from_slice(&(extension.len() as u32).to_le_bytes());
    input.extend_from_slice(&(root.len() as u32).to_le_bytes());
    input.extend_from_slice(extension.as_bytes());
    input.extend_from_slice(root);
    input.extend_from_slice(source);
    let mut output = vec![
        0;
        source
            .len()
            .checked_add(root.len())
            .and_then(|n| n.checked_add(contract::MAX_RESPONSE))
            .ok_or(contract::CAPACITY)?
    ];
    let count = lease.invoke(contract::TRUST_BUNDLE, &input, &mut output)?;
    if count > output.len() {
        return Err(contract::CAPACITY);
    }
    output.truncate(count);
    Ok(output)
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
        || length > contract::MAX_TRUST_REQUEST
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
        hooks: contract::REQUIRED_OPERATIONS,
        version_hash: Sha256::digest(VERSION.as_bytes()).into(),
        invoke: Some(invoke),
        health: Some(health),
    })
}
