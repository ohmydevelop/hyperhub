//! Private, authenticated lifecycle protocol for an already-running target.
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::sync::atomic::AtomicBool;

pub const PROTOCOL: u32 = 1;
pub const MAX_FRAME: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    /// Immutable provenance of an externally attached process and its children.
    /// Child startup ownership does not change this value.
    #[serde(default)]
    pub external_attachment: bool,
    #[serde(default)]
    pub native_dns_mode: NativeDnsMode,
    #[serde(default)]
    pub approval_root_identity: Option<RootImageIdentity>,
    pub attachment_id: String,
    pub session_id: String,
    pub token: String,
    pub control_endpoint: String,
    pub socks_address: String,
    pub tls_ca_pem: String,
    pub observe: bool,
    pub firewall: Option<serde_json::Value>,
    pub sandbox: Option<serde_json::Value>,
    pub host_endpoint: String,
    pub host_token: String,
    pub scope_tree: bool,
    pub root_pid: u32,
    pub approval_authority_file: String,
    pub approval_instance_id: String,
    #[serde(default)]
    pub initially_owned: bool,
    #[serde(default)]
    pub approval_not_before_ms: u64,
    pub approval_public_key: Option<[u8; 32]>,
    #[serde(default)]
    pub approval_inherited_public_key: Option<[u8; 32]>,
    #[serde(default)]
    pub alias_inherited: Option<AliasInheritance>,
    pub approval_core_public_key: Option<[u8; 32]>,
    pub approval_core_pid: u32,
    pub approval_core_birth: u64,
    pub approval_cli_sha256: String,
}
impl std::fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bootstrap")
            .field("attachment_id", &self.attachment_id)
            .field("root_pid", &self.root_pid)
            .field("host_endpoint", &self.host_endpoint)
            .field("credentials", &"<redacted>")
            .finish()
    }
}
impl Bootstrap {
    /// Bind immutable session, policy bootstrap and trust authority at the Host
    /// boundary. Member-local IPC addresses and proved child startup ownership
    /// are transport/lifecycle derivatives rather than session authority.
    pub fn approval_binding(&self) -> io::Result<String> {
        fn canonical(value: serde_json::Value) -> serde_json::Value {
            match value {
                serde_json::Value::Object(values) => {
                    let sorted: std::collections::BTreeMap<_, _> = values
                        .into_iter()
                        .map(|(key, value)| (key, canonical(value)))
                        .collect();
                    serde_json::Value::Object(sorted.into_iter().collect())
                }
                serde_json::Value::Array(values) => {
                    serde_json::Value::Array(values.into_iter().map(canonical).collect())
                }
                other => other,
            }
        }
        let mut value = serde_json::to_value(self).map_err(io::Error::other)?;
        let map = value
            .as_object_mut()
            .ok_or_else(|| io::Error::other("bootstrap is not an object"))?;
        map.remove("host_endpoint");
        map.remove("host_token");
        map.remove("initially_owned");
        map.remove("approval_not_before_ms");
        map.remove("approval_inherited_public_key");
        map.remove("alias_inherited");
        let bytes = serde_json::to_vec(&canonical(value)).map_err(io::Error::other)?;
        use sha2::Digest;
        let hash = sha2::Sha256::digest(bytes);
        Ok(hash.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    pub fn validate(&self) -> io::Result<()> {
        if self.attachment_id.is_empty()
            || self.session_id.is_empty()
            || self.root_pid == 0
            || self.token.len() < 32
            || self.host_token.len() < 32
            || self.host_endpoint.is_empty()
            || self.control_endpoint.is_empty()
            || self.socks_address.parse::<std::net::SocketAddr>().is_err()
            || !self.tls_ca_pem.contains("-----BEGIN CERTIFICATE-----")
            || self.tls_ca_pem.contains("PRIVATE KEY-----")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid attachment bootstrap",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostCommand {
    Activate,
    Detach,
    Status,
    Retire,
    EnrollmentChallenge,
    EnrollApprovalRoot,
    SnapshotAliases,
    ApplySessionAliases,
    PrepareDetachment,
    CancelDetachmentPreparation,
    ApplyRootImage,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalProof {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
impl std::fmt::Debug for ApprovalProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalProof")
            .field("approval", &"<redacted>")
            .finish()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedCommand {
    #[serde(default)]
    pub root_image: Option<SignedRootImage>,
    pub attachment_id: String,
    pub token: String,
    pub command: HostCommand,
    #[serde(default)]
    pub proof: Option<ApprovalProof>,
    #[serde(default)]
    pub enrollment: Option<ApprovalRootCertificate>,
    #[serde(default)]
    pub aliases: Option<SignedSessionAliasSnapshot>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostPhase {
    Preparing,
    Active,
    Detaching,
    DetachedResident,
    Detached,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InitializationStage {
    Bound,
    Registering,
    Engine,
    ForkBroker,
    InstallingHooks,
    Atfork,
    AliasCatchup,
    Ready,
    Failed,
    Cancelled,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InitializationNativePin {
    pub fd: i32,
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InitializationOrigin {
    #[default]
    Unknown,
    Fresh,
    ForkChild,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InitializationStatus {
    #[serde(default)]
    pub origin: InitializationOrigin,
    #[serde(default)]
    pub ever_active: bool,
    #[serde(default)]
    pub runtime_available: bool,
    pub stage: InitializationStage,
    pub initializing: bool,
    pub cancelled: bool,
    pub error: Option<String>,
    pub native_pin: Option<InitializationNativePin>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostStatus {
    #[serde(default)]
    pub initialization: Option<InitializationStatus>,
    #[serde(default)]
    pub root_image: Option<RootImageState>,
    pub protocol: u32,
    pub pid: u32,
    pub attachment_id: String,
    pub phase: HostPhase,
    #[serde(default)]
    pub native_ready: bool,
    pub active_calls: u64,
    #[serde(default)]
    pub control_workers: u64,
    #[serde(default)]
    pub background_workers: u64,
    #[serde(default)]
    pub pending_alias_publications: u64,
    #[serde(default)]
    pub alias_publication_paused: bool,
    #[serde(default)]
    pub spawn_calls: u64,
    #[serde(default)]
    pub approval_not_before_ms: u64,
    #[serde(default)]
    pub approval_root_enrolled: bool,
    #[serde(default)]
    pub approval_enrollment_available: bool,
    #[serde(default)]
    pub approval_public_key: Option<[u8; 32]>,
    #[serde(default)]
    pub approval_challenge: Option<ApprovalEnrollmentChallenge>,
    pub unload_ready: bool,
    pub tracked_sockets: usize,
    pub fake_addresses: usize,
    pub compatibility_reasons: Vec<String>,
    #[serde(default)]
    pub alias_snapshot: Option<AliasSnapshot>,
    #[serde(default)]
    pub alias_inheritance: Option<AliasInheritance>,
    #[serde(default)]
    pub alias_history_ready: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuedAliasSnapshot {
    pub address: std::net::IpAddr,
    pub hostname: String,
    pub ambiguous: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AliasSnapshot {
    pub issued: Vec<IssuedAliasSnapshot>,
    pub complete: bool,
    #[serde(default)]
    pub history_records: Vec<IssuedRecord>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    status: Option<HostStatus>,
    error: Option<String>,
}
fn read_frame(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid attachment frame size",
        ));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid attachment frame size",
        ));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()
}
fn handle_raw(
    stream: &mut (impl Read + Write),
    callback: &impl Fn(serde_json::Value) -> serde_json::Value,
) -> io::Result<()> {
    let input = serde_json::from_slice(&read_frame(stream)?).map_err(io::Error::other)?;
    write_frame(
        stream,
        &serde_json::to_vec(&callback(input)).map_err(io::Error::other)?,
    )
}
fn handle_raw_with_peer(
    stream: &mut (impl Read + Write),
    peer: u32,
    callback: &impl Fn(serde_json::Value, u32) -> serde_json::Value,
) -> io::Result<()> {
    let input = serde_json::from_slice(&read_frame(stream)?).map_err(io::Error::other)?;
    write_frame(
        stream,
        &serde_json::to_vec(&callback(input, peer)).map_err(io::Error::other)?,
    )
}
pub fn exchange_raw(endpoint: &str, command: &serde_json::Value) -> io::Result<serde_json::Value> {
    exchange_raw_checked(endpoint, command, None)
}
pub fn exchange_raw_for_process(
    endpoint: &str,
    command: &serde_json::Value,
    pid: u32,
) -> io::Result<serde_json::Value> {
    exchange_raw_checked(endpoint, command, Some(pid))
}
fn exchange_raw_checked(
    endpoint: &str,
    command: &serde_json::Value,
    pid: Option<u32>,
) -> io::Result<serde_json::Value> {
    let mut stream = transport::connect(endpoint)?;
    if let Some(pid) = pid {
        transport::verify_peer(&stream, pid)?;
    }
    write_frame(
        &mut stream,
        &serde_json::to_vec(command).map_err(io::Error::other)?,
    )?;
    serde_json::from_slice(&read_frame(&mut stream)?).map_err(io::Error::other)
}
pub fn exchange(endpoint: &str, command: &AuthenticatedCommand) -> io::Result<HostStatus> {
    exchange_checked(endpoint, command, None)
}
/// Authenticate the server's OS process identity before exposing approval proof.
pub fn exchange_for_process(
    endpoint: &str,
    command: &AuthenticatedCommand,
    pid: u32,
) -> io::Result<HostStatus> {
    exchange_checked(endpoint, command, Some(pid))
}
fn exchange_checked(
    endpoint: &str,
    command: &AuthenticatedCommand,
    pid: Option<u32>,
) -> io::Result<HostStatus> {
    let mut stream = transport::connect(endpoint)?;
    if let Some(pid) = pid {
        transport::verify_peer(&stream, pid)?;
    }
    write_frame(
        &mut stream,
        &serde_json::to_vec(command).map_err(io::Error::other)?,
    )?;
    let reply: Reply =
        serde_json::from_slice(&read_frame(&mut stream)?).map_err(io::Error::other)?;
    match (reply.status, reply.error) {
        (Some(status), None)
            if status.protocol == PROTOCOL
                && status.attachment_id == command.attachment_id
                && pid.is_none_or(|pid| status.pid == pid) =>
        {
            Ok(status)
        }
        (_, Some(error)) => Err(io::Error::new(io::ErrorKind::PermissionDenied, error)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid attachment reply",
        )),
    }
}
pub struct Listener(transport::Listener);
impl Listener {
    pub fn bind(endpoint: &str) -> io::Result<Self> {
        transport::Listener::bind(endpoint).map(Self)
    }
    pub fn run(
        self,
        stop: &AtomicBool,
        callback: impl Fn(AuthenticatedCommand) -> Result<HostStatus, String>,
    ) -> io::Result<()> {
        self.run_with_peer(stop, |request, _| callback(request))
    }
    pub fn run_with_peer(
        self,
        stop: &AtomicBool,
        callback: impl Fn(AuthenticatedCommand, u32) -> Result<HostStatus, String>,
    ) -> io::Result<()> {
        self.0.run_with_peer(stop, |value, peer| {
            let result = serde_json::from_value(value)
                .map_err(|_| "invalid attachment command".to_string())
                .and_then(|request| callback(request, peer));
            let reply = match result {
                Ok(status) => Reply {
                    status: Some(status),
                    error: None,
                },
                Err(error) => Reply {
                    status: None,
                    error: Some(error),
                },
            };
            serde_json::to_value(reply).unwrap_or_else(
                |_| serde_json::json!({"status":null,"error":"cannot encode attachment reply"}),
            )
        })
    }
    pub fn run_raw(
        self,
        stop: &AtomicBool,
        callback: impl Fn(serde_json::Value) -> serde_json::Value,
    ) -> io::Result<()> {
        self.0.run(stop, callback)
    }
    pub fn run_raw_with_peer(
        self,
        stop: &AtomicBool,
        callback: impl Fn(serde_json::Value, u32) -> serde_json::Value,
    ) -> io::Result<()> {
        self.0.run_with_peer(stop, callback)
    }
}
#[cfg(unix)]
#[path = "attachment/unix.rs"]
mod transport;
#[cfg(windows)]
#[path = "attachment/windows.rs"]
mod transport;

#[cfg(windows)]
#[path = "attachment/windows_inject.rs"]
pub mod windows_inject;

mod proof;
pub use proof::{
    verify_proof, verify_proof_with_key, verify_proof_with_key_for_recipient, ApprovalClaims,
    ApprovedAction,
};
mod enrollment;
pub use enrollment::*;
mod process_identity;
pub use process_identity::{process_identity, process_incarnation, ProcessIncarnation};

mod aliases;
pub use aliases::*;
mod dns;
pub use dns::*;

mod root_image;
pub use root_image::*;
mod operation;
pub use operation::*;
mod host_command;
pub use host_command::*;
mod host_command_transport;
pub use host_command_transport::*;

mod continuity;
pub use continuity::*;

#[cfg(test)]
#[path = "attachment/initialization_tests.rs"]
mod initialization_tests;
