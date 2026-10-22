//! Product upgrades continue in resident Serve after the initiating CLI exits.
//! Engine and forwarding participants share an irreversible finalize decision;
//! installation is acknowledged separately and never restarts managed targets.
mod coordinator;
pub mod installer;

pub use coordinator::Coordinator;
use hmac::{Hmac, Mac};
use hyperhub_runtime::Manifest;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Base {
    pub abi: u32,
    pub state_schema: u32,
    pub hooks: u64,
    pub frida_version: String,
    pub worker_protocol: u32,
    pub installer_protocol: u32,
    pub native_base_sha256: String,
    pub serve_base_sha256: String,
}
impl Base {
    pub fn resident() -> Self {
        Self {
            abi: hyperhub_runtime::abi::ABI_V1,
            state_schema: hyperhub_engine::contract::STATE_SCHEMA,
            hooks: hyperhub_engine::contract::REQUIRED_OPERATIONS,
            frida_version: "17.17.0".into(),
            worker_protocol: crate::socks::SocksService::forward_worker_protocol(),
            installer_protocol: 1,
            native_base_sha256: hyperhub_engine::NATIVE_BASE_SHA256.into(),
            serve_base_sha256: hyperhub_engine::SERVE_BASE_SHA256.into(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: u32,
    pub version: String,
    pub target: String,
    pub base: Base,
    pub engine: Manifest,
    pub engine_file: String,
    pub worker_sha256: String,
    pub worker_size: u64,
}
impl Bundle {
    pub fn validate(&self) -> io::Result<()> {
        self.engine.validate().map_err(io::Error::other)?;
        if self.format != 1
            || self.version != self.engine.version
            || self.target != self.engine.target
            || self.base.abi != self.engine.abi
            || self.base.state_schema != self.engine.state_schema
            || self.base.hooks != self.engine.hooks
            || self.base.frida_version.is_empty()
            || !installer::valid_hash(&self.base.native_base_sha256)
            || !installer::valid_hash(&self.base.serve_base_sha256)
            || self.worker_size == 0
            || self.worker_size > installer::MAX_EXECUTABLE
            || !installer::valid_hash(&self.worker_sha256)
            || self.engine_file != engine_name()
        {
            return Err(io::Error::other("invalid release bundle manifest"));
        }
        Ok(())
    }
}
pub fn engine_name() -> &'static str {
    if cfg!(windows) {
        "hyperhub_engine.dll"
    } else {
        "libhyperhub_engine.so"
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub bundle: Bundle,
    pub executable: PathBuf,
    pub engine: PathBuf,
    pub cache: PathBuf,
    pub target: PathBuf,
    pub expected_target_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Prepare { plan: Plan, auto_commit: bool },
    Commit,
    Abort,
    Recover,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub issued_at_ms: u64,
    pub action: Action,
}
impl Request {
    pub fn proof(&self, key: &[u8]) -> io::Result<Vec<u8>> {
        Ok(mac(key, b"hyperhub-release-owner-v1\0", self)?
            .finalize()
            .into_bytes()
            .to_vec())
    }
    pub fn authenticate(&self, key: &[u8], proof: &[u8]) -> bool {
        valid_id(&self.id)
            && self
                .issued_at_ms
                .abs_diff(crate::session::unix_timestamp_ms())
                <= 30_000
            && mac(key, b"hyperhub-release-owner-v1\0", self)
                .is_ok_and(|mac| mac.verify_slice(proof).is_ok())
    }
}
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
pub(crate) fn mac(key: &[u8], purpose: &[u8], value: &impl Serialize) -> io::Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(io::Error::other)?;
    mac.update(purpose);
    mac.update(&serde_json::to_vec(value).map_err(io::Error::other)?);
    Ok(mac)
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparing,
    Prepared,
    Switching,
    Observing,
    Finalizing,
    Installing,
    InstallationPending,
    Draining,
    Complete,
    RollingBack,
    RolledBack,
    RequiresRestart,
    Failed,
}
impl Phase {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::RolledBack | Self::RequiresRestart | Self::Failed
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Status {
    pub records: Vec<RecordView>,
    pub records_omitted: usize,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecordView {
    pub id: String,
    pub version: String,
    pub phase: Phase,
    pub reason: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub finalize_decided: bool,
    pub installation_confirmed: bool,
    pub engine_hosts: usize,
    pub worker_generation: Option<u64>,
    pub worker_pid: Option<u32>,
    pub helper_pid: Option<u32>,
    pub requires_restart_processes: Vec<u32>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    plan: Plan,
    phase: Phase,
    reason: Option<String>,
    created_at_ms: u64,
    updated_at_ms: u64,
    prepare_deadline_ms: u64,
    health_started_at_ms: Option<u64>,
    commit_requested: bool,
    abort_requested: bool,
    finalize_decided: bool,
    installation_confirmed: bool,
    hosts: Vec<String>,
    worker_generation: Option<u64>,
    worker_pid: Option<u32>,
    helper_pid: Option<u32>,
    helper_started_at_ms: Option<u64>,
    helper_attempt: u32,
    prepare_digest: String,
    requires_restart_processes: Vec<u32>,
    uncovered_since_ms: Option<u64>,
    restart_requested: bool,
}
impl Record {
    fn view(&self) -> RecordView {
        RecordView {
            id: self.id.clone(),
            version: self.plan.bundle.version.clone(),
            phase: self.phase,
            reason: self.reason.clone(),
            created_at_ms: self.created_at_ms,
            updated_at_ms: self.updated_at_ms,
            finalize_decided: self.finalize_decided,
            installation_confirmed: self.installation_confirmed,
            engine_hosts: self.hosts.len(),
            worker_generation: self.worker_generation,
            worker_pid: self.worker_pid,
            helper_pid: self.helper_pid,
            requires_restart_processes: self.requires_restart_processes.clone(),
        }
    }
}
