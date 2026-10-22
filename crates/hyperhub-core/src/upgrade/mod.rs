//! Durable Engine participant transactions in resident Serve. The release
//! coordinator will combine this component with workers and installer helpers.
mod driver;
pub(crate) mod store;

use crate::engine_hosts::{HostStatus, OwnerCommand};
use crate::session::unix_timestamp_ms;
use hmac::{Hmac, Mac};
use hyperhub_engine::host::Backend;
use hyperhub_runtime::{Manifest, Stage};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io;
use std::path::PathBuf;

pub use driver::Coordinator;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Prepare {
        manifest: Manifest,
        source: PathBuf,
        cache: PathBuf,
        hosts: Vec<String>,
    },
    PrepareAll {
        native_base_sha256: String,
        manifest: Manifest,
        source: PathBuf,
        cache: PathBuf,
        hosts: Vec<String>,
    },
    Commit,
    Abort,
    Rollback {
        reason: String,
    },
    Observe,
    ObserveHeld,
    Finalize,
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
    fn mac(&self, key: &[u8]) -> io::Result<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(io::Error::other)?;
        mac.update(b"hyperhub-engine-rollout-owner-v1\0");
        mac.update(&serde_json::to_vec(self).map_err(io::Error::other)?);
        Ok(mac)
    }
    pub fn proof(&self, key: &[u8]) -> io::Result<Vec<u8>> {
        Ok(self.mac(key)?.finalize().into_bytes().to_vec())
    }
    pub fn authenticate(&self, key: &[u8], proof: &[u8]) -> bool {
        valid_id(&self.id)
            && self.issued_at_ms.abs_diff(unix_timestamp_ms()) <= 30_000
            && self
                .mac(key)
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparing,
    Prepared,
    Switching,
    Committed,
    Observing,
    Finalizing,
    Draining,
    Complete,
    Aborting,
    Aborted,
    RollingBack,
    RolledBack,
    RequiresRestart,
    Failed,
}
impl Phase {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Complete
                | Self::Aborted
                | Self::RolledBack
                | Self::RequiresRestart
                | Self::Failed
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    #[serde(default)]
    pub session_id: String,
    pub backend: Backend,
    pub host_pid: u32,
    #[serde(default)]
    pub host_start_time: u64,
    #[serde(default)]
    pub member_instance: u64,
    pub root_pid: u32,
    pub root_start_time: u64,
}
impl Identity {
    fn from_host(host: &HostStatus) -> io::Result<Self> {
        let host_start_time = host
            .host_start_time
            .filter(|time| *time != 0)
            .ok_or_else(|| {
                io::Error::other("Host process creation time is unavailable; requires_restart")
            })?;
        let root_start_time = host
            .root_start_time
            .filter(|time| *time != 0)
            .or((host.backend == Backend::LinuxPtrace).then_some(host_start_time))
            .ok_or_else(|| {
                io::Error::other("Host process creation time is unavailable; requires_restart")
            })?;
        Ok(Self {
            session_id: host.session_id.clone(),
            backend: host.backend,
            host_pid: host.host_pid,
            host_start_time,
            member_instance: host.member_instance,
            root_pid: host.root_pid,
            root_start_time,
        })
    }
    fn matches(&self, host: &HostStatus) -> bool {
        host.online
            && host.session_id == self.session_id
            && host.backend == self.backend
            && host.host_pid == self.host_pid
            && host.host_start_time == Some(self.host_start_time)
            && host.member_instance == self.member_instance
            && host.root_pid == self.root_pid
            && (self.backend == Backend::LinuxPtrace
                || host.root_start_time == Some(self.root_start_time))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub identity: Identity,
    pub host_id: String,
    pub previous_generation: u64,
    pub generation: Option<u64>,
    pub stage: Option<Stage>,
    pub reason: Option<String>,
    pub confirmed: bool,
    pub finalized: bool,
    pub cleanup_done: bool,
    pub exited: bool,
    #[serde(default)]
    pub exit_clean: bool,
    pub(crate) sequence: u64,
    pub(crate) pending: Option<Pending>,
    pub(crate) recovering: bool,
    #[serde(default)]
    pub(crate) exit_wait_started_ms: Option<u64>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    request: OwnerCommand,
    purpose: Purpose,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Purpose {
    Prepare,
    Commit,
    Abort,
    Rollback,
    Recover,
    Finalize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: String,
    #[serde(default)]
    pub native_base_sha256: String,
    pub manifest: Manifest,
    pub phase: Phase,
    pub reason: Option<String>,
    pub participants: Vec<Participant>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub health_started_at_ms: Option<u64>,
    #[serde(default)]
    pub(crate) finalize_decided: bool,
    #[serde(default)]
    pub(crate) all_sessions: bool,
    #[serde(default)]
    pub(crate) defer_finalize: bool,
    #[serde(default)]
    pub(crate) finalize_order: u64,
    pub(crate) source: PathBuf,
    pub(crate) cache: PathBuf,
    pub(crate) rollback_requested: bool,
    pub(crate) restart_requested: bool,
    pub(crate) preparing_deadline_ms: u64,
    pub(crate) health_window_ms: u64,
    pub(crate) prepare_digest: String,
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
    pub manifest: Manifest,
    pub phase: Phase,
    pub reason: Option<String>,
    pub participants: Vec<ParticipantView>,
    pub participants_omitted: usize,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub health_started_at_ms: Option<u64>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParticipantView {
    pub identity: Identity,
    pub host_id: String,
    pub previous_generation: u64,
    pub generation: Option<u64>,
    pub stage: Option<Stage>,
    pub reason: Option<String>,
    pub confirmed: bool,
    pub finalized: bool,
    pub cleanup_done: bool,
    pub exited: bool,
    #[serde(default)]
    pub exit_clean: bool,
    pub awaiting: Option<String>,
    pub recovering: bool,
}
impl RecordView {
    pub fn from_record(record: &Record, detail: bool) -> Self {
        let participants = if detail {
            record
                .participants
                .iter()
                .map(|p| ParticipantView {
                    identity: p.identity.clone(),
                    host_id: p.host_id.clone(),
                    previous_generation: p.previous_generation,
                    generation: p.generation,
                    stage: p.stage,
                    reason: p.reason.as_deref().map(short_reason),
                    confirmed: p.confirmed,
                    finalized: p.finalized,
                    cleanup_done: p.cleanup_done,
                    exited: p.exited,
                    exit_clean: p.exit_clean,
                    awaiting: p
                        .pending
                        .as_ref()
                        .map(|pending| format!("{:?}", pending.purpose).to_ascii_lowercase()),
                    recovering: p.recovering,
                })
                .collect()
        } else {
            Vec::new()
        };
        Self {
            id: record.id.clone(),
            manifest: record.manifest.clone(),
            phase: record.phase,
            reason: record.reason.as_deref().map(short_reason),
            participants,
            participants_omitted: if detail { 0 } else { record.participants.len() },
            created_at_ms: record.created_at_ms,
            updated_at_ms: record.updated_at_ms,
            health_started_at_ms: record.health_started_at_ms,
        }
    }
}
fn short_reason(reason: &str) -> String {
    let mut text: String = reason.chars().take(256).collect();
    if reason.chars().count() > 256 {
        text.push_str(" [truncated]");
    }
    text
}

// Product deployments are stable numeric releases; build metadata does not
// change precedence. Unknown/prerelease versions never authorize a downgrade.
pub(crate) fn stable_version(version: &str) -> Option<[u64; 3]> {
    let version = version.split('+').next()?;
    let mut result = [0; 3];
    let parts: Vec<_> = version.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    for (index, part) in parts.into_iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        result[index] = part.parse().ok()?;
    }
    Some(result)
}
fn not_older(candidate: &Manifest, host: &Manifest) -> bool {
    stable_version(&candidate.version)
        .zip(stable_version(&host.version))
        .is_some_and(|(candidate, host)| candidate >= host)
}
