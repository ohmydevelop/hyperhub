use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub birth: u64,
    pub executable: String,
    pub executable_sha256: String,
    pub owner: String,
}
impl ProcessIdentity {
    pub fn validate(&self) -> Result<(), String> {
        if self.pid == 0
            || self.birth == 0
            || self.executable.is_empty()
            || self.owner.is_empty()
            || self.executable_sha256.len() != 64
            || !self
                .executable_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("attachment target identity is incomplete".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Process,
    #[default]
    Tree,
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    #[default]
    Auto,
    Ptrace,
    Gum,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    #[serde(default)]
    pub recovery: Option<RecoveryBinding>,
    #[serde(default)]
    pub capabilities: super::CapabilityReport,
    pub id: String,
    pub target: ProcessIdentity,
    #[serde(default)]
    pub current_target: Option<ProcessIdentity>,
    #[serde(default)]
    pub exec_epoch: u64,
    pub scope: Scope,
    pub backend: Backend,
    pub policy_digest: String,
}
impl Spec {
    pub fn effective_target(&self) -> &ProcessIdentity {
        self.current_target.as_ref().unwrap_or(&self.target)
    }
}
impl ProcessIdentity {
    pub fn root_image_identity(&self) -> hyperhub_runtime::attachment::RootImageIdentity {
        hyperhub_runtime::attachment::RootImageIdentity {
            pid: self.pid,
            birth: self.birth,
            executable_sha256: self.executable_sha256.clone(),
        }
    }
    pub fn same_incarnation(&self, other: &Self) -> bool {
        self.pid == other.pid && self.birth == other.birth && self.owner == other.owner
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Attach {
        spec: Spec,
    },
    Detach {
        #[serde(default)]
        exec_epoch: u64,
        attachment_id: String,
        target: ProcessIdentity,
        policy_digest: String,
        #[serde(default)]
        recovery: Option<RecoveryBinding>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBinding {
    pub manager: ProcessIdentity,
    pub context_digest: String,
}
impl Action {
    pub fn exec_epoch(&self) -> u64 {
        match self {
            Self::Attach { spec } => spec.exec_epoch,
            Self::Detach { exec_epoch, .. } => *exec_epoch,
        }
    }
    pub fn recovery(&self) -> Option<&RecoveryBinding> {
        match self {
            Self::Attach { spec } => spec.recovery.as_ref(),
            Self::Detach { recovery, .. } => recovery.as_ref(),
        }
    }
    pub fn target(&self) -> &ProcessIdentity {
        match self {
            Self::Attach { spec } => spec.effective_target(),
            Self::Detach { target, .. } => target,
        }
    }
    pub fn attachment_id(&self) -> &str {
        match self {
            Self::Attach { spec } => &spec.id,
            Self::Detach { attachment_id, .. } => attachment_id,
        }
    }
    pub fn policy_digest(&self) -> &str {
        match self {
            Self::Attach { spec } => &spec.policy_digest,
            Self::Detach { policy_digest, .. } => policy_digest,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub id: String,
    pub instance_id: String,
    pub created_at_ms: u64,
    pub action: Action,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StaleRequestReason {
    InstanceChanged,
    PolicyChanged,
    ExecutableEpochChanged { expected: u64, current: u64 },
}
impl std::fmt::Display for StaleRequestReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InstanceChanged => f.write_str("configuration instance changed"),
            Self::PolicyChanged => f.write_str("policy changed"),
            Self::ExecutableEpochChanged { expected, current } => write!(
                f,
                "root executable epoch changed from {expected} to {current}"
            ),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StaleRequestAudit {
    pub schema_version: u32,
    pub request_id: String,
    pub reason: StaleRequestReason,
    pub archived_at_ms: u64,
}
impl Request {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !super::valid_id(&self.id)
            || !super::valid_id(self.action.attachment_id())
            || self.instance_id.len() != 64
            || self.action.policy_digest().len() != 64
        {
            return Err("invalid attachment approval request".into());
        }
        if let Some(recovery) = self.action.recovery() {
            recovery.manager.validate()?;
            if recovery.context_digest.len() != 64
                || !recovery
                    .context_digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
            {
                return Err("invalid sealed recovery context fingerprint".into());
            }
        }
        if let Action::Attach { spec } = &self.action {
            spec.target.validate()?;
            if !spec.target.same_incarnation(spec.effective_target()) {
                return Err(
                    "current executable cannot change the approved process incarnation".into(),
                );
            }
        }
        self.action.target().validate()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub request: Request,
    pub approved_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: [u8; 32],
    pub executor_sha256: String,
    pub execution_digest: Option<String>,
    #[serde(default)]
    pub host_binding: Option<String>,
    #[serde(default)]
    pub core_attestation_public_key: Option<[u8; 32]>,
    #[serde(default)]
    pub manager_claimant: Option<hyperhub_runtime::attachment::ManagerClaimant>,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparing,
    Active,
    Detaching,
    Draining,
    DetachedResident,
    Detached,
    Degraded,
    Failed,
    CleanupPending,
    Exited,
}
impl Phase {
    pub fn is_attached(self) -> bool {
        matches!(self, Self::Preparing | Self::Active | Self::Detaching)
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Detached | Self::Exited | Self::Failed)
    }
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    #[default]
    Attach,
    Run,
}
impl Origin {
    pub fn native_dns_mode(self) -> hyperhub_runtime::attachment::NativeDnsMode {
        match self {
            Self::Attach => hyperhub_runtime::attachment::NativeDnsMode::PreserveAnswers,
            Self::Run => hyperhub_runtime::attachment::NativeDnsMode::SyntheticPool,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagerExecutionProfile {
    pub attachment_id: String,
    pub session_id: String,
    pub origin: Origin,
    pub native_dns_mode: hyperhub_runtime::attachment::NativeDnsMode,
    pub host_binding: String,
}
impl ManagerExecutionProfile {
    pub fn from_bootstrap(
        bootstrap: &hyperhub_runtime::attachment::Bootstrap,
        origin: Origin,
    ) -> Result<Self, String> {
        if bootstrap.native_dns_mode != origin.native_dns_mode()
            || bootstrap.external_attachment != (origin == Origin::Attach)
        {
            return Err("attachment origin differs from immutable native DNS mode".into());
        }
        Ok(Self {
            attachment_id: bootstrap.attachment_id.clone(),
            session_id: bootstrap.session_id.clone(),
            origin,
            native_dns_mode: bootstrap.native_dns_mode,
            host_binding: bootstrap.approval_binding().map_err(|e| e.to_string())?,
        })
    }
    pub fn validate_record(&self, record: &Record) -> Result<(), String> {
        if self.attachment_id != record.spec.id
            || self.session_id != record.session_id
            || self.origin != record.origin
            || self.native_dns_mode != self.origin.native_dns_mode()
            || record.host_binding.as_ref() != Some(&self.host_binding)
        {
            return Err(
                "record origin/session differs from proven immutable execution profile".into(),
            );
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub spec: Spec,
    #[serde(default)]
    pub current_target: Option<ProcessIdentity>,
    #[serde(default)]
    pub exec_epoch: u64,
    #[serde(default)]
    pub host_binding: Option<String>,
    #[serde(default)]
    pub origin: Origin,
    #[serde(default)]
    pub session_id: String,
    pub phase: Phase,
    pub members: Vec<ProcessIdentity>,
    pub manager: Option<ProcessIdentity>,
    pub manager_endpoint: Option<String>,
    pub compatibility_reasons: Vec<String>,
    pub error: Option<String>,
    pub updated_at_ms: u64,
}
impl Record {
    pub fn effective_target(&self) -> &ProcessIdentity {
        self.current_target
            .as_ref()
            .unwrap_or_else(|| self.spec.effective_target())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub phase: Phase,
    pub members: Vec<ProcessIdentity>,
    pub compatibility_reasons: Vec<String>,
    pub manager: Option<ProcessIdentity>,
    pub manager_endpoint: Option<String>,
}
/// This contains credentials and must only be persisted using save_execution.
/// Public status serializes Record, never Execution.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub spec: Spec,
    #[serde(default)]
    pub origin: Origin,
    pub bootstrap: hyperhub_runtime::attachment::Bootstrap,
    pub state_directory: PathBuf,
    pub authorization: Authorization,
}

/// Transport credential whose Debug output is always redacted.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Credential(String);
impl From<String> for Credential {
    fn from(value: String) -> Self {
        Self(value)
    }
}
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}
impl Credential {
    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}
impl std::fmt::Debug for Execution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Execution")
            .field("spec", &self.spec)
            .field("origin", &self.origin)
            .field("state_directory", &self.state_directory)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

/// Locators only. Core authenticates the actual Host peer and reads issued
/// alias state itself; callers cannot submit allocator contents as authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBootstrapBinding {
    pub identity: ProcessIdentity,
    pub bootstrap: hyperhub_runtime::attachment::Bootstrap,
}
