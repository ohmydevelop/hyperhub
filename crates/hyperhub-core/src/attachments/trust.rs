//! Process-local approval anchors. Disk records are audit material, never roots.
use super::{Authorization, ProcessIdentity};
use crate::config_store::KdfDescriptor;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAuthority {
    pub instance_id: String,
    pub config_id: [u8; 16],
    pub public_key: [u8; 32],
    pub generation: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnrollmentChallenge {
    pub nonce: String,
    pub peer: ProcessIdentity,
    pub descriptor: KdfDescriptor,
    pub config_digest: String,
    pub instance_id: String,
    pub expires_at_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnrollment {
    pub challenge: ApprovalEnrollmentChallenge,
    pub authority: ApprovalAuthority,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTrustView {
    pub authority: Option<ApprovalAuthority>,
    pub expected_authority: Option<ApprovalAuthority>,
    pub core_pid: u32,
    pub core_birth: u64,
    pub core_public_key: [u8; 32],
}
use super::enrollment_origins::{extend_origins, EnrollmentOrigin, MAX_ORIGINS};

struct State {
    authority: Option<ApprovalAuthority>,
    expected_authority: Option<ApprovalAuthority>,
    endpoint: Option<String>,
    remote_core_public_key: Option<[u8; 32]>,
    core_key: SigningKey,
    enrollment_origins: Vec<EnrollmentOrigin>,
    challenges: HashMap<String, ApprovalEnrollmentChallenge>,
    consumed: HashMap<String, Vec<u8>>,
    completions: HashMap<String, Vec<u8>>,
    activation_epochs: HashMap<String, (String, u64)>,
    approval_continuity: Vec<hyperhub_runtime::attachment::SignedApprovalRootTransition>,
    preparations: HashMap<String, super::preparation::PreparationMemory>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            authority: None,
            expected_authority: None,
            endpoint: None,
            remote_core_public_key: None,
            core_key: SigningKey::from_bytes(&rand::random()),
            enrollment_origins: EnrollmentOrigin::current().into_iter().collect(),
            challenges: HashMap::new(),
            consumed: HashMap::new(),
            completions: HashMap::new(),
            activation_epochs: HashMap::new(),
            approval_continuity: Vec::new(),
            preparations: HashMap::new(),
        }
    }
}
fn state(directory: &Path) -> Arc<Mutex<State>> {
    static STATES: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<State>>>>> = OnceLock::new();
    let path = directory
        .canonicalize()
        .unwrap_or_else(|_| directory.to_path_buf());
    STATES
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(path)
        .or_default()
        .clone()
}
pub fn approval_trust(directory: &Path) -> Result<ApprovalTrustView, String> {
    // Fix the filesystem identity before retaining a Core key. In particular,
    // Windows canonicalization adds the extended prefix after creation.
    super::private_directory(directory)?;
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    Ok(ApprovalTrustView {
        authority: s.authority.clone(),
        expected_authority: s.expected_authority.clone(),
        core_pid: std::process::id(),
        core_birth: super::process_birth(std::process::id())
            .ok_or("cannot identify Core incarnation")?,
        core_public_key: s.core_key.verifying_key().to_bytes(),
    })
}
pub fn trusted_authority(directory: &Path) -> Result<ApprovalAuthority, String> {
    approval_trust(directory)?.authority.ok_or_else(|| {
        "approval authority is unenrolled; a real administrator approval is required".into()
    })
}
pub(crate) fn pin_authority(
    directory: &Path,
    authority: ApprovalAuthority,
    endpoint: Option<String>,
) -> Result<(), String> {
    super::private_directory(directory)?;
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    if s.authority.as_ref().is_some_and(|old| old != &authority) {
        return Err("approval root changed; a verified rotation chain is required".into());
    }
    s.authority = Some(authority);
    if endpoint.is_some() {
        s.endpoint = endpoint;
    }
    Ok(())
}
pub(crate) fn invalidate_memory_authority(directory: &Path) {
    if let Ok(mut s) = state(directory).lock() {
        s.authority = None;
    }
}
pub(crate) fn remote_endpoint(directory: &Path) -> Option<String> {
    state(directory).lock().ok()?.endpoint.clone()
}
pub(crate) fn remember_consumption(
    directory: &Path,
    nonce: &[u8; 32],
    bytes: Vec<u8>,
) -> Result<(), String> {
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let id = super::digest(nonce);
    if s.consumed.contains_key(&id) {
        return Err("attachment authorization was already consumed".into());
    }
    s.consumed.insert(id, bytes);
    Ok(())
}
pub(crate) fn trusted_consumption(directory: &Path, nonce: &[u8; 32]) -> Option<Vec<u8>> {
    state(directory)
        .lock()
        .ok()?
        .consumed
        .get(&super::digest(nonce))
        .cloned()
}
pub(crate) fn remember_completion(directory: &Path, id: String, bytes: Vec<u8>) {
    if let Ok(mut s) = state(directory).lock() {
        s.completions.insert(id, bytes);
    }
}
pub(crate) fn trusted_completion(directory: &Path, id: &str) -> Option<Vec<u8>> {
    state(directory).lock().ok()?.completions.get(id).cloned()
}
pub(crate) fn challenge(
    directory: &Path,
    config: &Path,
    peer: ProcessIdentity,
) -> Result<ApprovalEnrollmentChallenge, String> {
    super::private_directory(directory)?;
    let descriptor = crate::config_store::read_descriptor(config).map_err(|e| e.to_string())?;
    let value = ApprovalEnrollmentChallenge {
        nonce: super::new_id() + &super::new_id(),
        peer,
        instance_id: super::instance_id(config, &descriptor),
        descriptor,
        config_digest: super::digest(&std::fs::read(config).map_err(|e| e.to_string())?),
        expires_at_ms: crate::session::unix_timestamp_ms() + 60_000,
    };
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    s.challenges
        .retain(|_, c| c.expires_at_ms > crate::session::unix_timestamp_ms());
    if s.challenges.len() >= 64 {
        return Err("too many pending approval enrollments".into());
    }
    s.challenges.insert(value.nonce.clone(), value.clone());
    Ok(value)
}
pub(crate) fn enroll_password(
    directory: &Path,
    config: &Path,
    nonce: &str,
    password: &[u8],
    peer: &ProcessIdentity,
) -> Result<(), String> {
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let expected = s
        .challenges
        .remove(nonce)
        .ok_or("approval enrollment challenge is unknown or already consumed")?;
    if &expected.peer != peer
        || expected.expires_at_ms <= crate::session::unix_timestamp_ms()
        || expected.config_digest
            != super::digest(&std::fs::read(config).map_err(|e| e.to_string())?)
    {
        return Err("approval enrollment challenge rejected".into());
    }
    // The password, not a candidate public key or peer executable name, is the
    // authentication proof. Only a public verifier survives this function.
    let unlocked =
        crate::config_store::load_encrypted(config, password).map_err(|e| e.to_string())?;
    if unlocked.descriptor != expected.descriptor {
        return Err("configuration generation changed during enrollment".into());
    }
    let key = super::authority::signing_key(password, &unlocked.descriptor)?;
    let authority = ApprovalAuthority {
        instance_id: expected.instance_id,
        config_id: unlocked.descriptor.config_id,
        public_key: key.verifying_key().to_bytes(),
        generation: unlocked.approval_continuity.len() as u64,
    };
    if s.expected_authority
        .as_ref()
        .is_some_and(|old| old != &authority)
        || s.authority.as_ref().is_some_and(|old| old != &authority)
    {
        return Err("approval root changed; a verified rotation chain is required".into());
    }
    s.authority = Some(authority);
    Ok(())
}
pub fn pin_expected_approval_anchor(
    directory: &Path,
    authority: ApprovalAuthority,
) -> Result<(), String> {
    super::private_directory(directory)?;
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    if s.expected_authority
        .as_ref()
        .is_some_and(|old| old != &authority)
    {
        return Err("startup approval anchor is already fixed".into());
    }
    s.expected_authority = Some(authority);
    Ok(())
}
/// Fetch only from the OS-authenticated trusted Core executable. Never enroll
/// this process from a writable verifier, Bootstrap, ledger or discovery file.
pub async fn import_core_trust(
    directory: &Path,
    endpoint: &str,
) -> Result<ApprovalTrustView, String> {
    super::private_directory(directory)?;
    let response = crate::control::trusted_control_request(
        endpoint,
        &crate::session::ControlRequest::GetApprovalTrust,
    )
    .await
    .map_err(|e| e.to_string())?;
    let crate::session::ControlResponse::ApprovalTrust { trust } = response else {
        return Err("Core did not return approval trust".into());
    };
    {
        let shared = state(directory);
        let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
        s.remote_core_public_key = Some(trust.core_public_key);
    }
    if let Some(authority) = trust.authority.clone() {
        pin_authority(directory, authority, Some(endpoint.into()))?;
    }
    Ok(trust)
}
pub async fn enroll_core_authority(
    directory: &Path,
    endpoint: &str,
    config: &Path,
    password: &[u8],
) -> Result<ApprovalTrustView, String> {
    crate::control::password_approval_enrollment(endpoint, config, password).await?;
    import_core_trust(directory, endpoint).await
}

/// Sign only the fixed memory authority for an existing authenticated session.
pub(crate) fn core_host_enrollment(
    directory: &Path,
    bootstrap: &hyperhub_runtime::attachment::Bootstrap,
    challenge: &hyperhub_runtime::attachment::ApprovalEnrollmentChallenge,
) -> Result<hyperhub_runtime::attachment::ApprovalRootCertificate, String> {
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let authority = s
        .authority
        .as_ref()
        .ok_or("administrator authority is unenrolled")?;
    let origin = EnrollmentOrigin {
        pid: bootstrap.approval_core_pid,
        birth: bootstrap.approval_core_birth,
    };
    if !s.enrollment_origins.contains(&origin)
        || origin.pid == 0
        || origin.birth == 0
        || bootstrap.approval_core_public_key != Some(s.core_key.verifying_key().to_bytes())
        || bootstrap.approval_instance_id != authority.instance_id
    {
        return Err(
            "the original Host Core attestation identity is unavailable after cold startup".into(),
        );
    }
    let now = crate::session::unix_timestamp_ms();
    if challenge.host_pid == 0
        || challenge.host_birth == 0
        || challenge.challenge == [0; 32]
        || challenge.expires_at_ms <= now
        || challenge.expires_at_ms > now + 60_000
    {
        return Err("Host enrollment challenge expired or invalid".into());
    }
    let value = hyperhub_runtime::attachment::EnrollmentPayload {
        schema_version: 1,
        source: "core".into(),
        instance_id: authority.instance_id.clone(),
        attachment_id: bootstrap.attachment_id.clone(),
        root_pid: bootstrap.root_pid,
        host_pid: challenge.host_pid,
        host_birth: challenge.host_birth,
        challenge: challenge.challenge,
        approval_public_key: authority.public_key,
        generation: authority.generation,
        core_pid: origin.pid,
        core_birth: origin.birth,
        issued_at_ms: now,
        expires_at_ms: challenge.expires_at_ms,
    };
    let mut payload = hyperhub_runtime::attachment::ENROLLMENT_DOMAIN.to_vec();
    payload.extend(serde_json::to_vec(&value).map_err(|e| e.to_string())?);
    let signature = s.core_key.sign(&payload).to_bytes().to_vec();
    Ok(hyperhub_runtime::attachment::ApprovalRootCertificate { payload, signature })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalStatus {
    pub state: String,
    pub expected_root: bool,
    pub generation: Option<u64>,
    pub legacy_unanchored_hosts_require_original_core: bool,
}
pub fn approval_status(directory: &Path) -> Result<ApprovalStatus, String> {
    let view = approval_trust(directory)?;
    Ok(ApprovalStatus {
        state: if view.authority.is_some() {
            "enrolled"
        } else {
            "unenrolled"
        }
        .into(),
        expected_root: view.expected_authority.is_some(),
        generation: view.authority.as_ref().map(|a| a.generation),
        legacy_unanchored_hosts_require_original_core: true,
    })
}

pub(crate) fn cancel_approval_challenge(directory: &Path, nonce: &str) {
    let shared = state(directory);
    if let Ok(mut s) = shared.lock() {
        s.challenges.remove(nonce);
    };
}
#[cfg(test)]
pub(crate) fn approval_challenge_pending(directory: &Path, nonce: &str) -> bool {
    state(directory)
        .lock()
        .is_ok_and(|s| s.challenges.contains_key(nonce))
}

pub(crate) fn activation_epoch(directory: &Path, id: &str) -> Option<String> {
    state(directory)
        .lock()
        .ok()?
        .activation_epochs
        .get(id)
        .map(|v| v.0.clone())
}
pub(crate) fn activate_epoch(directory: &Path, grant: &Authorization) -> Result<(), String> {
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let id = grant.request.action.attachment_id().to_owned();
    let nonce = super::digest(&grant.nonce);
    if let Some((previous, time)) = s.activation_epochs.get(&id) {
        if previous == &nonce {
            return Ok(());
        }
        if grant.approved_at_ms <= *time {
            return Err(
                "attachment activation grant predates the current authorization epoch".into(),
            );
        }
    }
    s.activation_epochs
        .insert(id, (nonce, grant.approved_at_ms));
    Ok(())
}
pub(crate) fn reject_stale_detach(directory: &Path, grant: &Authorization) -> Result<(), String> {
    if !matches!(grant.request.action, super::Action::Detach { .. }) {
        return Ok(());
    }
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    if s.activation_epochs
        .get(grant.request.action.attachment_id())
        .is_some_and(|(_, time)| grant.approved_at_ms <= *time)
    {
        return Err("detach approval predates the current activation epoch".into());
    }
    Ok(())
}
/// Final revocation linearizes with new activations under the same memory lock.
/// A prior detach receipt cannot revoke membership admitted by a newer Attach.
pub(crate) fn under_consumed_epoch<T>(
    directory: &Path,
    grant: &Authorization,
    action: impl FnOnce() -> T,
) -> Result<T, String> {
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let bytes = s
        .consumed
        .get(&super::digest(&grant.nonce))
        .ok_or("operation has no trusted acceptance")?;
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let epoch = value
        .get("activation_epoch")
        .and_then(serde_json::Value::as_str);
    let current = s
        .activation_epochs
        .get(grant.request.action.attachment_id())
        .map(|v| v.0.as_str());
    if epoch != current {
        return Err("detach operation was superseded by a fresh attachment epoch".into());
    }
    Ok(action())
}

pub(crate) fn remote_core_key(directory: &Path) -> Option<[u8; 32]> {
    state(directory).lock().ok()?.remote_core_public_key
}

/// Sign only a typed session history. The ephemeral private key never leaves Core memory.
pub(crate) fn sign_session_aliases(
    directory: &Path,
    payload: &hyperhub_runtime::attachment::AliasSnapshotPayload,
) -> Result<hyperhub_runtime::attachment::SignedSessionAliasSnapshot, String> {
    let payload =
        hyperhub_runtime::attachment::encode_alias_payload(payload).map_err(|e| e.to_string())?;
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    if s.endpoint.is_some() {
        return Err("only the owning Core may sign alias history".into());
    }
    let signature = s.core_key.sign(&payload).to_bytes().to_vec();
    Ok(hyperhub_runtime::attachment::SignedSessionAliasSnapshot { payload, signature })
}

pub(crate) fn sign_root_image_payload(
    directory: &Path,
    payload: &hyperhub_runtime::attachment::RootImagePayload,
) -> Result<hyperhub_runtime::attachment::SignedRootImage, String> {
    let payload = hyperhub_runtime::attachment::encode_root_image_payload(payload)
        .map_err(|e| e.to_string())?;
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    if s.endpoint.is_some() {
        return Err("only owning Core may attest root image epochs".into());
    }
    let signature = s.core_key.sign(&payload).to_bytes().to_vec();
    Ok(hyperhub_runtime::attachment::SignedRootImage { payload, signature })
}

pub(crate) fn sign_accepted_operation(
    directory: &Path,
    accepted: &hyperhub_runtime::attachment::AcceptedOperationPayload,
) -> Result<hyperhub_runtime::attachment::AcceptedOperationCertificate, String> {
    let payload = hyperhub_runtime::attachment::encode_accepted_operation(accepted)
        .map_err(|e| e.to_string())?;
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let authority = s
        .authority
        .as_ref()
        .ok_or("approval authority is unenrolled")?;
    if s.endpoint.is_some()
        || accepted.challenge.scope.instance_id != authority.instance_id
        || accepted.challenge.scope.core_public_key != s.core_key.verifying_key().to_bytes()
    {
        return Err("accepted operation is not scoped to the owning enrolled Core".into());
    }
    let signature = s.core_key.sign(&payload).to_bytes().to_vec();
    Ok(hyperhub_runtime::attachment::AcceptedOperationCertificate { payload, signature })
}

#[cfg(test)]
#[path = "continuity_tests.rs"]
mod continuity_tests;

/// Only authenticated configuration startup metadata may install this history.
pub(crate) fn pin_approval_continuity(
    directory: &Path,
    chain: Vec<hyperhub_runtime::attachment::SignedApprovalRootTransition>,
) -> Result<(), String> {
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let Some(expected) = s.expected_authority.as_ref() else {
        return if chain.is_empty() {
            Ok(())
        } else {
            Err("approval history requires a startup anchor".into())
        };
    };
    if chain.is_empty() {
        if expected.generation != 0 {
            return Err("approval history omits committed generations".into());
        }
    } else {
        let (public_key, generation, config_id) =
            hyperhub_runtime::attachment::verify_approval_root_chain(&expected.instance_id, &chain)
                .map_err(|e| e.to_string())?;
        if (public_key, generation, config_id)
            != (expected.public_key, expected.generation, expected.config_id)
        {
            return Err("approval history differs from authenticated startup anchor".into());
        }
    }
    if !s.approval_continuity.is_empty() && s.approval_continuity != chain {
        return Err("startup approval history is already fixed".into());
    }
    s.approval_continuity = chain;
    Ok(())
}

pub(super) fn historical_verifier_is_trusted(
    directory: &Path,
    instance: &str,
    verifier: &[u8; 32],
) -> bool {
    let shared = state(directory);
    let Ok(s) = shared.lock() else {
        return false;
    };
    let Some(current) = s.expected_authority.as_ref().or(s.authority.as_ref()) else {
        return false;
    };
    if current.instance_id != instance {
        return false;
    }
    current.public_key == *verifier
        || s.approval_continuity.iter().any(|link| {
            link.transition.previous_public_key == *verifier
                || link.transition.public_key == *verifier
        })
}

/// A completion attestation is separate from Host commands and cannot execute one.
pub(super) fn sign_durable_completion(
    directory: &Path,
    value: &super::completion_evidence::CompletionPayload,
) -> Result<Vec<u8>, String> {
    let bytes = super::completion_evidence::completion_bytes(value)?;
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let grant = &value.acceptance.consumption.authorization;
    if s.endpoint.is_some()
        || grant.core_attestation_public_key != Some(s.core_key.verifying_key().to_bytes())
        || s.consumed.get(&super::digest(&grant.nonce))
            != Some(&serde_json::to_vec(&value.acceptance.consumption).map_err(|e| e.to_string())?)
    {
        return Err("completion attestation is not owned by this Core acceptance".into());
    }
    Ok(s.core_key.sign(&bytes).to_bytes().to_vec())
}

/// Private anonymous-pipe state. Never expose this as a control response or file.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreTrustTransfer {
    authority: Option<ApprovalAuthority>,
    expected_authority: Option<ApprovalAuthority>,
    core_key: [u8; 32],
    owning_origin: EnrollmentOrigin,
    enrollment_origins: Vec<EnrollmentOrigin>,
    consumed: HashMap<String, Vec<u8>>,
    completions: HashMap<String, Vec<u8>>,
    activation_epochs: HashMap<String, (String, u64)>,
    approval_continuity: Vec<hyperhub_runtime::attachment::SignedApprovalRootTransition>,
    preparations: HashMap<String, super::preparation::PreparationMemory>,
}
impl Drop for CoreTrustTransfer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.core_key.zeroize();
    }
}
pub(super) fn export_successor(directory: &Path) -> Result<CoreTrustTransfer, String> {
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    if s.challenges
        .values()
        .any(|challenge| challenge.expires_at_ms > crate::session::unix_timestamp_ms())
    {
        return Err("approval enrollment is in progress; retry Core succession".into());
    }
    if s.remote_core_public_key.is_some() || s.endpoint.is_some() {
        return Err("only the owning Core may transfer approval memory".into());
    }
    let owning_origin = EnrollmentOrigin::current()?;
    extend_origins(&s.enrollment_origins, owning_origin, owning_origin)?;
    // A new direct child always has a new incarnation. Reserve its slot before
    // creating it, without dropping an origin that an empty live Host may pin.
    if s.enrollment_origins.len() >= MAX_ORIGINS {
        return Err("Core enrollment origin capacity reached; original Core remains active".into());
    }
    #[derive(Serialize)]
    struct BorrowedTrust<'a> {
        authority: &'a Option<ApprovalAuthority>,
        expected_authority: &'a Option<ApprovalAuthority>,
        consumed: &'a HashMap<String, Vec<u8>>,
        completions: &'a HashMap<String, Vec<u8>>,
        activation_epochs: &'a HashMap<String, (String, u64)>,
        approval_continuity: &'a [hyperhub_runtime::attachment::SignedApprovalRootTransition],
        preparations: &'a HashMap<String, super::preparation::PreparationMemory>,
        enrollment_origins: &'a [EnrollmentOrigin],
    }
    crate::successor::bounded_json::check(
        &BorrowedTrust {
            authority: &s.authority,
            expected_authority: &s.expected_authority,
            consumed: &s.consumed,
            completions: &s.completions,
            activation_epochs: &s.activation_epochs,
            approval_continuity: &s.approval_continuity,
            preparations: &s.preparations,
            enrollment_origins: &s.enrollment_origins,
        },
        crate::successor::MAX_STATE,
    )?;
    Ok(CoreTrustTransfer {
        owning_origin,
        enrollment_origins: s.enrollment_origins.clone(),
        authority: s.authority.clone(),
        expected_authority: s.expected_authority.clone(),
        core_key: s.core_key.to_bytes(),
        consumed: s.consumed.clone(),
        completions: s.completions.clone(),
        activation_epochs: s.activation_epochs.clone(),
        approval_continuity: s.approval_continuity.clone(),
        preparations: s.preparations.clone(),
    })
}
pub(super) fn import_successor(
    directory: &Path,
    mut incoming: CoreTrustTransfer,
) -> Result<(), String> {
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    if s.authority.is_some()
        || !s.consumed.is_empty()
        || !s.completions.is_empty()
        || !s.activation_epochs.is_empty()
    {
        return Err("successor approval memory is already initialized".into());
    }
    if s.expected_authority != incoming.expected_authority
        || s.approval_continuity != incoming.approval_continuity
    {
        return Err("successor configuration approval anchor or continuity differs".into());
    }
    let origins = extend_origins(
        &incoming.enrollment_origins,
        incoming.owning_origin,
        EnrollmentOrigin::current()?,
    )?;
    if incoming
        .authority
        .as_ref()
        .is_some_and(|root| Some(root) != incoming.expected_authority.as_ref())
    {
        return Err("successor enrolled root differs from authenticated configuration".into());
    }
    s.authority = incoming.authority.take();
    s.core_key = SigningKey::from_bytes(&incoming.core_key);
    s.enrollment_origins = origins;
    s.consumed = std::mem::take(&mut incoming.consumed);
    s.completions = std::mem::take(&mut incoming.completions);
    s.activation_epochs = std::mem::take(&mut incoming.activation_epochs);
    s.approval_continuity = std::mem::take(&mut incoming.approval_continuity);
    s.preparations = std::mem::take(&mut incoming.preparations);
    s.challenges.clear();
    Ok(())
}

pub(super) fn validate_successor_configuration(
    incoming: &CoreTrustTransfer,
    config: &Path,
    unlocked: &crate::config_store::UnlockedConfig,
) -> Result<(), String> {
    let expected = unlocked
        .approval_public_key
        .map(|public_key| ApprovalAuthority {
            instance_id: super::instance_id(config, &unlocked.descriptor),
            config_id: unlocked.descriptor.config_id,
            public_key,
            generation: unlocked.approval_continuity.len() as u64,
        });
    if incoming.expected_authority != expected
        || incoming.approval_continuity != unlocked.approval_continuity
        || incoming
            .authority
            .as_ref()
            .is_some_and(|authority| Some(authority) != expected.as_ref())
    {
        return Err("successor approval memory differs from authenticated configuration".into());
    }
    Ok(())
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod successor_tests {
    use super::*;
    #[test]
    fn successor_trust_keeps_signer_consumption_and_highwater_and_never_imports_over_live_memory() {
        let root =
            std::env::temp_dir().join(format!("hh-successor-trust-{}", super::super::new_id()));
        let parent = root.join("parent");
        let child = root.join("child");
        super::super::private_directory(&parent).unwrap();
        super::super::private_directory(&child).unwrap();
        let authority = ApprovalAuthority {
            instance_id: "private-successor-instance".into(),
            config_id: [1; 16],
            public_key: SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
            generation: 0,
        };
        pin_expected_approval_anchor(&parent, authority.clone()).unwrap();
        pin_expected_approval_anchor(&child, authority.clone()).unwrap();
        pin_authority(&parent, authority.clone(), None).unwrap();
        remember_consumption(&parent, &[3; 32], b"private-consumption".to_vec()).unwrap();
        remember_completion(
            &parent,
            "private-completion".into(),
            b"private-completion-bytes".to_vec(),
        );
        state(&parent)
            .lock()
            .unwrap()
            .activation_epochs
            .insert("private-attachment".into(), ("private-epoch".into(), 7));
        let old = approval_trust(&parent).unwrap();
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(&export_successor(&parent).unwrap()).unwrap(),
        );
        import_successor(&child, serde_json::from_slice(&bytes).unwrap()).unwrap();
        let new = approval_trust(&child).unwrap();
        assert_eq!(new.core_public_key, old.core_public_key);
        assert_eq!(new.authority, old.authority);
        assert_eq!(
            trusted_consumption(&child, &[3; 32]),
            Some(b"private-consumption".to_vec())
        );
        assert_eq!(
            trusted_completion(&child, "private-completion"),
            Some(b"private-completion-bytes".to_vec())
        );
        assert_eq!(
            state(&child).lock().unwrap().activation_epochs["private-attachment"].1,
            7
        );
        assert!(import_successor(&child, serde_json::from_slice(&bytes).unwrap()).is_err());
        let other = root.join("other");
        super::super::private_directory(&other).unwrap();
        assert!(import_successor(&other, serde_json::from_slice(&bytes).unwrap()).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

pub(crate) fn register_initial_preparation(
    directory: &Path,
    grant: &Authorization,
    accepted: &hyperhub_runtime::attachment::AcceptedOperationCertificate,
    scope: &hyperhub_runtime::attachment::OperationScope,
) -> Result<(), String> {
    let super::Action::Attach { spec } = &grant.request.action else {
        return Ok(());
    };
    // This gate protects the Linux Gum preparation path. Other backends keep
    // their existing lifecycle until their own mutation boundary adopts it.
    if !cfg!(target_os = "linux") || spec.backend != super::Backend::Gum || spec.recovery.is_some()
    {
        return Ok(());
    }
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    // Later Attach approvals must never reset a prior native-mutation barrier.
    if s.preparations.contains_key(&spec.id) || s.activation_epochs.contains_key(&spec.id) {
        return Ok(());
    }
    if s.preparations.len() >= 4096 {
        return Err("initial preparation capacity reached".into());
    }
    let accepted_digest = hyperhub_runtime::attachment::host_accepted_operation_digest(accepted)
        .map_err(|e| e.to_string())?;
    let activation_epoch = s.activation_epochs.get(&spec.id).map(|v| v.0.clone());
    s.preparations.insert(
        spec.id.clone(),
        super::preparation::PreparationMemory {
            scope: scope.clone(),
            accepted_digest,
            activation_epoch,
            decision: None,
            mutation_started: false,
        },
    );
    Ok(())
}
pub(crate) fn apply_preparation(
    directory: &Path,
    proof: &super::PreparationProof,
    accepted: &hyperhub_runtime::attachment::AcceptedOperationCertificate,
    revoke: impl FnOnce(),
) -> Result<Option<super::PreparationAbortReceipt>, String> {
    use super::{PreparationAbortReceipt, PreparationStep};
    let value = super::preparation::verify_preparation(proof, accepted)?;
    let shared = state(directory);
    let mut s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let id = &value.scope.attachment_id;
    let memory = s
        .preparations
        .get(id)
        .cloned()
        .ok_or("operation has no trusted initial preparation gate")?;
    if memory.scope != value.scope
        || memory.accepted_digest != value.accepted_digest
        || value.scope.core_public_key != s.core_key.verifying_key().to_bytes()
    {
        return Err("preparation step differs from Core accepted scope".into());
    }
    if let Some(previous) = &memory.decision {
        if previous != proof {
            return Err("initial preparation already crossed its one-way gate".into());
        }
    } else {
        let current = s.activation_epochs.get(id).map(|v| v.0.clone());
        if current != memory.activation_epoch {
            return Err("initial preparation was superseded by activation".into());
        }
        if value.step == PreparationStep::AbortBeforeMutation {
            revoke();
        }
        let entry = s
            .preparations
            .get_mut(id)
            .ok_or("initial preparation gate disappeared")?;
        entry.decision = Some(proof.clone());
        entry.mutation_started = value.step == PreparationStep::BeginMutation;
    }
    if value.step == PreparationStep::BeginMutation {
        return Ok(None);
    }
    if memory.mutation_started {
        return Err("native mutation already started".into());
    }
    let mut receipt = PreparationAbortReceipt {
        proof: proof.clone(),
        accepted: accepted.clone(),
        signature: vec![],
    };
    receipt.signature = s
        .core_key
        .sign(&super::preparation::abort_receipt_bytes(&receipt)?)
        .to_bytes()
        .to_vec();
    Ok(Some(receipt))
}

pub(crate) fn require_initial_mutation_gate(
    directory: &Path,
    grant: &Authorization,
) -> Result<(), String> {
    let shared = state(directory);
    let s = shared.lock().map_err(|_| "approval trust unavailable")?;
    let Some(memory) = s.preparations.get(grant.request.action.attachment_id()) else {
        return Ok(());
    };
    let digest =
        hyperhub_runtime::attachment::operation_administrator_digest(&super::host_proof(grant)?)
            .map_err(|e| e.to_string())?;
    if memory.scope.administrator_digest == digest && !memory.mutation_started {
        return Err("initial native attachment was not admitted or was aborted".into());
    }
    Ok(())
}

pub(super) fn validate_successor_parent(
    incoming: &CoreTrustTransfer,
    parent: &ProcessIdentity,
    child: &ProcessIdentity,
) -> Result<(), String> {
    let owner = EnrollmentOrigin::from_process(parent);
    if incoming.owning_origin != owner {
        return Err("successor enrollment origin differs from verified direct parent".into());
    }
    extend_origins(
        &incoming.enrollment_origins,
        owner,
        EnrollmentOrigin::from_process(child),
    )?;
    Ok(())
}

#[cfg(all(test, any(windows, target_os = "linux")))]
#[path = "enrollment_origin_tests.rs"]
mod enrollment_origin_tests;

#[cfg(test)]
mod startup_directory_identity_tests {
    use super::*;
    #[test]
    fn startup_anchor_and_core_key_are_fixed_after_private_directory_creation() {
        let root = std::env::temp_dir().join(format!("hh-trust-path-{}", super::super::new_id()));
        super::super::private_directory(&root).unwrap();
        let directory = root.join("not-yet-created").join("attachments");
        assert!(!directory.exists());
        let anchor = ApprovalAuthority {
            instance_id: "ab".repeat(32),
            config_id: [1; 16],
            public_key: SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
            generation: 0,
        };
        pin_expected_approval_anchor(&directory, anchor.clone()).unwrap();
        assert!(
            directory.is_dir(),
            "a retained approval anchor cannot be keyed by an unresolved filesystem identity"
        );
        let first = approval_trust(&directory).unwrap();
        let canonical = directory.canonicalize().unwrap();
        assert_eq!(
            approval_trust(&canonical).unwrap().core_public_key,
            first.core_public_key
        );
        assert_eq!(
            approval_trust(&canonical).unwrap().expected_authority,
            Some(anchor.clone())
        );
        pin_authority(&canonical, anchor.clone(), None).unwrap();
        assert_eq!(approval_trust(&directory).unwrap().authority, Some(anchor));
        assert_eq!(
            approval_trust(&directory).unwrap().core_public_key,
            first.core_public_key
        );
        let unanchored = root.join("unanchored-new-directory");
        let core = approval_trust(&unanchored).unwrap();
        assert!(unanchored.is_dir());
        assert_eq!(
            core.core_public_key,
            approval_trust(&unanchored.canonicalize().unwrap())
                .unwrap()
                .core_public_key
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
