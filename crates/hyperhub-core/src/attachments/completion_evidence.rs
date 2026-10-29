//! Durable evidence is a proof of an already completed cleanup, never a new
//! operation capability. The current authenticated config anchors old roots.
use super::{authority, trust, Action, Authorization, ProcessIdentity};
use ed25519_dalek::{Signature, VerifyingKey};
use hyperhub_runtime::attachment::{self as wire, AcceptedOperationCertificate};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const COMPLETION_DOMAIN: &[u8] = b"hyperhub/completed-attachment-cleanup/v1\0";
const MAX_EVIDENCE_BYTES: u64 = 128 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Acceptance {
    pub(super) consumption: authority::Consumption,
    certificate: AcceptedOperationCertificate,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletionPayload {
    schema_version: u32,
    pub(super) acceptance: Acceptance,
    receipt: authority::CompletionReceipt,
    completed_at_ms: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedCompletion {
    payload: Vec<u8>,
    signature: Vec<u8>,
}
fn accepted_path(directory: &Path, nonce: &[u8; 32]) -> PathBuf {
    directory.join("accepted").join(super::digest(nonce))
}
fn completion_path(directory: &Path, grant: &Authorization) -> PathBuf {
    directory
        .join("completion-proofs")
        .join(grant.request.action.attachment_id())
        .join(super::digest(&grant.nonce))
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err("cleanup evidence exceeds its size limit".into());
    }
    Ok(bytes)
}
pub(super) fn completion_bytes(value: &CompletionPayload) -> Result<Vec<u8>, String> {
    let mut bytes = COMPLETION_DOMAIN.to_vec();
    bytes.extend(encode(value)?);
    Ok(bytes)
}
fn verify_signature(key: &[u8; 32], payload: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| "invalid cleanup evidence key")?;
    if key.is_weak() {
        return Err("weak cleanup evidence key".into());
    }
    key.verify_strict(
        payload,
        &Signature::from_slice(signature).map_err(|_| "invalid cleanup evidence signature")?,
    )
    .map_err(|_| "cleanup evidence signature rejected".into())
}
fn verify_acceptance(directory: &Path, value: &Acceptance) -> Result<wire::OperationScope, String> {
    let consumption = &value.consumption;
    let grant = &consumption.authorization;
    grant.request.validate()?;
    let verifier = consumption
        .verifier
        .ok_or("acceptance has no approval verifier")?;
    if !trust::historical_verifier_is_trusted(directory, &grant.request.instance_id, &verifier)
        || consumption.instance_id != grant.request.instance_id
    {
        return Err("acceptance is not anchored by the authenticated configuration".into());
    }
    verify_signature(&verifier, &authority::payload(grant)?, &grant.signature)?;
    let payload = value
        .certificate
        .payload
        .strip_prefix(wire::OPERATION_ACCEPTED_DOMAIN)
        .ok_or("invalid acceptance evidence domain")?;
    let accepted: wire::AcceptedOperationPayload =
        serde_json::from_slice(payload).map_err(|e| e.to_string())?;
    let scope = &accepted.challenge.scope;
    wire::verify_accepted_operation(
        scope,
        &value.certificate,
        crate::session::unix_timestamp_ms(),
    )
    .map_err(|e| e.to_string())?;
    let claimant = grant
        .manager_claimant
        .as_ref()
        .ok_or("acceptance omits its signed claimant")?;
    let action = match &grant.request.action {
        Action::Attach { .. } => wire::OperationAction::Attach,
        Action::Detach { .. } => wire::OperationAction::Detach,
    };
    let administrator_digest = wire::operation_administrator_digest(&super::host_proof(grant)?)
        .map_err(|e| e.to_string())?;
    if grant.core_attestation_public_key != Some(scope.core_public_key)
        || scope.administrator_digest != administrator_digest
        || scope.action != action
        || scope.instance_id != grant.request.instance_id
        || scope.attachment_id != grant.request.action.attachment_id()
        || scope.claimant != *claimant
        || (claimant.pid, claimant.birth) != (consumption.pid, consumption.birth)
        || grant.host_binding.as_ref() != Some(&scope.host_binding)
        || scope.root_image.identity != grant.request.action.target().root_image_identity()
        || scope.root_image.exec_epoch != grant.request.action.exec_epoch()
        || accepted.accepted_at_ms < grant.approved_at_ms
        || accepted.accepted_at_ms >= grant.expires_at_ms
        || grant.expires_at_ms.checked_sub(grant.approved_at_ms)
            != Some(authority::AUTHORIZATION_LIFETIME_MS)
    {
        return Err("acceptance evidence differs from the signed operation scope".into());
    }
    Ok(scope.clone())
}

/// Publish the actual possession acceptance certificate before the reply. This
/// file never repopulates Core's execution or nonce-consumption authority.
pub(crate) fn record_operation_acceptance(
    directory: &Path,
    grant: &Authorization,
    certificate: &AcceptedOperationCertificate,
) -> Result<(), String> {
    let bytes = trust::trusted_consumption(directory, &grant.nonce)
        .ok_or("accepted operation has no owning Core consumption")?;
    let value = Acceptance {
        consumption: serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
        certificate: certificate.clone(),
    };
    verify_acceptance(directory, &value)?;
    let path = accepted_path(directory, &grant.nonce);
    super::private_directory(path.parent().ok_or("invalid acceptance path")?)?;
    super::create_private_file(&path, &encode(&value)?)
}
pub(crate) fn finalize_durable_completion(
    directory: &Path,
    grant: &Authorization,
    session: &str,
    token: &str,
    manager: &ProcessIdentity,
) -> Result<(), String> {
    // Legacy in-process APIs have no Core-key endorsement, so they retain only
    // their existing RAM trust and cannot create cold-recovery authority.
    if grant.core_attestation_public_key.is_none() {
        return Ok(());
    }
    let path = completion_path(directory, grant);
    if path.exists() {
        let value = read_completion(directory, &path)?;
        if value.receipt != authority::completion_receipt(grant, session, token, manager)?
            || authority::payload(&value.acceptance.consumption.authorization)?
                != authority::payload(grant)?
            || value.acceptance.consumption.authorization.signature != grant.signature
        {
            return Err("durable cleanup completion belongs to another operation".into());
        }
        return Ok(());
    }
    let bytes =
        super::read_private_file(&accepted_path(directory, &grant.nonce), MAX_EVIDENCE_BYTES)?;
    let acceptance: Acceptance = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let scope = verify_acceptance(directory, &acceptance)?;
    if authority::payload(&acceptance.consumption.authorization)? != authority::payload(grant)?
        || acceptance.consumption.authorization.signature != grant.signature
    {
        return Err("completion references another accepted administrator operation".into());
    }
    if scope.session_id != session
        || super::digest(token.as_bytes()) != hex_digest(&scope.credential_digest)
        || (manager.pid, manager.birth) != (scope.claimant.pid, scope.claimant.birth)
        || manager.executable_sha256 != grant.executor_sha256
    {
        return Err("cleanup completion differs from accepted session or manager".into());
    }
    let value = CompletionPayload {
        schema_version: 1,
        acceptance,
        receipt: authority::completion_receipt(grant, session, token, manager)?,
        completed_at_ms: crate::session::unix_timestamp_ms(),
    };
    let signed = SignedCompletion {
        payload: completion_bytes(&value)?,
        signature: trust::sign_durable_completion(directory, &value)?,
    };
    super::private_directory(path.parent().ok_or("invalid completion proof path")?)?;
    super::create_private_file(&path, &encode(&signed)?)
}
fn hex_digest(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn read_completion(directory: &Path, path: &Path) -> Result<CompletionPayload, String> {
    let bytes = super::read_private_file(path, MAX_EVIDENCE_BYTES)?;
    let signed: SignedCompletion = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let body = signed
        .payload
        .strip_prefix(COMPLETION_DOMAIN)
        .ok_or("invalid completion proof domain")?;
    let value: CompletionPayload = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let scope = verify_acceptance(directory, &value.acceptance)?;
    let grant = &value.acceptance.consumption.authorization;
    let mut administrator_bytes = authority::payload(grant)?;
    administrator_bytes.extend(&grant.signature);
    if value.schema_version != 1
        || completion_bytes(&value)? != signed.payload
        || value.completed_at_ms < grant.approved_at_ms
        || value.completed_at_ms
            < serde_json::from_slice::<wire::AcceptedOperationPayload>(
                &value.acceptance.certificate.payload[wire::OPERATION_ACCEPTED_DOMAIN.len()..],
            )
            .map_err(|e| e.to_string())?
            .accepted_at_ms
        || value.completed_at_ms > crate::session::unix_timestamp_ms()
        || path.file_name().and_then(|n| n.to_str()) != Some(super::digest(&grant.nonce).as_str())
        || value.receipt.target != *grant.request.action.target()
        || value.receipt.authorization_digest != super::digest(&administrator_bytes)
        || value.receipt.attachment_id != scope.attachment_id
        || value.receipt.session_id != scope.session_id
        || value.receipt.credential_digest != hex_digest(&scope.credential_digest)
        || value.receipt.pid != scope.claimant.pid
        || value.receipt.birth != scope.claimant.birth
    {
        return Err("cleanup proof differs from its accepted operation".into());
    }
    verify_signature(&scope.core_public_key, &signed.payload, &signed.signature)?;
    Ok(value)
}

/// Only a NEW signed cleanup for the vanished original manager may use this
/// proof. It neither imports the old acceptance nor registers session members.
pub(super) fn prior_completion_matches(
    directory: &Path,
    cleanup: &Authorization,
    session: &str,
    token: &str,
) -> bool {
    let Action::Detach {
        attachment_id,
        target,
        recovery: Some(binding),
        ..
    } = &cleanup.request.action
    else {
        return false;
    };
    if !super::process_incarnation_exited(binding.manager.pid, binding.manager.birth) {
        return false;
    }
    let base = directory.join("completion-proofs").join(attachment_id);
    let Ok(entries) = std::fs::read_dir(base) else {
        return false;
    };
    // Nonce filenames and every content byte are untrusted until verified.
    for entry in entries.take(4096).flatten() {
        let Ok(value) = read_completion(directory, &entry.path()) else {
            continue;
        };
        let old = &value.acceptance.consumption.authorization;
        if !matches!(old.request.action, Action::Detach { .. })
            || old.request.instance_id != cleanup.request.instance_id
            || old.request.action.attachment_id() != attachment_id
            || old.request.action.target() != target
            || old.request.action.exec_epoch() != cleanup.request.action.exec_epoch()
            || old.executor_sha256 != binding.manager.executable_sha256
            || old.approved_at_ms >= cleanup.approved_at_ms
            || trust::activation_epoch(directory, attachment_id).is_some_and(|current| {
                Some(current) != value.acceptance.consumption.activation_epoch
            })
        {
            continue;
        }
        if authority::completion_receipt(old, session, token, &binding.manager)
            .is_ok_and(|expected| expected == value.receipt)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[path = "completion_evidence_tests.rs"]
mod tests;
