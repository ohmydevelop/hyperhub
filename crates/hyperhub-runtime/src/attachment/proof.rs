//! Verify human approval at the target boundary, independently of runtime API
//! keys, session credentials and the manager transport token.
use super::{ApprovalProof, Bootstrap};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use std::io;

#[cfg(all(test, unix))]
#[path = "proof_tests.rs"]
mod proof_tests;
#[cfg(windows)]
#[path = "proof_windows.rs"]
mod proof_windows;
const DOMAIN: &[u8] = b"hyperhub/runtime-attachment-approval/v1\0";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    request: serde_json::Value,
    approved_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 32],
    executor_sha256: String,
    execution_digest: Option<String>,
    host_binding: Option<String>,
    #[serde(default)]
    core_attestation_public_key: Option<[u8; 32]>,
    #[serde(default)]
    manager_claimant: Option<super::ManagerClaimant>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovedAction {
    Attach,
    Detach,
}
#[derive(Clone, Debug)]
pub struct ApprovalClaims {
    pub action: ApprovedAction,
    pub nonce: [u8; 32],
    pub approved_at_ms: u64,
    pub expires_at_ms: u64,
    pub core_attestation_public_key: Option<[u8; 32]>,
    pub manager_claimant: Option<super::ManagerClaimant>,
    pub root_image: Option<super::RootImageIdentity>,
    pub exec_epoch: u64,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
pub fn verify_proof(
    bootstrap: &Bootstrap,
    proof: &ApprovalProof,
    now: u64,
) -> io::Result<ApprovalClaims> {
    if proof.payload.len() <= DOMAIN.len()
        || proof.payload.len() > super::MAX_FRAME
        || !proof.payload.starts_with(DOMAIN)
    {
        return Err(invalid("invalid attachment approval domain"));
    }
    let key = bootstrap
        .approval_public_key
        .ok_or_else(|| invalid("attachment approval root is not enrolled"))?;
    verify_proof_with_key(bootstrap, &key, proof, now)
}
pub fn verify_proof_with_key(
    bootstrap: &Bootstrap,
    pinned: &[u8; 32],
    proof: &ApprovalProof,
    now: u64,
) -> io::Result<ApprovalClaims> {
    verify_proof_with_key_for_recipient(bootstrap, pinned, proof, now, std::process::id())
}
/// Verify a proof for an independently authenticated recipient. This does not
/// prove tree membership or OS identity; the coordinator must establish those
/// before calling. Target Hosts use verify_proof_with_key, which pins self PID.
pub fn verify_proof_with_key_for_recipient(
    bootstrap: &Bootstrap,
    pinned: &[u8; 32],
    proof: &ApprovalProof,
    now: u64,
    recipient_pid: u32,
) -> io::Result<ApprovalClaims> {
    if proof.payload.len() <= DOMAIN.len()
        || proof.payload.len() > super::MAX_FRAME
        || !proof.payload.starts_with(DOMAIN)
    {
        return Err(invalid("invalid attachment approval domain"));
    }
    let key =
        VerifyingKey::from_bytes(pinned).map_err(|_| invalid("invalid pinned approval root"))?;
    let signature = Signature::from_slice(&proof.signature)
        .map_err(|_| invalid("invalid attachment approval signature"))?;
    key.verify_strict(&proof.payload, &signature)
        .map_err(|_| invalid("attachment approval signature rejected"))?;
    let payload: Payload = serde_json::from_slice(&proof.payload[DOMAIN.len()..])
        .map_err(|_| invalid("invalid attachment approval payload"))?;
    if let Some(claimant) = &payload.manager_claimant {
        claimant.validate()?;
    }
    if payload.approved_at_ms > now
        || payload.expires_at_ms <= now
        || payload.expires_at_ms.saturating_sub(payload.approved_at_ms) > 600_000
        || payload.executor_sha256.len() != 64
        || payload
            .execution_digest
            .as_ref()
            .is_some_and(|d| d.len() != 64)
    {
        return Err(invalid("attachment approval expired or malformed"));
    }
    if payload.host_binding.as_deref() != Some(bootstrap.approval_binding()?.as_str()) {
        return Err(invalid("attachment approval bootstrap binding mismatch"));
    }
    let request = &payload.request;
    if request.get("schema_version").and_then(|v| v.as_u64()) != Some(1)
        || request.get("instance_id").and_then(|v| v.as_str())
            != Some(&bootstrap.approval_instance_id)
    {
        return Err(invalid("attachment request instance mismatch"));
    }
    let action = request
        .get("action")
        .ok_or_else(|| invalid("attachment approval has no action"))?;
    let (kind, id, target, exec_epoch) = match action.get("kind").and_then(|v| v.as_str()) {
        Some("attach") => {
            let spec = action
                .get("spec")
                .ok_or_else(|| invalid("attach approval has no spec"))?;
            let scope = spec.get("scope").and_then(|v| v.as_str());
            if scope
                != Some(if bootstrap.scope_tree {
                    "tree"
                } else {
                    "process"
                })
            {
                return Err(invalid("attachment approval scope mismatch"));
            }
            (
                ApprovedAction::Attach,
                spec.get("id"),
                spec.get("current_target")
                    .filter(|v| !v.is_null())
                    .or_else(|| spec.get("target")),
                spec.get("exec_epoch").and_then(|v| v.as_u64()).unwrap_or(0),
            )
        }
        Some("detach") => (
            ApprovedAction::Detach,
            action.get("attachment_id"),
            action.get("target"),
            action
                .get("exec_epoch")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        ),
        _ => return Err(invalid("unknown attachment approval action")),
    };
    if id.and_then(|v| v.as_str()) != Some(&bootstrap.attachment_id)
        || target.and_then(|v| v.get("pid")).and_then(|v| v.as_u64())
            != Some(u64::from(bootstrap.root_pid))
    {
        return Err(invalid("attachment approval target mismatch"));
    }
    if payload.approved_at_ms <= bootstrap.approval_not_before_ms {
        return Err(invalid(
            "approval predates this Host's inherited lifecycle epoch",
        ));
    }
    if recipient_pid == 0 || (!bootstrap.scope_tree && bootstrap.root_pid != recipient_pid) {
        return Err(invalid("process-only approval does not cover this child"));
    }
    Ok(ApprovalClaims {
        action: kind,
        nonce: payload.nonce,
        approved_at_ms: payload.approved_at_ms,
        expires_at_ms: payload.expires_at_ms,
        core_attestation_public_key: payload.core_attestation_public_key,
        manager_claimant: payload.manager_claimant,
        exec_epoch,
        root_image: target.and_then(|target| {
            Some(super::RootImageIdentity {
                pid: u32::try_from(target.get("pid")?.as_u64()?).ok()?,
                birth: target.get("birth")?.as_u64()?,
                executable_sha256: target.get("executable_sha256")?.as_str()?.into(),
            })
        }),
    })
}

#[cfg(test)]
#[path = "proof_recipient_tests.rs"]
mod recipient_tests;
