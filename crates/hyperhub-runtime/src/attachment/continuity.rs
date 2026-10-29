//! Password-root continuity. A chain is historical metadata; only a current
//! root signature over a fresh Host challenge may advance a living Host.
use super::{ApprovalEnrollmentChallenge, ApprovalRootCertificate, Bootstrap};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io;

pub const APPROVAL_CONTINUITY_DOMAIN: &[u8] = b"hyperhub/approval-root-continuity/v1\0";
pub const APPROVAL_ROTATION_ENROLLMENT_DOMAIN: &[u8] =
    b"hyperhub/approval-root-rotation-enrollment/v1\0";
pub const MAX_APPROVAL_ROTATIONS: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRootTransition {
    pub schema_version: u32,
    pub instance_id: String,
    pub generation: u64,
    pub previous_public_key: [u8; 32],
    pub public_key: [u8; 32],
    pub previous_config_id: [u8; 16],
    pub config_id: [u8; 16],
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalRootTransition {
    pub transition: ApprovalRootTransition,
    pub previous_signature: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRotationEnrollment {
    pub schema_version: u32,
    pub instance_id: String,
    pub attachment_id: String,
    pub root_pid: u32,
    pub challenge: ApprovalEnrollmentChallenge,
    pub issued_at_ms: u64,
    pub chain: Vec<SignedApprovalRootTransition>,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "approval-root continuity rejected",
    )
}
pub fn approval_transition_bytes(value: &ApprovalRootTransition) -> io::Result<Vec<u8>> {
    let mut bytes = APPROVAL_CONTINUITY_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(value).map_err(|_| invalid())?);
    Ok(bytes)
}
fn verify(key: &[u8; 32], bytes: &[u8], signature: &[u8]) -> io::Result<()> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| invalid())?;
    if key.is_weak() {
        return Err(invalid());
    }
    key.verify_strict(
        bytes,
        &Signature::from_slice(signature).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())
}
/// Validate the whole canonical history, including the prefix before the
/// caller's pin. Duplicate roots would permit ambiguous rollback and are banned.
pub fn verify_approval_root_chain(
    instance: &str,
    chain: &[SignedApprovalRootTransition],
) -> io::Result<([u8; 32], u64, [u8; 16])> {
    if chain.is_empty() || chain.len() > MAX_APPROVAL_ROTATIONS {
        return Err(invalid());
    }
    let mut previous = chain[0].transition.previous_public_key;
    let mut seen = vec![previous];
    let mut previous_config = chain[0].transition.previous_config_id;
    let mut config_ids = vec![previous_config];
    for (index, link) in chain.iter().enumerate() {
        let value = &link.transition;
        if value.schema_version != 1
            || value.instance_id != instance
            || value.generation != index as u64 + 1
            || value.previous_public_key != previous
            || seen.contains(&value.public_key)
            || value.previous_config_id != previous_config
            || config_ids.contains(&value.config_id)
        {
            return Err(invalid());
        }
        let bytes = approval_transition_bytes(value)?;
        verify(&previous, &bytes, &link.previous_signature)?;
        verify(&value.public_key, &bytes, &link.signature)?;
        previous = value.public_key;
        seen.push(previous);
        config_ids.push(value.config_id);
        previous_config = value.config_id;
    }
    let tail = &chain.last().ok_or_else(invalid)?.transition;
    Ok((tail.public_key, tail.generation, tail.config_id))
}
pub fn approval_rotation_enrollment_bytes(
    value: &ApprovalRotationEnrollment,
) -> io::Result<Vec<u8>> {
    let mut bytes = APPROVAL_ROTATION_ENROLLMENT_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(value).map_err(|_| invalid())?);
    if bytes.len() > super::MAX_FRAME / 2 {
        return Err(invalid());
    }
    Ok(bytes)
}
pub fn verify_approval_rotation_enrollment(
    bootstrap: &Bootstrap,
    pinned: &[u8; 32],
    generation: u64,
    challenge: &ApprovalEnrollmentChallenge,
    certificate: &ApprovalRootCertificate,
    now: u64,
) -> io::Result<([u8; 32], u64)> {
    let bytes = &certificate.payload;
    if bytes.len() > super::MAX_FRAME / 2 || !bytes.starts_with(APPROVAL_ROTATION_ENROLLMENT_DOMAIN)
    {
        return Err(invalid());
    }
    let value: ApprovalRotationEnrollment =
        serde_json::from_slice(&bytes[APPROVAL_ROTATION_ENROLLMENT_DOMAIN.len()..])
            .map_err(|_| invalid())?;
    if approval_rotation_enrollment_bytes(&value)? != *bytes
        || value.schema_version != 1
        || value.instance_id != bootstrap.approval_instance_id
        || value.attachment_id != bootstrap.attachment_id
        || value.root_pid != bootstrap.root_pid
        || &value.challenge != challenge
        || challenge.expires_at_ms <= now
        || value.issued_at_ms > now
        || value.issued_at_ms >= challenge.expires_at_ms
        || challenge.expires_at_ms.saturating_sub(value.issued_at_ms) > 60_000
    {
        return Err(invalid());
    }
    let (key, next, _) = verify_approval_root_chain(&bootstrap.approval_instance_id, &value.chain)?;
    // The pin may have been installed at initial startup after earlier rotations.
    // Locate it in the complete signed chain instead of trusting a caller epoch.
    let position = if value.chain[0].transition.previous_public_key == *pinned {
        0
    } else {
        value
            .chain
            .iter()
            .position(|v| v.transition.public_key == *pinned)
            .map(|i| i as u64 + 1)
            .ok_or_else(invalid)?
    };
    if position < generation || next <= position || next <= generation {
        return Err(invalid());
    }
    verify(&key, bytes, &certificate.signature)?;
    Ok((key, next))
}

#[cfg(test)]
#[path = "continuity_tests.rs"]
mod tests;
