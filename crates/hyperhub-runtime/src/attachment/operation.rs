//! Delegated operation evidence. These codecs do not authorize a lifecycle
//! command: callers must independently validate the administrator proof and
//! derive the exact expected scope from it. Host command challenges are a
//! separate protocol; an acceptance certificate is not a bearer capability.
use super::{canonical_alias_bytes, RootImageState};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io;

pub const OPERATION_POSSESSION_DOMAIN: &[u8] = b"hyperhub/operation-possession/v1\0";
pub const OPERATION_ACCEPTED_DOMAIN: &[u8] = b"hyperhub/operation-accepted/v1\0";
pub const OPERATION_CHALLENGE_LIFETIME_MS: u64 = 30_000;
const MAX_OPERATION_BYTES: usize = 16 * 1024;

/// Hash exact signed administrator bytes, not a reserialized request. This
/// helper does not verify that signature or make the resulting scope trusted.
pub fn operation_administrator_digest(proof: &super::ApprovalProof) -> io::Result<[u8; 32]> {
    use sha2::Digest;
    if proof.payload.is_empty()
        || proof.payload.len() > super::MAX_FRAME
        || proof.signature.len() != 64
    {
        return Err(invalid("invalid administrator proof digest input"));
    }
    let mut hash = sha2::Sha256::new();
    hash.update(b"hyperhub/operation-administrator-proof/v1\0");
    hash.update((proof.payload.len() as u64).to_le_bytes());
    hash.update(&proof.payload);
    hash.update(&proof.signature);
    Ok(hash.finalize().into())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagerClaimant {
    pub pid: u32,
    pub birth: u64,
    pub role_epoch: [u8; 32],
    pub public_key: [u8; 32],
}
impl ManagerClaimant {
    pub fn validate(&self) -> io::Result<()> {
        if self.pid == 0 || self.birth == 0 || self.role_epoch == [0; 32] {
            return Err(invalid("invalid operation claimant incarnation"));
        }
        public_key(&self.public_key)?;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationAction {
    Attach,
    Detach,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationScope {
    pub action: OperationAction,
    pub administrator_digest: [u8; 32],
    pub instance_id: String,
    pub attachment_id: String,
    pub session_id: String,
    pub credential_digest: [u8; 32],
    pub host_binding: String,
    pub root_image: RootImageState,
    pub claimant: ManagerClaimant,
    pub core_public_key: [u8; 32],
}
impl OperationScope {
    pub fn validate(&self) -> io::Result<()> {
        self.claimant.validate()?;
        for value in [&self.instance_id, &self.attachment_id, &self.session_id] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(invalid("invalid delegated operation scope identifier"));
            }
        }
        let root = &self.root_image;
        if !hex_digest(&self.host_binding)
            || !hex_digest(&root.identity.executable_sha256)
            || root.identity.pid == 0
            || root.identity.birth == 0
            || (root.exec_epoch == 0 && (root.observed_at_ms != 0 || root.head != [0; 32]))
            || (root.exec_epoch != 0 && (root.observed_at_ms == 0 || root.head == [0; 32]))
        {
            return Err(invalid("invalid delegated root image scope"));
        }
        public_key(&self.core_public_key)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PossessionChallenge {
    pub schema_version: u32,
    pub scope: OperationScope,
    pub nonce: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
impl PossessionChallenge {
    pub fn validate_at(&self, now: u64) -> io::Result<()> {
        self.scope.validate()?;
        if self.schema_version != 1
            || self.nonce == [0; 32]
            || self.issued_at_ms > now
            || self.expires_at_ms <= now
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > OPERATION_CHALLENGE_LIFETIME_MS
        {
            return Err(invalid(
                "operation possession challenge expired or malformed",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PossessionProof {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptedOperationPayload {
    pub schema_version: u32,
    pub challenge: PossessionChallenge,
    pub accepted_at_ms: u64,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptedOperationCertificate {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
macro_rules! redacted_debug {
    ($name:ident) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("evidence", &"<redacted>")
                    .finish()
            }
        }
    };
}
redacted_debug!(PossessionProof);
redacted_debug!(AcceptedOperationCertificate);

fn hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn public_key(bytes: &[u8; 32]) -> io::Result<VerifyingKey> {
    let key =
        VerifyingKey::from_bytes(bytes).map_err(|_| invalid("invalid operation public key"))?;
    if key.is_weak() {
        return Err(invalid("weak operation public key"));
    }
    Ok(key)
}
fn encode<T: Serialize>(domain: &[u8], value: &T) -> io::Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend(canonical_alias_bytes(value)?);
    if bytes.len() > MAX_OPERATION_BYTES {
        return Err(invalid("delegated operation evidence exceeds frame"));
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned + Serialize>(domain: &[u8], bytes: &[u8]) -> io::Result<T> {
    if bytes.len() <= domain.len()
        || bytes.len() > MAX_OPERATION_BYTES
        || !bytes.starts_with(domain)
    {
        return Err(invalid(
            "invalid delegated operation evidence domain or size",
        ));
    }
    let value: T = serde_json::from_slice(&bytes[domain.len()..])
        .map_err(|_| invalid("invalid delegated operation evidence payload"))?;
    if encode(domain, &value)? != bytes {
        return Err(invalid("noncanonical delegated operation evidence"));
    }
    Ok(value)
}
fn verify(key: &[u8; 32], bytes: &[u8], signature: &[u8]) -> io::Result<()> {
    let key = public_key(key)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| invalid("invalid operation signature"))?;
    key.verify_strict(bytes, &signature)
        .map_err(|_| invalid("delegated operation signature rejected"))
}
pub fn encode_possession_challenge(challenge: &PossessionChallenge) -> io::Result<Vec<u8>> {
    challenge.validate_at(challenge.issued_at_ms)?;
    encode(OPERATION_POSSESSION_DOMAIN, challenge)
}
pub fn verify_possession_proof(
    expected: &PossessionChallenge,
    proof: &PossessionProof,
    now: u64,
) -> io::Result<()> {
    expected.validate_at(now)?;
    let actual: PossessionChallenge = decode(OPERATION_POSSESSION_DOMAIN, &proof.payload)?;
    if &actual != expected {
        return Err(invalid("operation possession proof changed the challenge"));
    }
    verify(
        &expected.scope.claimant.public_key,
        &proof.payload,
        &proof.signature,
    )
}
pub fn encode_accepted_operation(payload: &AcceptedOperationPayload) -> io::Result<Vec<u8>> {
    if payload.schema_version != 1 {
        return Err(invalid("unsupported accepted operation schema"));
    }
    payload.challenge.validate_at(payload.accepted_at_ms)?;
    encode(OPERATION_ACCEPTED_DOMAIN, payload)
}
/// A retained certificate proves exact historical acceptance, even after the
/// possession window. It cannot authorize a new action or a Host command.
pub fn verify_accepted_operation(
    expected: &OperationScope,
    certificate: &AcceptedOperationCertificate,
    now: u64,
) -> io::Result<AcceptedOperationPayload> {
    expected.validate()?;
    let payload: AcceptedOperationPayload =
        decode(OPERATION_ACCEPTED_DOMAIN, &certificate.payload)?;
    encode_accepted_operation(&payload)?;
    if payload.challenge.scope != *expected || payload.accepted_at_ms > now {
        return Err(invalid(
            "accepted operation scope or acceptance time mismatch",
        ));
    }
    verify(
        &expected.core_public_key,
        &certificate.payload,
        &certificate.signature,
    )?;
    Ok(payload)
}

#[cfg(test)]
#[path = "operation_tests.rs"]
mod tests;
