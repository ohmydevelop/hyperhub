//! Lifecycle command possession codecs, not a live command authorization path.
//! Callers must derive the expected operation scope from independently verified
//! administrator/bootstrap/RootImage state. A Host must issue and atomically
//! consume its own challenge with the current state checks before mutation.
use super::{
    canonical_alias_bytes, operation_administrator_digest, verify_accepted_operation,
    AcceptedOperationCertificate, AuthenticatedCommand, HostCommand, OperationAction,
    OperationScope,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;

pub const HOST_COMMAND_POSSESSION_DOMAIN: &[u8] = b"hyperhub/host-command-possession/v1\0";
pub const HOST_COMMAND_CHALLENGE_LIFETIME_MS: u64 = 30_000;
const MAX_COMMAND_PROOF_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostCommandAuthority {
    ObserverWithDetachedMaintenance,
    EnrollmentChallengeRead,
    OriginalCoreEnrollmentCertificate,
    ScopedCoreRead,
    SignedCoreMetadata,
    ManagerLifecycle,
}

/// Authority is distinct from the process relaying a signed message. Routine
/// Core metadata must not acquire a dependency on a manager signing roundtrip.
pub fn host_command_authority(command: HostCommand) -> HostCommandAuthority {
    match command {
        HostCommand::Status => HostCommandAuthority::ObserverWithDetachedMaintenance,
        HostCommand::EnrollmentChallenge => HostCommandAuthority::EnrollmentChallengeRead,
        HostCommand::EnrollApprovalRoot => HostCommandAuthority::OriginalCoreEnrollmentCertificate,
        HostCommand::SnapshotAliases => HostCommandAuthority::ScopedCoreRead,
        HostCommand::ApplySessionAliases | HostCommand::ApplyRootImage => {
            HostCommandAuthority::SignedCoreMetadata
        }
        HostCommand::Activate
        | HostCommand::Detach
        | HostCommand::Retire
        | HostCommand::PrepareDetachment
        | HostCommand::CancelDetachmentPreparation => HostCommandAuthority::ManagerLifecycle,
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostLifecycleCommand {
    Activate,
    /// Reserved for the explicit capture phase; no live wire command yet.
    PrepareActivation,
    PrepareDetachment,
    CancelDetachmentPreparation,
    Detach,
    Retire,
    /// Existing wire Detach, restricted to the same uncommitted initial Attach
    /// in Preparing. The Host must independently enforce that state condition.
    RollbackInitialAttach,
    /// Retire only the never-active Host from this same committed initial
    /// Attach rollback. This does not grant general Detach retirement rights.
    RollbackInitialAttachRetire,
}
impl HostLifecycleCommand {
    pub fn operation(self) -> OperationAction {
        match self {
            Self::Activate
            | Self::PrepareActivation
            | Self::RollbackInitialAttach
            | Self::RollbackInitialAttachRetire => OperationAction::Attach,
            Self::PrepareDetachment
            | Self::CancelDetachmentPreparation
            | Self::Detach
            | Self::Retire => OperationAction::Detach,
        }
    }
    pub fn wire_command(self) -> Option<HostCommand> {
        match self {
            Self::Activate => Some(HostCommand::Activate),
            Self::PrepareActivation => None,
            Self::PrepareDetachment => Some(HostCommand::PrepareDetachment),
            Self::CancelDetachmentPreparation => Some(HostCommand::CancelDetachmentPreparation),
            Self::Detach | Self::RollbackInitialAttach => Some(HostCommand::Detach),
            Self::Retire | Self::RollbackInitialAttachRetire => Some(HostCommand::Retire),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostCommandIntent {
    pub command: HostLifecycleCommand,
    pub payload_digest: [u8; 32],
}
impl HostCommandIntent {
    /// Hash the complete semantic command, including all signed metadata and
    /// administrator proof. Later delegation evidence belongs in an outer
    /// envelope, so it cannot create self-referential digest exclusions.
    pub fn for_request(
        request: &AuthenticatedCommand,
        command: HostLifecycleCommand,
    ) -> io::Result<Self> {
        if command.wire_command() != Some(request.command) {
            return Err(invalid(
                "lifecycle intent does not match the live Host command",
            ));
        }
        if request.enrollment.is_some() || request.aliases.is_some() || request.root_image.is_some()
        {
            return Err(invalid("lifecycle command contains unsupported metadata"));
        }
        let mut value =
            serde_json::to_value(request).map_err(|_| invalid("invalid Host command body"))?;
        // Bind the transport credential without copying it into canonical
        // proof bytes or exposing it through a diagnostic representation.
        value
            .as_object_mut()
            .ok_or_else(|| invalid("invalid Host command object"))?
            .insert(
                "token".into(),
                serde_json::to_value(Sha256::digest(request.token.as_bytes()).to_vec())
                    .map_err(|_| invalid("invalid Host credential digest"))?,
            );
        let bytes = canonical_alias_bytes(&value)?;
        if bytes.len() > super::MAX_FRAME {
            return Err(invalid("Host command body exceeds frame"));
        }
        let mut digest = Sha256::new();
        digest.update(b"hyperhub/host-command-body/v1\0");
        digest.update(bytes);
        Ok(Self {
            command,
            payload_digest: digest.finalize().into(),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostCommandChallenge {
    pub schema_version: u32,
    pub accepted_digest: [u8; 32],
    pub host_pid: u32,
    pub host_birth: u64,
    pub host_epoch: [u8; 32],
    pub state_epoch: u64,
    pub intent: HostCommandIntent,
    pub nonce: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
impl HostCommandChallenge {
    pub fn validate_at(&self, now: u64) -> io::Result<()> {
        if self.schema_version != 1
            || self.accepted_digest == [0; 32]
            || self.host_pid == 0
            || self.host_birth == 0
            || self.host_epoch == [0; 32]
            || self.intent.payload_digest == [0; 32]
            || self.nonce == [0; 32]
            || self.issued_at_ms > now
            || self.expires_at_ms <= now
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > HOST_COMMAND_CHALLENGE_LIFETIME_MS
        {
            return Err(invalid("Host command challenge expired or malformed"));
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostCommandPossessionProof {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
impl std::fmt::Debug for HostCommandPossessionProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostCommandPossessionProof")
            .field("evidence", &"<redacted>")
            .finish()
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// This digest alone does not verify or authorize the certificate.
pub fn host_accepted_operation_digest(
    certificate: &AcceptedOperationCertificate,
) -> io::Result<[u8; 32]> {
    if certificate.payload.is_empty()
        || certificate.payload.len() > MAX_COMMAND_PROOF_BYTES
        || certificate.signature.len() != 64
    {
        return Err(invalid("invalid accepted operation digest input"));
    }
    let mut digest = Sha256::new();
    digest.update(b"hyperhub/host-accepted-operation/v1\0");
    digest.update((certificate.payload.len() as u64).to_le_bytes());
    digest.update(&certificate.payload);
    digest.update(&certificate.signature);
    Ok(digest.finalize().into())
}
pub fn encode_host_command_challenge(challenge: &HostCommandChallenge) -> io::Result<Vec<u8>> {
    challenge.validate_at(challenge.issued_at_ms)?;
    let mut bytes = HOST_COMMAND_POSSESSION_DOMAIN.to_vec();
    bytes.extend(canonical_alias_bytes(challenge)?);
    if bytes.len() > MAX_COMMAND_PROOF_BYTES {
        return Err(invalid("Host command proof exceeds frame"));
    }
    Ok(bytes)
}

/// Validate the Host's locally retained challenge against the manager's exact
/// intended command and an independently derived scope, before signing it.
/// Historical acceptance does not replace current Host phase/epoch checks.
pub fn validate_host_command_challenge(
    expected: &HostCommandChallenge,
    request: &AuthenticatedCommand,
    scope: &OperationScope,
    certificate: &AcceptedOperationCertificate,
    now: u64,
) -> io::Result<()> {
    expected.validate_at(now)?;
    verify_accepted_operation(scope, certificate, now)?;
    let proof = request
        .proof
        .as_ref()
        .ok_or_else(|| invalid("administrator proof is required for a lifecycle command"))?;
    if expected.accepted_digest != host_accepted_operation_digest(certificate)?
        || expected.intent.command.operation() != scope.action
        || request.attachment_id != scope.attachment_id
        || operation_administrator_digest(proof)? != scope.administrator_digest
        || HostCommandIntent::for_request(request, expected.intent.command)? != expected.intent
    {
        return Err(invalid(
            "Host command does not match accepted operation or intent",
        ));
    }
    Ok(())
}

/// Verify possession only. The live Host must also compare its actual PID,
/// birth, random initialization epoch and state epoch, and atomically consume
/// the issued nonce. This codec neither consumes a nonce nor mutates a Host.
pub fn verify_host_command_proof(
    expected: &HostCommandChallenge,
    request: &AuthenticatedCommand,
    scope: &OperationScope,
    certificate: &AcceptedOperationCertificate,
    proof: &HostCommandPossessionProof,
    now: u64,
) -> io::Result<HostCommandChallenge> {
    validate_host_command_challenge(expected, request, scope, certificate, now)?;
    if proof.payload.len() > MAX_COMMAND_PROOF_BYTES
        || !proof.payload.starts_with(HOST_COMMAND_POSSESSION_DOMAIN)
    {
        return Err(invalid("invalid Host command proof domain or size"));
    }
    let value: HostCommandChallenge =
        serde_json::from_slice(&proof.payload[HOST_COMMAND_POSSESSION_DOMAIN.len()..])
            .map_err(|_| invalid("invalid Host command proof payload"))?;
    if value != *expected || encode_host_command_challenge(&value)? != proof.payload {
        return Err(invalid("Host command challenge changed or is noncanonical"));
    }
    let key = VerifyingKey::from_bytes(&scope.claimant.public_key)
        .map_err(|_| invalid("invalid manager public key"))?;
    let signature = Signature::from_slice(&proof.signature)
        .map_err(|_| invalid("invalid Host command signature"))?;
    key.verify_strict(&proof.payload, &signature)
        .map_err(|_| invalid("Host command possession rejected"))?;
    Ok(value)
}

#[cfg(test)]
#[path = "host_command_tests.rs"]
mod tests;
