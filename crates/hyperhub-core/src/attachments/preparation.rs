//! A fresh Gum Attach has a Core-owned preparation gate. No target mutation
//! may start until the one-way gate has advanced from Awaiting to Mutating.
use super::Execution;
use ed25519_dalek::{Signature, VerifyingKey};
use hyperhub_runtime::attachment::{self as wire, AcceptedOperationCertificate, OperationScope};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(super) const PREPARATION_DOMAIN: &[u8] = b"hyperhub/attachment-preparation-step/v1\0";
pub(super) const ABORT_RECEIPT_DOMAIN: &[u8] = b"hyperhub/attachment-preparation-aborted/v1\0";
const MAX_BYTES: u64 = 128 * 1024;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreparationStep {
    BeginMutation,
    AbortBeforeMutation,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparationPayload {
    pub schema_version: u32,
    pub step: PreparationStep,
    pub scope: OperationScope,
    pub accepted_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub failure_digest: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparationProof {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparationAbortReceipt {
    pub proof: PreparationProof,
    pub accepted: AcceptedOperationCertificate,
    pub signature: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparationMemory {
    pub scope: OperationScope,
    pub accepted_digest: [u8; 32],
    pub activation_epoch: Option<String>,
    pub decision: Option<PreparationProof>,
    pub mutation_started: bool,
}
pub(super) fn preparation_bytes(value: &PreparationPayload) -> Result<Vec<u8>, String> {
    value.scope.validate().map_err(|e| e.to_string())?;
    if value.schema_version != 1
        || value.scope.action != wire::OperationAction::Attach
        || value.nonce == [0; 32]
        || value.accepted_digest == [0; 32]
        || (value.step == PreparationStep::BeginMutation && value.failure_digest != [0; 32])
        || (value.step == PreparationStep::AbortBeforeMutation && value.failure_digest == [0; 32])
    {
        return Err("invalid initial attachment preparation proof".into());
    }
    let mut bytes = PREPARATION_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(value).map_err(|e| e.to_string())?);
    if bytes.len() as u64 > MAX_BYTES {
        return Err("preparation proof exceeds its size limit".into());
    }
    Ok(bytes)
}
pub(crate) fn verify_preparation(
    proof: &PreparationProof,
    accepted: &AcceptedOperationCertificate,
) -> Result<PreparationPayload, String> {
    if proof.payload.len() as u64 > MAX_BYTES {
        return Err("preparation proof exceeds its size limit".into());
    }
    let bytes = proof
        .payload
        .strip_prefix(PREPARATION_DOMAIN)
        .ok_or("invalid preparation proof domain")?;
    let value: PreparationPayload = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if preparation_bytes(&value)? != proof.payload
        || value.accepted_digest
            != wire::host_accepted_operation_digest(accepted).map_err(|e| e.to_string())?
    {
        return Err("preparation proof changes its accepted operation".into());
    }
    wire::verify_accepted_operation(&value.scope, accepted, crate::session::unix_timestamp_ms())
        .map_err(|e| e.to_string())?;
    verify(
        &value.scope.claimant.public_key,
        &proof.payload,
        &proof.signature,
    )?;
    Ok(value)
}
fn verify(key: &[u8; 32], payload: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| "invalid preparation verifier")?;
    if key.is_weak() {
        return Err("weak preparation verifier".into());
    }
    key.verify_strict(
        payload,
        &Signature::from_slice(signature).map_err(|_| "invalid preparation signature")?,
    )
    .map_err(|_| "preparation signature rejected".into())
}
pub(super) fn abort_receipt_bytes(receipt: &PreparationAbortReceipt) -> Result<Vec<u8>, String> {
    let mut bytes = ABORT_RECEIPT_DOMAIN.to_vec();
    bytes.extend(
        serde_json::to_vec(&(&receipt.proof, &receipt.accepted)).map_err(|e| e.to_string())?,
    );
    if bytes.len() as u64 > MAX_BYTES {
        return Err("preparation receipt exceeds its size limit".into());
    }
    Ok(bytes)
}
fn receipt_path(base: &Path, id: &str) -> PathBuf {
    base.join("aborted-preparations").join(id)
}
pub(crate) fn save_abort_receipt(
    base: &Path,
    receipt: &PreparationAbortReceipt,
) -> Result<(), String> {
    let value = verify_preparation(&receipt.proof, &receipt.accepted)?;
    if value.step != PreparationStep::AbortBeforeMutation {
        return Err("mutation admission is not an abort receipt".into());
    }
    verify(
        &value.scope.core_public_key,
        &abort_receipt_bytes(receipt)?,
        &receipt.signature,
    )?;
    let path = receipt_path(base, &value.scope.attachment_id);
    let bytes = serde_json::to_vec(receipt).map_err(|e| e.to_string())?;
    super::private_directory(path.parent().ok_or("invalid abort receipt path")?)?;
    if path.exists() {
        if super::read_private_file(&path, MAX_BYTES)? == bytes {
            return Ok(());
        }
        return Err("preparation abort receipt belongs to another operation".into());
    }
    super::create_private_file(&path, &bytes)
}
/// A verified Core receipt, not a writable display phase or missing recovery
/// file, proves that this exact initial attachment never crossed its gate.
pub fn verified_preparation_abort(base: &Path, execution: &Execution) -> Result<bool, String> {
    let path = receipt_path(base, &execution.spec.id);
    if !path.exists() {
        return Ok(false);
    }
    let receipt: PreparationAbortReceipt =
        serde_json::from_slice(&super::read_private_file(&path, MAX_BYTES)?)
            .map_err(|e| e.to_string())?;
    let value = verify_preparation(&receipt.proof, &receipt.accepted)?;
    let grant = &execution.authorization;
    super::verify_signature(base, grant)?;
    let expected = super::operation_scope_for_authorization(
        grant,
        &execution.bootstrap,
        value.scope.root_image.clone(),
    )?;
    if value.step != PreparationStep::AbortBeforeMutation || value.scope != expected {
        return Err("preparation abort receipt differs from approved execution".into());
    }
    verify(
        &value.scope.core_public_key,
        &abort_receipt_bytes(&receipt)?,
        &receipt.signature,
    )?;
    Ok(true)
}

pub async fn begin_initial_mutation(execution: &Execution) -> Result<(), String> {
    preparation_step(execution, PreparationStep::BeginMutation, None).await
}
pub async fn abort_before_initial_mutation(
    execution: &Execution,
    error: &str,
) -> Result<(), String> {
    preparation_step(execution, PreparationStep::AbortBeforeMutation, Some(error)).await
}
async fn preparation_step(
    execution: &Execution,
    step: PreparationStep,
    error: Option<&str>,
) -> Result<(), String> {
    use crate::session::{ControlRequest, ControlResponse};
    let (proof, accepted) = super::operation::prove_manager_preparation(execution, step, error)?;
    let manager = super::inspect_process(std::process::id())?;
    let request = ControlRequest::AttachmentPreparation {
        authorization: execution.authorization.clone(),
        bootstrap: execution.bootstrap.clone(),
        manager,
        accepted,
        proof,
    };
    let base = super::directory()?;
    let mut failure = "initial preparation request failed".to_owned();
    for _ in 0..2 {
        match crate::control::trusted_control_request(
            &execution.bootstrap.control_endpoint,
            &request,
        )
        .await
        {
            Ok(ControlResponse::Ok) if step == PreparationStep::BeginMutation => return Ok(()),
            Ok(ControlResponse::AttachmentPreparationAborted { receipt })
                if step == PreparationStep::AbortBeforeMutation =>
            {
                save_abort_receipt(&base, &receipt)?;
                if verified_preparation_abort(&base, execution)? {
                    return Ok(());
                }
            }
            Ok(ControlResponse::Error { message }) => {
                failure = message;
                break;
            }
            Ok(_) => {
                failure = "unexpected initial preparation reply".into();
                break;
            }
            Err(error) => failure = error.to_string(),
        }
        if step == PreparationStep::AbortBeforeMutation
            && verified_preparation_abort(&base, execution)?
        {
            return Ok(());
        }
    }
    Err(failure)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "preparation_tests.rs"]
mod tests;
