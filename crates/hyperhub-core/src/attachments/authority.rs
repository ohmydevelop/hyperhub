use super::{Authorization, Request};
use crate::config_store::{self, ConfigKeyring, KdfDescriptor};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

pub const AUTHORIZATION_LIFETIME_MS: u64 = 10 * 60 * 1000;
const DOMAIN: &[u8] = b"hyperhub/runtime-attachment-approval/v1\0";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    schema_version: u32,
    config_id: [u8; 16],
    instance_id: String,
    public_key: [u8; 32],
}
#[derive(Serialize)]
struct Payload<'a> {
    request: &'a Request,
    approved_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 32],
    executor_sha256: &'a str,
    execution_digest: &'a Option<String>,
    host_binding: &'a Option<String>,
    core_attestation_public_key: &'a Option<[u8; 32]>,
    manager_claimant: &'a Option<hyperhub_runtime::attachment::ManagerClaimant>,
}
pub(super) fn payload(grant: &Authorization) -> Result<Vec<u8>, String> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(
        serde_json::to_vec(&Payload {
            request: &grant.request,
            approved_at_ms: grant.approved_at_ms,
            expires_at_ms: grant.expires_at_ms,
            nonce: grant.nonce,
            executor_sha256: &grant.executor_sha256,
            execution_digest: &grant.execution_digest,
            host_binding: &grant.host_binding,
            core_attestation_public_key: &grant.core_attestation_public_key,
            manager_claimant: &grant.manager_claimant,
        })
        .map_err(|e| e.to_string())?,
    );
    Ok(bytes)
}
pub fn instance_id(config_path: &Path, _descriptor: &KdfDescriptor) -> String {
    // Instance identity outlives encryption-key generations. Current authority
    // verification still binds config_id and rotates the signing verifier.
    let mut bytes = b"hyperhub/attachment-instance/v1\0".to_vec();
    let absolute = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(config_path)
    };
    let normalized = absolute
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .and_then(|p| absolute.file_name().map(|name| p.join(name)))
        .unwrap_or(absolute);
    bytes.extend_from_slice(normalized.as_os_str().to_string_lossy().as_bytes());
    super::digest(&bytes)
}
/// This KDF is intentionally independent of the runtime-envelope master.
/// Possession of the API key and that master does not reveal this signing seed.
pub(super) fn signing_key(
    password: &[u8],
    descriptor: &KdfDescriptor,
) -> Result<SigningKey, String> {
    let seed = config_store::derive_password_approval_seed(password, descriptor)
        .map_err(|e| e.to_string())?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&bytes))
}
fn read_authority(directory: &Path) -> Result<Authority, String> {
    let bytes = super::read_private_file(&directory.join("authority.json"), 4096)?;
    let authority: Authority = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if authority.schema_version != 1 {
        return Err("unsupported attachment authority".into());
    }
    Ok(authority)
}
/// Call only after the administrator password successfully unlocks config.
/// An existing verifier can never be replaced through runtime API authority.
pub fn authorize(
    directory: &Path,
    config_path: &Path,
    password: &[u8],
    descriptor: &KdfDescriptor,
    request: Request,
    now: u64,
) -> Result<Authorization, String> {
    authorize_bound(
        directory,
        config_path,
        password,
        descriptor,
        request,
        now,
        None,
        super::executor_digest()?,
        None,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn authorize_bound(
    directory: &Path,
    config_path: &Path,
    password: &[u8],
    descriptor: &KdfDescriptor,
    request: Request,
    now: u64,
    execution_digest: Option<String>,
    executor_sha256: String,
    host_binding: Option<String>,
) -> Result<Authorization, String> {
    authorize_claimant_bound(
        directory,
        config_path,
        password,
        descriptor,
        request,
        now,
        execution_digest,
        executor_sha256,
        host_binding,
        super::manager_operation_claimant()?,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn authorize_claimant_bound(
    directory: &Path,
    config_path: &Path,
    password: &[u8],
    descriptor: &KdfDescriptor,
    request: Request,
    now: u64,
    execution_digest: Option<String>,
    executor_sha256: String,
    host_binding: Option<String>,
    manager_claimant: hyperhub_runtime::attachment::ManagerClaimant,
) -> Result<Authorization, String> {
    manager_claimant.validate().map_err(|e| e.to_string())?;
    request.validate()?;
    if executor_sha256.len() != 64 || !executor_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("approval executor fingerprint is invalid".into());
    }
    let unlocked =
        config_store::load_encrypted(config_path, password).map_err(|e| e.to_string())?;
    if &unlocked.descriptor != descriptor {
        return Err("configuration generation changed during approval".into());
    }
    let key = signing_key(password, descriptor)?;
    let instance = instance_id(config_path, descriptor);
    if request.instance_id != instance {
        return Err("approval belongs to a different instance".into());
    }
    super::private_directory(directory)?;
    super::trust::pin_authority(
        directory,
        super::ApprovalAuthority {
            instance_id: instance.clone(),
            config_id: descriptor.config_id,
            public_key: key.verifying_key().to_bytes(),
            generation: unlocked.approval_continuity.len() as u64,
        },
        None,
    )?;
    let authority_path = directory.join("authority.json");
    if authority_path.exists() {
        let existing = read_authority(directory)?;
        if existing.public_key != key.verifying_key().to_bytes()
            || existing.config_id != descriptor.config_id
            || existing.instance_id != instance
        {
            let authority = Authority {
                schema_version: 1,
                config_id: descriptor.config_id,
                instance_id: instance.clone(),
                public_key: key.verifying_key().to_bytes(),
            };
            config_store::save_durable_private_bytes(
                &authority_path,
                &serde_json::to_vec(&authority).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        }
    } else {
        let authority = Authority {
            schema_version: 1,
            config_id: descriptor.config_id,
            instance_id: instance,
            public_key: key.verifying_key().to_bytes(),
        };
        super::create_private_file(
            &authority_path,
            &serde_json::to_vec(&authority).map_err(|e| e.to_string())?,
        )?;
    }
    let mut grant = Authorization {
        request,
        approved_at_ms: now,
        expires_at_ms: now
            .checked_add(AUTHORIZATION_LIFETIME_MS)
            .ok_or("invalid approval time")?,
        nonce: rand::random(),
        executor_sha256,
        execution_digest,
        host_binding,
        core_attestation_public_key: super::trust::remote_core_key(directory),
        manager_claimant: Some(manager_claimant),
        signature: Vec::new(),
    };
    grant.signature = key.sign(&payload(&grant)?).to_bytes().to_vec();
    Ok(grant)
}
pub fn verify_authorization_at(
    directory: &Path,
    grant: &Authorization,
    now: u64,
) -> Result<(), String> {
    grant.request.validate()?;
    if grant.approved_at_ms > now
        || grant.expires_at_ms <= now
        || grant.expires_at_ms.checked_sub(grant.approved_at_ms) != Some(AUTHORIZATION_LIFETIME_MS)
    {
        return Err("attachment authorization expired or has invalid time bounds".into());
    }
    verify_signature(directory, grant)
}
pub fn verify_authorization(directory: &Path, grant: &Authorization) -> Result<(), String> {
    verify_authorization_at(directory, grant, crate::session::unix_timestamp_ms())
}
/// Recovery may verify an old signed decision, but this does not authorize a new operation.
pub fn verify_signature(directory: &Path, grant: &Authorization) -> Result<(), String> {
    let authority = super::trusted_authority(directory)?;
    if authority.instance_id != grant.request.instance_id {
        return Err("attachment authorization instance mismatch".into());
    }
    let key = VerifyingKey::from_bytes(&authority.public_key)
        .map_err(|_| "invalid attachment approval verifier")?;
    let signature = Signature::from_slice(&grant.signature)
        .map_err(|_| "invalid attachment approval signature")?;
    key.verify_strict(&payload(grant)?, &signature)
        .map_err(|_| "attachment approval signature rejected".into())
}
/// Create an exclusive durable marker before any target mutation. Replays fail.
pub fn consume_authorization(directory: &Path, grant: &Authorization) -> Result<(), String> {
    if let Some(endpoint) = super::trust::remote_endpoint(directory) {
        let directory = directory.to_path_buf();
        let grant = grant.clone();
        return std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let manager = super::inspect_process(std::process::id())?;
            let bootstrap =
                super::manager_operation_bootstrap(grant.request.action.attachment_id())?;
            if grant.manager_claimant.as_ref() != Some(&super::manager_operation_claimant()?) {
                return Err("approval belongs to another delegated manager key".into());
            }
            let begin = runtime
                .block_on(crate::control::trusted_control_request(
                    &endpoint,
                    &crate::session::ControlRequest::BeginAttachmentConsumption {
                        authorization: grant.clone(),
                        manager: manager.clone(),
                        bootstrap: bootstrap.clone(),
                    },
                ))
                .map_err(|e| e.to_string())?;
            let challenge = match begin {
                crate::session::ControlResponse::OperationPossessionChallenge { challenge } => {
                    challenge
                }
                crate::session::ControlResponse::Error { message } => return Err(message),
                _ => return Err("unexpected operation challenge reply".into()),
            };
            let scope = super::operation_scope_for_authorization(
                &grant,
                &bootstrap,
                challenge.scope.root_image.clone(),
            )?;
            if challenge.scope != scope {
                return Err("Core possession challenge changes the signed operation scope".into());
            }
            let possession =
                super::prove_manager_operation(&challenge, crate::session::unix_timestamp_ms())?;
            let response = runtime
                .block_on(crate::control::trusted_control_request(
                    &endpoint,
                    &crate::session::ControlRequest::ConsumeAttachmentAuthorization {
                        authorization: grant.clone(),
                        manager: manager.clone(),
                        bootstrap,
                        nonce: challenge.nonce,
                        possession,
                    },
                ))
                .map_err(|e| e.to_string())?;
            match response {
                crate::session::ControlResponse::AcceptedAttachmentOperation { certificate } => {
                    super::remember_accepted_operation(&scope, certificate)?;
                    let verifier = super::trusted_authority(&directory)?.public_key;
                    let value = Consumption {
                        authorization: grant.clone(),
                        pid: manager.pid,
                        birth: manager.birth,
                        verifier: Some(verifier),
                        instance_id: grant.request.instance_id.clone(),
                        activation_epoch: super::trust::activation_epoch(
                            &directory,
                            grant.request.action.attachment_id(),
                        ),
                    };
                    super::trust::remember_consumption(
                        &directory,
                        &grant.nonce,
                        serde_json::to_vec(&value).map_err(|e| e.to_string())?,
                    )
                }
                crate::session::ControlResponse::Error { message } => Err(message),
                _ => Err("unexpected approval consumption reply".into()),
            }
        })
        .join()
        .map_err(|_| "approval consumption worker failed")?;
    }
    let manager = super::inspect_process(std::process::id())?;
    consume_for_claimant(directory, grant, &manager)
}
pub(crate) fn consume_for_claimant(
    directory: &Path,
    grant: &Authorization,
    manager: &super::ProcessIdentity,
) -> Result<(), String> {
    verify_authorization(directory, grant)?;
    if grant
        .manager_claimant
        .as_ref()
        .is_none_or(|claimant| claimant.pid != manager.pid || claimant.birth != manager.birth)
    {
        return Err("approval is not signed for the actual manager incarnation".into());
    }
    super::trust::reject_stale_detach(directory, grant)?;
    if super::trust::trusted_consumption(directory, &grant.nonce).is_some() {
        return Err("attachment authorization was already consumed".into());
    }
    let accepted = super::trusted_authority(directory)?;
    let value = Consumption {
        authorization: grant.clone(),
        pid: manager.pid,
        birth: manager.birth,
        verifier: Some(accepted.public_key),
        instance_id: grant.request.instance_id.clone(),
        activation_epoch: super::trust::activation_epoch(
            directory,
            grant.request.action.attachment_id(),
        ),
    };
    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    let used = directory.join("consumed");
    super::private_directory(&used)?;
    super::create_private_file(&used.join(super::digest(&grant.nonce)), &bytes)?;
    super::trust::remember_consumption(directory, &grant.nonce, bytes)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Consumption {
    pub(super) authorization: Authorization,
    pub(super) pid: u32,
    pub(super) birth: u64,
    #[serde(default)]
    pub(super) verifier: Option<[u8; 32]>,
    #[serde(default)]
    pub(super) instance_id: String,
    #[serde(default)]
    pub(super) activation_epoch: Option<String>,
}
pub fn authorization_consumed_by(directory: &Path, grant: &Authorization, pid: u32) -> bool {
    let Some(bytes) = super::trust::trusted_consumption(directory, &grant.nonce) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<Consumption>(&bytes) else {
        return false;
    };
    value.pid == pid
        && crate::session::process_start_time(pid) == Some(value.birth)
        && value.authorization.signature == grant.signature
        && payload(&value.authorization).ok() == payload(grant).ok()
}

/// Exact signed bytes for the target Host. A session/API token alone never
/// authorizes lifecycle mutation, even if runtime transport state is readable.
pub fn host_proof(
    grant: &Authorization,
) -> Result<hyperhub_runtime::attachment::ApprovalProof, String> {
    Ok(hyperhub_runtime::attachment::ApprovalProof {
        payload: payload(grant)?,
        signature: grant.signature.clone(),
    })
}

/// Revoke old human approvals before committing a different encryption generation.
/// The verifier is removed rather than rewritten with runtime-key-derived material.
/// Its absence fails closed in live Hosts; a later authenticated human approval
/// enrolls the new password-derived verifier. Consumed nonces remain durable.
pub(crate) fn invalidate_authority_for_config_write_guarded(
    config_path: &Path,
    keyring: &ConfigKeyring,
    existing_guard: Option<&super::OperationGuard>,
) -> Result<Option<super::OperationGuard>, String> {
    let Some(parent) = config_path.parent() else {
        return Ok(None);
    };
    let directory = parent.join("runtime").join("attachments");
    if let Some(guard) = existing_guard {
        guard.protects(&directory)?;
    }
    let authority_path = directory.join("authority.json");
    if !authority_path.exists() {
        return Ok(None);
    }
    let authority = read_authority(&directory)?;
    if authority.instance_id != instance_id(config_path, keyring.descriptor()) {
        return Ok(None);
    }
    // Ordinary edits using the current key retain pending approvals. A changed
    // password with a deliberately reused descriptor still fails this decrypt.
    if authority.config_id == keyring.descriptor().config_id
        && config_store::load_encrypted_with_keyring(config_path, keyring).is_ok()
    {
        return Ok(None);
    }
    let guard = if existing_guard.is_none() {
        Some(super::OperationGuard::acquire(&directory)?)
    } else {
        None
    };
    super::trust::invalidate_memory_authority(&directory);
    std::fs::remove_file(&authority_path)
        .map_err(|e| format!("cannot revoke previous attachment approvals: {e}"))?;
    #[cfg(unix)]
    std::fs::File::open(&directory)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("cannot persist attachment authority revocation: {e}"))?;
    Ok(guard)
}

/// Verify continuation of an already accepted operation against its immutable
/// consumed-ledger verifier. This does not authorize any new lifecycle action.
/// It deliberately survives time expiry and later administrator-key rotation.
pub fn verify_consumed_continuation(
    directory: &Path,
    grant: &Authorization,
    pid: u32,
) -> Result<(), String> {
    let bytes = super::trust::trusted_consumption(directory, &grant.nonce).ok_or(
        "operation has no trusted in-memory acceptance; fresh recovery approval is required",
    )?;
    let audit = super::read_private_file(
        &directory.join("consumed").join(super::digest(&grant.nonce)),
        1024 * 1024,
    )?;
    if audit != bytes {
        return Err("consumed audit differs from trusted accepted operation".into());
    }
    let value: Consumption = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value.pid != pid
        || crate::session::process_start_time(pid) != Some(value.birth)
        || value.authorization.signature != grant.signature
        || payload(&value.authorization)? != payload(grant)?
        || value.instance_id != grant.request.instance_id
    {
        return Err("continuation differs from the consumed operation or OS claimant".into());
    }
    if matches!(grant.request.action, super::Action::Detach { .. }) {
        super::trust::under_consumed_epoch(directory, grant, || ())?;
    }
    let verifier = value.verifier.ok_or(
        "consumed operation has no retained approval verifier; fresh human approval is required",
    )?;
    let key =
        VerifyingKey::from_bytes(&verifier).map_err(|_| "invalid consumed approval verifier")?;
    let signature = Signature::from_slice(&grant.signature)
        .map_err(|_| "invalid consumed approval signature")?;
    key.verify_strict(&payload(grant)?, &signature)
        .map_err(|_| "consumed approval signature rejected".into())
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletionReceipt {
    pub(super) attachment_id: String,
    pub(super) target: super::ProcessIdentity,
    pub(super) authorization_digest: String,
    pub(super) session_id: String,
    pub(super) credential_digest: String,
    pub(super) pid: u32,
    pub(super) birth: u64,
}
pub(super) fn completion_receipt(
    grant: &Authorization,
    session: &str,
    token: &str,
    manager: &super::ProcessIdentity,
) -> Result<CompletionReceipt, String> {
    let mut signed = payload(grant)?;
    signed.extend(&grant.signature);
    Ok(CompletionReceipt {
        attachment_id: grant.request.action.attachment_id().into(),
        target: grant.request.action.target().clone(),
        authorization_digest: super::digest(&signed),
        session_id: session.into(),
        credential_digest: super::digest(token.as_bytes()),
        pid: manager.pid,
        birth: manager.birth,
    })
}
pub fn completion_receipt_matches(
    directory: &Path,
    grant: &Authorization,
    session: &str,
    token: &str,
    manager: &super::ProcessIdentity,
) -> bool {
    let Some(bytes) = super::trust::trusted_completion(directory, &super::digest(&grant.nonce))
    else {
        return false;
    };
    let Ok(receipt) = serde_json::from_slice::<CompletionReceipt>(&bytes) else {
        return false;
    };
    completion_receipt(grant, session, token, manager).is_ok_and(|expected| receipt == expected)
}
/// Write before revocation so an ACK loss/crash can safely retry the same exact
/// operation. A receipt never permits a different session/token/claimant.
pub fn record_completion_receipt(
    directory: &Path,
    grant: &Authorization,
    session: &str,
    token: &str,
    manager: &super::ProcessIdentity,
) -> Result<(), String> {
    let base = directory
        .join("completions")
        .join(grant.request.action.attachment_id());
    super::private_directory(&base)?;
    let path = base.join(super::digest(&grant.nonce));
    if path.exists() {
        let bytes = super::read_private_file(&path, 64 * 1024)?;
        let expected = serde_json::to_vec(&completion_receipt(grant, session, token, manager)?)
            .map_err(|e| e.to_string())?;
        if bytes != expected {
            return Err("completion receipt belongs to another operation".into());
        }
        super::trust::remember_completion(directory, super::digest(&grant.nonce), bytes);
        return Ok(());
    }
    let bytes = serde_json::to_vec(&completion_receipt(grant, session, token, manager)?)
        .map_err(|e| e.to_string())?;
    super::create_private_file(&path, &bytes)?;
    super::trust::remember_completion(directory, super::digest(&grant.nonce), bytes);
    Ok(())
}

/// A NEW signed cleanup request can finish an already committed revocation
/// after its old manager dies. It cannot reactivate or create session members.
pub fn prior_completion_receipt_matches(
    directory: &Path,
    cleanup: &Authorization,
    session: &str,
    token: &str,
) -> bool {
    let super::Action::Detach {
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
    if super::completion_evidence::prior_completion_matches(directory, cleanup, session, token) {
        return true;
    }
    let base = directory.join("completions").join(attachment_id);
    let Ok(entries) = std::fs::read_dir(base) else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(bytes) = super::read_private_file(&entry.path(), 64 * 1024) else {
            continue;
        };
        let Ok(receipt) = serde_json::from_slice::<CompletionReceipt>(&bytes) else {
            continue;
        };
        if receipt.attachment_id != *attachment_id
            || receipt.target != *target
            || receipt.pid != binding.manager.pid
            || receipt.birth != binding.manager.birth
        {
            continue;
        }
        let Ok(bytes) = super::read_private_file(
            &directory.join("consumed").join(entry.file_name()),
            1024 * 1024,
        ) else {
            continue;
        };
        let Ok(consumed) = serde_json::from_slice::<Consumption>(&bytes) else {
            continue;
        };
        if super::trust::trusted_consumption(directory, &consumed.authorization.nonce).as_deref()
            != Some(bytes.as_slice())
            || super::trust::trusted_completion(
                directory,
                &super::digest(&consumed.authorization.nonce),
            )
            .as_deref()
                != serde_json::to_vec(&receipt).ok().as_deref()
        {
            continue;
        }
        let old = &consumed.authorization;
        if consumed.pid != binding.manager.pid
            || consumed.birth != binding.manager.birth
            || consumed.instance_id != cleanup.request.instance_id
            || old.request.instance_id != cleanup.request.instance_id
            || old.executor_sha256 != binding.manager.executable_sha256
            || !matches!(old.request.action, super::Action::Detach { .. })
            || old.request.action.attachment_id() != attachment_id
            || old.request.action.target() != target
        {
            continue;
        }
        let Some(verifier) = consumed.verifier else {
            continue;
        };
        let Ok(key) = VerifyingKey::from_bytes(&verifier) else {
            continue;
        };
        let Ok(signature) = Signature::from_slice(&old.signature) else {
            continue;
        };
        let Ok(payload) = payload(old) else {
            continue;
        };
        if key.verify_strict(&payload, &signature).is_err() {
            continue;
        }
        if completion_receipt(old, session, token, &binding.manager)
            .is_ok_and(|expected| receipt == expected)
        {
            return true;
        }
    }
    false
}
