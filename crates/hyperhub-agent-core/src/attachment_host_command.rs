//! Live Host lifecycle admission. The registry lock serializes commands, while
//! the short state gate protects only state snapshots and final mutations.
//! Neither lock is requested through a reverse manager RPC.
use super::*;
use crate::host_command_registry::{
    CommandPermit, Consumption, HostCommandRegistry, HostStateStamp,
};
use hyperhub_runtime::attachment as wire;
use sha2::{Digest, Sha256};
use std::sync::MutexGuard;

static STATE_GATE: AtomicPtr<Mutex<()>> = AtomicPtr::new(std::ptr::null_mut());
static REGISTRY: AtomicPtr<Mutex<Option<HostCommandRegistry>>> =
    AtomicPtr::new(std::ptr::null_mut());
static PREPARED: AtomicPtr<Mutex<Option<ActivationPrepared>>> =
    AtomicPtr::new(std::ptr::null_mut());
static STATE_EPOCH: AtomicU64 = AtomicU64::new(1);
static EVER_ACTIVE: AtomicBool = AtomicBool::new(false);
struct ActivationPrepared {
    digest: [u8; 32],
    state: HostStateStamp,
}

fn slot<T: Default + 'static>(pointer: &AtomicPtr<Mutex<T>>) -> &'static Mutex<T> {
    let mut value = pointer.load(Ordering::Acquire);
    if value.is_null() {
        let fresh = Box::into_raw(Box::new(Mutex::new(T::default())));
        match pointer.compare_exchange(
            std::ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => value = fresh,
            Err(old) => {
                unsafe {
                    drop(Box::from_raw(fresh));
                }
                value = old;
            }
        }
    }
    unsafe { &*value }
}
pub(super) fn after_fork_child() {
    STATE_GATE.store(std::ptr::null_mut(), Ordering::Release);
    REGISTRY.store(std::ptr::null_mut(), Ordering::Release);
    PREPARED.store(std::ptr::null_mut(), Ordering::Release);
    STATE_EPOCH.store(1, Ordering::Release);
    EVER_ACTIVE.store(false, Ordering::Release);
}
pub(crate) fn state_gate() -> Result<MutexGuard<'static, ()>, String> {
    slot(&STATE_GATE)
        .lock()
        .map_err(|_| "Host lifecycle state gate unavailable".into())
}
pub(crate) fn advance_state_epoch() -> Result<(), String> {
    STATE_EPOCH
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
            epoch.checked_add(1)
        })
        .map(|_| ())
        .map_err(|_| "Host lifecycle state epoch exhausted".into())
}
/// Use only outside atfork/loader callbacks, before taking Agent state. Failed
/// mutations also advance the epoch because they may have changed partial state.
pub(crate) fn with_state_mutation<T>(
    mutation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let _gate = state_gate()?;
    advance_state_epoch()?;
    mutation()
}
pub(super) fn ever_active() -> bool {
    EVER_ACTIVE.load(Ordering::Acquire)
}
pub(super) fn mark_active() {
    EVER_ACTIVE.store(true, Ordering::Release);
}
fn stamp(accepted_digest: Option<[u8; 32]>) -> Result<HostStateStamp, String> {
    let boot = bootstrap().ok_or("attachment bootstrap unavailable")?;
    Ok(HostStateStamp {
        epoch: STATE_EPOCH.load(Ordering::Acquire),
        phase: status_phase(),
        native_ready: native_ready(),
        root_image: crate::root_image::current(),
        initially_owned: boot.initially_owned,
        ever_active: EVER_ACTIVE.load(Ordering::Acquire),
        preparation_cleanup: super::preparation_cleanup(),
        initialization_origin: startup::origin(),
        alias_paused: ALIAS_ADMISSION_PAUSED.load(Ordering::SeqCst),
        accepted_digest,
        unload_ready: STATE_RETIRED.load(Ordering::Acquire),
    })
}
pub(super) struct Execution<'a> {
    permit: Option<CommandPermit<'a>>,
    before_digest: Option<[u8; 32]>,
    accepted_digest: [u8; 32],
}
pub(super) fn activation_prepared(execution: &Option<&mut Execution<'_>>) -> Result<bool, String> {
    let execution = execution
        .as_deref()
        .ok_or("Host lifecycle possession is required")?;
    let _gate = state_gate()?;
    let current = stamp(execution.before_digest)?;
    let prepared = slot(&PREPARED)
        .lock()
        .map_err(|_| "Host activation preparation unavailable")?;
    Ok(prepared.as_ref().is_some_and(|prepared| {
        prepared.digest == execution.accepted_digest && prepared.state == current
    }) && crate::alias_namespace::admission_ready())
}
pub(super) fn remember_activation_prepared(
    execution: &Option<&mut Execution<'_>>,
) -> Result<(), String> {
    let execution = execution
        .as_deref()
        .ok_or("Host lifecycle possession is required")?;
    let _gate = state_gate()?;
    *slot(&PREPARED)
        .lock()
        .map_err(|_| "Host activation preparation unavailable")? = Some(ActivationPrepared {
        digest: execution.accepted_digest,
        state: stamp(execution.before_digest)?,
    });
    Ok(())
}
pub(super) fn commit_mutation(
    execution: &mut Option<&mut Execution<'_>>,
    mutation: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let execution = execution
        .as_deref_mut()
        .ok_or("Host lifecycle possession is required")?;
    let _gate = state_gate()?;
    let before = stamp(execution.before_digest)?;
    execution
        .permit
        .as_ref()
        .ok_or("Host lifecycle command was already completed")?
        .revalidate(&before)
        .map_err(|e| format!("Host lifecycle state changed: {e:?}"))?;
    advance_state_epoch()?;
    mutation()?;
    let after = stamp(Some(execution.accepted_digest))?;
    execution
        .permit
        .take()
        .unwrap()
        .commit(&before, &after)
        .map_err(|e| format!("Host lifecycle completion rejected: {e:?}"))
}
pub(super) fn finish_noop(execution: &mut Option<&mut Execution<'_>>) -> Result<(), String> {
    let Some(execution) = execution.as_deref_mut() else {
        return Ok(());
    };
    let _gate = state_gate()?;
    let before = stamp(execution.before_digest)?;
    execution
        .permit
        .take()
        .ok_or("Host lifecycle command was already completed")?
        .commit(&before, &before)
        .map_err(|e| format!("Host lifecycle no-op rejected: {e:?}"))
}

fn verified_scope(
    request: &AuthenticatedCommand,
    certificate: &wire::AcceptedOperationCertificate,
    purpose: wire::HostLifecycleCommand,
) -> Result<wire::OperationScope, String> {
    let boot = bootstrap().ok_or("attachment bootstrap unavailable")?;
    let proof = request
        .proof
        .as_ref()
        .ok_or("human approval proof is required for Host lifecycle")?;
    let now = now_ms();
    let retained = {
        let history = history()
            .lock()
            .map_err(|_| "approval history unavailable")?;
        history
            .last
            .as_ref()
            .filter(|last| {
                last.proof == *proof
                    && last.action == wire::ApprovedAction::Detach
                    && ((last.committed
                        && matches!(
                            purpose,
                            wire::HostLifecycleCommand::Detach
                                | wire::HostLifecycleCommand::Retire
                                | wire::HostLifecycleCommand::RollbackInitialAttachRetire
                        ))
                        || (!last.committed
                            && purpose == wire::HostLifecycleCommand::CancelDetachmentPreparation))
            })
            .map(|last| last.claims.clone())
    };
    let historical_continuation = retained.is_some();
    let claims = match retained {
        Some(claims) => claims,
        None => wire::verify_proof_with_key(
            &boot,
            &approval_public_key().ok_or("approval root is not enrolled")?,
            proof,
            now,
        )
        .map_err(|e| e.to_string())?,
    };
    if !historical_continuation {
        let history = history()
            .lock()
            .map_err(|_| "approval history unavailable")?;
        if !attachment_epoch_allows(
            claims.action,
            claims.approved_at_ms,
            history.last_detach_at.max(approval_not_before_ms()),
        ) {
            return Err("approval predates the current detach epoch".into());
        }
        if history.seen.contains_key(&claims.nonce)
            && !history
                .last
                .as_ref()
                .is_some_and(|last| last.nonce == claims.nonce && last.proof == *proof)
        {
            return Err("attachment approval nonce belongs to another accepted operation".into());
        }
    }
    let rollback = matches!(
        purpose,
        wire::HostLifecycleCommand::RollbackInitialAttach
            | wire::HostLifecycleCommand::RollbackInitialAttachRetire
    );
    if rollback && !super::initial_attach_rollback() {
        return Err("initial Attach rollback requires a fresh never-active initialization".into());
    }
    let preparation_detach = super::preparation_cleanup()
        && claims.action == wire::ApprovedAction::Detach
        && matches!(
            purpose,
            wire::HostLifecycleCommand::PrepareDetachment
                | wire::HostLifecycleCommand::CancelDetachmentPreparation
                | wire::HostLifecycleCommand::Detach
                | wire::HostLifecycleCommand::Retire
        )
        && crate::root_image::current().is_none();
    if !rollback && !preparation_detach {
        crate::root_image::verify_operation(&claims)?;
    }
    let root_image = match crate::root_image::current() {
        Some(image) => image,
        None if rollback || preparation_detach => {
            // These bytes are not trusted until verification below with the
            // administrator-endorsed Core key and all locally derived fields.
            let bytes = certificate
                .payload
                .strip_prefix(wire::OPERATION_ACCEPTED_DOMAIN)
                .ok_or("invalid accepted operation domain")?;
            serde_json::from_slice::<wire::AcceptedOperationPayload>(bytes)
                .map_err(|_| "invalid accepted operation payload")?
                .challenge
                .scope
                .root_image
        }
        None => return Err("Host has no trusted root image".into()),
    };
    if claims.root_image.as_ref() != Some(&root_image.identity)
        || claims.exec_epoch != root_image.exec_epoch
    {
        return Err("Host lifecycle approval differs from current root image".into());
    }
    let scope = wire::OperationScope {
        action: match claims.action {
            wire::ApprovedAction::Attach => wire::OperationAction::Attach,
            wire::ApprovedAction::Detach => wire::OperationAction::Detach,
        },
        administrator_digest: wire::operation_administrator_digest(proof)
            .map_err(|e| e.to_string())?,
        instance_id: boot.approval_instance_id.clone(),
        attachment_id: boot.attachment_id.clone(),
        session_id: boot.session_id.clone(),
        credential_digest: Sha256::digest(boot.token.as_bytes()).into(),
        host_binding: boot.approval_binding().map_err(|e| e.to_string())?,
        root_image,
        claimant: claims
            .manager_claimant
            .ok_or("approval has no delegated manager claimant")?,
        core_public_key: claims
            .core_attestation_public_key
            .ok_or("approval has no Core endorsement")?,
    };
    wire::verify_accepted_operation(&scope, certificate, now).map_err(|e| e.to_string())?;
    Ok(scope)
}

fn envelope(
    request: wire::HostLifecycleEnvelope,
    peer: u32,
) -> Result<wire::HostLifecycleReply, String> {
    let _access = crate::runtime::host_access().ok_or("attachment runtime storage is finalized")?;
    let (request, certificate, purpose, execution) = match request {
        wire::HostLifecycleEnvelope::Challenge {
            request,
            certificate,
            purpose,
        } => (request, certificate, purpose, None),
        wire::HostLifecycleEnvelope::Execute {
            request,
            certificate,
            purpose,
            nonce,
            possession,
        } => (request, certificate, purpose, Some((nonce, possession))),
    };
    let boot = bootstrap().ok_or("attachment bootstrap unavailable")?;
    if !local_owner()
        || request.attachment_id != boot.attachment_id
        || !equal(&request.token, &boot.host_token)
    {
        return Err("attachment authorization rejected".into());
    }
    if request.command == HostCommand::PrepareDetachment
        && status_phase() == HostPhase::Preparing
        && !super::preparation_cleanup()
    {
        return Err("activation_busy".into());
    }
    let mut registry_slot = slot(&REGISTRY)
        .lock()
        .map_err(|_| "Host lifecycle registry unavailable")?;
    let (scope, before) = {
        let _gate = state_gate()?;
        let scope = verified_scope(&request, &certificate, purpose)?;
        let accepted = registry_slot
            .as_ref()
            .and_then(HostCommandRegistry::accepted_digest);
        let before = stamp(accepted)?;
        if registry_slot.is_none() {
            *registry_slot = Some(
                HostCommandRegistry::new(before.clone())
                    .map_err(|e| format!("cannot initialize Host lifecycle registry: {e:?}"))?,
            );
        }
        (scope, before)
    };
    let registry = registry_slot.as_mut().unwrap();
    let Some((nonce, possession)) = execution else {
        let challenge = registry
            .issue(&request, &scope, &certificate, purpose, now_ms(), &before)
            .map_err(|e| format!("Host lifecycle challenge rejected: {e:?}"))?;
        return Ok(wire::HostLifecycleReply::challenge(challenge));
    };
    // The purpose is checked against the exact retained challenge, not merely
    // against a caller-selected execution branch.
    registry
        .verify_purpose(nonce, purpose)
        .map_err(|e| format!("Host lifecycle purpose rejected: {e:?}"))?;
    let digest = wire::host_accepted_operation_digest(&certificate).map_err(|e| e.to_string())?;
    let permit = match registry
        .consume(
            nonce,
            &request,
            &scope,
            &certificate,
            &possession,
            now_ms(),
            &before,
        )
        .map_err(|e| format!("Host lifecycle possession rejected: {e:?}"))?
    {
        Consumption::AlreadyCommitted => return Ok(wire::HostLifecycleReply::status(status())),
        Consumption::Execute(permit) => permit,
    };
    let mut execution = Execution {
        permit: Some(permit),
        before_digest: before.accepted_digest,
        accepted_digest: digest,
    };
    let status = super::command_semantic(request, peer, Some(&mut execution))?;
    if execution.permit.is_some() {
        return Err("Host lifecycle handler did not complete its admission".into());
    }
    Ok(wire::HostLifecycleReply::status(status))
}
pub(super) fn receive(value: serde_json::Value, peer: u32) -> serde_json::Value {
    let reply = if value.get("host_lifecycle").is_some() {
        match serde_json::from_value(value)
            .map_err(|_| "invalid Host lifecycle envelope".to_string())
            .and_then(|request| envelope(request, peer))
        {
            Ok(reply) => reply,
            Err(error) => wire::HostLifecycleReply::error(error),
        }
    } else {
        // Preserve the legacy read/enrollment reply shape. Lifecycle mutations
        // cannot use this path except the original owned startup duplicate.
        let result = serde_json::from_value(value)
            .map_err(|_| "invalid attachment command".to_string())
            .and_then(|request| super::command_with_peer(request, peer));
        return match result {
            Ok(status) => serde_json::json!({"status":status,"error":null}),
            Err(error) => serde_json::json!({"status":null,"error":error}),
        };
    };
    serde_json::to_value(reply).unwrap_or_else(|_| serde_json::json!({"challenge":null,"status":null,"error":"cannot encode lifecycle reply"}))
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(super) unsafe fn release_retired() {
    let registry = REGISTRY.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !registry.is_null() {
        drop(Box::from_raw(registry));
    }
    let prepared = PREPARED.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !prepared.is_null() {
        drop(Box::from_raw(prepared));
    }
    let gate = STATE_GATE.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !gate.is_null() {
        drop(Box::from_raw(gate));
    }
}

#[cfg(test)]
#[path = "attachment_host_command_tests.rs"]
pub(super) mod tests;
