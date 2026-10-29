//! Executable identity is a lifecycle boundary even when exec preserves PID,
//! birth and executable bytes. Fresh SDKs challenge the live pinned Core.
use crate::HH_ERR_PROTOCOL;
use hyperhub_runtime::attachment::{
    self as wire, ApprovalProof, Bootstrap, RootImageIdentity, RootImageState, SignedRootImage,
};
use std::sync::atomic::{AtomicU32, Ordering};
static CHALLENGED_OWNER: AtomicU32 = AtomicU32::new(0);
pub(crate) fn clear_challenge() {
    CHALLENGED_OWNER.store(0, Ordering::Release);
}
pub(crate) fn current() -> Option<RootImageState> {
    if !crate::attachment::startup::runtime_available() {
        return None;
    }
    let _access = crate::runtime::host_access()?;
    crate::state().lock().ok()?.gateway.root_image.clone()
}
/// Diagnostic reads must not wait for an initializer. Authentication uses
/// current() under the lifecycle gate and never treats a busy lock as absence.
pub(crate) fn current_for_status() -> Option<RootImageState> {
    if !crate::attachment::startup::runtime_available() {
        return None;
    }
    let _access = crate::runtime::host_access()?;
    crate::state().try_lock().ok()?.gateway.root_image.clone()
}
pub(crate) fn self_identity() -> Result<RootImageIdentity, i32> {
    let read = || {
        let _access = crate::runtime::host_access().ok_or(HH_ERR_PROTOCOL)?;
        let incarnation =
            wire::process_incarnation(std::process::id()).map_err(|_| HH_ERR_PROTOCOL)?;
        let cached = if !crate::attachment::startup::runtime_available() {
            None
        } else {
            let _gate = crate::attachment::state_gate().map_err(|_| HH_ERR_PROTOCOL)?;
            let state = crate::state().try_lock().ok();
            state.and_then(|state| {
                challenged_self_image(
                    &state.gateway,
                    incarnation,
                    CHALLENGED_OWNER.load(Ordering::Acquire),
                )
            })
        };
        if let Some(identity) = cached {
            return Ok(identity);
        }
        // First use, fork, or unchallenged staged metadata still reads and
        // hashes the actual OS executable. Only this SDK's proved image is cached.
        let identity = wire::process_identity(std::process::id()).map_err(|_| HH_ERR_PROTOCOL)?;
        if identity.birth != incarnation.birth {
            return Err(HH_ERR_PROTOCOL);
        }
        Ok(RootImageIdentity {
            pid: identity.pid,
            birth: identity.birth,
            executable_sha256: identity.executable_sha256,
        })
    };
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    {
        crate::engine_call::background(read)
    }
    #[cfg(not(all(any(windows, target_os = "linux"), feature = "gum-agent")))]
    {
        read()
    }
}
fn challenged_self_image(
    gateway: &crate::GatewayState,
    incarnation: wire::ProcessIncarnation,
    challenged_owner: u32,
) -> Option<RootImageIdentity> {
    if !gateway.root_image_challenged || challenged_owner != incarnation.pid {
        return None;
    }
    gateway
        .self_image
        .as_ref()
        .filter(|identity| identity.pid == incarnation.pid && identity.birth == incarnation.birth)
        .cloned()
}

fn signer(bootstrap: &Bootstrap) -> Result<[u8; 32], String> {
    let runtime_key = if crate::attachment::startup::runtime_available() {
        crate::state()
            .lock()
            .ok()
            .and_then(|state| state.gateway.root_image_signer)
            .or_else(|| crate::alias_namespace::inheritance().map(|anchor| anchor.public_key))
    } else {
        None
    };
    runtime_key
        .or(bootstrap.approval_core_public_key)
        .ok_or_else(|| "live Core root image attestation is unavailable".into())
}
pub(crate) fn accept_snapshot(
    bootstrap: &Bootstrap,
    packet: &SignedRootImage,
    challenge: &[u8; 32],
    recipient: &RootImageIdentity,
    proof: Option<&ApprovalProof>,
) -> Result<(), String> {
    let old_signer = signer(bootstrap)?;
    let endorsement = proof
        .map(crate::attachment::verify_root_endorsement)
        .transpose()?;
    let key = endorsement
        .as_ref()
        .and_then(|claims| claims.core_attestation_public_key)
        .unwrap_or(old_signer);
    let value = wire::verify_root_image_snapshot(bootstrap, &key, packet, challenge, recipient)
        .map_err(|e| e.to_string())?;
    if let Some(claims) = &endorsement {
        if claims.root_image.as_ref() != Some(&value.current.identity)
            || claims.exec_epoch != value.current.exec_epoch
        {
            return Err("endorsed Core snapshot differs from the approved root image epoch".into());
        }
    }
    if value.challenge.as_ref() != Some(challenge)
        || value.host_pid != Some(recipient.pid)
        || value.host_birth != Some(recipient.birth)
    {
        return Err("root image snapshot is not the outstanding live Host challenge".into());
    }
    if recipient.pid == bootstrap.root_pid && &value.current.identity != recipient {
        return Err("root image snapshot does not describe this actual executable".into());
    }
    let _gate = crate::attachment::state_gate()?;
    crate::attachment::startup::check().map_err(|_| "attachment initialization was cancelled")?;
    let mut state = crate::state()
        .lock()
        .map_err(|_| "root image state unavailable")?;
    if let Some(old) = &state.gateway.root_image {
        if !wire::root_image_snapshot_is_current(old, &value.current).map_err(|e| e.to_string())? {
            return Err("root_image_snapshot_stale".into());
        }
    }
    if state.gateway.root_image_challenged
        && state.gateway.self_image.as_ref() == Some(recipient)
        && state.gateway.root_image_signer == Some(key)
        && state.gateway.root_image.as_ref() == Some(&value.current)
        && CHALLENGED_OWNER.load(Ordering::Acquire) == std::process::id()
    {
        return Ok(());
    }
    crate::attachment::advance_state_epoch()?;
    state.gateway.root_image_challenged = true;
    state.gateway.self_image = Some(recipient.clone());
    state.gateway.root_image_signer = Some(key);
    state.gateway.root_image = Some(value.current);
    CHALLENGED_OWNER.store(std::process::id(), Ordering::Release);
    Ok(())
}
pub(crate) fn apply_transition(
    bootstrap: &Bootstrap,
    packet: &SignedRootImage,
    proof: Option<&ApprovalProof>,
) -> Result<(), String> {
    let current_signer = signer(bootstrap)?;
    let endorsement = proof
        .map(crate::attachment::verify_root_endorsement)
        .transpose()?;
    let key = endorsement
        .as_ref()
        .and_then(|claims| claims.core_attestation_public_key)
        .unwrap_or(current_signer);
    let value = wire::decode_root_image(bootstrap, &key, packet).map_err(|e| e.to_string())?;
    if let Some(claims) = &endorsement {
        if claims.root_image.as_ref() != Some(&value.current.identity)
            || claims.exec_epoch != value.current.exec_epoch
        {
            return Err("endorsed transition differs from the approved root image epoch".into());
        }
    }
    if value.challenge.is_some() {
        return Err("an unsolicited challenged root image cannot initialize this Host".into());
    }
    let actual_self = if bootstrap.root_pid == std::process::id() {
        Some(self_identity().map_err(|_| "cannot verify the actual root executable")?)
    } else {
        None
    };
    let _gate = crate::attachment::state_gate()?;
    let mut state = crate::state()
        .lock()
        .map_err(|_| "root image state unavailable")?;
    if state.gateway.root_image.is_none() {
        if crate::attachment::status_phase() != wire::HostPhase::Preparing {
            return Err("root image was not initialized by a live challenge".into());
        }
        if actual_self
            .as_ref()
            .is_some_and(|identity| identity != &value.current.identity)
        {
            return Err("staged root image does not match the actual executable".into());
        }
        crate::attachment::advance_state_epoch()?;
        state.gateway.root_image = Some(value.current);
        state.gateway.root_image_signer = Some(key);
        state.gateway.self_image = actual_self;
        // A signed transition can establish a retained prefix, never freshness.
        // The new Host still needs its own live nonce before any lifecycle grant.
        return Ok(());
    }
    let previous = state.gateway.root_image.as_ref().unwrap();
    wire::verify_root_image_continuation(previous, &value).map_err(|e| e.to_string())?;
    if value.current == *previous {
        if state.gateway.root_image_signer != Some(key) {
            crate::attachment::advance_state_epoch()?;
            state.gateway.root_image_signer = Some(key);
        }
        return Ok(());
    }
    if bootstrap.root_pid == std::process::id()
        && state.gateway.self_image.as_ref() != Some(&value.current.identity)
    {
        return Err("root image transition does not match the running executable".into());
    }
    crate::attachment::advance_state_epoch()?;
    state.gateway.root_image_signer = Some(key);
    state.gateway.root_image = Some(value.current);
    Ok(())
}
pub(crate) fn verify_operation(claims: &wire::ApprovalClaims) -> Result<(), String> {
    with_verified_operation(claims, |_| ())
}
pub(crate) fn with_verified_operation<T>(
    claims: &wire::ApprovalClaims,
    commit: impl FnOnce(&mut crate::AgentRuntime) -> T,
) -> Result<T, String> {
    let _access = crate::runtime::host_access().ok_or("attachment runtime storage is finalized")?;
    let bootstrap = crate::attachment::bootstrap().ok_or("attachment bootstrap unavailable")?;
    let mut state = crate::state()
        .lock()
        .map_err(|_| "root image state unavailable")?;
    if bootstrap.approval_root_identity.is_none() {
        return Ok(commit(&mut state));
    }
    verify_bound_operation(
        bootstrap.root_pid,
        claims,
        state.gateway.root_image.as_ref(),
        state.gateway.self_image.as_ref(),
        CHALLENGED_OWNER.load(Ordering::Acquire) == std::process::id()
            && state.gateway.root_image_challenged,
    )?;
    Ok(commit(&mut state))
}
fn verify_bound_operation(
    root_pid: u32,
    claims: &wire::ApprovalClaims,
    actual: Option<&RootImageState>,
    self_image: Option<&RootImageIdentity>,
    challenged: bool,
) -> Result<(), String> {
    if !challenged {
        return Err("root image has no fresh live Host challenge".into());
    }
    let actual = actual.ok_or("root image lifecycle attestation is unavailable")?;
    if claims.exec_epoch != actual.exec_epoch
        || claims.root_image.as_ref() != Some(&actual.identity)
    {
        return Err("approval targets an older executable image or exec epoch".into());
    }
    if root_pid == std::process::id() && self_image != Some(&actual.identity) {
        return Err("approval does not match this actual executable".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_image_cache_requires_a_live_challenge_and_exact_os_incarnation() {
        let image = state(0).identity;
        let incarnation = wire::ProcessIncarnation {
            pid: image.pid,
            birth: image.birth,
        };
        let mut gateway = crate::GatewayState::default();
        gateway.self_image = Some(image.clone());
        assert!(challenged_self_image(&gateway, incarnation, image.pid).is_none());
        gateway.root_image_challenged = true;
        assert_eq!(
            challenged_self_image(&gateway, incarnation, image.pid),
            Some(image.clone())
        );
        assert!(challenged_self_image(&gateway, incarnation, 0).is_none());
        assert!(challenged_self_image(
            &gateway,
            wire::ProcessIncarnation {
                pid: image.pid + 1,
                ..incarnation
            },
            image.pid + 1
        )
        .is_none());
        assert!(challenged_self_image(
            &gateway,
            wire::ProcessIncarnation {
                birth: image.birth + 1,
                ..incarnation
            },
            image.pid
        )
        .is_none());
        gateway.self_image = None;
        assert!(challenged_self_image(&gateway, incarnation, image.pid).is_none());
    }
    fn state(epoch: u64) -> RootImageState {
        RootImageState {
            identity: RootImageIdentity {
                pid: std::process::id(),
                birth: 45,
                executable_sha256: "a".repeat(64),
            },
            exec_epoch: epoch,
            observed_at_ms: epoch,
            head: [epoch as u8; 32],
        }
    }
    fn claims(state: &RootImageState) -> wire::ApprovalClaims {
        wire::ApprovalClaims {
            manager_claimant: None,
            action: wire::ApprovedAction::Attach,
            nonce: [1; 32],
            approved_at_ms: 100,
            expires_at_ms: 500,
            core_attestation_public_key: None,
            root_image: Some(state.identity.clone()),
            exec_epoch: state.exec_epoch,
        }
    }
    #[test]
    fn staged_transition_does_not_authorize_a_fresh_lifecycle_grant() {
        let state = state(1);
        let claims = claims(&state);
        assert!(verify_bound_operation(
            state.identity.pid,
            &claims,
            Some(&state),
            Some(&state.identity),
            false
        )
        .is_err());
        verify_bound_operation(
            state.identity.pid,
            &claims,
            Some(&state),
            Some(&state.identity),
            true,
        )
        .unwrap();
    }
    #[test]
    fn inflight_activation_is_rechecked_after_a_same_image_epoch_changes() {
        let previous = state(1);
        let current = state(2);
        let accepted = claims(&previous);
        verify_bound_operation(
            previous.identity.pid,
            &accepted,
            Some(&previous),
            Some(&previous.identity),
            true,
        )
        .unwrap();
        assert!(verify_bound_operation(
            current.identity.pid,
            &accepted,
            Some(&current),
            Some(&current.identity),
            true
        )
        .is_err());
        verify_bound_operation(
            current.identity.pid,
            &claims(&current),
            Some(&current),
            Some(&current.identity),
            true,
        )
        .unwrap();
        let mut wrong = current.identity.clone();
        wrong.executable_sha256 = "b".repeat(64);
        assert!(verify_bound_operation(
            current.identity.pid,
            &claims(&current),
            Some(&current),
            Some(&wrong),
            true
        )
        .is_err());
    }
}
