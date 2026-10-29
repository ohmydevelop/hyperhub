//! Manager-only Host command exchange. Core services never call the manager
//! signer or relay arbitrary lifecycle requests back into a manager listener.
use super::{Authorization, ProcessIdentity};
use hyperhub_runtime::attachment as wire;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCommandTarget {
    pub identity: ProcessIdentity,
    pub endpoint: String,
    pub token: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachBarrierPlan {
    pub authorization_nonce: [u8; 32],
    pub command: wire::HostLifecycleCommand,
    pub targets: Vec<HostCommandTarget>,
}
impl std::fmt::Debug for DetachBarrierPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachBarrierPlan")
            .field("command", &self.command)
            .field("targets", &self.targets.len())
            .field("evidence", &"<redacted>")
            .finish()
    }
}
pub(crate) const DETACH_BARRIER_BATCH_LIMIT: usize = 64;

pub fn manager_host_command(
    bootstrap: &wire::Bootstrap,
    identity: &ProcessIdentity,
    command: wire::HostCommand,
    authorization: Option<&Authorization>,
) -> Result<wire::HostStatus, String> {
    let proof = authorization.map(super::host_proof).transpose()?;
    manager_host_command_with_proof(bootstrap, identity, command, proof)
}

pub fn manager_host_command_with_proof(
    bootstrap: &wire::Bootstrap,
    identity: &ProcessIdentity,
    command: wire::HostCommand,
    proof: Option<wire::ApprovalProof>,
) -> Result<wire::HostStatus, String> {
    let request = wire::AuthenticatedCommand {
        attachment_id: bootstrap.attachment_id.clone(),
        token: bootstrap.host_token.clone(),
        command,
        proof,
        enrollment: None,
        aliases: None,
        root_image: None,
    };
    if wire::host_command_authority(command) != wire::HostCommandAuthority::ManagerLifecycle
        || request.proof.is_none()
    {
        // The receiver admits a proof-free Activate only as a status-equivalent
        // duplicate of its original owned Active startup, never a transition.
        return wire::exchange_for_process(&bootstrap.host_endpoint, &request, identity.pid)
            .map_err(|e| e.to_string());
    }
    super::ensure_host_approval_root(bootstrap, identity)?;
    let (scope, certificate) =
        super::manager_host_operation(request.proof.as_ref().unwrap(), bootstrap)?;
    use wire::{HostCommand as C, HostLifecycleCommand as L, OperationAction as A};
    let purpose = match (command, scope.action) {
        (C::Activate, A::Attach) => L::Activate,
        (C::Detach, A::Attach) => L::RollbackInitialAttach,
        (C::Retire, A::Attach) => L::RollbackInitialAttachRetire,
        (C::Detach, A::Detach) => L::Detach,
        (C::Retire, A::Detach) => L::Retire,
        (C::PrepareDetachment, A::Detach) => L::PrepareDetachment,
        (C::CancelDetachmentPreparation, A::Detach) => L::CancelDetachmentPreparation,
        _ => return Err("accepted operation does not authorize the requested Host command".into()),
    };
    for retry in 0..3 {
        match exchange_scoped(bootstrap, identity, &request, &scope, &certificate, purpose) {
            Err(error) if retry < 2 && error.starts_with("Host lifecycle state changed:") => {
                continue
            }
            result => return result,
        }
    }
    unreachable!()
}

fn exchange_scoped(
    bootstrap: &wire::Bootstrap,
    identity: &ProcessIdentity,
    request: &wire::AuthenticatedCommand,
    scope: &wire::OperationScope,
    certificate: &wire::AcceptedOperationCertificate,
    purpose: wire::HostLifecycleCommand,
) -> Result<wire::HostStatus, String> {
    super::verify_process(identity)?;
    wire::exchange_lifecycle_for_process(
        &bootstrap.host_endpoint,
        request,
        certificate,
        purpose,
        identity.pid,
        identity.birth,
        |challenge| {
            super::prove_manager_host_command(
                challenge,
                request,
                scope,
                certificate,
                identity,
                crate::session::unix_timestamp_ms(),
            )
            .map_err(std::io::Error::other)
        },
    )
    .map_err(|e| e.to_string())
}

/// Execute only the fixed pause/cancel stage requested by this local caller.
/// A Core plan cannot ask this helper to sign Activate, Detach, or Retire.
pub(crate) fn execute_detach_barrier_plan(
    execution: &super::Execution,
    authorization: &Authorization,
    plan: DetachBarrierPlan,
    expected: wire::HostLifecycleCommand,
) -> Result<(), String> {
    if plan.authorization_nonce != authorization.nonce
        || plan.command != expected
        || !matches!(
            expected,
            wire::HostLifecycleCommand::PrepareDetachment
                | wire::HostLifecycleCommand::CancelDetachmentPreparation
        )
        || plan.targets.len() > DETACH_BARRIER_BATCH_LIMIT
    {
        return Err("detach barrier plan differs from the current fixed operation".into());
    }
    let mut identities = std::collections::HashSet::new();
    for target in plan.targets {
        if !identities.insert((target.identity.pid, target.identity.birth))
            || target.identity.owner != execution.spec.target.owner
            || (execution.spec.scope == super::Scope::Process
                && target.identity.pid != execution.spec.target.pid)
        {
            return Err("detach barrier plan crosses the approved Host scope".into());
        }
        let mut bootstrap = execution.bootstrap.clone();
        bootstrap.host_endpoint = target.endpoint;
        bootstrap.host_token = target.token;
        manager_host_command(
            &bootstrap,
            &target.identity,
            expected.wire_command().unwrap(),
            Some(authorization),
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "host_command_client_tests.rs"]
mod tests;
