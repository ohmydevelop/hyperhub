//! Cleanup-only evidence for calls that the trusted manager journaled before
//! dispatch. This does not authorize injection, policy installation or aliases.
use super::{Authorization, HostBootstrapBinding};
use hyperhub_runtime::attachment as wire;
use serde::{Deserialize, Serialize};

pub(super) const UNSTARTED_DOMAIN: &[u8] = b"hyperhub/unstarted-injections/v1\0";
const MAX_PROOF: usize = 128 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnstartedInjectionProof {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub accepted: wire::AcceptedOperationCertificate,
}
impl std::fmt::Debug for UnstartedInjectionProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnstartedInjectionProof")
            .field("evidence", &"<redacted>")
            .finish()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnstartedInjectionPayload {
    pub scope: wire::OperationScope,
    pub bindings_digest: [u8; 32],
    pub accepted_digest: [u8; 32],
}
pub(super) fn bindings_digest(
    hosts: &[HostBootstrapBinding],
    bindings: &[HostBootstrapBinding],
) -> Result<[u8; 32], String> {
    use sha2::Digest;
    if hosts.len() + bindings.len() == 0 || hosts.len() + bindings.len() > 4096 {
        return Err("unstarted cleanup requires a bounded nonempty attempt roster".into());
    }
    let bytes = crate::successor::bounded_json::to_vec(&(hosts, bindings), 1024 * 1024)?;
    Ok(sha2::Sha256::digest(bytes.as_slice()).into())
}
pub(super) fn unstarted_bytes(value: &UnstartedInjectionPayload) -> Result<Vec<u8>, String> {
    if value.scope.action != wire::OperationAction::Detach {
        return Err("unstarted cleanup requires an accepted Detach operation".into());
    }
    let encoded =
        crate::successor::bounded_json::to_vec(value, MAX_PROOF - UNSTARTED_DOMAIN.len())?;
    let mut bytes = UNSTARTED_DOMAIN.to_vec();
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}
pub(crate) fn verify_unstarted(
    proof: &UnstartedInjectionProof,
    grant: &Authorization,
    hosts: &[HostBootstrapBinding],
    bindings: &[HostBootstrapBinding],
    current_core_key: [u8; 32],
) -> Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    if proof.payload.len() > MAX_PROOF {
        return Err("unstarted cleanup proof exceeds size limit".into());
    }
    let payload: UnstartedInjectionPayload = serde_json::from_slice(
        proof
            .payload
            .strip_prefix(UNSTARTED_DOMAIN)
            .ok_or("invalid unstarted cleanup proof domain")?,
    )
    .map_err(|e| e.to_string())?;
    if unstarted_bytes(&payload)? != proof.payload
        || payload.bindings_digest != bindings_digest(hosts, bindings)?
        || payload.accepted_digest
            != wire::host_accepted_operation_digest(&proof.accepted).map_err(|e| e.to_string())?
        || payload.scope.core_public_key != current_core_key
    {
        return Err("unstarted cleanup proof differs from its exact accepted roster".into());
    }
    for binding in hosts.iter().chain(bindings) {
        if payload.scope
            != super::operation::startup_cleanup_host_locator_scope(
                grant,
                &binding.bootstrap,
                payload.scope.root_image.clone(),
            )?
        {
            return Err("unstarted cleanup changes the original immutable Host scope".into());
        }
    }
    wire::verify_accepted_operation(
        &payload.scope,
        &proof.accepted,
        crate::session::unix_timestamp_ms(),
    )
    .map_err(|e| e.to_string())?;
    let key = VerifyingKey::from_bytes(&payload.scope.claimant.public_key)
        .map_err(|_| "invalid cleanup claimant key")?;
    if key.is_weak() {
        return Err("weak cleanup claimant key".into());
    }
    key.verify_strict(
        &proof.payload,
        &Signature::from_slice(&proof.signature)
            .map_err(|_| "invalid cleanup possession signature")?,
    )
    .map_err(|_| "unstarted cleanup manager possession rejected".into())
}
