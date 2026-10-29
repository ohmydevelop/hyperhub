//! Manager-memory delegated keys and Core acceptance evidence. CLI/consume
//! paths bind the administrator-signed claimant before using this registry.
//! Host fresh-command delegation is a separate, not-yet-connected boundary.
use ed25519_dalek::{Signer, SigningKey};
use hyperhub_runtime::attachment::{
    encode_possession_challenge, verify_possession_proof, AcceptedOperationCertificate,
    AcceptedOperationPayload, ManagerClaimant, OperationScope, PossessionChallenge,
    PossessionProof, OPERATION_CHALLENGE_LIFETIME_MS,
};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;

/// No Clone, serialization or secret getter. An inherited fork copy cannot
/// sign as its parent: every public operation rechecks the creator PID/birth.
pub struct ManagerOperationKey {
    key: SigningKey,
    claimant: ManagerClaimant,
}
fn manager_key() -> Result<&'static ManagerOperationKey, String> {
    static KEY: OnceLock<Result<ManagerOperationKey, String>> = OnceLock::new();
    KEY.get_or_init(ManagerOperationKey::generate)
        .as_ref()
        .map_err(Clone::clone)
}
pub fn manager_operation_claimant() -> Result<ManagerClaimant, String> {
    manager_key()?.claimant()
}
pub(crate) fn prove_manager_operation(
    challenge: &PossessionChallenge,
    now: u64,
) -> Result<PossessionProof, String> {
    manager_key()?.prove(challenge, now)
}
#[derive(Clone)]
struct ExecutionContext {
    bootstrap: hyperhub_runtime::attachment::Bootstrap,
    profile: super::ManagerExecutionProfile,
    policy_required: bool,
    cleanup_fenced: bool,
}
fn execution_contexts() -> &'static Mutex<HashMap<String, ExecutionContext>> {
    static CONTEXTS: OnceLock<Mutex<HashMap<String, ExecutionContext>>> = OnceLock::new();
    CONTEXTS.get_or_init(Default::default)
}
pub fn register_manager_execution(execution: &super::Execution) -> Result<(), String> {
    manager_operation_claimant()?;
    execution.bootstrap.validate().map_err(|e| e.to_string())?;
    let profile =
        super::ManagerExecutionProfile::from_bootstrap(&execution.bootstrap, execution.origin)?;
    let mut contexts = execution_contexts()
        .lock()
        .map_err(|_| "operation contexts unavailable")?;
    if let Some(previous) = contexts.get(&execution.spec.id) {
        if previous
            .bootstrap
            .approval_binding()
            .map_err(|e| e.to_string())?
            != execution
                .bootstrap
                .approval_binding()
                .map_err(|e| e.to_string())?
        {
            return Err("manager operation context changes immutable Host binding".into());
        }
    }
    let cleanup_fenced = matches!(
        execution.authorization.request.action,
        super::Action::Detach { .. }
    ) || contexts
        .get(&execution.spec.id)
        .is_some_and(|context| context.cleanup_fenced);
    let policy_required = contexts
        .get(&execution.spec.id)
        .map_or(true, |previous| previous.policy_required);
    contexts.insert(
        execution.spec.id.clone(),
        ExecutionContext {
            bootstrap: execution.bootstrap.clone(),
            profile,
            policy_required,
            cleanup_fenced,
        },
    );
    Ok(())
}
pub(crate) fn manager_operation_bootstrap(
    id: &str,
) -> Result<hyperhub_runtime::attachment::Bootstrap, String> {
    manager_operation_claimant()?;
    execution_contexts()
        .lock()
        .map_err(|_| "operation contexts unavailable")?
        .get(id)
        .map(|context| context.bootstrap.clone())
        .ok_or_else(|| "manager has no authenticated execution context".into())
}
/// RAM-only observer: no Core RPC, lifecycle/configuration or authority lock.
pub fn manager_execution_profile(id: &str) -> Result<super::ManagerExecutionProfile, String> {
    manager_operation_claimant()?;
    execution_contexts()
        .lock()
        .map_err(|_| "operation contexts unavailable")?
        .get(id)
        .map(|context| context.profile.clone())
        .ok_or_else(|| "manager has no immutable execution profile".into())
}

/// Trusted manager RAM admission, independent of record.json's display phase.
/// True includes an accepted activation that has not reached the Host yet.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerPolicyAdmission {
    pub profile: super::ManagerExecutionProfile,
    pub policy_required: bool,
}
pub fn manager_policy_admission(id: &str) -> Result<ManagerPolicyAdmission, String> {
    manager_operation_claimant()?;
    execution_contexts()
        .lock()
        .map_err(|_| "operation contexts unavailable")?
        .get(id)
        .map(|context| ManagerPolicyAdmission {
            profile: context.profile.clone(),
            policy_required: context.policy_required,
        })
        .ok_or_else(|| "manager has no policy admission state".into())
}
pub(crate) fn set_manager_policy_required(id: &str, required: bool) -> Result<(), String> {
    manager_operation_claimant()?;
    execution_contexts()
        .lock()
        .map_err(|_| "operation contexts unavailable")?
        .get_mut(id)
        .ok_or("manager has no policy admission state")?
        .policy_required = required;
    Ok(())
}
/// Derive protocol scope from exact signed bytes and their immutable bootstrap.
/// Signature/current-authority and actual OS role checks remain the caller's
/// responsibility; this helper never reads a public key from a file.
pub fn operation_scope_for_authorization(
    grant: &super::Authorization,
    bootstrap: &hyperhub_runtime::attachment::Bootstrap,
    root_image: hyperhub_runtime::attachment::RootImageState,
) -> Result<OperationScope, String> {
    operation_scope_for_bootstrap(
        grant,
        bootstrap,
        root_image,
        BootstrapScope::ManagerExecution,
    )
}

/// A startup-cleanup locator is an authenticated transport derivative of the
/// manager bootstrap. Its endpoint, token and inheritance cursors are expected
/// to differ, while `Bootstrap::approval_binding` remains immutable. The full
/// execution digest still belongs to the signed administrator proof and the
/// accepted operation; it must not be recomputed from this derivative.
pub(super) fn startup_cleanup_host_locator_scope(
    grant: &super::Authorization,
    bootstrap: &hyperhub_runtime::attachment::Bootstrap,
    root_image: hyperhub_runtime::attachment::RootImageState,
) -> Result<OperationScope, String> {
    operation_scope_for_bootstrap(
        grant,
        bootstrap,
        root_image,
        BootstrapScope::StartupCleanupHostLocator,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BootstrapScope {
    ManagerExecution,
    StartupCleanupHostLocator,
}

fn operation_scope_for_bootstrap(
    grant: &super::Authorization,
    bootstrap: &hyperhub_runtime::attachment::Bootstrap,
    root_image: hyperhub_runtime::attachment::RootImageState,
    bootstrap_scope: BootstrapScope,
) -> Result<OperationScope, String> {
    use sha2::Digest;
    grant.request.validate()?;
    let claimant = grant
        .manager_claimant
        .clone()
        .ok_or("approval has no delegated manager claimant")?;
    let binding = bootstrap.approval_binding().map_err(|e| e.to_string())?;
    let execution_matches = match (bootstrap_scope, &grant.execution_digest) {
        (BootstrapScope::ManagerExecution, Some(expected)) => {
            super::bootstrap_digest(bootstrap)? == *expected
        }
        (BootstrapScope::ManagerExecution, None)
        | (BootstrapScope::StartupCleanupHostLocator, _) => true,
    };
    let mut mismatches = Vec::new();
    if grant.host_binding.as_deref() != Some(binding.as_str()) {
        mismatches.push("host_binding");
    }
    if grant.request.instance_id != bootstrap.approval_instance_id {
        mismatches.push("instance_id");
    }
    if grant.request.action.attachment_id() != bootstrap.attachment_id {
        mismatches.push("attachment_id");
    }
    if grant.request.action.target().root_image_identity() != root_image.identity {
        mismatches.push("root_image_identity");
    }
    if grant.request.action.exec_epoch() != root_image.exec_epoch {
        mismatches.push("exec_epoch");
    }
    if bootstrap.root_pid != grant.request.action.target().pid {
        mismatches.push("root_pid");
    }
    if !execution_matches {
        mismatches.push("execution_digest");
    }
    if !mismatches.is_empty() {
        return Err(format!(
            "delegated approval differs from immutable bootstrap or current executable epoch: {}",
            mismatches.join(",")
        ));
    }
    let scope = OperationScope {
        action: match &grant.request.action {
            super::Action::Attach { .. } => hyperhub_runtime::attachment::OperationAction::Attach,
            super::Action::Detach { .. } => hyperhub_runtime::attachment::OperationAction::Detach,
        },
        administrator_digest: hyperhub_runtime::attachment::operation_administrator_digest(
            &super::host_proof(grant)?,
        )
        .map_err(|e| e.to_string())?,
        instance_id: grant.request.instance_id.clone(),
        attachment_id: bootstrap.attachment_id.clone(),
        session_id: bootstrap.session_id.clone(),
        credential_digest: sha2::Sha256::digest(bootstrap.token.as_bytes()).into(),
        host_binding: binding,
        root_image,
        claimant,
        core_public_key: grant
            .core_attestation_public_key
            .ok_or("approval has no Core attestation endorsement")?,
    };
    scope.validate().map_err(|e| e.to_string())?;
    Ok(scope)
}
fn accepted_operations(
) -> &'static Mutex<HashMap<[u8; 32], (OperationScope, AcceptedOperationCertificate)>> {
    static ACCEPTED: OnceLock<
        Mutex<HashMap<[u8; 32], (OperationScope, AcceptedOperationCertificate)>>,
    > = OnceLock::new();
    ACCEPTED.get_or_init(Default::default)
}
pub(crate) fn remember_accepted_operation(
    scope: &OperationScope,
    certificate: AcceptedOperationCertificate,
) -> Result<(), String> {
    if scope.claimant != manager_operation_claimant()? {
        return Err("accepted operation belongs to another manager role".into());
    }
    hyperhub_runtime::attachment::verify_accepted_operation(
        scope,
        &certificate,
        crate::session::unix_timestamp_ms(),
    )
    .map_err(|e| e.to_string())?;
    let mut accepted = accepted_operations()
        .lock()
        .map_err(|_| "accepted operations unavailable")?;
    if accepted.len() >= 4096 && !accepted.contains_key(&scope.administrator_digest) {
        return Err("accepted operation capacity reached".into());
    }
    accepted.insert(scope.administrator_digest, (scope.clone(), certificate));
    Ok(())
}
pub fn manager_accepted_operation(
    grant: &super::Authorization,
) -> Result<AcceptedOperationCertificate, String> {
    if grant.manager_claimant.as_ref() != Some(&manager_operation_claimant()?) {
        return Err("approval is not bound to this manager operation key".into());
    }
    let digest =
        hyperhub_runtime::attachment::operation_administrator_digest(&super::host_proof(grant)?)
            .map_err(|e| e.to_string())?;
    accepted_operations()
        .lock()
        .map_err(|_| "accepted operations unavailable")?
        .get(&digest)
        .map(|(_, certificate)| certificate.clone())
        .ok_or_else(|| "manager has no accepted operation certificate".into())
}
/// Return only the exact scope previously verified at the real consumption
/// boundary. A caller-supplied certificate cannot select a new Core signer.
pub(crate) fn manager_host_operation(
    proof: &hyperhub_runtime::attachment::ApprovalProof,
    bootstrap: &hyperhub_runtime::attachment::Bootstrap,
) -> Result<(OperationScope, AcceptedOperationCertificate), String> {
    use sha2::Digest;
    let digest = hyperhub_runtime::attachment::operation_administrator_digest(proof)
        .map_err(|e| e.to_string())?;
    let (scope, certificate) = accepted_operations()
        .lock()
        .map_err(|_| "accepted operations unavailable")?
        .get(&digest)
        .cloned()
        .ok_or("manager has no accepted Host operation")?;
    if scope.claimant != manager_operation_claimant()?
        || scope.administrator_digest != digest
        || scope.instance_id != bootstrap.approval_instance_id
        || scope.attachment_id != bootstrap.attachment_id
        || scope.session_id != bootstrap.session_id
        || scope.credential_digest
            != <[u8; 32]>::from(sha2::Sha256::digest(bootstrap.token.as_bytes()))
        || scope.host_binding != bootstrap.approval_binding().map_err(|e| e.to_string())?
    {
        return Err("accepted Host operation differs from manager and immutable Bootstrap".into());
    }
    hyperhub_runtime::attachment::verify_accepted_operation(
        &scope,
        &certificate,
        crate::session::unix_timestamp_ms(),
    )
    .map_err(|e| e.to_string())?;
    Ok((scope, certificate))
}
pub(crate) fn prove_manager_host_command(
    challenge: &hyperhub_runtime::attachment::HostCommandChallenge,
    request: &hyperhub_runtime::attachment::AuthenticatedCommand,
    scope: &OperationScope,
    certificate: &AcceptedOperationCertificate,
    host: &super::ProcessIdentity,
    now: u64,
) -> Result<hyperhub_runtime::attachment::HostCommandPossessionProof, String> {
    if request.command == hyperhub_runtime::attachment::HostCommand::Activate
        && execution_contexts()
            .lock()
            .map_err(|_| "operation contexts unavailable")?
            .get(&scope.attachment_id)
            .is_none_or(|context| context.cleanup_fenced)
    {
        return Err("cleanup-fenced manager cannot issue a new Host Activate proof".into());
    }
    manager_key()?.prove_host_command(challenge, request, scope, certificate, host, now)
}
impl std::fmt::Debug for ManagerOperationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerOperationKey")
            .field("key", &"<redacted>")
            .finish()
    }
}
impl ManagerOperationKey {
    pub fn generate() -> Result<Self, String> {
        let pid = std::process::id();
        let birth = super::process_birth(pid).ok_or("cannot identify operation key owner")?;
        let seed = Zeroizing::new(rand::random::<[u8; 32]>());
        let key = SigningKey::from_bytes(&seed);
        let claimant = ManagerClaimant {
            pid,
            birth,
            role_epoch: random_nonce(),
            public_key: key.verifying_key().to_bytes(),
        };
        let value = Self { key, claimant };
        value.check_owner()?;
        Ok(value)
    }
    fn check_owner(&self) -> Result<(), String> {
        if self.claimant.pid != std::process::id()
            || super::process_birth(self.claimant.pid) != Some(self.claimant.birth)
        {
            return Err("operation key belongs to a different process incarnation".into());
        }
        Ok(())
    }
    pub fn claimant(&self) -> Result<ManagerClaimant, String> {
        self.check_owner()?;
        Ok(self.claimant.clone())
    }
    pub fn prove(
        &self,
        challenge: &PossessionChallenge,
        now: u64,
    ) -> Result<PossessionProof, String> {
        self.check_owner()?;
        challenge.validate_at(now).map_err(|e| e.to_string())?;
        if challenge.scope.claimant != self.claimant {
            return Err(
                "operation challenge does not bind this delegated key and role epoch".into(),
            );
        }
        let payload = encode_possession_challenge(challenge).map_err(|e| e.to_string())?;
        let signature = self.key.sign(&payload).to_bytes().to_vec();
        self.check_owner()?;
        Ok(PossessionProof { payload, signature })
    }
    fn prove_host_command(
        &self,
        challenge: &hyperhub_runtime::attachment::HostCommandChallenge,
        request: &hyperhub_runtime::attachment::AuthenticatedCommand,
        scope: &OperationScope,
        certificate: &AcceptedOperationCertificate,
        host: &super::ProcessIdentity,
        now: u64,
    ) -> Result<hyperhub_runtime::attachment::HostCommandPossessionProof, String> {
        use hyperhub_runtime::attachment as wire;
        self.check_owner()?;
        super::verify_process(host)?;
        if scope.claimant != self.claimant
            || challenge.host_pid != host.pid
            || challenge.host_birth != host.birth
        {
            return Err("Host command challenge differs from manager or target incarnation".into());
        }
        wire::validate_host_command_challenge(challenge, request, scope, certificate, now)
            .map_err(|e| e.to_string())?;
        let payload = wire::encode_host_command_challenge(challenge).map_err(|e| e.to_string())?;
        let signature = self.key.sign(&payload).to_bytes().to_vec();
        self.check_owner()?;
        super::verify_process(host)?;
        Ok(wire::HostCommandPossessionProof { payload, signature })
    }
}
fn random_nonce() -> [u8; 32] {
    loop {
        let value = rand::random();
        if value != [0; 32] {
            return value;
        }
    }
}
/// Only pending challenges are stored. Removal precedes proof verification, so
/// a failed attempt cannot retry the same nonce with another actor or payload.
#[derive(Default)]
pub struct OperationChallengeBook {
    state: Mutex<ChallengeState>,
}
#[derive(Default)]
struct ChallengeState {
    pending: HashMap<[u8; 32], PossessionChallenge>,
    accepted: HashSet<[u8; 32]>,
}
const MAX_PENDING_OPERATION_CHALLENGES: usize = 128;
const MAX_ACCEPTED_OPERATIONS: usize = 4096;
impl OperationChallengeBook {
    pub fn begin_verified_scope(
        &self,
        scope: OperationScope,
        now: u64,
    ) -> Result<PossessionChallenge, String> {
        scope.validate().map_err(|e| e.to_string())?;
        let expires_at_ms = now
            .checked_add(OPERATION_CHALLENGE_LIFETIME_MS)
            .ok_or("operation challenge time overflow")?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "operation challenges unavailable")?;
        state
            .pending
            .retain(|_, challenge| challenge.expires_at_ms > now);
        if state.accepted.contains(&scope.administrator_digest)
            || state
                .pending
                .values()
                .any(|value| value.scope.administrator_digest == scope.administrator_digest)
        {
            return Err("administrator operation is already pending or accepted".into());
        }
        if state.pending.len() >= MAX_PENDING_OPERATION_CHALLENGES
            || state.accepted.len() >= MAX_ACCEPTED_OPERATIONS
        {
            return Err("operation challenge capacity reached".into());
        }
        let nonce = loop {
            let nonce = random_nonce();
            if !state.pending.contains_key(&nonce) {
                break nonce;
            }
        };
        let challenge = PossessionChallenge {
            schema_version: 1,
            scope,
            nonce,
            issued_at_ms: now,
            expires_at_ms,
        };
        state.pending.insert(nonce, challenge.clone());
        Ok(challenge)
    }
    /// `scope` must be independently derived from the verified administrator
    /// proof; `peer_pid/birth` must come from the authenticated OS connection.
    pub fn accept_verified_scope(
        &self,
        nonce: &[u8; 32],
        scope: &OperationScope,
        proof: &PossessionProof,
        peer_pid: u32,
        peer_birth: u64,
        now: u64,
    ) -> Result<AcceptedOperationPayload, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "operation challenges unavailable")?;
        let challenge = state
            .pending
            .remove(nonce)
            .ok_or("operation challenge is unknown or already consumed")?;
        if &challenge.scope != scope
            || scope.claimant.pid != peer_pid
            || scope.claimant.birth != peer_birth
        {
            return Err(
                "operation challenge differs from verified scope or actual claimant".into(),
            );
        }
        verify_possession_proof(&challenge, proof, now).map_err(|e| e.to_string())?;
        if !state.accepted.insert(scope.administrator_digest) {
            return Err("administrator operation was already accepted".into());
        }
        Ok(AcceptedOperationPayload {
            schema_version: 1,
            challenge,
            accepted_at_ms: now,
        })
    }
    /// This returns protocol evidence after verified administrator/claimant
    /// binding and possession. Host command authorization must independently
    /// verify its fresh command challenge; this certificate is not a bearer
    /// capability. The owning Core signs only this typed accepted payload.
    pub fn accept_and_attest_verified_scope(
        &self,
        directory: &Path,
        nonce: &[u8; 32],
        scope: &OperationScope,
        proof: &PossessionProof,
        peer_pid: u32,
        peer_birth: u64,
        now: u64,
    ) -> Result<AcceptedOperationCertificate, String> {
        let accepted =
            self.accept_verified_scope(nonce, scope, proof, peer_pid, peer_birth, now)?;
        super::trust::sign_accepted_operation(directory, &accepted)
    }
}

impl OperationChallengeBook {
    pub(crate) fn export_successor(&self) -> Result<Vec<[u8; 32]>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "operation challenges unavailable")?;
        if state
            .pending
            .values()
            .any(|challenge| challenge.expires_at_ms > crate::session::unix_timestamp_ms())
        {
            return Err(
                "manager operation consumption is in progress; retry Core succession".into(),
            );
        }
        Ok(state.accepted.iter().copied().collect())
    }
    pub(crate) fn import_successor(&self, accepted: Vec<[u8; 32]>) -> Result<(), String> {
        if accepted.len() > MAX_ACCEPTED_OPERATIONS {
            return Err("successor accepted operations exceed capacity".into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "operation challenges unavailable")?;
        if !state.pending.is_empty() || !state.accepted.is_empty() {
            return Err("successor operation memory already initialized".into());
        }
        state.accepted = accepted.into_iter().collect();
        Ok(())
    }
}

#[cfg(test)]
#[path = "operation_tests.rs"]
mod tests;

pub(super) fn prove_manager_preparation(
    execution: &super::Execution,
    step: super::PreparationStep,
    error: Option<&str>,
) -> Result<(super::PreparationProof, AcceptedOperationCertificate), String> {
    use sha2::Digest;
    let (scope, certificate) = manager_host_operation(
        &super::host_proof(&execution.authorization)?,
        &execution.bootstrap,
    )?;
    let value = super::PreparationPayload {
        schema_version: 1,
        step,
        scope,
        accepted_digest: hyperhub_runtime::attachment::host_accepted_operation_digest(&certificate)
            .map_err(|e| e.to_string())?,
        nonce: random_nonce(),
        failure_digest: error
            .map(|s| <[u8; 32]>::from(sha2::Sha256::digest(s.as_bytes())))
            .unwrap_or([0; 32]),
    };
    let payload = super::preparation::preparation_bytes(&value)?;
    let key = manager_key()?;
    key.check_owner()?;
    if value.scope.claimant != key.claimant {
        return Err("preparation proof belongs to another manager key".into());
    }
    let signature = key.key.sign(&payload).to_bytes().to_vec();
    key.check_owner()?;
    Ok((super::PreparationProof { payload, signature }, certificate))
}

pub(super) fn prove_unstarted_injections(
    execution: &super::Execution,
    hosts: &[super::HostBootstrapBinding],
    bindings: &[super::HostBootstrapBinding],
) -> Result<super::UnstartedInjectionProof, String> {
    let (scope, accepted) = manager_host_operation(
        &super::host_proof(&execution.authorization)?,
        &execution.bootstrap,
    )?;
    let value = super::startup_cleanup::UnstartedInjectionPayload {
        scope,
        bindings_digest: super::startup_cleanup::bindings_digest(hosts, bindings)?,
        accepted_digest: hyperhub_runtime::attachment::host_accepted_operation_digest(&accepted)
            .map_err(|e| e.to_string())?,
    };
    let payload = super::startup_cleanup::unstarted_bytes(&value)?;
    let key = manager_key()?;
    key.check_owner()?;
    if value.scope.claimant != key.claimant {
        return Err("unstarted cleanup belongs to another manager key".into());
    }
    let signature = key.key.sign(&payload).to_bytes().to_vec();
    key.check_owner()?;
    Ok(super::UnstartedInjectionProof {
        payload,
        signature,
        accepted,
    })
}
