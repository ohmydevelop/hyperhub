//! Private SDK admission state for lifecycle-envelope integration.
//! This module is not a command dispatcher or an administrator verifier. The
//! actor supplies a scope verified against its own trust state and a monotonic
//! state stamp; it must revalidate under its native/state gate before commit.
use hyperhub_runtime::attachment::{
    self as wire, AcceptedOperationCertificate, AuthenticatedCommand, HostCommandChallenge,
    HostCommandIntent, HostCommandPossessionProof, HostLifecycleCommand, HostPhase, OperationScope,
    RootImageState,
};
use rand::TryRng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostStateStamp {
    pub epoch: u64,
    pub phase: HostPhase,
    pub native_ready: bool,
    pub root_image: Option<RootImageState>,
    pub initially_owned: bool,
    /// This is monotonic for one Host initialization, including failed retries.
    pub ever_active: bool,
    /// Derived by the actor from its tracked, never-active initialization.
    pub preparation_cleanup: bool,
    /// Immutable SDK startup provenance, never supplied by the manager.
    pub initialization_origin: wire::InitializationOrigin,
    pub alias_paused: bool,
    pub accepted_digest: Option<[u8; 32]>,
    pub unload_ready: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RegistryError {
    WrongOwner,
    StateChanged,
    Busy,
    UnknownNonce,
    Replay,
    Capacity,
    Entropy,
    InvalidState,
    Rejected(String),
}
type Result<T> = std::result::Result<T, RegistryError>;
fn rejected(error: impl std::fmt::Display) -> RegistryError {
    RegistryError::Rejected(error.to_string())
}
#[derive(Clone)]
struct Pending {
    challenge: HostCommandChallenge,
    state: HostStateStamp,
}
struct Active {
    pending: Pending,
    proof_digest: [u8; 32],
}
struct Receipt {
    accepted_digest: [u8; 32],
    intent: HostCommandIntent,
    proof_digest: [u8; 32],
    state: HostStateStamp,
}

/// Never serialized, cloned, or reconstructed from an Execution file. A fresh
/// SDK after fork/exec creates a new random Host epoch outside loader callbacks.
pub(crate) struct HostCommandRegistry {
    owner_pid: u32,
    owner_birth: u64,
    host_epoch: [u8; 32],
    state: HostStateStamp,
    pending: BTreeMap<[u8; 32], Pending>,
    spent: BTreeSet<[u8; 32]>,
    receipts: BTreeMap<[u8; 32], Receipt>,
    active: Option<Active>,
    committed_initial_rollback: Option<[u8; 32]>,
    capacity: usize,
}
impl HostCommandRegistry {
    pub(crate) fn accepted_digest(&self) -> Option<[u8; 32]> {
        self.state.accepted_digest
    }
    pub(crate) fn verify_purpose(
        &self,
        nonce: [u8; 32],
        purpose: HostLifecycleCommand,
    ) -> Result<()> {
        self.owner()?;
        let expected = self
            .pending
            .get(&nonce)
            .map(|pending| pending.challenge.intent.command)
            .or_else(|| {
                self.receipts
                    .get(&nonce)
                    .map(|receipt| receipt.intent.command)
            })
            .ok_or(RegistryError::UnknownNonce)?;
        if expected == purpose {
            Ok(())
        } else {
            Err(RegistryError::Rejected(
                "Host lifecycle purpose changed".into(),
            ))
        }
    }
    pub(crate) fn new(state: HostStateStamp) -> Result<Self> {
        let identity = wire::process_incarnation(std::process::id()).map_err(rejected)?;
        Ok(Self::create(
            identity.pid,
            identity.birth,
            random_nonce()?,
            state,
        ))
    }
    fn create(pid: u32, birth: u64, epoch: [u8; 32], state: HostStateStamp) -> Self {
        Self {
            owner_pid: pid,
            owner_birth: birth,
            host_epoch: epoch,
            state,
            pending: BTreeMap::new(),
            spent: BTreeSet::new(),
            receipts: BTreeMap::new(),
            active: None,
            committed_initial_rollback: None,
            capacity: 128,
        }
    }
    /// This check performs no allocation or lock acquisition in a copied child.
    pub(crate) fn owned_by_current_process(&self) -> bool {
        self.owner_pid == std::process::id()
    }
    fn owner(&self) -> Result<()> {
        if self.owned_by_current_process() {
            Ok(())
        } else {
            Err(RegistryError::WrongOwner)
        }
    }
    fn synchronize(&mut self, state: &HostStateStamp) -> Result<()> {
        self.owner()?;
        if state.epoch < self.state.epoch
            || (state.epoch == self.state.epoch && state != &self.state)
            || state.initially_owned != self.state.initially_owned
            || state.initialization_origin != self.state.initialization_origin
            || (self.state.ever_active && !state.ever_active)
        {
            return Err(RegistryError::StateChanged);
        }
        if state.epoch > self.state.epoch {
            if state.ever_active
                || state.root_image != self.state.root_image
                || state.accepted_digest != self.committed_initial_rollback
                || !matches!(
                    state.phase,
                    HostPhase::Detaching | HostPhase::DetachedResident
                )
            {
                self.committed_initial_rollback = None;
            }
            self.pending.clear();
            self.spent.clear();
            self.receipts.clear();
            self.state = state.clone();
        }
        Ok(())
    }
    fn check_state(
        &self,
        state: &HostStateStamp,
        scope: &OperationScope,
        digest: [u8; 32],
        purpose: HostLifecycleCommand,
    ) -> Result<()> {
        if let Some(image) = &state.root_image {
            if image != &scope.root_image {
                return Err(RegistryError::StateChanged);
            }
        } else if !(state.preparation_cleanup
            && !state.ever_active
            && scope.action == wire::OperationAction::Detach
            && matches!(
                purpose,
                HostLifecycleCommand::PrepareDetachment
                    | HostLifecycleCommand::CancelDetachmentPreparation
                    | HostLifecycleCommand::Detach
                    | HostLifecycleCommand::Retire
            ))
            && !(state.initialization_origin == wire::InitializationOrigin::Fresh
                && matches!(
                    purpose,
                    HostLifecycleCommand::RollbackInitialAttach
                        | HostLifecycleCommand::RollbackInitialAttachRetire
                ))
        {
            return Err(RegistryError::InvalidState);
        }
        let off = matches!(
            state.phase,
            HostPhase::Detaching | HostPhase::DetachedResident
        );
        let allowed = match purpose {
            HostLifecycleCommand::Activate => {
                state.native_ready
                    && !state.alias_paused
                    && (matches!(
                        state.phase,
                        HostPhase::Preparing | HostPhase::DetachedResident
                    ) || (state.phase == HostPhase::Active
                        && state.accepted_digest == Some(digest)))
            }
            HostLifecycleCommand::PrepareActivation => false, // Reserved, not a live wire command.
            HostLifecycleCommand::PrepareDetachment => {
                ((state.phase == HostPhase::Active
                    || (state.phase == HostPhase::Preparing && state.preparation_cleanup))
                    && (!state.alias_paused || state.accepted_digest == Some(digest)))
                    || off
            }
            HostLifecycleCommand::CancelDetachmentPreparation => {
                ((state.phase == HostPhase::Active
                    || (state.phase == HostPhase::Preparing && state.preparation_cleanup))
                    && (!state.alias_paused || state.accepted_digest == Some(digest)))
                    || (off && !state.alias_paused)
            }
            HostLifecycleCommand::Detach => {
                matches!(state.phase, HostPhase::Active | HostPhase::Preparing) || off
            }
            HostLifecycleCommand::Retire => {
                off && state.unload_ready && state.accepted_digest == Some(digest)
            }
            HostLifecycleCommand::RollbackInitialAttach => {
                state.initialization_origin == wire::InitializationOrigin::Fresh
                    && state.phase == HostPhase::Preparing
                    && !state.initially_owned
                    && !state.ever_active
            }
            HostLifecycleCommand::RollbackInitialAttachRetire => {
                off && state.unload_ready
                    && state.initialization_origin == wire::InitializationOrigin::Fresh
                    && !state.initially_owned
                    && !state.ever_active
                    && state.accepted_digest == Some(digest)
                    && self.committed_initial_rollback == Some(digest)
            }
        };
        if allowed {
            Ok(())
        } else {
            Err(RegistryError::InvalidState)
        }
    }
    pub(crate) fn issue(
        &mut self,
        request: &AuthenticatedCommand,
        scope: &OperationScope,
        certificate: &AcceptedOperationCertificate,
        purpose: HostLifecycleCommand,
        now: u64,
        state: &HostStateStamp,
    ) -> Result<HostCommandChallenge> {
        self.synchronize(state)?;
        if self.active.is_some() {
            return Err(RegistryError::Busy);
        }
        let digest = wire::host_accepted_operation_digest(certificate).map_err(rejected)?;
        self.check_state(state, scope, digest, purpose)?;
        let intent = HostCommandIntent::for_request(request, purpose).map_err(rejected)?;
        let expires = now
            .checked_add(wire::HOST_COMMAND_CHALLENGE_LIFETIME_MS)
            .ok_or(RegistryError::InvalidState)?;
        let mut challenge = HostCommandChallenge {
            schema_version: 1,
            accepted_digest: digest,
            host_pid: self.owner_pid,
            host_birth: self.owner_birth,
            host_epoch: self.host_epoch,
            state_epoch: state.epoch,
            intent,
            nonce: [1; 32],
            issued_at_ms: now,
            expires_at_ms: expires,
        };
        wire::validate_host_command_challenge(&challenge, request, scope, certificate, now)
            .map_err(rejected)?;
        let expired = self
            .pending
            .iter()
            .filter_map(|(nonce, pending)| {
                (pending.challenge.expires_at_ms <= now).then_some(*nonce)
            })
            .collect::<Vec<_>>();
        for nonce in expired {
            self.pending.remove(&nonce);
            self.spent.insert(nonce);
        }
        // Repeated requests cannot replace the manager's still-valid challenge.
        if let Some(existing) = self.pending.values().find(|pending| {
            pending.challenge.accepted_digest == digest
                && pending.challenge.intent == challenge.intent
        }) {
            return Ok(existing.challenge.clone());
        }
        if self.pending.len() + self.spent.len() >= self.capacity {
            return Err(RegistryError::Capacity);
        }
        let nonce = (0..8)
            .find_map(|_| {
                random_nonce().ok().filter(|nonce| {
                    !self.pending.contains_key(nonce) && !self.spent.contains(nonce)
                })
            })
            .ok_or(RegistryError::Entropy)?;
        challenge.nonce = nonce;
        self.pending.insert(
            nonce,
            Pending {
                challenge: challenge.clone(),
                state: state.clone(),
            },
        );
        Ok(challenge)
    }
    pub(crate) fn consume<'a>(
        &'a mut self,
        nonce: [u8; 32],
        request: &AuthenticatedCommand,
        scope: &OperationScope,
        certificate: &AcceptedOperationCertificate,
        proof: &HostCommandPossessionProof,
        now: u64,
        state: &HostStateStamp,
    ) -> Result<Consumption<'a>> {
        self.synchronize(state)?;
        let accepted = wire::host_accepted_operation_digest(certificate).map_err(rejected)?;
        if let Some(receipt) = self.receipts.get(&nonce) {
            wire::verify_accepted_operation(scope, certificate, now).map_err(rejected)?;
            if receipt.state == *state
                && receipt.accepted_digest == accepted
                && receipt.proof_digest == proof_digest(proof)
                && HostCommandIntent::for_request(request, receipt.intent.command)
                    .map_err(rejected)?
                    == receipt.intent
            {
                return Ok(Consumption::AlreadyCommitted);
            }
            return Err(RegistryError::Replay);
        }
        if self.active.is_some() {
            return Err(RegistryError::Busy);
        }
        let pending = self.pending.get(&nonce).cloned().ok_or_else(|| {
            if self.spent.contains(&nonce) {
                RegistryError::Replay
            } else {
                RegistryError::UnknownNonce
            }
        })?;
        if pending.state != *state
            || pending.challenge.host_pid != self.owner_pid
            || pending.challenge.host_birth != self.owner_birth
            || pending.challenge.host_epoch != self.host_epoch
            || pending.challenge.state_epoch != state.epoch
        {
            return Err(RegistryError::StateChanged);
        }
        self.check_state(state, scope, accepted, pending.challenge.intent.command)?;
        wire::verify_host_command_proof(
            &pending.challenge,
            request,
            scope,
            certificate,
            proof,
            now,
        )
        .map_err(rejected)?;
        // Failed signatures above do not burn this or another valid nonce.
        self.pending.remove(&nonce);
        self.spent.extend(self.pending.keys().copied());
        self.pending.clear();
        self.spent.insert(nonce);
        self.active = Some(Active {
            pending,
            proof_digest: proof_digest(proof),
        });
        Ok(Consumption::Execute(CommandPermit {
            registry: self,
            nonce,
            finished: false,
        }))
    }
}
pub(crate) enum Consumption<'a> {
    Execute(CommandPermit<'a>),
    AlreadyCommitted,
}

/// The actor keeps this non-Clone permit across preparation work, then calls
/// revalidate while holding its actual state/native gate before mutation.
/// Error paths and unwinding abort admission without making a success receipt.
pub(crate) struct CommandPermit<'a> {
    registry: &'a mut HostCommandRegistry,
    nonce: [u8; 32],
    finished: bool,
}
impl CommandPermit<'_> {
    pub(crate) fn revalidate(&self, state: &HostStateStamp) -> Result<()> {
        self.registry.owner()?;
        let active = self
            .registry
            .active
            .as_ref()
            .ok_or(RegistryError::UnknownNonce)?;
        if active.pending.challenge.nonce != self.nonce
            || active.pending.state != *state
            || self.registry.state != *state
        {
            return Err(RegistryError::StateChanged);
        }
        Ok(())
    }
    /// Record only a successful actor transition. This does not apply policy;
    /// revalidation, mutation and this completion share the caller's state gate.
    pub(crate) fn commit(
        mut self,
        actual_before: &HostStateStamp,
        after: &HostStateStamp,
    ) -> Result<()> {
        self.registry.owner()?;
        let active = self
            .registry
            .active
            .as_ref()
            .ok_or(RegistryError::UnknownNonce)?;
        self.revalidate(actual_before)?;
        let before = active.pending.state.clone();
        if (after != &before && before.epoch.checked_add(1) != Some(after.epoch))
            || after.root_image != before.root_image
            || after.initially_owned != before.initially_owned
            || after.initialization_origin != before.initialization_origin
            || (before.ever_active && !after.ever_active)
            || (active.pending.challenge.intent.command != HostLifecycleCommand::Activate
                && after.ever_active != before.ever_active)
        {
            return Err(RegistryError::StateChanged);
        }
        let purpose = active.pending.challenge.intent.command;
        let digest = active.pending.challenge.accepted_digest;
        let off = matches!(
            after.phase,
            HostPhase::Detaching | HostPhase::DetachedResident
        );
        let transition = match purpose {
            HostLifecycleCommand::Activate => {
                after.phase == HostPhase::Active
                    && after.ever_active
                    && after.native_ready
                    && !after.alias_paused
                    && after.accepted_digest == Some(digest)
            }
            HostLifecycleCommand::PrepareActivation => false,
            HostLifecycleCommand::Detach | HostLifecycleCommand::RollbackInitialAttach => {
                off && !after.alias_paused && after.accepted_digest == Some(digest)
            }
            HostLifecycleCommand::Retire | HostLifecycleCommand::RollbackInitialAttachRetire => {
                off && after.unload_ready && after.accepted_digest == Some(digest)
            }
            HostLifecycleCommand::PrepareDetachment => {
                ((after.phase == HostPhase::Active
                    || (after.phase == HostPhase::Preparing && after.preparation_cleanup))
                    && after.alias_paused
                    && after.accepted_digest == Some(digest))
                    || (off && after == &before)
            }
            HostLifecycleCommand::CancelDetachmentPreparation => {
                !after.alias_paused
                    && after.phase == before.phase
                    && (after.accepted_digest == Some(digest) || after == &before)
            }
        };
        if !transition {
            return Err(RegistryError::InvalidState);
        }
        let active = self
            .registry
            .active
            .take()
            .ok_or(RegistryError::UnknownNonce)?;
        self.registry.pending.clear();
        if after.epoch > self.registry.state.epoch {
            self.registry.spent.clear();
            self.registry.receipts.clear();
        }
        self.registry.state = after.clone();
        self.registry.committed_initial_rollback = match purpose {
            HostLifecycleCommand::RollbackInitialAttach => Some(digest),
            HostLifecycleCommand::RollbackInitialAttachRetire => {
                self.registry.committed_initial_rollback
            }
            _ if after == &before => self.registry.committed_initial_rollback,
            _ => None,
        };
        self.registry.spent.insert(self.nonce);
        self.registry.receipts.insert(
            self.nonce,
            Receipt {
                accepted_digest: digest,
                intent: active.pending.challenge.intent,
                proof_digest: active.proof_digest,
                state: after.clone(),
            },
        );
        self.finished = true;
        Ok(())
    }
}
impl Drop for CommandPermit<'_> {
    fn drop(&mut self) {
        if !self.finished && self.registry.owned_by_current_process() {
            if self
                .registry
                .active
                .as_ref()
                .is_some_and(|active| active.pending.challenge.nonce == self.nonce)
            {
                self.registry.active.take();
            }
        }
    }
}
fn random_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| RegistryError::Entropy)?;
    if nonce == [0; 32] {
        Err(RegistryError::Entropy)
    } else {
        Ok(nonce)
    }
}
fn proof_digest(proof: &HostCommandPossessionProof) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"hyperhub/sdk-command-receipt/v1\0");
    hash.update((proof.payload.len() as u64).to_le_bytes());
    hash.update(&proof.payload);
    hash.update((proof.signature.len() as u64).to_le_bytes());
    hash.update(&proof.signature);
    hash.finalize().into()
}
#[cfg(test)]
#[path = "host_command_registry_tests.rs"]
mod tests;
