use super::*;
use ed25519_dalek::{Signer, SigningKey};
use wire::{
    AcceptedOperationPayload, ApprovalProof, HostCommand, ManagerClaimant, OperationAction,
    PossessionChallenge, RootImageIdentity,
};

const NOW: u64 = 1_000;

struct Fixture {
    core: SigningKey,
    manager: SigningKey,
    request: AuthenticatedCommand,
    scope: OperationScope,
    certificate: AcceptedOperationCertificate,
    state: HostStateStamp,
}
impl Fixture {
    fn new(purpose: HostLifecycleCommand) -> Self {
        let core = SigningKey::from_bytes(&[31; 32]);
        let manager = SigningKey::from_bytes(&[32; 32]);
        let request = AuthenticatedCommand {
            attachment_id: "attachment".into(),
            token: "h".repeat(64),
            command: purpose.wire_command().unwrap(),
            proof: Some(ApprovalProof {
                payload: vec![1, 2, 3],
                signature: vec![4; 64],
            }),
            enrollment: None,
            aliases: None,
            root_image: None,
        };
        // The live actor must derive this scope from independently verified
        // administrator/bootstrap state. These tests cover SDK admission only.
        let scope = OperationScope {
            action: purpose.operation(),
            administrator_digest: wire::operation_administrator_digest(
                request.proof.as_ref().unwrap(),
            )
            .unwrap(),
            instance_id: "instance".into(),
            attachment_id: "attachment".into(),
            session_id: "session".into(),
            credential_digest: [6; 32],
            host_binding: "a".repeat(64),
            root_image: RootImageState {
                identity: RootImageIdentity {
                    pid: 101,
                    birth: 202,
                    executable_sha256: "b".repeat(64),
                },
                exec_epoch: 0,
                observed_at_ms: 0,
                head: [0; 32],
            },
            claimant: ManagerClaimant {
                pid: 303,
                birth: 404,
                role_epoch: [5; 32],
                public_key: manager.verifying_key().to_bytes(),
            },
            core_public_key: core.verifying_key().to_bytes(),
        };
        let state = HostStateStamp {
            epoch: 1,
            phase: if purpose.operation() == OperationAction::Attach {
                HostPhase::Preparing
            } else {
                HostPhase::Active
            },
            native_ready: true,
            root_image: Some(scope.root_image.clone()),
            initially_owned: false,
            ever_active: purpose.operation() == OperationAction::Detach,
            preparation_cleanup: false,
            initialization_origin: wire::InitializationOrigin::Fresh,
            alias_paused: false,
            accepted_digest: None,
            unload_ready: false,
        };
        let certificate = Self::certificate(&core, &scope, 7);
        Self {
            core,
            manager,
            request,
            scope,
            certificate,
            state,
        }
    }
    fn certificate(
        core: &SigningKey,
        scope: &OperationScope,
        nonce: u8,
    ) -> AcceptedOperationCertificate {
        let payload = wire::encode_accepted_operation(&AcceptedOperationPayload {
            schema_version: 1,
            challenge: PossessionChallenge {
                schema_version: 1,
                scope: scope.clone(),
                nonce: [nonce; 32],
                issued_at_ms: 100,
                expires_at_ms: 500,
            },
            accepted_at_ms: 110,
        })
        .unwrap();
        AcceptedOperationCertificate {
            signature: core.sign(&payload).to_bytes().to_vec(),
            payload,
        }
    }
    fn registry(&self) -> HostCommandRegistry {
        HostCommandRegistry::create(std::process::id(), 222, [8; 32], self.state.clone())
    }
    fn issue(
        &self,
        registry: &mut HostCommandRegistry,
        purpose: HostLifecycleCommand,
    ) -> HostCommandChallenge {
        registry
            .issue(
                &self.request,
                &self.scope,
                &self.certificate,
                purpose,
                NOW,
                &self.state,
            )
            .unwrap()
    }
    fn proof(&self, challenge: &HostCommandChallenge) -> HostCommandPossessionProof {
        let payload = wire::encode_host_command_challenge(challenge).unwrap();
        HostCommandPossessionProof {
            signature: self.manager.sign(&payload).to_bytes().to_vec(),
            payload,
        }
    }
    fn consume<'a>(
        &self,
        registry: &'a mut HostCommandRegistry,
        challenge: &HostCommandChallenge,
        proof: &HostCommandPossessionProof,
    ) -> Result<Consumption<'a>> {
        registry.consume(
            challenge.nonce,
            &self.request,
            &self.scope,
            &self.certificate,
            proof,
            NOW,
            &self.state,
        )
    }
    fn admit<'a>(
        &self,
        registry: &'a mut HostCommandRegistry,
        challenge: &HostCommandChallenge,
    ) -> CommandPermit<'a> {
        match self
            .consume(registry, challenge, &self.proof(challenge))
            .unwrap()
        {
            Consumption::Execute(permit) => permit,
            Consumption::AlreadyCommitted => panic!("unexpected committed command"),
        }
    }
    fn after(&self, phase: HostPhase) -> HostStateStamp {
        HostStateStamp {
            epoch: self.state.epoch + 1,
            phase,
            ever_active: self.state.ever_active || phase == HostPhase::Active,
            accepted_digest: Some(wire::host_accepted_operation_digest(&self.certificate).unwrap()),
            ..self.state.clone()
        }
    }
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn actual_constructor_binds_identity_and_distinct_host_initializations() {
    let fixture = Fixture::new(HostLifecycleCommand::Detach);
    let a = HostCommandRegistry::new(fixture.state.clone()).unwrap();
    let b = HostCommandRegistry::new(fixture.state.clone()).unwrap();
    let actual = wire::process_identity(std::process::id()).unwrap();
    assert_eq!((a.owner_pid, a.owner_birth), (actual.pid, actual.birth));
    assert_ne!(a.host_epoch, b.host_epoch);
    assert_ne!(a.host_epoch, [0; 32]);
}

#[test]
fn issue_is_stable_bounded_and_does_not_replace_another_pending_command() {
    let fixture = Fixture::new(HostLifecycleCommand::Detach);
    let mut registry = fixture.registry();
    registry.capacity = 2;
    let a = fixture.issue(&mut registry, HostLifecycleCommand::Detach);
    assert_eq!(
        a,
        fixture.issue(&mut registry, HostLifecycleCommand::Detach)
    );
    let mut request = fixture.request.clone();
    request.token.push('2');
    let b = registry
        .issue(
            &request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Detach,
            NOW,
            &fixture.state,
        )
        .unwrap();
    assert_ne!(a.nonce, b.nonce);
    request.token.push('3');
    assert!(matches!(
        registry.issue(
            &request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Detach,
            NOW,
            &fixture.state
        ),
        Err(RegistryError::Capacity)
    ));
    assert!(matches!(
        registry.issue(
            &request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Detach,
            NOW + wire::HOST_COMMAND_CHALLENGE_LIFETIME_MS,
            &fixture.state
        ),
        Err(RegistryError::Capacity)
    ));
    assert_eq!((registry.pending.len(), registry.spent.len()), (0, 2));
    let mut advanced = fixture.state.clone();
    advanced.epoch += 1;
    assert!(registry
        .issue(
            &request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Detach,
            NOW,
            &advanced
        )
        .is_ok());
    assert_eq!(registry.spent.len(), 0);
    assert!(matches!(
        registry.consume(
            a.nonce,
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            &fixture.proof(&a),
            NOW,
            &advanced
        ),
        Err(RegistryError::UnknownNonce)
    ));
}

#[test]
fn invalid_signature_or_changed_envelope_does_not_burn_valid_nonce() {
    let fixture = Fixture::new(HostLifecycleCommand::Detach);
    let mut registry = fixture.registry();
    let challenge = fixture.issue(&mut registry, HostLifecycleCommand::Detach);
    let proof = fixture.proof(&challenge);
    let mut invalid = proof.clone();
    invalid.signature[0] ^= 1;
    assert!(fixture
        .consume(&mut registry, &challenge, &invalid)
        .is_err());
    let mut changed_request = fixture.request.clone();
    changed_request.token.push('x');
    assert!(registry
        .consume(
            challenge.nonce,
            &changed_request,
            &fixture.scope,
            &fixture.certificate,
            &proof,
            NOW,
            &fixture.state
        )
        .is_err());
    for field in [
        "pid",
        "birth",
        "host_epoch",
        "state_epoch",
        "nonce",
        "accepted",
    ] {
        let mut changed = challenge.clone();
        match field {
            "pid" => changed.host_pid += 1,
            "birth" => changed.host_birth += 1,
            "host_epoch" => changed.host_epoch[0] ^= 1,
            "state_epoch" => changed.state_epoch += 1,
            "nonce" => changed.nonce[0] ^= 1,
            "accepted" => changed.accepted_digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            fixture
                .consume(&mut registry, &challenge, &fixture.proof(&changed))
                .is_err(),
            "{field}"
        );
    }
    assert!(matches!(
        fixture.consume(&mut registry, &challenge, &proof),
        Ok(Consumption::Execute(_))
    ));
    assert!(registry.pending.is_empty());
}

#[test]
fn only_one_command_is_admitted_and_other_challenges_are_invalidated() {
    let fixture = Fixture::new(HostLifecycleCommand::Detach);
    let mut registry = fixture.registry();
    let a = fixture.issue(&mut registry, HostLifecycleCommand::Detach);
    let mut other = fixture.request.clone();
    other.token.push('x');
    let b = registry
        .issue(
            &other,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Detach,
            NOW,
            &fixture.state,
        )
        .unwrap();
    let permit = fixture.admit(&mut registry, &a);
    assert!(matches!(
        permit.registry.issue(
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Detach,
            NOW,
            &fixture.state
        ),
        Err(RegistryError::Busy)
    ));
    drop(permit);
    assert!(registry.active.is_none());
    assert!(registry.receipts.is_empty());
    for challenge in [a, b] {
        assert!(matches!(
            fixture.consume(&mut registry, &challenge, &fixture.proof(&challenge)),
            Err(RegistryError::Replay)
        ));
    }
    assert_ne!(
        fixture
            .issue(&mut registry, HostLifecycleCommand::Detach)
            .nonce,
        [0; 32]
    );
}

#[test]
fn failed_work_and_unwinding_abort_without_success_receipts() {
    let fixture = Fixture::new(HostLifecycleCommand::Detach);
    let mut registry = fixture.registry();
    let challenge = fixture.issue(&mut registry, HostLifecycleCommand::Detach);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _permit = fixture.admit(&mut registry, &challenge);
        panic!("simulated preparation failure");
    }));
    assert!(caught.is_err());
    assert!(registry.active.is_none());
    assert!(registry.receipts.is_empty());
    assert!(matches!(
        fixture.consume(&mut registry, &challenge, &fixture.proof(&challenge)),
        Err(RegistryError::Replay)
    ));
    assert_ne!(
        fixture
            .issue(&mut registry, HostLifecycleCommand::Detach)
            .nonce,
        challenge.nonce
    );
}

#[test]
fn state_revalidation_rejects_changes_during_preparation() {
    let fixture = Fixture::new(HostLifecycleCommand::Detach);
    let mut registry = fixture.registry();
    let challenge = fixture.issue(&mut registry, HostLifecycleCommand::Detach);
    let permit = fixture.admit(&mut registry, &challenge);
    let mut changed = fixture.state.clone();
    changed.epoch += 1;
    changed.alias_paused = true;
    assert_eq!(
        permit.revalidate(&changed),
        Err(RegistryError::StateChanged)
    );
    assert_eq!(
        permit.commit(&changed, &fixture.after(HostPhase::DetachedResident)),
        Err(RegistryError::StateChanged)
    );
    assert!(registry.active.is_none());
    assert!(registry.receipts.is_empty());
}

#[test]
fn successful_completion_has_only_an_exact_same_state_idempotent_receipt() {
    let mut fixture = Fixture::new(HostLifecycleCommand::Detach);
    let mut registry = fixture.registry();
    let challenge = fixture.issue(&mut registry, HostLifecycleCommand::Detach);
    let proof = fixture.proof(&challenge);
    let after = fixture.after(HostPhase::DetachedResident);
    fixture
        .admit(&mut registry, &challenge)
        .commit(&fixture.state, &after)
        .unwrap();
    fixture.state = after;
    assert!(matches!(
        fixture.consume(&mut registry, &challenge, &proof),
        Ok(Consumption::AlreadyCommitted)
    ));
    assert!(matches!(
        registry.consume(
            challenge.nonce,
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            &proof,
            NOW + 1_000_000,
            &fixture.state
        ),
        Ok(Consumption::AlreadyCommitted)
    ));
    let mut wrong = proof.clone();
    wrong.signature[0] ^= 1;
    assert!(matches!(
        fixture.consume(&mut registry, &challenge, &wrong),
        Err(RegistryError::Replay)
    ));
    fixture.state.epoch += 1;
    assert!(matches!(
        fixture.consume(&mut registry, &challenge, &proof),
        Err(RegistryError::UnknownNonce)
    ));
    assert!(registry.receipts.is_empty());
}

#[test]
fn completion_cannot_publish_an_unrelated_or_unversioned_state() {
    for change in [
        "no_epoch",
        "skip_epoch",
        "wrong_phase",
        "root",
        "origin",
        "startup_origin",
        "accepted",
        "not_active",
    ] {
        let fixture = Fixture::new(HostLifecycleCommand::Activate);
        let mut registry = fixture.registry();
        let challenge = fixture.issue(&mut registry, HostLifecycleCommand::Activate);
        let mut after = fixture.after(HostPhase::Active);
        match change {
            "no_epoch" => after.epoch -= 1,
            "skip_epoch" => after.epoch += 1,
            "wrong_phase" => after.phase = HostPhase::DetachedResident,
            "root" => after.root_image.as_mut().unwrap().identity.birth += 1,
            "origin" => after.initially_owned = true,
            "startup_origin" => after.initialization_origin = wire::InitializationOrigin::ForkChild,
            "accepted" => after.accepted_digest = Some([9; 32]),
            "not_active" => after.ever_active = false,
            _ => unreachable!(),
        }
        assert!(
            fixture
                .admit(&mut registry, &challenge)
                .commit(&fixture.state, &after)
                .is_err(),
            "{change}"
        );
        assert!(registry.receipts.is_empty());
        assert!(registry.active.is_none());
    }
}

#[test]
fn backwards_state_origin_change_and_copied_owner_are_rejected() {
    let fixture = Fixture::new(HostLifecycleCommand::Detach);
    for change in [
        "epoch",
        "same_epoch",
        "origin",
        "startup_origin",
        "ever_active",
        "owner",
    ] {
        let mut registry = fixture.registry();
        let mut state = fixture.state.clone();
        match change {
            "epoch" => state.epoch -= 1,
            "same_epoch" => state.alias_paused = true,
            "origin" => {
                state.epoch += 1;
                state.initially_owned = true;
            }
            "startup_origin" => {
                state.epoch += 1;
                state.initialization_origin = wire::InitializationOrigin::ForkChild;
            }
            "ever_active" => {
                state.epoch += 1;
                state.ever_active = false;
            }
            "owner" => registry.owner_pid = std::process::id().wrapping_add(1),
            _ => unreachable!(),
        }
        assert!(
            registry
                .issue(
                    &fixture.request,
                    &fixture.scope,
                    &fixture.certificate,
                    HostLifecycleCommand::Detach,
                    NOW,
                    &state
                )
                .is_err(),
            "{change}"
        );
        assert!(registry.pending.is_empty());
    }
}

#[test]
fn state_admission_checks_readiness_root_and_exact_current_retirement() {
    for change in ["native", "paused", "root", "missing_root"] {
        let mut fixture = Fixture::new(HostLifecycleCommand::Activate);
        match change {
            "native" => fixture.state.native_ready = false,
            "paused" => fixture.state.alias_paused = true,
            "root" => fixture.state.root_image.as_mut().unwrap().identity.birth += 1,
            "missing_root" => fixture.state.root_image = None,
            _ => unreachable!(),
        }
        assert!(
            fixture
                .registry()
                .issue(
                    &fixture.request,
                    &fixture.scope,
                    &fixture.certificate,
                    HostLifecycleCommand::Activate,
                    NOW,
                    &fixture.state
                )
                .is_err(),
            "{change}"
        );
    }
    let mut fixture = Fixture::new(HostLifecycleCommand::Retire);
    fixture.state.phase = HostPhase::DetachedResident;
    fixture.state.accepted_digest =
        Some(wire::host_accepted_operation_digest(&fixture.certificate).unwrap());
    assert!(fixture
        .registry()
        .issue(
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Retire,
            NOW,
            &fixture.state
        )
        .is_err());
    fixture.state.unload_ready = true;
    assert!(fixture
        .registry()
        .issue(
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Retire,
            NOW,
            &fixture.state
        )
        .is_ok());
    fixture.state.accepted_digest = Some([9; 32]);
    assert!(fixture
        .registry()
        .issue(
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Retire,
            NOW,
            &fixture.state
        )
        .is_err());
}

#[test]
fn rollback_retirement_requires_same_locally_committed_never_active_attach() {
    let mut fixture = Fixture::new(HostLifecycleCommand::RollbackInitialAttach);
    fixture.state.root_image = None; // Initialization may fail before enrollment.
    let mut registry = fixture.registry();
    let rollback = fixture.issue(&mut registry, HostLifecycleCommand::RollbackInitialAttach);
    let mut off = fixture.after(HostPhase::DetachedResident);
    off.unload_ready = true;
    fixture
        .admit(&mut registry, &rollback)
        .commit(&fixture.state, &off)
        .unwrap();
    fixture.state = off;
    fixture.request.command = HostCommand::Retire;
    let retire = fixture.issue(
        &mut registry,
        HostLifecycleCommand::RollbackInitialAttachRetire,
    );
    assert!(
        fixture
            .registry()
            .issue(
                &fixture.request,
                &fixture.scope,
                &fixture.certificate,
                HostLifecycleCommand::RollbackInitialAttachRetire,
                NOW,
                &fixture.state
            )
            .is_err(),
        "a reconstructed registry has no local rollback receipt"
    );
    assert!(
        registry
            .issue(
                &fixture.request,
                &fixture.scope,
                &fixture.certificate,
                HostLifecycleCommand::Retire,
                NOW,
                &fixture.state
            )
            .is_err(),
        "Attach is not general Detach authority"
    );
    let other = Fixture::certificate(&fixture.core, &fixture.scope, 8);
    assert!(registry
        .issue(
            &fixture.request,
            &fixture.scope,
            &other,
            HostLifecycleCommand::RollbackInitialAttachRetire,
            NOW,
            &fixture.state
        )
        .is_err());
    fixture
        .admit(&mut registry, &retire)
        .commit(&fixture.state, &fixture.state)
        .unwrap();
    assert_eq!(
        registry.committed_initial_rollback,
        fixture.state.accepted_digest
    );
    for origin in [
        wire::InitializationOrigin::Unknown,
        wire::InitializationOrigin::ForkChild,
    ] {
        let mut fixture = Fixture::new(HostLifecycleCommand::RollbackInitialAttach);
        fixture.state.initialization_origin = origin;
        for root_present in [true, false] {
            if !root_present {
                fixture.state.root_image = None;
            }
            assert!(fixture
                .registry()
                .issue(
                    &fixture.request,
                    &fixture.scope,
                    &fixture.certificate,
                    HostLifecycleCommand::RollbackInitialAttach,
                    NOW,
                    &fixture.state
                )
                .is_err());
        }
        fixture.state.phase = HostPhase::DetachedResident;
        fixture.state.unload_ready = true;
        fixture.state.accepted_digest =
            Some(wire::host_accepted_operation_digest(&fixture.certificate).unwrap());
        fixture.request.command = HostCommand::Retire;
        let mut registry = fixture.registry();
        registry.committed_initial_rollback = fixture.state.accepted_digest;
        assert!(registry
            .issue(
                &fixture.request,
                &fixture.scope,
                &fixture.certificate,
                HostLifecycleCommand::RollbackInitialAttachRetire,
                NOW,
                &fixture.state
            )
            .is_err());
    }
    for owned in [false, true] {
        let mut fixture = Fixture::new(HostLifecycleCommand::RollbackInitialAttach);
        fixture.state.initially_owned = owned;
        fixture.state.ever_active = !owned;
        assert!(fixture
            .registry()
            .issue(
                &fixture.request,
                &fixture.scope,
                &fixture.certificate,
                HostLifecycleCommand::RollbackInitialAttach,
                NOW,
                &fixture.state
            )
            .is_err());
    }
}

#[test]
fn expiry_overflow_and_new_initialization_do_not_revive_old_nonce() {
    let fixture = Fixture::new(HostLifecycleCommand::Detach);
    let mut registry = fixture.registry();
    let challenge = fixture.issue(&mut registry, HostLifecycleCommand::Detach);
    let proof = fixture.proof(&challenge);
    assert!(registry
        .consume(
            challenge.nonce,
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            &proof,
            challenge.expires_at_ms,
            &fixture.state
        )
        .is_err());
    assert!(registry.pending.contains_key(&challenge.nonce));
    // Pure expiry/replay behavior does not depend on a supported OS identity
    // reader. The actual constructor has its separate platform-specific test.
    let mut fresh =
        HostCommandRegistry::create(std::process::id(), 222, [9; 32], fixture.state.clone());
    assert!(matches!(
        fixture.consume(&mut fresh, &challenge, &proof),
        Err(RegistryError::UnknownNonce)
    ));
    assert!(fresh
        .issue(
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Detach,
            u64::MAX - 1,
            &fixture.state
        )
        .is_err());
    assert!(fresh.pending.is_empty());
}

#[test]
fn tracked_never_active_startup_accepts_new_detach_before_root_image_enrollment() {
    let mut fixture = Fixture::new(HostLifecycleCommand::PrepareDetachment);
    fixture.state.phase = HostPhase::Preparing;
    fixture.state.root_image = None;
    fixture.state.native_ready = false;
    fixture.state.ever_active = false;
    fixture.state.preparation_cleanup = true;
    let mut registry = fixture.registry();
    let challenge = fixture.issue(&mut registry, HostLifecycleCommand::PrepareDetachment);
    let mut paused = fixture.after(HostPhase::Preparing);
    paused.alias_paused = true;
    fixture
        .admit(&mut registry, &challenge)
        .commit(&fixture.state, &paused)
        .unwrap();
    fixture.state = paused;
    fixture.request.command = HostCommand::Detach;
    let detach = fixture.issue(&mut registry, HostLifecycleCommand::Detach);
    let mut off = fixture.after(HostPhase::DetachedResident);
    off.alias_paused = false;
    fixture
        .admit(&mut registry, &detach)
        .commit(&fixture.state, &off)
        .unwrap();
    fixture.state = off;
    fixture.request.command = HostCommand::Retire;
    fixture.state.unload_ready = true;
    fixture.state.epoch += 1;
    let retire = fixture.issue(&mut registry, HostLifecycleCommand::Retire);
    fixture
        .admit(&mut registry, &retire)
        .commit(&fixture.state, &fixture.state)
        .unwrap();
}

#[test]
fn startup_cleanup_never_bypasses_root_image_or_activation_authority() {
    for (tracked, ever_active) in [(false, false), (true, true)] {
        let mut fixture = Fixture::new(HostLifecycleCommand::PrepareDetachment);
        fixture.state.phase = HostPhase::Preparing;
        fixture.state.root_image = None;
        fixture.state.ever_active = ever_active;
        fixture.state.preparation_cleanup = tracked;
        assert!(fixture
            .registry()
            .issue(
                &fixture.request,
                &fixture.scope,
                &fixture.certificate,
                HostLifecycleCommand::PrepareDetachment,
                NOW,
                &fixture.state
            )
            .is_err());
    }
    let mut fixture = Fixture::new(HostLifecycleCommand::Activate);
    fixture.state.root_image = None;
    fixture.state.preparation_cleanup = true;
    assert!(fixture
        .registry()
        .issue(
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::Activate,
            NOW,
            &fixture.state
        )
        .is_err());
    let mut fixture = Fixture::new(HostLifecycleCommand::PrepareDetachment);
    fixture.state.phase = HostPhase::Preparing;
    fixture.state.ever_active = false;
    fixture.state.preparation_cleanup = true;
    fixture.state.root_image.as_mut().unwrap().exec_epoch += 1;
    assert!(fixture
        .registry()
        .issue(
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            HostLifecycleCommand::PrepareDetachment,
            NOW,
            &fixture.state
        )
        .is_err());
}
