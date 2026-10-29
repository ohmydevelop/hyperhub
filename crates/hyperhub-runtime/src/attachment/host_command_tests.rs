use super::*;
use crate::attachment::{
    encode_accepted_operation, AcceptedOperationPayload, ApprovalProof, ManagerClaimant,
    PossessionChallenge, RootImageIdentity, RootImageState,
};
use ed25519_dalek::{Signer, SigningKey};

struct Fixture {
    core: SigningKey,
    manager: SigningKey,
    request: AuthenticatedCommand,
    scope: OperationScope,
    certificate: AcceptedOperationCertificate,
    challenge: HostCommandChallenge,
}
impl Fixture {
    fn new() -> Self {
        let core = SigningKey::from_bytes(&[21; 32]);
        let manager = SigningKey::from_bytes(&[22; 32]);
        let request = AuthenticatedCommand {
            attachment_id: "attachment".into(),
            token: "h".repeat(64),
            command: HostCommand::Detach,
            proof: Some(ApprovalProof {
                payload: vec![1, 2, 3],
                signature: vec![4; 64],
            }),
            enrollment: None,
            aliases: None,
            root_image: None,
        };
        // This codec receives a scope already derived by the authorization
        // layer; its tests do not substitute for administrator verification.
        let scope = OperationScope {
            action: OperationAction::Detach,
            administrator_digest: operation_administrator_digest(request.proof.as_ref().unwrap())
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
        let certificate = Self::certificate(&core, &scope);
        let challenge = HostCommandChallenge {
            schema_version: 1,
            accepted_digest: host_accepted_operation_digest(&certificate).unwrap(),
            host_pid: 111,
            host_birth: 222,
            host_epoch: [8; 32],
            state_epoch: 3,
            intent: HostCommandIntent::for_request(&request, HostLifecycleCommand::Detach).unwrap(),
            nonce: [9; 32],
            issued_at_ms: 1000,
            expires_at_ms: 2000,
        };
        Self {
            core,
            manager,
            request,
            scope,
            certificate,
            challenge,
        }
    }
    fn certificate(core: &SigningKey, scope: &OperationScope) -> AcceptedOperationCertificate {
        let payload = encode_accepted_operation(&AcceptedOperationPayload {
            schema_version: 1,
            challenge: PossessionChallenge {
                schema_version: 1,
                scope: scope.clone(),
                nonce: [7; 32],
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
    fn proof(&self) -> HostCommandPossessionProof {
        let payload = encode_host_command_challenge(&self.challenge).unwrap();
        HostCommandPossessionProof {
            signature: self.manager.sign(&payload).to_bytes().to_vec(),
            payload,
        }
    }
    fn verify(&self, proof: &HostCommandPossessionProof) -> io::Result<HostCommandChallenge> {
        verify_host_command_proof(
            &self.challenge,
            &self.request,
            &self.scope,
            &self.certificate,
            proof,
            1100,
        )
    }
}

#[test]
fn issuer_matrix_keeps_core_metadata_separate_from_manager_lifecycle() {
    use HostCommandAuthority::*;
    for (command, authority) in [
        (HostCommand::Status, ObserverWithDetachedMaintenance),
        (HostCommand::EnrollmentChallenge, EnrollmentChallengeRead),
        (
            HostCommand::EnrollApprovalRoot,
            OriginalCoreEnrollmentCertificate,
        ),
        (HostCommand::SnapshotAliases, ScopedCoreRead),
        (HostCommand::ApplySessionAliases, SignedCoreMetadata),
        (HostCommand::ApplyRootImage, SignedCoreMetadata),
        (HostCommand::Activate, ManagerLifecycle),
        (HostCommand::Detach, ManagerLifecycle),
        (HostCommand::Retire, ManagerLifecycle),
        (HostCommand::PrepareDetachment, ManagerLifecycle),
        (HostCommand::CancelDetachmentPreparation, ManagerLifecycle),
    ] {
        assert_eq!(host_command_authority(command), authority);
    }
    let fixture = Fixture::new();
    let mut metadata = fixture.request.clone();
    metadata.command = HostCommand::ApplyRootImage;
    assert!(HostCommandIntent::for_request(&metadata, HostLifecycleCommand::Activate).is_err());
    assert!(HostCommandIntent::for_request(
        &fixture.request,
        HostLifecycleCommand::PrepareActivation
    )
    .is_err());
}

#[test]
fn accepted_certificate_requires_the_bound_manager_signature() {
    let fixture = Fixture::new();
    let proof = fixture.proof();
    assert_eq!(fixture.verify(&proof).unwrap(), fixture.challenge);
    let mut missing = proof.clone();
    missing.signature.clear();
    assert!(fixture.verify(&missing).is_err());
    let mut wrong = proof.clone();
    wrong.signature = fixture.core.sign(&wrong.payload).to_bytes().to_vec();
    assert!(fixture.verify(&wrong).is_err());
    let mut self_selected = fixture.scope.clone();
    self_selected.core_public_key = SigningKey::from_bytes(&[23; 32]).verifying_key().to_bytes();
    assert!(verify_host_command_proof(
        &fixture.challenge,
        &fixture.request,
        &self_selected,
        &fixture.certificate,
        &proof,
        1100
    )
    .is_err());
    assert!(!String::from_utf8_lossy(&proof.payload).contains(&fixture.request.token));
    assert!(!format!("{proof:?}").contains("signature"));
}

#[test]
fn host_process_epoch_command_nonce_and_accepted_scope_are_bound() {
    let fixture = Fixture::new();
    let proof = fixture.proof();
    for change in [
        "pid",
        "birth",
        "host_epoch",
        "state_epoch",
        "nonce",
        "intent",
        "accepted",
    ] {
        let mut expected = fixture.challenge.clone();
        match change {
            "pid" => expected.host_pid += 1,
            "birth" => expected.host_birth += 1,
            "host_epoch" => expected.host_epoch[0] ^= 1,
            "state_epoch" => expected.state_epoch += 1,
            "nonce" => expected.nonce[0] ^= 1,
            "intent" => expected.intent.payload_digest[0] ^= 1,
            "accepted" => expected.accepted_digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            verify_host_command_proof(
                &expected,
                &fixture.request,
                &fixture.scope,
                &fixture.certificate,
                &proof,
                1100
            )
            .is_err(),
            "{change}"
        );
    }
    let mut wrong_role = fixture.scope.clone();
    wrong_role.claimant.role_epoch[0] ^= 1;
    assert!(verify_host_command_proof(
        &fixture.challenge,
        &fixture.request,
        &wrong_role,
        &fixture.certificate,
        &proof,
        1100
    )
    .is_err());
    let mut wrong_image = fixture.scope.clone();
    wrong_image.root_image.identity.executable_sha256 = "c".repeat(64);
    assert!(verify_host_command_proof(
        &fixture.challenge,
        &fixture.request,
        &wrong_image,
        &fixture.certificate,
        &proof,
        1100
    )
    .is_err());
}

#[test]
fn every_current_optional_payload_and_credential_is_part_of_the_intent() {
    let fixture = Fixture::new();
    let proof = fixture.proof();
    for change in [
        "attachment",
        "token",
        "proof",
        "enrollment",
        "aliases",
        "root_image",
        "command",
    ] {
        let mut request = fixture.request.clone();
        match change {
            "attachment" => request.attachment_id.push('x'),
            "token" => request.token.push('x'),
            "proof" => request.proof.as_mut().unwrap().signature[0] ^= 1,
            "enrollment" => {
                request.enrollment = Some(crate::attachment::ApprovalRootCertificate {
                    payload: vec![1],
                    signature: vec![2; 64],
                })
            }
            "aliases" => {
                request.aliases = Some(crate::attachment::SignedSessionAliasSnapshot {
                    payload: vec![1],
                    signature: vec![2; 64],
                })
            }
            "root_image" => {
                request.root_image = Some(crate::attachment::SignedRootImage {
                    payload: vec![1],
                    signature: vec![2; 64],
                })
            }
            "command" => request.command = HostCommand::Retire,
            _ => unreachable!(),
        }
        assert!(
            verify_host_command_proof(
                &fixture.challenge,
                &request,
                &fixture.scope,
                &fixture.certificate,
                &proof,
                1100
            )
            .is_err(),
            "{change}"
        );
    }
    let mut no_admin = fixture.request.clone();
    no_admin.proof = None;
    assert!(verify_host_command_proof(
        &fixture.challenge,
        &no_admin,
        &fixture.scope,
        &fixture.certificate,
        &proof,
        1100
    )
    .is_err());
}

#[test]
fn fresh_command_window_is_required_even_for_historical_detach_acceptance() {
    let fixture = Fixture::new();
    let proof = fixture.proof();
    // Core acceptance expired at 500; exact historical evidence remains valid
    // only with new command possession. The live Host still checks history.
    assert!(fixture.verify(&proof).is_ok());
    assert!(verify_host_command_proof(
        &fixture.challenge,
        &fixture.request,
        &fixture.scope,
        &fixture.certificate,
        &proof,
        1999
    )
    .is_ok());
    for now in [999, 2000, 2001] {
        assert!(verify_host_command_proof(
            &fixture.challenge,
            &fixture.request,
            &fixture.scope,
            &fixture.certificate,
            &proof,
            now
        )
        .is_err());
    }
    let mut long = fixture.challenge.clone();
    long.expires_at_ms = long.issued_at_ms + HOST_COMMAND_CHALLENGE_LIFETIME_MS + 1;
    assert!(encode_host_command_challenge(&long).is_err());
}

#[test]
fn rollback_has_a_distinct_attach_purpose_and_never_a_generic_detach_intent() {
    let mut fixture = Fixture::new();
    fixture.scope.action = OperationAction::Attach;
    fixture.certificate = Fixture::certificate(&fixture.core, &fixture.scope);
    fixture.challenge.accepted_digest =
        host_accepted_operation_digest(&fixture.certificate).unwrap();
    assert!(fixture.verify(&fixture.proof()).is_err());
    fixture.challenge.intent = HostCommandIntent::for_request(
        &fixture.request,
        HostLifecycleCommand::RollbackInitialAttach,
    )
    .unwrap();
    assert!(fixture.verify(&fixture.proof()).is_ok());
    // Preparing/uncommitted/initial ownership is a live Host state condition,
    // deliberately not inferred from an accepted certificate by this codec.
    assert_eq!(
        fixture.challenge.intent.command.operation(),
        OperationAction::Attach
    );
}

#[test]
fn rollback_retirement_has_its_own_attach_intent() {
    let mut fixture = Fixture::new();
    fixture.scope.action = OperationAction::Attach;
    fixture.request.command = HostCommand::Retire;
    fixture.certificate = Fixture::certificate(&fixture.core, &fixture.scope);
    fixture.challenge.accepted_digest =
        host_accepted_operation_digest(&fixture.certificate).unwrap();
    fixture.challenge.intent =
        HostCommandIntent::for_request(&fixture.request, HostLifecycleCommand::Retire).unwrap();
    assert!(fixture.verify(&fixture.proof()).is_err());
    fixture.challenge.intent = HostCommandIntent::for_request(
        &fixture.request,
        HostLifecycleCommand::RollbackInitialAttachRetire,
    )
    .unwrap();
    assert!(fixture.verify(&fixture.proof()).is_ok());
    assert_eq!(
        fixture.challenge.intent.command.operation(),
        OperationAction::Attach
    );
    // The SDK must separately prove the same local rollback was committed and
    // that this Host was never Active. An acceptance certificate is insufficient.
}

#[test]
fn alternate_domains_noncanonical_or_oversized_proofs_are_rejected() {
    let fixture = Fixture::new();
    let mut proof = fixture.proof();
    proof.payload.push(b' ');
    assert!(fixture.verify(&proof).is_err());
    let mut proof = fixture.proof();
    proof.payload[0] ^= 1;
    assert!(fixture.verify(&proof).is_err());
    let mut proof = fixture.proof();
    proof.payload = vec![0; MAX_COMMAND_PROOF_BYTES + 1];
    assert!(fixture.verify(&proof).is_err());
}

#[test]
fn lifecycle_intents_reject_metadata_without_a_lifecycle_semantic() {
    let fixture = Fixture::new();
    for field in ["enrollment", "aliases", "root_image"] {
        let mut request = fixture.request.clone();
        match field {
            "enrollment" => {
                request.enrollment = Some(crate::attachment::ApprovalRootCertificate {
                    payload: vec![1],
                    signature: vec![2; 64],
                })
            }
            "aliases" => {
                request.aliases = Some(crate::attachment::SignedSessionAliasSnapshot {
                    payload: vec![1],
                    signature: vec![2; 64],
                })
            }
            "root_image" => {
                request.root_image = Some(crate::attachment::SignedRootImage {
                    payload: vec![1],
                    signature: vec![2; 64],
                })
            }
            _ => unreachable!(),
        }
        assert!(
            HostCommandIntent::for_request(&request, HostLifecycleCommand::Detach).is_err(),
            "{field}"
        );
    }
}
