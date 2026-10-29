use super::*;
use ed25519_dalek::{Signer, SigningKey};

fn fixture() -> (SigningKey, SigningKey, PossessionChallenge) {
    let manager = SigningKey::from_bytes(&[7; 32]);
    let core = SigningKey::from_bytes(&[8; 32]);
    let challenge = PossessionChallenge {
        schema_version: 1,
        scope: OperationScope {
            action: OperationAction::Detach,
            administrator_digest: [1; 32],
            instance_id: "instance".into(),
            attachment_id: "attachment".into(),
            session_id: "session".into(),
            credential_digest: [2; 32],
            host_binding: "ab".repeat(32),
            root_image: RootImageState {
                identity: super::super::RootImageIdentity {
                    pid: 4,
                    birth: 5,
                    executable_sha256: "cd".repeat(32),
                },
                exec_epoch: 0,
                observed_at_ms: 0,
                head: [0; 32],
            },
            claimant: ManagerClaimant {
                pid: 6,
                birth: 7,
                role_epoch: [3; 32],
                public_key: manager.verifying_key().to_bytes(),
            },
            core_public_key: core.verifying_key().to_bytes(),
        },
        nonce: [4; 32],
        issued_at_ms: 1_000,
        expires_at_ms: 2_000,
    };
    (manager, core, challenge)
}
fn proof(manager: &SigningKey, challenge: &PossessionChallenge) -> PossessionProof {
    let payload = encode_possession_challenge(challenge).unwrap();
    PossessionProof {
        signature: manager.sign(&payload).to_bytes().to_vec(),
        payload,
    }
}
fn certificate(core: &SigningKey, challenge: &PossessionChallenge) -> AcceptedOperationCertificate {
    let payload = encode_accepted_operation(&AcceptedOperationPayload {
        schema_version: 1,
        challenge: challenge.clone(),
        accepted_at_ms: 1_500,
    })
    .unwrap();
    AcceptedOperationCertificate {
        signature: core.sign(&payload).to_bytes().to_vec(),
        payload,
    }
}
#[test]
fn possession_binds_exact_scope_nonce_key_and_window() {
    let (manager, _, challenge) = fixture();
    let proof = proof(&manager, &challenge);
    verify_possession_proof(&challenge, &proof, 1_001).unwrap();
    assert!(verify_possession_proof(&challenge, &proof, 999).is_err());
    assert!(verify_possession_proof(&challenge, &proof, 2_000).is_err());
    let mut variants = Vec::new();
    let mut value = challenge.clone();
    value.nonce[0] ^= 1;
    variants.push(value);
    let mut value = challenge.clone();
    value.scope.claimant.role_epoch[0] ^= 1;
    variants.push(value);
    let mut value = challenge.clone();
    value.scope.claimant.pid += 1;
    variants.push(value);
    let mut value = challenge.clone();
    value.scope.root_image.exec_epoch = 1;
    value.scope.root_image.observed_at_ms = 1;
    value.scope.root_image.head = [5; 32];
    variants.push(value);
    for value in variants {
        assert!(verify_possession_proof(&value, &proof, 1_001).is_err());
    }
    let wrong = SigningKey::from_bytes(&[9; 32]);
    assert!(verify_possession_proof(&challenge, &self::proof(&wrong, &challenge), 1_001).is_err());
    let mut too_long = challenge;
    too_long.expires_at_ms = too_long.issued_at_ms + OPERATION_CHALLENGE_LIFETIME_MS + 1;
    assert!(encode_possession_challenge(&too_long).is_err());
}
#[test]
fn certificate_proves_only_exact_historical_acceptance() {
    let (_, core, challenge) = fixture();
    let cert = certificate(&core, &challenge);
    verify_accepted_operation(&challenge.scope, &cert, 100_000).unwrap();
    assert!(verify_accepted_operation(&challenge.scope, &cert, 1_499).is_err());
    let mut scopes = Vec::new();
    macro_rules! change {
        ($field:ident, $value:expr) => {{
            let mut value = challenge.scope.clone();
            value.$field = $value;
            scopes.push(value);
        }};
    }
    change!(action, OperationAction::Attach);
    change!(administrator_digest, [9; 32]);
    change!(instance_id, "another-instance".into());
    change!(attachment_id, "another-attachment".into());
    change!(session_id, "another-session".into());
    change!(credential_digest, [9; 32]);
    change!(host_binding, "ef".repeat(32));
    change!(
        core_public_key,
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes()
    );
    let mut scope = challenge.scope.clone();
    scope.root_image.identity.executable_sha256 = "ef".repeat(32);
    scopes.push(scope);
    let mut scope = challenge.scope.clone();
    scope.root_image.exec_epoch = 1;
    scope.root_image.observed_at_ms = 1;
    scope.root_image.head = [5; 32];
    scopes.push(scope);
    let mut scope = challenge.scope.clone();
    scope.claimant.birth += 1;
    scopes.push(scope);
    for scope in scopes {
        assert!(verify_accepted_operation(&scope, &cert, 100_000).is_err());
    }
    let wrong = SigningKey::from_bytes(&[9; 32]);
    assert!(
        verify_accepted_operation(&challenge.scope, &certificate(&wrong, &challenge), 1_500)
            .is_err()
    );
    let mut late = AcceptedOperationPayload {
        schema_version: 1,
        challenge: challenge.clone(),
        accepted_at_ms: challenge.expires_at_ms,
    };
    assert!(encode_accepted_operation(&late).is_err());
    late.accepted_at_ms = challenge.issued_at_ms - 1;
    assert!(encode_accepted_operation(&late).is_err());
    let mut weak = challenge.scope.clone();
    weak.claimant.public_key = [0; 32];
    assert!(weak.validate().is_err());
    let mut malformed_signature = cert;
    malformed_signature.signature.pop();
    assert!(verify_accepted_operation(&challenge.scope, &malformed_signature, 1_500).is_err());
}
#[test]
fn strict_decoding_rejects_wrong_domains_unknown_fields_and_noncanonical_bytes() {
    let (manager, core, challenge) = fixture();
    let mut proof = proof(&manager, &challenge);
    proof.payload[0] ^= 1;
    proof.signature = manager.sign(&proof.payload).to_bytes().to_vec();
    assert!(verify_possession_proof(&challenge, &proof, 1_001).is_err());
    let mut cert = certificate(&core, &challenge);
    let original = cert.payload.clone();
    let mut json: serde_json::Value =
        serde_json::from_slice(&original[OPERATION_ACCEPTED_DOMAIN.len()..]).unwrap();
    json["unexpected"] = serde_json::json!(true);
    cert.payload = OPERATION_ACCEPTED_DOMAIN.to_vec();
    cert.payload.extend(serde_json::to_vec(&json).unwrap());
    cert.signature = core.sign(&cert.payload).to_bytes().to_vec();
    assert!(verify_accepted_operation(&challenge.scope, &cert, 1_500).is_err());
    cert.payload = original;
    cert.payload.push(b' ');
    cert.signature = core.sign(&cert.payload).to_bytes().to_vec();
    assert!(verify_accepted_operation(&challenge.scope, &cert, 1_500).is_err());
    cert.payload = vec![0; MAX_OPERATION_BYTES + 1];
    assert!(verify_accepted_operation(&challenge.scope, &cert, 1_500).is_err());
    assert!(!format!("{cert:?}").contains("payload"));
}
#[test]
fn administrator_digest_preserves_exact_signed_bytes() {
    let mut proof = super::super::ApprovalProof {
        payload: vec![1, 2],
        signature: vec![3; 64],
    };
    let first = operation_administrator_digest(&proof).unwrap();
    proof.payload.push(0);
    assert_ne!(first, operation_administrator_digest(&proof).unwrap());
    proof.payload.pop();
    proof.signature[0] ^= 1;
    assert_ne!(first, operation_administrator_digest(&proof).unwrap());
    proof.signature.pop();
    assert!(operation_administrator_digest(&proof).is_err());
}
