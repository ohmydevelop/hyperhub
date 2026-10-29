use super::*;
use ed25519_dalek::{Signer, SigningKey};
fn link(
    instance: &str,
    generation: u64,
    previous: &SigningKey,
    next: &SigningKey,
) -> SignedApprovalRootTransition {
    let transition = ApprovalRootTransition {
        schema_version: 1,
        instance_id: instance.into(),
        generation,
        previous_public_key: previous.verifying_key().to_bytes(),
        public_key: next.verifying_key().to_bytes(),
        previous_config_id: [generation as u8 - 1; 16],
        config_id: [generation as u8; 16],
    };
    let bytes = approval_transition_bytes(&transition).unwrap();
    SignedApprovalRootTransition {
        transition,
        previous_signature: previous.sign(&bytes).to_bytes().to_vec(),
        signature: next.sign(&bytes).to_bytes().to_vec(),
    }
}
#[test]
fn dual_signatures_integer_generations_and_unique_roots_reject_forks_and_rollback() {
    let a = SigningKey::from_bytes(&[1; 32]);
    let b = SigningKey::from_bytes(&[2; 32]);
    let c = SigningKey::from_bytes(&[3; 32]);
    let chain = vec![link("instance", 1, &a, &b), link("instance", 2, &b, &c)];
    assert_eq!(
        verify_approval_root_chain("instance", &chain).unwrap(),
        (c.verifying_key().to_bytes(), 2, [2; 16])
    );
    assert!(verify_approval_root_chain("wrong-instance", &chain).is_err());
    for field in [
        "previous-signature",
        "next-signature",
        "generation",
        "previous-key",
        "config-id",
    ] {
        let mut bad = chain.clone();
        match field {
            "previous-signature" => bad[1].previous_signature[0] ^= 1,
            "next-signature" => bad[1].signature[0] ^= 1,
            "generation" => bad[1].transition.generation = 1,
            "previous-key" => bad[1].transition.previous_public_key = a.verifying_key().to_bytes(),
            _ => bad[1].transition.config_id = [1; 16],
        }
        assert!(
            verify_approval_root_chain("instance", &bad).is_err(),
            "{field}"
        );
    }
    let cycle = vec![link("instance", 1, &a, &b), link("instance", 2, &b, &a)];
    assert!(verify_approval_root_chain("instance", &cycle).is_err());
}
#[test]
fn fresh_host_nonce_is_required_and_a_prefix_cannot_move_a_current_pin_backwards() {
    let a = SigningKey::from_bytes(&[1; 32]);
    let b = SigningKey::from_bytes(&[2; 32]);
    let c = SigningKey::from_bytes(&[3; 32]);
    let bootstrap:Bootstrap = serde_json::from_value(serde_json::json!({
        "attachment_id":"attachment","session_id":"session","token":"t".repeat(64),
        "control_endpoint":"unused","socks_address":"127.0.0.1:1","tls_ca_pem":"unused","observe":false,
        "host_endpoint":"unused","host_token":"h".repeat(64),"scope_tree":true,"root_pid":123,
        "approval_authority_file":"unused","approval_instance_id":"instance","approval_cli_sha256":"c".repeat(64),
        "approval_core_pid":0,"approval_core_birth":0
    })).unwrap();
    let challenge = ApprovalEnrollmentChallenge {
        challenge: [8; 32],
        host_pid: 124,
        host_birth: 200,
        expires_at_ms: 600,
    };
    let value = ApprovalRotationEnrollment {
        schema_version: 1,
        instance_id: "instance".into(),
        attachment_id: "attachment".into(),
        root_pid: 123,
        challenge: challenge.clone(),
        issued_at_ms: 100,
        chain: vec![link("instance", 1, &a, &b), link("instance", 2, &b, &c)],
    };
    let sign = |value: &ApprovalRotationEnrollment, key: &SigningKey| {
        let payload = approval_rotation_enrollment_bytes(value).unwrap();
        ApprovalRootCertificate {
            signature: key.sign(&payload).to_bytes().to_vec(),
            payload,
        }
    };
    let certificate = sign(&value, &c);
    assert_eq!(
        verify_approval_rotation_enrollment(
            &bootstrap,
            &a.verifying_key().to_bytes(),
            0,
            &challenge,
            &certificate,
            200
        )
        .unwrap(),
        (c.verifying_key().to_bytes(), 2)
    );
    assert!(verify_approval_rotation_enrollment(
        &bootstrap,
        &c.verifying_key().to_bytes(),
        2,
        &challenge,
        &certificate,
        200
    )
    .is_err());
    assert!(verify_approval_rotation_enrollment(
        &bootstrap,
        &a.verifying_key().to_bytes(),
        0,
        &challenge,
        &certificate,
        600
    )
    .is_err());
    let mut other = challenge.clone();
    other.challenge[0] ^= 1;
    assert!(verify_approval_rotation_enrollment(
        &bootstrap,
        &a.verifying_key().to_bytes(),
        0,
        &other,
        &certificate,
        200
    )
    .is_err());
    assert!(verify_approval_rotation_enrollment(
        &bootstrap,
        &a.verifying_key().to_bytes(),
        0,
        &challenge,
        &sign(&value, &b),
        200
    )
    .is_err());
    let mut same_time = value;
    same_time.issued_at_ms = 100;
    same_time.chain.truncate(1);
    assert!(verify_approval_rotation_enrollment(
        &bootstrap,
        &c.verifying_key().to_bytes(),
        2,
        &challenge,
        &sign(&same_time, &b),
        200
    )
    .is_err());
}
