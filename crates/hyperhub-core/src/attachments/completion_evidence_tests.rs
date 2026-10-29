use super::*;
use crate::attachments::{self as a, ApprovalAuthority};
use ed25519_dalek::{Signer, SigningKey};

struct Fixture {
    directory: PathBuf,
    root: SigningKey,
    grant: Authorization,
    manager: ProcessIdentity,
    certificate: AcceptedOperationCertificate,
    session: String,
    token: String,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("hh-durable-{}", a::new_id()));
        a::private_directory(&directory).unwrap();
        let root = SigningKey::from_bytes(&[41; 32]);
        let authority = ApprovalAuthority {
            instance_id: "91".repeat(32),
            config_id: [1; 16],
            public_key: root.verifying_key().to_bytes(),
            generation: 0,
        };
        trust::pin_expected_approval_anchor(&directory, authority.clone()).unwrap();
        trust::pin_authority(&directory, authority, None).unwrap();
        trust::pin_approval_continuity(&directory, vec![]).unwrap();
        let core = trust::approval_trust(&directory).unwrap().core_public_key;
        let manager = ProcessIdentity {
            pid: u32::MAX,
            birth: 1,
            executable: "vanished-manager".into(),
            executable_sha256: "ab".repeat(32),
            owner: "test-owner".into(),
        };
        let claimant = wire::ManagerClaimant {
            pid: manager.pid,
            birth: manager.birth,
            role_epoch: [2; 32],
            public_key: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
        };
        let target = ProcessIdentity {
            pid: 42,
            birth: 99,
            executable: "test-target".into(),
            executable_sha256: "cd".repeat(32),
            owner: manager.owner.clone(),
        };
        let now = crate::session::unix_timestamp_ms() - 2000;
        let mut grant = Authorization {
            request: a::Request {
                schema_version: 1,
                id: a::new_id(),
                instance_id: "91".repeat(32),
                created_at_ms: now,
                action: Action::Detach {
                    attachment_id: a::new_id(),
                    target: target.clone(),
                    exec_epoch: 0,
                    policy_digest: "ef".repeat(32),
                    recovery: None,
                },
            },
            approved_at_ms: now,
            expires_at_ms: now + authority::AUTHORIZATION_LIFETIME_MS,
            nonce: [6; 32],
            executor_sha256: manager.executable_sha256.clone(),
            execution_digest: Some("12".repeat(32)),
            host_binding: Some("34".repeat(32)),
            core_attestation_public_key: Some(core),
            manager_claimant: Some(claimant.clone()),
            signature: vec![],
        };
        grant.signature = root
            .sign(&authority::payload(&grant).unwrap())
            .to_bytes()
            .to_vec();
        authority::consume_for_claimant(&directory, &grant, &manager).unwrap();
        let session = "test-session".to_owned();
        let token = "private-fixture-token".to_owned();
        let credential_digest = {
            use sha2::Digest;
            sha2::Sha256::digest(token.as_bytes()).into()
        };
        let accepted = wire::AcceptedOperationPayload {
            schema_version: 1,
            challenge: wire::PossessionChallenge {
                schema_version: 1,
                scope: wire::OperationScope {
                    action: wire::OperationAction::Detach,
                    administrator_digest: wire::operation_administrator_digest(
                        &a::host_proof(&grant).unwrap(),
                    )
                    .unwrap(),
                    instance_id: grant.request.instance_id.clone(),
                    attachment_id: grant.request.action.attachment_id().into(),
                    session_id: session.clone(),
                    credential_digest,
                    host_binding: grant.host_binding.clone().unwrap(),
                    root_image: wire::RootImageState {
                        identity: target.root_image_identity(),
                        exec_epoch: 0,
                        observed_at_ms: 0,
                        head: [0; 32],
                    },
                    claimant,
                    core_public_key: core,
                },
                nonce: [7; 32],
                issued_at_ms: now,
                expires_at_ms: now + wire::OPERATION_CHALLENGE_LIFETIME_MS,
            },
            accepted_at_ms: now + 1,
        };
        let certificate = trust::sign_accepted_operation(&directory, &accepted).unwrap();
        Self {
            directory,
            root,
            grant,
            manager,
            certificate,
            session,
            token,
        }
    }
    fn acceptance(&self) {
        record_operation_acceptance(&self.directory, &self.grant, &self.certificate).unwrap();
    }
    fn complete(&self) {
        self.acceptance();
        authority::record_completion_receipt(
            &self.directory,
            &self.grant,
            &self.session,
            &self.token,
            &self.manager,
        )
        .unwrap();
        finalize_durable_completion(
            &self.directory,
            &self.grant,
            &self.session,
            &self.token,
            &self.manager,
        )
        .unwrap();
    }
    fn cleanup(&self) -> Authorization {
        let mut cleanup = self.grant.clone();
        cleanup.nonce = [8; 32];
        cleanup.request.id = a::new_id();
        cleanup.approved_at_ms += 1000;
        cleanup.expires_at_ms += 1000;
        if let Action::Detach { recovery, .. } = &mut cleanup.request.action {
            *recovery = Some(a::RecoveryBinding {
                manager: self.manager.clone(),
                context_digest: "56".repeat(32),
            });
        }
        cleanup.signature = self
            .root
            .sign(&authority::payload(&cleanup).unwrap())
            .to_bytes()
            .to_vec();
        cleanup
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn acceptance_alone_and_unsigned_audit_never_prove_completion() {
    let f = Fixture::new();
    f.acceptance();
    let cleanup = f.cleanup();
    assert!(!prior_completion_matches(
        &f.directory,
        &cleanup,
        &f.session,
        &f.token
    ));
    assert!(!authority::prior_completion_receipt_matches(
        &f.directory,
        &cleanup,
        &f.session,
        &f.token
    ));
    let path = completion_path(&f.directory, &f.grant);
    a::private_directory(path.parent().unwrap()).unwrap();
    a::create_private_file(
        &path,
        &serde_json::to_vec(&serde_json::json!({"payload":[],"signature":[]})).unwrap(),
    )
    .unwrap();
    assert!(!prior_completion_matches(
        &f.directory,
        &cleanup,
        &f.session,
        &f.token
    ));
}

#[test]
fn signed_completion_rejects_changed_session_token_target_epoch_and_bytes() {
    let f = Fixture::new();
    f.complete();
    let cleanup = f.cleanup();
    assert!(prior_completion_matches(
        &f.directory,
        &cleanup,
        &f.session,
        &f.token
    ));
    assert!(!prior_completion_matches(
        &f.directory,
        &cleanup,
        "other-session",
        &f.token
    ));
    assert!(!prior_completion_matches(
        &f.directory,
        &cleanup,
        &f.session,
        "other-token"
    ));
    let mut changed = cleanup.clone();
    if let Action::Detach { exec_epoch, .. } = &mut changed.request.action {
        *exec_epoch += 1;
    }
    assert!(!prior_completion_matches(
        &f.directory,
        &changed,
        &f.session,
        &f.token
    ));
    changed = cleanup.clone();
    changed.request.instance_id.push('x');
    assert!(!prior_completion_matches(
        &f.directory,
        &changed,
        &f.session,
        &f.token
    ));
    changed = cleanup.clone();
    if let Action::Detach { target, .. } = &mut changed.request.action {
        target.birth += 1;
    }
    assert!(!prior_completion_matches(
        &f.directory,
        &changed,
        &f.session,
        &f.token
    ));
    let path = completion_path(&f.directory, &f.grant);
    let original = std::fs::read(&path).unwrap();
    let mut signed: SignedCompletion = serde_json::from_slice(&original).unwrap();
    signed.signature[0] ^= 1;
    crate::config_store::save_private_bytes(&path, &encode(&signed).unwrap()).unwrap();
    assert!(!prior_completion_matches(
        &f.directory,
        &cleanup,
        &f.session,
        &f.token
    ));
    crate::config_store::save_private_bytes(&path, &original).unwrap();
    assert!(prior_completion_matches(
        &f.directory,
        &cleanup,
        &f.session,
        &f.token
    ));
}

#[test]
fn durable_completion_cold_reader_fixture() {
    let Some(directory) = std::env::var_os("HYPERHUB_TEST_COLD_COMPLETION") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let cleanup: Authorization = serde_json::from_slice(
        &a::read_private_file(&directory.join("cleanup.json"), 128 * 1024).unwrap(),
    )
    .unwrap();
    let authority: ApprovalAuthority = serde_json::from_slice(
        &a::read_private_file(&directory.join("anchor.json"), 4096).unwrap(),
    )
    .unwrap();
    assert!(trust::trusted_consumption(&directory, &[6; 32]).is_none());
    assert!(trust::trusted_completion(&directory, &a::digest(&[6; 32])).is_none());
    trust::pin_expected_approval_anchor(&directory, authority).unwrap();
    let chain: Vec<wire::SignedApprovalRootTransition> = serde_json::from_slice(
        &a::read_private_file(&directory.join("chain.json"), 128 * 1024).unwrap(),
    )
    .unwrap();
    assert!(
        !prior_completion_matches(
            &directory,
            &cleanup,
            "test-session",
            "private-fixture-token"
        ),
        "new root alone must not trust a verifier copied from old disk records"
    );
    trust::pin_approval_continuity(&directory, chain).unwrap();
    assert!(authority::prior_completion_receipt_matches(
        &directory,
        &cleanup,
        "test-session",
        "private-fixture-token"
    ));
    // Merely reading a completion proof cannot turn old acceptance into authority.
    assert!(trust::trusted_consumption(&directory, &[6; 32]).is_none());
    assert!(!authority::authorization_consumed_by(
        &directory,
        &cleanup,
        std::process::id()
    ));
    assert!(
        authority::verify_consumed_continuation(&directory, &cleanup, std::process::id()).is_err()
    );
}

#[test]
fn separate_cold_core_verifies_completed_cleanup_after_root_rotation() {
    let f = Fixture::new();
    f.complete();
    let mut cleanup = f.cleanup();
    let next = SigningKey::from_bytes(&[42; 32]);
    cleanup.signature = next
        .sign(&authority::payload(&cleanup).unwrap())
        .to_bytes()
        .to_vec();
    let transition = wire::ApprovalRootTransition {
        schema_version: 1,
        instance_id: cleanup.request.instance_id.clone(),
        generation: 1,
        previous_public_key: f.root.verifying_key().to_bytes(),
        public_key: next.verifying_key().to_bytes(),
        previous_config_id: [1; 16],
        config_id: [2; 16],
    };
    let bytes = wire::approval_transition_bytes(&transition).unwrap();
    let chain = vec![wire::SignedApprovalRootTransition {
        transition,
        previous_signature: f.root.sign(&bytes).to_bytes().to_vec(),
        signature: next.sign(&bytes).to_bytes().to_vec(),
    }];
    let anchor = ApprovalAuthority {
        instance_id: cleanup.request.instance_id.clone(),
        config_id: [2; 16],
        public_key: next.verifying_key().to_bytes(),
        generation: 1,
    };
    for (name, bytes) in [
        ("cleanup.json", serde_json::to_vec(&cleanup).unwrap()),
        ("anchor.json", serde_json::to_vec(&anchor).unwrap()),
        ("chain.json", serde_json::to_vec(&chain).unwrap()),
    ] {
        a::create_private_file(&f.directory.join(name), &bytes).unwrap();
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "attachments::completion_evidence::tests::durable_completion_cold_reader_fixture",
            "--nocapture",
        ])
        .env("HYPERHUB_TEST_COLD_COMPLETION", &f.directory)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn unsigned_revoke_intent_and_new_activation_do_not_prove_current_cleanup() {
    let f = Fixture::new();
    f.acceptance();
    let cleanup = f.cleanup();
    authority::record_completion_receipt(&f.directory, &f.grant, &f.session, &f.token, &f.manager)
        .unwrap();
    assert!(!prior_completion_matches(
        &f.directory,
        &cleanup,
        &f.session,
        &f.token
    ));
    // This stands for the successful SessionRegistry revoke boundary.
    finalize_durable_completion(&f.directory, &f.grant, &f.session, &f.token, &f.manager).unwrap();
    assert!(prior_completion_matches(
        &f.directory,
        &cleanup,
        &f.session,
        &f.token
    ));
    let mut next = cleanup.clone();
    next.nonce = [9; 32];
    trust::activate_epoch(&f.directory, &next).unwrap();
    assert!(!prior_completion_matches(
        &f.directory,
        &cleanup,
        &f.session,
        &f.token
    ));
    assert!(trust::trusted_consumption(&f.directory, &cleanup.nonce).is_none());
}

#[test]
fn accepted_scope_and_history_substitution_are_rejected() {
    let f = Fixture::new();
    let mut changed = f.certificate.clone();
    changed.signature[0] ^= 1;
    assert!(record_operation_acceptance(&f.directory, &f.grant, &changed).is_err());
    assert!(!accepted_path(&f.directory, &f.grant.nonce).exists());
    let next = SigningKey::from_bytes(&[42; 32]);
    let transition = wire::ApprovalRootTransition {
        schema_version: 1,
        instance_id: f.grant.request.instance_id.clone(),
        generation: 1,
        previous_public_key: f.root.verifying_key().to_bytes(),
        public_key: next.verifying_key().to_bytes(),
        previous_config_id: [1; 16],
        config_id: [2; 16],
    };
    let bytes = wire::approval_transition_bytes(&transition).unwrap();
    let link = wire::SignedApprovalRootTransition {
        transition,
        previous_signature: f.root.sign(&bytes).to_bytes().to_vec(),
        signature: next.sign(&bytes).to_bytes().to_vec(),
    };
    // A self-consistent chain cannot override the already fixed config anchor.
    assert!(trust::pin_approval_continuity(&f.directory, vec![link]).is_err());
    assert!(trust::historical_verifier_is_trusted(
        &f.directory,
        &f.grant.request.instance_id,
        &f.root.verifying_key().to_bytes()
    ));
    assert!(!trust::historical_verifier_is_trusted(
        &f.directory,
        &f.grant.request.instance_id,
        &next.verifying_key().to_bytes()
    ));
}
