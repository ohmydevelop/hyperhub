use super::*;
use crate::attachments::{self as a, authority, trust};
use ed25519_dalek::{Signer, SigningKey};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct Fixture {
    directory: PathBuf,
    manager: a::ProcessIdentity,
    key: SigningKey,
    execution: Execution,
    scope: OperationScope,
    accepted: AcceptedOperationCertificate,
    anchor: a::ApprovalAuthority,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir()
            .join(format!("hh-p-{}", a::new_id()))
            .join("a");
        a::private_directory(&directory).unwrap();
        let root = SigningKey::from_bytes(&[61; 32]);
        let key = SigningKey::from_bytes(&[62; 32]);
        let anchor = a::ApprovalAuthority {
            instance_id: "71".repeat(32),
            config_id: [1; 16],
            public_key: root.verifying_key().to_bytes(),
            generation: 0,
        };
        trust::pin_expected_approval_anchor(&directory, anchor.clone()).unwrap();
        trust::pin_authority(&directory, anchor.clone(), None).unwrap();
        let core = trust::approval_trust(&directory).unwrap();
        let manager = a::inspect_process(std::process::id()).unwrap();
        let spec = a::Spec {
            id: a::new_id(),
            target: manager.clone(),
            current_target: None,
            exec_epoch: 0,
            scope: a::Scope::Tree,
            backend: a::Backend::Gum,
            policy_digest: "72".repeat(32),
            capabilities: Default::default(),
            recovery: None,
        };
        a::create_record(&directory, spec.clone()).unwrap();
        let bootstrap = wire::Bootstrap {
            attachment_id: spec.id.clone(),
            session_id: format!("attach-{}", spec.id),
            token: "t".repeat(64),
            control_endpoint: "unused-control".into(),
            socks_address: "127.0.0.1:18444".into(),
            tls_ca_pem: "-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n".into(),
            observe: false,
            firewall: None,
            sandbox: None,
            host_endpoint: "unused-host".into(),
            host_token: "h".repeat(64),
            scope_tree: true,
            root_pid: manager.pid,
            approval_authority_file: "unused-authority".into(),
            approval_instance_id: anchor.instance_id.clone(),
            initially_owned: false,
            approval_not_before_ms: 0,
            approval_public_key: Some(anchor.public_key),
            approval_inherited_public_key: None,
            approval_root_identity: Some(manager.root_image_identity()),
            approval_core_public_key: Some(core.core_public_key),
            approval_core_pid: core.core_pid,
            approval_core_birth: core.core_birth,
            approval_cli_sha256: manager.executable_sha256.clone(),
            alias_inherited: None,
            external_attachment: true,
            native_dns_mode: wire::NativeDnsMode::PreserveAnswers,
        };
        let now = crate::session::unix_timestamp_ms() - 1000;
        let mut grant = a::Authorization {
            request: a::Request {
                schema_version: 1,
                id: a::new_id(),
                instance_id: anchor.instance_id.clone(),
                created_at_ms: now,
                action: a::Action::Attach { spec: spec.clone() },
            },
            approved_at_ms: now,
            expires_at_ms: now + authority::AUTHORIZATION_LIFETIME_MS,
            nonce: rand::random(),
            executor_sha256: manager.executable_sha256.clone(),
            execution_digest: Some(a::bootstrap_digest(&bootstrap).unwrap()),
            host_binding: Some(bootstrap.approval_binding().unwrap()),
            core_attestation_public_key: Some(core.core_public_key),
            manager_claimant: Some(wire::ManagerClaimant {
                pid: manager.pid,
                birth: manager.birth,
                role_epoch: [3; 32],
                public_key: key.verifying_key().to_bytes(),
            }),
            signature: vec![],
        };
        grant.signature = root
            .sign(&authority::payload(&grant).unwrap())
            .to_bytes()
            .to_vec();
        authority::consume_for_claimant(&directory, &grant, &manager).unwrap();
        a::initialize_root_image(
            &directory,
            &spec,
            &bootstrap.session_id,
            &anchor.instance_id,
            grant.host_binding.as_deref().unwrap(),
        )
        .unwrap();
        let scope = a::operation_scope_for_authorization(
            &grant,
            &bootstrap,
            wire::RootImageState {
                identity: manager.root_image_identity(),
                exec_epoch: 0,
                observed_at_ms: 0,
                head: [0; 32],
            },
        )
        .unwrap();
        let accepted = trust::sign_accepted_operation(
            &directory,
            &wire::AcceptedOperationPayload {
                schema_version: 1,
                challenge: wire::PossessionChallenge {
                    schema_version: 1,
                    scope: scope.clone(),
                    nonce: [4; 32],
                    issued_at_ms: now,
                    expires_at_ms: now + wire::OPERATION_CHALLENGE_LIFETIME_MS,
                },
                accepted_at_ms: now + 1,
            },
        )
        .unwrap();
        a::record_operation_acceptance(&directory, &grant, &accepted).unwrap();
        trust::register_initial_preparation(&directory, &grant, &accepted, &scope).unwrap();
        let execution = Execution {
            spec,
            origin: a::Origin::Attach,
            bootstrap,
            state_directory: directory.join(scope.attachment_id.clone()),
            authorization: grant,
        };
        Self {
            directory,
            manager,
            key,
            execution,
            scope,
            accepted,
            anchor,
        }
    }
    fn proof(&self, step: PreparationStep) -> PreparationProof {
        let value = PreparationPayload {
            schema_version: 1,
            step,
            scope: self.scope.clone(),
            accepted_digest: wire::host_accepted_operation_digest(&self.accepted).unwrap(),
            nonce: rand::random(),
            failure_digest: if step == PreparationStep::AbortBeforeMutation {
                [5; 32]
            } else {
                [0; 32]
            },
        };
        let payload = preparation_bytes(&value).unwrap();
        let signature = self.key.sign(&payload).to_bytes().to_vec();
        PreparationProof { payload, signature }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.directory.parent().unwrap());
    }
}

#[test]
fn never_mutated_abort_is_exact_idempotent_and_blocks_later_activation() {
    let f = Fixture::new();
    let abort = f.proof(PreparationStep::AbortBeforeMutation);
    let revokes = AtomicUsize::new(0);
    assert!(
        trust::require_initial_mutation_gate(&f.directory, &f.execution.authorization).is_err()
    );
    let receipt = trust::apply_preparation(&f.directory, &abort, &f.accepted, || {
        revokes.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap()
    .unwrap();
    save_abort_receipt(&f.directory, &receipt).unwrap();
    assert!(verified_preparation_abort(&f.directory, &f.execution).unwrap());
    let duplicate = trust::apply_preparation(&f.directory, &abort, &f.accepted, || {
        revokes.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap()
    .unwrap();
    assert_eq!(receipt, duplicate);
    assert_eq!(revokes.load(Ordering::SeqCst), 1);
    assert!(trust::apply_preparation(
        &f.directory,
        &f.proof(PreparationStep::BeginMutation),
        &f.accepted,
        || panic!("begin cannot revoke")
    )
    .is_err());
    assert!(
        trust::require_initial_mutation_gate(&f.directory, &f.execution.authorization).is_err()
    );
    let path = receipt_path(&f.directory, &f.execution.spec.id);
    let mut altered = receipt;
    altered.signature[0] ^= 1;
    crate::config_store::save_private_bytes(&path, &serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(verified_preparation_abort(&f.directory, &f.execution).is_err());
}
#[test]
fn mutation_gate_cannot_reset_and_survives_private_successor_transfer() {
    let f = Fixture::new();
    let begin = f.proof(PreparationStep::BeginMutation);
    assert!(
        trust::apply_preparation(&f.directory, &begin, &f.accepted, || panic!(
            "begin cannot revoke"
        ))
        .unwrap()
        .is_none()
    );
    trust::require_initial_mutation_gate(&f.directory, &f.execution.authorization).unwrap();
    trust::register_initial_preparation(
        &f.directory,
        &f.execution.authorization,
        &f.accepted,
        &f.scope,
    )
    .unwrap();
    assert!(trust::apply_preparation(
        &f.directory,
        &f.proof(PreparationStep::AbortBeforeMutation),
        &f.accepted,
        || panic!("post-mutation abort must fail")
    )
    .is_err());
    let child = f.directory.join("successor");
    a::private_directory(&child).unwrap();
    trust::pin_expected_approval_anchor(&child, f.anchor.clone()).unwrap();
    let transfer = trust::export_successor(&f.directory).unwrap();
    trust::import_successor(&child, transfer).unwrap();
    trust::require_initial_mutation_gate(&child, &f.execution.authorization).unwrap();
    assert!(trust::apply_preparation(
        &child,
        &f.proof(PreparationStep::AbortBeforeMutation),
        &f.accepted,
        || panic!("handoff lost native mutation barrier")
    )
    .is_err());
}
#[test]
fn unaccepted_changed_proof_scope_and_superseded_epoch_cannot_abort() {
    let f = Fixture::new();
    let original = f.proof(PreparationStep::AbortBeforeMutation);
    let mut wrong = original.clone();
    wrong.signature[0] ^= 1;
    assert!(
        trust::apply_preparation(&f.directory, &wrong, &f.accepted, || panic!(
            "bad signature"
        ))
        .is_err()
    );
    let mut value: PreparationPayload =
        serde_json::from_slice(&original.payload[PREPARATION_DOMAIN.len()..]).unwrap();
    value.scope.root_image.exec_epoch = 1;
    value.scope.root_image.observed_at_ms = 1;
    value.scope.root_image.head = [7; 32];
    let payload = preparation_bytes(&value).unwrap();
    let wrong = PreparationProof {
        signature: f.key.sign(&payload).to_bytes().to_vec(),
        payload,
    };
    assert!(
        trust::apply_preparation(&f.directory, &wrong, &f.accepted, || panic!(
            "different scope"
        ))
        .is_err()
    );
    let empty = f.directory.join("empty-core");
    a::private_directory(&empty).unwrap();
    assert!(
        trust::apply_preparation(&empty, &original, &f.accepted, || panic!(
            "missing RAM gate"
        ))
        .is_err()
    );
    trust::activate_epoch(&f.directory, &f.execution.authorization).unwrap();
    assert!(
        trust::apply_preparation(&f.directory, &original, &f.accepted, || panic!(
            "new activation epoch"
        ))
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_control_transport_accepts_signed_abort_and_returns_replayable_receipt() {
    use crate::{
        control::{control_request, instance_control_endpoint, run_control_server},
        session::{ConnectionRegistry, ControlRequest, ControlResponse, SessionRegistry},
    };
    let f = Fixture::new();
    let sessions = SessionRegistry::default();
    let service = crate::control::ControlService::new(
        sessions,
        ConnectionRegistry::default(),
        "test-ca".into(),
        crate::audit::AuditWriter::open(None).unwrap(),
        crate::runtime::RuntimeState::new(Arc::new(crate::Config::default())).unwrap(),
        zeroize::Zeroizing::new(vec![0; 32]),
    )
    .with_attachment_directory(f.directory.clone());
    let home = f.directory.parent().unwrap().join("c");
    a::private_directory(&home).unwrap();
    let endpoint = instance_control_endpoint(&home);
    struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let server = Server(tokio::spawn(run_control_server(endpoint.clone(), service)));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if control_request(&endpoint, &ControlRequest::GetStatus)
            .await
            .is_ok()
        {
            break;
        }
        assert!(!server.0.is_finished());
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let proof = f.proof(PreparationStep::AbortBeforeMutation);
    let request = ControlRequest::AttachmentPreparation {
        authorization: f.execution.authorization.clone(),
        bootstrap: f.execution.bootstrap.clone(),
        manager: f.manager.clone(),
        accepted: f.accepted.clone(),
        proof: proof.clone(),
    };
    let send = |request| {
        let endpoint = endpoint.clone();
        async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                control_request(&endpoint, &request),
            )
            .await
            .unwrap()
            .unwrap()
        }
    };
    let first = send(request.clone()).await;
    assert!(
        matches!(first, ControlResponse::AttachmentPreparationAborted { .. }),
        "{first:?}"
    );
    // Drop the ACK object, then repeat the same signed step. No new mutation or
    // approval is allowed, and the already durable receipt is returned again.
    let retry = send(request).await;
    assert!(matches!(
        retry,
        ControlResponse::AttachmentPreparationAborted { .. }
    ));
    assert!(verified_preparation_abort(&f.directory, &f.execution).unwrap());
    let mut wrong = f.execution.authorization.clone();
    wrong.nonce[0] ^= 1;
    let reply = send(ControlRequest::AttachmentPreparation {
        authorization: wrong,
        bootstrap: f.execution.bootstrap.clone(),
        manager: f.manager.clone(),
        accepted: f.accepted.clone(),
        proof,
    })
    .await;
    assert!(matches!(reply, ControlResponse::Error { .. }));
    let reply = send(ControlRequest::AttachmentPreparation {
        authorization: f.execution.authorization.clone(),
        bootstrap: f.execution.bootstrap.clone(),
        manager: f.manager.clone(),
        accepted: f.accepted.clone(),
        proof: f.proof(PreparationStep::BeginMutation),
    })
    .await;
    assert!(matches!(reply, ControlResponse::Error { .. }));
}

#[test]
fn cleanup_roster_proof_preserves_certificate_and_manager_possession_and_roster_kind() {
    use crate::attachments::startup_cleanup as cleanup;
    let f = Fixture::new();
    let bindings = vec![a::HostBootstrapBinding {
        identity: f.manager.clone(),
        bootstrap: f.execution.bootstrap.clone(),
    }];
    let mut grant = f.execution.authorization.clone();
    grant.request.id = a::new_id();
    grant.nonce = rand::random();
    grant.request.action = a::Action::Detach {
        exec_epoch: 0,
        attachment_id: f.execution.spec.id.clone(),
        target: f.manager.clone(),
        policy_digest: f.execution.spec.policy_digest.clone(),
        recovery: None,
    };
    let root = SigningKey::from_bytes(&[61; 32]);
    grant.signature = root
        .sign(&authority::payload(&grant).unwrap())
        .to_bytes()
        .to_vec();
    let scope = a::operation_scope_for_authorization(
        &grant,
        &f.execution.bootstrap,
        f.scope.root_image.clone(),
    )
    .unwrap();
    let proof_for = |proof_scope: &OperationScope,
                     hosts: &[a::HostBootstrapBinding],
                     locators: &[a::HostBootstrapBinding]| {
        let now = crate::session::unix_timestamp_ms() - 100;
        let accepted = trust::sign_accepted_operation(
            &f.directory,
            &wire::AcceptedOperationPayload {
                schema_version: 1,
                challenge: wire::PossessionChallenge {
                    schema_version: 1,
                    scope: proof_scope.clone(),
                    nonce: [73; 32],
                    issued_at_ms: now,
                    expires_at_ms: now + wire::OPERATION_CHALLENGE_LIFETIME_MS,
                },
                accepted_at_ms: now + 1,
            },
        )
        .unwrap();
        let payload = cleanup::unstarted_bytes(&cleanup::UnstartedInjectionPayload {
            scope: proof_scope.clone(),
            bindings_digest: cleanup::bindings_digest(hosts, locators).unwrap(),
            accepted_digest: wire::host_accepted_operation_digest(&accepted).unwrap(),
        })
        .unwrap();
        a::UnstartedInjectionProof {
            signature: f.key.sign(&payload).to_bytes().to_vec(),
            payload,
            accepted,
        }
    };
    let mut proof = proof_for(&scope, &[], &bindings);
    assert!(
        cleanup::verify_unstarted(&proof, &grant, &[], &bindings, scope.core_public_key).is_ok()
    );
    assert!(
        cleanup::verify_unstarted(&proof, &grant, &bindings, &[], scope.core_public_key).is_err(),
        "changing an unstarted locator into a real Host needs a new exact proof"
    );
    let mut different = bindings.clone();
    different[0].bootstrap.host_token.push('x');
    assert!(
        cleanup::verify_unstarted(&proof, &grant, &[], &different, scope.core_public_key).is_err()
    );

    let mut derivative = bindings.clone();
    derivative[0].bootstrap.host_endpoint = "member-specific-endpoint".into();
    derivative[0].bootstrap.host_token = "m".repeat(64);
    derivative[0].bootstrap.initially_owned = true;
    derivative[0].bootstrap.approval_not_before_ms = 17;
    derivative[0].bootstrap.approval_inherited_public_key = Some([18; 32]);
    derivative[0].bootstrap.alias_inherited = Some(wire::AliasInheritance {
        metadata_only: true,
        public_key: [19; 32],
        sequence: 20,
        head: [21; 32],
        endorsement_approved_at_ms: 22,
        endorsement_nonce: Some([23; 32]),
    });
    assert_eq!(
        derivative[0].bootstrap.approval_binding().unwrap(),
        bindings[0].bootstrap.approval_binding().unwrap(),
        "transport derivatives must retain the immutable Host binding"
    );
    assert_ne!(
        a::bootstrap_digest(&derivative[0].bootstrap).unwrap(),
        a::bootstrap_digest(&bindings[0].bootstrap).unwrap(),
        "transport derivatives must not impersonate the manager's full bootstrap"
    );
    assert!(
        a::operation_scope_for_authorization(
            &grant,
            &derivative[0].bootstrap,
            scope.root_image.clone()
        )
        .unwrap_err()
        .contains("execution_digest"),
        "ordinary manager scope must retain the full execution digest check"
    );
    let derivative_proof = proof_for(&scope, &[], &derivative);
    assert!(
        cleanup::verify_unstarted(
            &derivative_proof,
            &grant,
            &[],
            &derivative,
            scope.core_public_key
        )
        .is_ok(),
        "startup cleanup must accept only the authenticated transport derivative"
    );

    for change in 0..6 {
        let mut changed = derivative.clone();
        let bootstrap = &mut changed[0].bootstrap;
        match change {
            0 => bootstrap.approval_instance_id.push('x'),
            1 => bootstrap.attachment_id.push('x'),
            2 => bootstrap.session_id.push('x'),
            3 => bootstrap.token.push('x'),
            4 => bootstrap.root_pid = bootstrap.root_pid.checked_add(1).unwrap(),
            _ => bootstrap.observe = !bootstrap.observe,
        }
        let changed_proof = proof_for(&scope, &[], &changed);
        assert!(
            cleanup::verify_unstarted(&changed_proof, &grant, &[], &changed, scope.core_public_key)
                .is_err(),
            "startup-cleanup locator accepted immutable bootstrap change {change}"
        );
    }
    let mut changed_root = scope.clone();
    changed_root.root_image.identity.executable_sha256 = "99".repeat(32);
    let changed_root_proof = proof_for(&changed_root, &[], &derivative);
    assert!(cleanup::verify_unstarted(
        &changed_root_proof,
        &grant,
        &[],
        &derivative,
        scope.core_public_key
    )
    .is_err());
    let mut changed_epoch = scope.clone();
    changed_epoch.root_image.exec_epoch = 1;
    changed_epoch.root_image.observed_at_ms = 1;
    changed_epoch.root_image.head = [24; 32];
    let changed_epoch_proof = proof_for(&changed_epoch, &[], &derivative);
    assert!(cleanup::verify_unstarted(
        &changed_epoch_proof,
        &grant,
        &[],
        &derivative,
        scope.core_public_key
    )
    .is_err());
    assert!(cleanup::verify_unstarted(
        &proof,
        &f.execution.authorization,
        &[],
        &bindings,
        scope.core_public_key
    )
    .is_err());
    assert!(cleanup::verify_unstarted(&proof, &grant, &[], &bindings, [1; 32]).is_err());
    proof.signature[0] ^= 1;
    assert!(
        cleanup::verify_unstarted(&proof, &grant, &[], &bindings, scope.core_public_key).is_err()
    );
    proof.signature[0] ^= 1;
    proof.accepted.signature[0] ^= 1;
    assert!(
        cleanup::verify_unstarted(&proof, &grant, &[], &bindings, scope.core_public_key).is_err()
    );
    assert!(cleanup::bindings_digest(&[], &[]).is_err());
    different[0].bootstrap.tls_ca_pem = "x".repeat(1024 * 1024);
    assert!(cleanup::bindings_digest(&[], &different).is_err());
}
