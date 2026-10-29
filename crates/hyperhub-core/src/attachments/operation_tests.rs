use super::*;
use hyperhub_runtime::attachment::{
    verify_accepted_operation, OperationAction, RootImageIdentity, RootImageState,
};

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn actual_manager_profile_resolution_uses_ram_without_querying_its_own_listener() {
    use crate::attachments as a;
    let manager = a::inspect_process(std::process::id()).unwrap();
    for origin in [a::Origin::Attach, a::Origin::Run] {
        let id = a::new_id();
        let session_id = format!("attach-{id}");
        let bootstrap:hyperhub_runtime::attachment::Bootstrap=serde_json::from_value(serde_json::json!({
            "attachment_id":id,"session_id":session_id,"token":"t".repeat(64),"control_endpoint":"unused","socks_address":"127.0.0.1:1",
            "tls_ca_pem":"-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n","observe":false,"firewall":null,"sandbox":null,"host_endpoint":"unused",
            "host_token":"h".repeat(64),"scope_tree":true,"root_pid":manager.pid,"approval_authority_file":"unused","approval_instance_id":"unit-instance",
            "initially_owned":origin==a::Origin::Run,"external_attachment":origin==a::Origin::Attach,"native_dns_mode":origin.native_dns_mode(),"approval_core_public_key":null,"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":"ab".repeat(32)
        })).unwrap();
        let spec = a::Spec {
            id: id.clone(),
            target: manager.clone(),
            current_target: None,
            exec_epoch: 0,
            scope: a::Scope::Tree,
            backend: a::Backend::Ptrace,
            policy_digest: "cd".repeat(32),
            capabilities: Default::default(),
            recovery: None,
        };
        // Only a protocol resolver fixture. No executor or target is started.
        let execution = a::Execution {
            spec: spec.clone(),
            origin,
            bootstrap: bootstrap.clone(),
            state_directory: std::env::temp_dir().join(&id),
            authorization: a::Authorization {
                request: a::Request {
                    schema_version: 1,
                    id: a::new_id(),
                    instance_id: "unit-instance".into(),
                    created_at_ms: 0,
                    action: a::Action::Attach { spec: spec.clone() },
                },
                approved_at_ms: 0,
                expires_at_ms: 0,
                nonce: [0; 32],
                executor_sha256: manager.executable_sha256.clone(),
                execution_digest: None,
                host_binding: None,
                core_attestation_public_key: None,
                manager_claimant: None,
                signature: vec![],
            },
        };
        a::register_manager_execution(&execution).unwrap();
        let mut record = a::Record {
            spec,
            current_target: None,
            exec_epoch: 0,
            host_binding: Some(bootstrap.approval_binding().unwrap()),
            origin,
            session_id,
            phase: a::Phase::Active,
            members: vec![manager.clone()],
            manager: Some(manager.clone()),
            manager_endpoint: Some("must-not-query-self-endpoint".into()),
            compatibility_reasons: vec![],
            error: None,
            updated_at_ms: 0,
        };
        let profile = a::manager_profile_for_record(&record).unwrap();
        assert_eq!(profile.origin, origin);
        assert_eq!(profile.native_dns_mode, origin.native_dns_mode());
        // The display phase can still be Resident after Core accepted Attach.
        // Configuration admission must use the manager's RAM state instead.
        let root = std::env::temp_dir().join(format!("hh-manager-admission-{}", a::new_id()));
        let directory = root.join("runtime").join("attachments");
        let state = a::attachment_directory(&directory, &record.spec.id).unwrap();
        record.phase = a::Phase::DetachedResident;
        crate::config_store::save_private_bytes(
            &state.join("record.json"),
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let mut named = crate::config::Config::default();
        named.rules.push(serde_json::from_value(serde_json::json!({"id":"hostname-rule","action":"deny","endpoints":[{"target":"example.test","port":443}]})).unwrap());
        named.ensure_item_uuids();
        let config_path = root.join("config.bin");
        let mut descriptor = crate::config_store::new_descriptor();
        descriptor.memory_kib = 8 * 1024;
        descriptor.iterations = 1;
        let keyring =
            crate::config_store::ConfigKeyring::derive(b"private-admission-password", descriptor)
                .unwrap();
        crate::config_store::save_encrypted_with_keyring(
            &config_path,
            &crate::config::Config::default(),
            &keyring,
        )
        .unwrap();
        let disk_before = std::fs::read(&config_path).unwrap();
        assert!(
            a::manager_policy_admission_for_record(&record)
                .unwrap()
                .policy_required
        );
        assert_eq!(
            a::configuration_guard(&directory, &named).is_err(),
            origin == a::Origin::Attach
        );
        if origin == a::Origin::Attach {
            assert!(
                crate::config_persistence::offline_configuration_guard(&config_path, &named)
                    .is_err()
            );
            assert_eq!(
                std::fs::read(&config_path).unwrap(),
                disk_before,
                "rejected resident admission must leave ciphertext unchanged"
            );
        }
        set_manager_policy_required(&record.spec.id, false).unwrap();
        a::register_manager_execution(&execution).unwrap();
        assert!(
            !a::manager_policy_admission_for_record(&record)
                .unwrap()
                .policy_required,
            "refreshing immutable execution metadata must retain a proven detach barrier"
        );
        assert!(a::configuration_guard(&directory, &named).is_ok());
        let offline =
            crate::config_persistence::offline_configuration_guard(&config_path, &named).unwrap();
        crate::config_store::save_encrypted_with_keyring_guarded(
            &config_path,
            &named,
            &keyring,
            &offline,
        )
        .unwrap();
        drop(offline);
        assert_eq!(
            crate::config_store::load_encrypted_with_keyring(&config_path, &keyring)
                .unwrap()
                .config
                .rules
                .len(),
            1
        );
        set_manager_policy_required(&record.spec.id, true).unwrap();
        assert_eq!(
            a::configuration_guard(&directory, &named).is_err(),
            origin == a::Origin::Attach
        );
        let held = a::configuration_guard(&directory, &crate::config::Config::default()).unwrap();
        assert!(
            a::OperationGuard::acquire(&directory).is_err(),
            "configuration persistence must exclude concurrent approval admission"
        );
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
        record.phase = a::Phase::Active;
        record.origin = if origin == a::Origin::Attach {
            a::Origin::Run
        } else {
            a::Origin::Attach
        };
        assert!(a::manager_profile_for_record(&record)
            .unwrap_err()
            .contains("local binding"));
        record.origin = origin;
        record.spec.id = a::new_id();
        assert!(
            a::manager_profile_for_record(&record)
                .unwrap_err()
                .contains("local RAM lookup"),
            "missing RAM must not fall back to socket or file"
        );
        record.manager.as_mut().unwrap().birth += 1;
        assert!(a::manager_profile_for_record(&record)
            .unwrap_err()
            .contains("manager identity"));
    }
}

fn scope(key: &ManagerOperationKey) -> OperationScope {
    OperationScope {
        action: OperationAction::Detach,
        administrator_digest: [1; 32],
        instance_id: "operation-test-instance".into(),
        attachment_id: "attachment".into(),
        session_id: "session".into(),
        credential_digest: [2; 32],
        host_binding: "ab".repeat(32),
        root_image: RootImageState {
            identity: RootImageIdentity {
                pid: 3,
                birth: 4,
                executable_sha256: "cd".repeat(32),
            },
            exec_epoch: 0,
            observed_at_ms: 0,
            head: [0; 32],
        },
        claimant: key.claimant().unwrap(),
        core_public_key: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
    }
}
#[test]
#[cfg(any(windows, target_os = "linux"))]
fn memory_key_rejects_other_creator_incarnations_and_role_epochs() {
    let mut key = ManagerOperationKey::generate().unwrap();
    let original = key.claimant().unwrap();
    let book = OperationChallengeBook::default();
    let challenge = book.begin_verified_scope(scope(&key), 1_000).unwrap();
    key.prove(&challenge, 1_001).unwrap();
    key.claimant.pid = original.pid.checked_add(1).unwrap();
    assert!(key.claimant().is_err());
    assert!(key.prove(&challenge, 1_001).is_err());
    key.claimant = original.clone();
    key.claimant.birth += 1;
    assert!(key.claimant().is_err());
    assert!(key.prove(&challenge, 1_001).is_err());
    key.claimant = original;
    let mut changed = challenge;
    changed.scope.claimant.role_epoch[0] ^= 1;
    assert!(key.prove(&changed, 1_001).is_err());
    assert_eq!(
        format!("{key:?}"),
        "ManagerOperationKey { key: \"<redacted>\" }"
    );
}
#[test]
#[cfg(any(windows, target_os = "linux"))]
fn fresh_possession_is_one_use_and_wrong_peer_burns_the_challenge() {
    let key = ManagerOperationKey::generate().unwrap();
    let scope = scope(&key);
    let book = OperationChallengeBook::default();
    let challenge = book.begin_verified_scope(scope.clone(), 1_000).unwrap();
    assert!(book.begin_verified_scope(scope.clone(), 1_000).is_err());
    let proof = key.prove(&challenge, 1_001).unwrap();
    assert!(book
        .accept_verified_scope(
            &challenge.nonce,
            &scope,
            &proof,
            scope.claimant.pid + 1,
            scope.claimant.birth,
            1_001
        )
        .is_err());
    assert!(book
        .accept_verified_scope(
            &challenge.nonce,
            &scope,
            &proof,
            scope.claimant.pid,
            scope.claimant.birth,
            1_001
        )
        .is_err());
    let fresh = book.begin_verified_scope(scope.clone(), 1_002).unwrap();
    assert_ne!(fresh.nonce, challenge.nonce);
    let proof = key.prove(&fresh, 1_003).unwrap();
    book.accept_verified_scope(
        &fresh.nonce,
        &scope,
        &proof,
        scope.claimant.pid,
        scope.claimant.birth,
        1_003,
    )
    .unwrap();
    assert!(book
        .accept_verified_scope(
            &fresh.nonce,
            &scope,
            &proof,
            scope.claimant.pid,
            scope.claimant.birth,
            1_003
        )
        .is_err());
    assert!(book.begin_verified_scope(scope, 1_004).is_err());
}
#[test]
#[cfg(any(windows, target_os = "linux"))]
fn malformed_stale_or_rebound_proofs_cannot_be_reused() {
    let key = ManagerOperationKey::generate().unwrap();
    for mode in 0..4 {
        let book = OperationChallengeBook::default();
        let expected = scope(&key);
        let challenge = book.begin_verified_scope(expected.clone(), 1_000).unwrap();
        let mut proof = key.prove(&challenge, 1_001).unwrap();
        let mut supplied = expected.clone();
        let mut now = 1_001;
        match mode {
            0 => proof.signature[0] ^= 1,
            1 => proof.payload.clear(),
            2 => supplied.root_image.identity.executable_sha256 = "ef".repeat(32),
            _ => now = challenge.expires_at_ms,
        }
        assert!(book
            .accept_verified_scope(
                &challenge.nonce,
                &supplied,
                &proof,
                expected.claimant.pid,
                expected.claimant.birth,
                now
            )
            .is_err());
        let proof = key.prove(&challenge, 1_001).unwrap();
        assert!(book
            .accept_verified_scope(
                &challenge.nonce,
                &expected,
                &proof,
                expected.claimant.pid,
                expected.claimant.birth,
                1_001
            )
            .is_err());
    }
}
#[test]
#[cfg(any(windows, target_os = "linux"))]
fn pending_challenges_are_bounded_expire_and_never_wrap_time() {
    let key = ManagerOperationKey::generate().unwrap();
    let book = OperationChallengeBook::default();
    for index in 0..MAX_PENDING_OPERATION_CHALLENGES {
        let mut value = scope(&key);
        value.administrator_digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
        book.begin_verified_scope(value, 1_000).unwrap();
    }
    let mut value = scope(&key);
    value.administrator_digest = [99; 32];
    assert!(book.begin_verified_scope(value.clone(), 1_000).is_err());
    book.begin_verified_scope(value.clone(), 1_000 + OPERATION_CHALLENGE_LIFETIME_MS)
        .unwrap();
    assert!(book.begin_verified_scope(value, u64::MAX).is_err());
}
#[test]
#[cfg(any(windows, target_os = "linux"))]
fn owning_enrolled_core_attests_exact_accepted_scope_only() {
    let directory =
        std::env::temp_dir().join(format!("hh-operation-{}", crate::attachments::new_id()));
    crate::attachments::private_directory(&directory).unwrap();
    let key = ManagerOperationKey::generate().unwrap();
    let mut scope = scope(&key);
    scope.core_public_key = crate::attachments::approval_trust(&directory)
        .unwrap()
        .core_public_key;
    let authority = crate::attachments::ApprovalAuthority {
        instance_id: scope.instance_id.clone(),
        config_id: [6; 16],
        public_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        generation: 0,
    };
    let book = OperationChallengeBook::default();
    let challenge = book.begin_verified_scope(scope.clone(), 1_000).unwrap();
    let proof = key.prove(&challenge, 1_001).unwrap();
    let accepted = book
        .accept_verified_scope(
            &challenge.nonce,
            &scope,
            &proof,
            scope.claimant.pid,
            scope.claimant.birth,
            1_001,
        )
        .unwrap();
    assert!(crate::attachments::trust::sign_accepted_operation(&directory, &accepted).is_err());
    crate::attachments::trust::pin_authority(&directory, authority, None).unwrap();
    let certificate =
        crate::attachments::trust::sign_accepted_operation(&directory, &accepted).unwrap();
    verify_accepted_operation(&scope, &certificate, 100_000).unwrap();
    let mut another = scope.clone();
    another.administrator_digest = [11; 32];
    let challenge = book.begin_verified_scope(another.clone(), 1_002).unwrap();
    let proof = key.prove(&challenge, 1_003).unwrap();
    let certificate = book
        .accept_and_attest_verified_scope(
            &directory,
            &challenge.nonce,
            &another,
            &proof,
            another.claimant.pid,
            another.claimant.birth,
            1_003,
        )
        .unwrap();
    verify_accepted_operation(&another, &certificate, 100_000).unwrap();
    let mut wrong = accepted.clone();
    wrong.challenge.scope.core_public_key =
        SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes();
    assert!(crate::attachments::trust::sign_accepted_operation(&directory, &wrong).is_err());
    wrong = accepted;
    wrong.challenge.scope.instance_id = "another-instance".into();
    assert!(crate::attachments::trust::sign_accepted_operation(&directory, &wrong).is_err());
    assert!(!directory.join("key").exists());
    assert_eq!(
        std::fs::read_dir(&directory).unwrap().count(),
        0,
        "operation primitives wrote private material"
    );
    std::fs::remove_dir_all(directory).unwrap();
}
