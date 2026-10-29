use super::*;
use crate::config_store::{self, ConfigKeyring, KdfDescriptor};
use std::path::PathBuf;
struct Fixture {
    root: PathBuf,
    config: PathBuf,
    directory: PathBuf,
    descriptor: KdfDescriptor,
    password: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("hh-attachment-{}", new_id()));
        private_directory(&root).unwrap();
        let config = root.join("config.bin");
        let directory = root.join("runtime").join("attachments");
        let mut descriptor = config_store::new_descriptor();
        descriptor.memory_kib = 8 * 1024;
        descriptor.iterations = 1;
        descriptor.lanes = 1;
        let password = b"dummy-administrator-password".to_vec();
        config_store::save_encrypted_with_descriptor(
            &config,
            &crate::config::Config::default(),
            &password,
            &descriptor,
        )
        .unwrap();
        Self {
            root,
            config,
            directory,
            descriptor,
            password,
        }
    }
    fn request(&self) -> Request {
        Request {
            schema_version: 1,
            id: new_id(),
            instance_id: instance_id(&self.config, &self.descriptor),
            created_at_ms: 1,
            action: Action::Attach {
                spec: Spec {
                    exec_epoch: 0,
                    current_target: None,
                    recovery: None,
                    capabilities: Default::default(),
                    id: new_id(),
                    target: ProcessIdentity {
                        pid: 42,
                        birth: 9,
                        executable: "test-target".into(),
                        executable_sha256: "ab".repeat(32),
                        owner: "test-owner".into(),
                    },
                    scope: Scope::Tree,
                    backend: Backend::Ptrace,
                    policy_digest: "cd".repeat(32),
                },
            },
        }
    }
    fn grant(&self) -> Authorization {
        authorize(
            &self.directory,
            &self.config,
            &self.password,
            &self.descriptor,
            self.request(),
            crate::session::unix_timestamp_ms(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn signature_binds_target_policy_scope_and_expiry() {
    let f = Fixture::new();
    let g = f.grant();
    let now = g.approved_at_ms;
    assert!(verify_authorization_at(&f.directory, &g, now).is_ok());
    for mutation in 0..5 {
        let mut bad = g.clone();
        if let Action::Attach { spec } = &mut bad.request.action {
            match mutation {
                0 => spec.target.pid += 1,
                1 => spec.scope = Scope::Process,
                2 => spec.policy_digest = "ef".repeat(32),
                3 => spec.target.executable_sha256 = "12".repeat(32),
                _ => spec.capabilities.supported.push("forged-capability".into()),
            }
        }
        assert!(verify_authorization_at(&f.directory, &bad, now).is_err());
    }
    assert!(verify_authorization_at(&f.directory, &g, g.expires_at_ms).is_err());
    assert!(verify_authorization_at(&f.directory, &g, now - 1).is_err());
    let mut bad = g.clone();
    bad.expires_at_ms += 1;
    assert!(verify_authorization_at(&f.directory, &bad, now).is_err());
}
#[test]
fn runtime_envelope_master_cannot_replace_password_signing_authority() {
    let f = Fixture::new();
    let g = f.grant();
    let cached = ConfigKeyring::derive(&f.password, f.descriptor.clone()).unwrap();
    let master = cached.runtime_master();
    let wrong = authorize(
        &f.directory,
        &f.config,
        &master,
        &f.descriptor,
        f.request(),
        g.approved_at_ms,
    );
    assert!(wrong.is_err());
    assert!(verify_authorization_at(&f.directory, &g, g.approved_at_ms).is_ok());
    assert!(authorize(
        &f.directory,
        &f.config,
        b"wrong password",
        &f.descriptor,
        f.request(),
        g.approved_at_ms
    )
    .is_err());
}
#[test]
fn authorization_is_single_use_and_consumption_binds_os_claimant() {
    let f = Fixture::new();
    let g = f.grant();
    consume_authorization(&f.directory, &g).unwrap();
    assert!(consume_authorization(&f.directory, &g).is_err());
    assert!(authorization_consumed_by(
        &f.directory,
        &g,
        std::process::id()
    ));
    assert!(!authorization_consumed_by(&f.directory, &g, u32::MAX));
}
#[test]
fn administrator_key_rotation_invalidates_old_grants_but_preserves_consumed_ledger() {
    let f = Fixture::new();
    let old = f.grant();
    consume_authorization(&f.directory, &old).unwrap();
    let password = b"new-dummy-administrator-password";
    let mut descriptor = f.descriptor.clone();
    descriptor.salt = rand::random();
    descriptor.config_id = rand::random();
    assert_eq!(
        instance_id(&f.config, &f.descriptor),
        instance_id(&f.config, &descriptor)
    );
    config_store::save_encrypted_with_descriptor(
        &f.config,
        &crate::config::Config::default(),
        password,
        &descriptor,
    )
    .unwrap();
    let mut request = f.request();
    request.instance_id = instance_id(&f.config, &descriptor);
    let new = authorize(
        &f.directory,
        &f.config,
        password,
        &descriptor,
        request,
        crate::session::unix_timestamp_ms(),
    )
    .unwrap();
    assert!(verify_authorization(&f.directory, &new).is_ok());
    assert!(verify_authorization(&f.directory, &old).is_err());
    assert!(authorization_consumed_by(
        &f.directory,
        &old,
        std::process::id()
    ));
}
#[test]
fn proposal_ids_cannot_escape_private_state_and_different_requests_do_not_overwrite() {
    let f = Fixture::new();
    let request = f.request();
    save_request(&f.directory, &request).unwrap();
    assert!(save_request(&f.directory, &request).is_err());
    assert_eq!(load_request(&f.directory, &request.id).unwrap(), request);
    assert!(request_path(&f.directory, "../config").is_err());
    assert_eq!(requests(&f.directory).unwrap().len(), 1);
}
#[test]
#[cfg(unix)]
fn proposal_reader_rejects_symlink_and_world_readable_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = Fixture::new();
    let request = f.request();
    save_request(&f.directory, &request).unwrap();
    let path = request_path(&f.directory, &request.id).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_request(&f.directory, &request.id).is_err());
    std::fs::remove_file(&path).unwrap();
    symlink(&f.config, &path).unwrap();
    assert!(load_request(&f.directory, &request.id).is_err());
}

#[test]
fn approval_lock_prevents_concurrent_creation_and_releases_without_stale_owner_files() {
    let f = Fixture::new();
    let first = OperationGuard::acquire(&f.directory).unwrap();
    assert!(OperationGuard::acquire(&f.directory).is_err());
    drop(first);
    assert!(OperationGuard::acquire(&f.directory).is_ok());
}

#[test]
fn activation_debug_does_not_expose_the_session_credential() {
    let f = Fixture::new();
    let authorization = f.grant();
    let member = authorization.request.action.target().clone();
    let request = crate::session::ControlRequest::ActivateAttachment {
        authorization,
        session_id: "test-session".into(),
        token: "dummy-session-secret-never-print".to_owned().into(),
        manager: member.clone(),
        members: vec![member],
        hosts: Vec::new(),
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains("dummy-session-secret-never-print"));
    assert!(debug.contains("<redacted>"));
}
#[test]
fn dead_manager_is_reported_as_lost_enforcement_without_falsely_claiming_unload() {
    let f = Fixture::new();
    let Action::Attach { spec } = f.request().action else {
        unreachable!()
    };
    let record = create_record(&f.directory, spec).unwrap();
    let directory = attachment_directory(&f.directory, &record.spec.id).unwrap();
    let manager = ProcessIdentity {
        pid: u32::MAX,
        birth: 1,
        executable: "test-manager".into(),
        executable_sha256: "ab".repeat(32),
        owner: "test-owner".into(),
    };
    update_record(
        &directory,
        &Outcome {
            phase: Phase::Active,
            members: vec![record.spec.target],
            compatibility_reasons: vec![],
            manager: Some(manager),
            manager_endpoint: Some("private-test-endpoint".into()),
        },
    )
    .unwrap();
    let records = records(&f.directory).unwrap();
    assert_eq!(records[0].phase, Phase::Degraded);
    assert!(records[0]
        .compatibility_reasons
        .iter()
        .any(|r| r == "ptrace_enforcement_lost"));
}
#[test]
fn root_exit_is_not_used_to_infer_that_a_live_managers_descendants_have_exited() {
    let f = Fixture::new();
    let Action::Attach { spec } = f.request().action else {
        unreachable!()
    };
    let record = create_record(&f.directory, spec).unwrap();
    let directory = attachment_directory(&f.directory, &record.spec.id).unwrap();
    let manager = ProcessIdentity {
        pid: std::process::id(),
        birth: crate::session::process_start_time(std::process::id()).unwrap(),
        executable: "test-manager".into(),
        executable_sha256: "ab".repeat(32),
        owner: "test-owner".into(),
    };
    update_record(
        &directory,
        &Outcome {
            phase: Phase::Active,
            members: vec![],
            compatibility_reasons: vec![],
            manager: Some(manager),
            manager_endpoint: Some("private-test-endpoint".into()),
        },
    )
    .unwrap();
    assert_eq!(records(&f.directory).unwrap()[0].phase, Phase::Active);
}

#[test]
fn authorized_execution_binds_bootstrap_and_manager_image_and_rejects_implicit_run_source() {
    let f = Fixture::new();
    let request = f.request();
    let Action::Attach { spec } = &request.action else {
        unreachable!()
    };
    let bootstrap = hyperhub_runtime::attachment::Bootstrap {
        external_attachment: true,
        native_dns_mode: hyperhub_runtime::attachment::NativeDnsMode::PreserveAnswers,
        attachment_id: spec.id.clone(),
        session_id: format!("attach-{}", spec.id),
        token: "dummy-session-token-aaaaaaaaaaaaaaaaaaaaaaaa".into(),
        control_endpoint: "private-test-control".into(),
        socks_address: "127.0.0.1:18444".into(),
        tls_ca_pem: "-----BEGIN CERTIFICATE-----\ndummy-fixture\n-----END CERTIFICATE-----\n"
            .into(),
        observe: false,
        firewall: None,
        sandbox: None,
        host_endpoint: "private-test-host".into(),
        host_token: "dummy-host-token-bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        scope_tree: true,
        root_pid: spec.target.pid,
        approval_authority_file: f.directory.join("authority.json").display().to_string(),
        approval_instance_id: request.instance_id.clone(),
        initially_owned: false,
        approval_not_before_ms: 0,
        approval_public_key: None,
        approval_inherited_public_key: None,
        alias_inherited: None,
        approval_root_identity: Some(spec.target.root_image_identity()),
        approval_core_public_key: None,
        approval_core_pid: std::process::id(),
        approval_core_birth: process_birth(std::process::id()).unwrap(),
        approval_cli_sha256: executor_digest().unwrap(),
    };
    let authorization = authorize_bound(
        &f.directory,
        &f.config,
        &f.password,
        &f.descriptor,
        request.clone(),
        crate::session::unix_timestamp_ms(),
        Some(bootstrap_digest(&bootstrap).unwrap()),
        executor_digest().unwrap(),
        Some(bootstrap.approval_binding().unwrap()),
    )
    .unwrap();
    let execution = Execution {
        spec: spec.clone(),
        origin: Origin::Attach,
        bootstrap,
        state_directory: f.directory.join(&spec.id),
        authorization,
    };
    verify_execution(&f.directory, &execution).unwrap();
    for mutation in 0..5 {
        let mut bad = execution.clone();
        match mutation {
            0 => bad.bootstrap.control_endpoint = "attacker-control".into(),
            1 => bad.bootstrap.observe = true,
            2 => bad.bootstrap.socks_address = "127.0.0.1:9999".into(),
            _ => bad.bootstrap.host_token = "replacement-host-secret-cccccccccccccc".into(),
        };
        assert!(verify_execution(&f.directory, &bad).is_err());
    }
    let mut bad = execution.clone();
    bad.authorization.executor_sha256 = "12".repeat(32);
    assert!(verify_execution(&f.directory, &bad).is_err());
    let mut bad = execution;
    bad.origin = Origin::Run;
    assert!(verify_execution(&f.directory, &bad).is_err());
}

#[test]
fn config_generation_save_immediately_revokes_old_verifier_without_erasing_audit() {
    let f = Fixture::new();
    let old = f.grant();
    consume_authorization(&f.directory, &old).unwrap();
    // Normal same-key edits retain the verifier and approved operations.
    config_store::save_encrypted_with_descriptor(
        &f.config,
        &crate::config::Config::default(),
        &f.password,
        &f.descriptor,
    )
    .unwrap();
    assert!(verify_signature(&f.directory, &old).is_ok());
    let mut next = f.descriptor.clone();
    next.config_id[0] ^= 1;
    next.salt[0] ^= 1;
    config_store::save_encrypted_with_descriptor(
        &f.config,
        &crate::config::Config::default(),
        b"new-administrator-password",
        &next,
    )
    .unwrap();
    assert!(!f.directory.join("authority.json").exists());
    assert!(verify_signature(&f.directory, &old).is_err());
    assert!(authorization_consumed_by(
        &f.directory,
        &old,
        std::process::id()
    ));
    let mut request = f.request();
    request.instance_id = instance_id(&f.config, &next);
    let new = authorize(
        &f.directory,
        &f.config,
        b"new-administrator-password",
        &next,
        request,
        crate::session::unix_timestamp_ms(),
    )
    .unwrap();
    assert!(verify_signature(&f.directory, &new).is_ok());
    assert!(verify_signature(&f.directory, &old).is_err());
}
#[test]
fn password_change_with_reused_descriptor_also_revokes_old_verifier() {
    let f = Fixture::new();
    let old = f.grant();
    config_store::save_encrypted_with_descriptor(
        &f.config,
        &crate::config::Config::default(),
        b"another-password",
        &f.descriptor,
    )
    .unwrap();
    assert!(verify_signature(&f.directory, &old).is_err());
    assert!(!f.directory.join("authority.json").exists());
}

#[test]
fn retired_runtime_envelopes_remain_recoverable_across_password_generations() {
    let f = Fixture::new();
    let Action::Attach { spec } = f.request().action else {
        unreachable!()
    };
    let record = create_record(&f.directory, spec).unwrap();
    let directory = attachment_directory(&f.directory, &record.spec.id).unwrap();
    let original = ConfigKeyring::derive(&f.password, f.descriptor.clone()).unwrap();
    let fixture = serde_json::json!({"broker_token":"dummy-backend-only-secret","members":[42]});
    let digest = save_recovery_context(&directory, &fixture, &original).unwrap();
    let mut second = f.descriptor.clone();
    second.config_id[0] ^= 1;
    second.salt[0] ^= 1;
    prepare_runtime_key_rotation(&f.config, &f.password, b"second-password", &second).unwrap();
    // Staging a new generation cannot make the current generation unreadable.
    assert_eq!(
        load_recovery_context::<serde_json::Value>(&directory, &original)
            .unwrap()
            .0,
        fixture
    );
    config_store::save_encrypted_with_descriptor(
        &f.config,
        &crate::config::Config::default(),
        b"second-password",
        &second,
    )
    .unwrap();
    let second_key = ConfigKeyring::derive(b"second-password", second.clone()).unwrap();
    let journal_id: String = second
        .config_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let journal = f.directory.join(format!("runtime-keys-{journal_id}.bin"));
    let before = std::fs::read(&journal).unwrap();
    assert!(prepare_runtime_key_rotation(
        &f.config,
        b"second-password",
        b"reused-generation-password",
        &second
    )
    .is_err());
    assert_eq!(
        std::fs::read(&journal).unwrap(),
        before,
        "rejected same-id rotation overwrote the current readable journal"
    );
    let restored = load_recovery_context::<serde_json::Value>(&directory, &second_key).unwrap();
    assert_eq!(restored, (fixture.clone(), digest.clone()));
    let mut third = second.clone();
    third.config_id[0] ^= 2;
    third.salt[0] ^= 2;
    prepare_runtime_key_rotation(&f.config, b"second-password", b"third-password", &third).unwrap();
    config_store::save_encrypted_with_descriptor(
        &f.config,
        &crate::config::Config::default(),
        b"third-password",
        &third,
    )
    .unwrap();
    let third_key = ConfigKeyring::derive(b"third-password", third).unwrap();
    assert_eq!(
        load_recovery_context::<serde_json::Value>(&directory, &third_key).unwrap(),
        (fixture, digest)
    );
}

#[test]
fn runtime_approval_binds_recovery_manager_context_and_host_identity() {
    let f = Fixture::new();
    let mut request = f.request();
    let binding = RecoveryBinding {
        manager: ProcessIdentity {
            pid: 55,
            birth: 99,
            executable: "old-manager".into(),
            executable_sha256: "01".repeat(32),
            owner: "test-owner".into(),
        },
        context_digest: "02".repeat(32),
    };
    if let Action::Attach { spec } = &mut request.action {
        spec.recovery = Some(binding);
    }
    let grant = authorize_bound(
        &f.directory,
        &f.config,
        &f.password,
        &f.descriptor,
        request,
        crate::session::unix_timestamp_ms(),
        Some("03".repeat(32)),
        "04".repeat(32),
        Some("05".repeat(32)),
    )
    .unwrap();
    for case in 0..3 {
        let mut changed = grant.clone();
        match case {
            0 => {
                if let Action::Attach { spec } = &mut changed.request.action {
                    spec.recovery.as_mut().unwrap().manager.birth += 1;
                }
            }
            1 => {
                if let Action::Attach { spec } = &mut changed.request.action {
                    spec.recovery.as_mut().unwrap().context_digest = "06".repeat(32);
                }
            }
            _ => changed.host_binding = Some("07".repeat(32)),
        }
        assert!(verify_authorization(&f.directory, &changed).is_err());
    }
    assert!(verify_authorization(&f.directory, &grant).is_ok());
    assert!(!authorization_consumed_by(
        &f.directory,
        &grant,
        std::process::id()
    ));
}

#[test]
fn consumed_continuation_keeps_original_verifier_after_rotation_but_rejects_forgery() {
    let f = Fixture::new();
    let consumed = f.grant();
    consume_authorization(&f.directory, &consumed).unwrap();
    let unused = f.grant();
    let mut next = f.descriptor.clone();
    next.config_id[0] ^= 1;
    next.salt[0] ^= 1;
    config_store::save_encrypted_with_descriptor(
        &f.config,
        &crate::config::Config::default(),
        b"rotated-password",
        &next,
    )
    .unwrap();
    assert!(verify_signature(&f.directory, &consumed).is_err());
    assert!(verify_consumed_continuation(&f.directory, &consumed, std::process::id()).is_ok());
    assert!(verify_consumed_continuation(&f.directory, &unused, std::process::id()).is_err());
    let mut altered = consumed.clone();
    altered.expires_at_ms += 1;
    assert!(verify_consumed_continuation(&f.directory, &altered, std::process::id()).is_err());
    assert!(verify_consumed_continuation(
        &f.directory,
        &consumed,
        std::process::id().wrapping_add(1)
    )
    .is_err());
    let marker = f.directory.join("consumed").join(digest(&consumed.nonce));
    let mut document: serde_json::Value =
        serde_json::from_slice(&read_private_file(&marker, 1024 * 1024).unwrap()).unwrap();
    document["verifier"] = serde_json::to_value([42u8; 32]).unwrap();
    config_store::save_durable_private_bytes(&marker, &serde_json::to_vec(&document).unwrap())
        .unwrap();
    assert!(verify_consumed_continuation(&f.directory, &consumed, std::process::id()).is_err());
}

#[test]
fn writable_authority_cache_never_enrolls_or_replaces_a_memory_root() {
    let f = Fixture::new();
    let grant = f.grant();
    let path = f.directory.join("authority.json");
    let mut cached: serde_json::Value =
        serde_json::from_slice(&read_private_file(&path, 4096).unwrap()).unwrap();
    cached["public_key"] = serde_json::to_value([42u8; 32]).unwrap();
    config_store::save_durable_private_bytes(&path, &serde_json::to_vec(&cached).unwrap()).unwrap();
    verify_signature(&f.directory, &grant).unwrap();
    super::trust::invalidate_memory_authority(&f.directory);
    assert!(verify_signature(&f.directory, &grant)
        .unwrap_err()
        .contains("unenrolled"));
    assert!(approval_trust(&f.directory).unwrap().authority.is_none());
}

#[test]
fn audit_nonce_cannot_create_an_accepted_operation_after_memory_loss() {
    let f = Fixture::new();
    let grant = f.grant();
    consume_authorization(&f.directory, &grant).unwrap();
    let marker = f.directory.join("consumed").join(digest(&grant.nonce));
    let copied = read_private_file(&marker, 1024 * 1024).unwrap();
    let another = Fixture::new();
    let same = another.directory.join("consumed");
    private_directory(&same).unwrap();
    create_private_file(&same.join(digest(&grant.nonce)), &copied).unwrap();
    assert!(!authorization_consumed_by(
        &another.directory,
        &grant,
        std::process::id()
    ));
    assert!(verify_consumed_continuation(&another.directory, &grant, std::process::id()).is_err());
}

#[test]
fn authenticated_config_anchor_does_not_implicitly_enroll_core_and_api_save_preserves_it() {
    let f = Fixture::new();
    let unlocked = config_store::load_encrypted(&f.config, &f.password).unwrap();
    let expected = unlocked.approval_public_key.unwrap();
    pin_expected_approval_anchor(
        &f.directory,
        ApprovalAuthority {
            instance_id: instance_id(&f.config, &f.descriptor),
            config_id: f.descriptor.config_id,
            public_key: expected,
            generation: 0,
        },
    )
    .unwrap();
    assert!(approval_trust(&f.directory).unwrap().authority.is_none());
    assert_eq!(
        approval_trust(&f.directory)
            .unwrap()
            .expected_authority
            .unwrap()
            .public_key,
        expected
    );
    let admin = config_store::ConfigKeyring::derive(&f.password, f.descriptor.clone()).unwrap();
    let runtime = config_store::ConfigKeyring::from_runtime_master(
        f.descriptor.clone(),
        admin.runtime_master(),
    )
    .unwrap();
    config_store::save_encrypted_with_keyring(
        &f.config,
        &crate::config::Config::default(),
        &runtime,
    )
    .unwrap();
    assert_eq!(
        config_store::load_encrypted_with_keyring(&f.config, &runtime)
            .unwrap()
            .approval_public_key,
        Some(expected)
    );
    let peer = inspect_process(std::process::id()).unwrap();
    let bad = super::trust::challenge(&f.directory, &f.config, peer.clone()).unwrap();
    assert!(super::trust::enroll_password(
        &f.directory,
        &f.config,
        &bad.nonce,
        b"wrong dummy password",
        &peer
    )
    .is_err());
    assert!(
        super::trust::enroll_password(&f.directory, &f.config, &bad.nonce, &f.password, &peer)
            .is_err(),
        "failed password attempt reused a challenge"
    );
    let correct = super::trust::challenge(&f.directory, &f.config, peer.clone()).unwrap();
    super::trust::enroll_password(&f.directory, &f.config, &correct.nonce, &f.password, &peer)
        .unwrap();
    assert_eq!(
        trusted_authority(&f.directory).unwrap().public_key,
        expected
    );
}

#[test]
fn new_attachment_epoch_prevents_prior_detach_receipt_from_revoking_membership() {
    let f = Fixture::new();
    let request = f.request();
    let now = crate::session::unix_timestamp_ms();
    let first = authorize(
        &f.directory,
        &f.config,
        &f.password,
        &f.descriptor,
        request.clone(),
        now.saturating_sub(1000),
    )
    .unwrap();
    activate_epoch(&f.directory, &first).unwrap();
    let mut detach_request = request.clone();
    detach_request.id = new_id();
    detach_request.action = Action::Detach {
        exec_epoch: 0,
        attachment_id: request.action.attachment_id().into(),
        target: request.action.target().clone(),
        policy_digest: request.action.policy_digest().into(),
        recovery: None,
    };
    let old = authorize(
        &f.directory,
        &f.config,
        &f.password,
        &f.descriptor,
        detach_request.clone(),
        now.saturating_sub(900),
    )
    .unwrap();
    consume_authorization(&f.directory, &old).unwrap();
    verify_consumed_continuation(&f.directory, &old, std::process::id()).unwrap();
    let fresh = authorize(
        &f.directory,
        &f.config,
        &f.password,
        &f.descriptor,
        request,
        now.saturating_sub(800),
    )
    .unwrap();
    activate_epoch(&f.directory, &fresh).unwrap();
    assert!(
        verify_consumed_continuation(&f.directory, &old, std::process::id())
            .unwrap_err()
            .contains("superseded")
    );
    let mut revoked = false;
    assert!(under_consumed_epoch(&f.directory, &old, || revoked = true).is_err());
    assert!(!revoked);
    let mut stale = old.clone();
    stale.nonce = rand::random();
    assert!(reject_stale_detach(&f.directory, &stale).is_err());
    let current = authorize(
        &f.directory,
        &f.config,
        &f.password,
        &f.descriptor,
        detach_request,
        now.saturating_sub(700),
    )
    .unwrap();
    consume_authorization(&f.directory, &current).unwrap();
    under_consumed_epoch(&f.directory, &current, || revoked = true).unwrap();
    assert!(revoked);
}

#[test]
fn admin_signature_binds_the_exact_core_successor_key() {
    let f = Fixture::new();
    let grant = f.grant();
    let mut changed = grant.clone();
    changed.core_attestation_public_key = Some([42; 32]);
    assert!(verify_signature(&f.directory, &changed).is_err());
    verify_signature(&f.directory, &grant).unwrap();
}
