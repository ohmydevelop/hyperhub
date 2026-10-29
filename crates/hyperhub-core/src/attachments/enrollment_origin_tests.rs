//! Pure Core trust-state continuation. Actual parent/child pipes are exercised
//! by the registered Serve restart fixture, not by these simulated old origins.
use super::*;
use hyperhub_runtime::attachment as wire;

fn bootstrap(origin: EnrollmentOrigin, key: [u8; 32]) -> wire::Bootstrap {
    wire::Bootstrap {
        attachment_id: "private-origin-attachment".into(),
        session_id: "private-origin-session".into(),
        token: "t".repeat(64),
        control_endpoint: "unused-private-control".into(),
        socks_address: "127.0.0.1:1".into(),
        tls_ca_pem: "private-test-certificate".into(),
        observe: false,
        firewall: None,
        sandbox: None,
        host_endpoint: "unused-private-host".into(),
        host_token: "h".repeat(64),
        scope_tree: true,
        root_pid: 123,
        approval_authority_file: "unused-private-authority".into(),
        approval_instance_id: "private-origin-instance".into(),
        initially_owned: true,
        external_attachment: true,
        native_dns_mode: wire::NativeDnsMode::PreserveAnswers,
        approval_not_before_ms: 0,
        approval_public_key: None,
        approval_inherited_public_key: None,
        approval_root_identity: None,
        alias_inherited: None,
        approval_core_public_key: Some(key),
        approval_core_pid: origin.pid,
        approval_core_birth: origin.birth,
        approval_cli_sha256: "ab".repeat(32),
    }
}
fn challenge(nonce: u8) -> wire::ApprovalEnrollmentChallenge {
    wire::ApprovalEnrollmentChallenge {
        challenge: [nonce; 32],
        host_pid: 321,
        host_birth: 654,
        expires_at_ms: crate::session::unix_timestamp_ms() + 30_000,
    }
}
fn setup(directory: &Path, authority: &ApprovalAuthority) {
    super::super::private_directory(directory).unwrap();
    pin_expected_approval_anchor(directory, authority.clone()).unwrap();
}
#[test]
fn successor_enrollment_keeps_original_host_origin_across_two_transfers_and_rejects_untrusted_origins(
) {
    let root =
        std::env::temp_dir().join(format!("hh-enrollment-origin-{}", super::super::new_id()));
    let a = root.join("a");
    let b = root.join("b");
    let c = root.join("c");
    let cold = root.join("cold");
    let authority = ApprovalAuthority {
        instance_id: "private-origin-instance".into(),
        config_id: [4; 16],
        public_key: SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes(),
        generation: 0,
    };
    for directory in [&a, &b, &c, &cold] {
        setup(directory, &authority);
    }
    pin_authority(&a, authority.clone(), None).unwrap();
    // Model an earlier, verified Core incarnation whose PID is different from
    // this test runner. This is test memory setup, never a production source.
    let origin = EnrollmentOrigin {
        pid: std::process::id().saturating_add(10000),
        birth: 987654321,
    };
    state(&a).lock().unwrap().enrollment_origins.push(origin);
    let original = bootstrap(origin, approval_trust(&a).unwrap().core_public_key);
    for (index, directory) in [&a, &b, &c].into_iter().enumerate() {
        if index > 0 {
            let previous = if index == 1 { &a } else { &b };
            import_successor(directory, export_successor(previous).unwrap()).unwrap();
        }
        let fresh = challenge(10 + index as u8);
        let certificate = core_host_enrollment(directory, &original, &fresh).unwrap();
        assert_eq!(
            wire::verify_enrollment(
                &original,
                &fresh,
                &certificate,
                std::process::id(),
                crate::session::unix_timestamp_ms()
            )
            .unwrap(),
            authority.public_key
        );
        let another = challenge(70 + index as u8);
        assert!(wire::verify_enrollment(
            &original,
            &another,
            &certificate,
            std::process::id(),
            crate::session::unix_timestamp_ms()
        )
        .is_err());
        let mut changed = original.clone();
        changed.approval_core_pid += 1;
        assert!(core_host_enrollment(directory, &changed, &fresh).is_err());
        changed = original.clone();
        changed.approval_core_birth += 1;
        assert!(core_host_enrollment(directory, &changed, &fresh).is_err());
        changed = original.clone();
        changed.approval_core_public_key =
            Some(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
        assert!(core_host_enrollment(directory, &changed, &fresh).is_err());
        changed = original.clone();
        changed.approval_instance_id.push_str("-other");
        assert!(core_host_enrollment(directory, &changed, &fresh).is_err());
        let mut expired = fresh.clone();
        expired.expires_at_ms = crate::session::unix_timestamp_ms();
        assert!(core_host_enrollment(directory, &original, &expired).is_err());
        let mut missing = fresh.clone();
        missing.challenge = [0; 32];
        assert!(core_host_enrollment(directory, &original, &missing).is_err());
    }
    pin_authority(&cold, authority, None).unwrap();
    // Same original key is insufficient without the exact retained origin.
    let original_key = state(&a).lock().unwrap().core_key.to_bytes();
    state(&cold).lock().unwrap().core_key = SigningKey::from_bytes(&original_key);
    assert!(core_host_enrollment(&cold, &original, &challenge(40)).is_err());
    state(&cold).lock().unwrap().enrollment_origins.push(origin);
    state(&cold).lock().unwrap().core_key = SigningKey::from_bytes(&[9; 32]);
    assert!(core_host_enrollment(&cold, &original, &challenge(41)).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn successor_malformed_or_overcapacity_origins_do_not_replace_any_trust_memory() {
    let root =
        std::env::temp_dir().join(format!("hh-enrollment-capacity-{}", super::super::new_id()));
    let parent = root.join("parent");
    let child = root.join("child");
    let authority = ApprovalAuthority {
        instance_id: "private-origin-instance".into(),
        config_id: [4; 16],
        public_key: SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes(),
        generation: 0,
    };
    setup(&parent, &authority);
    setup(&child, &authority);
    pin_authority(&parent, authority, None).unwrap();
    let bytes =
        zeroize::Zeroizing::new(serde_json::to_vec(&export_successor(&parent).unwrap()).unwrap());
    let before = approval_trust(&child).unwrap().core_public_key;
    for mode in ["duplicate", "zero", "missing-owner", "over-capacity"] {
        let mut transfer: CoreTrustTransfer = serde_json::from_slice(&bytes).unwrap();
        match mode {
            "duplicate" => transfer
                .enrollment_origins
                .push(transfer.enrollment_origins[0]),
            "zero" => transfer.enrollment_origins[0].birth = 0,
            "missing-owner" => transfer.owning_origin.birth += 1,
            _ => {
                for n in 0..MAX_ORIGINS {
                    transfer.enrollment_origins.push(EnrollmentOrigin {
                        pid: 100 + n as u32,
                        birth: 200 + n as u64,
                    });
                }
            }
        }
        assert!(import_successor(&child, transfer).is_err(), "{mode}");
        let current = approval_trust(&child).unwrap();
        assert_eq!(current.core_public_key, before);
        assert!(current.authority.is_none());
    }
    import_successor(&child, serde_json::from_slice(&bytes).unwrap()).unwrap();
    let own = EnrollmentOrigin::current().unwrap();
    {
        let shared = state(&parent);
        let mut state = shared.lock().unwrap();
        state.enrollment_origins = vec![own];
        for n in 1..MAX_ORIGINS {
            state.enrollment_origins.push(EnrollmentOrigin {
                pid: 100 + n as u32,
                birth: 200 + n as u64,
            });
        }
    }
    let before = approval_trust(&parent).unwrap();
    assert!(export_successor(&parent).is_err());
    let after = approval_trust(&parent).unwrap();
    assert_eq!(before.core_public_key, after.core_public_key);
    assert_eq!(before.authority, after.authority);
    assert_eq!(
        state(&parent).lock().unwrap().enrollment_origins.len(),
        MAX_ORIGINS
    );
    std::fs::remove_dir_all(root).unwrap();
}
