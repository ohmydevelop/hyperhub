//! Signed Attach authority for a tree is not Detach authority for future forks.
use super::*;
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn inherited_preparing_host_rejects_original_attach_but_accepts_new_detach() {
    use ed25519_dalek::SigningKey;
    use hyperhub_runtime::attachment as wire;
    const MARKER: &str = "HH_TEST_FORK_CHILD_ROLLBACK_AUTHORITY";
    if std::env::var_os(MARKER).is_none() {
        let test = format!(
            "{}::inherited_preparing_host_rejects_original_attach_but_accepts_new_detach",
            module_path!().split_once("::").unwrap().1
        );
        for origin in ["fresh", "fork"] {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .env(MARKER, origin)
                    .args(["--exact", &test, "--test-threads=1"])
                    .status()
                    .unwrap()
                    .success(),
                "{origin}"
            );
        }
        return;
    }
    let directory = std::env::temp_dir().join(format!("hh-child-rollback-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(unix)]
    let endpoint = directory.join("host").to_string_lossy().into_owned();
    #[cfg(windows)]
    let endpoint = format!(r"\\.\pipe\hh-child-rollback-{}", std::process::id());
    let admin = SigningKey::from_bytes(&[71; 32]);
    let core = SigningKey::from_bytes(&[72; 32]);
    let manager = SigningKey::from_bytes(&[73; 32]);
    let bootstrap:Bootstrap=serde_json::from_value(serde_json::json!({
        "attachment_id":"child-rollback-fixture","session_id":"fixture-session","token":"t".repeat(64),
        "control_endpoint":"unused-fixture","socks_address":"127.0.0.1:1","tls_ca_pem":"-----BEGIN CERTIFICATE-----fixture",
        "observe":false,"firewall":null,"sandbox":null,"host_endpoint":endpoint,
        "host_token":"h".repeat(64),"scope_tree":true,"root_pid":std::process::id(),
        "approval_authority_file":"unused","approval_instance_id":"child-rollback-fixture",
        "approval_public_key":admin.verifying_key().to_bytes(),"approval_core_public_key":core.verifying_key().to_bytes(),
        "approval_core_pid":std::process::id(),"approval_core_birth":wire::process_incarnation(std::process::id()).unwrap().birth,
        "approval_cli_sha256":"c".repeat(64)
    })).unwrap();
    let child = std::env::var(MARKER).unwrap() == "fork";
    let worker = bind_metadata_for_startup(&bootstrap, child)
        .unwrap()
        .unwrap();
    assert_eq!(
        origin(),
        if child {
            wire::InitializationOrigin::ForkChild
        } else {
            wire::InitializationOrigin::Fresh
        }
    );
    assert_eq!(hyperhub_attachment_recover_transport(), crate::HH_OK);
    let identity = wire::process_identity(std::process::id()).unwrap();
    let root = wire::RootImageState {
        identity: wire::RootImageIdentity {
            pid: identity.pid,
            birth: identity.birth,
            executable_sha256: identity.executable_sha256,
        },
        exec_epoch: 0,
        observed_at_ms: 0,
        head: [0; 32],
    };
    let command = |kind, proof| wire::AuthenticatedCommand {
        attachment_id: bootstrap.attachment_id.clone(),
        token: bootstrap.host_token.clone(),
        command: kind,
        proof: Some(proof),
        enrollment: None,
        aliases: None,
        root_image: None,
    };
    let exchange = |envelope| -> wire::HostLifecycleReply {
        serde_json::from_value(
            wire::exchange_raw_for_process(
                &bootstrap.host_endpoint,
                &serde_json::to_value(envelope).unwrap(),
                std::process::id(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let (attach, scope, certificate) = host_command::tests::authorization(
        &bootstrap,
        root.clone(),
        &admin,
        &core,
        &manager,
        wire::OperationAction::Attach,
    );
    // Both the administrator's tree proof and the original Core certificate
    // are valid for this binding. Rejection must come from actual SDK origin.
    wire::verify_proof(&bootstrap, &attach, now_ms()).unwrap();
    wire::verify_accepted_operation(&scope, &certificate, now_ms()).unwrap();
    if !child {
        // The same real signatures still permit rollback of the original
        // Fresh base. The new restriction must not strand initial failures.
        let request = command(wire::HostCommand::Detach, attach);
        let challenged = exchange(wire::HostLifecycleEnvelope::Challenge {
            request: request.clone(),
            certificate: certificate.clone(),
            purpose: wire::HostLifecycleCommand::RollbackInitialAttach,
        });
        assert!(challenged.error.is_none(), "{:?}", challenged.error);
        let challenge = challenged.challenge.unwrap();
        let reply = exchange(wire::HostLifecycleEnvelope::Execute {
            request,
            certificate,
            purpose: wire::HostLifecycleCommand::RollbackInitialAttach,
            nonce: challenge.nonce,
            possession: host_command::tests::sign(&challenge, &manager),
        });
        assert!(reply.error.is_none(), "{:?}", reply.error);
        assert_eq!(
            reply.status.unwrap().phase,
            wire::HostPhase::DetachedResident
        );
        assert!(cancelled());
        worker.finish(false);
        assert_eq!(
            status().unwrap().stage,
            wire::InitializationStage::Cancelled
        );
        return;
    }
    for (purpose, kind) in [
        (
            wire::HostLifecycleCommand::RollbackInitialAttach,
            wire::HostCommand::Detach,
        ),
        (
            wire::HostLifecycleCommand::RollbackInitialAttachRetire,
            wire::HostCommand::Retire,
        ),
    ] {
        let reply = exchange(wire::HostLifecycleEnvelope::Challenge {
            request: command(kind, attach.clone()),
            certificate: certificate.clone(),
            purpose,
        });
        assert!(reply
            .error
            .unwrap()
            .contains("fresh never-active initialization"));
        assert!(!cancelled());
        assert_eq!(running(), 1);
        assert_eq!(super::super::status_phase(), wire::HostPhase::Preparing);
    }
    let (detach, _, certificate) = host_command::tests::authorization(
        &bootstrap,
        root,
        &admin,
        &core,
        &manager,
        wire::OperationAction::Detach,
    );
    let request = command(wire::HostCommand::Detach, detach);
    let challenged = exchange(wire::HostLifecycleEnvelope::Challenge {
        request: request.clone(),
        certificate: certificate.clone(),
        purpose: wire::HostLifecycleCommand::Detach,
    });
    assert!(challenged.error.is_none(), "{:?}", challenged.error);
    let challenge = challenged.challenge.unwrap();
    let reply = exchange(wire::HostLifecycleEnvelope::Execute {
        request,
        certificate,
        purpose: wire::HostLifecycleCommand::Detach,
        nonce: challenge.nonce,
        possession: host_command::tests::sign(&challenge, &manager),
    });
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert_eq!(
        reply.status.unwrap().phase,
        wire::HostPhase::DetachedResident
    );
    assert!(cancelled());
    worker.finish(false);
    let final_status = super::super::status();
    assert_eq!(final_status.phase, wire::HostPhase::DetachedResident);
    assert!(!final_status.unload_ready);
    assert_eq!(final_status.tracked_sockets, usize::MAX);
    let evidence = final_status.initialization.unwrap();
    assert_eq!(evidence.origin, wire::InitializationOrigin::ForkChild);
    assert_eq!(evidence.stage, wire::InitializationStage::Cancelled);
    assert!(!evidence.runtime_available);
    assert!(!evidence.initializing);
}
