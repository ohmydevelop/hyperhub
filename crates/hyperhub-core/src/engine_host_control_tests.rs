use super::*;
use hyperhub_engine::host::Backend;

fn service() -> (ControlService, String) {
    let sessions = SessionRegistry::default();
    let executable = std::env::current_exe().unwrap().display().to_string();
    let challenge = sessions
        .begin_auth("host-auth".into(), executable, [9; 32])
        .unwrap();
    let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
    let record = sessions
        .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(10))
        .unwrap();
    assert!(sessions.activate("host-auth", &record.token, std::process::id()));
    (
        ControlService::new(
            sessions,
            ConnectionRegistry::default(),
            String::new(),
            AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        ),
        record.token,
    )
}
#[tokio::test]
async fn enrollment_requires_peer_identity_session_membership_and_backend() {
    let (service, token) = service();
    #[cfg(target_os = "linux")]
    let backend = Backend::LinuxGum;
    #[cfg(windows)]
    let backend = Backend::WindowsGum;
    #[cfg(not(any(target_os = "linux", windows)))]
    let backend = Backend::LinuxGum;
    for (peer, token, root, backend) in [
        (None, token.clone(), std::process::id(), backend),
        (
            Some(std::process::id() + 1),
            token.clone(),
            std::process::id(),
            backend,
        ),
        (
            Some(std::process::id()),
            "invalid token".into(),
            std::process::id(),
            backend,
        ),
        (
            Some(std::process::id()),
            token.clone(),
            std::process::id() + 1,
            backend,
        ),
        (
            Some(std::process::id()),
            token.clone(),
            std::process::id(),
            Backend::LinuxPtrace,
        ),
    ] {
        let (mut client, server) = tokio::io::duplex(32 * 1024);
        let service = service.clone();
        let task = tokio::spawn(async move { service.handle(server, peer).await });
        write_frame(
            &mut client,
            &ControlRequest::SubscribeEngineHost {
                native_base_sha256: hyperhub_engine::NATIVE_BASE_SHA256.into(),
                session_id: "host-auth".into(),
                token,
                root_pid: root,
                backend,
                snapshot: hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
                nonce: [4; 32],
            },
        )
        .await
        .unwrap();
        let reply: ControlResponse = read_frame(&mut client).await.unwrap();
        assert!(matches!(reply, ControlResponse::Error { .. }));
        task.await.unwrap().unwrap();
    }
    assert!(service.engine_hosts.hosts().is_empty());
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn exec_enrollment_waits_for_old_registration_without_replacing_live_channel() {
    use hyperhub_engine::host::{Acknowledgement, Delivery, Enrolled};
    use tokio::io::AsyncReadExt;
    let (service, token) = service();
    let pid = std::process::id();
    let birth = crate::session::process_start_time(pid);
    #[cfg(target_os = "linux")]
    let backend = Backend::LinuxGum;
    #[cfg(windows)]
    let backend = Backend::WindowsGum;
    let runtime = hyperhub_engine::resident();
    let snapshot = hyperhub_engine::host::report(&runtime).unwrap();
    let old = service
        .engine_hosts
        .register(
            "host-auth".into(),
            hyperhub_engine::NATIVE_BASE_SHA256.into(),
            backend,
            pid,
            pid,
            service
                .sessions
                .member_instance("host-auth", &token, pid)
                .unwrap(),
            birth,
            birth,
            snapshot.clone(),
        )
        .unwrap();
    let old_id = old.id.clone();
    let (mut client, server) = tokio::io::duplex(32 * 1024);
    let task_service = service.clone();
    let task = tokio::spawn(async move { task_service.handle(server, Some(pid)).await });
    write_frame(
        &mut client,
        &ControlRequest::SubscribeEngineHost {
            session_id: "host-auth".into(),
            native_base_sha256: hyperhub_engine::NATIVE_BASE_SHA256.into(),
            token: token.clone(),
            root_pid: pid,
            backend,
            snapshot,
            nonce: [7; 32],
        },
    )
    .await
    .unwrap();
    // A live old subscriber remains authoritative; no enrollment or heartbeat
    // from a replacement is allowed before its actual registration is dropped.
    assert!(
        tokio::time::timeout(Duration::from_millis(75), client.read_u8())
            .await
            .is_err()
    );
    let online: Vec<_> = service
        .engine_hosts
        .hosts()
        .into_iter()
        .filter(|h| h.online)
        .collect();
    assert_eq!(online.len(), 1);
    assert_eq!(online[0].host_id, old_id);
    drop(old);
    let enrolled = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let value: serde_json::Value = read_frame(&mut client).await.unwrap();
            if value.get("type").and_then(|v| v.as_str()) == Some("engine_host_enrolled") {
                break serde_json::from_value::<Enrolled>(value).unwrap();
            }
            let delivery: Delivery = serde_json::from_value(value).unwrap();
            let reply = unsafe { hyperhub_engine::management::execute(&runtime, delivery.command) };
            write_frame(
                &mut client,
                &Acknowledgement {
                    request_id: delivery.request_id,
                    reply,
                    snapshot: hyperhub_engine::host::report(&runtime).unwrap(),
                },
            )
            .await
            .unwrap();
        }
    })
    .await
    .unwrap();
    assert!(enrolled.verify(&token, &[7; 32]));
    assert_ne!(enrolled.host_id, old_id);
    drop(client);
    task.abort();
    let _ = task.await;
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn unenrolled_host_missing_ack_cannot_extend_the_startup_deadline() {
    let (mut service, token) = service();
    let directory = std::env::temp_dir().join(format!(
        "hh-admission-deadline-{}-{:x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let coordinator = crate::upgrade::Coordinator::open(
        &directory.join("store"),
        Zeroizing::new(vec![3; 32]),
        service.engine_hosts.clone(),
    )
    .unwrap();
    coordinator
        .submit(crate::upgrade::Request {
            id: "startup-deadline".into(),
            issued_at_ms: 0,
            action: crate::upgrade::Action::PrepareAll {
                native_base_sha256: hyperhub_engine::NATIVE_BASE_SHA256.into(),
                manifest: hyperhub_engine::manifest(b"deadline", "1.0.0"),
                source: directory.join("candidate"),
                cache: directory.join("cache"),
                hosts: vec![],
            },
        })
        .await
        .unwrap();
    service.engine_upgrades = Some(coordinator);
    let (mut client, server) = tokio::io::duplex(32 * 1024);
    let task_service = service.clone();
    let task =
        tokio::spawn(async move { task_service.handle(server, Some(std::process::id())).await });
    #[cfg(target_os = "linux")]
    let backend = Backend::LinuxGum;
    #[cfg(windows)]
    let backend = Backend::WindowsGum;
    write_frame(
        &mut client,
        &ControlRequest::SubscribeEngineHost {
            session_id: "host-auth".into(),
            native_base_sha256: hyperhub_engine::NATIVE_BASE_SHA256.into(),
            token,
            root_pid: std::process::id(),
            backend,
            snapshot: hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
            nonce: [8; 32],
        },
    )
    .await
    .unwrap();
    // Preparing prevents Enrolled. The client receives a signed heartbeat but
    // never acknowledges it; the old unconditional 35s wait exceeded startup.
    let delivery: hyperhub_engine::host::Delivery = read_frame(&mut client).await.unwrap();
    assert!(matches!(
        delivery.command,
        hyperhub_engine::management::Command::Observe
    ));
    let error = tokio::time::timeout(Duration::from_secs(27), task)
        .await
        .expect("missing ACK must expire within the 25s admission budget")
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(service.engine_hosts.hosts().iter().all(|h| !h.online));
    drop(service);
    drop(client);
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "linux")]
async fn request(
    service: ControlService,
    request: ControlRequest,
    peer: Option<u32>,
) -> ControlResponse {
    let (mut client, server) = tokio::io::duplex(32 * 1024);
    let task = tokio::spawn(async move { service.handle(server, peer).await.unwrap() });
    write_frame(&mut client, &request).await.unwrap();
    let response = read_frame(&mut client).await.unwrap();
    task.await.unwrap();
    response
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn rootless_ptrace_refresh_and_audit_require_the_retained_manager_incarnation() {
    let (service, token) = service();
    let pid = std::process::id();
    let birth = crate::session::process_start_time(pid).unwrap();
    let child = u32::MAX - 3;
    let instance = service
        .sessions
        .member_instance("host-auth", &token, pid)
        .unwrap();
    let _registration = service
        .engine_hosts
        .register(
            "host-auth".into(),
            hyperhub_engine::NATIVE_BASE_SHA256.into(),
            Backend::LinuxPtrace,
            pid,
            pid,
            instance,
            Some(birth),
            Some(birth),
            hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
        )
        .unwrap();
    assert!(service
        .sessions
        .retain_engine_manager("host-auth", &token, pid, birth));
    assert!(service.sessions.register_child(
        "host-auth",
        &token,
        pid,
        child,
        "living-child".into()
    ));
    // Model the original root's confirmed retirement while its authenticated
    // tracer and another registered member remain. Native orphan coverage runs
    // the real waitpid/exit sequence in the platform Suite.
    assert!(service.sessions.member_exited("host-auth", pid, instance));
    assert!(!service
        .sessions
        .authenticate_member("host-auth", &token, pid));
    let refresh = |root_pid, token: String| ControlRequest::RefreshSandbox {
        session_id: "host-auth".into(),
        token,
        root_pid,
        current_version: 0,
    };
    assert!(matches!(
        request(service.clone(), refresh(pid, token.clone()), Some(pid)).await,
        ControlResponse::SandboxRefresh { .. }
    ));
    for (peer, root, key) in [
        (None, pid, token.clone()),
        (Some(pid + 1), pid, token.clone()),
        (Some(pid), u32::MAX, token.clone()),
        (Some(pid), pid, "wrong".into()),
    ] {
        assert!(matches!(
            request(service.clone(), refresh(root, key), peer).await,
            ControlResponse::Error { .. }
        ));
    }
    let audit = |process_pid, token: String| ControlRequest::ReportStaticSandboxAudit {
        session_id: "host-auth".into(),
        token,
        root_pid: pid,
        event: SandboxAuditEvent {
            kind: crate::sandbox::SandboxAuditKind::Process,
            decision: crate::config::SandboxAction::Deny,
            rule_id: Some("deny-spawn".into()),
            source: "ptrace".into(),
            operation: "exec".into(),
            target: "child".into(),
            process_argv_redacted: None,
            target_argv_redacted: None,
            reason: None,
            process_pid,
            process_tid: process_pid,
            snapshot_version: 0,
        },
    };
    assert!(matches!(
        request(service.clone(), audit(child, token.clone()), Some(pid)).await,
        ControlResponse::Ok
    ));
    // A manager cannot attest an arbitrary process or reuse a removed member.
    for process in [pid, child - 1] {
        assert!(matches!(
            request(service.clone(), audit(process, token.clone()), Some(pid)).await,
            ControlResponse::Error { .. }
        ));
    }
    assert!(matches!(
        request(service.clone(), audit(child, token.clone()), Some(pid + 1)).await,
        ControlResponse::Error { .. }
    ));
    assert!(matches!(
        request(service.clone(), audit(child, "wrong".into()), Some(pid)).await,
        ControlResponse::Error { .. }
    ));
    let smart = |process_pid, token: String| ControlRequest::StaticSmartProtectionCheck {
        session_id: "host-auth".into(),
        token,
        root_pid: pid,
        process_pid,
        protection_id: "local-unconfigured-provider".into(),
        rule_id: None,
        stage: "process".into(),
        executable: "living-child".into(),
        argv: vec![],
        features: vec![],
        context: serde_json::json!({}),
    };
    assert!(matches!(
        request(service.clone(), smart(child, token.clone()), Some(pid)).await,
        ControlResponse::SmartProtectionDecision { .. }
    ));
    for (peer, process, key) in [
        (Some(pid + 1), child, token.clone()),
        (Some(pid), pid, token.clone()),
        (Some(pid), child, "wrong".into()),
    ] {
        assert!(matches!(
            request(service.clone(), smart(process, key), peer).await,
            ControlResponse::Error { .. }
        ));
    }
    // A historical Host with the same PID but another creation time is not the
    // authenticated manager, even when its claimed root otherwise matches.
    let _reused = service
        .engine_hosts
        .register(
            "host-auth".into(),
            hyperhub_engine::NATIVE_BASE_SHA256.into(),
            Backend::LinuxPtrace,
            pid,
            child - 2,
            instance,
            Some(1),
            Some(birth + 1),
            hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
        )
        .unwrap();
    assert!(!service.authenticated_ptrace_manager("host-auth", &token, Some(pid), child - 2));
    service
        .sessions
        .release_engine_manager("host-auth", pid, birth);
    assert!(service.sessions.authenticate_control("host-auth", &token));
    assert!(matches!(
        request(service.clone(), refresh(pid, token.clone()), Some(pid)).await,
        ControlResponse::Error { .. }
    ));
    assert!(matches!(
        request(service.clone(), audit(child, token.clone()), Some(pid)).await,
        ControlResponse::Error { .. }
    ));
    assert!(matches!(
        request(service, smart(child, token), Some(pid)).await,
        ControlResponse::Error { .. }
    ));
}
