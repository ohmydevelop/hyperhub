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
