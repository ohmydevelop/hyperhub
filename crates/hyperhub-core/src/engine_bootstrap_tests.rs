use super::*;
use crate::session::{ConnectionRegistry, ControlRequest, ControlResponse, SessionRegistry};
use crate::Config;
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

fn service() -> (ControlService, String) {
    let sessions = SessionRegistry::default();
    let executable = std::env::current_exe().unwrap().display().to_string();
    let challenge = sessions
        .begin_auth("bootstrap-unit".into(), executable, [5; 32])
        .unwrap();
    let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
    let record = sessions
        .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(30))
        .unwrap();
    assert!(sessions.activate("bootstrap-unit", &record.token, std::process::id()));
    (
        ControlService::new(
            sessions,
            ConnectionRegistry::default(),
            String::new(),
            crate::audit::AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        ),
        record.token,
    )
}

async fn call(
    service: ControlService,
    request: ControlRequest,
    peer: Option<u32>,
) -> ControlResponse {
    let (mut client, server) = tokio::io::duplex(1024 * 1024);
    let task = tokio::spawn(async move { service.handle(server, peer).await.unwrap() });
    crate::framing::write_frame(&mut client, &request)
        .await
        .unwrap();
    let response = crate::framing::read_frame(&mut client).await.unwrap();
    task.await.unwrap();
    response
}

#[tokio::test]
async fn bootstrap_binds_session_peer_member_nonce_and_host_manifest() {
    let (service, token) = service();
    let pid = std::process::id();
    let host = hyperhub_engine::manifest(b"bootstrap-unit", "unit");
    let request = ControlRequest::GetEngineBootstrap {
        native_base_sha256: "a".repeat(64),
        session_id: "bootstrap-unit".into(),
        token: token.clone(),
        pid,
        root_pid: pid,
        nonce: [8; 32],
        host: host.clone(),
    };
    let response = call(service.clone(), request.clone(), Some(pid)).await;
    let ControlResponse::EngineBootstrap { bootstrap } = response else {
        panic!("missing bootstrap")
    };
    assert!(bootstrap.verify(&token, &[8; 32], pid, pid, &host, &"a".repeat(64)));
    assert!(!bootstrap.verify(&token, &[9; 32], pid, pid, &host, &"a".repeat(64)));
    assert!(bootstrap.selection.stable.is_none() && bootstrap.selection.candidate.is_none());
    assert!(matches!(
        call(service.clone(), request.clone(), Some(pid + 1)).await,
        ControlResponse::Error { .. }
    ));
    assert!(matches!(
        call(service.clone(), request.clone(), None).await,
        ControlResponse::Error { .. }
    ));
    let mut wrong_token = request.clone();
    if let ControlRequest::GetEngineBootstrap { token, .. } = &mut wrong_token {
        *token = "invalid".into();
    }
    assert!(matches!(
        call(service.clone(), wrong_token, Some(pid)).await,
        ControlResponse::Error { .. }
    ));
    let mut wrong_session = request.clone();
    if let ControlRequest::GetEngineBootstrap { session_id, .. } = &mut wrong_session {
        *session_id = "other".into();
    }
    assert!(matches!(
        call(service.clone(), wrong_session, Some(pid)).await,
        ControlResponse::Error { .. }
    ));
    let mut wrong_root = request;
    if let ControlRequest::GetEngineBootstrap { root_pid, .. } = &mut wrong_root {
        *root_pid += 1;
    }
    assert!(matches!(
        call(service, wrong_root, Some(pid)).await,
        ControlResponse::Error { .. }
    ));
}

#[tokio::test]
async fn enrolled_acknowledgement_is_signed_for_the_registered_host_and_nonce() {
    let (service, token) = service();
    let hosts = service.engine_hosts.clone();
    let pid = std::process::id();
    #[cfg(windows)]
    let backend = hyperhub_engine::host::Backend::WindowsGum;
    #[cfg(not(windows))]
    let backend = hyperhub_engine::host::Backend::LinuxGum;
    let request = ControlRequest::SubscribeEngineHost {
        native_base_sha256: "a".repeat(64),
        session_id: "bootstrap-unit".into(),
        token: token.clone(),
        root_pid: pid,
        backend,
        snapshot: hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
        nonce: [11; 32],
    };
    let (mut client, server) = tokio::io::duplex(1024 * 1024);
    let task = tokio::spawn(async move { service.handle(server, Some(pid)).await });
    crate::framing::write_frame(&mut client, &request)
        .await
        .unwrap();
    let enrolled = loop {
        let value: serde_json::Value = crate::framing::read_frame(&mut client).await.unwrap();
        if value.get("type").and_then(|v| v.as_str()) == Some("engine_host_enrolled") {
            break serde_json::from_value::<hyperhub_engine::host::Enrolled>(value).unwrap();
        }
        let delivery: hyperhub_engine::host::Delivery = serde_json::from_value(value).unwrap();
        crate::framing::write_frame(
            &mut client,
            &hyperhub_engine::host::Acknowledgement {
                request_id: delivery.request_id,
                reply: hyperhub_engine::management::Reply::Ok,
                snapshot: hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
            },
        )
        .await
        .unwrap();
    };
    assert!(enrolled.verify(&token, &[11; 32]));
    assert!(!enrolled.verify(&token, &[12; 32]));
    let registered = hosts.host(Some(&enrolled.host_id));
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].session_id, "bootstrap-unit");
    assert_eq!(registered[0].root_pid, pid);
    task.abort();
}

#[tokio::test]
async fn release_messages_authenticate_before_reporting_unavailable_coordination() {
    let (service, _) = service();
    let pid = std::process::id();
    let request = crate::release::Request {
        id: "control-test".into(),
        issued_at_ms: crate::session::unix_timestamp_ms(),
        action: crate::release::Action::Commit,
    };
    let proof = request.proof(&[0; 32]).unwrap();
    let response = call(
        service.clone(),
        ControlRequest::ReleaseUpgrade {
            request: request.clone(),
            proof: vec![0; 32],
        },
        Some(pid),
    )
    .await;
    assert!(
        matches!(response, ControlResponse::Error { message } if message == "invalid release upgrade owner proof")
    );
    let response = call(
        service.clone(),
        ControlRequest::ReleaseUpgrade {
            request,
            proof: proof.clone(),
        },
        Some(pid),
    )
    .await;
    assert!(
        matches!(response, ControlResponse::Error { message } if message.contains("coordinator unavailable"))
    );
    let ack = crate::release::installer::Acknowledgement {
        id: "control-test".into(),
        attempt: 1,
        issued_at_ms: crate::session::unix_timestamp_ms(),
        sha256: "a".repeat(64),
        installed: true,
        error: None,
    };
    let response = call(
        service.clone(),
        ControlRequest::ReleaseHelperAck {
            ack: ack.clone(),
            proof,
        },
        Some(pid),
    )
    .await;
    assert!(
        matches!(response, ControlResponse::Error { message } if message == "invalid release installation acknowledgement proof")
    );
    let proof = ack.proof(&[0; 32]).unwrap();
    let response = call(
        service.clone(),
        ControlRequest::ReleaseHelperAck { ack, proof },
        Some(pid),
    )
    .await;
    assert!(
        matches!(response, ControlResponse::Error { message } if message.contains("coordinator unavailable"))
    );
    assert!(matches!(
        call(
            service.clone(),
            ControlRequest::GetReleaseUpgrades { id: None },
            Some(pid)
        )
        .await,
        ControlResponse::ReleaseUpgrades { status: None }
    ));
    let response = call(service, ControlRequest::GetStatus, Some(pid)).await;
    assert!(matches!(
        response,
        ControlResponse::Status {
            release_upgrades: None,
            forward_workers: None,
            ..
        }
    ));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_known_tracer_can_reconnect_after_its_original_session_member_exits() {
    let (service, token) = service();
    let pid = std::process::id();
    let start = crate::session::process_start_time(pid).unwrap();
    let instance = service
        .sessions
        .member_instance("bootstrap-unit", &token, pid)
        .unwrap();
    let registration = service
        .engine_hosts
        .register(
            "bootstrap-unit".into(),
            String::new(),
            hyperhub_engine::host::Backend::LinuxPtrace,
            pid,
            pid,
            instance,
            Some(start),
            Some(start),
            hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
        )
        .unwrap();
    drop(registration);
    assert!(service.sessions.register_child(
        "bootstrap-unit",
        &token,
        pid,
        pid + 1,
        "unit-child".into()
    ));
    assert!(service
        .sessions
        .member_exited("bootstrap-unit", pid, instance));
    assert!(!service
        .sessions
        .authenticate_member("bootstrap-unit", &token, pid));
    assert!(service
        .sessions
        .authenticate_control("bootstrap-unit", &token));
    let host = hyperhub_engine::manifest(b"known-tracer", "unit");
    let response = call(
        service.clone(),
        ControlRequest::GetEngineBootstrap {
            native_base_sha256: "a".repeat(64),
            session_id: "bootstrap-unit".into(),
            token: token.clone(),
            pid,
            root_pid: pid,
            nonce: [13; 32],
            host: host.clone(),
        },
        Some(pid),
    )
    .await;
    assert!(
        matches!(response, ControlResponse::EngineBootstrap { bootstrap } if bootstrap.verify(&token, &[13; 32], pid, pid, &host, &"a".repeat(64)))
    );
    assert!(service
        .engine_hosts
        .known_ptrace("other", pid, start, pid)
        .is_none());
    assert!(service
        .engine_hosts
        .known_ptrace("bootstrap-unit", pid, start + 1, pid)
        .is_none());
    let (mut client, server) = tokio::io::duplex(1024 * 1024);
    let task = tokio::spawn(async move { service.handle(server, Some(pid)).await });
    crate::framing::write_frame(
        &mut client,
        &ControlRequest::SubscribeEngineHost {
            native_base_sha256: "a".repeat(64),
            session_id: "bootstrap-unit".into(),
            token: token.clone(),
            root_pid: pid,
            backend: hyperhub_engine::host::Backend::LinuxPtrace,
            snapshot: hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
            nonce: [14; 32],
        },
    )
    .await
    .unwrap();
    loop {
        let value: serde_json::Value = crate::framing::read_frame(&mut client).await.unwrap();
        if value.get("type").and_then(|v| v.as_str()) == Some("engine_host_enrolled") {
            let enrolled: hyperhub_engine::host::Enrolled = serde_json::from_value(value).unwrap();
            assert!(enrolled.verify(&token, &[14; 32]));
            break;
        }
        let delivery: hyperhub_engine::host::Delivery = serde_json::from_value(value).unwrap();
        crate::framing::write_frame(
            &mut client,
            &hyperhub_engine::host::Acknowledgement {
                request_id: delivery.request_id,
                reply: hyperhub_engine::management::Reply::Ok,
                snapshot: hyperhub_engine::host::report(&hyperhub_engine::resident()).unwrap(),
            },
        )
        .await
        .unwrap();
    }
    task.abort();
}
