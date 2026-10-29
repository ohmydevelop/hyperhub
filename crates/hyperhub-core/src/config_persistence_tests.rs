use super::*;
use crate::config_persistence::{configuration_digest, ConfigPersistenceSigner};
use crate::config_store::{self, ConfigKeyring};

fn fixture() -> (
    std::path::PathBuf,
    ControlService,
    ConfigPersistenceSigner,
    Config,
) {
    let root = std::env::temp_dir().join(format!(
        "hh-config-transaction-{}",
        crate::attachments::new_id()
    ));
    crate::attachments::private_directory(&root).unwrap();
    let path = root.join("config.bin");
    let mut descriptor = config_store::new_descriptor();
    descriptor.memory_kib = 8 * 1024;
    descriptor.iterations = 1;
    let keyring =
        ConfigKeyring::derive(b"private-persistence-password", descriptor.clone()).unwrap();
    let signer =
        ConfigPersistenceSigner::from_password(b"private-persistence-password", &descriptor)
            .unwrap();
    let config = Config::default();
    config_store::save_encrypted_with_keyring(&path, &config, &keyring).unwrap();
    let runtime = RuntimeState::new(Arc::new(config.clone())).unwrap();
    let service = ControlService::new(
        SessionRegistry::default(),
        ConnectionRegistry::default(),
        String::new(),
        AuditWriter::open(None).unwrap(),
        runtime,
        keyring.session_auth_key().unwrap(),
    )
    .with_configuration_store(path, keyring)
    .unwrap();
    (root, service, signer, config)
}

#[cfg(all(unix, not(target_os = "linux")))]
#[tokio::test]
async fn unsupported_live_configuration_transport_rejects_without_connecting_or_sending_secrets() {
    let root = std::env::temp_dir().join(format!(
        "hh-config-unsupported-{}",
        crate::attachments::new_id()
    ));
    crate::attachments::private_directory(&root).unwrap();
    let endpoint = root.join("observer.sock");
    let listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
    let error = configuration_control_request(
        endpoint.to_str().unwrap(),
        &root.join("config.bin"),
        &ControlRequest::UpdateConfig {
            proof: Vec::new(),
            config_json: "dummy-secret-must-never-be-sent".into(),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    drop(listener);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn configuration_persistence_compiles_before_disk_and_commits_exact_revision_once() {
    let (root, service, signer, config) = fixture();
    let store = service.configuration_store.as_ref().unwrap();
    let before_bytes = std::fs::read(&store.path).unwrap();
    let before_version = service.runtime.snapshot().updated_at_ms;
    let digest = configuration_digest(&config).unwrap();
    let mut invalid = config.clone();
    invalid.rules.push(serde_json::from_value(serde_json::json!({"id":"bad-upstream","action":"deny","upstream":"missing","endpoints":[{"target":"example.test"}]})).unwrap());
    invalid.ensure_item_uuids();
    let authorization = signer
        .authorize(
            &store.path,
            store.keyring.descriptor(),
            store.core_epoch,
            digest.clone(),
            &invalid,
            unix_timestamp_ms(),
        )
        .unwrap();
    assert!(matches!(
        service
            .apply_configuration(invalid, Some(&authorization))
            .await,
        ControlResponse::Error { .. }
    ));
    assert_eq!(std::fs::read(&store.path).unwrap(), before_bytes);
    assert_eq!(service.runtime.snapshot().updated_at_ms, before_version);
    let mut next = config.clone();
    next.debug = true;
    let authorization = signer
        .authorize(
            &store.path,
            store.keyring.descriptor(),
            store.core_epoch,
            digest.clone(),
            &next,
            unix_timestamp_ms(),
        )
        .unwrap();
    let desired = configuration_digest(&next).unwrap();
    assert!(
        matches!(service.apply_configuration(next.clone(), Some(&authorization)).await,
        ControlResponse::ConfigurationPersisted { ref config_digest, .. } if config_digest == &desired)
    );
    assert!(service.runtime.snapshot().config.debug);
    assert_eq!(store.persisted_digest().unwrap(), desired);
    let committed = std::fs::read(&store.path).unwrap();
    let version = service.runtime.snapshot().updated_at_ms;
    assert!(matches!(
        service
            .apply_configuration(next.clone(), Some(&authorization))
            .await,
        ControlResponse::Error { .. }
    ));
    let retry = signer
        .authorize(
            &store.path,
            store.keyring.descriptor(),
            store.core_epoch,
            digest.clone(),
            &next,
            unix_timestamp_ms(),
        )
        .unwrap();
    assert!(matches!(
        service
            .apply_configuration(next.clone(), Some(&retry))
            .await,
        ControlResponse::ConfigurationPersisted { .. }
    ));
    assert_eq!(
        std::fs::read(&store.path).unwrap(),
        committed,
        "idempotent retry must not rewrite ciphertext"
    );
    assert_eq!(service.runtime.snapshot().updated_at_ms, version);
    let stale = signer
        .authorize(
            &store.path,
            store.keyring.descriptor(),
            store.core_epoch,
            digest,
            &config,
            unix_timestamp_ms(),
        )
        .unwrap();
    assert!(matches!(
        service.apply_configuration(config, Some(&stale)).await,
        ControlResponse::Error { .. }
    ));
    assert_eq!(std::fs::read(&store.path).unwrap(), committed);
    drop(service);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn configuration_display_failure_is_reported_after_real_commit_and_offline_write_cannot_race_live_core(
) {
    let (root, service, signer, config) = fixture();
    let store = service.configuration_store.as_ref().unwrap();
    assert!(crate::config_persistence::offline_configuration_guard(&store.path, &config).is_err());
    let display = config_store::redacted_config_path(&store.path);
    std::fs::remove_file(&display).unwrap();
    std::fs::create_dir(&display).unwrap();
    let mut next = config.clone();
    next.debug = true;
    let authorization = signer
        .authorize(
            &store.path,
            store.keyring.descriptor(),
            store.core_epoch,
            configuration_digest(&config).unwrap(),
            &next,
            unix_timestamp_ms(),
        )
        .unwrap();
    assert!(matches!(
        service
            .apply_configuration(next.clone(), Some(&authorization))
            .await,
        ControlResponse::ConfigurationPersisted {
            redacted_view_error: Some(_),
            ..
        }
    ));
    assert_eq!(
        store.persisted_digest().unwrap(),
        configuration_digest(&next).unwrap()
    );
    assert!(service.runtime.snapshot().config.debug);
    drop(service);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ciphertext_commit_failure_keeps_runtime_and_original_configuration() {
    use std::os::fd::AsRawFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (root, mut service, signer, mut config) = fixture();
    let original = root.join("config.bin");
    let listener_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.listener.socks_listen = listener_probe.local_addr().unwrap().to_string();
    drop(listener_probe);
    let socks = crate::socks::SocksService::with_environment(
        Arc::new(config.clone()),
        service.sessions.clone(),
        crate::connector::EnvironmentProxy::default(),
    )
    .unwrap();
    let controller = socks.listener_controller();
    let old_address = socks.prepare_listener().await.unwrap();
    config.listener.socks_listen = old_address.to_string();
    socks.runtime().apply(Arc::new(config.clone())).unwrap();
    service.runtime = socks.runtime();
    service.audit = socks.audit_writer();
    service.socks_listener = Some(controller.clone());
    config_store::save_encrypted_with_keyring(
        &original,
        &config,
        &service.configuration_store.as_ref().unwrap().keyring,
    )
    .unwrap();
    let challenge = service
        .sessions
        .begin_auth(
            "config-transaction-stream".into(),
            std::env::current_exe().unwrap().display().to_string(),
            [7; 32],
        )
        .unwrap();
    let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
    let session = service
        .sessions
        .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(60))
        .unwrap();
    assert!(service
        .sessions
        .activate(&session.session_id, &session.token, std::process::id()));
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_address = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut buffer = [0; 1024];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            stream.write_all(&buffer[..count]).await.unwrap();
        }
    });
    let socks_task = tokio::spawn(socks.run());
    let mut connection = tokio::net::TcpStream::connect(old_address).await.unwrap();
    connection.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0; 2];
    connection.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2]);
    let username = format!("hh2:{}:{}:1", session.session_id, std::process::id());
    let mut credentials = vec![1, username.len() as u8];
    credentials.extend_from_slice(username.as_bytes());
    credentials.push(session.token.len() as u8);
    credentials.extend_from_slice(session.token.as_bytes());
    connection.write_all(&credentials).await.unwrap();
    connection.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [1, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo_address.port().to_be_bytes());
    connection.write_all(&request).await.unwrap();
    let mut connected = [0; 10];
    connection.read_exact(&mut connected).await.unwrap();
    assert_eq!(connected[1], 0);
    connection.write_all(b"before\n").await.unwrap();
    let mut echoed = [0; 7];
    tokio::time::timeout(Duration::from_secs(5), connection.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"before\n");
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let next_address = probe.local_addr().unwrap();
    drop(probe);
    let before = std::fs::read(&original).unwrap();
    let file = std::fs::File::open(&original).unwrap();
    let store = Arc::get_mut(service.configuration_store.as_mut().unwrap()).unwrap();
    // Deterministic filesystem fault: the valid ciphertext can be read through
    // this FD, but procfs cannot create the atomic-write temporary file.
    store.path = std::path::PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let authorization = signer
        .authorize(
            &original,
            store.keyring.descriptor(),
            store.core_epoch,
            configuration_digest(&config).unwrap(),
            &{
                let mut next = config.clone();
                next.debug = true;
                next.listener.socks_listen = next_address.to_string();
                next
            },
            unix_timestamp_ms(),
        )
        .unwrap();
    let mut next = config;
    next.debug = true;
    next.listener.socks_listen = next_address.to_string();
    let version = service.runtime.snapshot().updated_at_ms;
    assert!(
        matches!(service.apply_configuration(next, Some(&authorization)).await,
        ControlResponse::Error { ref message } if message.contains("not persisted"))
    );
    assert_eq!(service.runtime.snapshot().updated_at_ms, version);
    assert!(!service.runtime.snapshot().config.debug);
    assert!(
        !service.audit.debug_enabled(),
        "failed persistence cannot enable diagnostics"
    );
    assert_eq!(
        controller.address(),
        Some(old_address),
        "failed persistence cannot advertise a prepared address"
    );
    let released = tokio::net::TcpListener::bind(next_address)
        .await
        .expect("unpublished prepared listener must be closed");
    drop(released);
    connection.write_all(b"after!\n").await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), connection.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"after!\n");
    assert_eq!(std::fs::read(&original).unwrap(), before);
    drop(service);
    drop(file);
    drop(connection);
    socks_task.abort();
    echo_task.abort();
    let _ = socks_task.await;
    let _ = echo_task.await;
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn captured_persistence_packet_is_rejected_after_core_restart_even_when_config_digest_returns_to_original(
) {
    let (root, service, signer, original) = fixture();
    let store = service.configuration_store.as_ref().unwrap();
    let path = store.path.clone();
    let keyring = store.keyring.clone();
    let old_epoch = store.core_epoch;
    let mut next = original.clone();
    next.debug = true;
    let packet = signer
        .authorize(
            &path,
            keyring.descriptor(),
            old_epoch,
            configuration_digest(&original).unwrap(),
            &next,
            unix_timestamp_ms(),
        )
        .unwrap();
    assert!(matches!(
        service
            .apply_configuration(next.clone(), Some(&packet))
            .await,
        ControlResponse::ConfigurationPersisted { .. }
    ));
    drop(service);
    // A later legitimate offline edit restores the exact old content. The
    // captured packet would pass digest CAS in a new Core without epoch binding.
    config_store::save_encrypted_with_keyring(&path, &original, &keyring).unwrap();
    let fresh = ControlService::new(
        SessionRegistry::default(),
        ConnectionRegistry::default(),
        String::new(),
        AuditWriter::open(None).unwrap(),
        RuntimeState::new(Arc::new(original.clone())).unwrap(),
        keyring.session_auth_key().unwrap(),
    )
    .with_configuration_store(path.clone(), keyring)
    .unwrap();
    assert_ne!(
        fresh.configuration_store.as_ref().unwrap().core_epoch,
        old_epoch
    );
    let before = std::fs::read(&path).unwrap();
    let version = fresh.runtime.snapshot().updated_at_ms;
    assert!(matches!(
        fresh.apply_configuration(next, Some(&packet)).await,
        ControlResponse::Error { .. }
    ));
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(fresh.runtime.snapshot().updated_at_ms, version);
    drop(fresh);
    std::fs::remove_dir_all(root).unwrap();
}
