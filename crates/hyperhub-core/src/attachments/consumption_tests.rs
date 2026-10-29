//! Real private control transport, no target injection or external credentials.
use super::*;
use ed25519_dalek::Signer;
use hyperhub_runtime::attachment as wire;

struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn resign(grant: &mut Authorization, key: &ed25519_dalek::SigningKey) {
    grant.signature = key
        .sign(&attachments::host_proof(grant).unwrap().payload)
        .to_bytes()
        .to_vec();
}
async fn send(endpoint: &str, request: ControlRequest) -> ControlResponse {
    tokio::time::timeout(
        Duration::from_secs(5),
        crate::control::control_request(endpoint, &request),
    )
    .await
    .unwrap()
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delegated_consumption_private_ipc_requires_possession_and_exact_record_binding() {
    let root = std::env::temp_dir().join(format!("hh-delegated-ipc-{}", attachments::new_id()));
    attachments::private_directory(&root).unwrap();
    let config = root.join("config.bin");
    let directory = root.join("runtime").join("attachments");
    let mut descriptor = crate::config_store::new_descriptor();
    descriptor.memory_kib = 8 * 1024;
    descriptor.iterations = 1;
    let password = b"dummy-delegation-password";
    crate::config_store::save_encrypted_with_descriptor(
        &config,
        &Config::default(),
        password,
        &descriptor,
    )
    .unwrap();
    let unlocked = crate::config_store::load_encrypted(&config, password).unwrap();
    let manager = attachments::inspect_process(std::process::id()).unwrap();
    let sessions = SessionRegistry::default();
    let spec = attachments::Spec {
        id: attachments::new_id(),
        target: manager.clone(),
        current_target: None,
        exec_epoch: 0,
        scope: Scope::Tree,
        backend: Backend::Ptrace,
        policy_digest: attachments::policy_digest(&Config::default()).unwrap(),
        capabilities: attachments::dynamic_capabilities_for_origin(
            &Config::default(),
            Backend::Ptrace,
            attachments::Origin::Attach,
        ),
        recovery: None,
    };
    let session_id = format!("attach-{}", spec.id);
    let auth = sessions
        .begin_auth(session_id.clone(), manager.executable.clone(), [5; 32])
        .unwrap();
    let proof = crate::session::session_proof(&[0; 32], &auth).unwrap();
    let session = sessions
        .finish_auth(&auth.challenge_id, &proof, Duration::from_secs(60))
        .unwrap();
    let service = ControlService::new(
        sessions,
        ConnectionRegistry::default(),
        "test-ca".into(),
        AuditWriter::open(None).unwrap(),
        RuntimeState::new(Arc::new(Config::default())).unwrap(),
        Zeroizing::new(vec![0; 32]),
    )
    .with_attachment_directory(directory.clone())
    .with_approval_anchor(&config, &descriptor, unlocked.approval_public_key)
    .unwrap();
    let control_home = root.join("control");
    attachments::private_directory(&control_home).unwrap();
    let endpoint = instance_control_endpoint(&control_home);
    let mut server = Server(tokio::spawn(run_control_server(endpoint.clone(), service)));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let trust = loop {
        assert!(
            !server.0.is_finished(),
            "private Core exited during startup"
        );
        if let Ok(ControlResponse::ApprovalTrust { trust }) = trusted_control_request_for_config(
            &endpoint,
            &config,
            &ControlRequest::GetApprovalTrust,
        )
        .await
        {
            break trust;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "private Core did not start"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    password_approval_enrollment(&endpoint, &config, password)
        .await
        .unwrap();
    let instance = attachments::instance_id(&config, &descriptor);
    let bootstrap = wire::Bootstrap {
        attachment_id: spec.id.clone(),
        session_id: session_id.clone(),
        token: session.token.clone(),
        control_endpoint: endpoint.clone(),
        socks_address: "127.0.0.1:18444".into(),
        tls_ca_pem: "-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n".into(),
        observe: false,
        firewall: None,
        sandbox: None,
        host_endpoint: "unused-private-host".into(),
        host_token: "dummy-host-token-aaaaaaaaaaaaaaaaaaaaaaaa".into(),
        scope_tree: true,
        root_pid: manager.pid,
        approval_authority_file: directory.join("authority.json").display().to_string(),
        approval_instance_id: instance.clone(),
        initially_owned: false,
        approval_not_before_ms: 0,
        approval_public_key: unlocked.approval_public_key,
        approval_inherited_public_key: None,
        approval_root_identity: Some(manager.root_image_identity()),
        approval_core_public_key: Some(trust.core_public_key),
        approval_core_pid: trust.core_pid,
        approval_core_birth: trust.core_birth,
        approval_cli_sha256: manager.executable_sha256.clone(),
        alias_inherited: None,
        external_attachment: true,
        native_dns_mode: wire::NativeDnsMode::PreserveAnswers,
    };
    let request = attachments::Request {
        schema_version: 1,
        id: attachments::new_id(),
        instance_id: instance,
        created_at_ms: unix_timestamp_ms(),
        action: Action::Attach { spec: spec.clone() },
    };
    let mut grant = attachments::authorize_claimant_bound(
        &directory,
        &config,
        password,
        &descriptor,
        request,
        unix_timestamp_ms(),
        Some(attachments::bootstrap_digest(&bootstrap).unwrap()),
        manager.executable_sha256.clone(),
        Some(bootstrap.approval_binding().unwrap()),
        attachments::manager_operation_claimant().unwrap(),
    )
    .unwrap();
    // The client is in this test process, so it must not import remote trust
    // into the owning Core's state. Endorse the actual OS-authenticated view
    // and sign it with the independently decrypted dummy administrator key.
    grant.core_attestation_public_key = Some(trust.core_public_key);
    let seed = crate::config_store::derive_password_approval_seed(password, &descriptor).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
    resign(&mut grant, &key);
    attachments::create_record(&directory, spec.clone()).unwrap();
    let record_directory = attachments::attachment_directory(&directory, &spec.id).unwrap();
    let execution = attachments::Execution {
        spec,
        origin: attachments::Origin::Attach,
        bootstrap: bootstrap.clone(),
        state_directory: record_directory.clone(),
        authorization: grant.clone(),
    };
    attachments::save_execution(
        &record_directory,
        &execution,
        &crate::config_store::ConfigKeyring::derive(password, descriptor.clone()).unwrap(),
    )
    .unwrap();
    let begin = |authorization, manager, bootstrap| ControlRequest::BeginAttachmentConsumption {
        authorization,
        manager,
        bootstrap,
    };
    let assert_unconsumed = || {
        assert!(!attachments::authorization_consumed_by(
            &directory,
            &grant,
            manager.pid
        ))
    };
    let mut missing = grant.clone();
    missing.manager_claimant = None;
    resign(&mut missing, &key);
    assert!(matches!(
        send(
            &endpoint,
            begin(missing, manager.clone(), bootstrap.clone())
        )
        .await,
        ControlResponse::Error { .. }
    ));
    assert_unconsumed();
    let mut other = manager.clone();
    other.pid = other.pid.checked_add(1).unwrap();
    assert!(matches!(
        send(&endpoint, begin(grant.clone(), other, bootstrap.clone())).await,
        ControlResponse::Error { .. }
    ));
    assert_unconsumed();
    let mut changed_bootstrap = bootstrap.clone();
    changed_bootstrap.token.push('x');
    let mut rebound = grant.clone();
    rebound.host_binding = Some(changed_bootstrap.approval_binding().unwrap());
    rebound.execution_digest = Some(attachments::bootstrap_digest(&changed_bootstrap).unwrap());
    resign(&mut rebound, &key);
    assert!(matches!(
        send(
            &endpoint,
            begin(rebound, manager.clone(), changed_bootstrap)
        )
        .await,
        ControlResponse::Error { .. }
    ));
    assert_unconsumed();
    assert!(
        attachments::root_image_state(&directory, &execution.spec.id).is_err(),
        "invalid binding primed trusted root metadata"
    );
    let response = send(
        &endpoint,
        begin(grant.clone(), manager.clone(), bootstrap.clone()),
    )
    .await;
    let challenge = match response {
        ControlResponse::OperationPossessionChallenge { challenge } => challenge,
        ControlResponse::Error { message } => {
            panic!("valid delegated scope was rejected before possession challenge: {message}")
        }
        _ => panic!("valid delegated scope returned an unexpected challenge response"),
    };
    let mut proof = attachments::prove_manager_operation(&challenge, unix_timestamp_ms()).unwrap();
    proof.signature[0] ^= 1;
    let consume = |nonce, possession| ControlRequest::ConsumeAttachmentAuthorization {
        authorization: grant.clone(),
        manager: manager.clone(),
        bootstrap: bootstrap.clone(),
        nonce,
        possession,
    };
    assert!(matches!(
        send(&endpoint, consume(challenge.nonce, proof)).await,
        ControlResponse::Error { .. }
    ));
    assert_unconsumed();
    let proof = attachments::prove_manager_operation(&challenge, unix_timestamp_ms()).unwrap();
    assert!(matches!(
        send(&endpoint, consume(challenge.nonce, proof)).await,
        ControlResponse::Error { .. }
    ));
    assert_unconsumed();
    let ControlResponse::OperationPossessionChallenge { challenge } = send(
        &endpoint,
        begin(grant.clone(), manager.clone(), bootstrap.clone()),
    )
    .await
    else {
        panic!("no fresh challenge")
    };
    let proof = attachments::prove_manager_operation(&challenge, unix_timestamp_ms()).unwrap();
    let ControlResponse::AcceptedAttachmentOperation { certificate } =
        send(&endpoint, consume(challenge.nonce, proof.clone())).await
    else {
        panic!("no accepted certificate")
    };
    let scope = attachments::operation_scope_for_authorization(
        &grant,
        &bootstrap,
        challenge.scope.root_image,
    )
    .unwrap();
    wire::verify_accepted_operation(&scope, &certificate, unix_timestamp_ms()).unwrap();
    attachments::remember_accepted_operation(&scope, certificate.clone()).unwrap();
    assert_eq!(
        attachments::manager_accepted_operation(&grant).unwrap(),
        certificate
    );
    assert!(attachments::authorization_consumed_by(
        &directory,
        &grant,
        manager.pid
    ));
    assert!(matches!(
        send(&endpoint, consume(challenge.nonce, proof)).await,
        ControlResponse::Error { .. }
    ));
    assert_eq!(
        attachments::load_record(&record_directory).unwrap().phase,
        attachments::Phase::Preparing,
        "protocol test must not mutate a target or pretend backend activation"
    );
    server.0.abort();
    let _ = (&mut server.0).await;
    drop(server);
    std::fs::remove_dir_all(root).unwrap();
}
