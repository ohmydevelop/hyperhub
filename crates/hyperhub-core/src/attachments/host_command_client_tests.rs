//! Real private IPC tests of the manager client. The peer is a protocol mock;
//! SDK receiver and native Hook behavior have separate regression tests.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

struct Fixture {
    root: std::path::PathBuf,
    bootstrap: wire::Bootstrap,
    identity: ProcessIdentity,
    proof: wire::ApprovalProof,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    challenges: Arc<AtomicUsize>,
    signatures: Arc<AtomicUsize>,
}
impl Fixture {
    fn new(fault: &'static str) -> Self {
        let root = std::env::temp_dir().join(format!("hh-hcs-{:08x}", rand::random::<u32>()));
        super::super::private_directory(&root).unwrap();
        #[cfg(unix)]
        let endpoint = root.join("h").to_string_lossy().into_owned();
        #[cfg(windows)]
        let endpoint = format!(
            r"\\.\pipe\hyperhub-host-sender-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        );
        let identity = super::super::inspect_process(std::process::id()).unwrap();
        let id = super::super::new_id();
        let core = SigningKey::from_bytes(&[51; 32]);
        let bootstrap: wire::Bootstrap = serde_json::from_value(serde_json::json!({
            "attachment_id":id,"session_id":format!("session-{id}"),"token":"t".repeat(64),"control_endpoint":"unused-core","socks_address":"127.0.0.1:1","tls_ca_pem":"-----BEGIN CERTIFICATE-----fixture",
            "observe":false,"firewall":null,"sandbox":null,"host_endpoint":endpoint,"host_token":"h".repeat(64),"scope_tree":false,"root_pid":identity.pid,
            "approval_authority_file":"unused","approval_instance_id":"host-client-instance","approval_public_key":null,"approval_core_public_key":core.verifying_key().to_bytes(),"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":identity.executable_sha256
        })).unwrap();
        let proof = wire::ApprovalProof {
            payload: id.as_bytes().to_vec(),
            signature: vec![3; 64],
        };
        // Trusted client-cache setup only. Real administrator verification and
        // consumption are covered by consumption_tests, not by this mock.
        use sha2::Digest;
        let scope = wire::OperationScope {
            action: wire::OperationAction::Detach,
            administrator_digest: wire::operation_administrator_digest(&proof).unwrap(),
            instance_id: bootstrap.approval_instance_id.clone(),
            attachment_id: id,
            session_id: bootstrap.session_id.clone(),
            credential_digest: sha2::Sha256::digest(bootstrap.token.as_bytes()).into(),
            host_binding: bootstrap.approval_binding().unwrap(),
            root_image: wire::RootImageState {
                identity: identity.root_image_identity(),
                exec_epoch: 0,
                observed_at_ms: 0,
                head: [0; 32],
            },
            claimant: super::super::manager_operation_claimant().unwrap(),
            core_public_key: core.verifying_key().to_bytes(),
        };
        let now = crate::session::unix_timestamp_ms();
        let payload = wire::encode_accepted_operation(&wire::AcceptedOperationPayload {
            schema_version: 1,
            challenge: wire::PossessionChallenge {
                schema_version: 1,
                scope: scope.clone(),
                nonce: [4; 32],
                issued_at_ms: now - 2,
                expires_at_ms: now + 29_998,
            },
            accepted_at_ms: now - 1,
        })
        .unwrap();
        let certificate = wire::AcceptedOperationCertificate {
            signature: core.sign(&payload).to_bytes().to_vec(),
            payload,
        };
        super::super::remember_accepted_operation(&scope, certificate.clone()).unwrap();
        let listener = wire::Listener::bind(&bootstrap.host_endpoint).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let challenges = Arc::new(AtomicUsize::new(0));
        let server_challenges = challenges.clone();
        let signatures = Arc::new(AtomicUsize::new(0));
        let server_signatures = signatures.clone();
        let server_bootstrap = bootstrap.clone();
        let host = identity.clone();
        let server = std::thread::spawn(move || {
            let pending = Mutex::new(None::<wire::HostCommandChallenge>);
            listener.run_raw_with_peer(&server_stop, |value, _| {
                let status = || serde_json::from_value::<wire::HostStatus>(serde_json::json!({
                    "protocol":wire::PROTOCOL,"pid":host.pid,"attachment_id":server_bootstrap.attachment_id,"phase":"active","native_ready":true,
                    "active_calls":0,"unload_ready":false,"tracked_sockets":0,"fake_addresses":0,"compatibility_reasons":[],"approval_root_enrolled":true,"alias_publication_paused":true
                })).unwrap();
                if value.get("host_lifecycle").is_none() {
                    let request: wire::AuthenticatedCommand = serde_json::from_value(value).unwrap();
                    assert_eq!(request.command, wire::HostCommand::Status);
                    return serde_json::json!({"status":status(),"error":null});
                }
                let reply = match serde_json::from_value::<wire::HostLifecycleEnvelope>(value).unwrap() {
                    wire::HostLifecycleEnvelope::Challenge { request, certificate: actual, purpose } => {
                        assert_eq!(actual, certificate);
                        let sequence = server_challenges.fetch_add(1, Ordering::AcqRel) + 1;
                        let now = crate::session::unix_timestamp_ms();
                        let challenge = wire::HostCommandChallenge {
                            schema_version: 1, accepted_digest: wire::host_accepted_operation_digest(&actual).unwrap(),
                            host_pid: host.pid, host_birth: host.birth + u64::from(fault == "wrong_birth"), host_epoch: [7;32], state_epoch: sequence as u64,
                            intent: wire::HostCommandIntent::for_request(&request, purpose).unwrap(), nonce: [sequence as u8;32], issued_at_ms: now, expires_at_ms: now+30_000,
                        };
                        wire::validate_host_command_challenge(&challenge, &request, &scope, &actual, now).unwrap();
                        *pending.lock().unwrap() = Some(challenge.clone());
                        wire::HostLifecycleReply::challenge(challenge)
                    }
                    wire::HostLifecycleEnvelope::Execute { request, certificate: actual, purpose, nonce, possession } => {
                        let challenge = pending.lock().unwrap().take().unwrap();
                        assert_eq!(nonce, challenge.nonce);
                        assert_eq!(purpose, challenge.intent.command);
                        wire::verify_host_command_proof(&challenge, &request, &scope, &actual, &possession, crate::session::unix_timestamp_ms()).unwrap();
                        let sequence = server_signatures.fetch_add(1, Ordering::AcqRel);
                        if fault == "retry" && sequence == 0 {
                            wire::HostLifecycleReply::error("Host lifecycle state changed: StateChanged")
                        } else if fault == "reject" {
                            wire::HostLifecycleReply::error("fixture rejected preparation")
                        } else { wire::HostLifecycleReply::status(status()) }
                    }
                };
                serde_json::to_value(reply).unwrap()
            })
        });
        Self {
            root,
            bootstrap,
            identity,
            proof,
            stop,
            server: Some(server),
            challenges,
            signatures,
        }
    }
    fn send(&self) -> Result<wire::HostStatus, String> {
        manager_host_command_with_proof(
            &self.bootstrap,
            &self.identity,
            wire::HostCommand::PrepareDetachment,
            Some(self.proof.clone()),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            let result = server.join();
            if !std::thread::panicking() {
                result.unwrap().unwrap();
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn actual_manager_sender_proves_exact_command_over_private_peer_checked_ipc() {
    let fixture = Fixture::new("none");
    assert!(fixture.send().unwrap().alias_publication_paused);
    assert_eq!(fixture.challenges.load(Ordering::Acquire), 1);
    assert_eq!(fixture.signatures.load(Ordering::Acquire), 1);
    assert!(!format!(
        "{:?}",
        DetachBarrierPlan {
            authorization_nonce: [1; 32],
            command: wire::HostLifecycleCommand::PrepareDetachment,
            targets: vec![HostCommandTarget {
                identity: fixture.identity.clone(),
                endpoint: fixture.bootstrap.host_endpoint.clone(),
                token: fixture.bootstrap.host_token.clone()
            }]
        }
    )
    .contains(&fixture.bootstrap.host_token));
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn actual_manager_sender_rechecks_fresh_epoch_but_never_retries_arbitrary_failures() {
    for (fault, attempts, success) in [
        ("retry", 2, true),
        ("reject", 1, false),
        ("wrong_birth", 0, false),
    ] {
        let fixture = Fixture::new(fault);
        assert_eq!(fixture.send().is_ok(), success, "{fault}");
        assert_eq!(
            fixture.signatures.load(Ordering::Acquire),
            attempts,
            "{fault}"
        );
        assert_eq!(
            fixture.challenges.load(Ordering::Acquire),
            attempts.max(1),
            "{fault}"
        );
    }
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn actual_manager_sender_will_not_sign_missing_cache_or_changed_immutable_scope() {
    let fixture = Fixture::new("none");
    let mut proof = fixture.proof.clone();
    proof.payload.push(99);
    assert!(manager_host_command_with_proof(
        &fixture.bootstrap,
        &fixture.identity,
        wire::HostCommand::PrepareDetachment,
        Some(proof)
    )
    .is_err());
    let mut bootstrap = fixture.bootstrap.clone();
    bootstrap.session_id.push('x');
    assert!(manager_host_command_with_proof(
        &bootstrap,
        &fixture.identity,
        wire::HostCommand::PrepareDetachment,
        Some(fixture.proof.clone())
    )
    .is_err());
    assert!(manager_host_command_with_proof(
        &fixture.bootstrap,
        &fixture.identity,
        wire::HostCommand::Activate,
        Some(fixture.proof.clone())
    )
    .is_err());
    assert_eq!(fixture.challenges.load(Ordering::Acquire), 0);
    assert_eq!(fixture.signatures.load(Ordering::Acquire), 0);
}
