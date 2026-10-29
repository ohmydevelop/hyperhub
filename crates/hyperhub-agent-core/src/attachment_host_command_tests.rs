use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::time::{Duration, Instant};

pub(in crate::attachment) fn authorization(
    boot: &Bootstrap,
    root: wire::RootImageState,
    administrator: &SigningKey,
    core: &SigningKey,
    manager: &SigningKey,
    action: wire::OperationAction,
) -> (
    wire::ApprovalProof,
    wire::OperationScope,
    wire::AcceptedOperationCertificate,
) {
    let now = now_ms();
    let claimant = wire::ManagerClaimant {
        pid: std::process::id(),
        birth: 123,
        role_epoch: [11; 32],
        public_key: manager.verifying_key().to_bytes(),
    };
    let target = serde_json::json!({"pid":root.identity.pid,"birth":root.identity.birth,"executable_sha256":root.identity.executable_sha256});
    let action_json = match action {
        wire::OperationAction::Attach => {
            serde_json::json!({"kind":"attach","spec":{"id":boot.attachment_id,"target":target,"scope":if boot.scope_tree { "tree" } else { "process" },"exec_epoch":root.exec_epoch}})
        }
        wire::OperationAction::Detach => {
            serde_json::json!({"kind":"detach","attachment_id":boot.attachment_id,"target":target,"exec_epoch":root.exec_epoch})
        }
    };
    let value = serde_json::json!({"request":{"schema_version":1,"instance_id":boot.approval_instance_id,"action":action_json},"approved_at_ms":now-1,"expires_at_ms":now+60_000,"nonce":vec![12;32],"executor_sha256":"e".repeat(64),"execution_digest":"d".repeat(64),"host_binding":boot.approval_binding().unwrap(),"core_attestation_public_key":core.verifying_key().to_bytes(),"manager_claimant":claimant});
    let mut payload = b"hyperhub/runtime-attachment-approval/v1\0".to_vec();
    payload.extend(serde_json::to_vec(&value).unwrap());
    let proof = wire::ApprovalProof {
        signature: administrator.sign(&payload).to_bytes().to_vec(),
        payload,
    };
    let scope = wire::OperationScope {
        action,
        administrator_digest: wire::operation_administrator_digest(&proof).unwrap(),
        instance_id: boot.approval_instance_id.clone(),
        attachment_id: boot.attachment_id.clone(),
        session_id: boot.session_id.clone(),
        credential_digest: Sha256::digest(boot.token.as_bytes()).into(),
        host_binding: boot.approval_binding().unwrap(),
        root_image: root,
        claimant,
        core_public_key: core.verifying_key().to_bytes(),
    };
    let payload = wire::encode_accepted_operation(&wire::AcceptedOperationPayload {
        schema_version: 1,
        challenge: wire::PossessionChallenge {
            schema_version: 1,
            scope: scope.clone(),
            nonce: [13; 32],
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
    (proof, scope, certificate)
}
pub(in crate::attachment) fn sign(
    challenge: &wire::HostCommandChallenge,
    manager: &SigningKey,
) -> wire::HostCommandPossessionProof {
    let payload = wire::encode_host_command_challenge(challenge).unwrap();
    wire::HostCommandPossessionProof {
        signature: manager.sign(&payload).to_bytes().to_vec(),
        payload,
    }
}
fn signed_root(
    boot: &Bootstrap,
    root: &wire::RootImageState,
    challenge: [u8; 32],
    identity: &wire::RootImageIdentity,
    core: &SigningKey,
) -> wire::SignedRootImage {
    let payload = wire::encode_root_image_payload(&wire::RootImagePayload {
        schema_version: 1,
        instance_id: boot.approval_instance_id.clone(),
        attachment_id: boot.attachment_id.clone(),
        session_id: boot.session_id.clone(),
        host_binding: boot.approval_binding().unwrap(),
        initial_identity: root.identity.clone(),
        previous: root.clone(),
        current: root.clone(),
        transition_nonce: [0; 32],
        challenge: Some(challenge),
        host_pid: Some(identity.pid),
        host_birth: Some(identity.birth),
    })
    .unwrap();
    wire::SignedRootImage {
        signature: core.sign(&payload).to_bytes().to_vec(),
        payload,
    }
}
fn local_request(envelope: wire::HostLifecycleEnvelope) -> wire::HostLifecycleReply {
    serde_json::from_value(receive(
        serde_json::to_value(envelope).unwrap(),
        std::process::id(),
    ))
    .unwrap()
}
pub(in crate::attachment) fn execute_local(
    request: wire::AuthenticatedCommand,
    certificate: &wire::AcceptedOperationCertificate,
    manager: &SigningKey,
    purpose: wire::HostLifecycleCommand,
) -> wire::HostStatus {
    let reply = local_request(wire::HostLifecycleEnvelope::Challenge {
        request: request.clone(),
        certificate: certificate.clone(),
        purpose,
    });
    assert!(reply.error.is_none(), "{:?}", reply.error);
    let challenge = reply.challenge.unwrap();
    let reply = local_request(wire::HostLifecycleEnvelope::Execute {
        request,
        certificate: certificate.clone(),
        purpose,
        nonce: challenge.nonce,
        possession: sign(&challenge, manager),
    });
    assert!(reply.error.is_none(), "{:?}", reply.error);
    reply.status.unwrap()
}

struct Fixture {
    directory: std::path::PathBuf,
    boot: Bootstrap,
    identity: wire::RootImageIdentity,
    manager: SigningKey,
    scope: wire::OperationScope,
    certificate: wire::AcceptedOperationCertificate,
    proof: wire::ApprovalProof,
    core_server: Option<(
        std::sync::Arc<AtomicBool>,
        std::thread::JoinHandle<std::io::Result<()>>,
    )>,
    core_requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl Fixture {
    fn install(action: wire::OperationAction, core_mode: &str) -> Self {
        Self::install_with_administrator(
            action,
            core_mode,
            SigningKey::from_bytes(&[41; 32]),
            "host-command-instance",
        )
    }
    fn install_with_administrator(
        action: wire::OperationAction,
        core_mode: &str,
        administrator: SigningKey,
        instance: &str,
    ) -> Self {
        let directory = std::env::temp_dir().join(format!("hh-hc-{:08x}", rand::random::<u32>()));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(unix)]
        let endpoint = directory.join("h").to_string_lossy().into_owned();
        #[cfg(windows)]
        let endpoint = format!(
            r"\\.\pipe\hyperhub-host-command-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        );
        #[cfg(unix)]
        let control_endpoint = directory.join("c").to_string_lossy().into_owned();
        #[cfg(windows)]
        let control_endpoint = format!(
            r"\\.\pipe\hyperhub-command-core-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        );
        let core = SigningKey::from_bytes(&[42; 32]);
        let manager = SigningKey::from_bytes(&[43; 32]);
        let actual = wire::process_identity(std::process::id()).unwrap();
        let identity = wire::RootImageIdentity {
            pid: actual.pid,
            birth: actual.birth,
            executable_sha256: actual.executable_sha256,
        };
        let root = wire::RootImageState {
            identity: identity.clone(),
            exec_epoch: 0,
            observed_at_ms: 0,
            head: [0; 32],
        };
        let mut boot:Bootstrap=serde_json::from_value(serde_json::json!({
            "attachment_id":"live-host-command-test","session_id":"session","token":"t".repeat(64),"control_endpoint":control_endpoint,"socks_address":"127.0.0.1:1","tls_ca_pem":"-----BEGIN CERTIFICATE-----fixture",
            "observe":false,"firewall":null,"sandbox":null,"host_endpoint":endpoint,"host_token":"h".repeat(64),"scope_tree":false,"root_pid":identity.pid,
            "approval_authority_file":"unused","approval_instance_id":instance,"approval_public_key":administrator.verifying_key().to_bytes(),"approval_core_public_key":core.verifying_key().to_bytes(),"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":"c".repeat(64)
        })).unwrap();
        if core_mode == "trust" {
            boot.approval_root_identity = Some(identity.clone());
        }
        // This fixture isolates the live authentication/state machine. It does
        // not claim native Hook installation or RootImage attestation coverage.
        *crate::state().lock().unwrap() = crate::tests::configured_core();
        {
            let mut state = crate::state().lock().unwrap();
            state.session.control_endpoint = boot.control_endpoint.clone();
            state.session.session_id = boot.session_id.clone();
            state.session.token = boot.token.clone();
        }
        crate::state().lock().unwrap().gateway.root_image = Some(root.clone());
        if core_mode == "trust" {
            crate::state().lock().unwrap().gateway.namespace =
                crate::alias_namespace::Namespace::from_bootstrap(&boot);
        }
        *bootstrap_slot().lock().unwrap() = Some(boot.clone());
        SNAPSHOT.store(Box::into_raw(Box::new(boot.clone())), Ordering::Release);
        OWNER_PID.store(std::process::id(), Ordering::Release);
        ROOT_PID.store(identity.pid, Ordering::Release);
        PHASE.store(
            if action == wire::OperationAction::Attach {
                1
            } else {
                2
            },
            Ordering::Release,
        );
        NATIVE_READY.store(true, Ordering::Release);
        if action == wire::OperationAction::Detach {
            mark_active();
        }
        pin_approval_key(administrator.verifying_key().to_bytes()).unwrap();
        if core_mode == "trust" {
            crate::root_image::accept_snapshot(
                &boot,
                &signed_root(&boot, &root, [91; 32], &identity, &core),
                &[91; 32],
                &identity,
                None,
            )
            .unwrap();
        }
        let (proof, scope, certificate) =
            authorization(&boot, root.clone(), &administrator, &core, &manager, action);
        let core_requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let core_server = if core_mode != "missing" {
            let listener = wire::Listener::bind(&boot.control_endpoint).unwrap();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let server_stop = stop.clone();
            let server_boot = boot.clone();
            let server_identity = identity.clone();
            let count = core_requests.clone();
            let trust = core_mode == "trust";
            let handle = std::thread::spawn(move || {
                listener.run_raw(&server_stop, |request| {
                if !trust { return serde_json::json!({"type":"error","message":"fixture explicitly rejected policy refresh"}); }
                count.fetch_add(1, Ordering::AcqRel);
                match request.get("type").and_then(|value| value.as_str()) {
                    Some("get_trust") => serde_json::json!({"type":"trust_bootstrap","socks_address":"127.0.0.1:1","agent_flags":{"observe":false},"environment":[],"tls_ca_pem":"-----BEGIN CERTIFICATE-----fixture","firewall":null,"sandbox":null}),
                    Some("register_alias_host") => {
                        let challenge: [u8;32] = serde_json::from_value(request["root_image_challenge"].clone()).unwrap();
                        serde_json::json!({"type":"alias_host_registration","ready":true,"snapshot":null,"proof":null,"root_image":signed_root(&server_boot,&root,challenge,&server_identity,&core)})
                    }
                    _ => serde_json::json!({"type":"error","message":"unexpected fixture request"}),
                }
            })
            });
            Some((stop, handle))
        } else {
            None
        };
        start_server().unwrap();
        Self {
            directory,
            boot,
            identity,
            manager,
            scope,
            certificate,
            proof,
            core_server,
            core_requests,
        }
    }
    fn request(&self, command: HostCommand) -> AuthenticatedCommand {
        AuthenticatedCommand {
            attachment_id: self.boot.attachment_id.clone(),
            token: self.boot.host_token.clone(),
            command,
            proof: Some(self.proof.clone()),
            enrollment: None,
            aliases: None,
            root_image: None,
        }
    }
    fn raw(&self, envelope: wire::HostLifecycleEnvelope) -> wire::HostLifecycleReply {
        serde_json::from_value(
            wire::exchange_raw_for_process(
                &self.boot.host_endpoint,
                &serde_json::to_value(envelope).unwrap(),
                self.identity.pid,
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn challenge(
        &self,
        command: HostCommand,
        purpose: wire::HostLifecycleCommand,
    ) -> wire::HostCommandChallenge {
        let reply = self.raw(wire::HostLifecycleEnvelope::Challenge {
            request: self.request(command),
            certificate: self.certificate.clone(),
            purpose,
        });
        assert!(reply.error.is_none(), "{:?}", reply.error);
        reply.challenge.unwrap()
    }
    fn execute(
        &self,
        request: AuthenticatedCommand,
        purpose: wire::HostLifecycleCommand,
        challenge: &wire::HostCommandChallenge,
        possession: wire::HostCommandPossessionProof,
    ) -> wire::HostLifecycleReply {
        self.raw(wire::HostLifecycleEnvelope::Execute {
            request,
            certificate: self.certificate.clone(),
            purpose,
            nonce: challenge.nonce,
            possession,
        })
    }
    fn roundtrip(
        &self,
        command: HostCommand,
        purpose: wire::HostLifecycleCommand,
    ) -> std::io::Result<HostStatus> {
        let request = self.request(command);
        wire::exchange_lifecycle_for_process(
            &self.boot.host_endpoint,
            &request,
            &self.certificate,
            purpose,
            self.identity.pid,
            self.identity.birth,
            |challenge| {
                wire::validate_host_command_challenge(
                    challenge,
                    &request,
                    &self.scope,
                    &self.certificate,
                    now_ms(),
                )?;
                Ok(sign(challenge, &self.manager))
            },
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        STOP_SERVER.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(3);
        while SERVER_STARTED.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        if SERVER_STARTED.load(Ordering::Acquire) {
            eprintln!(
                "test Host cleanup remains pending at {}",
                self.directory.display()
            );
            if !std::thread::panicking() {
                panic!("test Host listener did not stop");
            }
            return;
        }
        if let Some((stop, handle)) = self.core_server.take() {
            stop.store(true, Ordering::Release);
            let result = handle.join();
            if !std::thread::panicking() {
                result.unwrap().unwrap();
            }
        }
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn isolated(test: &str, mode: &str, seconds: u64) {
    let filter = format!("{}::{test}", module_path!().split_once("::").unwrap().1);
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.env_clear();
    for (name, value) in std::env::vars_os() {
        if matches!(
            name.to_string_lossy().to_ascii_uppercase().as_str(),
            "SYSTEMROOT"
                | "WINDIR"
                | "COMSPEC"
                | "PATH"
                | "PATHEXT"
                | "TMP"
                | "TEMP"
                | "TMPDIR"
                | "LD_LIBRARY_PATH"
                | "DYLD_LIBRARY_PATH"
        ) {
            command.env(name, value);
        }
    }
    let mut child = command
        .env("HH_TEST_HOST_COMMAND_CHILD", mode)
        .args(["--exact", &filter, "--test-threads=1"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let completed = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            break false;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let output = child.wait_with_output().unwrap();
    assert!(
        completed && output.status.success(),
        "receiver {mode} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn actual_receiver_requires_possession_and_rejects_replay_after_real_state_aba() {
    let Some(mode) = std::env::var("HH_TEST_HOST_COMMAND_CHILD").ok() else {
        for mode in [
            "commands",
            "aba",
            "abort",
            "transport_abort",
            "memo",
            "memo_invalidated",
            "engine_abort",
            "issuer",
            "cache",
        ] {
            if mode == "engine_abort"
                && !cfg!(all(
                    any(windows, target_os = "linux"),
                    feature = "gum-agent"
                ))
            {
                continue;
            }
            isolated(
                "actual_receiver_requires_possession_and_rejects_replay_after_real_state_aba",
                mode,
                if mode == "cache" { 40 } else { 20 },
            );
        }
        return;
    };
    use wire::HostLifecycleCommand as L;
    let fixture = Fixture::install(
        if matches!(
            mode.as_str(),
            "abort" | "transport_abort" | "memo" | "memo_invalidated" | "engine_abort"
        ) {
            wire::OperationAction::Attach
        } else {
            wire::OperationAction::Detach
        },
        match mode.as_str() {
            "abort" => "reject",
            "memo" | "memo_invalidated" | "engine_abort" | "cache" => "trust",
            _ => "missing",
        },
    );
    let _native_return = super::super::enter(); // Keep this protocol fixture resident.
    if mode == "commands" {
        let mut request = fixture.request(HostCommand::PrepareDetachment);
        assert!(wire::exchange_for_process(
            &fixture.boot.host_endpoint,
            &request,
            fixture.identity.pid
        )
        .is_err());
        request.proof = None;
        assert!(wire::exchange_for_process(
            &fixture.boot.host_endpoint,
            &request,
            fixture.identity.pid
        )
        .is_err());
        let challenge = fixture.challenge(HostCommand::PrepareDetachment, L::PrepareDetachment);
        let valid = sign(&challenge, &fixture.manager);
        let wrong = sign(&challenge, &SigningKey::from_bytes(&[44; 32]));
        assert!(fixture
            .execute(
                fixture.request(HostCommand::PrepareDetachment),
                L::PrepareDetachment,
                &challenge,
                wrong
            )
            .error
            .is_some());
        for field in ["host_pid", "host_birth", "host_epoch"] {
            let mut other = challenge.clone();
            match field {
                "host_pid" => other.host_pid += 1,
                "host_birth" => other.host_birth += 1,
                "host_epoch" => other.host_epoch[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                fixture
                    .execute(
                        fixture.request(HostCommand::PrepareDetachment),
                        L::PrepareDetachment,
                        &challenge,
                        sign(&other, &fixture.manager)
                    )
                    .error
                    .is_some(),
                "{field}"
            );
        }
        let reply = fixture.execute(
            fixture.request(HostCommand::PrepareDetachment),
            L::PrepareDetachment,
            &challenge,
            valid.clone(),
        );
        assert!(reply.error.is_none(), "{:?}", reply.error);
        assert!(reply.status.unwrap().alias_publication_paused);
        let epoch = STATE_EPOCH.load(Ordering::Acquire);
        assert!(fixture
            .execute(
                fixture.request(HostCommand::PrepareDetachment),
                L::PrepareDetachment,
                &challenge,
                valid
            )
            .error
            .is_none());
        assert_eq!(
            STATE_EPOCH.load(Ordering::Acquire),
            epoch,
            "exact retry must not repeat the mutation"
        );
        assert!(
            !fixture
                .roundtrip(
                    HostCommand::CancelDetachmentPreparation,
                    L::CancelDetachmentPreparation
                )
                .unwrap()
                .alias_publication_paused
        );
    } else if mode == "aba" {
        let old = fixture.challenge(HostCommand::Detach, L::Detach);
        let signed = sign(&old, &fixture.manager);
        let epoch = STATE_EPOCH.load(Ordering::Acquire);
        assert!(
            fixture
                .roundtrip(HostCommand::PrepareDetachment, L::PrepareDetachment)
                .unwrap()
                .alias_publication_paused
        );
        assert!(
            !fixture
                .roundtrip(
                    HostCommand::CancelDetachmentPreparation,
                    L::CancelDetachmentPreparation
                )
                .unwrap()
                .alias_publication_paused
        );
        assert_eq!(STATE_EPOCH.load(Ordering::Acquire), epoch + 2);
        assert_eq!(status_phase(), HostPhase::Active);
        assert!(fixture
            .execute(
                fixture.request(HostCommand::Detach),
                L::Detach,
                &old,
                signed
            )
            .error
            .is_some());
        assert_eq!(
            fixture
                .roundtrip(HostCommand::Detach, L::Detach)
                .unwrap()
                .phase,
            HostPhase::DetachedResident
        );
    } else if mode == "issuer" {
        DETACH_CUTOFF_MS.store(now_ms(), Ordering::Release);
        let reply = fixture.raw(wire::HostLifecycleEnvelope::Challenge {
            request: fixture.request(HostCommand::PrepareDetachment),
            certificate: fixture.certificate.clone(),
            purpose: L::PrepareDetachment,
        });
        assert!(reply.error.unwrap().contains("current detach epoch"));
        assert!(
            slot(&REGISTRY).lock().unwrap().is_none(),
            "rejected old evidence must not create a nonce registry"
        );
        DETACH_CUTOFF_MS.store(0, Ordering::Release);
        let claims = wire::verify_proof_with_key(
            &fixture.boot,
            &approval_public_key().unwrap(),
            &fixture.proof,
            now_ms(),
        )
        .unwrap();
        history()
            .lock()
            .unwrap()
            .seen
            .insert(claims.nonce, claims.expires_at_ms);
        let reply = fixture.raw(wire::HostLifecycleEnvelope::Challenge {
            request: fixture.request(HostCommand::PrepareDetachment),
            certificate: fixture.certificate.clone(),
            purpose: L::PrepareDetachment,
        });
        assert!(reply.error.unwrap().contains("another accepted operation"));
        history().lock().unwrap().seen.clear();
        for field in ["enrollment", "aliases", "root_image"] {
            let mut request = fixture.request(HostCommand::PrepareDetachment);
            match field {
                "enrollment" => {
                    request.enrollment = Some(wire::ApprovalRootCertificate {
                        payload: vec![1],
                        signature: vec![2; 64],
                    })
                }
                "aliases" => {
                    request.aliases = Some(wire::SignedSessionAliasSnapshot {
                        payload: vec![1],
                        signature: vec![2; 64],
                    })
                }
                "root_image" => {
                    request.root_image = Some(wire::SignedRootImage {
                        payload: vec![1],
                        signature: vec![2; 64],
                    })
                }
                _ => unreachable!(),
            }
            let reply = fixture.raw(wire::HostLifecycleEnvelope::Challenge {
                request,
                certificate: fixture.certificate.clone(),
                purpose: L::PrepareDetachment,
            });
            assert!(reply.error.is_some(), "{field}");
        }
        assert!(
            fixture
                .roundtrip(HostCommand::PrepareDetachment, L::PrepareDetachment)
                .unwrap()
                .alias_publication_paused
        );
    } else if mode == "cache" {
        assert_eq!(
            crate::root_image::self_identity().unwrap(),
            fixture.identity
        );
        for field in ["pid", "birth", "missing", "unchallenged"] {
            {
                let mut state = crate::state().lock().unwrap();
                state.gateway.self_image = Some(fixture.identity.clone());
                state.gateway.root_image_challenged = true;
                match field {
                    "pid" => state.gateway.self_image.as_mut().unwrap().pid += 1,
                    "birth" => state.gateway.self_image.as_mut().unwrap().birth += 1,
                    "missing" => state.gateway.self_image = None,
                    "unchallenged" => state.gateway.root_image_challenged = false,
                    _ => unreachable!(),
                }
            }
            assert_eq!(
                crate::root_image::self_identity().unwrap(),
                fixture.identity,
                "{field} must use actual full executable verification"
            );
        }
    } else if mode == "engine_abort" {
        STOP_BACKGROUND.store(true, Ordering::Release);
        for _ in 0..2 {
            let challenge = fixture.challenge(HostCommand::Activate, L::Activate);
            let failed = fixture.execute(
                fixture.request(HostCommand::Activate),
                L::Activate,
                &challenge,
                sign(&challenge, &fixture.manager),
            );
            assert!(failed.error.unwrap().contains("cannot reenroll attachment"));
            assert!(
                STOP_BACKGROUND.load(Ordering::Acquire),
                "failed Engine enrollment must remain required for a fresh retry"
            );
            assert_eq!(status_phase(), HostPhase::Preparing);
        }
        assert_eq!(
            fixture.core_requests.load(Ordering::Acquire),
            4,
            "both attempts must request trust and Engine bootstrap"
        );
    } else if mode.starts_with("memo") {
        let challenge = fixture.challenge(HostCommand::Activate, L::Activate);
        let failed = fixture.execute(
            fixture.request(HostCommand::Activate),
            L::Activate,
            &challenge,
            sign(&challenge, &fixture.manager),
        );
        assert!(failed
            .error
            .unwrap()
            .starts_with("Host lifecycle state changed:"));
        assert_eq!(status_phase(), HostPhase::Preparing);
        assert_eq!(fixture.core_requests.load(Ordering::Acquire), 2);
        if mode == "memo_invalidated" {
            with_state_mutation(|| Ok(())).unwrap();
            let again = fixture.challenge(HostCommand::Activate, L::Activate);
            let failed = fixture.execute(
                fixture.request(HostCommand::Activate),
                L::Activate,
                &again,
                sign(&again, &fixture.manager),
            );
            assert!(failed
                .error
                .unwrap()
                .starts_with("Host lifecycle state changed:"));
            assert_eq!(fixture.core_requests.load(Ordering::Acquire), 4);
        }
        let retry = fixture.challenge(HostCommand::Activate, L::Activate);
        assert_ne!(retry.nonce, challenge.nonce);
        let calls = fixture.core_requests.load(Ordering::Acquire);
        let active = fixture.execute(
            fixture.request(HostCommand::Activate),
            L::Activate,
            &retry,
            sign(&retry, &fixture.manager),
        );
        assert!(active.error.is_none(), "{:?}", active.error);
        assert_eq!(active.status.unwrap().phase, HostPhase::Active);
        assert_eq!(
            fixture.core_requests.load(Ordering::Acquire),
            calls,
            "fresh proof may reuse only exact completed preparation"
        );
    } else {
        let challenge = fixture.challenge(HostCommand::Activate, L::Activate);
        let signed = sign(&challenge, &fixture.manager);
        let started = Instant::now();
        let failed = fixture.execute(
            fixture.request(HostCommand::Activate),
            L::Activate,
            &challenge,
            signed.clone(),
        );
        assert!(failed
            .error
            .unwrap()
            .contains("cannot refresh attachment policy"));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "a failed preparation must reply before the Host transport deadline"
        );
        assert_eq!(status_phase(), HostPhase::Preparing);
        assert!(fixture
            .execute(
                fixture.request(HostCommand::Activate),
                L::Activate,
                &challenge,
                signed
            )
            .error
            .is_some());
        let retry = fixture.challenge(HostCommand::Activate, L::Activate);
        assert_ne!(retry.nonce, challenge.nonce);
        let registry = slot(&REGISTRY).lock().unwrap();
        assert_eq!(registry.as_ref().unwrap().accepted_digest(), None);
    }
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn actual_receiver_expires_unexecuted_challenge_and_allows_a_fresh_attempt() {
    if std::env::var("HH_TEST_HOST_COMMAND_CHILD").is_err() {
        isolated(
            "actual_receiver_expires_unexecuted_challenge_and_allows_a_fresh_attempt",
            "expiry",
            40,
        );
        return;
    }
    use wire::HostLifecycleCommand as L;
    let fixture = Fixture::install(wire::OperationAction::Detach, "missing");
    let _native_return = super::super::enter();
    let challenge = fixture.challenge(HostCommand::PrepareDetachment, L::PrepareDetachment);
    let signed = sign(&challenge, &fixture.manager);
    std::thread::sleep(Duration::from_millis(
        wire::HOST_COMMAND_CHALLENGE_LIFETIME_MS + 10,
    ));
    assert!(fixture
        .execute(
            fixture.request(HostCommand::PrepareDetachment),
            L::PrepareDetachment,
            &challenge,
            signed
        )
        .error
        .is_some());
    assert!(!ALIAS_ADMISSION_PAUSED.load(Ordering::Acquire));
    let retry = fixture.challenge(HostCommand::PrepareDetachment, L::PrepareDetachment);
    assert_ne!(retry.nonce, challenge.nonce);
    assert!(fixture
        .execute(
            fixture.request(HostCommand::PrepareDetachment),
            L::PrepareDetachment,
            &retry,
            sign(&retry, &fixture.manager)
        )
        .error
        .is_none());
}

#[cfg(any(windows, target_os = "linux"))]
#[test]
fn real_password_saves_advance_surviving_sdk_listener_twice_without_activation() {
    if std::env::var("HH_TEST_HOST_COMMAND_CHILD").ok().as_deref() != Some("password-continuity") {
        isolated(
            "real_password_saves_advance_surviving_sdk_listener_twice_without_activation",
            "password-continuity",
            45,
        );
        return;
    }
    use hyperhub_core::{config::Config, config_store as store};
    let private =
        std::env::temp_dir().join(format!("hh-password-chain-{:016x}", rand::random::<u64>()));
    std::fs::create_dir(&private).unwrap();
    let path = private.join("config.bin");
    let descriptor = || {
        let mut d = store::new_descriptor();
        d.memory_kib = 8192;
        d.iterations = 1;
        d
    };
    let passwords: [&[u8]; 3] = [
        b"private-fixture-password-a",
        b"private-fixture-password-b",
        b"private-fixture-password-c",
    ];
    let initial = store::ConfigKeyring::derive(passwords[0], descriptor()).unwrap();
    store::save_encrypted_with_keyring(&path, &Config::default(), &initial).unwrap();
    let signing_key = |password: &[u8], descriptor: &store::KdfDescriptor| {
        // Reconstruct this fixture's known password domain through the public
        // password KDF. The original runtime master cannot derive this seed.
        // Keep the production signing seed API private.
        let mut separated = descriptor.clone();
        let mut hash = Sha256::new();
        hash.update(b"hyperhub/runtime-attachment-approval/v1\0");
        hash.update(descriptor.salt);
        hash.update(descriptor.config_id);
        separated.salt.copy_from_slice(&hash.finalize()[..16]);
        let seed = store::ConfigKeyring::derive(password, separated)
            .unwrap()
            .runtime_master();
        SigningKey::from_bytes(seed.as_slice().try_into().unwrap())
    };
    let first_key = signing_key(passwords[0], initial.descriptor());
    let fixture = Fixture::install_with_administrator(
        wire::OperationAction::Detach,
        "missing",
        first_key,
        &hyperhub_core::attachments::instance_id(&path, initial.descriptor()),
    );
    let exchange = |command, enrollment| {
        wire::exchange_for_process(
            &fixture.boot.host_endpoint,
            &AuthenticatedCommand {
                attachment_id: fixture.boot.attachment_id.clone(),
                token: fixture.boot.host_token.clone(),
                command,
                proof: None,
                enrollment,
                aliases: None,
                root_image: None,
            },
            fixture.identity.pid,
        )
    };
    let original = exchange(HostCommand::Status, None).unwrap();
    assert_eq!(original.phase, HostPhase::Active);
    let immutable_binding = fixture.boot.approval_binding().unwrap();
    let mut previous_proof = fixture.proof.clone();
    let mut first_generation = None;
    let application_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut application_client =
        std::net::TcpStream::connect(application_listener.local_addr().unwrap()).unwrap();
    let (mut application_peer, _) = application_listener.accept().unwrap();
    for rotation in 1..=2 {
        let ring = store::ConfigKeyring::derive(passwords[rotation], descriptor())
            .unwrap()
            .with_password_rotation(&path, passwords[rotation - 1], passwords[rotation])
            .unwrap();
        let before = exchange(HostCommand::Status, None).unwrap();
        let committed_bytes = std::fs::read(&path).unwrap();
        let wrong_guard = hyperhub_core::attachments::OperationGuard::acquire(
            &private.join("different-instance"),
        )
        .unwrap();
        assert!(store::save_encrypted_with_keyring_guarded(
            &path,
            &Config::default(),
            &ring,
            &wrong_guard
        )
        .is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            committed_bytes,
            "failed save preserves current config and chain"
        );
        drop(wrong_guard);
        let challenge = exchange(HostCommand::EnrollmentChallenge, None)
            .unwrap()
            .approval_challenge
            .unwrap();
        // Preparing a candidate cannot issue a certificate from an uncommitted
        // password, even with a real living Host challenge already available.
        assert!(store::approval_rotation_certificate(
            &path,
            passwords[rotation],
            &fixture.boot,
            &challenge,
            now_ms()
        )
        .is_err());
        assert_eq!(
            exchange(HostCommand::Status, None)
                .unwrap()
                .approval_public_key,
            before.approval_public_key
        );
        store::save_encrypted_with_keyring(&path, &Config::default(), &ring).unwrap();
        let certificate = store::approval_rotation_certificate(
            &path,
            passwords[rotation],
            &fixture.boot,
            &challenge,
            now_ms(),
        )
        .unwrap();
        let mut wrong_scope = fixture.boot.clone();
        wrong_scope.approval_instance_id.push('x');
        assert!(store::approval_rotation_certificate(
            &path,
            passwords[rotation],
            &wrong_scope,
            &challenge,
            now_ms()
        )
        .is_err());
        let changed = exchange(HostCommand::EnrollApprovalRoot, Some(certificate.clone())).unwrap();
        assert_eq!(changed.phase, original.phase);
        assert_eq!(changed.native_ready, original.native_ready);
        assert_eq!(changed.tracked_sockets, original.tracked_sockets);
        use std::io::{Read, Write};
        application_client.write_all(&[rotation as u8]).unwrap();
        let mut echo = [0];
        application_peer.read_exact(&mut echo).unwrap();
        assert_eq!(
            echo,
            [rotation as u8],
            "existing business stream remains open"
        );
        assert_eq!(fixture.boot.approval_binding().unwrap(), immutable_binding);
        let loaded = store::load_encrypted(&path, passwords[rotation]).unwrap();
        assert_eq!(changed.approval_public_key, loaded.approval_public_key);
        assert_eq!(APPROVAL_GENERATION.load(Ordering::Acquire), rotation as u64);
        assert!(
            exchange(HostCommand::EnrollApprovalRoot, Some(certificate)).is_err(),
            "consumed nonce replay"
        );
        let key = signing_key(passwords[rotation], &loaded.descriptor);
        let root = crate::root_image::current().unwrap();
        let core = SigningKey::from_bytes(&[42; 32]);
        let (fresh, _, _) = authorization(
            &fixture.boot,
            root,
            &key,
            &core,
            &fixture.manager,
            wire::OperationAction::Detach,
        );
        assert!(wire::verify_proof_with_key(
            &fixture.boot,
            &approval_public_key().unwrap(),
            &fresh,
            now_ms()
        )
        .is_ok());
        assert!(
            wire::verify_proof_with_key(
                &fixture.boot,
                &approval_public_key().unwrap(),
                &previous_proof,
                now_ms()
            )
            .is_err(),
            "old approval cannot cross a committed root transition"
        );
        let mut snapshot = fixture.request(HostCommand::SnapshotAliases);
        snapshot.proof = Some(fresh.clone());
        assert!(
            wire::exchange_for_process(
                &fixture.boot.host_endpoint,
                &snapshot,
                fixture.identity.pid
            )
            .is_ok(),
            "new approval is usable by the actual Host listener"
        );
        snapshot.proof = Some(previous_proof);
        assert!(
            wire::exchange_for_process(
                &fixture.boot.host_endpoint,
                &snapshot,
                fixture.identity.pid
            )
            .is_err(),
            "old approval rejected by the actual Host listener"
        );
        previous_proof = fresh;
        if rotation == 1 {
            first_generation = Some(std::fs::read(&path).unwrap());
        }
    }
    let latest = std::fs::read(&path).unwrap();
    store::save_private_bytes(&path, &first_generation.unwrap()).unwrap();
    let challenge = exchange(HostCommand::EnrollmentChallenge, None)
        .unwrap()
        .approval_challenge
        .unwrap();
    let rollback = store::approval_rotation_certificate(
        &path,
        passwords[1],
        &fixture.boot,
        &challenge,
        now_ms(),
    )
    .unwrap();
    let latest_key = approval_public_key().unwrap();
    assert!(
        exchange(HostCommand::EnrollApprovalRoot, Some(rollback)).is_err(),
        "a valid earlier committed config plus fresh nonce cannot roll Host back"
    );
    assert_eq!(approval_public_key(), Some(latest_key));
    store::save_private_bytes(&path, &latest).unwrap();
    assert_eq!(APPROVAL_GENERATION.load(Ordering::Acquire), 2);
    drop(fixture);
    std::fs::remove_dir_all(private).unwrap();
}
