// A mapped native base is not an initialized Host. Exercise the real exported
// entrypoint and its authenticated rollback transport without real credentials.
#[cfg(any(windows, target_os = "linux"))]
fn main() {
    if let Err(error) = native::run() {
        eprintln!("native init-failure fixture: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(any(windows, target_os = "linux")))]
fn main() {
    std::process::exit(77);
}
#[cfg(any(windows, target_os = "linux"))]
mod native {
    use ed25519_dalek::{Signer, SigningKey};
    use hyperhub_runtime::attachment as wire;
    use sha2::{Digest, Sha256};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
    fn authorization(
        boot: &wire::Bootstrap,
        admin: &SigningKey,
        core: &SigningKey,
        manager: &SigningKey,
        action: wire::OperationAction,
    ) -> Result<(wire::ApprovalProof, wire::AcceptedOperationCertificate)> {
        let stamp = now();
        let identity = wire::process_identity(std::process::id())?;
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
        let claimant = wire::ManagerClaimant {
            pid: identity.pid,
            birth: identity.birth,
            role_epoch: [11; 32],
            public_key: manager.verifying_key().to_bytes(),
        };
        let target = serde_json::to_value(&root.identity)?;
        let operation = match action {
            wire::OperationAction::Attach => {
                serde_json::json!({"kind":"attach","spec":{"id":boot.attachment_id,"scope":"process","target":target,"exec_epoch":0}})
            }
            wire::OperationAction::Detach => {
                serde_json::json!({"kind":"detach","attachment_id":boot.attachment_id,"target":target,"exec_epoch":0})
            }
        };
        let value = serde_json::json!({"request":{"schema_version":1,"instance_id":boot.approval_instance_id,"action":operation},
            "approved_at_ms":stamp,"expires_at_ms":stamp+60_000,"nonce":vec![if action==wire::OperationAction::Attach {8} else {9};32],
            "executor_sha256":"e".repeat(64),"execution_digest":"d".repeat(64),"host_binding":boot.approval_binding()?,
            "core_attestation_public_key":core.verifying_key().to_bytes(),"manager_claimant":claimant});
        let mut payload = b"hyperhub/runtime-attachment-approval/v1\0".to_vec();
        payload.extend(serde_json::to_vec(&value)?);
        let proof = wire::ApprovalProof {
            signature: admin.sign(&payload).to_bytes().to_vec(),
            payload,
        };
        wire::verify_proof(boot, &proof, now())?;
        let scope = wire::OperationScope {
            action,
            administrator_digest: wire::operation_administrator_digest(&proof)?,
            instance_id: boot.approval_instance_id.clone(),
            attachment_id: boot.attachment_id.clone(),
            session_id: boot.session_id.clone(),
            credential_digest: Sha256::digest(boot.token.as_bytes()).into(),
            host_binding: boot.approval_binding()?,
            root_image: root,
            claimant,
            core_public_key: core.verifying_key().to_bytes(),
        };
        let payload = wire::encode_accepted_operation(&wire::AcceptedOperationPayload {
            schema_version: 1,
            challenge: wire::PossessionChallenge {
                schema_version: 1,
                scope,
                nonce: [13; 32],
                issued_at_ms: stamp,
                expires_at_ms: stamp + 30_000,
            },
            accepted_at_ms: stamp,
        })?;
        let certificate = wire::AcceptedOperationCertificate {
            signature: core.sign(&payload).to_bytes().to_vec(),
            payload,
        };
        Ok((proof, certificate))
    }
    fn lifecycle(
        endpoint: &str,
        request: wire::AuthenticatedCommand,
        certificate: &wire::AcceptedOperationCertificate,
        manager: &SigningKey,
        purpose: wire::HostLifecycleCommand,
    ) -> Result<wire::HostStatus> {
        let raw = wire::exchange_raw_for_process(
            endpoint,
            &serde_json::to_value(wire::HostLifecycleEnvelope::Challenge {
                request: request.clone(),
                certificate: certificate.clone(),
                purpose,
            })?,
            std::process::id(),
        )?;
        let reply: wire::HostLifecycleReply = serde_json::from_value(raw)?;
        if let Some(error) = reply.error {
            return Err(error.into());
        }
        let challenge = reply.challenge.ok_or("missing Host challenge")?;
        let payload = wire::encode_host_command_challenge(&challenge)?;
        let possession = wire::HostCommandPossessionProof {
            signature: manager.sign(&payload).to_bytes().to_vec(),
            payload,
        };
        let raw = wire::exchange_raw_for_process(
            endpoint,
            &serde_json::to_value(wire::HostLifecycleEnvelope::Execute {
                request,
                certificate: certificate.clone(),
                purpose,
                nonce: challenge.nonce,
                possession,
            })?,
            std::process::id(),
        )?;
        let reply: wire::HostLifecycleReply = serde_json::from_value(raw)?;
        if let Some(error) = reply.error {
            return Err(error.into());
        }
        Ok(reply.status.ok_or("missing Host status")?)
    }
    pub fn run() -> Result<()> {
        let library_path = std::path::PathBuf::from(
            std::env::args_os()
                .nth(1)
                .ok_or("expected an absolute native Agent path")?,
        );
        if !library_path.is_absolute() {
            return Err("native Agent path must be absolute".into());
        }
        let mode = std::env::args().nth(2).unwrap_or_else(|| "engine".into());
        if !matches!(mode.as_str(), "engine" | "missing-pin" | "host-bind") {
            return Err("unknown fixture mode".into());
        }
        #[cfg(windows)]
        if mode != "engine" {
            return Err("fault mode is Linux-only".into());
        }
        let pid = std::process::id();
        let stamp = now();
        let identifier = format!("native-init-failure-{pid}-{stamp}");
        let directory = std::env::temp_dir().join(&identifier);
        std::fs::create_dir(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(windows)]
        let control = format!(r"\\.\pipe\hh-failed-init-core-{pid}-{stamp}");
        #[cfg(windows)]
        let endpoint = format!(r"\\.\pipe\hh-failed-init-host-{pid}-{stamp}");
        #[cfg(target_os = "linux")]
        let control = directory.join("core.sock").to_string_lossy().into_owned();
        #[cfg(target_os = "linux")]
        let endpoint = directory.join("host.sock").to_string_lossy().into_owned();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let listener = wire::Listener::bind(&control)?;
        let server = std::thread::spawn(move || {
            listener.run_raw(&server_stop, |request| {
                observed.fetch_add(1, Ordering::SeqCst);
                #[cfg(target_os = "linux")]
                if request.get("type").and_then(|v| v.as_str()) == Some("register_child") {
                    return serde_json::json!({"type":"ok"});
                }
                let _ = request;
                serde_json::json!({"type":"error","message":"fixture Core refuses fresh work"})
            })
        });
        let admin = SigningKey::from_bytes(&[53; 32]);
        let core = SigningKey::from_bytes(&[54; 32]);
        let manager = SigningKey::from_bytes(&[55; 32]);
        let incarnation = wire::process_incarnation(pid)?;
        let bootstrap = wire::Bootstrap {
            attachment_id: identifier.clone(),
            session_id: "disposable-fixture-session".into(),
            token: "t".repeat(64),
            control_endpoint: control,
            socks_address: "127.0.0.1:1".into(),
            tls_ca_pem: "-----BEGIN CERTIFICATE-----fixture".into(),
            observe: false,
            firewall: Some(serde_json::json!({"invalid_fixture_snapshot":true})),
            sandbox: None,
            host_endpoint: endpoint.clone(),
            host_token: "h".repeat(64),
            scope_tree: false,
            root_pid: pid,
            approval_authority_file: "unused-fixture-discovery".into(),
            approval_instance_id: "native-init-fixture".into(),
            initially_owned: false,
            external_attachment: true,
            native_dns_mode: wire::NativeDnsMode::PreserveAnswers,
            approval_not_before_ms: 0,
            approval_public_key: Some(admin.verifying_key().to_bytes()),
            approval_inherited_public_key: None,
            approval_root_identity: None,
            alias_inherited: None,
            approval_core_public_key: Some(core.verifying_key().to_bytes()),
            approval_core_pid: pid,
            approval_core_birth: incarnation.birth,
            approval_cli_sha256: "c".repeat(64),
        };
        let library = unsafe { libloading::Library::new(&library_path)? };
        let recover = unsafe {
            *library
                .get::<unsafe extern "C" fn() -> i32>(b"hyperhub_attachment_recover_transport\0")?
        };
        #[cfg(windows)]
        {
            let start = unsafe {
                *library.get::<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(
                    b"hyperhub_attachment_start\0",
                )?
            };
            let json = serde_json::to_vec(&bootstrap)?;
            let mut input = (json.len() as u32).to_be_bytes().to_vec();
            input.extend(json);
            if unsafe { start(input.as_mut_ptr().cast()) } == 0 {
                return Err("invalid initialization unexpectedly succeeded".into());
            }
        }
        #[cfg(target_os = "linux")]
        {
            let start = unsafe {
                *library.get::<unsafe extern "C" fn(*const std::ffi::c_char, *mut u32)>(
                    b"frida_attachment_main\0",
                )?
            };
            let ready = directory.join("ready");
            // Force publication failure independently from native initialization.
            // The manager must recover from authenticated status, never this file.
            std::fs::write(directory.join("ready.pending"), b"private fixture conflict")?;
            if mode == "host-bind" {
                std::fs::write(&endpoint, b"private fixture conflict")?;
            }
            let runtime = if mode == "missing-pin" {
                directory.join("absent.so")
            } else {
                library_path.clone()
            };
            let input = std::ffi::CString::new(serde_json::to_vec(
                &serde_json::json!({"bootstrap":bootstrap,"ready_path":ready,"runtime_path":runtime,"fork_socket":directory.join("fork.sock"),"fork_secret":"f".repeat(64)}),
            )?)?;
            let mut resident = 0;
            unsafe { start(input.as_ptr(), &mut resident) };
            if resident != 1 || ready.exists() {
                return Err(
                    "failed initializer published a receipt or lost native residency".into(),
                );
            }
            if mode == "host-bind" {
                if unsafe { recover() } == 0 {
                    return Err("occupied endpoint unexpectedly rebound".into());
                }
                std::fs::remove_file(&endpoint)?;
            }
        }
        // Reopening is idempotent and cannot replace Bootstrap or run Engine.
        if unsafe { recover() } != 0 || unsafe { recover() } != 0 {
            return Err("bound recovery transport could not reopen".into());
        }
        std::mem::forget(library); // The authenticated Host owns live native code.
        let command = |kind, proof| wire::AuthenticatedCommand {
            attachment_id: bootstrap.attachment_id.clone(),
            token: bootstrap.host_token.clone(),
            command: kind,
            proof,
            enrollment: None,
            aliases: None,
            root_image: None,
        };
        let checked = (|| -> Result<()> {
            let before = wire::exchange_for_process(
                &endpoint,
                &command(wire::HostCommand::Status, None),
                pid,
            )?;
            let init = before
                .initialization
                .as_ref()
                .ok_or("missing startup evidence")?;
            if before.phase != wire::HostPhase::Preparing
                || before.native_ready
                || init.initializing
                || init.stage != wire::InitializationStage::Failed
                || init.origin != wire::InitializationOrigin::Fresh
                || init.ever_active
                || !init.runtime_available
            {
                return Err("failed base did not retain truthful unready startup evidence".into());
            }
            #[cfg(target_os = "linux")]
            if init.native_pin.is_some() != (mode == "engine") {
                return Err("native pin evidence differs from actual completed stage".into());
            }
            let prior = requests.load(Ordering::SeqCst);
            let (proof, certificate) = authorization(
                &bootstrap,
                &admin,
                &core,
                &manager,
                wire::OperationAction::Attach,
            )?;
            if lifecycle(
                &endpoint,
                command(wire::HostCommand::Activate, Some(proof)),
                &certificate,
                &manager,
                wire::HostLifecycleCommand::Activate,
            )
            .is_ok()
            {
                return Err("valid approval activated an unready base".into());
            }
            if requests.load(Ordering::SeqCst) != prior {
                return Err("unready activation contacted Core".into());
            }
            let (proof, certificate) = authorization(
                &bootstrap,
                &admin,
                &core,
                &manager,
                wire::OperationAction::Detach,
            )?;
            // A new Detach approval must clean an incomplete initial Attach;
            // neither root-image/alias catchup nor an expired old manager is needed.
            let paused = lifecycle(
                &endpoint,
                command(wire::HostCommand::PrepareDetachment, Some(proof.clone())),
                &certificate,
                &manager,
                wire::HostLifecycleCommand::PrepareDetachment,
            )?;
            if !paused.alias_publication_paused {
                return Err("startup cleanup barrier was not prepared".into());
            }
            let detached = lifecycle(
                &endpoint,
                command(wire::HostCommand::Detach, Some(proof)),
                &certificate,
                &manager,
                wire::HostLifecycleCommand::Detach,
            )?;
            if detached.phase != wire::HostPhase::DetachedResident
                || detached.native_ready
                || detached
                    .initialization
                    .as_ref()
                    .is_none_or(|i| i.initializing || !i.cancelled)
            {
                return Err(
                    "approved startup cancellation did not reach a stable policy-off terminal"
                        .into(),
                );
            }
            Ok(())
        })();
        stop.store(true, Ordering::Release);
        server.join().map_err(|_| "fake Core thread panicked")??;
        checked?;
        println!(
            "{}",
            serde_json::json!({"status":"pass","mode":mode,"initialization_failed":true,"native_ready":false,"phase":"preparing","fresh_control_requests":0,"approved_cleanup":true})
        );
        // Host lifetime ends with this disposable process; do not unlink its
        // live endpoint while callbacks may still observe it.
        Ok(())
    }
}
