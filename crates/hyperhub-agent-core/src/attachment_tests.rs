//! Lifecycle boundaries preserve native calls and process-local ownership.
#[cfg(unix)]
#[test]
fn fork_child_does_not_decrement_copied_call_or_background_guard() {
    let inherited = hyperhub_runtime::attachment::Bootstrap {
        attachment_id: "fixture-attachment".into(),
        session_id: "fixture-session".into(),
        token: "t".repeat(64),
        control_endpoint: "unused-control".into(),
        socks_address: "127.0.0.1:1".into(),
        tls_ca_pem: "-----BEGIN CERTIFICATE-----fixture".into(),
        observe: false,
        firewall: None,
        sandbox: None,
        host_endpoint: "unused-host".into(),
        host_token: "h".repeat(64),
        scope_tree: true,
        root_pid: std::process::id(),
        approval_authority_file: "/unused-authority".into(),
        approval_instance_id: "fixture-instance".into(),
        initially_owned: true,
        external_attachment: true,
        native_dns_mode: hyperhub_runtime::attachment::NativeDnsMode::PreserveAnswers,
        approval_not_before_ms: 0,
        approval_public_key: None,
        approval_inherited_public_key: None,
        approval_root_identity: None,
        alias_inherited: None,
        approval_core_public_key: None,
        approval_core_pid: 0,
        approval_core_birth: 0,
        approval_cli_sha256: "c".repeat(64),
    };
    let call = super::enter();
    let allocator_call = super::enter_allocator();
    let background = super::background_enter();
    let publication = super::begin_alias_publication();
    let child = unsafe { libc::fork() };
    assert!(
        child >= 0,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    if child == 0 {
        // Do not allocate, lock, run the harness, or invoke process destructors.
        // This is exactly the early atfork transition used by the native Host.
        // Isolate the nonzero epoch seed from the parallel test harness, then
        // exercise a second real fork with that inherited parent value.
        super::DETACH_CUTOFF_MS.store(200, std::sync::atomic::Ordering::Release);
        let descendant = unsafe { libc::fork() };
        if descendant == 0 {
            super::after_fork_child();
            // Rebuilt metadata updates OWNER_PID before the copied stack
            // guards drop; a stale startup floor still cannot lower the epoch.
            if super::initialize_rebuilt(&inherited).is_err() {
                unsafe {
                    libc::_exit(95);
                }
            }
            let copied_publication_rejected = !publication.may_publish();
            drop(call);
            drop(allocator_call);
            drop(background);
            drop(publication);
            // A prepared pause admits no new DNS work and does not consume
            // the accepted detach cutoff. Existing publications still drain.
            super::PHASE.store(2, std::sync::atomic::Ordering::Release);
            let admitted = super::try_alias_publication().unwrap();
            super::ALIAS_ADMISSION_PAUSED.store(true, std::sync::atomic::Ordering::SeqCst);
            let no_new_publication =
                super::try_alias_publication().is_none() && super::alias_publications() == 1;
            drop(admitted);
            let prepared_drained = no_new_publication
                && super::alias_publications() == 0
                && super::enforcing()
                && super::approval_not_before_ms() == 200;
            super::ALIAS_ADMISSION_PAUSED.store(false, std::sync::atomic::Ordering::SeqCst);
            let cancelled_reopens = super::try_alias_publication().is_some();
            let gateway = crate::GatewayState::default();
            let fresh_publication = super::begin_alias_publication();
            let pending_snapshot_rejected =
                super::snapshot_issued_aliases(&gateway).is_ok_and(|snapshot| !snapshot.complete);
            drop(fresh_publication);
            let completed_snapshot_ready =
                super::snapshot_issued_aliases(&gateway).is_ok_and(|snapshot| snapshot.complete);
            let correct = super::CALLS.load(std::sync::atomic::Ordering::Acquire) == 0
                && super::BACKGROUND.load(std::sync::atomic::Ordering::Acquire) == 0
                && super::CONTROL_BACKGROUND.load(std::sync::atomic::Ordering::Acquire) == 0
                && prepared_drained
                && cancelled_reopens
                && pending_snapshot_rejected
                && completed_snapshot_ready
                && copied_publication_rejected
                && super::alias_publications() == 0
                && super::approval_not_before_ms() == 200;
            unsafe {
                libc::_exit(if correct { 0 } else { 91 });
            }
        }
        if descendant < 0 {
            unsafe {
                libc::_exit(92);
            }
        }
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(descendant, &mut status, 0) };
            if result == descendant {
                break;
            }
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            if result < 0 {
                unsafe {
                    libc::_exit(93);
                }
            }
        }
        unsafe {
            libc::_exit(
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    0
                } else {
                    94
                },
            );
        }
    }
    drop(call);
    drop(allocator_call);
    drop(background);
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(child, &mut status, 0) };
        if result == child {
            break;
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        panic!("waitpid failed: {}", std::io::Error::last_os_error());
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "copied lifecycle guard corrupted child counters"
    );
}

#[test]
fn control_workers_stop_after_socket_drain_without_retiring_a_pending_native_call() {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    const CHILD: &str = "HH_TEST_ATTACHMENT_RETIREMENT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // A fresh process isolates global lifecycle state from parallel tests.
        // It receives OS runtime paths, rather than the caller's credentials.
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
        let filter = format!(
            "{}::control_workers_stop_after_socket_drain_without_retiring_a_pending_native_call",
            module_path!().split_once("::").unwrap().1
        );
        let mut child = command
            .env(CHILD, "1")
            .args(["--exact", &filter, "--test-threads=1"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
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
            "isolated retirement regression failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    *crate::state().lock().unwrap() = crate::tests::configured_core();
    super::PHASE.store(2, Ordering::Release);
    let pending_call = super::enter();
    assert_eq!(super::active_calls(), 1);
    super::try_retire();
    assert!(
        !super::stopping_background(),
        "Active hosts must retain control workers"
    );

    // This entry owns an actual Engine lease and connection identity, exactly
    // like a native adapter's prepared managed socket.
    crate::state()
        .lock()
        .unwrap()
        .prepare_connect(42, 2, &[203, 0, 113, 9], 443)
        .unwrap();
    let publication = super::begin_alias_publication();
    assert!(publication.admitted());
    let control_guard = super::background_enter();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        while !super::stopping_background() {
            std::thread::park_timeout(Duration::from_millis(1));
        }
        drop(control_guard);
        done_tx.send(()).unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    super::PHASE.store(4, Ordering::Release);
    super::try_retire();
    assert!(
        !super::stopping_background(),
        "a live old stream must retain its control context"
    );
    assert_eq!(crate::state().lock().unwrap().gateway.sockets.len(), 1);
    assert_eq!(super::CONTROL_BACKGROUND.load(Ordering::Acquire), 1);
    assert_eq!(crate::hh_agent_close_socket(42), crate::HH_OK);
    super::try_retire();
    assert!(
        !super::stopping_background(),
        "an admitted publication must finish before controls stop"
    );
    drop(publication);
    super::try_retire();
    assert!(
        super::stopping_background(),
        "a blocked application call must not retain drained control workers"
    );
    done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    worker.join().unwrap();
    assert_eq!(super::CONTROL_BACKGROUND.load(Ordering::Acquire), 0);
    assert_eq!(super::BACKGROUND.load(Ordering::Acquire), 0);
    assert_eq!(super::active_calls(), 1);
    let resident = super::status();
    assert_eq!(resident.phase, super::HostPhase::DetachedResident);
    assert_eq!(resident.active_calls, 1);
    assert!(resident
        .compatibility_reasons
        .iter()
        .any(|reason| reason == "active_hook_calls"));
    assert!(!super::CALLBACKS_RETIRED.load(Ordering::Acquire));
    assert!(!super::STATE_RETIRED.load(Ordering::Acquire));
    assert!(!super::unload_ready());
    assert!(crate::state().lock().unwrap().session.initialized);
    assert!(crate::state().lock().unwrap().gateway.sockets.is_empty());
    drop(pending_call);
    assert_eq!(super::active_calls(), 0);
}

#[test]
fn fresh_child_cannot_replay_unseen_root_attach_proof_after_detach() {
    use hyperhub_runtime::attachment::ApprovedAction;
    // An internally activated child has not consumed its parent's initial nonce.
    // Its first accepted detach still closes all older attach approval epochs.
    let history = super::History {
        last_detach_at: 200,
        ..Default::default()
    };
    assert!(history.seen.is_empty());
    assert!(!super::attachment_epoch_allows(
        ApprovedAction::Attach,
        100,
        history.last_detach_at
    ));
    assert!(!super::attachment_epoch_allows(
        ApprovedAction::Attach,
        200,
        history.last_detach_at
    ));
    assert!(super::attachment_epoch_allows(
        ApprovedAction::Attach,
        201,
        history.last_detach_at
    ));
    assert!(!super::attachment_epoch_allows(
        ApprovedAction::Detach,
        200,
        history.last_detach_at
    ));
}

#[test]
fn retired_runtime_storage_is_released_only_after_last_reader_and_is_never_reopened() {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    const CHILD: &str = "HH_TEST_RUNTIME_RETIREMENT_CHILD";
    let mode = std::env::var(CHILD).ok();
    if mode.is_none() {
        for mode in ["sdk", "host", "fork"] {
            // Dynamic Host identity is an explicit Linux/Windows alpha
            // contract. SDK storage and Unix fork protection still run here.
            if mode == "host" && !cfg!(any(windows, target_os = "linux")) {
                continue;
            }
            if mode == "fork" && !cfg!(unix) {
                continue;
            }
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
            let filter=format!("{}::retired_runtime_storage_is_released_only_after_last_reader_and_is_never_reopened",module_path!().split_once("::").unwrap().1);
            let mut child = command
                .env(CHILD, mode)
                .args(["--exact", &filter, "--test-threads=1"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(15);
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
                "retirement {mode} failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    }
    *crate::state().lock().unwrap() = crate::tests::configured_core();
    let boot:hyperhub_runtime::attachment::Bootstrap=serde_json::from_value(serde_json::json!({
        "attachment_id":"runtime-retirement","session_id":"session","token":"t".repeat(64),"control_endpoint":"unused-control","socks_address":"127.0.0.1:1","tls_ca_pem":"-----BEGIN CERTIFICATE-----fixture",
        "observe":false,"firewall":null,"sandbox":null,"host_endpoint":"unused-host","host_token":"h".repeat(64),"scope_tree":false,"root_pid":std::process::id(),
        "approval_authority_file":"unused","approval_instance_id":"retirement-instance","approval_public_key":null,"approval_core_public_key":null,"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":"c".repeat(64)
    })).unwrap();
    if mode.as_deref() == Some("fork") {
        #[cfg(unix)]
        {
            let sdk = crate::runtime::sdk_access().unwrap();
            let host = crate::runtime::host_access().unwrap();
            assert!(!crate::runtime::close_sdk_access());
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                crate::runtime::after_fork_child();
                drop(sdk);
                drop(host);
                let correct = crate::runtime::access_user_counts() == (0, 0)
                    && crate::runtime::sdk_access().is_none()
                    && super::initialize_rebuilt(&boot) == Err(crate::HH_ERR_NOT_INITIALIZED);
                unsafe {
                    libc::_exit(if correct { 0 } else { 91 });
                }
            }
            drop(sdk);
            drop(host);
            let mut status = 0;
            loop {
                let waited = unsafe { libc::waitpid(child, &mut status, 0) };
                if waited == child {
                    break;
                }
                if waited < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                panic!("waitpid failed");
            }
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
        return;
    }
    if mode.as_deref() == Some("sdk") {
        let sdk = crate::runtime::sdk_access().unwrap();
        assert!(unsafe { crate::runtime::retire_attachment_state() }.is_err());
        assert!(crate::runtime::storage_present());
        assert!(crate::state().lock().unwrap().session.initialized);
        assert_eq!(
            crate::hh_agent_is_initialized(),
            crate::HH_ERR_NOT_INITIALIZED
        );
        drop(sdk);
        unsafe { crate::runtime::retire_attachment_state() }.unwrap();
    } else {
        use ed25519_dalek::SigningKey;
        use hyperhub_runtime::attachment::{AuthenticatedCommand, HostCommand};
        *super::bootstrap_slot().lock().unwrap() = Some(boot.clone());
        super::SNAPSHOT.store(Box::into_raw(Box::new(boot.clone())), Ordering::Release);
        super::OWNER_PID.store(std::process::id(), Ordering::Release);
        super::PHASE.store(4, Ordering::Release);
        // Simulate an already proven native retirement boundary. This test
        // exercises storage ordering, not OS hook/unload proof.
        super::CALLBACKS_RETIRED.store(true, Ordering::Release);
        assert!(crate::runtime::close_sdk_access());
        super::STATE_RETIRED.store(true, Ordering::Release);
        let key = SigningKey::from_bytes(&[31; 32]);
        super::pin_approval_key(key.verifying_key().to_bytes()).unwrap();
        let core_key = SigningKey::from_bytes(&[32; 32]);
        let manager_key = SigningKey::from_bytes(&[33; 32]);
        let root = hyperhub_runtime::attachment::RootImageState {
            identity: hyperhub_runtime::attachment::RootImageIdentity {
                pid: boot.root_pid,
                birth: 1,
                executable_sha256: "b".repeat(64),
            },
            exec_epoch: 0,
            observed_at_ms: 0,
            head: [0; 32],
        };
        crate::state().lock().unwrap().gateway.root_image = Some(root.clone());
        let (proof, _scope, certificate) = super::host_command::tests::authorization(
            &boot,
            root,
            &key,
            &core_key,
            &manager_key,
            hyperhub_runtime::attachment::OperationAction::Detach,
        );
        let command = |kind, proof| AuthenticatedCommand {
            attachment_id: boot.attachment_id.clone(),
            token: boot.host_token.clone(),
            command: kind,
            proof,
            enrollment: None,
            aliases: None,
            root_image: None,
        };
        assert!(
            super::command(command(HostCommand::Status, None))
                .unwrap()
                .unload_ready
        );
        assert!(
            super::command(command(HostCommand::SnapshotAliases, Some(proof.clone())))
                .unwrap()
                .alias_snapshot
                .is_some()
        );
        assert!(super::command(command(HostCommand::Activate, Some(proof.clone()))).is_err());
        assert!(super::command(command(HostCommand::Detach, Some(proof.clone()))).is_err());
        assert!(super::command(command(HostCommand::Retire, Some(proof.clone()))).is_err());
        assert!(
            super::host_command::tests::execute_local(
                command(HostCommand::Detach, Some(proof.clone())),
                &certificate,
                &manager_key,
                hyperhub_runtime::attachment::HostLifecycleCommand::Detach,
            )
            .unload_ready
        );
        assert!(
            super::host_command::tests::execute_local(
                command(HostCommand::Retire, Some(proof.clone())),
                &certificate,
                &manager_key,
                hyperhub_runtime::attachment::HostLifecycleCommand::Retire,
            )
            .unload_ready
        );
        assert!(
            crate::runtime::storage_present(),
            "final reply must precede runtime destruction"
        );
        let host = crate::runtime::host_access().unwrap();
        assert!(unsafe { crate::runtime::retire_attachment_state() }.is_err());
        assert!(crate::state().lock().unwrap().session.initialized);
        drop(host);
        unsafe { crate::runtime::retire_attachment_state() }.unwrap();
        assert!(super::command(command(HostCommand::Status, None)).is_err());
        assert!(super::command(command(HostCommand::Retire, Some(proof.clone()))).is_err());
        let claims = hyperhub_runtime::attachment::verify_proof_with_key(
            &boot,
            &key.verifying_key().to_bytes(),
            &proof,
            super::now_ms(),
        )
        .unwrap();
        assert!(crate::root_image::verify_operation(&claims).is_err());
    }
    assert!(!crate::runtime::storage_present());
    assert!(super::status().unload_ready);
    assert!(super::status()
        .compatibility_reasons
        .iter()
        .any(|reason| reason == "native_storage_finalized"));
    assert_eq!(
        crate::hh_agent_is_initialized(),
        crate::HH_ERR_NOT_INITIALIZED
    );
    assert_eq!(
        crate::hh_agent_handshake_complete(42),
        crate::HH_ERR_NOT_INITIALIZED
    );
    assert_eq!(
        crate::hh_agent_close_socket(42),
        crate::HH_ERR_NOT_INITIALIZED
    );
    assert_eq!(
        crate::hh_agent_initialize_from_env(),
        crate::HH_ERR_NOT_INITIALIZED
    );
    assert_eq!(crate::hh_agent_abi_version(), crate::ABI_VERSION);
    assert_eq!(crate::runtime::access_user_counts(), (0, 0));
}
