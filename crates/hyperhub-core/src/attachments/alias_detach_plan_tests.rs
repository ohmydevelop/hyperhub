//! Observer component tests start after the existing consumed-manager check.
//! No fixture weakens or bypasses the real control entry-point authentication.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

struct Fixture {
    root: std::path::PathBuf,
    service: ControlService,
    history: SharedHistory,
    identity: ProcessIdentity,
    paused: Arc<AtomicBool>,
    pending: Arc<AtomicU64>,
    status_available: Arc<AtomicBool>,
    startup_running: Arc<AtomicBool>,
    publish_inline: Arc<AtomicBool>,
    replace_inline: Arc<AtomicBool>,
    observations: Arc<AtomicUsize>,
    publications: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_initialization(None)
    }
    fn with_initialization(initialization: Option<wire::InitializationStatus>) -> Self {
        let root = std::env::temp_dir().join(format!("hh-dbp-{:08x}", rand::random::<u32>()));
        attachments::private_directory(&root).unwrap();
        let directory = root.join("a");
        attachments::private_directory(&directory).unwrap();
        #[cfg(unix)]
        let endpoint = root.join("h").to_string_lossy().into_owned();
        #[cfg(windows)]
        let endpoint = format!(
            r"\\.\pipe\hyperhub-barrier-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        );
        let identity = attachments::inspect_process(std::process::id()).unwrap();
        let signer = attachments::approval_trust(&directory)
            .unwrap()
            .core_public_key;
        let bootstrap:wire::Bootstrap=serde_json::from_value(serde_json::json!({
            "attachment_id":"barrier-fixture","session_id":"barrier-session","token":"t".repeat(64),"control_endpoint":"unused","socks_address":"127.0.0.1:1","tls_ca_pem":"unused","observe":false,"firewall":null,"sandbox":null,"host_endpoint":endpoint,"host_token":"h".repeat(64),"scope_tree":true,"root_pid":identity.pid,"approval_authority_file":"unused","approval_instance_id":"instance","initially_owned":false,"approval_core_public_key":signer,"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":identity.executable_sha256
        })).unwrap();
        let history = Arc::new(Mutex::new(History {
            operation: Arc::new(Mutex::new(())),
            bootstrap: bootstrap.clone(),
            records: vec![],
            heads: vec![[0; 32]],
            hosts: HashMap::from([(
                identity.pid,
                Host {
                    identity: identity.clone(),
                    bootstrap: bootstrap.clone(),
                    sequence: 0,
                    ready: true,
                    startup_cleanup_only: false,
                    startup_pristine: false,
                    signer,
                },
            )]),
            proof: None,
            cleanup_unproven: false,
            durable_sequence: 0,
            detaching: None,
            barrier_scan: None,
        }));
        let service = ControlService::new(
            SessionRegistry::default(),
            ConnectionRegistry::default(),
            "unused".into(),
            crate::audit::AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(crate::config::Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        )
        .with_attachment_directory(directory);
        let status_available = Arc::new(AtomicBool::new(true));
        let startup_running = Arc::new(AtomicBool::new(
            initialization
                .as_ref()
                .is_some_and(|status| status.initializing),
        ));
        let server_status_available = status_available.clone();
        let server_startup_running = startup_running.clone();
        let paused = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(AtomicU64::new(0));
        let publish_inline = Arc::new(AtomicBool::new(false));
        let replace_inline = Arc::new(AtomicBool::new(false));
        let observations = Arc::new(AtomicUsize::new(0));
        let publications = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let listener = wire::Listener::bind(&bootstrap.host_endpoint).unwrap();
        let server_history = history.clone();
        let server_paused = paused.clone();
        let server_pending = pending.clone();
        let server_publish = publish_inline.clone();
        let server_replace = replace_inline.clone();
        let server_observations = observations.clone();
        let server_publications = publications.clone();
        let server_stop = stop.clone();
        let member = identity.clone();
        let server = std::thread::spawn(move || {
            listener.run(&server_stop, |request| {
            if !server_status_available.load(Ordering::Acquire) { return Err("Host initialization transport is not ready".into()); }
            let mut status: wire::HostStatus = serde_json::from_value(serde_json::json!({
                "protocol":wire::PROTOCOL,"pid":member.pid,"attachment_id":bootstrap.attachment_id,"phase":"active","active_calls":0,"unload_ready":false,"tracked_sockets":0,"fake_addresses":0,"compatibility_reasons":[],
                "alias_publication_paused":server_paused.load(Ordering::Acquire),"pending_alias_publications":server_pending.load(Ordering::Acquire)
            })).unwrap();
            status.initialization = initialization.clone();
            if let Some(initialization) = status.initialization.as_mut() {
                initialization.initializing = server_startup_running.load(Ordering::Acquire);
                status.active_calls = u64::from(initialization.initializing);
            }
            if status.initialization.is_some() { status.phase = wire::HostPhase::Preparing; }
            match request.command {
                wire::HostCommand::Status => {
                    // The callback models a DNS publication producer. If Core
                    // holds either lock while querying, this deterministic
                    // try_lock assertion fails instead of hanging the test.
                    let operation = server_history.try_lock().map_err(|_| "history lock held across Host RPC")?.operation.clone();
                    let _publication = operation.try_lock().map_err(|_| "publication lock held across Host RPC")?;
                    let mut history = server_history.try_lock().map_err(|_| "history lock held across Host RPC")?;
                    if server_publish.swap(false, Ordering::AcqRel) {
                        let record = wire::IssuedRecord {
                            sequence: 1, address: "198.18.0.1".parse().unwrap(), hostname: "local.fixture.test".into(),
                            native_fallback: wire::NativeFallback { family: 4, addresses: vec![wire::NativeAddress { ip: "127.0.0.1".parse().unwrap(), scope_id: 0, flowinfo: 0 }], failure: None, unavailable: None },
                            issuer_pid: member.pid, issuer_birth: member.birth, ambiguous: false,
                        };
                        history.heads.push(wire::alias_record_head(&[0;32], &record).unwrap());
                        history.records.push(record);
                    }
                    if server_replace.swap(false, Ordering::AcqRel) {
                        history.hosts.get_mut(&member.pid).unwrap().bootstrap.host_token.push('x');
                    }
                    server_observations.fetch_add(1, Ordering::AcqRel);
                }
                wire::HostCommand::ApplySessionAliases => {
                    let page = wire::decode_alias_snapshot(&bootstrap, &signer, request.aliases.as_ref().ok_or("missing page")?).map_err(|e| e.to_string())?;
                    status.alias_inheritance = Some(wire::AliasInheritance { metadata_only: false, public_key: signer, sequence: page.sequence, head: page.head, endorsement_approved_at_ms: 0, endorsement_nonce: None });
                    server_publications.fetch_add(1, Ordering::AcqRel);
                }
                _ => return Err("Core must return a plan instead of sending lifecycle commands".into()),
            }
            Ok(status)
        })
        });
        Self {
            root,
            service,
            history,
            identity,
            paused,
            pending,
            status_available,
            startup_running,
            publish_inline,
            replace_inline,
            observations,
            publications,
            stop,
            server: Some(server),
        }
    }
    fn observe(&self, nonce: [u8; 32], cancel: bool) -> Result<ControlResponse, String> {
        self.service
            .observe_attachment_detach(&self.history, nonce, "barrier-fixture", cancel)
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
fn bounded_core_plan_observes_publication_without_holding_producer_locks() {
    let fixture = Fixture::new();
    let nonce = [1; 32];
    let ControlResponse::AttachmentDetachPlan { plan } = fixture.observe(nonce, false).unwrap()
    else {
        panic!("missing pause plan");
    };
    assert_eq!(plan.command, wire::HostLifecycleCommand::PrepareDetachment);
    assert_eq!(plan.authorization_nonce, nonce);
    assert_eq!(plan.targets.len(), 1);
    assert_eq!(plan.targets[0].identity, fixture.identity);
    assert_eq!(fixture.history.lock().unwrap().durable_sequence, 0);
    fixture.paused.store(true, Ordering::Release); // Manager executed the fixed plan.
    fixture.pending.store(1, Ordering::Release);
    fixture.publish_inline.store(true, Ordering::Release);
    assert!(
        matches!(fixture.observe(nonce, false), Err(message) if message == "alias_publication_busy")
    );
    assert_eq!(fixture.history.lock().unwrap().records.len(), 1);
    assert_eq!(fixture.history.lock().unwrap().durable_sequence, 0);
    fixture.pending.store(0, Ordering::Release);
    assert!(matches!(
        fixture.observe(nonce, false).unwrap(),
        ControlResponse::Ok
    ));
    let history = fixture.history.lock().unwrap();
    assert_eq!(history.durable_sequence, 1);
    assert_eq!(history.hosts[&fixture.identity.pid].sequence, 1);
    assert_eq!(history.detaching, Some(nonce));
    drop(history);
    assert_eq!(fixture.publications.load(Ordering::Acquire), 1);
    let ControlResponse::AttachmentDetachPlan { plan } = fixture.observe(nonce, true).unwrap()
    else {
        panic!("missing cancel plan");
    };
    assert_eq!(
        plan.command,
        wire::HostLifecycleCommand::CancelDetachmentPreparation
    );
    fixture.paused.store(false, Ordering::Release);
    assert!(matches!(
        fixture.observe(nonce, true).unwrap(),
        ControlResponse::Ok
    ));
    assert!(fixture.history.lock().unwrap().detaching.is_none());
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn core_plan_restarts_observation_if_a_member_is_replaced_during_status_rpc() {
    let fixture = Fixture::new();
    fixture.paused.store(true, Ordering::Release);
    fixture.replace_inline.store(true, Ordering::Release);
    let nonce = [2; 32];
    assert!(
        matches!(fixture.observe(nonce, false), Err(message) if message == "alias_publication_busy")
    );
    assert!(fixture.history.lock().unwrap().barrier_scan.is_none());
    let observed = fixture.observations.load(Ordering::Acquire);
    assert!(fixture.observe([3; 32], true).is_err());
    assert_eq!(fixture.observations.load(Ordering::Acquire), observed);
    assert!(matches!(
        fixture.observe(nonce, false).unwrap(),
        ControlResponse::Ok
    ));
}

#[test]
fn core_plan_batches_and_frames_are_bounded_without_silent_completion() {
    let identity = ProcessIdentity {
        pid: 1,
        birth: 1,
        executable: "fixture".into(),
        executable_sha256: "a".repeat(64),
        owner: "fixture-owner".into(),
    };
    let target = attachments::HostCommandTarget {
        identity,
        endpoint: "fixture".into(),
        token: "h".repeat(64),
    };
    let response = bounded_barrier_plan(
        [4; 32],
        wire::HostLifecycleCommand::PrepareDetachment,
        vec![target.clone(); 100],
    )
    .unwrap();
    let ControlResponse::AttachmentDetachPlan { plan } = response else {
        panic!("missing bounded plan");
    };
    assert_eq!(plan.targets.len(), attachments::DETACH_BARRIER_BATCH_LIMIT);
    let mut large = target;
    large.endpoint = "x".repeat(wire::MAX_FRAME / 3);
    let response = bounded_barrier_plan(
        [4; 32],
        wire::HostLifecycleCommand::PrepareDetachment,
        vec![large.clone(); 2],
    )
    .unwrap();
    assert!(serde_json::to_vec(&response).unwrap().len() <= wire::MAX_FRAME / 2);
    let ControlResponse::AttachmentDetachPlan { plan } = response else {
        panic!("missing framed plan");
    };
    assert_eq!(plan.targets.len(), 1);
    large.endpoint = "x".repeat(wire::MAX_FRAME);
    assert!(bounded_barrier_plan(
        [4; 32],
        wire::HostLifecycleCommand::PrepareDetachment,
        vec![large]
    )
    .is_err());
}

#[test]
fn startup_cleanup_ack_requires_real_runtime_and_never_hides_a_core_prefix() {
    let mut status: wire::HostStatus = serde_json::from_value(serde_json::json!({
        "protocol":wire::PROTOCOL,"pid":1,"attachment_id":"fixture","phase":"detached_resident",
        "active_calls":0,"unload_ready":false,"tracked_sockets":0,"fake_addresses":0,"compatibility_reasons":[],
        "initialization":{"origin":"fresh","ever_active":false,"runtime_available":true,"stage":"cancelled","initializing":false,"cancelled":true,"error":null,"native_pin":null}
    })).unwrap();
    assert!(verify_startup_cleanup_prefix(&status, true).is_ok());
    assert!(verify_startup_cleanup_prefix(&status, false).is_err());
    assert!(detach_status_acknowledges(&status));
    status.initialization.as_mut().unwrap().initializing = true;
    assert!(!startup_pristine(&status));
    assert!(
        !detach_status_acknowledges(&status),
        "zero counters are insufficient while the initializer is still running"
    );
    status.initialization.as_mut().unwrap().initializing = false;
    status.active_calls = 1;
    assert!(!startup_pristine(&status));
    assert!(
        detach_status_acknowledges(&status),
        "resident callbacks may finish after logical detachment"
    );
    status.phase = wire::HostPhase::Detaching;
    assert!(
        !detach_status_acknowledges(&status),
        "the transient detaching phase is not a logical completion"
    );
    status.phase = wire::HostPhase::Active;
    assert!(!detach_status_acknowledges(&status));
    status.phase = wire::HostPhase::Detached;
    assert!(
        !detach_status_acknowledges(&status),
        "full detachment cannot retain native callbacks"
    );
    status.active_calls = 0;
    assert!(detach_status_acknowledges(&status));
    status.phase = wire::HostPhase::DetachedResident;
    let init = status.initialization.as_mut().unwrap();
    init.origin = wire::InitializationOrigin::ForkChild;
    init.runtime_available = false;
    status.tracked_sockets = usize::MAX;
    status.fake_addresses = usize::MAX;
    assert!(
        !detach_status_acknowledges(&status),
        "zero publication/spawn counters cannot turn an unknown inherited runtime into a full ACK"
    );
    status.initialization.as_mut().unwrap().origin = wire::InitializationOrigin::Unknown;
    assert!(!detach_status_acknowledges(&status));
    status.initialization.as_mut().unwrap().runtime_available = true;
    status.pending_alias_publications = 1;
    assert!(!detach_status_acknowledges(&status));
    status.pending_alias_publications = 0;
    status.spawn_calls = 1;
    assert!(!detach_status_acknowledges(&status));
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn cleanup_host_locator_with_unknown_prefix_is_retained_without_empty_history_authority() {
    let fixture = Fixture::new();
    let bootstrap = fixture.history.lock().unwrap().bootstrap.clone();
    // The real receiver in this fixture reports Active without initialization
    // evidence, so the new locator must be retained as unproven, not empty.
    fixture
        .service
        .register_startup_cleanup_hosts(&[attachments::HostBootstrapBinding {
            identity: fixture.identity.clone(),
            bootstrap: bootstrap.clone(),
        }])
        .unwrap();
    let shared = fixture.service.alias_histories.0.lock().unwrap()[&bootstrap.session_id].clone();
    {
        let history = shared.lock().unwrap();
        assert!(history.cleanup_unproven);
        assert_eq!(
            history.hosts[&fixture.identity.pid].identity,
            fixture.identity
        );
        assert!(history.records.is_empty());
        assert_eq!(history.heads, vec![[0; 32]]);
    }
    assert!(fixture.service.publish_aliases(&shared).is_err());
    fixture.paused.store(true, Ordering::Release);
    assert!(
        matches!(fixture.service.observe_attachment_detach(&shared, [31;32], &bootstrap.attachment_id, false), Err(message) if message == "alias_detach_members_pending")
    );
    assert!(shared.lock().unwrap().cleanup_unproven);
    assert!(
        fixture.service.alias_histories.export_successor().is_err(),
        "a real pending barrier must prevent succession"
    );
    let ControlResponse::AttachmentDetachPlan { plan } = fixture
        .service
        .observe_attachment_detach(&shared, [31; 32], &bootstrap.attachment_id, true)
        .unwrap()
    else {
        panic!("missing original cancellation plan");
    };
    assert_eq!(
        plan.command,
        wire::HostLifecycleCommand::CancelDetachmentPreparation
    );
    fixture.paused.store(false, Ordering::Release);
    assert!(matches!(
        fixture
            .service
            .observe_attachment_detach(&shared, [31; 32], &bootstrap.attachment_id, true)
            .unwrap(),
        ControlResponse::Ok
    ));
    assert!(
        shared.lock().unwrap().cleanup_unproven,
        "cancelling admission is not proof of an empty inherited prefix"
    );
    let transfer = fixture.service.alias_histories.export_successor().unwrap();
    let restored = AliasHistories::default();
    restored.import_successor(&transfer).unwrap();
    assert!(
        restored.0.lock().unwrap()[&bootstrap.session_id]
            .lock()
            .unwrap()
            .cleanup_unproven
    );
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn fresh_startup_cleanup_keeps_locator_without_fabricating_alias_ack_or_publishing_policy() {
    let fixture = Fixture::with_initialization(Some(wire::InitializationStatus {
        origin: wire::InitializationOrigin::Fresh,
        ever_active: false,
        runtime_available: true,
        stage: wire::InitializationStage::Cancelled,
        initializing: false,
        cancelled: true,
        error: None,
        native_pin: None,
    }));
    let bootstrap = fixture.history.lock().unwrap().bootstrap.clone();
    fixture
        .service
        .sessions
        .prepare_approved_attachment(
            &bootstrap.session_id,
            &bootstrap.token,
            &fixture.identity.executable,
            &[],
        )
        .unwrap();
    assert!(fixture.service.sessions.activate_with_policy(
        &bootstrap.session_id,
        &bootstrap.token,
        fixture.identity.pid,
        crate::session::ProcessHookMetadata {
            hook_status: "preparing".into(),
            decision_source: "attachment_approval".into(),
            ..Default::default()
        }
    ));
    fixture
        .service
        .register_startup_cleanup_hosts(&[attachments::HostBootstrapBinding {
            identity: fixture.identity.clone(),
            bootstrap: bootstrap.clone(),
        }])
        .unwrap();
    let shared = fixture.service.alias_histories.0.lock().unwrap()[&bootstrap.session_id].clone();
    {
        let history = shared.lock().unwrap();
        assert!(!history.cleanup_unproven);
        assert!(history.hosts[&fixture.identity.pid].startup_cleanup_only);
        assert!(
            !history.hosts[&fixture.identity.pid].ready,
            "no alias ACK was received"
        );
    }
    fixture.paused.store(true, Ordering::Release);
    assert!(matches!(
        fixture
            .service
            .observe_attachment_detach(&shared, [32; 32], &bootstrap.attachment_id, false)
            .unwrap(),
        ControlResponse::Ok
    ));
    assert_eq!(
        fixture.publications.load(Ordering::Acquire),
        0,
        "cleanup must not install aliases or policy into a cancelled startup"
    );
    let history = shared.lock().unwrap();
    assert!(history.records.is_empty());
    assert_eq!(history.durable_sequence, 0);
    assert!(!history.hosts[&fixture.identity.pid].ready);
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn rejected_fresh_startup_cleanup_does_not_block_authenticated_admission_cancellation() {
    let fixture = Fixture::with_initialization(Some(wire::InitializationStatus {
        origin: wire::InitializationOrigin::Fresh,
        ever_active: false,
        runtime_available: true,
        stage: wire::InitializationStage::Cancelled,
        initializing: false,
        cancelled: true,
        error: None,
        native_pin: None,
    }));
    fixture.publish_inline.store(true, Ordering::Release);
    let nonce = [33; 32];
    assert!(
        matches!(fixture.observe(nonce, false), Err(message) if message == "startup cleanup requires an empty Core alias history")
    );
    assert_eq!(fixture.history.lock().unwrap().records.len(), 1);
    fixture.paused.store(true, Ordering::Release);
    let ControlResponse::AttachmentDetachPlan { plan } = fixture.observe(nonce, true).unwrap()
    else {
        panic!("missing cancellation plan after preparation rejection");
    };
    assert_eq!(
        plan.command,
        wire::HostLifecycleCommand::CancelDetachmentPreparation
    );
    fixture.paused.store(false, Ordering::Release);
    assert!(matches!(
        fixture.observe(nonce, true).unwrap(),
        ControlResponse::Ok
    ));
    assert!(fixture.history.lock().unwrap().detaching.is_none());
    assert_eq!(
        fixture.history.lock().unwrap().records.len(),
        1,
        "cancellation preserves existing aliases"
    );
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn scoped_unreachable_or_running_fresh_host_only_upgrades_after_real_terminal_observation() {
    let fixture = Fixture::with_initialization(Some(wire::InitializationStatus {
        origin: wire::InitializationOrigin::Fresh,
        ever_active: false,
        runtime_available: true,
        stage: wire::InitializationStage::InstallingHooks,
        initializing: true,
        cancelled: false,
        error: None,
        native_pin: None,
    }));
    let bootstrap = fixture.history.lock().unwrap().bootstrap.clone();
    fixture
        .service
        .sessions
        .prepare_approved_attachment(
            &bootstrap.session_id,
            &bootstrap.token,
            &fixture.identity.executable,
            &[],
        )
        .unwrap();
    assert!(fixture.service.sessions.activate_with_policy(
        &bootstrap.session_id,
        &bootstrap.token,
        fixture.identity.pid,
        crate::session::ProcessHookMetadata {
            hook_status: "preparing".into(),
            decision_source: "attachment_approval".into(),
            ..Default::default()
        }
    ));
    let hosts = [attachments::HostBootstrapBinding {
        identity: fixture.identity.clone(),
        bootstrap: bootstrap.clone(),
    }];
    fixture.status_available.store(false, Ordering::Release);
    // The real receiver returns an error, not a fabricated empty Host status.
    fixture
        .service
        .register_startup_cleanup_hosts(&hosts)
        .unwrap();
    let shared = fixture.service.alias_histories.0.lock().unwrap()[&bootstrap.session_id].clone();
    assert!(shared.lock().unwrap().cleanup_unproven);
    fixture.status_available.store(true, Ordering::Release);
    fixture
        .service
        .register_startup_cleanup_hosts(&hosts)
        .unwrap();
    assert!(
        shared.lock().unwrap().cleanup_unproven,
        "runtime availability and zeros do not prove the initializer has ended"
    );
    fixture.startup_running.store(false, Ordering::Release);
    fixture
        .service
        .register_startup_cleanup_hosts(&hosts)
        .unwrap();
    {
        let history = shared.lock().unwrap();
        assert!(!history.cleanup_unproven);
        assert!(history.hosts[&fixture.identity.pid].startup_pristine);
        assert!(!history.hosts[&fixture.identity.pid].ready);
    }
    fixture.paused.store(true, Ordering::Release);
    assert!(matches!(
        fixture
            .service
            .observe_attachment_detach(&shared, [34; 32], &bootstrap.attachment_id, false)
            .unwrap(),
        ControlResponse::Ok
    ));
    assert_eq!(fixture.publications.load(Ordering::Acquire), 0);
}
