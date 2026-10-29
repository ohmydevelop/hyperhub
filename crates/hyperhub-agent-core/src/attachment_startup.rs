//! A live initializer owns native state until it has stopped, even if its
//! notification file cannot be published. Only an admitted cleanup cancels it.
use super::*;
use hyperhub_runtime::attachment::{
    InitializationNativePin, InitializationOrigin, InitializationStage, InitializationStatus,
};

static STAGE: AtomicU8 = AtomicU8::new(0);
static RUNNING: AtomicUsize = AtomicUsize::new(0);
static CANCELLED: AtomicBool = AtomicBool::new(false);
static CHILD_ORIGIN: AtomicBool = AtomicBool::new(false);
static RUNTIME_AVAILABLE: AtomicBool = AtomicBool::new(true);
static PIN: AtomicPtr<InitializationNativePin> = AtomicPtr::new(std::ptr::null_mut());

pub(crate) struct Startup {
    pid: u32,
    epoch: u64,
    finished: bool,
}
pub(super) fn begin(child: bool) -> Startup {
    CANCELLED.store(false, Ordering::Release);
    CHILD_ORIGIN.store(child, Ordering::Release);
    RUNTIME_AVAILABLE.store(!child, Ordering::Release);
    STAGE.store(1, Ordering::Release);
    RUNNING.fetch_add(1, Ordering::AcqRel);
    Startup {
        pid: std::process::id(),
        epoch: LIFE_EPOCH.load(Ordering::Acquire),
        finished: false,
    }
}
pub(super) fn after_fork_child() {
    STAGE.store(0, Ordering::Release);
    RUNNING.store(0, Ordering::Release);
    CANCELLED.store(false, Ordering::Release);
    CHILD_ORIGIN.store(false, Ordering::Release);
    RUNTIME_AVAILABLE.store(!managed(), Ordering::Release);
    PIN.store(std::ptr::null_mut(), Ordering::Release);
}
pub(crate) fn runtime_available() -> bool {
    RUNTIME_AVAILABLE.load(Ordering::Acquire)
}
pub(crate) fn mutate_runtime<T>(mutation: impl FnOnce() -> Result<T, i32>) -> Result<T, i32> {
    let tracked = running() != 0;
    if tracked {
        with_state_mutation(|| {
            check().map_err(|_| "attachment initialization was cancelled")?;
            RUNTIME_AVAILABLE.store(false, Ordering::Release);
            Ok(())
        })
        .map_err(|_| HH_ERR_NOT_INITIALIZED)?;
    }
    let result = mutation();
    // A returned error may leave partial Runtime data, but the lock is now
    // available and Status must report those real resources rather than zero.
    if tracked {
        runtime_rebuilt()?;
    }
    result
}
pub(crate) fn runtime_rebuilt() -> Result<(), i32> {
    with_state_mutation(|| {
        RUNTIME_AVAILABLE.store(true, Ordering::Release);
        Ok(())
    })
    .map_err(|_| HH_ERR_PROTOCOL)
}
pub(crate) fn running() -> usize {
    RUNNING.load(Ordering::Acquire)
}
pub(crate) fn cancelled() -> bool {
    CANCELLED.load(Ordering::Acquire)
}
pub(crate) fn tracked() -> bool {
    STAGE.load(Ordering::Acquire) != 0
}
pub(crate) fn origin() -> InitializationOrigin {
    if !tracked() {
        InitializationOrigin::Unknown
    } else if CHILD_ORIGIN.load(Ordering::Acquire) {
        InitializationOrigin::ForkChild
    } else {
        InitializationOrigin::Fresh
    }
}
/// Approved cleanup of an unrebuildable inherited image keeps its immutable
/// alias compatibility pin, without ever consulting a copied Runtime mutex.
pub(crate) fn native_only() -> bool {
    tracked() && cancelled() && running() == 0 && !runtime_available()
}
pub(crate) fn check() -> Result<(), i32> {
    if cancelled() || (running() != 0 && matches!(PHASE.load(Ordering::Acquire), 3 | 4 | 5)) {
        Err(HH_ERR_NOT_INITIALIZED)
    } else {
        Ok(())
    }
}
pub(crate) fn stage(value: InitializationStage) -> Result<(), i32> {
    check()?;
    let value = match value {
        InitializationStage::Bound => 1,
        InitializationStage::Registering => 2,
        InitializationStage::Engine => 3,
        InitializationStage::ForkBroker => 4,
        InitializationStage::InstallingHooks => 5,
        InitializationStage::Atfork => 6,
        InitializationStage::AliasCatchup => 7,
        InitializationStage::Ready => 8,
        InitializationStage::Failed => 9,
        InitializationStage::Cancelled => 10,
    };
    STAGE.store(value, Ordering::Release);
    check()
}
pub(crate) fn set_pin(pin: InitializationNativePin) {
    // Pins remain owned by the module; publishing diagnostic metadata must not
    // free a value concurrently read by a lifecycle request.
    PIN.store(Box::into_raw(Box::new(pin)), Ordering::Release);
}
pub(crate) fn status() -> Option<InitializationStatus> {
    let value = STAGE.load(Ordering::Acquire);
    let stage = match value {
        0 => return None,
        1 => InitializationStage::Bound,
        2 => InitializationStage::Registering,
        3 => InitializationStage::Engine,
        4 => InitializationStage::ForkBroker,
        5 => InitializationStage::InstallingHooks,
        6 => InitializationStage::Atfork,
        7 => InitializationStage::AliasCatchup,
        8 => InitializationStage::Ready,
        9 => InitializationStage::Failed,
        _ => InitializationStage::Cancelled,
    };
    let pin = PIN.load(Ordering::Acquire);
    Some(InitializationStatus {
        origin: origin(),
        ever_active: host_command::ever_active(),
        runtime_available: runtime_available(),
        stage,
        initializing: running() != 0,
        cancelled: cancelled(),
        error: (stage == InitializationStage::Failed)
            .then(|| "attachment_initialization_failed".into()),
        native_pin: (!pin.is_null()).then(|| unsafe { &*pin }.clone()),
    })
}
pub(super) fn cancel() {
    if !tracked()
        || (STAGE.load(Ordering::Acquire) == 8 && running() == 0 && host_command::ever_active())
    {
        return;
    }
    CANCELLED.store(true, Ordering::Release);
    STAGE.store(10, Ordering::Release);
    NATIVE_READY.store(false, Ordering::Release);
    #[cfg(all(target_os = "linux", feature = "gum-agent"))]
    if CHILD_ORIGIN.load(Ordering::Acquire) && local_owner() && running() == 0 {
        crate::unix_gum::fork::cancel_initialization_after_approved_detach();
    }
}
#[cfg(test)]
pub(crate) fn begin_for_test(child: bool) -> Startup {
    begin(child)
}
#[cfg(test)]
pub(crate) fn cancel_for_test() {
    cancel();
}
impl Startup {
    pub(crate) fn finish(mut self, success: bool) {
        STAGE.store(
            if cancelled() {
                10
            } else if success {
                8
            } else {
                9
            },
            Ordering::Release,
        );
        self.finished = true;
    }
}
impl Drop for Startup {
    fn drop(&mut self) {
        if self.pid == std::process::id() && self.epoch == LIFE_EPOCH.load(Ordering::Acquire) {
            if !self.finished {
                STAGE.store(if cancelled() { 10 } else { 9 }, Ordering::Release);
            }
            let last = RUNNING.fetch_sub(1, Ordering::AcqRel) == 1;
            #[cfg(all(target_os = "linux", feature = "gum-agent"))]
            if last && cancelled() && CHILD_ORIGIN.load(Ordering::Acquire) && local_owner() {
                crate::unix_gum::fork::cancel_initialization_after_approved_detach();
            }
            #[cfg(not(all(target_os = "linux", feature = "gum-agent")))]
            let _ = last;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn published_binding_is_owned_before_recovery_can_cancel_it() {
        use ed25519_dalek::SigningKey;
        use hyperhub_runtime::attachment as wire;
        const MARKER: &str = "HH_TEST_BOUND_STARTUP_RECOVERY_CHILD";
        if std::env::var_os(MARKER).is_none() {
            let test = format!(
                "{}::published_binding_is_owned_before_recovery_can_cancel_it",
                module_path!().split_once("::").unwrap().1
            );
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .env(MARKER, "1")
                .args(["--exact", &test, "--test-threads=1"])
                .status()
                .unwrap()
                .success());
            return;
        }
        let directory =
            std::env::temp_dir().join(format!("hh-startup-bind-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(unix)]
        let endpoint = directory.join("host").to_string_lossy().into_owned();
        #[cfg(windows)]
        let endpoint = format!(r"\\.\pipe\hh-startup-bind-{}", std::process::id());
        let admin = SigningKey::from_bytes(&[61; 32]);
        let core = SigningKey::from_bytes(&[62; 32]);
        let manager = SigningKey::from_bytes(&[63; 32]);
        let bootstrap: Bootstrap = serde_json::from_value(serde_json::json!({
            "attachment_id":"bound-startup-fixture","session_id":"fixture-session","token":"t".repeat(64),
            "control_endpoint":"unused-fixture","socks_address":"127.0.0.1:1","tls_ca_pem":"-----BEGIN CERTIFICATE-----fixture",
            "observe":false,"firewall":null,"sandbox":null,"host_endpoint":endpoint,
            "host_token":"h".repeat(64),"scope_tree":false,"root_pid":std::process::id(),
            "approval_authority_file":"unused","approval_instance_id":"bound-startup-fixture",
            "approval_public_key":admin.verifying_key().to_bytes(),"approval_core_public_key":core.verifying_key().to_bytes(),
            "approval_core_pid":std::process::id(),"approval_core_birth":wire::process_incarnation(std::process::id()).unwrap().birth,
            "approval_cli_sha256":"c".repeat(64)
        })).unwrap();
        let worker = bind_metadata_for_startup(&bootstrap, false)
            .unwrap()
            .unwrap();
        // Pause the real entry sequence exactly after metadata publication. A
        // recovery manager now reopens the listener before start_server/Engine.
        assert_eq!(running(), 1);
        assert!(status().unwrap().initializing);
        assert_eq!(hyperhub_attachment_recover_transport(), crate::HH_OK);
        let identity = wire::process_identity(std::process::id()).unwrap();
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
        let (proof, _, certificate) = host_command::tests::authorization(
            &bootstrap,
            root,
            &admin,
            &core,
            &manager,
            wire::OperationAction::Detach,
        );
        let request = wire::AuthenticatedCommand {
            attachment_id: bootstrap.attachment_id.clone(),
            token: bootstrap.host_token.clone(),
            command: wire::HostCommand::Detach,
            proof: Some(proof),
            enrollment: None,
            aliases: None,
            root_image: None,
        };
        let exchange = |envelope| -> wire::HostLifecycleReply {
            serde_json::from_value(
                wire::exchange_raw_for_process(
                    &bootstrap.host_endpoint,
                    &serde_json::to_value(envelope).unwrap(),
                    std::process::id(),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let challenged = exchange(wire::HostLifecycleEnvelope::Challenge {
            request: request.clone(),
            certificate: certificate.clone(),
            purpose: wire::HostLifecycleCommand::Detach,
        });
        assert!(challenged.error.is_none(), "{:?}", challenged.error);
        let challenge = challenged.challenge.unwrap();
        let reply = exchange(wire::HostLifecycleEnvelope::Execute {
            request,
            certificate,
            purpose: wire::HostLifecycleCommand::Detach,
            nonce: challenge.nonce,
            possession: host_command::tests::sign(&challenge, &manager),
        });
        assert!(reply.error.is_none(), "{:?}", reply.error);
        let detached = reply.status.unwrap();
        assert_eq!(detached.phase, wire::HostPhase::DetachedResident);
        assert!(detached.initialization.unwrap().initializing);
        assert!(
            !detached.unload_ready,
            "the paused entry still owns native lifetime"
        );
        assert!(cancelled());
        assert_eq!(running(), 1);
        // A duplicate dispatch is inert. Resuming the original entry cannot
        // execute another begin(), revive cancelled state or reach Engine.
        assert!(bind_metadata_for_startup(&bootstrap, false)
            .unwrap()
            .is_none());
        assert!(cancelled());
        assert_eq!(running(), 1);
        assert!(stage(InitializationStage::Engine).is_err());
        assert!(initialize_bound(&bootstrap).is_err());
        worker.finish(true);
        assert_eq!(running(), 0);
        assert_eq!(status().unwrap().stage, InitializationStage::Cancelled);
        assert!(mark_native_ready().is_err());
        assert!(!native_ready());
    }

    #[test]
    fn cancellation_is_terminal_and_a_running_worker_remains_owned() {
        const MARKER: &str = "HH_TEST_STARTUP_CANCELLATION_CHILD";
        if std::env::var_os(MARKER).is_none() {
            let test = format!(
                "{}::cancellation_is_terminal_and_a_running_worker_remains_owned",
                module_path!().split_once("::").unwrap().1
            );
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .env(MARKER, "1")
                .args(["--exact", &test, "--test-threads=1"])
                .status()
                .unwrap()
                .success());
            return;
        }
        let worker = begin(false);
        assert_eq!(running(), 1);
        assert!(active_calls() >= 1);
        stage(InitializationStage::InstallingHooks).unwrap();
        cancel();
        assert!(check().is_err());
        assert!(stage(InitializationStage::AliasCatchup).is_err());
        assert!(status().unwrap().initializing);
        worker.finish(true);
        let terminal = status().unwrap();
        assert_eq!(terminal.stage, InitializationStage::Cancelled);
        assert!(terminal.cancelled);
        assert!(!terminal.initializing);
        assert_eq!(running(), 0);
        PHASE.store(0, Ordering::Release);
        let worker = begin(false);
        let failed: Result<(), i32> = mutate_runtime(|| {
            assert!(!runtime_available());
            let status = super::super::status();
            assert_eq!(status.tracked_sockets, usize::MAX);
            assert_eq!(status.fake_addresses, usize::MAX);
            Err(HH_ERR_INVALID)
        });
        assert_eq!(failed, Err(HH_ERR_INVALID));
        assert!(runtime_available());
        worker.finish(false);
        let worker = begin(true);
        assert!(!runtime_available());
        // Holding a copied Runtime lock cannot block authenticated startup
        // diagnostics: they report unknown inheritance rather than read it.
        let copied_runtime = crate::state().lock().unwrap();
        let snapshot = super::super::status();
        assert_eq!(snapshot.tracked_sockets, usize::MAX);
        assert_eq!(snapshot.fake_addresses, usize::MAX);
        assert!(!snapshot.alias_history_ready);
        assert!(snapshot.alias_inheritance.is_none());
        assert!(snapshot.root_image.is_none());
        drop(copied_runtime);
        drop(worker);
        let failed = status().unwrap();
        assert_eq!(failed.origin, InitializationOrigin::ForkChild);
        assert_eq!(failed.stage, InitializationStage::Failed);
        assert!(!failed.initializing);
        assert!(!failed.runtime_available);
        assert!(failed.native_pin.is_none());
        runtime_rebuilt().unwrap();
        #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
        {
            let live_host = crate::runtime::host_access().unwrap();
            let users = crate::runtime::access_user_counts();
            crate::runtime::replace_fork_state_preserving_access(
                crate::runtime::AgentRuntime::default(),
            );
            assert_eq!(crate::runtime::access_user_counts(), users);
            drop(live_host);
            assert_eq!(crate::runtime::access_user_counts().1 + 1, users.1);
        }
        PHASE.store(1, Ordering::Release);
        let worker = begin(false);
        worker.finish(true);
        cancel(); // Entry-ready but never-Active tracking must stay cancelled.
        assert_eq!(status().unwrap().stage, InitializationStage::Cancelled);
        assert!(check().is_err());
        assert!(commit_initial_owned_activation().is_err());
        assert_eq!(PHASE.load(Ordering::Acquire), 1);
        let worker = begin(false);
        worker.finish(true);
        commit_initial_owned_activation().unwrap();
        cancel(); // Ordinary Active detach does not invalidate reattachment.
        assert_eq!(status().unwrap().stage, InitializationStage::Ready);
        assert!(!cancelled());
        let bootstrap: Bootstrap = serde_json::from_value(serde_json::json!({
            "attachment_id":"binding-fixture","session_id":"fixture-session","token":"t".repeat(64),
            "control_endpoint":"unused-fixture","socks_address":"127.0.0.1:1","tls_ca_pem":"-----BEGIN CERTIFICATE-----fixture",
            "observe":false,"firewall":null,"sandbox":null,"host_endpoint":"unused-fixture-host",
            "host_token":"h".repeat(64),"scope_tree":false,"root_pid":std::process::id(),
            "approval_authority_file":"unused","approval_instance_id":"binding-fixture",
            "approval_core_pid":0,"approval_core_birth":0,
            "approval_cli_sha256":"c".repeat(64)
        })).unwrap();
        assert!(bind_metadata(&bootstrap).unwrap());
        NATIVE_READY.store(true, Ordering::Release);
        let mut replacement = bootstrap.clone();
        replacement.host_endpoint = "different-fixture-host".into();
        assert!(!bind_metadata(&replacement).unwrap());
        assert!(
            native_ready(),
            "duplicate entry cannot clear existing readiness"
        );
        assert_eq!(
            super::super::bootstrap().unwrap().host_endpoint,
            bootstrap.host_endpoint
        );
        replacement.host_token = "x".repeat(64);
        assert!(bind_metadata(&replacement).is_err());
        assert!(native_ready());
    }
}

#[cfg(test)]
#[path = "attachment_startup_rollback_tests.rs"]
mod rollback_tests;
