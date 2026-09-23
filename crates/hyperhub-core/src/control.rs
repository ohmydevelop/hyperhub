use crate::audit::AuditWriter;
use crate::config::Config;
use crate::config_document::ConfigDocument;
use crate::firewall::compile_snapshot as compile_firewall_snapshot;
use crate::framing::{read_frame, write_frame};
use crate::runtime::{RuntimeSnapshot, RuntimeState};
use crate::sandbox::{
    compile_runtime_snapshot, compile_snapshot as compile_sandbox_snapshot, decide_process,
    decide_process_hook, process_protection_binding, sanitize_action, ProtectionContext,
};
use crate::session::{
    unix_timestamp_after, unix_timestamp_ms, verify_config_update_proof, AgentFlags,
    ConnectionRegistry, ControlRequest, ControlResponse, SessionRegistry,
};
use crate::socks::SocksListenerController;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

#[cfg(windows)]
pub const DISCOVERY_CONTROL_ENDPOINT: &str = r"\\.\pipe\hyperhub-control";
#[cfg(unix)]
pub const DISCOVERY_CONTROL_ENDPOINT: &str = "/tmp/hyperhub-control.sock";

#[cfg(windows)]
pub fn discovery_control_endpoint() -> String {
    let sid = crate::config_store::current_user_sid_string().unwrap_or_else(|_| "unknown".into());
    let home = crate::config_store::hyperhub_home()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    windows_control_endpoint(&sid, &home)
}

#[cfg(windows)]
fn windows_control_endpoint(sid: &str, home: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{sid}\0{home}").as_bytes());
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(r"\\.\pipe\hyperhub-{suffix}")
}

#[cfg(unix)]
pub fn discovery_control_endpoint() -> String {
    crate::config_store::hyperhub_home()
        .map(|home| control_endpoint_for_home(&home))
        .unwrap_or_else(|_| std::path::PathBuf::from(DISCOVERY_CONTROL_ENDPOINT))
        .display()
        .to_string()
}

#[cfg(unix)]
fn control_endpoint_for_home(home: &std::path::Path) -> std::path::PathBuf {
    home.join("runtime").join("control.sock")
}

#[cfg(target_os = "linux")]
fn linux_effective_uid() -> io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|metadata| metadata.uid())
}

fn compile_agent_snapshots(
    config: &Config,
    version: u64,
) -> Result<
    (
        Option<crate::firewall::FirewallSnapshot>,
        crate::sandbox::SandboxSnapshot,
    ),
    String,
> {
    let firewall = compile_firewall_snapshot(config, version)?;
    let sandbox = compile_sandbox_snapshot(config, version)?;
    Ok((firewall, sandbox))
}

fn should_record_smart_audit(debug_enabled: bool, action: crate::config::SandboxAction) -> bool {
    action != crate::config::SandboxAction::Pass || debug_enabled
}

fn should_record_sandbox_audit(debug_enabled: bool, source: &str) -> bool {
    source != "smart_protection_pass" || debug_enabled
}

#[derive(Clone)]
pub struct ControlService {
    sessions: SessionRegistry,
    connections: ConnectionRegistry,
    tls_ca_pem: Arc<String>,
    audit: AuditWriter,
    runtime: RuntimeState,
    session_auth_key: Zeroizing<Vec<u8>>,
    started_at_ms: u64,
    debug_forced: bool,
    socks_listener: Option<SocksListenerController>,
    config_update: Arc<tokio::sync::Mutex<()>>,
    shutdown: Option<tokio::sync::watch::Sender<bool>>,
}

impl ControlService {
    pub fn new(
        sessions: SessionRegistry,
        connections: ConnectionRegistry,
        tls_ca_pem: String,
        audit: AuditWriter,
        runtime: RuntimeState,
        session_auth_key: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            sessions,
            connections,
            tls_ca_pem: Arc::new(tls_ca_pem),
            audit,
            runtime,
            session_auth_key,
            started_at_ms: unix_timestamp_ms(),
            debug_forced: false,
            socks_listener: None,
            config_update: Arc::new(tokio::sync::Mutex::new(())),
            shutdown: None,
        }
    }

    pub fn with_forced_debug(mut self, forced: bool) -> Self {
        self.debug_forced = forced;
        self
    }

    pub fn with_socks_listener(mut self, listener: SocksListenerController) -> Self {
        self.socks_listener = Some(listener);
        self
    }

    pub fn with_shutdown(mut self, shutdown: tokio::sync::watch::Sender<bool>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    fn socks_address(&self, runtime: &RuntimeSnapshot) -> String {
        self.socks_listener
            .as_ref()
            .and_then(SocksListenerController::address)
            .map(|address| address.to_string())
            .unwrap_or_else(|| runtime.config.listener.socks_listen.clone())
    }

    async fn update_config(&self, config: Config) -> ControlResponse {
        let _update = self.config_update.lock().await;
        let previous = self.runtime.snapshot();
        let debug = self.debug_forced || config.debug;
        let prepared = match self.runtime.prepare_update(Arc::new(config)) {
            Ok(prepared) => prepared,
            Err(message) => return ControlResponse::Error { message },
        };
        let socks_listener_changed =
            previous.config.listener.socks_listen != prepared.config.listener.socks_listen;
        if socks_listener_changed {
            let Some(listener) = &self.socks_listener else {
                return ControlResponse::Error {
                    message: "SOCKS5 listener hot update is unavailable".into(),
                };
            };
            if let Err(error) = listener
                .ensure_listener(&prepared.config.listener.socks_listen)
                .await
            {
                return ControlResponse::Error {
                    message: format!(
                        "cannot bind SOCKS5 listener {}: {error}",
                        prepared.config.listener.socks_listen
                    ),
                };
            }
        }
        if let Err(error) = self.audit.set_debug(debug) {
            return ControlResponse::Error {
                message: format!("cannot update debug output: {error}"),
            };
        }
        let socks_listen = self.socks_address(&prepared);
        self.runtime.commit_update(prepared);
        self.audit.system_event(
            "config_reloaded",
            serde_json::json!({
                "mode": "hot_update",
                "debug": debug,
                "socks_listen": socks_listen,
                "socks_listener_changed": socks_listener_changed,
            }),
        );
        ControlResponse::Ok
    }

    async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
        peer_pid: Option<u32>,
    ) -> io::Result<()> {
        let request: ControlRequest = read_frame(&mut stream).await?;
        if let ControlRequest::SubscribeSandbox {
            session_id,
            token,
            current_version,
        } = request
        {
            return self
                .subscribe_sandbox(stream, peer_pid, session_id, token, current_version)
                .await;
        }
        let runtime = self.runtime.snapshot();
        let mut shutdown_requested = false;
        let response = match request {
            ControlRequest::BeginSessionAuth {
                session_id,
                executable,
                client_nonce,
            } => {
                let ttl = Duration::from_secs(runtime.config.listener.pending_session_ttl_secs);
                let inherited = peer_pid.and_then(|client_pid| {
                    process_ancestors(client_pid)
                        .into_iter()
                        .find_map(|parent_pid| {
                            let expected = self.sessions.member_executable(parent_pid)?;
                            validate_process_path(parent_pid, &expected).ok()?;
                            self.sessions.begin_inherited(
                                session_id.clone(),
                                executable.clone(),
                                parent_pid,
                                ttl,
                            )
                        })
                });
                if let Some(record) = inherited {
                    self.audit.session_event(
                        "session_auth",
                        &record.session_id,
                        peer_pid,
                        Some(&record.executable),
                        serde_json::json!({
                            "mode": "automatic_parent",
                        }),
                    );
                    self.bootstrap(&runtime, record, ttl)
                } else if let Some(record) =
                    self.sessions
                        .begin_cached_auth(session_id.clone(), executable.clone(), ttl)
                {
                    self.audit.session_event(
                        "session_auth",
                        &record.session_id,
                        peer_pid,
                        Some(&record.executable),
                        serde_json::json!({
                            "mode": "cached",
                        }),
                    );
                    self.bootstrap(&runtime, record, ttl)
                } else {
                    match self
                        .sessions
                        .begin_auth(session_id, executable, client_nonce)
                    {
                        Some(challenge) => ControlResponse::SessionChallenge { challenge },
                        None => ControlResponse::Error {
                            message: "session authentication is temporarily unavailable".into(),
                        },
                    }
                }
            }
            ControlRequest::FinishSessionAuth {
                challenge_id,
                proof,
            } => {
                let ttl = Duration::from_secs(runtime.config.listener.pending_session_ttl_secs);
                let Some(record) = self.sessions.finish_auth(&challenge_id, &proof, ttl) else {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    write_frame(
                        &mut stream,
                        &ControlResponse::Error {
                            message: "invalid password or expired authentication challenge".into(),
                        },
                    )
                    .await?;
                    return Ok(());
                };
                self.audit.session_event(
                    "session_auth",
                    &record.session_id,
                    peer_pid,
                    Some(&record.executable),
                    serde_json::json!({
                        "mode": "password",
                    }),
                );
                self.bootstrap(&runtime, record, ttl)
            }
            ControlRequest::BootstrapChild => {
                let inherited = peer_pid.and_then(|child_pid| {
                    let executable = process_path(child_pid).ok()?.display().to_string();
                    let record =
                        process_ancestors(child_pid)
                            .into_iter()
                            .find_map(|parent_pid| {
                                let expected = self.sessions.member_executable(parent_pid)?;
                                validate_process_path(parent_pid, &expected).ok()?;
                                self.sessions.inherit_member(
                                    parent_pid,
                                    child_pid,
                                    executable.clone(),
                                )
                            })?;
                    Some((record, child_pid, executable))
                });
                match inherited {
                    Some((record, child_pid, executable)) => {
                        if let Err(error) = monitor_new_session_member(
                            &self.sessions,
                            &record.session_id,
                            &record.token,
                            child_pid,
                            &executable,
                        ) {
                            return write_frame(
                                &mut stream,
                                &ControlResponse::Error {
                                    message: format!(
                                        "cannot monitor inherited child process: {error}"
                                    ),
                                },
                            )
                            .await;
                        }
                        self.sessions.note_agent(
                            &record.session_id,
                            &record.token,
                            child_pid,
                            runtime.updated_at_ms,
                        );
                        self.audit.session_event(
                            "child_session_inherited",
                            &record.session_id,
                            Some(child_pid),
                            Some(&executable),
                            serde_json::json!({}),
                        );
                        match compile_agent_snapshots(&runtime.config, runtime.updated_at_ms) {
                            Ok((firewall, sandbox)) => ControlResponse::AgentBootstrap {
                                socks_address: self.socks_address(&runtime),
                                control_endpoint: discovery_control_endpoint(),
                                session_id: record.session_id,
                                token: record.token,
                                tls_ca_pem: self.tls_ca_pem.as_ref().clone(),
                                agent_flags: AgentFlags {
                                    observe: runtime.config.mode
                                        == crate::config::EnforcementMode::Observe,
                                },
                                environment: runtime.environment.as_ref().clone(),
                                firewall,
                                sandbox: Some(sandbox),
                            },
                            Err(message) => ControlResponse::Error {
                                message: format!("cannot compile agent snapshots: {message}"),
                            },
                        }
                    }
                    None => ControlResponse::Error {
                        message: "child process has no valid ancestor session".into(),
                    },
                }
            }
            ControlRequest::CheckRootProcessProtection {
                session_id,
                token,
                executable,
                argv,
            } => {
                if !self.sessions.authenticate_pending(&session_id, &token) {
                    ControlResponse::Error {
                        message: "invalid root process protection reporter".into(),
                    }
                } else {
                    let command_line = argv.join(" ");
                    let compiled = compile_sandbox_snapshot(&runtime.config, runtime.updated_at_ms)
                        .and_then(|snapshot| {
                            compile_runtime_snapshot(snapshot).map_err(|error| error.to_string())
                        });
                    match compiled {
                        Err(error) => ControlResponse::Error {
                            message: format!("cannot compile root process protection: {error}"),
                        },
                        Ok(snapshot) => {
                            let Some(process) = snapshot.process.as_ref() else {
                                return write_frame(
                                    &mut stream,
                                    &ControlResponse::SmartProtectionDecision {
                                        action: crate::config::SandboxAction::Pass,
                                        reason: "sandbox_disabled".into(),
                                        risk_level: None,
                                        confidence: None,
                                        cache_hit: false,
                                    },
                                )
                                .await;
                            };
                            let static_decision =
                                decide_process(process, &executable, &command_line);
                            let binding =
                                process_protection_binding(process, &executable, &command_line);
                            let mut action = static_decision.action;
                            let mut reason = static_decision.source.to_owned();
                            let mut rule_id = static_decision.rule_id.clone();
                            let mut risk_level = None;
                            let mut confidence = None;
                            let mut cache_hit = false;
                            let mut audit_features = Vec::new();
                            let context = ProtectionContext::default();
                            let sanitized = sanitize_action(&executable, &argv, &context);
                            let audit_argv = sanitized.redacted_argv.clone();
                            let mut destructive_probability = None;
                            let mut blast_radius = None;
                            let mut provider_queried = false;
                            let smart_binding = binding.is_some();
                            if action != crate::config::SandboxAction::Deny {
                                if let Some(binding) = binding {
                                    rule_id = Some(binding.rule_id.clone());
                                    audit_features = sanitized.features.clone();
                                    if sanitized.local_deny {
                                        action = if runtime
                                            .protection
                                            .profile_mode(&binding.protection_id)
                                            == Some(crate::config::ProtectionMode::Enforce)
                                        {
                                            crate::config::SandboxAction::Deny
                                        } else {
                                            crate::config::SandboxAction::Pass
                                        };
                                        reason = "local_data_protection".into();
                                    } else {
                                        provider_queried = true;
                                        let outcome = runtime
                                            .protection
                                            .evaluate_agent(
                                                &binding.protection_id,
                                                &session_id,
                                                peer_pid.unwrap_or_default(),
                                                &executable,
                                                "root_process_create",
                                                sanitized.redacted_argv.clone(),
                                                sanitized.features.clone(),
                                                serde_json::to_value(&context)
                                                    .unwrap_or_else(|_| serde_json::json!({})),
                                            )
                                            .await;
                                        let provider = outcome
                                            .provider
                                            .as_ref()
                                            .filter(|item| item.error.is_none());
                                        action = if outcome.deny {
                                            crate::config::SandboxAction::Deny
                                        } else {
                                            crate::config::SandboxAction::Pass
                                        };
                                        reason = outcome
                                            .reason
                                            .unwrap_or_else(|| "provider_pass".into());
                                        risk_level =
                                            provider.and_then(|item| item.risk_level.clone());
                                        confidence = provider.and_then(|item| item.confidence);
                                        destructive_probability =
                                            provider.and_then(|item| item.destructive_probability);
                                        blast_radius = provider.and_then(|item| item.blast_radius);
                                        cache_hit = provider.is_some_and(|item| item.cache_hit);
                                    }
                                }
                            }
                            let smart_pass =
                                action == crate::config::SandboxAction::Pass && smart_binding;
                            if !smart_pass || self.audit.debug_enabled() {
                                let event_name = if action == crate::config::SandboxAction::Deny {
                                    "sandbox_denied"
                                } else {
                                    "sandbox_allowed"
                                };
                                self.audit.session_event(
                                    event_name,
                                    &session_id,
                                    peer_pid,
                                    Some(&executable),
                                    serde_json::json!({
                                        "kind": "process",
                                        "decision": action,
                                        "rule_id": rule_id,
                                        "decision_source": reason,
                                        "operation": "root_create",
                                        "target": executable,
                                        "argv_redacted": audit_argv.clone(),
                                        "reporter": "root-launcher",
                                    }),
                                );
                            }
                            if smart_binding
                                && (action != crate::config::SandboxAction::Pass
                                    || self.audit.debug_enabled())
                            {
                                self.audit.session_event(
                                    "smart_protection_decision",
                                    &session_id,
                                    peer_pid,
                                    Some(&executable),
                                    serde_json::json!({
                                        "rule_id": rule_id,
                                        "stage": "root_process_create",
                                        "action": action,
                                        "reason": reason,
                                        "argv_redacted": audit_argv,
                                        "features": audit_features,
                                        "risk_level": risk_level,
                                        "confidence": confidence,
                                        "destructive_probability": destructive_probability,
                                        "blast_radius": blast_radius,
                                        "cache_hit": cache_hit,
                                        "provider_queried": provider_queried,
                                        "reporter": "root-launcher",
                                    }),
                                );
                            }
                            ControlResponse::SmartProtectionDecision {
                                action,
                                reason,
                                risk_level,
                                confidence,
                                cache_hit,
                            }
                        }
                    }
                }
            }
            ControlRequest::DecideProcessHook {
                session_id,
                token,
                executable,
                root: _,
            } => {
                if !self.sessions.authenticate_member(
                    &session_id,
                    &token,
                    peer_pid.unwrap_or_default(),
                ) {
                    ControlResponse::Error {
                        message: "invalid process hook reporter".into(),
                    }
                } else {
                    match compile_sandbox_snapshot(&runtime.config, runtime.updated_at_ms).and_then(
                        |snapshot| {
                            compile_runtime_snapshot(snapshot).map_err(|error| error.to_string())
                        },
                    ) {
                        Ok(snapshot) => {
                            let decision = snapshot
                                .process
                                .as_ref()
                                .map(|process| decide_process_hook(process, &executable));
                            let decision = decision.unwrap_or(crate::sandbox::SandboxDecision {
                                action: crate::config::SandboxAction::Pass,
                                rule_id: None,
                                source: "default",
                            });
                            ControlResponse::ProcessHookDecision {
                                hook: true,
                                rule_id: decision.rule_id,
                                source: decision.source.into(),
                                version: runtime.updated_at_ms,
                            }
                        }
                        Err(_) => ControlResponse::ProcessHookDecision {
                            hook: true,
                            rule_id: None,
                            source: "fallback".into(),
                            version: runtime.updated_at_ms,
                        },
                    }
                }
            }
            ControlRequest::ActivateSession {
                session_id,
                token,
                root_pid,
                executable,
                root_executable,
                process_policy_version,
                process_rule_id,
                process_decision_source,
            } => match self.sessions.pending_executable(&session_id, &token) {
                Some(expected)
                    if same_requested_executable(&expected, &executable)
                        && root_executable.as_deref().is_none_or(|root| {
                            peer_pid.is_some_and(|peer_pid| {
                                validate_process_path(peer_pid, root).is_ok()
                            })
                        }) =>
                {
                    let root_executable = root_executable.as_deref().unwrap_or(&expected);
                    match open_validated_root_process(root_pid, root_executable) {
                        Ok(handle)
                            if self.sessions.activate_with_policy(
                                &session_id,
                                &token,
                                root_pid,
                                crate::session::ProcessHookMetadata {
                                    hook_status: "hook".into(),
                                    policy_version: process_policy_version,
                                    rule_id: process_rule_id,
                                    decision_source: process_decision_source,
                                },
                            ) =>
                        {
                            let instance = self
                                .sessions
                                .member_instance(&session_id, &token, root_pid)
                                .expect("activated root process must have a member instance");
                            match monitor_session_member(
                                handle,
                                session_id.clone(),
                                root_pid,
                                instance,
                                self.sessions.clone(),
                            ) {
                                Ok(()) => ControlResponse::Ok,
                                Err(error) => {
                                    self.sessions.revoke(&session_id);
                                    ControlResponse::Error {
                                        message: format!("cannot monitor root process: {error}"),
                                    }
                                }
                            }
                        }
                        Ok(handle) => {
                            close_process_handle(handle);
                            ControlResponse::Error {
                                message: "invalid or expired pending session".into(),
                            }
                        }
                        Err(error) => ControlResponse::Error {
                            message: error.to_string(),
                        },
                    }
                }
                Some(_) => ControlResponse::Error {
                    message: "activated executable does not match the authenticated target".into(),
                },
                None => ControlResponse::Error {
                    message: "invalid or expired pending session".into(),
                },
            },
            ControlRequest::RegisterChild {
                session_id,
                token,
                parent_pid,
                child_pid,
                executable,
                process_policy_version,
                process_rule_id,
                process_decision_source,
            } => {
                let policy = crate::session::ProcessHookMetadata {
                    hook_status: "hook".into(),
                    policy_version: process_policy_version,
                    rule_id: process_rule_id,
                    decision_source: process_decision_source,
                };
                let refreshing = peer_pid == Some(child_pid)
                    && self
                        .sessions
                        .authenticate_member(&session_id, &token, child_pid);
                let valid_process = if refreshing {
                    validate_process_path(child_pid, &executable)
                } else {
                    validate_child_process(parent_pid, child_pid, &executable)
                };
                let registered = valid_process.is_ok()
                    && if refreshing {
                        self.sessions.refresh_member_with_policy(
                            &session_id,
                            &token,
                            child_pid,
                            executable.clone(),
                            policy,
                        )
                    } else {
                        self.sessions.register_child_with_policy(
                            &session_id,
                            &token,
                            parent_pid,
                            child_pid,
                            executable.clone(),
                            policy,
                        )
                    };
                if registered {
                    if refreshing {
                        ControlResponse::Ok
                    } else {
                        match monitor_new_session_member(
                            &self.sessions,
                            &session_id,
                            &token,
                            child_pid,
                            &executable,
                        ) {
                            Ok(()) => ControlResponse::Ok,
                            Err(error) => ControlResponse::Error {
                                message: format!("cannot monitor child process: {error}"),
                            },
                        }
                    }
                } else {
                    ControlResponse::Error {
                        message: valid_process
                            .err()
                            .map(|error| error.to_string())
                            .unwrap_or_else(|| "invalid child session registration".into()),
                    }
                }
            }
            ControlRequest::BeginFork {
                session_id,
                token,
                parent_pid,
            } => {
                if peer_pid == Some(parent_pid) {
                    match self.sessions.begin_fork_lease(
                        &session_id,
                        &token,
                        parent_pid,
                        Duration::from_secs(300),
                    ) {
                        Some(lease_id) => {
                            self.audit.session_event(
                                "fork_lease_started",
                                &session_id,
                                Some(parent_pid),
                                None,
                                serde_json::json!({ "runtime": "msys_cygwin" }),
                            );
                            ControlResponse::ForkLease { lease_id }
                        }
                        None => ControlResponse::Error {
                            message: "cannot authorize MSYS/Cygwin fork lease".into(),
                        },
                    }
                } else {
                    ControlResponse::Error {
                        message: "fork lease parent does not match control peer".into(),
                    }
                }
            }
            ControlRequest::RegisterForkCandidate {
                session_id,
                token,
                lease_id,
                parent_pid,
                child_pid,
                executable,
            } => {
                let valid = peer_pid == Some(parent_pid)
                    && validate_child_process(parent_pid, child_pid, &executable).is_ok()
                    && self.sessions.register_fork_candidate(
                        &session_id,
                        &token,
                        &lease_id,
                        parent_pid,
                        child_pid,
                        executable.clone(),
                    );
                if !valid {
                    ControlResponse::Error {
                        message: "invalid MSYS/Cygwin fork candidate".into(),
                    }
                } else {
                    match monitor_new_session_member(
                        &self.sessions,
                        &session_id,
                        &token,
                        child_pid,
                        &executable,
                    ) {
                        Ok(()) => {
                            self.audit.session_event(
                                "fork_candidate_registered",
                                &session_id,
                                Some(child_pid),
                                Some(&executable),
                                serde_json::json!({
                                    "runtime": "msys_cygwin",
                                    "parent_pid": parent_pid,
                                }),
                            );
                            let sessions = self.sessions.clone();
                            let audit = self.audit.clone();
                            let observe =
                                runtime.config.mode == crate::config::EnforcementMode::Observe;
                            let session_id_for_timeout = session_id.clone();
                            let lease_id_for_timeout = lease_id.clone();
                            let executable_for_timeout = executable.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(10)).await;
                                if let Some(pid) = sessions.expire_fork_candidate(
                                    &session_id_for_timeout,
                                    &lease_id_for_timeout,
                                    child_pid,
                                ) {
                                    audit.session_event(
                                        "fork_child_uncovered",
                                        &session_id_for_timeout,
                                        Some(pid),
                                        Some(&executable_for_timeout),
                                        serde_json::json!({
                                            "runtime": "msys_cygwin",
                                            "stage": "attestation_timeout",
                                            "error_code": windows_access_denied_error(),
                                            "coverage": if observe { "observe_uncovered" } else { "terminated" },
                                        }),
                                    );
                                    if !observe {
                                        terminate_process_by_pid(pid);
                                    }
                                }
                            });
                            ControlResponse::ForkStatus { attested: false }
                        }
                        Err(error) => ControlResponse::Error {
                            message: format!("cannot monitor fork candidate: {error}"),
                        },
                    }
                }
            }
            ControlRequest::GetPendingForkLease { session_id, token } => {
                let child_pid = peer_pid.unwrap_or_default();
                match self
                    .sessions
                    .pending_fork_lease_for_candidate(&session_id, &token, child_pid)
                {
                    Some(lease_id) => {
                        self.audit.session_event(
                            "fork_child_postfork_started",
                            &session_id,
                            Some(child_pid),
                            None,
                            serde_json::json!({
                                "runtime": "msys_cygwin",
                                "stage": "agent_reload",
                            }),
                        );
                        ControlResponse::ForkLease { lease_id }
                    }
                    None => ControlResponse::Error {
                        message: "control peer is not a pending fork candidate".into(),
                    },
                }
            }
            ControlRequest::AttestForkChild {
                session_id,
                token,
                lease_id,
                runtime_generation,
                hook_manifest,
                policy_version,
            } => {
                let child_pid = peer_pid.unwrap_or_default();
                let hook_manifest_complete = required_fork_hook_manifest()
                    .iter()
                    .all(|required| hook_manifest.iter().any(|hook| hook == required));
                let attested = hook_manifest_complete
                    && runtime_generation > 0
                    && policy_version == runtime.updated_at_ms
                    && self.sessions.attest_fork_child(
                        &session_id,
                        &token,
                        &lease_id,
                        child_pid,
                        policy_version,
                    );
                if !attested {
                    ControlResponse::Error {
                        message: "invalid or incomplete MSYS/Cygwin fork attestation".into(),
                    }
                } else {
                    self.sessions
                        .note_agent(&session_id, &token, child_pid, policy_version);
                    self.audit.session_event(
                        "fork_child_attested",
                        &session_id,
                        Some(child_pid),
                        None,
                        serde_json::json!({
                            "runtime": "msys_cygwin",
                            "runtime_generation": runtime_generation,
                            "policy_version": policy_version,
                            "hook_manifest_count": hook_manifest.len(),
                        }),
                    );
                    match compile_agent_snapshots(&runtime.config, runtime.updated_at_ms) {
                        Ok((firewall, sandbox)) => ControlResponse::TrustBootstrap {
                            socks_address: self.socks_address(&runtime),
                            agent_flags: AgentFlags {
                                observe: runtime.config.mode
                                    == crate::config::EnforcementMode::Observe,
                            },
                            environment: runtime.environment.as_ref().clone(),
                            tls_ca_pem: self.tls_ca_pem.as_ref().clone(),
                            firewall,
                            sandbox: Some(sandbox),
                        },
                        Err(message) => ControlResponse::Error {
                            message: format!("cannot compile fork child snapshots: {message}"),
                        },
                    }
                }
            }
            ControlRequest::FinishFork {
                session_id,
                token,
                lease_id,
                require_attested,
            } => {
                let parent_pid = peer_pid.unwrap_or_default();
                let status =
                    self.sessions
                        .fork_lease_status(&session_id, &token, &lease_id, parent_pid);
                let attested = status == Some(crate::session::ForkLeaseStatus::Attested);
                if require_attested && !attested {
                    if let Some(finished) =
                        self.sessions
                            .finish_fork_lease(&session_id, &token, &lease_id, false)
                    {
                        if let Some(child_pid) = finished.candidate_pid {
                            terminate_process_by_pid(child_pid);
                        }
                    }
                    ControlResponse::Error {
                        message: "fork child did not complete Hook attestation".into(),
                    }
                } else if self
                    .sessions
                    .finish_fork_lease(&session_id, &token, &lease_id, require_attested)
                    .is_some()
                {
                    ControlResponse::ForkStatus { attested }
                } else {
                    ControlResponse::Error {
                        message: "invalid or expired fork lease".into(),
                    }
                }
            }
            ControlRequest::GetForkStatus {
                session_id,
                token,
                lease_id,
            } => {
                let parent_pid = peer_pid.unwrap_or_default();
                match self
                    .sessions
                    .fork_lease_status(&session_id, &token, &lease_id, parent_pid)
                {
                    Some(status) => {
                        if self.sessions.is_fork_candidate(
                            &session_id,
                            &token,
                            &lease_id,
                            parent_pid,
                        ) {
                            self.audit.session_event(
                                "fork_child_postfork_started",
                                &session_id,
                                Some(parent_pid),
                                None,
                                serde_json::json!({
                                    "runtime": "msys_cygwin",
                                    "stage": "postfork_entry",
                                }),
                            );
                        }
                        ControlResponse::ForkStatus {
                            attested: status == crate::session::ForkLeaseStatus::Attested,
                        }
                    }
                    None => ControlResponse::Error {
                        message: "invalid or expired fork lease".into(),
                    },
                }
            }
            ControlRequest::ReportChildInjectionFailure {
                session_id,
                token,
                parent_pid,
                child_pid,
                executable,
                stage,
                error_code,
            } => {
                if self
                    .sessions
                    .authenticate_member(&session_id, &token, parent_pid)
                {
                    self.audit.session_event(
                        "child_injection_uncovered",
                        &session_id,
                        Some(child_pid),
                        executable.as_deref(),
                        serde_json::json!({
                            "parent_pid": parent_pid,
                            "stage": stage,
                            "error_code": error_code,
                        }),
                    );
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error {
                        message: "invalid parent session for child failure report".into(),
                    }
                }
            }
            ControlRequest::RevokeSession { session_id } => {
                self.sessions.revoke(&session_id);
                ControlResponse::Ok
            }
            ControlRequest::ClearPasswordAuthorization => {
                if self.sessions.clear_password_authorization() {
                    self.audit.session_event(
                        "authorization_cache_cleared",
                        "authorization-cache",
                        peer_pid,
                        None,
                        serde_json::json!({}),
                    );
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error {
                        message: "authorization cache is temporarily unavailable".into(),
                    }
                }
            }
            ControlRequest::Ping => ControlResponse::Ok,
            ControlRequest::ResolveName {
                session_id,
                token,
                hostname,
                family,
            } => match self
                .sessions
                .resolve_fake(&session_id, &token, &hostname, family)
            {
                Some(address) => ControlResponse::ResolvedName {
                    address: address.to_string(),
                    ttl_secs: 60,
                },
                None => ControlResponse::Error {
                    message: "invalid session, hostname, or address family".into(),
                },
            },
            ControlRequest::GetTrust { session_id, token } => {
                if self.sessions.authenticate_control(&session_id, &token) {
                    let executable = peer_pid.and_then(|pid| {
                        let executable = match self.sessions.member_executable(pid) {
                            Some(executable) => executable,
                            None => {
                                let executable = process_path(pid).ok()?.display().to_string();
                                let parent_pid =
                                    process_ancestors(pid).into_iter().find(|parent_pid| {
                                        self.sessions.authenticate_member(
                                            &session_id,
                                            &token,
                                            *parent_pid,
                                        ) && validate_child_process(*parent_pid, pid, &executable)
                                            .is_ok()
                                    })?;
                                if !self.sessions.register_child(
                                    &session_id,
                                    &token,
                                    parent_pid,
                                    pid,
                                    executable.clone(),
                                ) {
                                    return None;
                                }
                                monitor_new_session_member(
                                    &self.sessions,
                                    &session_id,
                                    &token,
                                    pid,
                                    &executable,
                                )
                                .ok()?;
                                executable
                            }
                        };
                        self.sessions
                            .note_agent(&session_id, &token, pid, runtime.updated_at_ms)
                            .then_some(executable)
                    });
                    match executable {
                        Some(_executable) => {
                            match compile_agent_snapshots(&runtime.config, runtime.updated_at_ms) {
                                Ok((firewall, sandbox)) => ControlResponse::TrustBootstrap {
                                    socks_address: self.socks_address(&runtime),
                                    agent_flags: AgentFlags {
                                        observe: runtime.config.mode
                                            == crate::config::EnforcementMode::Observe,
                                    },
                                    environment: runtime.environment.as_ref().clone(),
                                    tls_ca_pem: self.tls_ca_pem.as_ref().clone(),
                                    firewall,
                                    sandbox: Some(sandbox),
                                },
                                Err(message) => ControlResponse::Error {
                                    message: format!("cannot compile agent snapshots: {message}"),
                                },
                            }
                        }
                        None => ControlResponse::Error {
                            message: "control peer is not a member of the requested session".into(),
                        },
                    }
                } else {
                    ControlResponse::Error {
                        message: "invalid or expired session".into(),
                    }
                }
            }
            ControlRequest::RefreshFirewall {
                session_id,
                token,
                current_version,
            } => match peer_pid.and_then(|pid| {
                self.sessions
                    .member_executable(pid)
                    .map(|executable| (pid, executable))
            }) {
                Some((pid, _executable))
                    if self
                        .sessions
                        .note_agent(&session_id, &token, pid, current_version) =>
                {
                    if current_version >= runtime.updated_at_ms {
                        ControlResponse::FirewallRefresh {
                            version: current_version,
                            changed: false,
                            firewall: None,
                        }
                    } else {
                        match compile_firewall_snapshot(&runtime.config, runtime.updated_at_ms) {
                            Ok(firewall) => ControlResponse::FirewallRefresh {
                                version: runtime.updated_at_ms,
                                changed: true,
                                firewall,
                            },
                            Err(message) => ControlResponse::Error {
                                message: format!("cannot compile firewall snapshot: {message}"),
                            },
                        }
                    }
                }
                _ => ControlResponse::Error {
                    message: "invalid firewall refresh reporter".into(),
                },
            },
            ControlRequest::RefreshSandbox {
                session_id,
                token,
                root_pid,
                current_version,
            } => {
                if !self
                    .sessions
                    .authenticate_member(&session_id, &token, root_pid)
                {
                    ControlResponse::Error {
                        message: "invalid sandbox refresh session".into(),
                    }
                } else if current_version >= runtime.updated_at_ms {
                    ControlResponse::SandboxRefresh {
                        version: current_version,
                        changed: false,
                        enforce: runtime.config.mode == crate::config::EnforcementMode::Enforce,
                        sandbox: None,
                    }
                } else {
                    match compile_sandbox_snapshot(&runtime.config, runtime.updated_at_ms) {
                        Ok(sandbox) => ControlResponse::SandboxRefresh {
                            version: runtime.updated_at_ms,
                            changed: true,
                            enforce: runtime.config.mode == crate::config::EnforcementMode::Enforce,
                            sandbox: Some(sandbox),
                        },
                        Err(message) => ControlResponse::Error {
                            message: format!("cannot compile sandbox snapshot: {message}"),
                        },
                    }
                }
            }
            ControlRequest::ReportFirewallAudit {
                session_id,
                token,
                event,
            } => {
                let authenticated = peer_pid.is_some_and(|pid| {
                    pid == event.process_pid
                        && self.sessions.authenticate_member(&session_id, &token, pid)
                });
                if authenticated {
                    let event_name = match event.decision {
                        crate::config::FirewallAction::Pass => "firewall_allowed",
                        crate::config::FirewallAction::Deny => "firewall_denied",
                        crate::config::FirewallAction::Smart => "firewall_allowed",
                    };
                    self.audit.session_event(
                        event_name,
                        &session_id,
                        Some(event.process_pid),
                        self.sessions
                            .member_executable(event.process_pid)
                            .as_deref(),
                        serde_json::json!({
                            "decision": event.decision,
                            "rule_id": event.rule_id,
                            "decision_source": event.source,
                            "stage": event.stage,
                            "hostname": event.hostname,
                            "ip": event.ip,
                            "port": event.port,
                            "process_tid": event.process_tid,
                            "snapshot_version": event.snapshot_version,
                        }),
                    );
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error {
                        message: "invalid firewall audit reporter".into(),
                    }
                }
            }
            ControlRequest::ReportStaticSandboxAudit {
                session_id,
                token,
                root_pid,
                event,
            } => {
                let authenticated = peer_pid.is_some_and(|reporter| {
                    process_ancestors(root_pid).contains(&reporter)
                        && self
                            .sessions
                            .authenticate_member(&session_id, &token, root_pid)
                        && self
                            .sessions
                            .authenticate_member(&session_id, &token, event.process_pid)
                });
                if authenticated {
                    if should_record_sandbox_audit(self.audit.debug_enabled(), &event.source) {
                        let event_name = match event.decision {
                            crate::config::SandboxAction::Pass => "sandbox_allowed",
                            crate::config::SandboxAction::Deny => "sandbox_denied",
                            crate::config::SandboxAction::Smart => "sandbox_allowed",
                        };
                        self.audit.session_event(
                            event_name,
                            &session_id,
                            Some(event.process_pid),
                            self.sessions
                                .member_executable(event.process_pid)
                                .as_deref(),
                            serde_json::json!({
                                "kind": event.kind,
                                "decision": event.decision,
                                "rule_id": event.rule_id,
                                "decision_source": event.source,
                                "operation": event.operation,
                                "target": event.target,
                                "argv_redacted": event.argv_redacted,
                                "process_tid": event.process_tid,
                                "snapshot_version": event.snapshot_version,
                                "reporter": "static-supervisor",
                            }),
                        );
                    }
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error {
                        message: "invalid static sandbox audit reporter".into(),
                    }
                }
            }
            ControlRequest::ReportSandboxAudit {
                session_id,
                token,
                event,
            } => {
                let authenticated = peer_pid.is_some_and(|pid| {
                    pid == event.process_pid
                        && self.sessions.authenticate_member(&session_id, &token, pid)
                });
                if authenticated {
                    if should_record_sandbox_audit(self.audit.debug_enabled(), &event.source) {
                        let event_name = match event.decision {
                            crate::config::SandboxAction::Pass => "sandbox_allowed",
                            crate::config::SandboxAction::Deny => "sandbox_denied",
                            crate::config::SandboxAction::Smart => "sandbox_allowed",
                        };
                        self.audit.session_event(event_name, &session_id, Some(event.process_pid), self.sessions.member_executable(event.process_pid).as_deref(), serde_json::json!({
                            "kind": event.kind, "decision": event.decision, "rule_id": event.rule_id, "decision_source": event.source,
                            "operation": event.operation, "target": event.target, "argv_redacted": event.argv_redacted, "process_tid": event.process_tid,
                            "snapshot_version": event.snapshot_version,
                        }));
                    }
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error {
                        message: "invalid sandbox audit reporter".into(),
                    }
                }
            }
            ControlRequest::StaticSmartProtectionCheck {
                session_id,
                token,
                root_pid,
                process_pid,
                protection_id,
                rule_id,
                stage,
                executable,
                argv,
                features,
                context,
            } => {
                let authenticated = peer_pid.is_some_and(|reporter| {
                    process_ancestors(root_pid).contains(&reporter)
                        && self
                            .sessions
                            .authenticate_member(&session_id, &token, root_pid)
                        && self
                            .sessions
                            .authenticate_member(&session_id, &token, process_pid)
                });
                if !authenticated {
                    ControlResponse::Error {
                        message: "invalid static smart protection reporter".into(),
                    }
                } else {
                    let audit_argv = argv.clone();
                    let audit_features = features.clone();
                    let outcome = runtime
                        .protection
                        .evaluate_agent(
                            &protection_id,
                            &session_id,
                            process_pid,
                            &executable,
                            &stage,
                            argv,
                            features,
                            context,
                        )
                        .await;
                    let provider = outcome
                        .provider
                        .as_ref()
                        .filter(|item| item.error.is_none());
                    let action = if outcome.deny {
                        crate::config::SandboxAction::Deny
                    } else {
                        crate::config::SandboxAction::Pass
                    };
                    let reason = outcome
                        .reason
                        .clone()
                        .unwrap_or_else(|| "provider_pass".into());
                    let risk_level = provider.and_then(|item| item.risk_level.clone());
                    let confidence = provider.and_then(|item| item.confidence);
                    let destructive_probability =
                        provider.and_then(|item| item.destructive_probability);
                    let blast_radius = provider.and_then(|item| item.blast_radius);
                    let cache_hit = provider.is_some_and(|item| item.cache_hit);
                    if should_record_smart_audit(self.audit.debug_enabled(), action) {
                        self.audit.session_event(
                            "smart_protection_decision",
                            &session_id,
                            Some(process_pid),
                            Some(&executable),
                            serde_json::json!({
                                "protection": protection_id,
                                "rule_id": rule_id,
                                "stage": stage,
                                "action": action,
                                "reason": reason,
                                "argv_redacted": audit_argv,
                                "features": audit_features,
                                "risk_level": risk_level,
                                "confidence": confidence,
                                "destructive_probability": destructive_probability,
                                "blast_radius": blast_radius,
                                "cache_hit": cache_hit,
                                "reporter": "static-supervisor",
                            }),
                        );
                    }
                    ControlResponse::SmartProtectionDecision {
                        action,
                        reason,
                        risk_level,
                        confidence,
                        cache_hit,
                    }
                }
            }
            ControlRequest::SmartProtectionCheck {
                session_id,
                token,
                protection_id,
                rule_id,
                stage,
                executable,
                argv,
                features,
                context,
            } => {
                if peer_pid.is_none() {
                    ControlResponse::Error {
                        message: "invalid smart protection reporter".into(),
                    }
                } else if !self
                    .sessions
                    .authenticate_member(&session_id, &token, peer_pid.unwrap())
                {
                    ControlResponse::Error {
                        message: "invalid smart protection reporter".into(),
                    }
                } else {
                    let reporter_pid = peer_pid.unwrap();
                    let audit_argv = argv.clone();
                    let audit_features = features.clone();
                    let outcome = runtime
                        .protection
                        .evaluate_agent(
                            &protection_id,
                            &session_id,
                            reporter_pid,
                            &executable,
                            &stage,
                            argv,
                            features,
                            context,
                        )
                        .await;
                    let provider = outcome
                        .provider
                        .as_ref()
                        .filter(|item| item.error.is_none());
                    let action = if outcome.deny {
                        crate::config::SandboxAction::Deny
                    } else {
                        crate::config::SandboxAction::Pass
                    };
                    let reason = outcome
                        .reason
                        .clone()
                        .unwrap_or_else(|| "provider_pass".into());
                    let risk_level = provider.and_then(|item| item.risk_level.clone());
                    let confidence = provider.and_then(|item| item.confidence);
                    let destructive_probability =
                        provider.and_then(|item| item.destructive_probability);
                    let blast_radius = provider.and_then(|item| item.blast_radius);
                    let cache_hit = provider.is_some_and(|item| item.cache_hit);
                    if should_record_smart_audit(self.audit.debug_enabled(), action) {
                        self.audit.session_event(
                            "smart_protection_decision",
                            &session_id,
                            Some(reporter_pid),
                            Some(&executable),
                            serde_json::json!({
                                "protection": protection_id,
                                "rule_id": rule_id,
                                "stage": stage,
                                "action": action,
                                "reason": reason,
                                "argv_redacted": audit_argv,
                                "features": audit_features,
                                "risk_level": risk_level,
                                "confidence": confidence,
                                "destructive_probability": destructive_probability,
                                "blast_radius": blast_radius,
                                "cache_hit": cache_hit,
                            }),
                        );
                    }
                    ControlResponse::SmartProtectionDecision {
                        action,
                        reason,
                        risk_level,
                        confidence,
                        cache_hit,
                    }
                }
            }
            ControlRequest::UpdateConfig { proof, config_json } => {
                if !verify_config_update_proof(&self.session_auth_key, &config_json, &proof) {
                    ControlResponse::Error {
                        message: "invalid config update proof".into(),
                    }
                } else {
                    match serde_json::from_str::<ConfigDocument>(&config_json)
                        .map_err(|error| error.to_string())
                        .and_then(|document| document.into_config())
                    {
                        Ok(config) => self.update_config(config).await,
                        Err(error) => ControlResponse::Error {
                            message: format!("invalid config: {error}"),
                        },
                    }
                }
            }
            ControlRequest::GetStatus => ControlResponse::Status {
                pid: std::process::id(),
                socks_address: self.socks_address(&self.runtime.snapshot()),
                started_at_ms: self.started_at_ms,
                generated_at_ms: unix_timestamp_ms(),
                sessions: self.sessions.snapshot(),
                connections: self.connections.snapshot(),
            },
            ControlRequest::SubscribeSandbox { .. } => {
                unreachable!("subscription handled before request dispatch")
            }
            ControlRequest::Shutdown => {
                if self.shutdown.is_some() {
                    shutdown_requested = true;
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error {
                        message: "serve lifecycle management is unavailable".into(),
                    }
                }
            }
        };
        write_frame(&mut stream, &response).await?;
        if shutdown_requested {
            if let Some(shutdown) = &self.shutdown {
                let _ = shutdown.send(true);
            }
        }
        Ok(())
    }

    async fn subscribe_sandbox<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
        peer_pid: Option<u32>,
        session_id: String,
        token: String,
        mut current_version: u64,
    ) -> io::Result<()> {
        let Some((pid, _executable)) =
            peer_pid.and_then(|pid| self.sessions.member_executable(pid).map(|exe| (pid, exe)))
        else {
            return write_frame(
                &mut stream,
                &ControlResponse::Error {
                    message: "invalid sandbox subscriber".into(),
                },
            )
            .await;
        };
        if !self.sessions.authenticate_member(&session_id, &token, pid) {
            return write_frame(
                &mut stream,
                &ControlResponse::Error {
                    message: "invalid sandbox subscriber".into(),
                },
            )
            .await;
        }
        let mut updates = self.runtime.subscribe();
        let mut heartbeat = tokio::time::interval(Duration::from_secs(2));
        loop {
            let runtime = self.runtime.snapshot();
            let changed = runtime.updated_at_ms > current_version;
            let sandbox = if changed {
                match compile_sandbox_snapshot(&runtime.config, runtime.updated_at_ms) {
                    Ok(snapshot) => Some(snapshot),
                    Err(message) => {
                        write_frame(
                            &mut stream,
                            &ControlResponse::Error {
                                message: format!("cannot compile sandbox snapshot: {message}"),
                            },
                        )
                        .await?;
                        return Ok(());
                    }
                }
            } else {
                None
            };
            self.sessions
                .note_agent(&session_id, &token, pid, runtime.updated_at_ms);
            write_frame(
                &mut stream,
                &ControlResponse::SandboxUpdate {
                    version: runtime.updated_at_ms,
                    changed,
                    sandbox,
                },
            )
            .await?;
            current_version = runtime.updated_at_ms;
            tokio::select! {
                result = updates.changed() => { if result.is_err() { return Ok(()); } }
                _ = heartbeat.tick() => {}
            }
        }
    }

    fn bootstrap(
        &self,
        runtime: &RuntimeSnapshot,
        record: crate::session::SessionRecord,
        ttl: Duration,
    ) -> ControlResponse {
        match compile_sandbox_snapshot(&runtime.config, runtime.updated_at_ms) {
            Ok(sandbox) => ControlResponse::SessionBootstrap {
                socks_address: self.socks_address(runtime),
                session_id: record.session_id,
                token: record.token,
                expires_at_ms: unix_timestamp_after(ttl),
                lifecycle: record.lifecycle,
                agent_flags: AgentFlags {
                    observe: runtime.config.mode == crate::config::EnforcementMode::Observe,
                },
                tls_ca_pem: self.tls_ca_pem.as_ref().clone(),
                environment: runtime.environment.as_ref().clone(),
                sandbox: Some(sandbox),
            },
            Err(message) => ControlResponse::Error {
                message: format!("cannot compile session sandbox snapshot: {message}"),
            },
        }
    }
}

#[cfg(windows)]
fn open_validated_root_process(pid: u32, executable: &str) -> io::Result<usize> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut path = vec![0u16; 32_768];
    let mut length = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) } == 0 {
        unsafe { CloseHandle(handle) };
        return Err(io::Error::last_os_error());
    }
    path.truncate(length as usize);
    let actual = std::path::PathBuf::from(String::from_utf16_lossy(&path));
    if !same_executable(&actual, std::path::Path::new(executable)) {
        unsafe { CloseHandle(handle) };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root process executable does not match the authorized target",
        ));
    }
    Ok(handle as usize)
}

fn monitor_new_session_member(
    sessions: &SessionRegistry,
    session_id: &str,
    token: &str,
    pid: u32,
    executable: &str,
) -> io::Result<()> {
    let instance = sessions
        .member_instance(session_id, token, pid)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "session member disappeared"))?;
    let handle = match open_validated_root_process(pid, executable) {
        Ok(handle) => handle,
        Err(error) => {
            sessions.member_exited(session_id, pid, instance);
            return Err(error);
        }
    };
    if let Err(error) = monitor_session_member(
        handle,
        session_id.to_owned(),
        pid,
        instance,
        sessions.clone(),
    ) {
        sessions.member_exited(session_id, pid, instance);
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
fn monitor_session_member(
    handle: usize,
    session_id: String,
    pid: u32,
    instance: u64,
    sessions: SessionRegistry,
) -> io::Result<()> {
    let result = std::thread::Builder::new()
        .name(format!("hyperhub-session-{session_id}-{pid}"))
        .spawn(move || {
            let handle = handle as windows_sys::Win32::Foundation::HANDLE;
            unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(
                    handle,
                    windows_sys::Win32::System::Threading::INFINITE,
                );
                windows_sys::Win32::Foundation::CloseHandle(handle);
            }
            sessions.member_exited(&session_id, pid, instance);
        });
    if result.is_err() {
        close_process_handle(handle);
    }
    result.map(|_| ())
}

#[cfg(target_os = "linux")]
struct LinuxProcessHandle {
    pid: u32,
    start_time: u64,
}

#[cfg(target_os = "linux")]
fn open_validated_root_process(pid: u32, executable: &str) -> io::Result<usize> {
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid root pid",
        ));
    }
    validate_process_path(pid, executable)?;
    let handle = Box::new(LinuxProcessHandle {
        pid,
        start_time: linux_process_start_time(pid)?,
    });
    Ok(Box::into_raw(handle) as usize)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn open_validated_root_process(_pid: u32, _executable: &str) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "root process validation is unsupported on this platform",
    ))
}

#[cfg(windows)]
fn close_process_handle(handle: usize) {
    unsafe { windows_sys::Win32::Foundation::CloseHandle(handle as _) };
}

#[cfg(target_os = "linux")]
fn close_process_handle(handle: usize) {
    if handle != 0 {
        unsafe { drop(Box::from_raw(handle as *mut LinuxProcessHandle)) };
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn close_process_handle(_handle: usize) {}

#[cfg(windows)]
fn terminate_process_by_pid(pid: u32) {
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if !handle.is_null() {
        unsafe {
            let _ = TerminateProcess(handle, windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED);
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
    }
}

#[cfg(not(windows))]
fn terminate_process_by_pid(_pid: u32) {}

#[cfg(windows)]
fn windows_access_denied_error() -> u32 {
    windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED
}

#[cfg(not(windows))]
fn windows_access_denied_error() -> u32 {
    5
}

fn required_fork_hook_manifest() -> &'static [&'static str] {
    &[
        "getaddrinfo",
        "GetAddrInfoW",
        "connect",
        "WSAConnect",
        "send",
        "recv",
        "closesocket",
        "ioctlsocket",
        "WSASend",
        "WSARecv",
        "CertGetCertificateChain",
        "CertVerifyCertificateChainPolicy",
        "AcquireCredentialsHandleA",
        "AcquireCredentialsHandleW",
        "InitializeSecurityContextA",
        "InitializeSecurityContextW",
        "CreateProcessA",
        "CreateProcessW",
        "CreateProcessInternalA",
        "CreateProcessInternalW",
        "NtCreateUserProcess",
        "CertOpenSystemStoreA",
        "CertOpenSystemStoreW",
        "NtCreateFile",
        "NtOpenFile",
        "NtReadFile",
        "NtWriteFile",
        "NtSetInformationFile",
        "NtDeleteFile",
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtDuplicateObject",
        "NtClose",
        "fork",
        "vfork",
        "LdrLoadDll",
    ]
}

#[cfg(target_os = "linux")]
fn monitor_session_member(
    handle: usize,
    session_id: String,
    pid: u32,
    instance: u64,
    sessions: SessionRegistry,
) -> io::Result<()> {
    let handle = unsafe { Box::from_raw(handle as *mut LinuxProcessHandle) };
    std::thread::Builder::new()
        .name(format!("hyperhub-session-{session_id}-{pid}"))
        .spawn(move || {
            while linux_process_start_time(handle.pid).ok() == Some(handle.start_time) {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            sessions.member_exited(&session_id, pid, instance);
        })
        .map(|_| ())
}

#[cfg(not(any(windows, target_os = "linux")))]
fn monitor_session_member(
    _handle: usize,
    _session_id: String,
    _pid: u32,
    _instance: u64,
    _sessions: SessionRegistry,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "root process monitoring is unsupported on this platform",
    ))
}

#[cfg(windows)]
fn validate_child_process(parent_pid: u32, child_pid: u32, executable: &str) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut found = false;
    let mut next = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while next {
        if entry.th32ProcessID == child_pid {
            found = entry.th32ParentProcessID == parent_pid;
            break;
        }
        next = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    if !found {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "child process parent does not belong to the session",
        ));
    }
    validate_process_path(child_pid, executable)
}

#[cfg(target_os = "linux")]
fn validate_child_process(parent_pid: u32, child_pid: u32, executable: &str) -> io::Result<()> {
    let actual_parent = linux_process_parent(child_pid)?;
    if actual_parent != parent_pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "child process parent does not belong to the session",
        ));
    }
    validate_process_path(child_pid, executable)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn validate_child_process(_parent_pid: u32, _child_pid: u32, _executable: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "child process validation is unsupported on this platform",
    ))
}

#[cfg(windows)]
fn process_ancestors(client_pid: u32) -> Vec<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut parents = std::collections::HashMap::new();
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut next = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while next {
        parents.insert(entry.th32ProcessID, entry.th32ParentProcessID);
        next = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };

    let mut ancestors = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = client_pid;
    while ancestors.len() < 64 {
        let Some(&parent) = parents.get(&current) else {
            break;
        };
        if parent == 0 || parent == current || !seen.insert(parent) {
            break;
        }
        ancestors.push(parent);
        current = parent;
    }
    ancestors
}

#[cfg(target_os = "linux")]
fn process_ancestors(client_pid: u32) -> Vec<u32> {
    let mut ancestors = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = client_pid;
    while ancestors.len() < 64 {
        let Ok(parent) = linux_process_parent(current) else {
            break;
        };
        if parent == 0 || parent == current || !seen.insert(parent) {
            break;
        }
        ancestors.push(parent);
        current = parent;
    }
    ancestors
}

#[cfg(not(any(windows, target_os = "linux")))]
fn process_ancestors(_client_pid: u32) -> Vec<u32> {
    Vec::new()
}

#[cfg(windows)]
fn validate_process_path(pid: u32, executable: &str) -> io::Result<()> {
    let actual = process_path(pid)?;
    if same_executable(&actual, std::path::Path::new(executable)) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "child executable path does not match",
        ))
    }
}

#[cfg(target_os = "linux")]
fn validate_process_path(pid: u32, executable: &str) -> io::Result<()> {
    if same_executable(&process_path(pid)?, std::path::Path::new(executable)) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process executable path does not match",
        ))
    }
}

#[cfg(windows)]
fn process_path(pid: u32) -> io::Result<std::path::PathBuf> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut path = vec![0u16; 32_768];
    let mut length = path.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    path.truncate(length as usize);
    Ok(std::path::PathBuf::from(String::from_utf16_lossy(&path)))
}

#[cfg(target_os = "linux")]
fn process_path(pid: u32) -> io::Result<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn process_path(_pid: u32) -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process inspection is unsupported on this platform",
    ))
}

#[cfg(windows)]
fn same_executable(left: &std::path::Path, right: &std::path::Path) -> bool {
    let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_owned());
    let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_owned());
    left.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .eq_ignore_ascii_case(right.to_string_lossy().trim_start_matches(r"\\?\"))
}

#[cfg(target_os = "linux")]
fn same_executable(left: &std::path::Path, right: &std::path::Path) -> bool {
    let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_owned());
    let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_owned());
    left == right
}

#[cfg(target_os = "linux")]
fn linux_process_stat(pid: u32) -> io::Result<String> {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
}

#[cfg(target_os = "linux")]
fn linux_process_stat_fields(pid: u32) -> io::Result<Vec<String>> {
    let stat = linux_process_stat(pid)?;
    let tail = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid proc stat"))?
        .1;
    Ok(tail.split_whitespace().map(str::to_owned).collect())
}

#[cfg(target_os = "linux")]
fn linux_process_parent(pid: u32) -> io::Result<u32> {
    linux_process_stat_fields(pid)?
        .get(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid parent pid"))
}

#[cfg(target_os = "linux")]
fn linux_process_start_time(pid: u32) -> io::Result<u64> {
    let fields = linux_process_stat_fields(pid)?;
    if fields.first().is_some_and(|state| state == "Z") {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "process is a zombie",
        ));
    }
    fields
        .get(19)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process start time"))
}

#[cfg(windows)]
fn same_requested_executable(left: &str, right: &str) -> bool {
    same_executable(std::path::Path::new(left), std::path::Path::new(right))
}

#[cfg(not(windows))]
fn same_requested_executable(left: &str, right: &str) -> bool {
    left == right
}

#[cfg(windows)]
pub async fn run_control_server(endpoint: String, service: ControlService) -> io::Result<()> {
    let mut first = true;
    loop {
        let server = create_current_user_pipe(&endpoint, first)?;
        first = false;
        server.connect().await?;
        let peer_pid = named_pipe_client_pid(&server).ok();
        let service = service.clone();
        tokio::spawn(async move {
            let _ = service.handle(server, peer_pid).await;
        });
    }
}

#[cfg(windows)]
fn named_pipe_client_pid(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> io::Result<u32> {
    use std::os::windows::io::AsRawHandle;
    let mut pid = 0;
    let ok = unsafe {
        windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId(
            server.as_raw_handle() as _,
            &mut pid,
        )
    };
    if ok == 0 || pid == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(pid)
    }
}

#[cfg(windows)]
fn create_current_user_pipe(
    endpoint: &str,
    first: bool,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let sid = crate::config_store::current_user_sid_string()?;
    let sddl = format!("D:P(A;;GA;;;{sid})");
    let sddl: Vec<u16> = OsStr::new(&sddl).encode_wide().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    let result = unsafe {
        options.create_with_security_attributes_raw(
            endpoint,
            std::ptr::addr_of_mut!(attributes).cast(),
        )
    };
    unsafe { LocalFree(descriptor.cast()) };
    result
}

#[cfg(unix)]
pub async fn run_control_server(endpoint: String, service: ControlService) -> io::Result<()> {
    use tokio::net::UnixListener;
    let path = std::path::Path::new(&endpoint);
    if let Some(parent) = path.parent() {
        #[cfg(target_os = "linux")]
        ensure_linux_control_directory(parent)?;
        #[cfg(not(target_os = "linux"))]
        {
            std::fs::create_dir_all(parent)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let peer_pid = stream
            .peer_cred()
            .ok()
            .and_then(|credentials| credentials.pid())
            .map(|pid| pid as u32);
        let service = service.clone();
        tokio::spawn(async move {
            let _ = service.handle(stream, peer_pid).await;
        });
    }
}

#[cfg(target_os = "linux")]
fn ensure_linux_control_directory(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let uid = linux_effective_uid()?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("unsafe HyperHub control directory {}", path.display()),
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir(path)?;
        }
        Err(error) => return Err(error),
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unsafe HyperHub control directory {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(windows)]
async fn open_control(
    endpoint: &str,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    for _ in 0..50 {
        match ClientOptions::new().open(endpoint) {
            Ok(client) => return Ok(client),
            Err(error)
                if error.raw_os_error() == Some(231) || error.kind() == io::ErrorKind::NotFound =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "timed out opening HyperHub control pipe",
    ))
}

#[cfg(unix)]
async fn open_control(endpoint: &str) -> io::Result<tokio::net::UnixStream> {
    for _ in 0..50 {
        match tokio::net::UnixStream::connect(endpoint).await {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "timed out opening HyperHub control socket",
    ))
}

pub async fn control_request(
    endpoint: &str,
    request: &ControlRequest,
) -> io::Result<ControlResponse> {
    let mut stream = open_control(endpoint).await?;
    write_frame(&mut stream, request).await?;
    read_frame(&mut stream).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smart_pass_audits_are_debug_only() {
        assert!(!should_record_smart_audit(
            false,
            crate::config::SandboxAction::Pass
        ));
        assert!(should_record_smart_audit(
            true,
            crate::config::SandboxAction::Pass
        ));
        assert!(should_record_smart_audit(
            false,
            crate::config::SandboxAction::Deny
        ));
    }

    #[test]
    fn only_smart_pass_sandbox_audits_are_filtered() {
        assert!(!should_record_sandbox_audit(false, "smart_protection_pass"));
        assert!(should_record_sandbox_audit(true, "smart_protection_pass"));
        assert!(should_record_sandbox_audit(false, "smart_protection"));
        assert!(should_record_sandbox_audit(false, "rule"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_control_endpoint_is_scoped_to_hyperhub_home() {
        assert_eq!(
            control_endpoint_for_home(std::path::Path::new("/isolated/hyperhub")),
            std::path::PathBuf::from("/isolated/hyperhub/runtime/control.sock")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_control_endpoint_is_scoped_to_user_and_hyperhub_home() {
        let first = windows_control_endpoint("S-1-test", r"C:\one");
        let second = windows_control_endpoint("S-1-test", r"C:\two");
        assert!(first.starts_with(r"\\.\pipe\hyperhub-"));
        assert_ne!(first, second);
        assert_eq!(first, windows_control_endpoint("S-1-test", r"C:\one"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_control_directory_rejects_symlinks_and_repairs_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = std::env::temp_dir().join(format!(
            "hyperhub-control-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let directory = root.join("private");
        let link = root.join("link");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_linux_control_directory(&directory).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        symlink(&directory, &link).unwrap();
        assert_eq!(
            ensure_linux_control_directory(&link).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(link).unwrap();
        std::fs::remove_dir(directory).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_root_process_identity_is_validated() {
        let pid = std::process::id();
        let executable = std::env::current_exe().unwrap();
        let handle = open_validated_root_process(pid, &executable.to_string_lossy()).unwrap();
        assert!(linux_process_start_time(pid).unwrap() > 0);
        assert_eq!(process_path(pid).unwrap(), executable);
        close_process_handle(handle);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn named_pipe_parent_session_uses_automatic_authentication() {
        let parent_pid = process_ancestors(std::process::id())
            .into_iter()
            .next()
            .expect("test process must have a parent");
        let parent_executable = process_path(parent_pid).unwrap().display().to_string();
        let sessions = SessionRegistry::default();
        let challenge = sessions
            .begin_auth("parent".into(), parent_executable, [9; 32])
            .unwrap();
        let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
        let parent = sessions
            .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(10))
            .unwrap();
        assert!(sessions.activate("parent", &parent.token, parent_pid));

        let mut config = Config::default();
        config.firewall.enabled = true;
        config.firewall.default = Some(crate::config::FirewallDefaultRule {
            action: crate::config::FirewallAction::Pass,
        });
        config.firewall.rules.push(crate::config::FirewallRule {
            uuid: crate::config::new_config_uuid(),
            id: "child-deny".into(),
            enabled: true,
            priority: 10,
            action: crate::config::FirewallAction::Deny,
            endpoints: vec![crate::config::FirewallEndpoint {
                target: "child.example".into(),
                port: None,
            }],
            legacy: Default::default(),
            protection: None,
        });
        let endpoint = format!(r"\\.\pipe\hyperhub-auto-auth-test-{}", std::process::id());
        let service = ControlService::new(
            sessions,
            ConnectionRegistry::default(),
            String::new(),
            crate::audit::AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(config)).unwrap(),
            Zeroizing::new(vec![0; 32]),
        );
        let task = tokio::spawn(run_control_server(endpoint.clone(), service));
        let inherited_agent = control_request(&endpoint, &ControlRequest::BootstrapChild)
            .await
            .unwrap();
        assert!(matches!(
            inherited_agent,
            ControlResponse::AgentBootstrap {
                session_id,
                firewall: Some(firewall),
                ..
            } if session_id == "parent"
                && firewall.rules[0].id == "child-deny"
        ));
        let response = control_request(
            &endpoint,
            &ControlRequest::BeginSessionAuth {
                session_id: "inherited".into(),
                executable: std::env::current_exe().unwrap().display().to_string(),
                client_nonce: [1; 32],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            response,
            ControlResponse::SessionBootstrap {
                lifecycle: crate::session::SessionLifecycle::Pending,
                ..
            }
        ));
        task.abort();
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_bootstrap_child_monitor_helper() {
        let Some(endpoint) = std::env::var_os("HYPERHUB_TEST_BOOTSTRAP_ENDPOINT") else {
            return;
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = runtime
            .block_on(control_request(
                &endpoint.to_string_lossy(),
                &ControlRequest::BootstrapChild,
            ))
            .unwrap();
        assert!(matches!(response, ControlResponse::AgentBootstrap { .. }));
        std::thread::sleep(Duration::from_millis(500));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bootstrap_child_exit_revokes_session_without_register_child() {
        let sessions = SessionRegistry::default();
        let root_pid = std::process::id();
        let root_executable = std::env::current_exe().unwrap().display().to_string();
        let challenge = sessions
            .begin_auth("bootstrap-monitor".into(), root_executable, [11; 32])
            .unwrap();
        let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
        let record = sessions
            .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(10))
            .unwrap();
        assert!(sessions.activate("bootstrap-monitor", &record.token, root_pid));
        let root_instance = sessions
            .member_instance("bootstrap-monitor", &record.token, root_pid)
            .unwrap();

        let endpoint = format!(
            r"\\.\pipe\hyperhub-bootstrap-monitor-test-{}",
            std::process::id()
        );
        let service = ControlService::new(
            sessions.clone(),
            ConnectionRegistry::default(),
            String::new(),
            crate::audit::AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        );
        let task = tokio::spawn(run_control_server(endpoint.clone(), service));
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("named_pipe_bootstrap_child_monitor_helper")
            .arg("--nocapture")
            .env("HYPERHUB_TEST_BOOTSTRAP_ENDPOINT", &endpoint)
            .spawn()
            .unwrap();
        let child_pid = child.id();

        for _ in 0..100 {
            if sessions
                .member_instance("bootstrap-monitor", &record.token, child_pid)
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(sessions
            .member_instance("bootstrap-monitor", &record.token, child_pid)
            .is_some());
        assert!(sessions.member_exited("bootstrap-monitor", root_pid, root_instance));
        assert!(sessions.authenticate_control("bootstrap-monitor", &record.token));

        assert!(tokio::task::spawn_blocking(move || child.wait().unwrap())
            .await
            .unwrap()
            .success());
        for _ in 0..100 {
            if !sessions.authenticate_control("bootstrap-monitor", &record.token) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!sessions.authenticate_control("bootstrap-monitor", &record.token));
        task.abort();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn trust_bootstrap_rejects_a_peer_from_another_session() {
        let sessions = SessionRegistry::default();
        let executable = std::env::current_exe().unwrap().display().to_string();

        let first_challenge = sessions
            .begin_auth("first".into(), executable.clone(), [7; 32])
            .unwrap();
        let first_proof = crate::session::session_proof(&[0; 32], &first_challenge).unwrap();
        let first = sessions
            .finish_auth(
                &first_challenge.challenge_id,
                &first_proof,
                Duration::from_secs(10),
            )
            .unwrap();
        assert!(sessions.activate("first", &first.token, std::process::id()));

        let second_challenge = sessions
            .begin_auth("second".into(), executable, [8; 32])
            .unwrap();
        let second_proof = crate::session::session_proof(&[0; 32], &second_challenge).unwrap();
        let second = sessions
            .finish_auth(
                &second_challenge.challenge_id,
                &second_proof,
                Duration::from_secs(10),
            )
            .unwrap();
        assert!(sessions.activate(
            "second",
            &second.token,
            std::process::id().saturating_add(100_000)
        ));

        let mut config = Config::default();
        config.environment.push(crate::config::EnvironmentVariable {
            uuid: crate::config::new_config_uuid(),
            name: "SESSION_SECRET".into(),
            value: crate::config::SecretValue::Inline {
                value: "must-not-cross-sessions".into(),
            },
        });
        let endpoint = format!(
            r"\\.\pipe\hyperhub-cross-session-test-{}",
            std::process::id()
        );
        let service = ControlService::new(
            sessions,
            ConnectionRegistry::default(),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".into(),
            crate::audit::AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(config)).unwrap(),
            Zeroizing::new(vec![0; 32]),
        );
        let task = tokio::spawn(run_control_server(endpoint.clone(), service));
        let response = control_request(
            &endpoint,
            &ControlRequest::GetTrust {
                session_id: "second".into(),
                token: second.token,
            },
        )
        .await
        .unwrap();
        assert!(matches!(response, ControlResponse::Error { .. }));
        task.abort();
    }

    #[tokio::test]
    async fn registration_round_trip() {
        let mut config = Config::default();
        config.environment.push(crate::config::EnvironmentVariable {
            uuid: crate::config::new_config_uuid(),
            name: "GH_TOKEN".into(),
            value: crate::config::SecretValue::Inline {
                value: "session-secret".into(),
            },
        });
        config.firewall.enabled = true;
        config.firewall.default = Some(crate::config::FirewallDefaultRule {
            action: crate::config::FirewallAction::Pass,
        });
        config.firewall.rules.push(crate::config::FirewallRule {
            uuid: crate::config::new_config_uuid(),
            id: "block-example".into(),
            enabled: true,
            priority: 10,
            action: crate::config::FirewallAction::Deny,
            endpoints: vec![crate::config::FirewallEndpoint {
                target: "example.com".into(),
                port: Some(443),
            }],
            legacy: Default::default(),
            protection: None,
        });
        #[cfg(windows)]
        let endpoint = format!(r"\\.\pipe\hyperhub-test-{}", std::process::id());
        #[cfg(unix)]
        let endpoint_root = {
            let root = std::env::temp_dir().join(format!(
                "hyperhub-control-test-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&root).unwrap();
            root
        };
        #[cfg(unix)]
        let endpoint = endpoint_root.join("control.sock").display().to_string();
        let runtime = RuntimeState::new(Arc::new(config)).unwrap();
        let service = ControlService::new(
            SessionRegistry::default(),
            ConnectionRegistry::default(),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".into(),
            crate::audit::AuditWriter::open(None).unwrap(),
            runtime.clone(),
            Zeroizing::new(vec![0; 32]),
        );
        let task = tokio::spawn(run_control_server(endpoint.clone(), service));
        let response = control_request(
            &endpoint,
            &ControlRequest::BeginSessionAuth {
                session_id: "test".into(),
                executable: std::env::current_exe().unwrap().display().to_string(),
                client_nonce: [1; 32],
            },
        )
        .await
        .unwrap();
        let challenge = match response {
            ControlResponse::SessionChallenge { challenge } => challenge,
            _ => panic!("unexpected challenge response"),
        };
        let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
        let response = control_request(
            &endpoint,
            &ControlRequest::FinishSessionAuth {
                challenge_id: challenge.challenge_id,
                proof,
            },
        )
        .await
        .unwrap();
        let token = match response {
            ControlResponse::SessionBootstrap {
                token, environment, ..
            } => {
                assert_eq!(environment.len(), 1);
                assert_eq!(environment[0].name, "GH_TOKEN");
                assert_eq!(environment[0].value, "session-secret");
                token
            }
            _ => panic!("unexpected bootstrap response"),
        };
        let cached = control_request(
            &endpoint,
            &ControlRequest::BeginSessionAuth {
                session_id: "cached".into(),
                executable: "curl".into(),
                client_nonce: [2; 32],
            },
        )
        .await
        .unwrap();
        assert!(matches!(cached, ControlResponse::SessionBootstrap { .. }));
        assert!(matches!(
            control_request(
                &endpoint,
                &ControlRequest::RevokeSession {
                    session_id: "cached".into(),
                },
            )
            .await
            .unwrap(),
            ControlResponse::Ok
        ));
        assert!(matches!(
            control_request(&endpoint, &ControlRequest::ClearPasswordAuthorization)
                .await
                .unwrap(),
            ControlResponse::Ok
        ));
        let after_clear = control_request(
            &endpoint,
            &ControlRequest::BeginSessionAuth {
                session_id: "after-clear".into(),
                executable: "ssh".into(),
                client_nonce: [3; 32],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            after_clear,
            ControlResponse::SessionChallenge { .. }
        ));
        let response = control_request(
            &endpoint,
            &ControlRequest::ActivateSession {
                session_id: "test".into(),
                token: token.clone(),
                root_pid: std::process::id(),
                executable: std::env::current_exe().unwrap().display().to_string(),
                root_executable: Some(std::env::current_exe().unwrap().display().to_string()),
                process_policy_version: 0,
                process_rule_id: None,
                process_decision_source: "unknown".into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(response, ControlResponse::Ok));
        let response = control_request(
            &endpoint,
            &ControlRequest::RefreshSandbox {
                session_id: "test".into(),
                token: token.clone(),
                root_pid: std::process::id(),
                current_version: 0,
            },
        )
        .await
        .unwrap();
        let sandbox_version = match response {
            ControlResponse::SandboxRefresh {
                version,
                changed: true,
                enforce: true,
                sandbox: Some(sandbox),
            } => {
                assert_eq!(sandbox.version, version);
                version
            }
            _ => panic!("unexpected sandbox refresh response"),
        };
        let response = control_request(
            &endpoint,
            &ControlRequest::RefreshSandbox {
                session_id: "test".into(),
                token: token.clone(),
                root_pid: std::process::id(),
                current_version: sandbox_version,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            response,
            ControlResponse::SandboxRefresh {
                version,
                changed: false,
                enforce: true,
                sandbox: None,
            } if version == sandbox_version
        ));
        let mut observe = (*runtime.snapshot().config).clone();
        observe.mode = crate::config::EnforcementMode::Observe;
        runtime.apply(Arc::new(observe)).unwrap();
        let response = control_request(
            &endpoint,
            &ControlRequest::RefreshSandbox {
                session_id: "test".into(),
                token: token.clone(),
                root_pid: std::process::id(),
                current_version: sandbox_version,
            },
        )
        .await
        .unwrap();
        let sandbox_version = match response {
            ControlResponse::SandboxRefresh {
                version,
                changed: true,
                enforce: false,
                sandbox: Some(sandbox),
            } => {
                assert_eq!(sandbox.version, version);
                version
            }
            _ => panic!("sandbox refresh did not propagate observe mode"),
        };
        let response = control_request(
            &endpoint,
            &ControlRequest::RefreshSandbox {
                session_id: "test".into(),
                token: token.clone(),
                root_pid: u32::MAX,
                current_version: sandbox_version,
            },
        )
        .await
        .unwrap();
        assert!(matches!(response, ControlResponse::Error { .. }));

        let response = control_request(
            &endpoint,
            &ControlRequest::ResolveName {
                session_id: "test".into(),
                token: token.clone(),
                hostname: "api.example.test".into(),
                family: 4,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            response,
            ControlResponse::ResolvedName {
                ref address,
                ..
            } if address == "198.18.0.1"
        ));
        let response = control_request(
            &endpoint,
            &ControlRequest::GetTrust {
                session_id: "test".into(),
                token: token.clone(),
            },
        )
        .await
        .unwrap();
        #[cfg(windows)]
        assert!(matches!(
            response,
            ControlResponse::TrustBootstrap {
                ref socks_address,
                ref environment,
                firewall: Some(firewall),
                ..
            } if socks_address == "127.0.0.1:18444"
                && environment[0].name == "GH_TOKEN"
                && environment[0].value == "session-secret"
                && firewall.default_action == Some(crate::config::FirewallAction::Pass)
                && firewall.rules[0].id == "block-example"
        ));
        #[cfg(not(windows))]
        assert!(matches!(
            response,
            ControlResponse::TrustBootstrap {
                ref socks_address,
                ref environment,
                firewall: Some(firewall),
                ..
            } if socks_address == "127.0.0.1:18444"
                && environment[0].name == "GH_TOKEN"
                && environment[0].value == "session-secret"
                && firewall.default_action == Some(crate::config::FirewallAction::Pass)
                    && firewall.rules[0].id == "block-example"
        ));

        #[cfg(windows)]
        {
            let response = control_request(
                &endpoint,
                &ControlRequest::RefreshFirewall {
                    session_id: "test".into(),
                    token: token.clone(),
                    current_version: 0,
                },
            )
            .await
            .unwrap();
            let version = match response {
                ControlResponse::FirewallRefresh {
                    version,
                    changed: true,
                    firewall: Some(firewall),
                } => {
                    assert_eq!(firewall.rules[0].id, "block-example");
                    version
                }
                _ => panic!("unexpected firewall refresh response"),
            };
            let response = control_request(
                &endpoint,
                &ControlRequest::RefreshFirewall {
                    session_id: "test".into(),
                    token: token.clone(),
                    current_version: version,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                response,
                ControlResponse::FirewallRefresh {
                    version: current,
                    changed: false,
                    firewall: None,
                } if current == version
            ));

            let mut updated = Config::default();
            updated.firewall.enabled = true;
            updated.firewall.default = Some(crate::config::FirewallDefaultRule {
                action: crate::config::FirewallAction::Deny,
            });
            updated.firewall.rules.push(crate::config::FirewallRule {
                uuid: crate::config::new_config_uuid(),
                id: "allow-updated".into(),
                enabled: true,
                priority: 20,
                action: crate::config::FirewallAction::Pass,
                endpoints: vec![crate::config::FirewallEndpoint {
                    target: "updated.example".into(),
                    port: Some(443),
                }],
                legacy: Default::default(),
                protection: None,
            });
            let config_json =
                serde_json::to_string(&ConfigDocument::from_config(&updated)).unwrap();
            let proof = crate::session::config_update_proof(&[0; 32], &config_json).unwrap();
            let response = control_request(
                &endpoint,
                &ControlRequest::UpdateConfig { proof, config_json },
            )
            .await
            .unwrap();
            assert!(matches!(response, ControlResponse::Ok));

            let response = control_request(
                &endpoint,
                &ControlRequest::RefreshFirewall {
                    session_id: "test".into(),
                    token: token.clone(),
                    current_version: version,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                response,
                ControlResponse::FirewallRefresh {
                    version: updated_version,
                    changed: true,
                    firewall: Some(firewall),
                } if updated_version > version
                    && firewall.default_action == Some(crate::config::FirewallAction::Deny)
                    && firewall.rules[0].id == "allow-updated"
            ));
        }

        #[cfg(windows)]
        {
            let response = control_request(
                &endpoint,
                &ControlRequest::ReportFirewallAudit {
                    session_id: "test".into(),
                    token,
                    event: crate::firewall::FirewallAuditEvent {
                        decision: crate::config::FirewallAction::Deny,
                        rule_id: Some("block-example".into()),
                        source: crate::firewall::FirewallDecisionSource::Rule,
                        stage: crate::firewall::FirewallAuditStage::Connect,
                        hostname: Some("example.com".into()),
                        ip: Some("198.18.0.1".parse().unwrap()),
                        port: Some(443),
                        process_pid: std::process::id(),
                        process_tid: 1,
                        snapshot_version: 1,
                    },
                },
            )
            .await
            .unwrap();
            assert!(matches!(response, ControlResponse::Ok));
        }

        let response = control_request(&endpoint, &ControlRequest::GetStatus)
            .await
            .unwrap();
        #[cfg(any(windows, target_os = "linux"))]
        assert!(matches!(
            response,
            ControlResponse::Status {
                ref sessions,
                ref connections,
                ..
            } if sessions.len() == 1
                && sessions[0].processes.len() == 1
                && sessions[0].processes[0].pid == std::process::id()
                && connections.is_empty()
        ));
        #[cfg(not(any(windows, target_os = "linux")))]
        assert!(matches!(
            response,
            ControlResponse::Status {
                ref sessions,
                ref connections,
                ..
            } if sessions.len() == 1 && sessions[0].processes.is_empty() && connections.is_empty()
        ));
        task.abort();
        let _ = task.await;
        #[cfg(unix)]
        {
            std::fs::remove_dir_all(endpoint_root).unwrap();
        }
    }

    #[tokio::test]
    async fn config_update_is_applied_only_with_valid_proof() {
        let mut config = Config::default();
        let managed_log = "state/audit/hyperhub.jsonl";
        let managed_transcripts = "state/audit/transcripts";
        config.audit.log = Some(managed_log.into());
        config.audit.transcript_dir = Some(managed_transcripts.into());
        let runtime = RuntimeState::new(Arc::new(config.clone())).unwrap();
        let audit = crate::audit::AuditWriter::open(None).unwrap();
        let service = ControlService::new(
            SessionRegistry::default(),
            ConnectionRegistry::default(),
            String::new(),
            audit.clone(),
            runtime.clone(),
            Zeroizing::new(vec![0; 32]),
        );

        let mut next = config.clone();
        next.default_route.action = crate::config::RuleAction::Deny;
        next.debug = true;
        let config_json = serde_json::to_string(&ConfigDocument::from_config(&next)).unwrap();
        let proof = crate::session::config_update_proof(&[0; 32], &config_json).unwrap();

        async fn send_update(
            service: ControlService,
            config_json: String,
            proof: Vec<u8>,
        ) -> ControlResponse {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let task = tokio::spawn(async move {
                let _ = service.handle(server, None).await;
            });
            let mut client = client;
            write_frame(
                &mut client,
                &ControlRequest::UpdateConfig { proof, config_json },
            )
            .await
            .unwrap();
            let response: ControlResponse = read_frame(&mut client).await.unwrap();
            task.abort();
            let _ = task.await;
            response
        }

        let response = send_update(service.clone(), config_json.clone(), proof).await;
        assert!(matches!(response, ControlResponse::Ok));
        assert!(
            runtime.snapshot().config.default_route.action == crate::config::RuleAction::Deny,
            "hot update must replace the runtime snapshot"
        );
        assert!(audit.debug_enabled(), "hot update must toggle debug output");
        let snapshot = runtime.snapshot().config;
        assert_eq!(snapshot.audit.log, Some(managed_log.into()));
        assert_eq!(
            snapshot.audit.transcript_dir,
            Some(managed_transcripts.into())
        );

        next.debug = false;
        let debug_disabled_json =
            serde_json::to_string(&ConfigDocument::from_config(&next)).unwrap();
        let proof = crate::session::config_update_proof(&[0; 32], &debug_disabled_json).unwrap();
        let response = send_update(service.clone(), debug_disabled_json.clone(), proof).await;
        assert!(matches!(response, ControlResponse::Ok));
        assert!(
            !audit.debug_enabled(),
            "config updates must disable debug without a command-line override"
        );

        audit.set_debug(true).unwrap();
        let forced_service = service.clone().with_forced_debug(true);
        let proof = crate::session::config_update_proof(&[0; 32], &debug_disabled_json).unwrap();
        let response = send_update(forced_service, debug_disabled_json, proof).await;
        assert!(matches!(response, ControlResponse::Ok));
        assert!(
            audit.debug_enabled(),
            "config updates must preserve a command-line debug override"
        );

        // 篡改证明：拒绝应用，旧快照保留。
        let response = send_update(service, config_json, vec![0; 32]).await;
        assert!(matches!(
            response,
            ControlResponse::Error { ref message } if message.contains("proof")
        ));
        assert!(
            runtime.snapshot().config.default_route.action == crate::config::RuleAction::Deny,
            "rejected update must keep the previous snapshot"
        );
        let snapshot = runtime.snapshot().config;
        assert_eq!(snapshot.audit.log, Some(managed_log.into()));
        assert_eq!(
            snapshot.audit.transcript_dir,
            Some(managed_transcripts.into())
        );
    }

    #[tokio::test]
    async fn config_update_uses_a_fallback_when_new_socks_listener_is_occupied() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let initial_address = probe.local_addr().unwrap();
        drop(probe);

        let mut config = Config::default();
        config.listener.socks_listen = initial_address.to_string();
        let sessions = SessionRegistry::default();
        let socks =
            crate::socks::SocksService::new(Arc::new(config.clone()), sessions.clone()).unwrap();
        let runtime = socks.runtime();
        let audit = socks.audit_writer();
        let listener_controller = socks.listener_controller();
        let listener_state = listener_controller.clone();
        let socks_task = tokio::spawn(socks.run());
        listener_controller
            .ensure_listener(&initial_address.to_string())
            .await
            .unwrap();

        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_address = occupied.local_addr().unwrap();
        let service = ControlService::new(
            sessions,
            ConnectionRegistry::default(),
            String::new(),
            audit,
            runtime.clone(),
            Zeroizing::new(vec![0; 32]),
        )
        .with_socks_listener(listener_controller);

        let mut next = config;
        next.listener.socks_listen = occupied_address.to_string();
        let config_json = serde_json::to_string(&ConfigDocument::from_config(&next)).unwrap();
        let proof = crate::session::config_update_proof(&[0; 32], &config_json).unwrap();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let control_task = tokio::spawn(async move {
            let _ = service.handle(server, None).await;
        });
        let mut client = client;
        write_frame(
            &mut client,
            &ControlRequest::UpdateConfig { proof, config_json },
        )
        .await
        .unwrap();
        let response: ControlResponse = read_frame(&mut client).await.unwrap();

        assert!(matches!(response, ControlResponse::Ok));
        assert_eq!(
            runtime.snapshot().config.listener.socks_listen,
            occupied_address.to_string(),
            "the requested listener remains the active configuration"
        );
        let actual_address = listener_state.address().unwrap();
        assert_ne!(actual_address, occupied_address);
        assert_eq!(actual_address.ip(), occupied_address.ip());

        control_task.abort();
        let _ = control_task.await;
        socks_task.abort();
        let _ = socks_task.await;
    }
}
