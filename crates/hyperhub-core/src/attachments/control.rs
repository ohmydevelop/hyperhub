use super::*;
use crate::attachments::{self, Action, Authorization, Backend, ProcessIdentity, Scope};

#[cfg(all(test, any(windows, target_os = "linux")))]
#[path = "consumption_tests.rs"]
mod consumption_tests;

#[cfg(all(test, any(windows, target_os = "linux")))]
#[path = "origin_tests.rs"]
mod origin_tests;

impl ControlService {
    pub(super) fn approval_control(&self, begin: bool, peer_pid: Option<u32>) -> ControlResponse {
        let result = (|| {
            let directory = self
                .attachment_directory
                .as_ref()
                .ok_or("runtime attachments are not enabled")?;
            if begin {
                let peer = self.approval_cli_peer(peer_pid)?;
                let config = self
                    .approval_config_path
                    .as_ref()
                    .ok_or("approval configuration path is not bound to this Core instance")?;
                Ok(ControlResponse::ApprovalEnrollmentChallenge {
                    challenge: attachments::challenge(directory, &config, peer)?,
                })
            } else {
                Ok(ControlResponse::ApprovalTrust {
                    trust: attachments::approval_trust(directory)?,
                })
            }
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    fn approval_cli_peer(&self, peer_pid: Option<u32>) -> Result<ProcessIdentity, String> {
        let peer = attachments::inspect_process(peer_pid.ok_or("approval requires an OS peer")?)?;
        let own = attachments::inspect_process(std::process::id())?;
        if peer.owner != own.owner || peer.executable_sha256 != own.executable_sha256 {
            return Err("approval requires the trusted administrator CLI executable".into());
        }
        Ok(peer)
    }
    pub(super) fn approval_password(
        &self,
        nonce: String,
        password: Zeroizing<Vec<u8>>,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            let peer = self.approval_cli_peer(peer_pid)?;
            let directory = self
                .attachment_directory
                .as_ref()
                .ok_or("runtime attachments disabled")?;
            let config = self
                .approval_config_path
                .as_ref()
                .ok_or("approval configuration path is not bound to this Core instance")?;
            attachments::enroll_password(directory, &config, &nonce, &password, &peer)?;
            Ok(ControlResponse::Ok)
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    pub(super) fn approval_host_certificate(
        &self,
        bootstrap: hyperhub_runtime::attachment::Bootstrap,
        challenge: hyperhub_runtime::attachment::ApprovalEnrollmentChallenge,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            self.approval_cli_peer(peer_pid)?;
            let directory = self
                .attachment_directory
                .as_ref()
                .ok_or("runtime attachments disabled")?;
            let record = attachments::load_record(&attachments::attachment_directory(
                directory,
                &bootstrap.attachment_id,
            )?)?;
            if record.session_id != bootstrap.session_id
                || record.spec.target.pid != bootstrap.root_pid
                || !self.sessions.authenticate_member(
                    &bootstrap.session_id,
                    &bootstrap.token,
                    challenge.host_pid,
                )
                || attachments::process_birth(challenge.host_pid) != Some(challenge.host_birth)
            {
                return Err(
                    "Host enrollment does not match an authenticated live attachment member"
                        .to_string(),
                );
            }
            Ok(ControlResponse::ApprovalRootCertificate {
                certificate: attachments::core_host_enrollment(directory, &bootstrap, &challenge)?,
            })
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    fn consumption_context(
        &self,
        authorization: &Authorization,
        manager: &ProcessIdentity,
        bootstrap: &hyperhub_runtime::attachment::Bootstrap,
        peer_pid: Option<u32>,
    ) -> Result<
        (
            PathBuf,
            PathBuf,
            attachments::Record,
            hyperhub_runtime::attachment::OperationScope,
            bool,
        ),
        String,
    > {
        let directory = self
            .attachment_directory
            .as_ref()
            .ok_or("runtime attachments are not enabled")?;
        if peer_pid != Some(manager.pid) {
            return Err("approval claimant does not match OS peer".to_string());
        }
        attachments::verify_process(manager)?;
        if manager.executable_sha256 != authorization.executor_sha256 {
            return Err("approval claimant executable differs from signed executor".into());
        }
        if authorization.core_attestation_public_key
            != Some(attachments::approval_trust(directory)?.core_public_key)
        {
            return Err("approval does not endorse this controlled Core attestation key".into());
        }
        attachments::verify_authorization(directory, authorization)?;
        let claimant = authorization
            .manager_claimant
            .as_ref()
            .ok_or("approval has no delegated manager claimant")?;
        if claimant.pid != manager.pid || claimant.birth != manager.birth {
            return Err("approval claimant differs from actual manager incarnation".into());
        }
        let record_directory = attachments::attachment_directory(
            directory,
            authorization.request.action.attachment_id(),
        )?;
        let record = attachments::load_record(&record_directory)?;
        attachments::ManagerExecutionProfile::from_bootstrap(bootstrap, record.origin)?
            .validate_record(&record)?;
        bootstrap.validate().map_err(|e| e.to_string())?;
        if record.session_id != bootstrap.session_id
            || bootstrap.root_pid != record.spec.target.pid
            || record.host_binding.is_none()
            || record.host_binding.as_deref() != authorization.host_binding.as_deref()
            || authorization.host_binding.as_deref()
                != Some(
                    bootstrap
                        .approval_binding()
                        .map_err(|e| e.to_string())?
                        .as_str(),
                )
        {
            return Err(
                "consumption bootstrap differs from original session and immutable Host binding"
                    .into(),
            );
        }
        let target = authorization.request.action.target();
        if !record.spec.target.same_incarnation(target) {
            return Err("approval target is a different process incarnation".into());
        }
        let live = attachments::process_birth(target.pid) == Some(target.birth);
        if live || matches!(authorization.request.action, Action::Attach { .. }) {
            attachments::verify_process(target)?;
        }
        match attachments::root_image_state(directory, &record.spec.id) {
            Ok(state) => state,
            Err(_) if matches!(&authorization.request.action,Action::Attach{spec} if record.phase==attachments::Phase::Preparing && spec.exec_epoch==0 && spec.current_target.is_none()) =>
            {
                let Action::Attach { spec } = &authorization.request.action else {
                    unreachable!()
                };
                attachments::initialize_root_image(
                    directory,
                    spec,
                    &record.session_id,
                    &authorization.request.instance_id,
                    authorization
                        .host_binding
                        .as_deref()
                        .ok_or("initial attachment has no immutable Host binding")?,
                )?;
                attachments::root_image_state(directory, &record.spec.id)?
            }
            Err(error) => return Err(error),
        };
        attachments::verify_root_image_scope(directory, &authorization.request.action)?;
        attachments::verify_root_image_bootstrap(directory, bootstrap)?;
        let profile = attachments::root_image_profile(directory, &record.spec.id)?;
        profile.validate_record(&record)?;
        if let Action::Attach { spec } = &authorization.request.action {
            let runtime = self.runtime.snapshot();
            let capabilities = attachments::dynamic_capabilities_for_origin(
                &runtime.config,
                spec.backend,
                profile.origin,
            );
            capabilities.require_supported()?;
            if capabilities != spec.capabilities {
                return Err(
                    "approved capability report differs from proven execution profile".into(),
                );
            }
        }
        if !live
            && matches!(
                &authorization.request.action,
                Action::Detach { recovery: None, .. }
            )
            && (record.manager.as_ref() != Some(manager)
                || !self.sessions.orphan_manager_has_live_members(
                    &record.session_id,
                    record.spec.target.pid,
                    manager.pid,
                    manager.birth,
                ))
        {
            return Err(
                "orphan Detach requires its actual manager and surviving managed members".into(),
            );
        }
        let scope = attachments::operation_scope_for_authorization(
            authorization,
            bootstrap,
            attachments::root_image_state(directory, &record.spec.id)?,
        )?;
        Ok((directory.clone(), record_directory, record, scope, live))
    }
    pub(super) fn begin_attachment_consumption(
        &self,
        authorization: Authorization,
        manager: ProcessIdentity,
        bootstrap: hyperhub_runtime::attachment::Bootstrap,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            let (_, _, _, scope, _) =
                self.consumption_context(&authorization, &manager, &bootstrap, peer_pid)?;
            let challenge = self
                .operation_challenges
                .begin_verified_scope(scope, unix_timestamp_ms())?;
            Ok(ControlResponse::OperationPossessionChallenge { challenge })
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    pub(super) fn consume_attachment_authorization(
        &self,
        authorization: Authorization,
        manager: ProcessIdentity,
        bootstrap: hyperhub_runtime::attachment::Bootstrap,
        nonce: [u8; 32],
        possession: hyperhub_runtime::attachment::PossessionProof,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            let (directory, record_directory, record, scope, live) =
                self.consumption_context(&authorization, &manager, &bootstrap, peer_pid)?;
            let target = authorization.request.action.target();
            let accepted = attachments::under_root_image_scope(
                &directory,
                &authorization.request.action,
                |epoch| {
                    let accepted = self.operation_challenges.accept_verified_scope(
                        &nonce,
                        &scope,
                        &possession,
                        manager.pid,
                        manager.birth,
                        unix_timestamp_ms(),
                    )?;
                    attachments::consume_for_claimant(&directory, &authorization, &manager)?;
                    if live && record.effective_target() != target {
                        attachments::update_current_target(
                            &record_directory,
                            record.effective_target(),
                            target,
                            epoch.exec_epoch,
                        )?;
                    }
                    Ok(accepted)
                },
            )?;
            let certificate = attachments::sign_accepted_operation(&directory, &accepted)?;
            attachments::record_operation_acceptance(&directory, &authorization, &certificate)?;
            if record.phase == attachments::Phase::Preparing && record.manager.is_none() {
                attachments::register_initial_preparation(
                    &directory,
                    &authorization,
                    &certificate,
                    &scope,
                )?;
            }
            Ok(ControlResponse::AcceptedAttachmentOperation { certificate })
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    pub(super) async fn activate_attachment(
        &self,
        authorization: Authorization,
        session_id: String,
        token: String,
        manager: ProcessIdentity,
        members: Vec<ProcessIdentity>,
        hosts: Vec<attachments::HostBootstrapBinding>,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let _configuration = self.config_update.lock().await;
        let runtime = self.runtime.snapshot();
        let result = (|| {
            let directory = self
                .attachment_directory
                .clone()
                .ok_or("runtime attachments are not enabled for this control instance")?;
            attachments::verify_authorization(&directory, &authorization)?;
            if self.sessions.cleanup_fenced(&session_id, &token) {
                return Err("startup cleanup is fenced; finish cleanup before reactivation".into());
            }
            attachments::require_initial_mutation_gate(&directory, &authorization)?;
            let Action::Attach { spec } = &authorization.request.action else {
                return Err("detach approval cannot activate a process".to_string());
            };
            if peer_pid != Some(manager.pid)
                || !attachments::authorization_consumed_by(&directory, &authorization, manager.pid)
            {
                return Err("attachment manager does not own this one-shot authorization".into());
            }
            let persisted = attachments::load_record(&attachments::attachment_directory(
                &directory, &spec.id,
            )?)?;
            if persisted.spec.target != spec.target || persisted.session_id != session_id {
                return Err("attachment session identity mismatch".into());
            }
            if spec.recovery.is_some()
                && self
                    .sessions
                    .engine_manager_start(&session_id, &token, manager.pid)
                    != Some(manager.birth)
            {
                return Err(
                    "recovery requires explicit authenticated session adoption before activation"
                        .into(),
                );
            }
            let profile = attachments::root_image_profile(&directory, &spec.id)?;
            profile.validate_record(&persisted)?;
            let capabilities = attachments::dynamic_capabilities_for_origin(
                &runtime.config,
                spec.backend,
                profile.origin,
            );
            capabilities.require_supported()?;
            if capabilities != spec.capabilities {
                return Err(
                    "approved attachment capability report differs from current policy".into(),
                );
            }
            if attachments::policy_digest(&runtime.config)? != spec.policy_digest {
                return Err("policy changed after attachment approval".into());
            }
            attachments::verify_process(&manager)?;
            if manager.executable_sha256 != authorization.executor_sha256 {
                return Err("attachment manager executable is not the approved executor".into());
            }
            attachments::verify_process(spec.effective_target())?;
            if spec.target.pid == std::process::id() || spec.target.pid == manager.pid {
                return Err("cannot attach the attachment control plane".into());
            }
            if members.is_empty()
                || members.len() > 4096
                || !members.iter().any(|m| m == spec.effective_target())
            {
                return Err(
                    "attachment member list omits the approved root or exceeds its limit".into(),
                );
            }
            let mut seen = std::collections::HashSet::new();
            for member in &members {
                if !seen.insert(member.pid) {
                    return Err("duplicate attachment member".into());
                }
                attachments::verify_process(member)?;
                if member.owner != spec.target.owner {
                    return Err("attachment tree crosses a process owner boundary".into());
                }
                if member.pid != spec.target.pid
                    && (spec.scope != Scope::Tree
                        || !process_ancestors(member.pid).contains(&spec.target.pid))
                {
                    return Err("attachment member is outside the approved tree".into());
                }
            }
            if authorization.host_binding != persisted.host_binding {
                return Err("approved Host binding differs from attachment record".into());
            }
            let missing = !self.sessions.authenticate_control(&session_id, &token)
                && self
                    .sessions
                    .pending_executable(&session_id, &token)
                    .is_none();
            let mut alias_sources = Vec::new();
            let aliases = if spec.backend == Backend::Gum && (!hosts.is_empty() || missing) {
                if hosts.len() != members.len() {
                    return Err(
                        "resident session restoration requires every live Host locator".into(),
                    );
                }
                let mut aliases = Vec::new();
                let proof = attachments::host_proof(&authorization)?;
                for member in &members {
                    let host = hosts
                        .iter()
                        .find(|host| &host.identity == member)
                        .ok_or("resident Host locator omits a live approved member")?;
                    if host.bootstrap.attachment_id != spec.id
                        || host.bootstrap.root_pid != spec.target.pid
                        || host.bootstrap.session_id != session_id
                        || !crate::session::constant_time_eq(
                            host.bootstrap.token.as_bytes(),
                            token.as_bytes(),
                        )
                        || Some(
                            host.bootstrap
                                .approval_binding()
                                .map_err(|e| e.to_string())?,
                        ) != authorization.host_binding
                    {
                        return Err(
                            "resident Host locator differs from approved original Bootstrap".into(),
                        );
                    }
                    let response = hyperhub_runtime::attachment::exchange_for_process(
                        &host.bootstrap.host_endpoint,
                        &hyperhub_runtime::attachment::AuthenticatedCommand {
                            attachment_id: spec.id.clone(),
                            token: host.bootstrap.host_token.clone(),
                            command: hyperhub_runtime::attachment::HostCommand::SnapshotAliases,
                            proof: Some(proof.clone()),
                            enrollment: None,
                            aliases: None,
                            root_image: None,
                        },
                        member.pid,
                    )
                    .map_err(|e| format!("cannot obtain actual resident issued aliases: {e}"))?;
                    let snapshot = response
                        .alias_snapshot
                        .ok_or("Host did not return issued alias snapshot")?;
                    if !snapshot.complete {
                        return Err("alias_publication_busy".into());
                    }
                    alias_sources.push((
                        host.clone(),
                        snapshot.clone(),
                        response.alias_inheritance,
                        response.root_image,
                    ));
                    aliases.extend(snapshot.issued);
                    if aliases.len() > 8192 {
                        return Err("resident alias snapshot exceeds restoration limit".into());
                    }
                }
                aliases
            } else {
                Vec::new()
            };
            attachments::verify_root_image_scope(&directory, &authorization.request.action)?;
            attachments::activate_epoch(&directory, &authorization)?;
            if !self.sessions.authenticate_control(&session_id, &token)
                && self
                    .sessions
                    .pending_executable(&session_id, &token)
                    .is_none()
            {
                self.sessions.prepare_approved_attachment(
                    &session_id,
                    &token,
                    &spec.effective_target().executable,
                    &aliases,
                )?;
            } else if !aliases.is_empty() {
                self.sessions
                    .merge_approved_aliases(&session_id, &token, &aliases)?;
            }
            let policy = crate::session::ProcessHookMetadata {
                hook_status: "preparing".into(),
                policy_version: runtime.updated_at_ms,
                rule_id: None,
                decision_source: "attachment_approval".into(),
            };
            if let Some(expected) = self.sessions.pending_executable(&session_id, &token) {
                if !same_requested_executable(&expected, &spec.effective_target().executable) {
                    return Err("pending attachment executable mismatch".into());
                }
                if !self.sessions.activate_with_policy(
                    &session_id,
                    &token,
                    spec.target.pid,
                    policy.clone(),
                ) {
                    return Err("cannot activate attachment session".into());
                }
                monitor_new_session_member(
                    &self.sessions,
                    &self.engine_hosts,
                    &session_id,
                    &token,
                    spec.target.pid,
                    &spec.effective_target().executable,
                )
                .map_err(|e| e.to_string())?;
            } else if !self
                .sessions
                .authenticate_member(&session_id, &token, spec.target.pid)
            {
                return Err("attachment session is not authenticated".into());
            }
            if !self
                .sessions
                .retain_engine_manager(&session_id, &token, manager.pid, manager.birth)
                || !self.sessions.set_attachment_manager_scope(
                    &session_id,
                    &token,
                    manager.pid,
                    manager.birth,
                    spec.scope,
                )
            {
                return Err("cannot retain attachment manager".into());
            }
            if spec.backend == Backend::Ptrace {
                let instance = self
                    .sessions
                    .member_instance(&session_id, &token, spec.target.pid)
                    .ok_or("attachment root member missing")?;
                if !self.sessions.remember_ptrace_root(
                    &session_id,
                    &token,
                    manager.pid,
                    manager.birth,
                    crate::session::DurablePtraceRoot {
                        root_pid: spec.target.pid,
                        root_start_time: spec.target.birth,
                        member_instance: instance,
                    },
                ) {
                    return Err("cannot bind ptrace attachment manager".into());
                }
            }
            for member in &members {
                if member.pid != spec.target.pid {
                    if !self.sessions.register_child_with_policy(
                        &session_id,
                        &token,
                        spec.target.pid,
                        member.pid,
                        member.executable.clone(),
                        policy.clone(),
                    ) {
                        return Err("cannot register approved attachment member".into());
                    }
                    monitor_new_session_member(
                        &self.sessions,
                        &self.engine_hosts,
                        &session_id,
                        &token,
                        member.pid,
                        &member.executable,
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
            if !alias_sources.is_empty() {
                self.restore_alias_history(&authorization, &alias_sources)?;
            }
            self.audit.session_event("attachment_activated",&session_id,peer_pid,Some(&spec.target.executable),serde_json::json!({"attachment_id":spec.id,"members":members.len(),"scope":spec.scope,"backend":spec.backend}));
            Ok(())
        })();
        match result {
            Ok(()) => ControlResponse::Ok,
            Err(message) => ControlResponse::Error { message },
        }
    }
}

impl ControlService {
    pub(super) fn attachment_status(
        &self,
    ) -> (
        Vec<attachments::Record>,
        Option<String>,
        Vec<crate::session::SessionSnapshot>,
    ) {
        let state = self
            .attachment_directory
            .as_ref()
            .map(|d| attachments::records(d))
            .unwrap_or_else(|| Ok(vec![]));
        let (records, error) = match state {
            Ok(records) => (records, None),
            Err(error) => (vec![], Some(error)),
        };
        let mut sessions = self.sessions.snapshot();
        for record in &records {
            if let Some(session) = sessions
                .iter_mut()
                .find(|s| s.session_id == record.session_id)
            {
                let state = match record.phase {
                    attachments::Phase::Active => "hook",
                    attachments::Phase::Preparing => "preparing",
                    attachments::Phase::Detaching | attachments::Phase::Draining => "detaching",
                    attachments::Phase::DetachedResident => "detached_resident",
                    attachments::Phase::Detached => "detached",
                    attachments::Phase::Exited => "exited",
                    attachments::Phase::Degraded
                    | attachments::Phase::Failed
                    | attachments::Phase::CleanupPending => "unknown",
                };
                for process in &mut session.processes {
                    if matches!(process.hook_status.as_str(), "hook" | "preparing") {
                        process.hook_status = state.into();
                    }
                }
            }
        }
        (records, error, sessions)
    }
    pub(super) fn attachment_configuration_guard(
        &self,
        config: &Config,
    ) -> Result<Option<attachments::OperationGuard>, String> {
        let Some(directory) = &self.attachment_directory else {
            return Ok(None);
        };
        attachments::configuration_guard(directory, config).map(Some)
    }
    fn attachment_upgrade_guard(&self) -> Result<Option<attachments::OperationGuard>, String> {
        let Some(directory) = &self.attachment_directory else {
            return Ok(None);
        };
        let guard = attachments::OperationGuard::acquire(directory)?;
        if attachments::records(directory)?.iter().any(|r| {
            matches!(
                r.phase,
                attachments::Phase::Preparing
                    | attachments::Phase::Detaching
                    | attachments::Phase::Draining
                    | attachments::Phase::CleanupPending
            )
        }) {
            return Err(
                "runtime attachment transition is busy; retry the upgrade after it completes"
                    .into(),
            );
        }
        Ok(Some(guard))
    }
    pub(super) async fn submit_attachment_guarded_release(
        &self,
        request: crate::release::Request,
    ) -> ControlResponse {
        let _guard = match self.attachment_upgrade_guard() {
            Ok(g) => g,
            Err(message) => return ControlResponse::Error { message },
        };
        let Some(coordinator) = &self.release_upgrades else {
            return ControlResponse::Error {
                message: "release coordinator unavailable; requires_restart".into(),
            };
        };
        match coordinator.submit(request).await {
            Ok(record) => {
                coordinator.spawn();
                ControlResponse::ReleaseUpgrade { record }
            }
            Err(e) => ControlResponse::Error {
                message: e.to_string(),
            },
        }
    }
    pub(super) async fn submit_attachment_guarded_engine(
        &self,
        request: crate::upgrade::Request,
    ) -> ControlResponse {
        let _guard = match self.attachment_upgrade_guard() {
            Ok(g) => g,
            Err(message) => return ControlResponse::Error { message },
        };
        let Some(coordinator) = &self.engine_upgrades else {
            return ControlResponse::Error {
                message: "durable upgrade coordinator unavailable; requires_restart".into(),
            };
        };
        let recover = matches!(request.action, crate::upgrade::Action::Recover);
        match coordinator.submit(request).await {
            Ok(record) => {
                if recover {
                    let _ = coordinator.spawn();
                }
                ControlResponse::EngineUpgrade {
                    record: crate::upgrade::RecordView::from_record(&record, true),
                }
            }
            Err(e) => ControlResponse::Error {
                message: e.to_string(),
            },
        }
    }
}

/// A launcher's random handoff secret is never persisted in the runtime envelope.
/// OS IPC peer identity authenticates registration; the one-use secret authenticates
/// its child keeper, including on Windows where an observed parent PID can be forged.
pub(super) struct OwnedRunHandoff {
    session_id: String,
    launcher: ProcessIdentity,
    target: ProcessIdentity,
    keeper: ProcessIdentity,
    execution_digest: String,
    secret_digest: String,
    expires_at_ms: u64,
    claimed: Option<ProcessIdentity>,
}
impl ControlService {
    pub(super) fn register_owned_attachment_keeper(
        &self,
        session_id: String,
        token: String,
        attachment_id: String,
        target: ProcessIdentity,
        keeper: ProcessIdentity,
        execution_digest: String,
        secret_digest: String,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| -> Result<(), String> {
            if !attachments::valid_id(&attachment_id)
                || execution_digest.len() != 64
                || secret_digest.len() != 64
            {
                return Err("invalid owned-run keeper handoff".into());
            }
            let peer =
                peer_pid.ok_or("keeper registration requires an OS-authenticated launcher")?;
            let launcher = attachments::inspect_process(peer)?;
            if launcher.executable_sha256 != attachments::executor_digest()? {
                return Err(
                    "keeper registration did not originate from this HyperHub executable".into(),
                );
            }
            keeper.validate()?;
            if keeper.pid == target.pid
                || keeper.executable_sha256 != launcher.executable_sha256
                || keeper.owner != launcher.owner
                || crate::session::process_start_time(keeper.pid) != Some(keeper.birth)
            {
                return Err("keeper handoff does not name the launcher's exact new helper".into());
            }
            validate_child_process(peer, keeper.pid, &keeper.executable)
                .map_err(|e| e.to_string())?;
            attachments::verify_process(&target)?;
            validate_child_process(peer, target.pid, &target.executable)
                .map_err(|e| e.to_string())?;
            if !self
                .sessions
                .authenticate_member(&session_id, &token, target.pid)
            {
                return Err("keeper target is not an activated child of this run".into());
            }
            let base = self
                .attachment_directory
                .as_ref()
                .ok_or("attachment lifecycle is disabled")?;
            let record = attachments::load_record(&attachments::attachment_directory(
                base,
                &attachment_id,
            )?)?;
            if record.origin != attachments::Origin::Run
                || record.spec.target != target
                || record.manager.as_ref() != Some(&launcher)
                || record.session_id != session_id
            {
                return Err(
                    "owned-run handoff does not match its original launcher and child".into(),
                );
            }
            let mut handoffs = self
                .owned_attachment_handoffs
                .lock()
                .map_err(|_| "keeper handoff registry unavailable")?;
            let now = unix_timestamp_ms();
            handoffs.retain(|_, h| h.expires_at_ms >= now);
            if handoffs.contains_key(&attachment_id) {
                return Err("owned-run keeper handoff is already pending".into());
            }
            handoffs.insert(
                attachment_id,
                OwnedRunHandoff {
                    session_id,
                    launcher,
                    target,
                    keeper,
                    execution_digest,
                    secret_digest,
                    expires_at_ms: now.saturating_add(30_000),
                    claimed: None,
                },
            );
            Ok(())
        })();
        match result {
            Ok(()) => ControlResponse::Ok,
            Err(message) => ControlResponse::Error { message },
        }
    }
    pub(super) fn claim_owned_attachment_keeper(
        &self,
        session_id: String,
        token: String,
        attachment_id: String,
        execution_digest: String,
        secret: String,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| -> Result<(), String> {
            let peer = peer_pid.ok_or("keeper claim requires an OS-authenticated process")?;
            let keeper = attachments::inspect_process(peer)?;
            if keeper.executable_sha256 != attachments::executor_digest()? {
                return Err("keeper executable does not match its launcher".into());
            }
            let mut handoffs = self
                .owned_attachment_handoffs
                .lock()
                .map_err(|_| "keeper handoff registry unavailable")?;
            let handoff = handoffs
                .get_mut(&attachment_id)
                .ok_or("no pending owned-run keeper handoff")?;
            if handoff.claimed.is_some() {
                return Err("owned-run keeper handoff is already claimed".into());
            }
            if keeper != handoff.keeper {
                return Err("keeper claim does not match its pinned creation identity".into());
            }
            if handoff.expires_at_ms < unix_timestamp_ms()
                || handoff.session_id != session_id
                || handoff.execution_digest != execution_digest
                || secret.len() != 64
                || !crate::session::constant_time_eq(
                    handoff.secret_digest.as_bytes(),
                    attachments::digest(secret.as_bytes()).as_bytes(),
                )
            {
                return Err("owned-run keeper handoff proof rejected".into());
            }
            attachments::verify_process(&handoff.launcher)?;
            attachments::verify_process(&handoff.target)?;
            validate_child_process(handoff.launcher.pid, peer, &keeper.executable)
                .map_err(|e| e.to_string())?;
            validate_child_process(
                handoff.launcher.pid,
                handoff.target.pid,
                &handoff.target.executable,
            )
            .map_err(|e| e.to_string())?;
            if !self
                .sessions
                .authenticate_member(&session_id, &token, handoff.target.pid)
                || !self
                    .sessions
                    .retain_engine_manager(&session_id, &token, peer, keeper.birth)
                || !self.sessions.set_attachment_manager_scope(
                    &session_id,
                    &token,
                    peer,
                    keeper.birth,
                    Scope::Tree,
                )
            {
                return Err("cannot adopt the owned-run session".into());
            }
            handoff.claimed = Some(keeper);
            Ok(())
        })();
        match result {
            Ok(()) => ControlResponse::Ok,
            Err(message) => ControlResponse::Error { message },
        }
    }
    pub(super) fn complete_attachment(
        &self,
        authorization: Authorization,
        session_id: String,
        token: String,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| -> Result<(), String> {
            let base = self
                .attachment_directory
                .as_ref()
                .ok_or("attachment lifecycle is disabled")?;
            let peer = peer_pid.ok_or("completion requires an OS-authenticated manager")?;
            let manager = attachments::inspect_process(peer)?;
            if manager.executable_sha256 != authorization.executor_sha256 {
                return Err("completion manager is not the approved executable".into());
            }
            attachments::verify_consumed_continuation(base, &authorization, peer)?;
            let Action::Detach {
                attachment_id,
                target,
                ..
            } = &authorization.request.action
            else {
                return Err("completion requires a detach approval".into());
            };
            let record =
                attachments::load_record(&attachments::attachment_directory(base, attachment_id)?)?;
            if !completion_phase_proven(&record)
                || !record.spec.target.same_incarnation(target)
                || record.manager.as_ref() != Some(&manager)
                || record.session_id != session_id
                || (self
                    .sessions
                    .engine_manager_start(&session_id, &token, peer)
                    != Some(manager.birth)
                    && !attachments::completion_receipt_matches(
                        base,
                        &authorization,
                        &session_id,
                        &token,
                        &manager,
                    )
                    && !attachments::prior_completion_receipt_matches(
                        base,
                        &authorization,
                        &session_id,
                        &token,
                    ))
            {
                return Err(
                    "completion does not prove this manager's fully detached session".into(),
                );
            }
            attachments::record_completion_receipt(
                base,
                &authorization,
                &session_id,
                &token,
                &manager,
            )?;
            attachments::under_consumed_epoch(base, &authorization, || {
                self.sessions.revoke(&session_id)
            })?;
            // Only a committed revocation may become cold-recovery authority.
            // The earlier unsigned audit is an intent if the epoch CAS fails.
            attachments::finalize_durable_completion(
                base,
                &authorization,
                &session_id,
                &token,
                &manager,
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => ControlResponse::Ok,
            Err(message) => ControlResponse::Error { message },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Source fixture for the real parent/child contract. The normal suite returns
    /// immediately; an explicitly spawned copy lives until its anonymous pipe closes.
    #[test]
    fn owned_child_fixture() {
        if std::env::var_os("HYPERHUB_TEST_OWNED_CHILD").is_some() {
            use std::io::Read;
            let _ = std::io::stdin().read(&mut [0u8; 1]);
        }
    }
    #[tokio::test]
    #[cfg(any(windows, target_os = "linux"))]
    async fn owned_child_activation_round_trip() {
        let root = std::env::temp_dir().join(format!("hh-owned-child-{}", attachments::new_id()));
        attachments::private_directory(&root).unwrap();
        let endpoint = instance_control_endpoint(&root);
        let sessions = SessionRegistry::default();
        let service = ControlService::new(
            sessions.clone(),
            ConnectionRegistry::default(),
            "test-ca".into(),
            AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(crate::config::Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        );
        let directory = root.join("attachments");
        let service = service.with_attachment_directory(directory.clone());
        let handoffs = service.owned_attachment_handoffs.clone();
        let task = tokio::spawn(run_control_server(endpoint.clone(), service));
        let executable = std::env::current_exe().unwrap().display().to_string();
        let challenge = sessions
            .begin_auth("owned-child".into(), executable.clone(), [2; 32])
            .unwrap();
        let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
        let record = sessions
            .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(60))
            .unwrap();
        let mut child = std::process::Command::new(&executable)
            .args([
                "--exact",
                "control::attachment_control::tests::owned_child_fixture",
                "--nocapture",
            ])
            .env("HYPERHUB_TEST_OWNED_CHILD", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let response = control_request(
            &endpoint,
            &ControlRequest::ActivateSession {
                session_id: "owned-child".into(),
                token: record.token.clone(),
                root_pid: child.id(),
                executable,
                root_executable: None,
                process_policy_version: 0,
                process_rule_id: None,
                process_decision_source: "test".into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(response, ControlResponse::Ok));
        let target = attachments::inspect_process(child.id()).unwrap();
        let id = attachments::new_id();
        attachments::register_owned_run(
            &directory,
            attachments::Spec {
                exec_epoch: 0,
                current_target: None,
                recovery: None,
                id: id.clone(),
                target: target.clone(),
                scope: Scope::Tree,
                backend: Backend::Gum,
                policy_digest: "ab".repeat(32),
                capabilities: Default::default(),
            },
            "owned-child".into(),
            attachments::inspect_process(std::process::id()).unwrap(),
        )
        .unwrap();
        let mut keeper_fixture = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "control::attachment_control::tests::owned_child_fixture",
                "--nocapture",
            ])
            .env("HYPERHUB_TEST_OWNED_CHILD", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut keeper_identity = attachments::inspect_process(std::process::id()).unwrap();
        keeper_identity.pid = keeper_fixture.id();
        keeper_identity.birth = attachments::process_birth(keeper_fixture.id()).unwrap();
        let secret = "12".repeat(32);
        let registered = control_request(
            &endpoint,
            &ControlRequest::RegisterOwnedAttachmentKeeper {
                session_id: "owned-child".into(),
                token: record.token.clone().into(),
                attachment_id: id.clone(),
                target,
                keeper: keeper_identity,
                execution_digest: "cd".repeat(32),
                secret_digest: attachments::digest(secret.as_bytes()),
            },
        )
        .await
        .unwrap();
        assert!(matches!(registered, ControlResponse::Ok));
        // Possessing the session credential is insufficient, and a rejected
        // claimant cannot consume the launcher's one-use handoff.
        let rejected = control_request(
            &endpoint,
            &ControlRequest::ClaimOwnedAttachmentKeeper {
                session_id: "owned-child".into(),
                token: record.token.clone().into(),
                attachment_id: id.clone(),
                execution_digest: "cd".repeat(32),
                secret: "wrong-api-holder-proof".to_owned().into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(rejected, ControlResponse::Error { .. }));
        assert!(handoffs.lock().unwrap().contains_key(&id));
        // Even the correct secret does not make the launcher its own keeper.
        let wrong_source = control_request(
            &endpoint,
            &ControlRequest::ClaimOwnedAttachmentKeeper {
                session_id: "owned-child".into(),
                token: record.token.clone().into(),
                attachment_id: id.clone(),
                execution_digest: "cd".repeat(32),
                secret: secret.clone().into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(wrong_source, ControlResponse::Error { .. }));
        assert!(handoffs.lock().unwrap().contains_key(&id));
        let rejected_cancel = control_request(
            &endpoint,
            &ControlRequest::CancelOwnedAttachmentKeeper {
                session_id: "owned-child".into(),
                token: record.token.clone().into(),
                attachment_id: id.clone(),
                secret: "wrong-cancel-secret".to_owned().into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(rejected_cancel, ControlResponse::Error { .. }));
        assert!(handoffs.lock().unwrap().contains_key(&id));
        let cancelled = control_request(
            &endpoint,
            &ControlRequest::CancelOwnedAttachmentKeeper {
                session_id: "owned-child".into(),
                token: record.token.clone().into(),
                attachment_id: id.clone(),
                secret: secret.into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(cancelled, ControlResponse::Ok));
        assert!(!handoffs.lock().unwrap().contains_key(&id));
        assert!(
            sessions.authenticate_member("owned-child", &record.token, child.id()),
            "cancellation revoked target session"
        );
        drop(keeper_fixture.stdin.take());
        let keeper_deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if keeper_fixture.try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= keeper_deadline {
                let _ = keeper_fixture.kill();
                panic!("owned test keeper did not exit");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = child.stdin.take();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("owned test child did not exit after its private pipe closed");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        task.abort();
        let _ = task.await;
        let _ = std::fs::remove_dir_all(root);
        assert!(status.success());
        assert!(matches!(response, ControlResponse::Ok));
    }
}

impl ControlService {
    fn validate_unstarted_cleanup(
        &self,
        authorization: &Authorization,
        record: &attachments::Record,
        session_id: &str,
        token: &str,
        members: &[ProcessIdentity],
        hosts: &[attachments::HostBootstrapBinding],
        unstarted: &[attachments::HostBootstrapBinding],
        proof: &attachments::UnstartedInjectionProof,
        manager: &ProcessIdentity,
    ) -> Result<(), String> {
        let base = self
            .attachment_directory
            .as_ref()
            .ok_or("attachment recovery is disabled")?;
        if !cfg!(target_os = "linux")
            || record.spec.backend != Backend::Gum
            || !matches!(authorization.request.action, Action::Detach { .. })
        {
            return Err(
                "unstarted recovery is cleanup-only for approved initial Gum dispatch".into(),
            );
        }
        attachments::verify_consumed_continuation(base, authorization, manager.pid)?;
        attachments::verify_unstarted(
            proof,
            authorization,
            hosts,
            unstarted,
            attachments::approval_trust(base)?.core_public_key,
        )?;
        let mut seen = members
            .iter()
            .map(|member| member.pid)
            .collect::<std::collections::HashSet<_>>();
        for binding in hosts.iter().chain(unstarted) {
            let identity = &binding.identity;
            attachments::verify_process(identity)?;
            if (unstarted
                .iter()
                .any(|attempt| attempt.identity == *identity)
                && !seen.insert(identity.pid))
                || identity.owner != record.spec.target.owner
                || (record.spec.scope == Scope::Process && identity.pid != record.spec.target.pid)
                || binding.bootstrap.session_id != session_id
                || binding.bootstrap.token != token
                || binding.bootstrap.attachment_id != record.spec.id
                || record.host_binding.as_deref()
                    != Some(
                        &binding
                            .bootstrap
                            .approval_binding()
                            .map_err(|e| e.to_string())?,
                    )
            {
                return Err(
                    "unstarted cleanup locator differs from an original approved session member"
                        .into(),
                );
            }
            attachments::verify_root_image_bootstrap(base, &binding.bootstrap)?;
        }
        if !hosts.is_empty()
            && (hosts.len() != members.len()
                || members
                    .iter()
                    .any(|member| !hosts.iter().any(|host| &host.identity == member)))
        {
            return Err("startup cleanup must bind every surviving real Host".into());
        }
        self.sessions.validate_unstarted_members(
            session_id,
            token,
            unstarted,
            members.is_empty(),
        )?;
        self.validate_unstarted_aliases(session_id, unstarted, members.is_empty())?;
        if self.engine_hosts.hosts().iter().any(|host| {
            host.session_id == session_id
                && (members.is_empty()
                    || unstarted.iter().any(|binding| {
                        binding.identity.pid == host.root_pid
                            || binding.identity.pid == host.host_pid
                    }))
        }) {
            return Err("unstarted cleanup conflicts with a registered Engine Host".into());
        }
        Ok(())
    }
    pub(super) async fn recover_attachment(
        &self,
        authorization: Authorization,
        session_id: String,
        token: String,
        manager: ProcessIdentity,
        members: Vec<ProcessIdentity>,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        self.recover_attachment_with_unstarted(
            authorization,
            session_id,
            token,
            manager,
            members,
            Vec::new(),
            Vec::new(),
            None,
            peer_pid,
        )
        .await
    }
    pub(super) async fn recover_attachment_with_unstarted(
        &self,
        authorization: Authorization,
        session_id: String,
        token: String,
        manager: ProcessIdentity,
        members: Vec<ProcessIdentity>,
        startup_hosts: Vec<attachments::HostBootstrapBinding>,
        unstarted: Vec<attachments::HostBootstrapBinding>,
        unstarted_proof: Option<attachments::UnstartedInjectionProof>,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let _configuration = self.config_update.lock().await;
        let result = (|| -> Result<(), String> {
            let base = self
                .attachment_directory
                .as_ref()
                .ok_or("attachment recovery is disabled")?;
            attachments::verify_authorization(base, &authorization)?;
            if peer_pid != Some(manager.pid)
                || !attachments::authorization_consumed_by(base, &authorization, manager.pid)
            {
                return Err(
                    "recovery grant was not consumed by this OS-authenticated manager".into(),
                );
            }
            let record = attachments::load_record(&attachments::attachment_directory(
                base,
                authorization.request.action.attachment_id(),
            )?)?;
            let live_cleanup = live_startup_cleanup_scope(
                &authorization,
                &record,
                &manager,
                self.sessions.attachment_manager_scope(
                    &session_id,
                    &token,
                    manager.pid,
                    manager.birth,
                ),
                !startup_hosts.is_empty() || !unstarted.is_empty(),
            );
            if !record
                .spec
                .target
                .same_incarnation(authorization.request.action.target())
                || record.session_id != session_id
            {
                return Err("cleanup differs from this attachment's original session".into());
            }
            if live_cleanup {
                // This is not adoption by another manager. The original live
                // OS peer may fence and cancel its own journaled initialization
                // only under a newly consumed Detach and exact roster proof.
                attachments::verify_root_image_scope(base, &authorization.request.action)?;
            } else {
                let binding = authorization
                    .request
                    .action
                    .recovery()
                    .ok_or("recovery requires explicit signed recovery binding")?;
                if record.manager.as_ref() != Some(&binding.manager)
                    || !attachments::process_incarnation_exited(
                        binding.manager.pid,
                        binding.manager.birth,
                    )
                {
                    return Err(
                        "recovery does not replace this attachment's vanished manager".into(),
                    );
                }
            }
            attachments::verify_process(&manager)?;
            if manager.executable_sha256 != authorization.executor_sha256
                || authorization.request.action.policy_digest()
                    != attachments::policy_digest(&self.runtime.snapshot().config)?
            {
                return Err("recovery executor or policy differs from approval".into());
            }
            if let Action::Attach { spec } = &authorization.request.action {
                attachments::verify_process(spec.effective_target())?;
                let profile = attachments::root_image_profile(base, &record.spec.id)?;
                profile.validate_record(&record)?;
                let capabilities = attachments::dynamic_capabilities_for_origin(
                    &self.runtime.snapshot().config,
                    spec.backend,
                    profile.origin,
                );
                capabilities.require_supported()?;
                if capabilities != spec.capabilities
                    || spec.scope != record.spec.scope
                    || spec.backend != record.spec.backend
                {
                    return Err("recovery attachment contract changed".into());
                }
            }
            if (unstarted.is_empty() && startup_hosts.is_empty()) != unstarted_proof.is_none() {
                return Err(
                    "unstarted cleanup roster and possession proof must occur together".into(),
                );
            }
            if !unstarted.is_empty() || !startup_hosts.is_empty() {
                self.validate_unstarted_cleanup(
                    &authorization,
                    &record,
                    &session_id,
                    &token,
                    &members,
                    &startup_hosts,
                    &unstarted,
                    unstarted_proof.as_ref().unwrap(),
                    &manager,
                )?;
            }
            if !self.sessions.authenticate_control(&session_id, &token) {
                if !attachments::prior_completion_receipt_matches(
                    base,
                    &authorization,
                    &session_id,
                    &token,
                ) {
                    return Err("missing session requires exact prior signed cleanup completion; attach cannot revive it".into());
                }
                // The old completion proves revocation already committed. Only
                // cleanup is permitted, with no registration or membership grant.
                for member in &members {
                    attachments::verify_process(member)?;
                    if !record.members.iter().any(|known| known == member) {
                        return Err("cleanup cannot add new session members".into());
                    }
                }
                return Ok(());
            }
            if (members.is_empty() && unstarted.is_empty())
                || members.len() + unstarted.len() > 4096
            {
                return Err(
                    "recovery requires live authenticated members or proven unstarted cleanup"
                        .into(),
                );
            }
            let mut seen = std::collections::HashSet::new();
            for member in &members {
                attachments::verify_process(member)?;
                if !seen.insert(member.pid)
                    || member.owner != record.spec.target.owner
                    || !self
                        .sessions
                        .authenticate_member(&session_id, &token, member.pid)
                    || !self
                        .sessions
                        .member_birth_matches(&session_id, &token, member.pid)
                    || self.sessions.member_executable(member.pid).as_deref()
                        != Some(member.executable.as_str())
                {
                    return Err(
                        "recovery member is not the recorded live session incarnation".into(),
                    );
                }
            }
            if !startup_hosts.is_empty() || !unstarted.is_empty() {
                self.sessions
                    .fence_attachment_cleanup(&session_id, &token, authorization.nonce)?;
            }
            if live_cleanup {
                self.sessions.validate_live_cleanup_roster(
                    &session_id,
                    &token,
                    &members,
                    &unstarted,
                )?;
            }
            if !startup_hosts.is_empty() {
                self.register_startup_cleanup_hosts(&startup_hosts)?;
            }
            if !self
                .sessions
                .retain_engine_manager(&session_id, &token, manager.pid, manager.birth)
                || !self.sessions.set_attachment_manager_scope(
                    &session_id,
                    &token,
                    manager.pid,
                    manager.birth,
                    record.spec.scope,
                )
            {
                return Err("cannot retain recovered manager".into());
            }
            if record.spec.backend == Backend::Ptrace {
                if let Some(instance) =
                    self.sessions
                        .member_instance(&session_id, &token, record.spec.target.pid)
                {
                    if !self.sessions.remember_ptrace_root(
                        &session_id,
                        &token,
                        manager.pid,
                        manager.birth,
                        crate::session::DurablePtraceRoot {
                            root_pid: record.spec.target.pid,
                            root_start_time: record.spec.target.birth,
                            member_instance: instance,
                        },
                    ) {
                        return Err(
                            "cannot bind recovered ptrace manager to its original root".into()
                        );
                    }
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => ControlResponse::Ok,
            Err(message) => ControlResponse::Error { message },
        }
    }
}

// Signature, OS peer, consumed claimant and exact roster possession are
// verified by the caller; this gate cannot turn Attach into a cleanup grant.
fn live_startup_cleanup_scope(
    authorization: &Authorization,
    record: &attachments::Record,
    manager: &ProcessIdentity,
    ram_scope: Option<Scope>,
    has_roster: bool,
) -> bool {
    cfg!(target_os = "linux")
        && record.spec.backend == Backend::Gum
        && matches!(
            authorization.request.action,
            Action::Detach { recovery: None, .. }
        )
        && authorization.request.action.exec_epoch() == record.exec_epoch
        && authorization.request.action.target().root_image_identity()
            == record.effective_target().root_image_identity()
        && record.manager.as_ref() == Some(manager)
        && ram_scope == Some(record.spec.scope)
        && has_roster
}

fn completion_phase_proven(record: &attachments::Record) -> bool {
    record.phase == attachments::Phase::Detached
        || (matches!(
            record.phase,
            attachments::Phase::Detaching | attachments::Phase::CleanupPending
        ) && record
            .compatibility_reasons
            .iter()
            .any(|reason| reason == "physical_native_modules_absent_pending_session_revocation"))
}

#[cfg(all(test, target_os = "linux"))]
mod live_cleanup_scope_tests {
    use super::*;
    #[test]
    fn live_cleanup_never_adopts_another_manager_or_reuses_attach_or_old_epoch() {
        let manager = attachments::inspect_process(std::process::id()).unwrap();
        let directory =
            std::env::temp_dir().join(format!("hh-live-cleanup-scope-{}", attachments::new_id()));
        let spec = attachments::Spec {
            id: attachments::new_id(),
            target: manager.clone(),
            current_target: None,
            exec_epoch: 0,
            scope: Scope::Tree,
            backend: Backend::Gum,
            policy_digest: "ab".repeat(32),
            capabilities: Default::default(),
            recovery: None,
        };
        let mut record = attachments::create_record(&directory, spec.clone()).unwrap();
        record.manager = Some(manager.clone());
        let mut grant: Authorization = serde_json::from_value(serde_json::json!({
            "request":{"schema_version":1,"id":attachments::new_id(),"instance_id":"ab".repeat(32),"created_at_ms":1,
                "action":{"kind":"detach","exec_epoch":0,"attachment_id":spec.id,"target":manager,"policy_digest":spec.policy_digest,"recovery":null}},
            "approved_at_ms":1,"expires_at_ms":2,"nonce":vec![1u8;32],"executor_sha256":manager.executable_sha256,"signature":[]
        })).unwrap();
        let check = |grant: &Authorization,
                     record: &attachments::Record,
                     manager: &ProcessIdentity,
                     scope,
                     roster| {
            live_startup_cleanup_scope(grant, record, manager, scope, roster)
        };
        assert!(check(&grant, &record, &manager, Some(Scope::Tree), true));
        assert!(!check(&grant, &record, &manager, None, true));
        assert!(!check(
            &grant,
            &record,
            &manager,
            Some(Scope::Process),
            true
        ));
        assert!(!check(&grant, &record, &manager, Some(Scope::Tree), false));
        let mut other = manager.clone();
        other.birth += 1;
        assert!(!check(&grant, &record, &other, Some(Scope::Tree), true));
        let detach = grant.request.action.clone();
        grant.request.action = Action::Attach { spec: spec.clone() };
        assert!(!check(&grant, &record, &manager, Some(Scope::Tree), true));
        grant.request.action = detach;
        record.exec_epoch = 1;
        assert!(!check(&grant, &record, &manager, Some(Scope::Tree), true));
        record.exec_epoch = 0;
        if let Action::Detach { recovery, .. } = &mut grant.request.action {
            *recovery = Some(attachments::RecoveryBinding {
                manager: manager.clone(),
                context_digest: "cd".repeat(32),
            });
        }
        assert!(!check(&grant, &record, &manager, Some(Scope::Tree), true));
        let _ = std::fs::remove_dir_all(directory);
    }
}

#[cfg(test)]
mod completion_tests {
    use super::*;
    #[test]
    fn exact_physical_marker_and_consumed_grant_allow_idempotent_rotation_continuation() {
        let root = std::env::temp_dir().join(format!("hh-completion-{}", attachments::new_id()));
        attachments::private_directory(&root).unwrap();
        let path = root.join("config.bin");
        let directory = root.join("runtime").join("attachments");
        let mut descriptor = crate::config_store::new_descriptor();
        descriptor.memory_kib = 8 * 1024;
        descriptor.iterations = 1;
        crate::config_store::save_encrypted_with_descriptor(
            &path,
            &Config::default(),
            b"dummy-password",
            &descriptor,
        )
        .unwrap();
        let manager = attachments::inspect_process(std::process::id()).unwrap();
        let target = ProcessIdentity {
            pid: 42,
            birth: 99,
            executable: "already-exited-fixture".into(),
            executable_sha256: "12".repeat(32),
            owner: manager.owner.clone(),
        };
        let record = attachments::create_record(
            &directory,
            attachments::Spec {
                exec_epoch: 0,
                current_target: None,
                id: attachments::new_id(),
                target: target.clone(),
                scope: Scope::Tree,
                backend: Backend::Gum,
                policy_digest: "ab".repeat(32),
                capabilities: Default::default(),
                recovery: None,
            },
        )
        .unwrap();
        let state = attachments::attachment_directory(&directory, &record.spec.id).unwrap();
        let sessions = SessionRegistry::default();
        let challenge = sessions
            .begin_auth(
                record.session_id.clone(),
                manager.executable.clone(),
                [9; 32],
            )
            .unwrap();
        let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
        let session = sessions
            .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(60))
            .unwrap();
        assert!(sessions.activate(&record.session_id, &session.token, manager.pid));
        assert!(sessions.retain_engine_manager(
            &record.session_id,
            &session.token,
            manager.pid,
            manager.birth
        ));
        let outcome = attachments::Outcome {
            phase: attachments::Phase::Detaching,
            members: vec![],
            manager: Some(manager.clone()),
            manager_endpoint: None,
            compatibility_reasons: vec![],
        };
        attachments::update_record(&state, &outcome).unwrap();
        let request = attachments::Request {
            schema_version: 1,
            id: attachments::new_id(),
            instance_id: attachments::instance_id(&path, &descriptor),
            created_at_ms: unix_timestamp_ms(),
            action: Action::Detach {
                exec_epoch: 0,
                attachment_id: record.spec.id.clone(),
                target,
                policy_digest: "ab".repeat(32),
                recovery: None,
            },
        };
        let grant = attachments::authorize(
            &directory,
            &path,
            b"dummy-password",
            &descriptor,
            request.clone(),
            unix_timestamp_ms(),
        )
        .unwrap();
        let unused = attachments::authorize(
            &directory,
            &path,
            b"dummy-password",
            &descriptor,
            request,
            unix_timestamp_ms(),
        )
        .unwrap();
        attachments::consume_authorization(&directory, &grant).unwrap();
        let service = ControlService::new(
            sessions.clone(),
            ConnectionRegistry::default(),
            "test-ca".into(),
            AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        )
        .with_attachment_directory(directory.clone());
        assert!(matches!(
            service.complete_attachment(
                grant.clone(),
                record.session_id.clone(),
                session.token.clone(),
                Some(manager.pid)
            ),
            ControlResponse::Error { .. }
        ));
        for phase in [
            attachments::Phase::Active,
            attachments::Phase::Draining,
            attachments::Phase::DetachedResident,
        ] {
            let mut unproven = outcome.clone();
            unproven.phase = phase;
            unproven.compatibility_reasons =
                vec!["physical_native_modules_absent_pending_session_revocation".into()];
            attachments::update_record(&state, &unproven).unwrap();
            assert!(matches!(
                service.complete_attachment(
                    grant.clone(),
                    record.session_id.clone(),
                    session.token.clone(),
                    Some(manager.pid)
                ),
                ControlResponse::Error { .. }
            ));
        }
        let mut proven = outcome;
        proven.phase = attachments::Phase::CleanupPending;
        proven.compatibility_reasons =
            vec!["physical_native_modules_absent_pending_session_revocation".into()];
        attachments::update_record(&state, &proven).unwrap();
        assert!(matches!(
            service.complete_attachment(
                unused,
                record.session_id.clone(),
                session.token.clone(),
                Some(manager.pid)
            ),
            ControlResponse::Error { .. }
        ));
        let mut next = descriptor;
        next.config_id[0] ^= 1;
        next.salt[0] ^= 1;
        crate::config_store::save_encrypted_with_descriptor(
            &path,
            &Config::default(),
            b"new-password",
            &next,
        )
        .unwrap();
        assert!(matches!(
            service.complete_attachment(
                grant.clone(),
                record.session_id.clone(),
                session.token.clone(),
                Some(manager.pid)
            ),
            ControlResponse::Ok
        ));
        assert!(!sessions.authenticate_control(&record.session_id, &session.token));
        assert!(matches!(
            service.complete_attachment(
                grant.clone(),
                record.session_id.clone(),
                session.token.clone(),
                Some(manager.pid)
            ),
            ControlResponse::Ok
        ));
        assert!(matches!(
            service.complete_attachment(
                grant.clone(),
                record.session_id.clone(),
                "wrong-token".into(),
                Some(manager.pid)
            ),
            ControlResponse::Error { .. }
        ));
        let mut altered = grant;
        altered.expires_at_ms += 1;
        assert!(matches!(
            service.complete_attachment(
                altered,
                record.session_id,
                session.token,
                Some(manager.pid)
            ),
            ControlResponse::Error { .. }
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod cleanup_recovery_tests {
    use super::*;
    #[test]
    fn completed_manager_fixture() {
        let Some(root) = std::env::var_os("HYPERHUB_COMPLETION_FIXTURE") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let directory = root.join("runtime").join("attachments");
        let grant: Authorization = serde_json::from_slice(
            &attachments::read_private_file(&root.join("grant.json"), 1024 * 1024).unwrap(),
        )
        .unwrap();
        let manager = ProcessIdentity {
            pid: std::process::id(),
            birth: attachments::process_birth(std::process::id()).unwrap(),
            executable: std::env::current_exe().unwrap().display().to_string(),
            executable_sha256: grant.executor_sha256.clone(),
            owner: std::env::var("HYPERHUB_COMPLETION_FIXTURE_OWNER").unwrap(),
        };
        crate::config_store::save_durable_private_bytes(
            &root.join("claimant.json"),
            &serde_json::to_vec(&attachments::manager_operation_claimant().unwrap()).unwrap(),
        )
        .unwrap();
        crate::config_store::save_durable_private_bytes(
            &root.join("manager.json"),
            &serde_json::to_vec(&manager).unwrap(),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !root.join("trusted-core-accepted").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "Core did not accept fixture completion"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[tokio::test]
    async fn fresh_cleanup_after_commit_ack_loss_and_manager_death_never_revives_session() {
        let root =
            std::env::temp_dir().join(format!("hh-completed-recovery-{}", attachments::new_id()));
        attachments::private_directory(&root).unwrap();
        let path = root.join("config.bin");
        let directory = root.join("runtime").join("attachments");
        let mut descriptor = crate::config_store::new_descriptor();
        descriptor.memory_kib = 8 * 1024;
        descriptor.iterations = 1;
        crate::config_store::save_encrypted_with_descriptor(
            &path,
            &Config::default(),
            b"dummy-password",
            &descriptor,
        )
        .unwrap();
        let manager = attachments::inspect_process(std::process::id()).unwrap();
        let target = manager.clone();
        let policy = attachments::policy_digest(&Config::default()).unwrap();
        let record = attachments::create_record(
            &directory,
            attachments::Spec {
                exec_epoch: 0,
                current_target: None,
                id: attachments::new_id(),
                target: target.clone(),
                scope: Scope::Tree,
                backend: Backend::Gum,
                policy_digest: policy.clone(),
                capabilities: attachments::dynamic_capabilities(&Config::default(), Backend::Gum),
                recovery: None,
            },
        )
        .unwrap();
        let approve = |action: Action| {
            attachments::authorize(
                &directory,
                &path,
                b"dummy-password",
                &descriptor,
                attachments::Request {
                    schema_version: 1,
                    id: attachments::new_id(),
                    instance_id: attachments::instance_id(&path, &descriptor),
                    created_at_ms: unix_timestamp_ms(),
                    action,
                },
                unix_timestamp_ms(),
            )
            .unwrap()
        };
        let mut old = approve(Action::Detach {
            exec_epoch: 0,
            attachment_id: record.spec.id.clone(),
            target: target.clone(),
            policy_digest: policy.clone(),
            recovery: None,
        });
        attachments::create_private_file(
            &root.join("grant.json"),
            &serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "control::attachment_control::cleanup_recovery_tests::completed_manager_fixture",
                "--nocapture",
            ])
            .env("HYPERHUB_COMPLETION_FIXTURE", &root)
            .env("HYPERHUB_COMPLETION_FIXTURE_OWNER", &manager.owner)
            .env("HYPERHUB_COMPLETION_FIXTURE_SESSION", &record.session_id)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let mut accepted = false;
        let status = loop {
            if !accepted && root.join("manager.json").exists() {
                let actual: ProcessIdentity = serde_json::from_slice(
                    &attachments::read_private_file(&root.join("manager.json"), 64 * 1024).unwrap(),
                )
                .unwrap();
                assert_eq!(actual.pid, child.id());
                assert_eq!(attachments::process_birth(actual.pid), Some(actual.birth));
                assert_eq!(actual.executable_sha256, manager.executable_sha256);
                let claimant: hyperhub_runtime::attachment::ManagerClaimant =
                    serde_json::from_slice(
                        &attachments::read_private_file(&root.join("claimant.json"), 64 * 1024)
                            .unwrap(),
                    )
                    .unwrap();
                assert_eq!((claimant.pid, claimant.birth), (actual.pid, actual.birth));
                old = attachments::authorize_claimant_bound(
                    &directory,
                    &path,
                    b"dummy-password",
                    &descriptor,
                    old.request.clone(),
                    unix_timestamp_ms(),
                    None,
                    actual.executable_sha256.clone(),
                    None,
                    claimant,
                )
                .unwrap();
                attachments::consume_for_claimant(&directory, &old, &actual).unwrap();
                attachments::record_completion_receipt(
                    &directory,
                    &old,
                    &record.session_id,
                    "dummy-completion-token",
                    &actual,
                )
                .unwrap();
                attachments::create_private_file(&root.join("trusted-core-accepted"), b"accepted")
                    .unwrap();
                accepted = true;
            }
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("completion fixture did not finish");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert!(status.success());
        let vanished: ProcessIdentity = serde_json::from_slice(
            &attachments::read_private_file(&root.join("manager.json"), 64 * 1024).unwrap(),
        )
        .unwrap();
        assert_ne!(vanished.pid, manager.pid);
        assert!(
            attachments::process_incarnation_exited(vanished.pid, vanished.birth),
            "manager must have exited even while Child retains its Windows process handle"
        );
        let state = attachments::attachment_directory(&directory, &record.spec.id).unwrap();
        let outcome = attachments::Outcome {
            phase: attachments::Phase::CleanupPending,
            members: vec![],
            manager: Some(vanished.clone()),
            manager_endpoint: None,
            compatibility_reasons: vec![
                "physical_native_modules_absent_pending_session_revocation".into(),
            ],
        };
        attachments::update_record(&state, &outcome).unwrap();
        let sessions = SessionRegistry::default();
        let service = ControlService::new(
            sessions.clone(),
            ConnectionRegistry::default(),
            "test-ca".into(),
            AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        )
        .with_attachment_directory(directory.clone());
        let binding = attachments::RecoveryBinding {
            manager: vanished.clone(),
            context_digest: "cd".repeat(32),
        };
        let fresh = approve(Action::Detach {
            exec_epoch: 0,
            attachment_id: record.spec.id.clone(),
            target: target.clone(),
            policy_digest: policy.clone(),
            recovery: Some(binding.clone()),
        });
        attachments::consume_authorization(&directory, &fresh).unwrap();
        assert!(matches!(
            service
                .recover_attachment(
                    fresh.clone(),
                    record.session_id.clone(),
                    "wrong-token".into(),
                    manager.clone(),
                    vec![],
                    Some(manager.pid)
                )
                .await,
            ControlResponse::Error { .. }
        ));
        assert!(matches!(
            service
                .recover_attachment(
                    fresh.clone(),
                    record.session_id.clone(),
                    "dummy-completion-token".into(),
                    vanished.clone(),
                    vec![],
                    Some(manager.pid)
                )
                .await,
            ControlResponse::Error { .. }
        ));
        let mut wrong_target = target.clone();
        wrong_target.birth += 1;
        let bad = approve(Action::Detach {
            exec_epoch: 0,
            attachment_id: record.spec.id.clone(),
            target: wrong_target,
            policy_digest: policy.clone(),
            recovery: Some(binding.clone()),
        });
        attachments::consume_authorization(&directory, &bad).unwrap();
        assert!(matches!(
            service
                .recover_attachment(
                    bad,
                    record.session_id.clone(),
                    "dummy-completion-token".into(),
                    manager.clone(),
                    vec![],
                    Some(manager.pid)
                )
                .await,
            ControlResponse::Error { .. }
        ));
        let mut attach = record.spec.clone();
        attach.recovery = Some(binding);
        let attach = approve(Action::Attach { spec: attach });
        attachments::consume_authorization(&directory, &attach).unwrap();
        assert!(matches!(
            service
                .recover_attachment(
                    attach,
                    record.session_id.clone(),
                    "dummy-completion-token".into(),
                    manager.clone(),
                    vec![],
                    Some(manager.pid)
                )
                .await,
            ControlResponse::Error { .. }
        ));
        assert!(matches!(
            service
                .recover_attachment(
                    fresh.clone(),
                    record.session_id.clone(),
                    "dummy-completion-token".into(),
                    manager.clone(),
                    vec![],
                    Some(manager.pid)
                )
                .await,
            ControlResponse::Ok
        ));
        assert!(
            sessions.snapshot().is_empty(),
            "cleanup recreated a retired session"
        );
        let mut owned = outcome;
        owned.manager = Some(manager.clone());
        attachments::update_record(&state, &owned).unwrap();
        assert!(matches!(
            service.complete_attachment(
                fresh.clone(),
                record.session_id.clone(),
                "dummy-completion-token".into(),
                Some(manager.pid)
            ),
            ControlResponse::Ok
        ));
        assert!(sessions.snapshot().is_empty());
        assert!(matches!(
            service.complete_attachment(
                fresh,
                record.session_id,
                "dummy-completion-token".into(),
                Some(manager.pid)
            ),
            ControlResponse::Ok
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}

impl ControlService {
    pub(super) fn cancel_owned_attachment_keeper(
        &self,
        session_id: String,
        token: String,
        attachment_id: String,
        secret: String,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| -> Result<(), String> {
            let mut handoffs = self
                .owned_attachment_handoffs
                .lock()
                .map_err(|_| "keeper handoff registry unavailable")?;
            let Some(handoff) = handoffs.get(&attachment_id) else {
                return Ok(());
            };
            if peer_pid != Some(handoff.launcher.pid)
                || crate::session::process_start_time(handoff.launcher.pid)
                    != Some(handoff.launcher.birth)
                || handoff.session_id != session_id
                || !self.sessions.authenticate_control(&session_id, &token)
                || secret.len() != 64
                || !crate::session::constant_time_eq(
                    handoff.secret_digest.as_bytes(),
                    attachments::digest(secret.as_bytes()).as_bytes(),
                )
            {
                return Err(
                    "only the original launcher may cancel this exact keeper handoff".into(),
                );
            }
            let handoff = handoffs.remove(&attachment_id).unwrap();
            if let Some(keeper) = handoff.claimed {
                self.sessions
                    .release_engine_manager(&session_id, keeper.pid, keeper.birth);
            }
            Ok(())
        })();
        match result {
            Ok(()) => ControlResponse::Ok,
            Err(message) => ControlResponse::Error { message },
        }
    }
}

#[cfg(test)]
mod approval_enrollment_tests {
    use super::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn password_enrollment_uses_only_explicit_private_config_and_same_connection() {
        let root =
            std::env::temp_dir().join(format!("hh-private-enroll-{}", attachments::new_id()));
        attachments::private_directory(&root).unwrap();
        let config = root.join("private-config.bin");
        let directory = root.join("runtime").join("attachments");
        let mut descriptor = crate::config_store::new_descriptor();
        descriptor.memory_kib = 8 * 1024;
        descriptor.iterations = 1;
        crate::config_store::save_encrypted_with_descriptor(
            &config,
            &Config::default(),
            b"dummy-private-password",
            &descriptor,
        )
        .unwrap();
        let unlocked =
            crate::config_store::load_encrypted(&config, b"dummy-private-password").unwrap();
        let service = ControlService::new(
            SessionRegistry::default(),
            ConnectionRegistry::default(),
            "test-ca".into(),
            AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        )
        .with_attachment_directory(directory.clone())
        .with_approval_anchor(&config, &descriptor, unlocked.approval_public_key)
        .unwrap();
        assert_eq!(
            attachments::approval_status(&directory).unwrap().state,
            "unenrolled"
        );
        let control_home = root.join("control");
        attachments::private_directory(&control_home).unwrap();
        let endpoint = instance_control_endpoint(&control_home);
        let serve_endpoint = endpoint.clone();
        let server = tokio::spawn(async move { run_control_server(serve_endpoint, service).await });
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if server.is_finished() {
                panic!("private Core exited before readiness: {:?}", server.await);
            }
            if trusted_control_request_for_config(
                &endpoint,
                &config,
                &ControlRequest::GetApprovalTrust,
            )
            .await
            .is_ok()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "private Core did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            password_approval_enrollment(&endpoint, &config, b"wrong-dummy-password")
                .await
                .is_err()
        );
        assert!(attachments::approval_trust(&directory)
            .unwrap()
            .authority
            .is_none());
        let copied = root.join("copied-config.bin");
        std::fs::copy(&config, &copied).unwrap();
        assert!(
            password_approval_enrollment(&endpoint, &copied, b"dummy-private-password")
                .await
                .unwrap_err()
                .contains("another configuration instance")
        );
        // A nonce issued on A cannot authenticate B, even for the same CLI PID.
        let (mut first, _) = trusted_control_stream_for_config(&endpoint, &config)
            .await
            .unwrap();
        write_frame(&mut first, &ControlRequest::BeginApprovalEnrollment)
            .await
            .unwrap();
        let ControlResponse::ApprovalEnrollmentChallenge {
            challenge: first_challenge,
        } = read_frame(&mut first).await.unwrap()
        else {
            panic!("first challenge missing")
        };
        let (mut second, _) = trusted_control_stream_for_config(&endpoint, &config)
            .await
            .unwrap();
        write_frame(&mut second, &ControlRequest::BeginApprovalEnrollment)
            .await
            .unwrap();
        let ControlResponse::ApprovalEnrollmentChallenge {
            challenge: second_challenge,
        } = read_frame(&mut second).await.unwrap()
        else {
            panic!("second challenge missing")
        };
        write_approval_password(
            &mut second,
            &first_challenge.nonce,
            b"dummy-private-password",
        )
        .await
        .unwrap();
        assert!(matches!(
            read_frame::<_, ControlResponse>(&mut second).await.unwrap(),
            ControlResponse::Error { .. }
        ));
        assert!(attachments::approval_trust(&directory)
            .unwrap()
            .authority
            .is_none());
        assert!(!attachments::approval_challenge_pending(
            &directory,
            &second_challenge.nonce
        ));
        assert!(attachments::approval_challenge_pending(
            &directory,
            &first_challenge.nonce
        ));
        drop(first);
        let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while attachments::approval_challenge_pending(&directory, &first_challenge.nonce) {
            assert!(
                std::time::Instant::now() < cleanup_deadline,
                "disconnected enrollment challenge was retained"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        password_approval_enrollment(&endpoint, &config, b"dummy-private-password")
            .await
            .unwrap();
        assert_eq!(
            attachments::trusted_authority(&directory)
                .unwrap()
                .public_key,
            unlocked.approval_public_key.unwrap()
        );
        server.abort();
        let _ = server.await;
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn attachment_directory_without_explicit_config_cannot_begin_password_enrollment() {
        let directory =
            std::env::temp_dir().join(format!("hh-unbound-enroll-{}", attachments::new_id()));
        let service = ControlService::new(
            SessionRegistry::default(),
            ConnectionRegistry::default(),
            "test-ca".into(),
            AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        )
        .with_attachment_directory(directory);
        assert!(
            matches!(service.approval_control(true,Some(std::process::id())),ControlResponse::Error{message} if message.contains("configuration path is not bound"))
        );
    }
}

impl ControlService {
    pub(super) fn report_attachment_exec(
        &self,
        attachment_id: String,
        session_id: String,
        token: String,
        manager: ProcessIdentity,
        previous: ProcessIdentity,
        current: ProcessIdentity,
        transition_nonce: [u8; 32],
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            let base = self
                .attachment_directory
                .as_ref()
                .ok_or("attachment exec reporting is disabled")?;
            if peer_pid != Some(manager.pid)
                || self
                    .sessions
                    .engine_manager_start(&session_id, &token, manager.pid)
                    != Some(manager.birth)
            {
                return Err("exec reporting requires the current OS-authenticated manager".into());
            }
            attachments::verify_process(&manager)?;
            attachments::verify_process(&current)?;
            if !previous.same_incarnation(&current)
                || !self
                    .sessions
                    .authenticate_member(&session_id, &token, current.pid)
                || !self
                    .sessions
                    .member_birth_matches(&session_id, &token, current.pid)
            {
                return Err("exec report changes a session member incarnation".into());
            }
            let directory = attachments::attachment_directory(base, &attachment_id)?;
            let record = attachments::load_record(&directory)?;
            if record.session_id != session_id
                || record.manager.as_ref() != Some(&manager)
                || !record.spec.target.same_incarnation(&current)
            {
                return Err(
                    "root exec report does not match the original attachment and actual manager"
                        .into(),
                );
            }
            let state =
                self.commit_root_exec(&attachment_id, &previous, &current, transition_nonce)?;
            Ok(ControlResponse::AttachmentImage { state })
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
}

impl ControlService {
    pub(super) fn initialize_owned_attachment_image(
        &self,
        bootstrap: hyperhub_runtime::attachment::Bootstrap,
        manager: ProcessIdentity,
        target: ProcessIdentity,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            let base = self
                .attachment_directory
                .as_ref()
                .ok_or("attachment image lifecycle is disabled")?;
            if peer_pid != Some(manager.pid) {
                return Err("owned image initialization requires actual launcher peer".into());
            }
            attachments::verify_launch_origin(&manager)?;
            attachments::verify_process(&target)?;
            if !process_ancestors(target.pid).contains(&manager.pid)
                || !self.sessions.authenticate_member(
                    &bootstrap.session_id,
                    &bootstrap.token,
                    target.pid,
                )
                || !self.sessions.member_birth_matches(
                    &bootstrap.session_id,
                    &bootstrap.token,
                    target.pid,
                )
            {
                return Err(
                    "owned image initialization is not the actual activated launcher child".into(),
                );
            }
            let record = attachments::load_record(&attachments::attachment_directory(
                base,
                &bootstrap.attachment_id,
            )?)?;
            if record.origin != attachments::Origin::Run
                || record.manager.as_ref() != Some(&manager)
                || record.spec.target != target
                || record.session_id != bootstrap.session_id
                || bootstrap.approval_root_identity.as_ref() != Some(&target.root_image_identity())
                || record.host_binding.as_deref()
                    != Some(&bootstrap.approval_binding().map_err(|e| e.to_string())?)
            {
                return Err(
                    "owned image initialization changed the original startup binding".into(),
                );
            }
            attachments::ManagerExecutionProfile::from_bootstrap(
                &bootstrap,
                attachments::Origin::Run,
            )?
            .validate_record(&record)?;
            attachments::initialize_root_image(
                base,
                &record.spec,
                &record.session_id,
                &bootstrap.approval_instance_id,
                record.host_binding.as_deref().unwrap(),
            )?;
            attachments::verify_root_image_bootstrap(base, &bootstrap)?;
            Ok(ControlResponse::AttachmentImage {
                state: attachments::root_image_state(base, &record.spec.id)?,
            })
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    pub(super) fn attachment_image_view(
        &self,
        attachment_id: String,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            let base = self
                .attachment_directory
                .as_ref()
                .ok_or("attachment image lifecycle is disabled")?;
            if let Ok(state) = attachments::root_image_state(base, &attachment_id) {
                return Ok(ControlResponse::AttachmentImage { state });
            }
            let record = attachments::load_record(&attachments::attachment_directory(
                base,
                &attachment_id,
            )?)?;
            let manager = record
                .manager
                .as_ref()
                .ok_or("root image has no live controller")?;
            attachments::verify_process(manager)?;
            if peer_pid == Some(manager.pid) {
                return Err("root_image_restore_required: cold Core cannot synchronously query its requesting manager".into());
            }
            let endpoint = record
                .manager_endpoint
                .as_ref()
                .ok_or("root image controller has no private endpoint")?;
            let response = hyperhub_runtime::attachment::exchange_raw_for_process(
                endpoint,
                &serde_json::json!({"query":"root_image","attachment_id":attachment_id}),
                manager.pid,
            )
            .map_err(|e| e.to_string())?;
            if response
                .get("attachment_id")
                .and_then(serde_json::Value::as_str)
                != Some(attachment_id.as_str())
                || !response
                    .get("error")
                    .is_some_and(serde_json::Value::is_null)
            {
                return Err("actual manager could not prove its retained root image epoch".into());
            }
            let state: hyperhub_runtime::attachment::RootImageState = serde_json::from_value(
                response
                    .get("root_image")
                    .cloned()
                    .ok_or("actual manager omitted retained root image")?,
            )
            .map_err(|e| e.to_string())?;
            let profile = attachments::manager_profile_for_record(&record)?;
            let config = self
                .approval_config_path
                .as_ref()
                .ok_or("root image instance path is not bound")?;
            let descriptor =
                crate::config_store::read_descriptor(config).map_err(|e| e.to_string())?;
            attachments::adopt_manager_root_image(
                base,
                &record,
                &attachments::instance_id(config, &descriptor),
                state.clone(),
                &profile,
            )?;
            Ok(ControlResponse::AttachmentImage { state })
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    pub(super) fn attachment_profile_view(
        &self,
        bootstrap: hyperhub_runtime::attachment::Bootstrap,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        if let ControlResponse::Error { message } =
            self.attachment_image_view(bootstrap.attachment_id.clone(), peer_pid)
        {
            return ControlResponse::Error { message };
        }
        let result = (|| {
            let directory = self
                .attachment_directory
                .as_ref()
                .ok_or("attachment profiles disabled")?;
            attachments::verify_root_image_bootstrap(directory, &bootstrap)?;
            let profile = attachments::root_image_profile(directory, &bootstrap.attachment_id)?;
            let record = attachments::load_record(&attachments::attachment_directory(
                directory,
                &bootstrap.attachment_id,
            )?)?;
            profile.validate_record(&record)?;
            Ok(ControlResponse::AttachmentProfile { profile })
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
}

impl ControlService {
    pub(super) fn attachment_preparation(
        &self,
        authorization: Authorization,
        bootstrap: hyperhub_runtime::attachment::Bootstrap,
        manager: ProcessIdentity,
        accepted: hyperhub_runtime::attachment::AcceptedOperationCertificate,
        proof: attachments::PreparationProof,
        peer: Option<u32>,
    ) -> crate::session::ControlResponse {
        use crate::session::ControlResponse;
        let result = (|| -> Result<ControlResponse, String> {
            let base = self
                .attachment_directory
                .as_ref()
                .ok_or("attachment lifecycle is disabled")?;
            if peer != Some(manager.pid) {
                return Err("preparation requires the exact OS-authenticated manager".into());
            }
            attachments::verify_process(&manager)?;
            if manager.executable_sha256 != authorization.executor_sha256 {
                return Err("preparation manager is not the approved executor".into());
            }
            attachments::verify_consumed_continuation(base, &authorization, manager.pid)?;
            let value = attachments::verify_preparation(&proof, &accepted)?;
            let expected = attachments::operation_scope_for_authorization(
                &authorization,
                &bootstrap,
                value.scope.root_image.clone(),
            )?;
            if value.scope != expected
                || value.scope.claimant.pid != manager.pid
                || value.scope.claimant.birth != manager.birth
            {
                return Err(
                    "preparation step differs from original manager and approved execution".into(),
                );
            }
            if value.step == attachments::PreparationStep::BeginMutation {
                attachments::verify_authorization(base, &authorization)?;
                attachments::verify_process(authorization.request.action.target())?;
                attachments::verify_root_image_scope(base, &authorization.request.action)?;
            }
            let receipt = attachments::apply_preparation(base, &proof, &accepted, || {
                self.sessions.revoke(&bootstrap.session_id);
            })?;
            match receipt {
                None => Ok(ControlResponse::Ok),
                Some(receipt) => {
                    attachments::save_abort_receipt(base, &receipt)?;
                    Ok(ControlResponse::AttachmentPreparationAborted { receipt })
                }
            }
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
}
