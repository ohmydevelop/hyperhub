//! Runtime proposals and the administrator-only execution handoff.
mod manager_bootstrap;
mod owned_keeper;
mod recovery;
mod root_enrollment;
#[cfg(target_os = "linux")]
mod run_worker;
mod stale_requests;
mod terminal_replan;
use hyperhub_core::attachments::{self, Action, Backend, Execution, Phase, Request, Scope, Spec};
use hyperhub_core::config_store::{self, ConfigKeyring};
use hyperhub_core::control::{control_request, discovery_control_endpoint};
use hyperhub_core::session::{session_proof, unix_timestamp_ms, ControlRequest, ControlResponse};
pub(crate) use owned_keeper::{spawn_owned_run_keeper, OwnedRunKeeperBarrier, ENTRY_RELEASE};
#[cfg(target_os = "linux")]
pub(crate) use run_worker::{notify_owned_run_root_exit, run_worker, spawn_worker};
use serde_json::json;
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Attach {
        pid: u32,
        scope: Scope,
        backend: Backend,
    },
    Detach {
        id: String,
    },
    Manager {
        directory: PathBuf,
    },
    OwnedKeeper {
        directory: PathBuf,
    },
}
pub(crate) fn parse(name: &str, args: &[OsString]) -> Result<Command, String> {
    if name == "owned-run-keeper" {
        return match args {
            [path] => Ok(Command::OwnedKeeper {
                directory: path.into(),
            }),
            _ => Err("owned-run-keeper requires one private handoff directory".into()),
        };
    }
    if name == "attachment-manager" {
        return match args {
            [path] => Ok(Command::Manager {
                directory: path.into(),
            }),
            _ => Err("attachment-manager requires one sealed execution directory".into()),
        };
    }
    if name == "detach" {
        return match args {
            [id] if attachments::valid_id(&id.to_string_lossy()) => Ok(Command::Detach {
                id: id.to_string_lossy().into_owned(),
            }),
            _ => Err("usage: hyperhub detach <attachment-id>".into()),
        };
    }
    let pid = args
        .first()
        .and_then(|p| p.to_str())
        .and_then(|p| p.parse::<u32>().ok())
        .filter(|p| *p > 0)
        .ok_or("usage: hyperhub attach <pid> [--scope process|tree] [--backend auto|ptrace|gum]")?;
    let mut scope = Scope::Tree;
    let mut backend = Backend::Auto;
    let mut i = 1;
    while i < args.len() {
        let name = args[i].to_string_lossy();
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("{name} requires a value"))?
            .to_string_lossy();
        match (name.as_ref(), value.as_ref()) {
            ("--scope", "process") => scope = Scope::Process,
            ("--scope", "tree") => scope = Scope::Tree,
            ("--backend", "auto") => backend = Backend::Auto,
            ("--backend", "ptrace") => backend = Backend::Ptrace,
            ("--backend", "gum") => backend = Backend::Gum,
            _ => return Err(format!("invalid attachment option {name} {value}")),
        }
        i += 2;
    }
    Ok(Command::Attach {
        pid,
        scope,
        backend,
    })
}
pub(crate) fn run(command: Command) -> Result<i32, String> {
    match command {
        Command::Attach {
            pid,
            scope,
            backend,
        } => propose_attach(pid, scope, backend),
        Command::Detach { id } => propose_detach(&id),
        Command::Manager { directory } => run_manager(&directory),
        Command::OwnedKeeper { directory } => owned_keeper::run_keeper(&directory),
    }
}
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}
fn current_policy() -> Result<(PathBuf, config_store::KdfDescriptor, String), String> {
    let path = config_store::default_config_path().map_err(|e| e.to_string())?;
    let descriptor = config_store::read_descriptor(&path).map_err(|e| e.to_string())?;
    let value: serde_json::Value = serde_json::from_slice(
        &config_store::read_redacted_json(&path).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok((path, descriptor, attachments::policy_digest_view(&value)?))
}
fn live_status() -> Result<ControlResponse, String> {
    runtime()?
        .block_on(control_request(
            &discovery_control_endpoint(),
            &ControlRequest::GetStatus,
        ))
        .map_err(|e| format!("HyperHub Serve must be running for this operation: {e}"))
}
fn trusted_exec_epoch(id: &str) -> Result<u64, String> {
    match runtime()?
        .block_on(hyperhub_core::control::trusted_control_request(
            &discovery_control_endpoint(),
            &ControlRequest::GetAttachmentImage {
                attachment_id: id.into(),
            },
        ))
        .map_err(|e| e.to_string())?
    {
        ControlResponse::AttachmentImage { state } => Ok(state.exec_epoch),
        ControlResponse::Error { message } => Err(message),
        _ => Err("Core omitted trusted executable epoch".into()),
    }
}
fn proven_record_origin(record: &attachments::Record) -> Result<attachments::Origin, String> {
    let profile = if record
        .manager
        .as_ref()
        .is_some_and(|manager| attachments::process_birth(manager.pid) == Some(manager.birth))
    {
        attachments::manager_profile_for_record(record)?
    } else {
        // The envelope is only a candidate. Current Core memory must prove its
        // immutable binding; API/runtime-key access is not an origin authority.
        let directory =
            attachments::attachment_directory(&attachments::directory()?, &record.spec.id)?;
        let execution =
            attachments::load_execution(&directory, &crate::password::load_runtime_keyring()?)?;
        match runtime()?
            .block_on(hyperhub_core::control::trusted_control_request(
                &discovery_control_endpoint(),
                &ControlRequest::GetAttachmentProfile {
                    bootstrap: execution.bootstrap,
                },
            ))
            .map_err(|e| e.to_string())?
        {
            ControlResponse::AttachmentProfile { profile } => profile,
            ControlResponse::Error { message } => return Err(message),
            _ => return Err("Core omitted proven immutable execution profile".into()),
        }
    };
    profile.validate_record(record)?;
    Ok(profile.origin)
}
fn proven_action_origin(id: &str) -> Result<attachments::Origin, String> {
    let directory = attachments::attachment_directory(&attachments::directory()?, id)?;
    if !directory.join("record.json").exists() {
        return Ok(attachments::Origin::Attach);
    }
    proven_record_origin(&attachments::load_record(&directory)?)
}
fn propose_attach(pid: u32, scope: Scope, backend: Backend) -> Result<i32, String> {
    let target = attachments::inspect_process(pid)?;
    let (path, descriptor, policy_digest) = current_policy()?;
    let selected = crate::platform::target_backend(
        Path::new(&target.executable),
        match backend {
            Backend::Auto => None,
            Backend::Ptrace => Some("ptrace"),
            Backend::Gum => Some("gum"),
        },
    )?;
    let backend = match selected {
        crate::platform::TargetBackend::GumInterceptor => Backend::Gum,
        #[cfg(target_os = "linux")]
        crate::platform::TargetBackend::PtraceSyscall => Backend::Ptrace,
    };
    crate::platform::validate_attachment_backend(pid, scope, backend)?;
    let value = serde_json::from_slice(
        &config_store::read_redacted_json(&path).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let config = hyperhub_core::config_document::ConfigDocument::from_value(value)?;
    let directory = attachments::directory()?;
    let records = attachments::records(&directory)?;
    let recoverable = records.iter().find(|r| {
        r.spec.target.same_incarnation(&target)
            && matches!(r.phase, Phase::Degraded | Phase::CleanupPending)
            && r.manager
                .as_ref()
                .is_some_and(|m| attachments::process_birth(m.pid) != Some(m.birth))
    });
    let recovery = recoverable.map(recovery::binding).transpose()?.flatten();
    if recoverable.is_none() {
        crate::platform::inspect_attachment_target(pid)?;
    }
    let resident = records.iter().find(|r| {
        r.spec.target.same_incarnation(&target)
            && matches!(r.phase, Phase::DetachedResident | Phase::Draining)
    });
    let origin = resident
        .or(recoverable)
        .map(proven_record_origin)
        .transpose()?
        .unwrap_or(attachments::Origin::Attach);
    if origin == attachments::Origin::Attach {
        crate::platform::validate_external_runtime(pid)?;
    }
    let capabilities = attachments::dynamic_capabilities_for_origin(&config, backend, origin);
    capabilities.require_supported()?;
    if records
        .iter()
        .any(|r| r.spec.target.same_incarnation(&target) && r.phase.is_attached())
    {
        return Err("target already has an active attachment".into());
    }
    if records.iter().any(|r| {
        r.spec.target.same_incarnation(&target)
            && matches!(r.phase, Phase::Degraded | Phase::CleanupPending)
            && recoverable.is_none()
    }) {
        return Err("target has unresolved attachment state; inspect its attachment-id before recovery, no second agent was injected".into());
    }
    if let Some(record) = resident {
        if record.spec.scope != scope || record.spec.backend != backend {
            return Err("resident attachment scope/backend is incompatible; no second agent will be injected".into());
        }
    }
    let status = live_status()?;
    if let ControlResponse::Status { sessions, .. } = status {
        if resident.is_none()
            && recoverable.is_none()
            && sessions.iter().any(|session| {
                session.processes.iter().any(|p| p.pid == pid)
                    && !records.iter().any(|record| {
                        record.spec.target.same_incarnation(&target)
                            && record.session_id == session.session_id
                            && matches!(record.phase, Phase::Detached | Phase::Exited)
                    })
            })
        {
            return Err("target is already managed by a session without this reversible attachment record; legacy injection is incompatible".into());
        }
    } else {
        return Err("Serve did not return an attachment status".into());
    }
    if let Some(record) = recoverable {
        if record.spec.scope != scope || record.spec.backend != backend {
            return Err("recovery cannot change original scope or backend".into());
        }
    }
    let id = resident
        .or(recoverable)
        .map_or_else(attachments::new_id, |r| r.spec.id.clone());
    let request = Request {
        schema_version: 1,
        id: attachments::new_id(),
        instance_id: attachments::instance_id(&path, &descriptor),
        created_at_ms: unix_timestamp_ms(),
        action: Action::Attach {
            spec: Spec {
                exec_epoch: resident
                    .or(recoverable)
                    .map(|record| trusted_exec_epoch(&record.spec.id))
                    .transpose()?
                    .unwrap_or(0),
                current_target: resident
                    .or(recoverable)
                    .filter(|record| record.spec.target != target)
                    .map(|_| target.clone()),
                recovery,
                capabilities,
                id,
                target: resident
                    .or(recoverable)
                    .map(|record| record.spec.target.clone())
                    .unwrap_or(target),
                scope,
                backend,
                policy_digest,
            },
        },
    };
    save_proposal(&directory, &request)
}
fn propose_detach(id: &str) -> Result<i32, String> {
    let directory = attachments::directory()?;
    let record = attachments::load_record(&attachments::attachment_directory(&directory, id)?)?;
    if matches!(record.phase, Phase::Detached | Phase::Exited) {
        return Err("attachment is already detached or all of its targets have exited".into());
    }
    if record.phase == Phase::Failed {
        // Failed is a writable display phase. Only the original Core-signed
        // gate receipt can establish that approved rollback already completed.
        runtime()?.block_on(attachments::import_core_trust(
            &directory,
            &discovery_control_endpoint(),
        ))?;
        let execution = attachments::load_execution(
            &attachments::attachment_directory(&directory, id)?,
            &crate::password::load_runtime_keyring()?,
        )?;
        if attachments::verified_preparation_abort(&directory, &execution)? {
            println!(
                "{}",
                json!({"status":"already_detached","attachment_id":id,"phase":"failed","preparation_rollback":"verified"})
            );
            return Ok(0);
        }
    }
    let (path, descriptor, policy_digest) = current_policy()?;
    let recovery = recovery::binding(&record)?;
    let request = Request {
        schema_version: 1,
        id: attachments::new_id(),
        instance_id: attachments::instance_id(&path, &descriptor),
        created_at_ms: unix_timestamp_ms(),
        action: Action::Detach {
            exec_epoch: trusted_exec_epoch(id)?,
            attachment_id: id.into(),
            target: if attachments::process_birth(record.spec.target.pid)
                == Some(record.spec.target.birth)
            {
                attachments::inspect_process(record.spec.target.pid)?
            } else {
                record.effective_target().clone()
            },
            policy_digest,
            recovery,
        },
    };
    save_proposal(&directory, &request)
}
fn ensure_proposal(directory: &Path, request: &Request) -> Result<Request, String> {
    let _operation = attachments::OperationGuard::acquire(directory)?;
    if let Some(existing) = attachments::requests(directory)?
        .into_iter()
        .find(|r| same_intent(&r.action, &request.action) && r.instance_id == request.instance_id)
    {
        return Ok(existing);
    }
    attachments::save_request(directory, request)?;
    Ok(request.clone())
}
fn save_proposal(directory: &Path, request: &Request) -> Result<i32, String> {
    let request = ensure_proposal(directory, request)?;
    println!(
        "{}",
        json!({"status":"approval_required","request_id":request.id,"attachment_id":request.action.attachment_id(),"action":request.action})
    );
    Ok(0)
}
/// Returns None only when the existing configuration approval flow should run.
pub(crate) fn approve(
    request_id: Option<&str>,
    password_file: Option<&Path>,
    editor: Option<&Path>,
) -> Result<Option<i32>, String> {
    let directory = attachments::directory()?;
    let pending = attachments::requests(&directory)?;
    if let Some(id) = request_id {
        if let Some(error) = stale_requests::archived_error(&directory, id)? {
            return Err(error);
        }
    }
    if pending.is_empty() && request_id.is_none() {
        return Ok(None);
    }
    if editor.is_some() {
        if request_id.is_none() {
            return Ok(None);
        }
        return Err("runtime action approvals do not accept a configuration editor".into());
    }
    let (path, descriptor, policy_digest) = current_policy()?;
    let instance = attachments::instance_id(&path, &descriptor);
    let pending =
        stale_requests::filter_pending(&directory, &instance, &policy_digest, |request| {
            stale_requests::probe_epoch(&directory, request)
        })?;
    if pending.is_empty() && request_id.is_none() {
        return Ok(None);
    }
    if let Some(id) = request_id {
        if let Some(error) = stale_requests::archived_error(&directory, id)? {
            return Err(error);
        }
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("approve requires an interactive terminal for human runtime review".into());
    }
    let mut request_id = request_id.map(str::to_owned);
    if request_id.is_none() {
        let config_pending = path.with_extension("approval.json").exists()
            || path.with_extension("approval.bin").exists();
        if pending.len() == 1 && !config_pending {
            request_id = Some(pending[0].id.clone());
        } else {
            eprintln!("Pending runtime approvals:");
            for r in &pending {
                eprintln!(
                    "  {} {} PID {}",
                    r.id,
                    match r.action {
                        Action::Attach { .. } => "attach",
                        Action::Detach { .. } => "detach",
                    },
                    r.action.target().pid
                );
            }
            if config_pending {
                eprintln!("  config: pending configuration changes");
            }
            eprint!(
                "Select request id{}: ",
                if config_pending { " or config" } else { "" }
            );
            std::io::stderr().flush().map_err(|e| e.to_string())?;
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .map_err(|e| e.to_string())?;
            if answer.trim() == "config" && config_pending {
                return Ok(None);
            }
            request_id = Some(answer.trim().to_owned());
        }
    }
    let mut request = attachments::load_request(
        &directory,
        request_id.as_deref().ok_or("select a runtime approval")?,
    )?;
    let initial_replan = {
        let preview = attachments::OperationGuard::acquire(&directory)?;
        stale_requests::validate_selected(
            &directory,
            &request,
            &instance,
            &policy_digest,
            &preview,
            |request| stale_requests::probe_epoch(&directory, request),
        )?;
        terminal_replan::refresh(&mut request, &directory)?
    };
    let mut supersedes_request_id = initial_replan.superseded_request_id().map(str::to_owned);
    match &request.action {
        Action::Attach { spec } => {
            attachments::verify_process(spec.effective_target())?;
            crate::platform::validate_attachment_backend(
                spec.target.pid,
                spec.scope,
                spec.backend,
            )?;
        }
        Action::Detach {
            attachment_id,
            target,
            ..
        } => {
            let record = attachments::load_record(&attachments::attachment_directory(
                &directory,
                attachment_id,
            )?)?;
            if !record.spec.target.same_incarnation(target) {
                return Err("attachment identity changed before approval".into());
            }
            if attachments::process_birth(target.pid) == Some(target.birth) {
                attachments::verify_process(target)?;
            }
        }
    }
    let password = crate::password::acquire(password_file, false)?;
    let keyring = ConfigKeyring::derive(password.as_bytes(), descriptor.clone())
        .map_err(|e| e.to_string())?;
    let unlocked =
        config_store::load_encrypted_with_keyring(&path, &keyring).map_err(|e| e.to_string())?;
    if let Action::Attach { spec } = &request.action {
        let current = attachments::dynamic_capabilities_for_origin(
            &unlocked.config,
            spec.backend,
            proven_action_origin(&spec.id)?,
        );
        current.require_supported()?;
        if current != spec.capabilities {
            return Err("attachment capability report changed; submit a new proposal".into());
        }
    }
    if attachments::policy_digest(&unlocked.config)? != policy_digest {
        return Err("policy changed during administrator authentication".into());
    }
    eprintln!(
        "Runtime approval {}\n{}",
        request.id,
        serde_json::to_string_pretty(&request.action).map_err(|e| e.to_string())?
    );
    eprint!("Approve [y], reject [n], or quit [q]: ");
    std::io::stderr().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    match answer.trim().to_ascii_lowercase().as_str() {
        "q" | "quit" => {
            println!(
                "{}",
                json!({"status":"approval_pending","request_id":request.id,"supersedes_request_id":supersedes_request_id})
            );
            return Ok(Some(0));
        }
        "n" | "no" | "reject" => {
            archive_request(&directory, &request, "rejected")?;
            println!(
                "{}",
                json!({"status":"rejected","request_id":request.id,"supersedes_request_id":supersedes_request_id})
            );
            return Ok(Some(0));
        }
        "y" | "yes" | "approve" => (),
        _ => return Err("runtime approval was not confirmed".into()),
    }
    let _operation = attachments::OperationGuard::acquire(&directory)?;
    ensure_no_live_upgrade()?;
    let replan = terminal_replan::refresh(&mut request, &directory)?;
    if let Some(previous) = replan.superseded_request_id() {
        supersedes_request_id.get_or_insert_with(|| previous.to_owned());
    }
    if let Some(reason) = replan.fresh_review_reason() {
        println!(
            "{}",
            json!({
                "status":"approval_required",
                "request_id":request.id,
                "supersedes_request_id":supersedes_request_id,
                "attachment_id":request.action.attachment_id(),
                "reason":reason
            })
        );
        return Ok(Some(0));
    }
    if let Action::Attach { spec } = &request.action {
        if attachments::records(&directory)?.iter().any(|r| {
            r.spec.id != spec.id
                && r.spec.target.same_incarnation(&spec.target)
                && !matches!(r.phase, Phase::Detached | Phase::Exited | Phase::Failed)
        }) {
            return Err(
                "another attachment already owns this target; no second agent was injected".into(),
            );
        }
        attachments::verify_process(spec.effective_target())?;
        crate::platform::validate_attachment_backend(spec.target.pid, spec.scope, spec.backend)?;
    }
    runtime()?.block_on(attachments::enroll_core_authority(
        &directory,
        &discovery_control_endpoint(),
        &path,
        password.as_bytes(),
    ))?;
    validate_runtime_authorization_pending(&request, &_operation)?;
    let record_directory =
        attachments::attachment_directory(&directory, request.action.attachment_id())?;
    root_enrollment::existing_hosts(&record_directory, &keyring, &path, password.as_bytes())?;
    if request.action.recovery().is_some() {
        return recovery::execute_approved(
            &directory,
            &record_directory,
            &path,
            &descriptor,
            password.as_bytes(),
            &keyring,
            &request,
        );
    }
    match &request.action {
        Action::Attach { spec } => {
            let existing = attachments::load_record(&record_directory).ok();
            if let Some(record) = existing
                .as_ref()
                .filter(|r| matches!(r.phase, Phase::DetachedResident | Phase::Draining))
            {
                if record.spec.target != spec.target
                    || record.spec.scope != spec.scope
                    || record.spec.backend != spec.backend
                {
                    return Err("resident attachment contract changed".into());
                }
                let executor = record
                    .manager
                    .as_ref()
                    .ok_or("resident attachment manager identity missing")?
                    .executable_sha256
                    .clone();
                let authorization = attachments::authorize_claimant_bound(
                    &directory,
                    &path,
                    password.as_bytes(),
                    &descriptor,
                    request.clone(),
                    unix_timestamp_ms(),
                    None,
                    executor,
                    Some(record.host_binding.clone().ok_or(
                        "resident Host binding is unavailable; authenticated recovery is required",
                    )?),
                    attachments::manager_claimant_for_record(record)?,
                )?;
                let outcome = crate::platform::reattach_attachment(&record, &authorization)?;
                archive_request(&directory, &request, "approved")?;
                println!(
                    "{}",
                    json!({"status":"approved","request_id":request.id,"supersedes_request_id":supersedes_request_id,"attachment_id":spec.id,"phase":outcome.phase})
                );
                return Ok(Some(0));
            }
            if existing.is_some() {
                return Err("attachment state changed during review; submit a new proposal instead of reusing its session".into());
            }
            attachments::verify_process(spec.effective_target())?;
            let bootstrap = prepare_bootstrap(spec, &keyring, &unlocked.config)?;
            let waiting_manager = manager_bootstrap::WaitingManager::spawn(&record_directory)?;
            let authorization = attachments::authorize_claimant_bound(
                &directory,
                &path,
                password.as_bytes(),
                &descriptor,
                request.clone(),
                unix_timestamp_ms(),
                Some(attachments::bootstrap_digest(&bootstrap)?),
                attachments::executor_digest()?,
                Some(bootstrap.approval_binding().map_err(|e| e.to_string())?),
                waiting_manager.claimant.clone(),
            )?;
            let execution = Execution {
                spec: spec.clone(),
                origin: attachments::Origin::Attach,
                bootstrap,
                state_directory: record_directory.clone(),
                authorization,
            };
            attachments::create_record(&directory, spec.clone())?;
            let mut uncommitted =
                manager_bootstrap::UncommittedRecord::new(&record_directory, true);
            attachments::save_execution(&record_directory, &execution, &keyring)?;
            if spec.backend == Backend::Ptrace {
                attachments::save_recovery_context(
                    &record_directory,
                    &json!({"schema_version":1,"backend":"ptrace"}),
                    &keyring,
                )?;
            }
            archive_request(&directory, &request, "approved")?;
            let mut started_manager = waiting_manager.commit()?;
            uncommitted.disarm();
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(status) = started_manager.exited()? {
                    let final_record = attachments::load_record(&record_directory)?;
                    if final_record.manager.as_ref() == Some(started_manager.identity())
                        && matches!(final_record.phase, Phase::Exited | Phase::Detached)
                    {
                        println!(
                            "{}",
                            json!({"status":"approved","request_id":request.id,"supersedes_request_id":supersedes_request_id,"attachment_id":spec.id,"phase":final_record.phase})
                        );
                        return Ok(Some(0));
                    }
                    if attachments::verified_preparation_abort(&directory, &execution)? {
                        attachments::fail_record(&record_directory, "approved attachment refused before target mutation; trusted preparation rollback completed".into())?;
                        return Err("approved attachment refused before target mutation; target is unchanged and preparation rollback is complete".into());
                    }
                    attachments::record_execution_error(&record_directory, format!("created approved manager exited before startup acknowledgement: {status}"))?;
                    return Err("approved manager exited during startup; inspect attachment status and manager log".into());
                }
                let record = attachments::load_record(&record_directory)?;
                if record.phase != Phase::Preparing {
                    println!(
                        "{}",
                        json!({"status":"approved","request_id":request.id,"supersedes_request_id":supersedes_request_id,"attachment_id":spec.id,"phase":record.phase,"error":record.error})
                    );
                    if record.phase == Phase::Failed {
                        return Err("approved attach failed; inspect attachment status and private manager log".into());
                    }
                    return Ok(Some(0));
                }
                if Instant::now() >= deadline {
                    println!(
                        "{}",
                        json!({"status":"execution_pending","request_id":request.id,"supersedes_request_id":supersedes_request_id,"attachment_id":spec.id})
                    );
                    return Ok(Some(0));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Action::Detach {
            attachment_id,
            target,
            ..
        } => {
            let record = attachments::load_record(&record_directory)?;
            if !record.spec.target.same_incarnation(target) {
                return Err("detach target no longer matches approved attachment".into());
            }
            if attachments::process_birth(target.pid) == Some(target.birth) {
                attachments::verify_process(target)?;
            }
            let executor = record
                .manager
                .as_ref()
                .ok_or("attachment manager identity missing")?
                .executable_sha256
                .clone();
            let authorization = attachments::authorize_claimant_bound(
                &directory,
                &path,
                password.as_bytes(),
                &descriptor,
                request.clone(),
                unix_timestamp_ms(),
                None,
                executor,
                Some(record.host_binding.clone().ok_or(
                    "attachment Host binding is unavailable; authenticated recovery is required",
                )?),
                attachments::manager_claimant_for_record(&record)?,
            )?;
            let outcome = crate::platform::detach_attachment(&record, &authorization)?;
            archive_request(&directory, &request, "approved")?;
            println!(
                "{}",
                json!({"status":"approved","request_id":request.id,"supersedes_request_id":supersedes_request_id,"attachment_id":attachment_id,"phase":outcome.phase,"compatibility_reasons":outcome.compatibility_reasons})
            );
            Ok(Some(0))
        }
    }
}
fn archive_request(directory: &Path, request: &Request, state: &str) -> Result<(), String> {
    let history = directory.join("history");
    attachments::private_directory(&history)?;
    let target = history.join(format!("{}-{state}.json", request.id));
    std::fs::rename(attachments::request_path(directory, &request.id)?, target)
        .map_err(|e| e.to_string())
}
fn prepare_bootstrap(
    spec: &Spec,
    keyring: &ConfigKeyring,
    config: &hyperhub_core::config::Config,
) -> Result<hyperhub_runtime::attachment::Bootstrap, String> {
    let runtime = runtime()?;
    let control = discovery_control_endpoint();
    let trust = runtime.block_on(attachments::import_core_trust(
        &attachments::directory()?,
        &control,
    ))?;
    let authority = trust
        .authority
        .as_ref()
        .ok_or("external attachment requires enrolled administrator authority")?;
    let session_id = format!("attach-{}", spec.id);
    let response = runtime
        .block_on(control_request(
            &control,
            &ControlRequest::BeginSessionAuth {
                session_id: session_id.clone(),
                executable: spec.target.executable.clone(),
                client_nonce: rand::random(),
            },
        ))
        .map_err(|e| e.to_string())?;
    let response = match response {
        ControlResponse::SessionChallenge { challenge } => {
            let proof = session_proof(
                &keyring.session_auth_key().map_err(|e| e.to_string())?,
                &challenge,
            )?;
            runtime
                .block_on(control_request(
                    &control,
                    &ControlRequest::FinishSessionAuth {
                        challenge_id: challenge.challenge_id,
                        proof,
                    },
                ))
                .map_err(|e| e.to_string())?
        }
        other => other,
    };
    match response {
        ControlResponse::SessionBootstrap {
            session_id,
            token,
            socks_address,
            tls_ca_pem,
            agent_flags,
            sandbox,
            ..
        } => {
            let host = attachments::attachment_directory(&attachments::directory()?, &spec.id)?
                .join("host");
            let firewall = hyperhub_core::firewall::compile_snapshot(config, unix_timestamp_ms())?;
            Ok(hyperhub_runtime::attachment::Bootstrap {
                external_attachment: true,
                native_dns_mode: hyperhub_runtime::attachment::NativeDnsMode::PreserveAnswers,
                attachment_id: spec.id.clone(),
                session_id,
                token,
                control_endpoint: control,
                socks_address,
                tls_ca_pem,
                observe: agent_flags.observe,
                firewall: firewall.map(|f| serde_json::to_value(f).expect("firewall serializes")),
                sandbox: sandbox.map(|s| serde_json::to_value(s).expect("sandbox serializes")),
                host_endpoint: hyperhub_core::control::instance_control_endpoint(&host),
                host_token: attachments::new_id() + &attachments::new_id(),
                scope_tree: spec.scope == Scope::Tree,
                root_pid: spec.target.pid,
                approval_authority_file: attachments::directory()?
                    .join("authority.json")
                    .display()
                    .to_string(),
                approval_instance_id: attachments::instance_id(
                    &config_store::default_config_path().map_err(|e| e.to_string())?,
                    &config_store::read_descriptor(
                        &config_store::default_config_path().map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?,
                ),
                initially_owned: false,
                approval_not_before_ms: 0,
                approval_public_key: Some(authority.public_key),
                approval_inherited_public_key: None,
                alias_inherited: None,
                approval_root_identity: Some(spec.target.root_image_identity()),
                approval_core_public_key: Some(trust.core_public_key),
                approval_core_pid: trust.core_pid,
                approval_core_birth: trust.core_birth,
                approval_cli_sha256: attachments::executor_digest()?,
            })
        }
        ControlResponse::Error { message } => Err(message),
        _ => Err("Serve rejected pending attachment session".into()),
    }
}
fn run_manager(directory: &Path) -> Result<i32, String> {
    manager_bootstrap::await_creator()?;
    manager_bootstrap::redirect_output(directory)?;
    let keyring = crate::password::load_runtime_keyring()?;
    let execution = attachments::load_execution(directory, &keyring)?;
    attachments::register_manager_execution(&execution)?;
    let base = attachments::directory()?;
    runtime()?.block_on(attachments::import_core_trust(
        &base,
        &execution.bootstrap.control_endpoint,
    ))?;
    attachments::verify_execution(&base, &execution)?;
    let _manager_lifetime = attachments::ManagerGuard::acquire(directory)?;
    if execution.origin != attachments::Origin::Attach
        && execution.authorization.request.action.recovery().is_none()
    {
        return Err("external manager cannot claim an implicit run authorization".into());
    }
    if attachments::attachment_directory(&base, &execution.spec.id)? != directory {
        return Err("manager execution is outside this HyperHub instance".into());
    }
    if execution.authorization.request.action.recovery().is_some() {
        validate_runtime_authorization(&execution.authorization)?;
        let record = attachments::load_record(directory)?;
        let binding = execution.authorization.request.action.recovery().unwrap();
        let (_, digest) = load_backend_recovery::<serde_json::Value>(&execution)?;
        if digest != binding.context_digest {
            return Err("sealed backend recovery context changed after approval".into());
        }
        attachments::consume_authorization(&base, &execution.authorization)?;
        let result = crate::platform::run_attachment_recovery(&execution, &record);
        if let Err(error) = &result {
            let _ = attachments::record_execution_error(directory, error.clone());
        }
        return result.map(|()| 0);
    }
    let Action::Attach { spec } = &execution.authorization.request.action else {
        return Err("manager startup requires attach authorization".into());
    };
    if spec != &execution.spec {
        return Err("sealed execution does not match signed attachment".into());
    }
    attachments::verify_process(execution.spec.effective_target())?;
    attachments::consume_authorization(&base, &execution.authorization)?;
    let result = crate::platform::run_attachment_manager(&execution);
    if let Err(error) = &result {
        // Also cover failures before the backend creates its listener or enters
        // Gum's own preflight closure. Core's one-way gate remains the authority;
        // an error after mutation admission cannot use this rollback path.
        let rolled_back = cfg!(target_os = "linux")
            && execution.spec.backend == Backend::Gum
            && (attachments::verified_preparation_abort(&base, &execution).unwrap_or(false)
                || runtime()?
                    .block_on(attachments::abort_before_initial_mutation(
                        &execution, error,
                    ))
                    .is_ok());
        if rolled_back {
            let _ = attachments::fail_record(directory, error.clone());
        } else {
            let _ = attachments::record_execution_error(directory, error.clone());
        }
    }
    result.map(|()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
    #[test]
    fn defaults_attach_to_tree_and_requires_explicit_valid_options() {
        assert_eq!(
            parse("attach", &os(&["42"])).unwrap(),
            Command::Attach {
                pid: 42,
                scope: Scope::Tree,
                backend: Backend::Auto
            }
        );
        assert_eq!(
            parse(
                "attach",
                &os(&["42", "--scope", "process", "--backend", "gum"])
            )
            .unwrap(),
            Command::Attach {
                pid: 42,
                scope: Scope::Process,
                backend: Backend::Gum
            }
        );
        for args in [
            vec!["0"],
            vec!["-1"],
            vec!["42", "--scope"],
            vec!["42", "--scope", "all"],
            vec!["42", "--force", "yes"],
            vec!["42", "--api-key", "x"],
        ] {
            assert!(parse("attach", &os(&args)).is_err(), "{args:?}");
        }
    }
    #[test]
    fn detach_uses_attachment_identity_and_never_a_bare_pid() {
        assert!(parse("detach", &os(&["42"])).is_err());
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse("detach", &os(&[id])).unwrap(),
            Command::Detach { id: id.into() }
        );
        assert!(parse("detach", &os(&[id, "--force"])).is_err());
    }
}

/// Managers check the current authenticated configuration, not the attachment's
/// original policy digest. Legitimate hot updates must not make detach impossible.
pub(crate) fn validate_runtime_authorization(
    authorization: &hyperhub_core::attachments::Authorization,
) -> Result<(), String> {
    let path = config_store::default_config_path().map_err(|e| e.to_string())?;
    runtime()?.block_on(attachments::import_core_trust(
        &attachments::directory()?,
        &discovery_control_endpoint(),
    ))?;
    let keyring = crate::password::load_runtime_keyring()?;
    let current =
        config_store::load_encrypted_with_keyring(&path, &keyring).map_err(|e| e.to_string())?;
    if let Action::Attach { spec } = &authorization.request.action {
        let capabilities = attachments::dynamic_capabilities_for_origin(
            &current.config,
            spec.backend,
            proven_action_origin(&spec.id)?,
        );
        capabilities.require_supported()?;
        if capabilities != spec.capabilities {
            return Err("approved capabilities no longer match the current policy".into());
        }
    }
    if authorization.request.instance_id != attachments::instance_id(&path, &current.descriptor)
        || authorization.request.action.policy_digest()
            != attachments::policy_digest(&current.config)?
    {
        return Err("configuration or instance changed after runtime approval".into());
    }
    Ok(())
}

pub(crate) struct OwnedRunPreparation {
    id: String,
    backend: Backend,
    directory: PathBuf,
    bootstrap: hyperhub_runtime::attachment::Bootstrap,
}
pub(crate) fn prepare_owned_run(
    backend: crate::platform::TargetBackend,
    session_id: &str,
    token: &str,
    socks_address: &str,
    tls_ca_pem: &str,
    observe: bool,
    sandbox: Option<&hyperhub_core::sandbox::SandboxSnapshot>,
) -> Result<OwnedRunPreparation, String> {
    let backend = match backend {
        crate::platform::TargetBackend::GumInterceptor => Backend::Gum,
        #[cfg(target_os = "linux")]
        crate::platform::TargetBackend::PtraceSyscall => Backend::Ptrace,
    };
    let id = attachments::new_id();
    let directory = attachments::attachment_directory(&attachments::directory()?, &id)?;
    // A new owned process is an API-only startup. Its password anchor comes
    // from this CLI's authenticated TCB configuration, never a verifier file.
    let keyring = crate::password::load_runtime_keyring()?;
    let config_path = config_store::default_config_path().map_err(|e| e.to_string())?;
    let owned_config = config_store::load_encrypted_with_keyring(&config_path, &keyring)
        .map_err(|e| e.to_string())?;
    // Core attestation is optional compatibility information for ordinary run.
    let trust = runtime()?
        .block_on(attachments::import_core_trust(
            &attachments::directory()?,
            &discovery_control_endpoint(),
        ))
        .ok();
    let anchor = owned_config.approval_public_key.or_else(|| {
        trust
            .as_ref()
            .and_then(|t| t.authority.as_ref())
            .filter(|root| {
                root.instance_id == attachments::instance_id(&config_path, &owned_config.descriptor)
                    && root.config_id == owned_config.descriptor.config_id
            })
            .map(|root| root.public_key)
    });
    let bootstrap = hyperhub_runtime::attachment::Bootstrap {
        external_attachment: false,
        native_dns_mode: hyperhub_runtime::attachment::NativeDnsMode::SyntheticPool,
        attachment_id: id.clone(),
        session_id: session_id.into(),
        token: token.into(),
        control_endpoint: discovery_control_endpoint(),
        socks_address: socks_address.into(),
        tls_ca_pem: tls_ca_pem.into(),
        observe,
        firewall: None,
        sandbox: sandbox
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| e.to_string())?,
        host_endpoint: hyperhub_core::control::instance_control_endpoint(&directory.join("host")),
        host_token: attachments::new_id() + &attachments::new_id(),
        scope_tree: true,
        root_pid: 0,
        approval_authority_file: attachments::directory()?
            .join("authority.json")
            .display()
            .to_string(),
        approval_instance_id: {
            let (path, descriptor, _) = current_policy()?;
            attachments::instance_id(&path, &descriptor)
        },
        initially_owned: true,
        approval_not_before_ms: 0,
        approval_public_key: anchor,
        approval_inherited_public_key: None,
        alias_inherited: None,
        approval_root_identity: None,
        approval_core_public_key: trust.as_ref().map(|t| t.core_public_key),
        approval_core_pid: trust.as_ref().map_or(0, |t| t.core_pid),
        approval_core_birth: trust.as_ref().map_or(0, |t| t.core_birth),
        approval_cli_sha256: attachments::executor_digest()?,
    };
    Ok(OwnedRunPreparation {
        id,
        backend,
        directory,
        bootstrap,
    })
}
pub(crate) fn owned_run_environment(
    preparation: &OwnedRunPreparation,
) -> Vec<(OsString, OsString)> {
    vec![
        (
            "HYPERHUB_ATTACHMENT_ID".into(),
            preparation.id.clone().into(),
        ),
        (
            "HYPERHUB_ATTACHMENT_STATE_DIRECTORY".into(),
            preparation.directory.clone().into_os_string(),
        ),
    ]
}
pub(crate) fn register_owned_run(
    preparation: &OwnedRunPreparation,
    root_pid: u32,
) -> Result<(), String> {
    let (config_path, descriptor, policy_digest) = current_policy()?;
    let target = attachments::inspect_process(root_pid)?;
    let manager = attachments::inspect_process(std::process::id())?;
    let spec = Spec {
        exec_epoch: 0,
        current_target: None,
        recovery: None,
        capabilities: Default::default(),
        id: preparation.id.clone(),
        target,
        scope: Scope::Tree,
        backend: preparation.backend,
        policy_digest,
    };
    let base = attachments::directory()?;
    attachments::register_owned_run(
        &base,
        spec.clone(),
        preparation.bootstrap.session_id.clone(),
        manager.clone(),
    )?;
    let mut bootstrap = preparation.bootstrap.clone();
    bootstrap.root_pid = root_pid;
    bootstrap.approval_root_identity = Some(spec.target.root_image_identity());
    // Run itself is the explicit launch operation, not permission to seize an
    // existing process. This marker is never accepted by external manager entry.
    let request = Request {
        schema_version: 1,
        id: attachments::new_id(),
        instance_id: attachments::instance_id(&config_path, &descriptor),
        created_at_ms: unix_timestamp_ms(),
        action: Action::Attach { spec: spec.clone() },
    };
    let execution = Execution {
        spec,
        origin: attachments::Origin::Run,
        bootstrap,
        state_directory: preparation.directory.clone(),
        authorization: hyperhub_core::attachments::Authorization {
            request,
            approved_at_ms: 0,
            expires_at_ms: 0,
            nonce: [0; 32],
            executor_sha256: attachments::executor_digest()?,
            execution_digest: None,
            host_binding: None,
            core_attestation_public_key: None,
            manager_claimant: None,
            signature: vec![],
        },
    };
    let keyring = crate::password::load_runtime_keyring()?;
    attachments::save_execution(&preparation.directory, &execution, &keyring)?;
    runtime()?.block_on(attachments::initialize_owned_image(&execution, &manager))?;
    if preparation.backend == Backend::Ptrace {
        attachments::save_recovery_context(
            &preparation.directory,
            &json!({"schema_version":1,"backend":"ptrace"}),
            &keyring,
        )?;
    }
    Ok(())
}
pub(crate) fn owned_run_execution(
    environment: &[(OsString, OsString)],
) -> Result<Option<Execution>, String> {
    let value = |name: &str| {
        environment
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };
    let Some(id) = value("HYPERHUB_ATTACHMENT_ID") else {
        return Ok(None);
    };
    let id = id.to_str().ok_or("run attachment id is not UTF-8")?;
    let directory = attachments::attachment_directory(&attachments::directory()?, id)?;
    if value("HYPERHUB_ATTACHMENT_STATE_DIRECTORY").map(PathBuf::from) != Some(directory.clone()) {
        return Err("run attachment state directory does not match this instance".into());
    }
    let execution =
        attachments::load_execution(&directory, &crate::password::load_runtime_keyring()?)?;
    let record = attachments::load_record(&directory)?;
    if execution.origin != attachments::Origin::Run
        || record.origin != attachments::Origin::Run
        || record.manager.as_ref().map(|m| m.pid) != Some(std::process::id())
    {
        return Err("run attachment metadata does not belong to this launcher".into());
    }
    attachments::verify_process(
        record
            .manager
            .as_ref()
            .ok_or("run manager identity missing")?,
    )?;
    attachments::verify_process(execution.spec.effective_target())?;
    Ok(Some(execution))
}

pub(crate) fn record_owned_run_pre_entry_failure(
    execution: &Execution,
    reason: &str,
) -> Result<(), String> {
    let record = attachments::load_record(&execution.state_directory)?;
    if execution.origin != attachments::Origin::Run
        || record.origin != attachments::Origin::Run
        || record.spec != execution.spec
    {
        return Err("pre-entry failure does not belong to this owned run".into());
    }
    let message = format!("pre_entry_startup_failed:{reason}");
    attachments::update_record(
        &execution.state_directory,
        &owned_run_pre_entry_failure_outcome(message.clone()),
    )?;
    attachments::fail_record(&execution.state_directory, message)
}

fn owned_run_pre_entry_failure_outcome(message: String) -> attachments::Outcome {
    attachments::Outcome {
        phase: Phase::Failed,
        members: Vec::new(),
        manager: None,
        manager_endpoint: None,
        compatibility_reasons: vec![message],
    }
}

#[cfg(test)]
mod owned_run_pre_entry_failure_tests {
    use super::*;

    #[test]
    fn failed_pre_entry_target_is_never_published_live() {
        let outcome =
            owned_run_pre_entry_failure_outcome("pre_entry_startup_failed:injected fault".into());
        assert_eq!(outcome.phase, Phase::Failed);
        assert!(outcome.members.is_empty());
        assert!(outcome.manager.is_none());
        assert!(outcome.manager_endpoint.is_none());
        assert_eq!(
            outcome.compatibility_reasons,
            ["pre_entry_startup_failed:injected fault"]
        );
    }
}

fn validate_runtime_authorization_pending(
    request: &Request,
    guard: &attachments::OperationGuard,
) -> Result<(), String> {
    let (path, descriptor, policy) = current_policy()?;
    let directory = attachments::directory()?;
    stale_requests::validate_selected(
        &directory,
        request,
        &attachments::instance_id(&path, &descriptor),
        &policy,
        guard,
        |request| stale_requests::probe_epoch(&directory, request),
    )
}

fn ensure_no_live_upgrade() -> Result<(), String> {
    let status = live_status()?;
    let ControlResponse::Status {
        engine_upgrades,
        release_upgrades,
        ..
    } = status
    else {
        return Err("cannot determine current upgrade state".into());
    };
    if engine_upgrades.as_ref().is_some_and(|s| {
        s.error.is_some()
            || s.records_omitted > 0
            || s.records.iter().any(|r| !r.phase.clone().terminal())
    }) || release_upgrades.as_ref().is_some_and(|s| {
        s.error.is_some()
            || s.records_omitted > 0
            || s.records.iter().any(|r| !r.phase.clone().terminal())
    }) {
        return Err("an upgrade transaction is active or its state is incomplete; retry the runtime action after recovery".into());
    }
    Ok(())
}

fn same_intent(left: &Action, right: &Action) -> bool {
    match (left, right) {
        (Action::Attach { spec: a }, Action::Attach { spec: b }) => {
            a.target == b.target
                && a.current_target == b.current_target
                && a.exec_epoch == b.exec_epoch
                && a.scope == b.scope
                && a.backend == b.backend
                && a.policy_digest == b.policy_digest
                && a.capabilities == b.capabilities
                && a.recovery == b.recovery
        }
        _ => left == right,
    }
}

#[cfg(test)]
mod proposal_retry_tests {
    use super::*;
    #[test]
    fn repeated_attach_intent_keeps_request_and_attachment_ids_with_one_pending_file() {
        let directory =
            std::env::temp_dir().join(format!("hh-proposal-retry-{}", attachments::new_id()));
        let target = attachments::ProcessIdentity {
            pid: 42,
            birth: 1,
            executable: "test-fixture".into(),
            executable_sha256: "ab".repeat(32),
            owner: "test".into(),
        };
        let request = Request {
            schema_version: 1,
            id: attachments::new_id(),
            instance_id: "cd".repeat(32),
            created_at_ms: 1,
            action: Action::Attach {
                spec: Spec {
                    exec_epoch: 0,
                    current_target: None,
                    recovery: None,
                    capabilities: Default::default(),
                    id: attachments::new_id(),
                    target,
                    scope: Scope::Tree,
                    backend: Backend::Ptrace,
                    policy_digest: "ef".repeat(32),
                },
            },
        };
        let first = ensure_proposal(&directory, &request).unwrap();
        let mut retry = request.clone();
        retry.id = attachments::new_id();
        if let Action::Attach { spec } = &mut retry.action {
            spec.id = attachments::new_id();
        }
        let repeated = ensure_proposal(&directory, &retry).unwrap();
        assert_eq!(repeated.id, first.id);
        assert_eq!(
            repeated.action.attachment_id(),
            first.action.attachment_id()
        );
        assert_eq!(attachments::requests(&directory).unwrap().len(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

pub(crate) fn save_backend_recovery<T: serde::Serialize>(
    execution: &Execution,
    value: &T,
) -> Result<String, String> {
    attachments::save_recovery_context(
        &execution.state_directory,
        value,
        &crate::password::load_runtime_keyring()?,
    )
}
pub(crate) fn load_backend_recovery<T: serde::de::DeserializeOwned>(
    execution: &Execution,
) -> Result<(T, String), String> {
    attachments::load_recovery_context(
        &execution.state_directory,
        &crate::password::load_runtime_keyring()?,
    )
}
