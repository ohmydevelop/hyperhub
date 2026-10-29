//! Approval-authorized, non-owning Linux attachment managers.
use hyperhub_core::attachments::{
    self, Action, Authorization, Backend, Execution, Outcome, Phase, ProcessIdentity, Record, Scope,
};
use serde::{Deserialize, Serialize};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

pub fn inspect_attachment_target(pid: u32) -> Result<ProcessIdentity, String> {
    attachments::inspect_process(pid)
}

pub(super) fn endpoint_path(directory: &Path, suffix: &str) -> Result<String, String> {
    let uid = unsafe { libc::geteuid() };
    let selected = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let mut root = selected.join(format!("hyperhub-attach-{uid}"));
    if root.as_os_str().as_encoded_bytes().len() > 65 {
        root = std::env::temp_dir().join(format!("hyperhub-attach-{uid}"));
    }
    attachments::private_directory(&root)?;
    let name = attachments::digest(format!("{}\0{suffix}", directory.display()).as_bytes());
    let endpoint = root.join(format!("{}.sock", &name[..24]));
    endpoint
        .to_str()
        .map(str::to_owned)
        .ok_or("attachment endpoint path is not UTF-8".into())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagerCommand {
    authorization: Authorization,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootImageQuery {
    query: String,
    attachment_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    outcome: Option<Outcome>,
    error: Option<String>,
}

fn publish_consumed_detach<T: Clone, R>(
    current: &Mutex<T>,
    detach: &AtomicBool,
    approved: &T,
    after_publish: impl FnOnce() -> Result<R, String>,
) -> Result<R, String> {
    // Once a one-use Detach has been consumed, every fallible cleanup step
    // must be able to observe it. A poisoned bookkeeping mutex cannot safely
    // turn that consumed approval back into the previous Attach.
    *current
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = approved.clone();
    detach.store(true, Ordering::Release);
    after_publish()
}

pub(super) struct ManagerListener {
    pub(super) endpoint: String,
    stop: Arc<AtomicBool>,
    pub(super) authorization: Arc<Mutex<Authorization>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl ManagerListener {
    pub(super) fn start(execution: &Execution, detach: Arc<AtomicBool>) -> Result<Self, String> {
        let endpoint = endpoint_path(&execution.state_directory, "manager")?;
        let listener = UnixListener::bind(&endpoint).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let directory = execution.state_directory.clone();
        let execution = execution.clone();
        let manager = inspect_attachment_target(std::process::id())?;
        let authorization = Arc::new(Mutex::new(execution.authorization.clone()));
        let worker_authorization = authorization.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread = std::thread::Builder::new().name("hyperhub-attachment-control".into()).spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream,_)) => {
                        let _=stream.set_read_timeout(Some(Duration::from_secs(3)));
                        let _=stream.set_write_timeout(Some(Duration::from_secs(3)));
                        let result=(||->Result<Option<Outcome>,String>{
                            let mut peer:libc::ucred=unsafe{std::mem::zeroed()};
                            let mut length=std::mem::size_of::<libc::ucred>() as libc::socklen_t;
                            let result=unsafe{libc::getsockopt(stream.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,(&mut peer as *mut libc::ucred).cast(),&mut length)};
                            if result!=0 || length as usize!=std::mem::size_of::<libc::ucred>() || peer.uid!=unsafe{libc::geteuid()} {return Err("attachment manager peer has another owner or invalid credentials".into());}
                            let value:serde_json::Value=hyperhub_engine::host::read_frame(&mut stream).map_err(|e|e.to_string())?;
                            if value.get("query").is_some() {
                                let query:RootImageQuery=serde_json::from_value(value).map_err(|e|e.to_string())?;
                                if query.attachment_id!=execution.spec.id {return Err("unknown attachment manager query".into());}
                                let reply=match query.query.as_str() {
                                    "policy_admission"=>match attachments::manager_policy_admission(&execution.spec.id) {
                                        Ok(admission)=>serde_json::json!({"attachment_id":execution.spec.id,"admission":admission,"error":null}),
                                        Err(error)=>serde_json::json!({"attachment_id":execution.spec.id,"admission":null,"error":error}),
                                    },
                                    "root_image"=>{
                                        let image=attachments::manager_root_image(&execution.spec.id)?;
                                        serde_json::json!({"attachment_id":execution.spec.id,"root_image":image,"error":null})
                                    },
                                    "execution_profile"=>match attachments::manager_execution_profile(&execution.spec.id) {
                                        Ok(profile)=>serde_json::json!({"attachment_id":execution.spec.id,"profile":profile,"error":null}),
                                        Err(error)=>serde_json::json!({"attachment_id":execution.spec.id,"profile":null,"error":error}),
                                    },
                                    "operation_claimant"=>match attachments::manager_operation_claimant() {
                                        Ok(claimant)=>serde_json::json!({"attachment_id":execution.spec.id,"claimant":claimant,"error":null}),
                                        Err(error)=>serde_json::json!({"attachment_id":execution.spec.id,"claimant":null,"error":error}),
                                    },
                                    _=>return Err("unknown attachment manager query".into()),
                                };
                                hyperhub_engine::host::write_frame(&mut stream,&reply).map_err(|e|e.to_string())?;
                                return Ok(None);
                            }
                            let command:ManagerCommand=serde_json::from_value(value).map_err(|e|e.to_string())?;
                            let current=attachments::load_record(&directory)?;
                            let image=attachments::manager_root_image(&execution.spec.id)?;
                            match &command.authorization.request.action {
                                Action::Detach{attachment_id,target,exec_epoch,..} if attachment_id==&execution.spec.id && target.same_incarnation(&execution.spec.target) && target.root_image_identity()==image.identity && *exec_epoch==image.exec_epoch=>{},
                                Action::Attach{spec} if spec.id==execution.spec.id && spec.target==execution.spec.target && spec.effective_target().root_image_identity()==image.identity && spec.exec_epoch==image.exec_epoch && spec.scope==execution.spec.scope && spec.backend==execution.spec.backend && matches!(current.phase,Phase::DetachedResident|Phase::Draining)=>{},
                                _=>return Err("detach approval does not authorize this attachment".into()),
                            }
                            let removing=matches!(command.authorization.request.action,Action::Detach{..});
                            let dispatch_guard=if removing && execution.spec.backend==Backend::Gum{Some(gum::dispatch_gate()?)}else{None};
                            crate::attachment::validate_runtime_authorization(&command.authorization)?;
                            attachments::consume_authorization(&attachments::directory()?,&command.authorization)?;
                            let mut compatibility_reasons=Vec::new();
                            if removing {
                                let preparation=publish_consumed_detach(
                                    worker_authorization.as_ref(),
                                    detach.as_ref(),
                                    &command.authorization,
                                    || {
                                        let pending_startup=execution.spec.backend==Backend::Gum && gum::fence_pending_startup_cleanup(&execution,&command.authorization,&manager)?;
                                        if !pending_startup {
                                            super::engine_control::control_runtime()?.block_on(attachments::prepare_detach_session(&execution,&command.authorization,&manager))?;
                                        }
                                        Ok(())
                                    },
                                );
                                if let Err(error)=preparation {
                                    // The approval is already consumed and published. The
                                    // resident manager owns retrying cleanup; returning an
                                    // error here would falsely invite an impossible replay.
                                    compatibility_reasons.push(format!("detach_cleanup_fence_pending:{error}"));
                                }
                            } else {
                                let members:Vec<_>=current.members.iter().filter(|identity|identity_alive(identity)).cloned().collect();
                                let hosts=if execution.spec.backend==Backend::Gum{gum::host_bindings(&execution,&members)?}else{vec![]};
                                super::engine_control::control_runtime()?.block_on(attachments::reactivate_session(&execution,&command.authorization,&manager,&members,&hosts))?;
                                if let Action::Attach{spec}=&command.authorization.request.action{attachments::update_spec(&directory,spec)?;}
                                *worker_authorization.lock().map_err(|_|"attachment authorization state poisoned")?=command.authorization.clone();
                                detach.store(false,Ordering::Release);
                            }
                            drop(dispatch_guard);
                            Ok(Some(Outcome{phase:if removing{Phase::Detaching}else{Phase::Preparing},members:current.members,manager:current.manager,manager_endpoint:current.manager_endpoint,compatibility_reasons}))
                        })();
                        let reply=match result{Ok(None)=>continue,Ok(Some(outcome))=>Reply{outcome:Some(outcome),error:None},Err(error)=>Reply{outcome:None,error:Some(error)}};
                        let _=hyperhub_engine::host::write_frame(&mut stream,&reply);
                    }
                    Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(10)),
                    Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>{},
                    Err(_)=>break,
                }
            }
        }).map_err(|e|e.to_string())?;
        Ok(Self {
            endpoint,
            stop,
            authorization,
            thread: Some(thread),
        })
    }
}
impl Drop for ManagerListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.endpoint);
    }
}

pub fn reattach_attachment(
    record: &Record,
    authorization: &Authorization,
) -> Result<Outcome, String> {
    manage_attachment(record, authorization)
}
pub fn detach_attachment(
    record: &Record,
    authorization: &Authorization,
) -> Result<Outcome, String> {
    manage_attachment(record, authorization)
}
fn manage_attachment(record: &Record, authorization: &Authorization) -> Result<Outcome, String> {
    attachments::verify_authorization(&attachments::directory()?, authorization)?;
    if let Some(manager) = record.manager.as_ref() {
        if !identity_alive(manager) {
            return Err("attachment manager identity changed".into());
        }
    } else {
        return Err("attachment has no live manager".into());
    }
    let endpoint = record
        .manager_endpoint
        .as_ref()
        .ok_or("attachment has no manager endpoint")?;
    let mut stream = UnixStream::connect(endpoint).map_err(|e| e.to_string())?;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let peer_result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if peer_result != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
        || record
            .manager
            .as_ref()
            .is_none_or(|manager| peer.pid as u32 != manager.pid || !identity_alive(manager))
    {
        return Err("attachment manager endpoint has another process identity".into());
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    hyperhub_engine::host::write_frame(
        &mut stream,
        &ManagerCommand {
            authorization: authorization.clone(),
        },
    )
    .map_err(|e| e.to_string())?;
    let reply: Reply = hyperhub_engine::host::read_frame(&mut stream).map_err(|e| e.to_string())?;
    match (reply.outcome, reply.error) {
        (Some(outcome), None) => Ok(outcome),
        (_, Some(error)) => Err(error),
        _ => Err("invalid attachment manager reply".into()),
    }
}

fn outcome(
    execution: &Execution,
    manager: &ProcessIdentity,
    endpoint: &str,
    phase: Phase,
    members: Vec<ProcessIdentity>,
    reasons: Vec<String>,
) -> Result<(), String> {
    let current = attachments::load_record(&execution.state_directory)?;
    if current.phase == phase
        && current.members == members
        && current.manager.as_ref() == Some(manager)
        && current.manager_endpoint.as_deref() == Some(endpoint)
        && current.compatibility_reasons == reasons
    {
        return Ok(());
    }
    attachments::update_record(
        &execution.state_directory,
        &Outcome {
            phase,
            members,
            manager: Some(manager.clone()),
            manager_endpoint: Some(endpoint.to_owned()),
            compatibility_reasons: reasons,
        },
    )
    .map(|_| ())
}
fn member_snapshot(root: u32, tree: bool) -> Result<Vec<ProcessIdentity>, String> {
    super::syscall_supervisor::attachment_process_tree(root, tree)?
        .into_iter()
        .map(inspect_attachment_target)
        .collect()
}
fn identity_alive(identity: &ProcessIdentity) -> bool {
    super::syscall_supervisor::process_birth(identity.pid as i32) == Some(identity.birth)
        && std::fs::read_link(format!("/proc/{}/exe", identity.pid))
            .ok()
            .is_some_and(|path| path.to_string_lossy() == identity.executable)
}
fn verify_target(execution: &Execution) -> Result<(), String> {
    if execution.spec.target.pid == std::process::id() || execution.spec.target.pid <= 1 {
        return Err("cannot attach this management process or init".into());
    }
    attachments::verify_authorization(&attachments::directory()?, &execution.authorization)?;
    if inspect_attachment_target(execution.spec.target.pid)? != execution.spec.target {
        return Err("attachment target identity changed".into());
    }
    Ok(())
}

pub fn run_attachment_manager(execution: &Execution) -> Result<(), String> {
    let manager = inspect_attachment_target(std::process::id())?;
    if let Err(error) = verify_target(execution)
        .and_then(|()| {
            super::validate_attachment_backend(
                execution.spec.target.pid,
                execution.spec.scope,
                execution.spec.backend,
            )
        })
        .and_then(|()| inspection::reject_incompatible_agent(execution.spec.target.pid))
    {
        attachments::update_record(
            &execution.state_directory,
            &Outcome {
                phase: Phase::Failed,
                members: vec![],
                manager: Some(manager),
                manager_endpoint: None,
                compatibility_reasons: vec!["preflight_failed_before_target_mutation".into()],
            },
        )?;
        return Err(error);
    }
    let detach = Arc::new(AtomicBool::new(false));
    let listener = ManagerListener::start(execution, detach.clone())?;
    match execution.spec.backend {
        Backend::Auto | Backend::Ptrace => run_ptrace(
            execution,
            &manager,
            &listener.endpoint,
            detach,
            listener.authorization.clone(),
        ),
        Backend::Gum => run_gum(
            execution,
            &manager,
            &listener.endpoint,
            detach,
            listener.authorization.clone(),
        ),
    }
}

pub(super) fn persist_ptrace_context(execution: &Execution) -> Result<(), String> {
    crate::attachment::save_backend_recovery(
        execution,
        &serde_json::json!({"schema":1,"backend":"ptrace","safe":true}),
    )?;
    Ok(())
}

pub fn run_attachment_recovery(execution: &Execution, record: &Record) -> Result<(), String> {
    let binding = execution
        .authorization
        .request
        .action
        .recovery()
        .ok_or("recovery lacks a signed binding")?;
    if record.manager.as_ref() != Some(&binding.manager) || identity_alive(&binding.manager) {
        return Err("previous attachment manager is still alive or changed".into());
    }
    let (context, digest) =
        crate::attachment::load_backend_recovery::<serde_json::Value>(execution)?;
    if digest != binding.context_digest {
        return Err("attachment recovery context changed after approval".into());
    }
    if execution.spec.backend == Backend::Gum {
        return gum::recover(execution, record, context);
    }
    if context.get("backend").and_then(|value| value.as_str()) != Some("ptrace") {
        return Err("attachment recovery backend context is incompatible".into());
    }
    if context.get("safe").and_then(|value| value.as_bool()) != Some(true) {
        return Err("previous tracer stopped with unproven virtual descriptor, DNS or in-flight syscall state; refusing semantic recovery".into());
    }
    let members = record
        .members
        .iter()
        .filter(|member| identity_alive(member))
        .cloned()
        .collect::<Vec<_>>();
    if members.is_empty() {
        return Err("attachment recovery has no surviving approved process".into());
    }
    for member in &members {
        let status = std::fs::read_to_string(format!("/proc/{}/status", member.pid))
            .map_err(|error| error.to_string())?;
        let tracer = status
            .lines()
            .find_map(|line| {
                line.strip_prefix("TracerPid:")
                    .and_then(|value| value.trim().parse::<u32>().ok())
            })
            .ok_or("cannot establish previous tracer removal")?;
        if tracer != 0 {
            return Err("attachment recovery target has another live tracer".into());
        }
        inspection::reject_incompatible_agent(member.pid)?;
    }
    remove_dead_manager_endpoint(execution, record)?;
    let manager = inspect_attachment_target(std::process::id())?;
    // Core adopts only existing approved members while Record still pins the
    // vanished old manager. No target has been seized or modified at this point.
    super::engine_control::control_runtime()?
        .block_on(attachments::recover_session(execution, &manager, &members))?;
    if matches!(
        execution.authorization.request.action,
        Action::Detach { .. }
    ) {
        super::engine_control::control_runtime()?.block_on(attachments::prepare_detach_session(
            execution,
            &execution.authorization,
            &manager,
        ))?;
    }
    attachments::update_spec(&execution.state_directory, &execution.spec)?;
    let detach = Arc::new(AtomicBool::new(matches!(
        execution.authorization.request.action,
        Action::Detach { .. }
    )));
    let listener = ManagerListener::start(execution, detach.clone())?;
    outcome(
        execution,
        &manager,
        &listener.endpoint,
        Phase::Preparing,
        members.clone(),
        vec![],
    )?;
    run_ptrace_with_members(
        execution,
        &manager,
        &listener.endpoint,
        detach,
        listener.authorization.clone(),
        members,
        true,
    )
}
fn remove_dead_manager_endpoint(execution: &Execution, record: &Record) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let expected = endpoint_path(&execution.state_directory, "manager")?;
    if record.manager_endpoint.as_deref() != Some(expected.as_str()) {
        return Err("recorded manager endpoint has incompatible ownership".into());
    }
    match std::fs::symlink_metadata(&expected) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
                return Err("previous manager endpoint is not an owned socket".into());
            }
            match UnixStream::connect(&expected) {
                Ok(_) => return Err("previous manager endpoint still has a live listener".into()),
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ENOENT | libc::ECONNREFUSED)
                    ) => {}
                Err(error) => return Err(error.to_string()),
            }
            std::fs::remove_file(&expected).map_err(|error| error.to_string())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    Ok(())
}

fn run_ptrace(
    execution: &Execution,
    manager: &ProcessIdentity,
    endpoint: &str,
    detach: Arc<AtomicBool>,
    authorization: Arc<Mutex<Authorization>>,
) -> Result<(), String> {
    persist_ptrace_context(execution)?;
    run_ptrace_with_members(
        execution,
        manager,
        endpoint,
        detach,
        authorization,
        vec![],
        false,
    )
}
fn run_ptrace_with_members(
    execution: &Execution,
    manager: &ProcessIdentity,
    endpoint: &str,
    detach: Arc<AtomicBool>,
    authorization: Arc<Mutex<Authorization>>,
    members: Vec<ProcessIdentity>,
    recovery: bool,
) -> Result<(), String> {
    let (send, reporter) = start_reporter(execution, manager, endpoint, authorization.clone())?;
    let bootstrap = &execution.bootstrap;
    let environment = vec![
        (
            "HYPERHUB_CONTROL_ENDPOINT".into(),
            bootstrap.control_endpoint.clone().into(),
        ),
        (
            "HYPERHUB_SESSION_ID".into(),
            bootstrap.session_id.clone().into(),
        ),
        (
            "HYPERHUB_SESSION_TOKEN".into(),
            bootstrap.token.clone().into(),
        ),
        (
            "HYPERHUB_SOCKS_ADDR".into(),
            bootstrap.socks_address.clone().into(),
        ),
        (
            "HYPERHUB_ENFORCEMENT_MODE".into(),
            if bootstrap.observe {
                "observe"
            } else {
                "enforce"
            }
            .into(),
        ),
    ];
    let sandbox = bootstrap
        .sandbox
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| e.to_string())?;
    let config = super::syscall_supervisor::AttachedConfiguration {
        root_pid: execution.spec.target.pid,
        tree: execution.spec.scope == Scope::Tree,
        environment,
        sandbox,
        detach,
        events: send,
        initial_members: members,
        execution: Some(execution.clone()),
        authorization,
    };
    let result = super::syscall_supervisor::run_attached(config, |_, _| {
        if recovery {
            return Ok(true);
        }
        let members = member_snapshot(
            execution.spec.target.pid,
            execution.spec.scope == Scope::Tree,
        )?;
        super::engine_control::control_runtime()?
            .block_on(attachments::activate_session(execution, manager, &members))?;
        Ok(true)
    });
    let _ = reporter.join();
    result
}

pub(super) fn start_reporter(
    execution: &Execution,
    manager: &ProcessIdentity,
    endpoint: &str,
    authorization: Arc<Mutex<Authorization>>,
) -> Result<
    (
        mpsc::Sender<super::syscall_supervisor::AttachmentEvent>,
        std::thread::JoinHandle<()>,
    ),
    String,
> {
    let (send, receive) = mpsc::channel();
    let state = execution.clone();
    let identity = manager.clone();
    let socket = endpoint.to_owned();
    let reporter = std::thread::Builder::new()
        .name("hyperhub-attachment-status".into())
        .spawn(move || {
            let mut members = vec![state.spec.target.clone()];
            while let Ok(event) = receive.recv() {
                use super::syscall_supervisor::AttachmentEvent;
                let (phase, reasons) = match event {
                    AttachmentEvent::Active(pids) => {
                        members = pids
                            .into_iter()
                            .filter_map(|pid| inspect_attachment_target(pid).ok())
                            .collect();
                        (Phase::Active, vec![])
                    }
                    AttachmentEvent::CleanupPending(error) => (Phase::CleanupPending, vec![error]),
                    AttachmentEvent::Draining { sockets } => (
                        Phase::Draining,
                        if sockets > 0 {
                            vec![format!("existing_socket_state:{sockets}")]
                        } else {
                            vec![]
                        },
                    ),
                    AttachmentEvent::Detached => (Phase::Detached, vec![]),
                    AttachmentEvent::Exited => (Phase::Exited, vec![]),
                    AttachmentEvent::Degraded(error) => (Phase::Degraded, vec![error]),
                };
                if phase != Phase::Detached {
                    let _ = outcome(&state, &identity, &socket, phase, members.clone(), reasons);
                    continue;
                }
                const ABSENT: &str = "physical_native_modules_absent_pending_session_revocation";
                loop {
                    // Physical tracing is already gone. Keep the authenticated
                    // manager alive until Serve acknowledges token revocation;
                    // neither a timeout nor a failed reply proves completion.
                    if outcome(
                        &state,
                        &identity,
                        &socket,
                        Phase::Detaching,
                        members.clone(),
                        vec![ABSENT.into()],
                    )
                    .is_err()
                    {
                        std::thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                    let completion = (|| -> Result<(), String> {
                        let grant = authorization
                            .lock()
                            .map_err(|_| "attachment authorization state poisoned")?
                            .clone();
                        super::engine_control::control_runtime()?.block_on(async {
                            tokio::time::timeout(
                                Duration::from_secs(5),
                                attachments::complete_session(&state, &grant),
                            )
                            .await
                            .map_err(|_| {
                                "session revocation response deadline expired".to_owned()
                            })?
                        })
                    })();
                    match completion {
                        Ok(()) => {
                            let _ = outcome(
                                &state,
                                &identity,
                                &socket,
                                Phase::Detached,
                                members.clone(),
                                vec![],
                            );
                            break;
                        }
                        Err(error) => {
                            let _ = outcome(
                                &state,
                                &identity,
                                &socket,
                                Phase::Detaching,
                                members.clone(),
                                vec![ABSENT.into(), format!("session_cleanup_pending:{error}")],
                            );
                            std::thread::sleep(Duration::from_secs(1));
                        }
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok((send, reporter))
}

#[path = "attachment_gum.rs"]
mod gum;
use gum::run as run_gum;

#[path = "attachment_inspection.rs"]
mod inspection;

pub(crate) use gum::OwnedGumMonitor;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumed_detach_remains_published_when_the_following_fence_fails() {
        let current = Mutex::new("attach".to_owned());
        let detach = AtomicBool::new(false);

        let result = publish_consumed_detach(&current, &detach, &"detach".to_owned(), || {
            Err::<(), _>("injected fence failure".to_owned())
        });

        assert_eq!(result.unwrap_err(), "injected fence failure");
        assert_eq!(&*current.lock().unwrap(), "detach");
        assert!(detach.load(Ordering::Acquire));
    }
}
