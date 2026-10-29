//! Live Gum attachment. The manager outlives the command that requested it.
use super::super::fork_handoff::ForkHandoffBroker;
use super::super::frida_core::{ChildOrigin, FridaCore, Process};
use super::*;
use hyperhub_runtime::attachment::{Bootstrap, HostCommand, HostPhase};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::time::{Duration, Instant};

const ATTACH_INJECTION_TIMEOUT: Duration = Duration::from_secs(15);
const ATTACH_PREPARATION_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy)]
struct PreparationDeadline {
    deadline: Instant,
}

impl PreparationDeadline {
    fn new_at(started: Instant) -> Self {
        Self {
            deadline: started + ATTACH_PREPARATION_TIMEOUT,
        }
    }

    fn new() -> Self {
        Self::new_at(Instant::now())
    }

    fn operation_timeout_at(self, now: Instant) -> Result<Duration, String> {
        let remaining = self.deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return Err("dynamic attachment preparation deadline exceeded".into());
        }
        Ok(remaining.min(ATTACH_INJECTION_TIMEOUT))
    }

    fn operation_timeout(self) -> Result<Duration, String> {
        self.operation_timeout_at(Instant::now())
    }
}

fn after_preparing_publication<T>(
    publish: impl FnOnce() -> Result<(), String>,
    native_dispatch: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    publish()?;
    native_dispatch()
}

fn after_cleanup_pending_publication<T>(
    publish: impl FnOnce() -> Result<(), String>,
    cleanup: impl FnOnce() -> T,
) -> (Result<(), String>, T) {
    let publication = publish();
    (publication, cleanup())
}

fn cleanup_authorization_for_round(
    authorization: &Mutex<Authorization>,
) -> Result<Authorization, String> {
    authorization
        .lock()
        .map_err(|_| "attachment authorization state poisoned".to_string())
        .map(|authorization| authorization.clone())
}

#[derive(Debug, PartialEq, Eq)]
struct PreparationCleanupAttempt {
    complete: bool,
    reasons: Vec<String>,
}

/// Run one ordered cleanup pass without inferring completion from a failed
/// operation. A member's logical Host detach must commit before its native
/// listener or child gate can be retired. Pending children observed in this
/// pass make the pass incomplete even when resume succeeds; the next pass must
/// independently confirm that Core no longer holds them.
fn ordered_preparation_cleanup_attempt(
    member_pids: &[u32],
    tree: bool,
    mut detach_host: impl FnMut(u32) -> Result<(), String>,
    mut abort_listener: impl FnMut(u32) -> Result<(), String>,
    mut disable_gating: impl FnMut(u32) -> Result<(), String>,
    pending_children: impl FnOnce() -> Result<Vec<(u32, i32)>, String>,
    mut resume_child: impl FnMut(i32) -> Result<(), String>,
) -> PreparationCleanupAttempt {
    let mut complete = true;
    let mut reasons = Vec::new();
    let mut logically_detached = std::collections::BTreeSet::new();

    for pid in member_pids {
        if let Err(error) = detach_host(*pid) {
            complete = false;
            reasons.push(format!("rollback_incomplete:{pid}:{error}"));
            continue;
        }
        logically_detached.insert(*pid);
        if tree {
            if let Err(error) = abort_listener(*pid) {
                complete = false;
                reasons.push(format!("fork_listener_abort_cleanup_pending:{pid}:{error}"));
                continue;
            }
        }
        if let Err(error) = disable_gating(*pid) {
            complete = false;
            reasons.push(format!("child_gating_cleanup_pending:{pid}:{error}"));
        }
    }

    match pending_children() {
        Ok(children) => {
            for (parent_pid, child_pid) in children {
                if !member_pids.contains(&parent_pid) {
                    continue;
                }
                // A child of a member whose logical detach is unconfirmed must
                // remain held by the still-live manager. Releasing it could
                // let a propagating Host create new work during rollback.
                if !logically_detached.contains(&parent_pid) {
                    complete = false;
                    continue;
                }
                complete = false;
                if let Err(error) = resume_child(child_pid) {
                    reasons.push(format!("child_resume_cleanup_pending:{child_pid}:{error}"));
                }
            }
        }
        Err(error) => {
            complete = false;
            reasons.push(format!("pending_child_cleanup_unknown:{error}"));
        }
    }

    PreparationCleanupAttempt { complete, reasons }
}

#[derive(Serialize)]
struct Envelope<'a> {
    bootstrap: &'a Bootstrap,
    ready_path: String,
    fork_socket: String,
    fork_secret: String,
    runtime_path: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct NativePin {
    fd: i32,
    device: u64,
    inode: u64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Member {
    identity: ProcessIdentity,
    bootstrap: Bootstrap,
    native_pin: Option<NativePin>,
    #[serde(default)]
    preparation_only: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct PendingInjection {
    identity: ProcessIdentity,
    bootstrap: Bootstrap,
    #[serde(default)]
    ready_path: String,
    #[serde(default = "unknown_dispatch_is_started")]
    dispatch_started: bool,
    #[serde(default)]
    observation: Option<PendingObservation>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PendingObservation {
    NotDispatched,
    ReplacedImage { current: ProcessIdentity },
    PayloadAbsent,
    Unknown { reason: String },
}
fn unknown_dispatch_is_started() -> bool {
    true
}
type PendingInjections = RefCell<Vec<PendingInjection>>;

// A manager's control thread and injector share this short admission gate.
// A dispatched call is durably journaled before approval can fence its roster;
// after approval publishes cancellation no new native call can pass this gate.
static NATIVE_DISPATCH: Mutex<()> = Mutex::new(());
pub(super) fn dispatch_gate() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    NATIVE_DISPATCH
        .lock()
        .map_err(|_| "native dispatch admission unavailable".into())
}

fn admit_native_dispatch(
    cancelled: Option<&AtomicBool>,
) -> Result<std::sync::MutexGuard<'static, ()>, String> {
    let guard = dispatch_gate()?;
    if cancelled.is_some_and(|requested| requested.load(Ordering::Acquire)) {
        return Err("approved cleanup interrupted native injection before dispatch".into());
    }
    Ok(guard)
}

pub(super) fn fence_pending_startup_cleanup(
    execution: &Execution,
    authorization: &Authorization,
    manager: &ProcessIdentity,
) -> Result<bool, String> {
    let (context, _) = crate::attachment::load_backend_recovery::<GumRecovery>(execution)?;
    if context.schema != 1 || context.backend != "gum" {
        return Err("attachment startup cleanup context is incompatible".into());
    }
    if context.pending_injections.is_empty() {
        return Ok(false);
    }
    let mut hosts = BTreeMap::new();
    let mut unstarted = Vec::new();
    for member in context.members {
        if publication_member_alive(&member.identity)? {
            hosts.insert(
                member.identity.pid,
                attachments::HostBootstrapBinding {
                    identity: member.identity,
                    bootstrap: member.bootstrap,
                },
            );
        }
    }
    for attempt in context.pending_injections {
        if !publication_member_alive(&attempt.identity)? {
            continue;
        }
        let binding = attachments::HostBootstrapBinding {
            identity: attempt.identity,
            bootstrap: attempt.bootstrap,
        };
        if attempt.dispatch_started {
            if let Some(existing) = hosts.get(&binding.identity.pid) {
                if existing.identity != binding.identity
                    || existing.bootstrap.host_endpoint != binding.bootstrap.host_endpoint
                    || existing.bootstrap.host_token != binding.bootstrap.host_token
                {
                    return Err("startup cleanup has conflicting journal bindings".into());
                }
            } else {
                hosts.insert(binding.identity.pid, binding);
            }
        } else {
            unstarted.push(binding);
        }
    }
    let hosts = hosts.into_values().collect::<Vec<_>>();
    let members = hosts
        .iter()
        .map(|host| host.identity.clone())
        .collect::<Vec<_>>();
    let mut cleanup = execution.clone();
    cleanup.authorization = authorization.clone();
    super::super::engine_control::control_runtime()?.block_on(
        attachments::recover_session_with_startup_cleanup(
            &cleanup, manager, &members, &hosts, &unstarted,
        ),
    )?;
    Ok(true)
}

struct InjectionJournal<'a> {
    payload: &'a NativePayload,
    members: BTreeMap<u32, Member>,
    pending: &'a PendingInjections,
    cancellation: Option<(&'a AtomicBool, &'a Mutex<Authorization>)>,
}
impl InjectionJournal<'_> {
    fn record(
        &self,
        execution: &Execution,
        handoff: &ForkHandoffBroker,
        attempt: PendingInjection,
    ) -> Result<(), String> {
        retain_pending(self.pending, attempt, || {
            persist_context(
                execution,
                self.payload,
                handoff,
                &self.members,
                self.pending,
            )
        })
    }
}

fn retain_pending(
    pending: &PendingInjections,
    attempt: PendingInjection,
    persist: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    {
        let mut pending = pending.borrow_mut();
        if let Some(existing) = pending
            .iter_mut()
            .find(|old| old.identity.pid == attempt.identity.pid)
        {
            if existing.identity != attempt.identity
                || existing.ready_path != attempt.ready_path
                || existing.bootstrap.host_endpoint != attempt.bootstrap.host_endpoint
                || existing.bootstrap.host_token != attempt.bootstrap.host_token
                || existing
                    .bootstrap
                    .approval_binding()
                    .map_err(|e| e.to_string())?
                    != attempt
                        .bootstrap
                        .approval_binding()
                        .map_err(|e| e.to_string())?
                || (existing.dispatch_started && !attempt.dispatch_started)
            {
                return Err("a prior native injection attempt remains unresolved".into());
            }
            *existing = attempt;
        } else {
            pending.push(attempt);
        }
    }
    persist()
}

fn dispatch_injection<T>(
    mut attempt: PendingInjection,
    mut record: impl FnMut(PendingInjection) -> Result<(), String>,
    dispatch: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    attempt.dispatch_started = false;
    attempt.observation = Some(PendingObservation::NotDispatched);
    record(attempt.clone())?;
    attempt.dispatch_started = true;
    attempt.observation = Some(PendingObservation::Unknown {
        reason: "native dispatch may still be in flight".into(),
    });
    record(attempt)?;
    dispatch()
}
type MemberCheckpoint<'a> = Option<&'a mut dyn FnMut(&Member) -> Result<(), String>>;

fn track_verified_member(
    member: Member,
    checkpoint: MemberCheckpoint<'_>,
    track: impl FnOnce(&Member) -> Result<(), String>,
) -> Result<Member, String> {
    // Ownership must enter the manager's RAM table before a persistence or
    // tracking failure. Such a failure is already after native mutation and
    // must leave a real Host visible to authorized rollback/recovery.
    if let Some(checkpoint) = checkpoint {
        checkpoint(&member)?;
    }
    track(&member)?;
    Ok(member)
}
#[derive(Clone, Serialize, Deserialize)]
struct NativePayload {
    device: u64,
    inode: u64,
    size: u64,
    sha256: String,
    seals: i32,
}
#[derive(Serialize, Deserialize)]
struct GumRecovery {
    schema: u32,
    backend: String,
    payload: NativePayload,
    broker: super::super::fork_handoff::BrokerIdentity,
    members: Vec<Member>,
    #[serde(default)]
    pending_injections: Vec<PendingInjection>,
}
/// Missing/replaced incarnations, or groups with no surviving threads, cannot
/// execute more application code. IO and malformed records never prove exit.
fn publication_member_alive(identity: &ProcessIdentity) -> Result<bool, String> {
    let text = match std::fs::read_to_string(format!("/proc/{}/stat", identity.pid)) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot verify fork publication member: {error}")),
    };
    let (state, birth) = publication_stat(&text, identity.pid)?;
    if birth != identity.birth {
        return Ok(false);
    }
    if !matches!(state, "Z" | "X" | "x") {
        return Ok(true);
    }
    // A group leader can exit through pthread_exit while another application
    // thread still runs. Zombie leader state alone never proves group exit.
    let tasks = match std::fs::read_dir(format!("/proc/{}/task", identity.pid)) {
        Ok(tasks) => tasks,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "cannot verify fork publication thread group: {error}"
            ))
        }
    };
    for task in tasks {
        let task =
            task.map_err(|error| format!("cannot inspect fork publication thread: {error}"))?;
        let tid = task
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or("fork publication thread ID is malformed")?;
        let text = match std::fs::read_to_string(task.path().join("stat")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot verify fork publication thread: {error}")),
        };
        if !matches!(publication_stat(&text, tid)?.0, "Z" | "X" | "x") {
            return Ok(true);
        }
    }
    Ok(false)
}
fn publication_stat(text: &str, pid: u32) -> Result<(&str, u64), String> {
    if text
        .split_once(' ')
        .and_then(|(value, _)| value.parse::<u32>().ok())
        != Some(pid)
    {
        return Err("fork publication process record has another PID".into());
    }
    let (_, tail) = text
        .rsplit_once(") ")
        .ok_or("fork publication process record is malformed")?;
    let mut fields = tail.split_whitespace();
    let state = fields
        .next()
        .ok_or("fork publication process state is missing")?;
    let actual = fields
        .nth(18)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or("fork publication process birth is missing")?;
    Ok((state, actual))
}
fn wait_fork_publication(path: &Path, identity: &ProcessIdentity) -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                let status = attachments::read_private_file(path, 8192)?;
                let _ = std::fs::remove_file(path);
                return if status == b"ok" {
                    Ok(true)
                } else {
                    Err("fork child publication failed".into())
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect fork publication receipt: {error}")),
        }
        if !publication_member_alive(identity)? {
            return Ok(false);
        }
        if Instant::now() >= deadline {
            return Err("fork publish timed out".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn native_payload(runtime: &Path) -> Result<NativePayload, String> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let file = std::fs::File::open(runtime).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if metadata.len() > 256 * 1024 * 1024 {
        return Err("native payload exceeds recovery size bound".into());
    }
    let bytes = std::fs::read(runtime).map_err(|error| error.to_string())?;
    Ok(NativePayload {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        sha256: attachments::digest(&bytes),
        seals: unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) },
    })
}
fn persist_context(
    execution: &Execution,
    payload: &NativePayload,
    handoff: &ForkHandoffBroker,
    members: &BTreeMap<u32, Member>,
    pending: &PendingInjections,
) -> Result<(), String> {
    for member in members.values() {
        match &member.native_pin {
            Some(pin) if pin.device == payload.device && pin.inode == payload.inode => {}
            None if member.preparation_only => {}
            _ => return Err("target native pin differs from approved payload inode".into()),
        }
    }
    crate::attachment::save_backend_recovery(
        execution,
        &GumRecovery {
            schema: 1,
            backend: "gum".into(),
            payload: payload.clone(),
            broker: handoff.identity(),
            members: members.values().cloned().collect(),
            pending_injections: pending.borrow().clone(),
        },
    )?;
    Ok(())
}
pub(super) fn host_bindings(
    execution: &Execution,
    members: &[ProcessIdentity],
) -> Result<Vec<attachments::HostBootstrapBinding>, String> {
    let (context, _) = crate::attachment::load_backend_recovery::<GumRecovery>(execution)?;
    if context.schema != 1 || context.backend != "gum" {
        return Err("attachment Host recovery metadata is incompatible".into());
    }
    members
        .iter()
        .map(|identity| {
            let member = context
                .members
                .iter()
                .find(|member| &member.identity == identity)
                .ok_or("live member has no sealed Host endpoint metadata")?;
            Ok(attachments::HostBootstrapBinding {
                identity: identity.clone(),
                bootstrap: member.bootstrap.clone(),
            })
        })
        .collect()
}

fn host(
    member: &Member,
    command: HostCommand,
    authorization: Option<&Authorization>,
) -> Result<hyperhub_runtime::attachment::HostStatus, String> {
    attachments::manager_host_command(&member.bootstrap, &member.identity, command, authorization)
}
fn bootstrap_for(execution: &Execution, identity: &ProcessIdentity) -> Result<Bootstrap, String> {
    let mut bootstrap = execution.bootstrap.clone();
    bootstrap.host_endpoint = endpoint_path(
        &execution.state_directory,
        &format!(
            "host-{}-{}-{:016x}",
            identity.pid,
            identity.birth,
            rand::random::<u64>()
        ),
    )?;
    bootstrap.host_token = attachments::digest(
        format!(
            "{}\0{}\0{}\0{}",
            bootstrap.host_token, identity.pid, identity.birth, bootstrap.host_endpoint
        )
        .as_bytes(),
    );
    Ok(bootstrap)
}

fn pending_host_status(
    attempt: &PendingInjection,
    frida: &FridaCore,
    runtime: &Path,
    cleanup_transport: bool,
) -> Result<hyperhub_runtime::attachment::HostStatus, String> {
    if !attempt.dispatch_started {
        return Err("native injection was never dispatched".into());
    }
    attachments::verify_process(&attempt.identity)?;
    let status = || {
        attachments::manager_host_command(
            &attempt.bootstrap,
            &attempt.identity,
            HostCommand::Status,
            None,
        )
    };
    match status() {
        Ok(status) => Ok(status),
        Err(first) => {
            // This script only finds the already mapped, exact Native Base and
            // reopens its original bound transport. It never dlopens/injects a
            // replacement module or supplies another Bootstrap.
            let reopen = if cleanup_transport {
                frida.recover_transport_cleanup(
                    Process::from_pid(attempt.identity.pid)?,
                    runtime,
                    &attempt.identity,
                )
            } else {
                frida.exec_monitor(
                    Process::from_pid(attempt.identity.pid)?,
                    runtime,
                    super::super::frida_core::ExecMonitorAction::RecoverTransport,
                )
            };
            reopen.map_err(|error| {
                format!("{first}; cannot reopen pending Host transport: {error}")
            })?;
            status()
        }
    }
}

fn member_from_pending_status(
    attempt: &PendingInjection,
    status: &hyperhub_runtime::attachment::HostStatus,
    payload: &NativePayload,
) -> Result<Member, String> {
    if status.protocol != hyperhub_runtime::attachment::PROTOCOL
        || status.pid != attempt.identity.pid
        || status.attachment_id != attempt.bootstrap.attachment_id
    {
        return Err("pending Host initialization belongs to another process or attachment".into());
    }
    let initialization = status
        .initialization
        .as_ref()
        .ok_or("pending Host does not expose authenticated initialization evidence")?;
    let native_pin = initialization.native_pin.as_ref().map(|pin| NativePin {
        fd: pin.fd,
        device: pin.device,
        inode: pin.inode,
    });
    if native_pin
        .as_ref()
        .is_some_and(|pin| pin.fd < 0 || pin.device != payload.device || pin.inode != payload.inode)
    {
        return Err("pending Host native pin differs from approved payload".into());
    }
    let preparation_only =
        status.phase != HostPhase::Active && (!status.native_ready || !initialization.ever_active);
    if !preparation_only && native_pin.is_none() {
        return Err("active pending Host has no authenticated native pin".into());
    }
    let mut bootstrap = attempt.bootstrap.clone();
    bootstrap.approval_not_before_ms = bootstrap
        .approval_not_before_ms
        .max(status.approval_not_before_ms);
    bootstrap.approval_inherited_public_key = status
        .approval_public_key
        .or(bootstrap.approval_inherited_public_key);
    bootstrap.alias_inherited = status.alias_inheritance.clone();
    Ok(Member {
        identity: attempt.identity.clone(),
        bootstrap,
        native_pin,
        preparation_only,
    })
}

// These are retry diagnostics after scope cancellation, never evidence that a
// queued loader cannot run later and never permission to sign full completion.
fn missing_host_observation(
    expected: &ProcessIdentity,
    current: &ProcessIdentity,
    payload_mapped: bool,
    reason: &str,
) -> PendingObservation {
    if current.pid != expected.pid
        || current.birth != expected.birth
        || current.owner != expected.owner
    {
        return PendingObservation::Unknown {
            reason: "target incarnation or owner changed during recovery observation".into(),
        };
    }
    if payload_mapped {
        return PendingObservation::Unknown {
            reason: reason.to_owned(),
        };
    }
    if current.executable != expected.executable
        || current.executable_sha256 != expected.executable_sha256
    {
        PendingObservation::ReplacedImage {
            current: current.clone(),
        }
    } else {
        PendingObservation::PayloadAbsent
    }
}

fn observe_missing_host_after_fence(
    attempt: &PendingInjection,
    payload: &NativePayload,
    reason: &str,
) -> PendingObservation {
    let result = (|| {
        let current = inspect_attachment_target(attempt.identity.pid)?;
        let mapped = super::inspection::matches_pinned_agent(
            attempt.identity.pid,
            payload.device,
            payload.inode,
        )?;
        if inspect_attachment_target(attempt.identity.pid)? != current {
            return Err("target image changed during recovery observation".to_string());
        }
        Ok(missing_host_observation(
            &attempt.identity,
            &current,
            mapped,
            reason,
        ))
    })();
    result.unwrap_or_else(|error| PendingObservation::Unknown {
        reason: format!("{reason}; {error}"),
    })
}

fn reconcile_pending_hosts(
    execution: &Execution,
    frida: &FridaCore,
    runtime: &Path,
    payload: &NativePayload,
    handoff: &ForkHandoffBroker,
    members: &mut BTreeMap<u32, Member>,
    pending: &PendingInjections,
    scope_fenced: bool,
    cleanup_transport: bool,
) -> Vec<String> {
    let mut errors = Vec::new();
    let attempts = pending.borrow().clone();
    for attempt in attempts {
        if members
            .get(&attempt.identity.pid)
            .is_some_and(|member| member.identity == attempt.identity)
        {
            pending
                .borrow_mut()
                .retain(|old| old.identity != attempt.identity);
            continue;
        }
        if !attempt.dispatch_started {
            continue;
        }
        let result = (|| {
            if !publication_member_alive(&attempt.identity)? {
                pending
                    .borrow_mut()
                    .retain(|old| old.identity != attempt.identity);
                return Ok(());
            }
            let status = pending_host_status(&attempt, frida, runtime, cleanup_transport)?;
            let member = member_from_pending_status(&attempt, &status, payload)?;
            members.insert(member.identity.pid, member);
            pending
                .borrow_mut()
                .retain(|old| old.identity != attempt.identity);
            persist_context(execution, payload, handoff, members, pending)
        })();
        if let Err(error) = result {
            let observation = if scope_fenced {
                observe_missing_host_after_fence(&attempt, payload, &error)
            } else {
                PendingObservation::Unknown {
                    reason: error.clone(),
                }
            };
            if let Some(saved) = pending
                .borrow_mut()
                .iter_mut()
                .find(|saved| saved.identity == attempt.identity)
            {
                saved.observation = Some(observation);
            }
            errors.push(format!(
                "pending_injection_recovery:{}:{error}",
                attempt.identity.pid
            ));
        }
    }
    if let Err(error) = persist_context(execution, payload, handoff, members, pending) {
        errors.push(format!("pending_reconciliation_checkpoint_failed:{error}"));
    }
    errors
}
fn cleanup_members_snapshot(
    members: &BTreeMap<u32, Member>,
    pending: &PendingInjections,
) -> Vec<ProcessIdentity> {
    let mut result = members_snapshot(members);
    for attempt in pending.borrow().iter() {
        if !result.contains(&attempt.identity) {
            result.push(attempt.identity.clone());
        }
    }
    result.sort_by_key(|identity| identity.pid);
    result
}

fn preparation_affected_snapshot(
    attempted: &[ProcessIdentity],
    members: &BTreeMap<u32, Member>,
    pending: &PendingInjections,
) -> Vec<ProcessIdentity> {
    let mut result = cleanup_members_snapshot(members, pending);
    for identity in attempted {
        if !result.contains(identity) {
            result.push(identity.clone());
        }
    }
    result.sort_by_key(|identity| (identity.pid, identity.birth));
    result
}

fn cancel_pending_startups(
    execution: &Execution,
    grant: &Authorization,
    frida: &FridaCore,
    runtime: &Path,
    payload: &NativePayload,
    handoff: &ForkHandoffBroker,
    members: &mut BTreeMap<u32, Member>,
    pending: &PendingInjections,
) -> Vec<String> {
    let mut errors = reconcile_pending_hosts(
        execution, frida, runtime, payload, handoff, members, pending, true, true,
    );
    for member in members.values().filter(|member| member.preparation_only) {
        let result = (|| {
            if !publication_member_alive(&member.identity)? {
                return Ok(());
            }
            let status = host(member, HostCommand::Detach, Some(grant))?;
            let terminal = status
                .initialization
                .as_ref()
                .is_some_and(|startup| startup.cancelled && !startup.initializing);
            if !terminal {
                return Err("approved startup cancellation is still running".to_string());
            }
            // A cancelled startup releases only its original application gate.
            // This broker ACK is not an alias-prefix ACK or unload evidence.
            for candidate in handoff
                .snapshot()
                .map_err(|error| error.to_string())?
                .candidates
            {
                if candidate.child_pid == member.identity.pid
                    && candidate.child_birth == member.identity.birth
                {
                    handoff
                        .complete(candidate.lease_id)
                        .map_err(|error| error.to_string())?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            errors.push(format!(
                "startup_cleanup_pending:{}:{error}",
                member.identity.pid
            ));
        }
    }
    if let Err(error) = persist_context(execution, payload, handoff, members, pending) {
        errors.push(error);
    }
    errors
}

fn record_host_states(
    execution: &Execution,
    members: &BTreeMap<u32, Member>,
    previous: &mut Vec<u8>,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let values=members.values().map(|member|{
        match host(member,HostCommand::Status,None) {
            Ok(state)=>serde_json::json!({"pid":member.identity.pid,"birth":member.identity.birth,"available":true,"phase":state.phase,"active_calls":state.active_calls,"native_ready":state.native_ready,"control_workers":state.control_workers,"background_workers":state.background_workers,"pending_alias_publications":state.pending_alias_publications,"tracked_sockets":state.tracked_sockets,"fake_addresses":state.fake_addresses,"compatibility_reasons":state.compatibility_reasons}),
            Err(_)=>serde_json::json!({"pid":member.identity.pid,"birth":member.identity.birth,"available":false,"native_ready":false,"compatibility_reasons":["host_status_unavailable"]}),
        }
    }).collect::<Vec<_>>();
    let identity = serde_json::to_vec(&values).map_err(|error| error.to_string())?;
    if &identity == previous {
        return Ok(());
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let payload =
        serde_json::to_vec(&serde_json::json!({"sampled_at_unix_ns":timestamp,"hosts":values}))
            .map_err(|error| error.to_string())?;
    let temporary = execution.state_directory.join("host-states.next");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(&payload)
        .map_err(|error| error.to_string())?;
    drop(file);
    std::fs::rename(
        &temporary,
        execution.state_directory.join("host-states.json"),
    )
    .map_err(|error| error.to_string())?;
    *previous = identity;
    Ok(())
}
fn inject(
    frida: &FridaCore,
    runtime: &Path,
    execution: &Execution,
    identity: ProcessIdentity,
    handoff: &ForkHandoffBroker,
    fork: bool,
    new_image: bool,
    owned_child: bool,
    approval_not_before_ms: u64,
    inherited_approval_root: Option<[u8; 32]>,
    inherited_aliases: Option<hyperhub_runtime::attachment::AliasInheritance>,
    preparation_deadline: Option<PreparationDeadline>,
    journal: InjectionJournal<'_>,
    checkpoint: MemberCheckpoint<'_>,
) -> Result<Member, String> {
    let mut bootstrap = bootstrap_for(execution, &identity)?;
    bootstrap.initially_owned |= owned_child;
    bootstrap.approval_not_before_ms = bootstrap.approval_not_before_ms.max(approval_not_before_ms);
    bootstrap.approval_inherited_public_key =
        inherited_approval_root.or(bootstrap.approval_inherited_public_key);
    bootstrap.alias_inherited = inherited_aliases.or(bootstrap.alias_inherited);
    let environment = handoff.environment();
    let ready = execution.state_directory.join(format!(
        "ready-{}-{:016x}",
        identity.pid,
        rand::random::<u64>()
    ));
    let envelope = Envelope {
        bootstrap: &bootstrap,
        ready_path: ready
            .to_str()
            .ok_or("readiness path is not UTF-8")?
            .to_owned(),
        fork_socket: environment[0]
            .1
            .to_str()
            .ok_or("fork endpoint is not UTF-8")?
            .to_owned(),
        fork_secret: environment[1]
            .1
            .to_str()
            .ok_or("fork secret is not UTF-8")?
            .to_owned(),
        runtime_path: runtime
            .to_str()
            .ok_or("runtime path is not UTF-8")?
            .to_owned(),
    };
    let process = Process::from_pid(identity.pid)?;
    let attempt = PendingInjection {
        identity: identity.clone(),
        bootstrap: bootstrap.clone(),
        ready_path: envelope.ready_path.clone(),
        dispatch_started: false,
        observation: None,
    };
    let dispatch_guard =
        admit_native_dispatch(journal.cancellation.map(|(requested, _)| requested))?;
    journal.record(execution, handoff, attempt.clone())?;
    let bytes = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
    if bytes.len() > hyperhub_runtime::attachment::MAX_FRAME {
        return Err("attachment bootstrap exceeds native initialization frame bound".into());
    }
    let data = CString::new(bytes).map_err(|_| "attachment bootstrap contains NUL")?;
    let injection_timeout = preparation_deadline
        .map(PreparationDeadline::operation_timeout)
        .transpose()?
        .unwrap_or(ATTACH_INJECTION_TIMEOUT);
    dispatch_injection(
        attempt,
        |attempt| {
            let dispatched = attempt.dispatch_started;
            journal.record(execution, handoff, attempt)?;
            if !dispatched
                && journal
                    .cancellation
                    .is_some_and(|(requested, _)| requested.load(Ordering::Acquire))
            {
                return Err("approved cleanup interrupted native injection before dispatch".into());
            }
            Ok(())
        },
        || {
            frida
                .inject_with_timeout(
                    process,
                    runtime,
                    if fork {
                        "frida_attachment_fork_main"
                    } else {
                        "frida_attachment_main"
                    },
                    &data,
                    injection_timeout,
                )
                .map_err(|error| error.to_string())
        },
    )?;
    drop(dispatch_guard);
    let deadline = preparation_deadline
        .map(|deadline| deadline.deadline)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
    let mut receipt_pin = None;
    let mut receipt_seen = false;
    let native_pin = loop {
        if journal
            .cancellation
            .is_some_and(|(requested, _)| requested.load(Ordering::Acquire))
        {
            // The control thread already fenced the exact journal in Core.
            // Return ownership to the monitor, which can reopen and cancel the
            // original Host even when its first bind never succeeded.
            return Err("approved cleanup interrupted native initialization".into());
        }
        // The file only wakes/notifies the manager. The authenticated Host can
        // prove completion even when atomic receipt publication failed.
        if !receipt_seen && ready.exists() {
            if let Ok(bytes) = attachments::read_private_file(&ready, 8192) {
                receipt_seen = true;
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    if value.get("status").and_then(|status| status.as_str()) == Some("ok") {
                        receipt_pin = value
                            .get("native_pin")
                            .cloned()
                            .and_then(|pin| serde_json::from_value::<NativePin>(pin).ok());
                    }
                }
            }
        }
        if let Ok(status) =
            attachments::manager_host_command(&bootstrap, &identity, HostCommand::Status, None)
        {
            if let Some((requested, authorization)) = journal.cancellation {
                if requested.load(Ordering::Acquire) {
                    let authorization = authorization
                        .lock()
                        .map_err(|_| "attachment authorization state poisoned")?
                        .clone();
                    attachments::manager_host_command(
                        &bootstrap,
                        &identity,
                        HostCommand::Detach,
                        Some(&authorization),
                    )?;
                    return Err("approved cleanup cancelled native initialization".into());
                }
            }
            if let Some(initialization) = status.initialization.as_ref() {
                if !initialization.initializing {
                    if initialization.cancelled
                        || initialization.stage
                            != hyperhub_runtime::attachment::InitializationStage::Ready
                    {
                        return Err(initialization.error.clone().unwrap_or_else(|| {
                            "attachment initialization ended without native readiness".into()
                        }));
                    }
                    let pin = initialization
                        .native_pin
                        .as_ref()
                        .ok_or("completed attachment initialization has no native pin")?;
                    break NativePin {
                        fd: pin.fd,
                        device: pin.device,
                        inode: pin.inode,
                    };
                }
            } else if let Some(pin) = receipt_pin.take() {
                // Alpha contexts without initialization evidence retain their
                // successful-receipt path, still gated by a real Host reply.
                break pin;
            }
        }
        if !identity_alive(&identity) {
            return Err("target changed during Gum injection".into());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for authenticated attachment initialization".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if receipt_seen {
        let _ = std::fs::remove_file(&ready);
    }
    let mut member = Member {
        identity,
        bootstrap,
        native_pin: Some(native_pin),
        preparation_only: false,
    };
    if member.bootstrap.approval_core_public_key.is_some()
        || member.bootstrap.alias_inherited.is_some()
    {
        super::super::engine_control::control_runtime()?.block_on(
            attachments::catchup_alias_host(&member.bootstrap, &member.identity),
        )?;
    }
    let status = host(&member, HostCommand::Status, None)?;
    member.bootstrap.approval_not_before_ms = member
        .bootstrap
        .approval_not_before_ms
        .max(status.approval_not_before_ms);
    member.bootstrap.approval_inherited_public_key = status
        .approval_public_key
        .or(member.bootstrap.approval_inherited_public_key);
    member.bootstrap.alias_inherited = status.alias_inheritance;
    track_verified_member(member, checkpoint, |member| {
        // Only a real exec event proves the old image and its callbacks are gone.
        // Restore each interceptor layer in ownership order before enabling the
        // new Core monitor. Never perform this on a live inherited fork image.
        if new_image {
            if let Some(deadline) = preparation_deadline {
                frida
                    .exec_monitor_with_timeout(
                        process,
                        runtime,
                        super::super::frida_core::ExecMonitorAction::RemoveFresh,
                        deadline.operation_timeout()?,
                    )
                    .map_err(|error| error.to_string())?;
                frida
                    .disable_child_gating_with_timeout(process, deadline.operation_timeout()?)
                    .map_err(|error| error.to_string())?;
                frida
                    .exec_monitor_with_timeout(
                        process,
                        runtime,
                        super::super::frida_core::ExecMonitorAction::ReinstallFresh,
                        deadline.operation_timeout()?,
                    )
                    .map_err(|error| error.to_string())?;
            } else {
                frida.exec_monitor(
                    process,
                    runtime,
                    super::super::frida_core::ExecMonitorAction::RemoveFresh,
                )?;
                frida.disable_child_gating(process)?;
                frida.exec_monitor(
                    process,
                    runtime,
                    super::super::frida_core::ExecMonitorAction::ReinstallFresh,
                )?;
            }
        }
        if let Some(deadline) = preparation_deadline {
            frida
                .exec_monitor_with_timeout(
                    process,
                    runtime,
                    super::super::frida_core::ExecMonitorAction::Prepare,
                    deadline.operation_timeout()?,
                )
                .map_err(|error| error.to_string())?;
        } else {
            frida.exec_monitor(
                process,
                runtime,
                super::super::frida_core::ExecMonitorAction::Prepare,
            )?;
        }
        if execution.spec.scope == Scope::Tree {
            if let Some(deadline) = preparation_deadline {
                frida
                    .prepare_fork_listener_with_timeout(
                        process,
                        runtime,
                        deadline.operation_timeout()?,
                    )
                    .map_err(|error| error.to_string())?;
                frida
                    .enable_child_gating_with_timeout(process, deadline.operation_timeout()?)
                    .map_err(|error| error.to_string())?;
                frida
                    .arm_fork_listener_with_timeout(process, runtime, deadline.operation_timeout()?)
                    .map_err(|error| error.to_string())?;
            } else {
                frida.prepare_fork_listener(process, runtime)?;
                frida.enable_child_gating(process)?;
                frida.arm_fork_listener(process, runtime)?;
            }
            handoff
                .allow_parent(member.identity.pid, member.identity.birth)
                .map_err(|e| e.to_string())?;
        } else {
            // Core's creation monitor also supplies the root exec startup gate.
            // Its out-of-scope child events are resumed without policy enrollment.
            if let Some(deadline) = preparation_deadline {
                frida
                    .enable_child_gating_with_timeout(process, deadline.operation_timeout()?)
                    .map_err(|error| error.to_string())?;
                frida
                    .exec_monitor_with_timeout(
                        process,
                        runtime,
                        super::super::frida_core::ExecMonitorAction::Confirm,
                        deadline.operation_timeout()?,
                    )
                    .map_err(|error| error.to_string())?;
            } else {
                frida.enable_child_gating(process)?;
                frida.exec_monitor(
                    process,
                    runtime,
                    super::super::frida_core::ExecMonitorAction::Confirm,
                )?;
            }
        }
        Ok(())
    })
}
fn members_snapshot(members: &BTreeMap<u32, Member>) -> Vec<ProcessIdentity> {
    members
        .values()
        .map(|member| member.identity.clone())
        .collect()
}
fn prune_exited_members(members: &mut BTreeMap<u32, Member>) -> Result<(), String> {
    let mut exited = Vec::new();
    for member in members.values() {
        if !publication_member_alive(&member.identity)? {
            exited.push(member.identity.pid);
        }
    }
    for pid in exited {
        members.remove(&pid);
    }
    Ok(())
}

fn kernel_parent(pid: u32) -> Result<u32, String> {
    let stat =
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| error.to_string())?;
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(1))
        .and_then(|parent| parent.parse().ok())
        .ok_or_else(|| "cannot establish pending process parent".into())
}

pub(super) fn run(
    execution: &Execution,
    manager: &ProcessIdentity,
    endpoint: &str,
    detach: Arc<AtomicBool>,
    authorization: Arc<Mutex<Authorization>>,
) -> Result<(), String> {
    #[cfg(not(feature = "embedded-agent"))]
    {
        let _ = (execution, manager, endpoint, detach, authorization);
        Err("external live Gum attachment requires the Agent embedded in the administrator-approved CLI".into())
    }
    #[cfg(feature = "embedded-agent")]
    {
        let preflight = (|| -> Result<_, String> {
            let agent = crate::agent_runtime::AgentRuntime::embedded()?;
            agent.verify()?;
            // The load handle is an integrity-sealed /proc/PID/fd/N. Its
            // display path carries the shared-object extension used by the
            // same target/runtime preflight as ordinary run.
            super::super::validate_target_runtime(
                Path::new(&execution.spec.target.executable),
                agent.display_path(),
            )?;
            let frida = FridaCore::new()?;
            Ok((agent, frida))
        })();
        let (agent, frida) = match preflight {
            Ok(value) => value,
            Err(error) => {
                return reject_before_mutation(execution, manager, endpoint, error);
            }
        };
        run_with_runtime(
            execution,
            manager,
            endpoint,
            detach,
            authorization,
            &frida,
            agent.load_path(),
            false,
            None,
        )
    }
}
/// An accepted Attach also authorizes rollback while Core still proves that
/// no target mutation began. Writable status/recovery metadata cannot prove it.
fn reject_before_mutation(
    execution: &Execution,
    manager: &ProcessIdentity,
    endpoint: &str,
    error: String,
) -> Result<(), String> {
    if execution.origin == attachments::Origin::Attach {
        if let Err(rollback) = super::super::engine_control::control_runtime()?.block_on(
            attachments::abort_before_initial_mutation(execution, &error),
        ) {
            return Err(format!(
                "{error}; trusted pre-mutation rollback remains pending: {rollback}"
            ));
        }
    }
    outcome(
        execution,
        manager,
        endpoint,
        Phase::Failed,
        vec![],
        vec![if execution.origin == attachments::Origin::Attach {
            "verified_preparation_aborted_before_mutation".into()
        } else {
            "preflight_failed_before_target_mutation".into()
        }],
    )?;
    attachments::fail_record(&execution.state_directory, error.clone())?;
    Err(error)
}

fn run_with_runtime(
    execution: &Execution,
    manager: &ProcessIdentity,
    endpoint: &str,
    detach: Arc<AtomicBool>,
    authorization: Arc<Mutex<Authorization>>,
    frida: &FridaCore,
    runtime: &Path,
    resume_root: bool,
    ready: Option<mpsc::Sender<Result<(), String>>>,
) -> Result<(), String> {
    let pending = PendingInjections::default();
    // These operations only inspect metadata and create private manager resources.
    // Any failure remains on the Core-owned, abortable side of the mutation gate.
    let preflight = (|| -> Result<_, String> {
        let initial = member_snapshot(
            execution.spec.target.pid,
            execution.spec.scope == Scope::Tree,
        )?;
        if execution.origin == attachments::Origin::Attach {
            for identity in &initial {
                super::inspection::reject_incompatible_agent(identity.pid)?;
            }
        }
        let handoff = ForkHandoffBroker::new().map_err(|e| e.to_string())?;
        let payload = native_payload(runtime)?;
        // A failed private context write is still before any target operation.
        persist_context(execution, &payload, &handoff, &BTreeMap::new(), &pending)?;
        Ok((initial, handoff, payload))
    })();
    let (initial, handoff, payload) = match preflight {
        Ok(value) => value,
        Err(error) => return reject_before_mutation(execution, manager, endpoint, error),
    };
    let mut members = BTreeMap::new();
    // Persist conservative recovery metadata before target mutation, including
    // the currently empty Host set. It is not proof that later injection failed
    // without residue; only the signed abort gate provides that proof.
    if execution.origin == attachments::Origin::Attach {
        if let Err(error) = super::super::engine_control::control_runtime()?
            .block_on(attachments::begin_initial_mutation(execution))
        {
            return reject_before_mutation(execution, manager, endpoint, error);
        }
        super::super::engine_control::control_runtime()?
            .block_on(attachments::activate_session(execution, manager, &initial))?;
    }
    // Only dynamic attach has a bounded initial preparation transaction. Owned
    // `hyperhub run` startup retains its established unbounded request semantics.
    let preparation_deadline =
        (execution.origin == attachments::Origin::Attach).then(PreparationDeadline::new);
    let tree_deadline = preparation_deadline
        .map(|deadline| deadline.deadline)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(20));
    let mut attempted = initial.clone();
    // Arm creation tracking before taking a second tree snapshot. Pending new
    // children are enrolled by the same manager, never presumed to be covered.
    // Native early return listeners are installed before Core child gating.
    // A new fork observed during this preparation phase cannot be reported as
    // protected until it has an authenticated snapshot and completed recovery.
    let prepared = after_preparing_publication(
        || {
            if execution.origin != attachments::Origin::Attach {
                return Ok(());
            }
            // The accepted manager is observable before any target mutation.
            // Empty members deliberately avoid claiming injection or policy
            // installation has completed for any process.
            outcome(
                execution,
                manager,
                endpoint,
                Phase::Preparing,
                vec![],
                vec![],
            )
        },
        || -> Result<(), String> {
            for identity in initial {
                if detach.load(Ordering::Acquire) {
                    return Err("approved cleanup interrupted initial native preparation".into());
                }
                inject(
                    &frida,
                    runtime,
                    execution,
                    identity,
                    &handoff,
                    false,
                    false,
                    false,
                    execution.bootstrap.approval_not_before_ms,
                    None,
                    None,
                    preparation_deadline,
                    InjectionJournal {
                        payload: &payload,
                        members: members.clone(),
                        pending: &pending,
                        cancellation: Some((detach.as_ref(), authorization.as_ref())),
                    },
                    Some(&mut |member| {
                        members.insert(member.identity.pid, member.clone());
                        pending
                            .borrow_mut()
                            .retain(|attempt| attempt.identity != member.identity);
                        persist_context(execution, &payload, &handoff, &members, &pending)
                    }),
                )?;
            }
            loop {
                if Instant::now() >= tree_deadline {
                    return Err("tree did not reach a stable child-gated preparation point".into());
                }
                let gated_children = if let Some(deadline) = preparation_deadline {
                    frida
                        .pending_children_with_timeout(deadline.operation_timeout()?)
                        .map_err(|error| error.to_string())?
                } else {
                    frida
                        .pending_children()
                        .map_err(|error| error.to_string())?
                }
                .into_iter()
                .filter(|child| {
                    members.contains_key(&(child.parent_pid as u32))
                        || members.contains_key(&(child.process.pid() as u32))
                })
                .collect::<Vec<_>>();
                if execution.spec.scope == Scope::Tree
                    && gated_children
                        .iter()
                        .any(|child| child.origin == ChildOrigin::Fork)
                {
                    return Err("preparing tree produced an inherited fork without authenticated frozen runtime state; activation is incomplete".into());
                }
                for child in gated_children {
                    let pid = child.process.pid() as u32;
                    if execution.spec.scope == Scope::Process && pid != execution.spec.target.pid {
                        if let Some(deadline) = preparation_deadline {
                            frida
                                .resume_with_timeout(child.process, deadline.operation_timeout()?)
                                .map_err(|error| error.to_string())?;
                        } else {
                            frida.resume(child.process)?;
                        }
                        continue;
                    }
                    if members.contains_key(&pid) {
                        return Err("preparing member changed image before tree activation".into());
                    }
                    let identity = inspect_attachment_target(pid)?;
                    attempted.push(identity.clone());
                    super::super::launcher::register_fork_child(
                        &super::super::launcher::SessionCredentials {
                            endpoint: execution.bootstrap.control_endpoint.clone(),
                            session_id: execution.bootstrap.session_id.clone(),
                            token: execution.bootstrap.token.clone(),
                        },
                        child.parent_pid as u32,
                        child.process,
                    )?;
                    let parent_status = members
                        .get(&(child.parent_pid as u32))
                        .map(|parent| host(parent, HostCommand::Status, None))
                        .transpose()?;
                    inject(
                        &frida,
                        runtime,
                        execution,
                        identity,
                        &handoff,
                        false,
                        child.origin == ChildOrigin::Exec,
                        false,
                        execution.bootstrap.approval_not_before_ms,
                        parent_status
                            .as_ref()
                            .and_then(|status| status.approval_public_key),
                        parent_status.and_then(|status| status.alias_inheritance),
                        preparation_deadline,
                        InjectionJournal {
                            payload: &payload,
                            members: members.clone(),
                            pending: &pending,
                            cancellation: Some((detach.as_ref(), authorization.as_ref())),
                        },
                        Some(&mut |member| {
                            members.insert(member.identity.pid, member.clone());
                            pending
                                .borrow_mut()
                                .retain(|attempt| attempt.identity != member.identity);
                            persist_context(execution, &payload, &handoff, &members, &pending)
                        }),
                    )?;
                    if let Some(deadline) = preparation_deadline {
                        frida
                            .resume_with_timeout(child.process, deadline.operation_timeout()?)
                            .map_err(|error| error.to_string())?;
                    } else {
                        frida.resume(child.process)?;
                    }
                }
                let snapshot = member_snapshot(
                    execution.spec.target.pid,
                    execution.spec.scope == Scope::Tree,
                )?;
                let mut added = false;
                for identity in snapshot {
                    if !members.contains_key(&identity.pid) {
                        super::inspection::reject_incompatible_agent(identity.pid)?;
                        attempted.push(identity.clone());
                        inject(
                            &frida,
                            runtime,
                            execution,
                            identity,
                            &handoff,
                            false,
                            false,
                            false,
                            execution.bootstrap.approval_not_before_ms,
                            None,
                            None,
                            preparation_deadline,
                            InjectionJournal {
                                payload: &payload,
                                members: members.clone(),
                                pending: &pending,
                                cancellation: Some((detach.as_ref(), authorization.as_ref())),
                            },
                            Some(&mut |member| {
                                members.insert(member.identity.pid, member.clone());
                                pending
                                    .borrow_mut()
                                    .retain(|attempt| attempt.identity != member.identity);
                                persist_context(execution, &payload, &handoff, &members, &pending)
                            }),
                        )?;
                        added = true;
                    }
                }
                let remaining_children = if let Some(deadline) = preparation_deadline {
                    frida
                        .pending_children_with_timeout(deadline.operation_timeout()?)
                        .map_err(|error| error.to_string())?
                } else {
                    frida
                        .pending_children()
                        .map_err(|error| error.to_string())?
                }
                .into_iter()
                .filter(|child| {
                    members.contains_key(&(child.parent_pid as u32))
                        || members.contains_key(&(child.process.pid() as u32))
                })
                .count();
                if !added && remaining_children == 0 {
                    break;
                }
            }
            for member in members.values() {
                if detach.load(Ordering::Acquire) {
                    return Err("approved cleanup interrupted initial native activation".into());
                }
                if execution.origin == attachments::Origin::Attach {
                    host(
                        member,
                        HostCommand::Activate,
                        Some(&execution.authorization),
                    )?;
                } else if host(member, HostCommand::Status, None)?.phase != HostPhase::Active {
                    return Err(
                        "owned Gum startup did not establish parent-authorized active lifecycle"
                            .into(),
                    );
                }
            }
            let activation_pending = if let Some(deadline) = preparation_deadline {
                frida
                    .pending_children_with_timeout(deadline.operation_timeout()?)
                    .map_err(|error| error.to_string())?
            } else {
                frida
                    .pending_children()
                    .map_err(|error| error.to_string())?
            };
            if activation_pending
                .iter()
                .any(|child| members.contains_key(&(child.parent_pid as u32)))
            {
                return Err("tree activation has startup-held children awaiting authenticated bootstrap; partial activation requires cleanup".into());
            }
            if member_snapshot(
                execution.spec.target.pid,
                execution.spec.scope == Scope::Tree,
            )?
            .iter()
            .any(|identity| {
                members
                    .get(&identity.pid)
                    .is_none_or(|member| member.identity != *identity)
            }) {
                return Err("tree identity changed during per-member activation; partial activation requires cleanup".into());
            }
            Ok(())
        },
    );
    if let Err(error) = prepared {
        let mut reasons = vec![
            error.clone(),
            "preparation_may_have_mutated_listed_members".into(),
            "injected_module_retained_for_safe_cleanup".into(),
        ];
        let initial_affected = preparation_affected_snapshot(&attempted, &members, &pending);
        let initial_reasons = reasons.clone();
        let (cleanup_publication, reconciliation) = after_cleanup_pending_publication(
            || {
                outcome(
                    execution,
                    manager,
                    endpoint,
                    Phase::CleanupPending,
                    initial_affected,
                    initial_reasons,
                )
            },
            || {
                reconcile_pending_hosts(
                    execution,
                    frida,
                    runtime,
                    &payload,
                    &handoff,
                    &mut members,
                    &pending,
                    false,
                    true,
                )
            },
        );
        if let Err(publication) = cleanup_publication {
            reasons.push(format!("cleanup_pending_publication_failed:{publication}"));
        }
        reasons.extend(reconciliation);
        let mut cleanup_session_finished = false;
        loop {
            // A vanished incarnation cannot execute more application code and
            // needs no further Host/Frida cleanup. Ambiguous inspection errors
            // keep the member and therefore keep this manager resident.
            for pid in members.keys().copied().collect::<Vec<_>>() {
                let Some(member) = members.get(&pid) else {
                    continue;
                };
                match publication_member_alive(&member.identity) {
                    Ok(true) => {}
                    Ok(false) => {
                        members.remove(&pid);
                    }
                    Err(inspect) => {
                        reasons.push(format!("cleanup_member_liveness_unknown:{pid}:{inspect}"))
                    }
                }
            }
            pending
                .borrow_mut()
                .retain(|attempt| publication_member_alive(&attempt.identity).unwrap_or(true));

            if members.is_empty() && pending.borrow().is_empty() {
                match outcome(execution, manager, endpoint, Phase::Exited, vec![], vec![]) {
                    Ok(()) => return Ok(()),
                    Err(publication) => {
                        reasons.push(format!("cleanup_exited_publication_failed:{publication}"));
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                }
            }

            if cleanup_session_finished {
                let terminal = persist_context(execution, &payload, &handoff, &members, &pending)
                    .and_then(|()| {
                        outcome(
                            execution,
                            manager,
                            endpoint,
                            Phase::DetachedResident,
                            members_snapshot(&members),
                            vec![
                                "resident_native_module".into(),
                                format!("initial_preparation_failed:{error}"),
                            ],
                        )
                    });
                match terminal {
                    Ok(()) => {
                        return monitor_members(
                            execution,
                            manager,
                            endpoint,
                            detach,
                            authorization,
                            frida,
                            runtime,
                            &payload,
                            &handoff,
                            members,
                            pending,
                            true,
                        )
                    }
                    Err(publication) => {
                        reasons.push(format!("cleanup_terminal_publication_failed:{publication}"))
                    }
                }
                let mut published_reasons = vec![
                    error.clone(),
                    "cleanup_session_revoked_terminal_publication_pending".into(),
                ];
                published_reasons.append(&mut reasons);
                if let Err(publication) = outcome(
                    execution,
                    manager,
                    endpoint,
                    Phase::CleanupPending,
                    preparation_affected_snapshot(&attempted, &members, &pending),
                    published_reasons,
                ) {
                    reasons.push(format!("cleanup_pending_publication_failed:{publication}"));
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            // The manager listener may accept a new Detach while this
            // preparation-failure loop is already resident. Freeze one current
            // authorization for this whole cleanup round, but refresh it on
            // every retry. Keeping the original Attach forever would prevent
            // Core's detach fence from observing the later human approval.
            let cleanup_authorization = cleanup_authorization_for_round(authorization.as_ref())?;

            reasons.extend(cancel_pending_startups(
                execution,
                &cleanup_authorization,
                frida,
                runtime,
                &payload,
                &handoff,
                &mut members,
                &pending,
            ));

            let session_prepared = match super::super::engine_control::control_runtime()?.block_on(
                attachments::prepare_detach_session(execution, &cleanup_authorization, manager),
            ) {
                Ok(()) => true,
                Err(prepare) => {
                    reasons.push(format!("cleanup_session_fence_pending:{prepare}"));
                    false
                }
            };

            let member_pids = members.keys().copied().collect::<Vec<_>>();
            let attempt = if !session_prepared {
                PreparationCleanupAttempt {
                    complete: false,
                    reasons: Vec::new(),
                }
            } else if preparation_deadline.is_some() {
                ordered_preparation_cleanup_attempt(
                    &member_pids,
                    execution.spec.scope == Scope::Tree,
                    |pid| {
                        let member = members
                            .get(&pid)
                            .ok_or_else(|| format!("cleanup member {pid} disappeared"))?;
                        host(member, HostCommand::Detach, Some(&cleanup_authorization)).map(|_| ())
                    },
                    |pid| frida.abort_fork_listener(Process::from_pid(pid)?, runtime),
                    |pid| frida.disable_child_gating_cleanup(Process::from_pid(pid)?),
                    || {
                        frida.pending_children_cleanup().map(|children| {
                            children
                                .into_iter()
                                .map(|child| (child.parent_pid as u32, child.process.pid()))
                                .collect()
                        })
                    },
                    |pid| frida.resume_cleanup(Process::from_pid(pid as u32)?),
                )
            } else {
                ordered_preparation_cleanup_attempt(
                    &member_pids,
                    execution.spec.scope == Scope::Tree,
                    |pid| {
                        let member = members
                            .get(&pid)
                            .ok_or_else(|| format!("cleanup member {pid} disappeared"))?;
                        host(member, HostCommand::Detach, Some(&cleanup_authorization)).map(|_| ())
                    },
                    |pid| frida.abort_fork_listener(Process::from_pid(pid)?, runtime),
                    |pid| frida.disable_child_gating(Process::from_pid(pid)?),
                    || {
                        frida.pending_children().map(|children| {
                            children
                                .into_iter()
                                .map(|child| (child.parent_pid as u32, child.process.pid()))
                                .collect()
                        })
                    },
                    |pid| frida.resume(Process::from_pid(pid as u32)?),
                )
            };
            reasons.extend(attempt.reasons);

            if attempt.complete && pending.borrow().is_empty() {
                match super::super::engine_control::control_runtime()?.block_on(
                    attachments::finish_detach_session(execution, &cleanup_authorization, manager),
                ) {
                    Ok(true) => {
                        cleanup_session_finished = true;
                        if let Err(checkpoint) =
                            persist_context(execution, &payload, &handoff, &members, &pending)
                        {
                            reasons.push(format!("cleanup_final_checkpoint_pending:{checkpoint}"));
                        } else {
                            match outcome(
                                execution,
                                manager,
                                endpoint,
                                Phase::DetachedResident,
                                members_snapshot(&members),
                                vec![
                                    "resident_native_module".into(),
                                    format!("initial_preparation_failed:{error}"),
                                ],
                            ) {
                                Ok(()) => {
                                    return monitor_members(
                                        execution,
                                        manager,
                                        endpoint,
                                        detach,
                                        authorization,
                                        frida,
                                        runtime,
                                        &payload,
                                        &handoff,
                                        members,
                                        pending,
                                        true,
                                    )
                                }
                                Err(publication) => reasons.push(format!(
                                    "cleanup_terminal_publication_failed:{publication}"
                                )),
                            }
                        }
                    }
                    Ok(false) => reasons.push("cleanup_session_revocation_pending".into()),
                    Err(finish) => {
                        reasons.push(format!("cleanup_session_revocation_failed:{finish}"))
                    }
                }
            }

            let mut published_reasons = vec![
                error.clone(),
                "preparation_may_have_mutated_listed_members".into(),
                "injected_module_retained_for_safe_cleanup".into(),
            ];
            published_reasons.append(&mut reasons);
            if let Err(publication) = outcome(
                execution,
                manager,
                endpoint,
                Phase::CleanupPending,
                preparation_affected_snapshot(&attempted, &members, &pending),
                published_reasons,
            ) {
                reasons.push(format!("cleanup_pending_publication_failed:{publication}"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    persist_context(execution, &payload, &handoff, &members, &pending)?;
    outcome(
        execution,
        manager,
        endpoint,
        Phase::Active,
        members_snapshot(&members),
        vec![],
    )?;
    if resume_root {
        frida.resume(Process::from_pid(execution.spec.target.pid)?)?;
    }
    if let Some(ready) = ready {
        let _ = ready.send(Ok(()));
    }
    monitor_members(
        execution,
        manager,
        endpoint,
        detach,
        authorization,
        frida,
        runtime,
        &payload,
        &handoff,
        members,
        pending,
        false,
    )
}
fn monitor_members(
    execution: &Execution,
    manager: &ProcessIdentity,
    endpoint: &str,
    detach: Arc<AtomicBool>,
    authorization: Arc<Mutex<Authorization>>,
    frida: &FridaCore,
    runtime: &Path,
    payload: &NativePayload,
    handoff: &ForkHandoffBroker,
    mut members: BTreeMap<u32, Member>,
    pending: PendingInjections,
    mut detached: bool,
) -> Result<(), String> {
    // A logical Detach is not complete until every captured pre-cutoff child
    // has policy off and Core has released the global alias admission fence.
    let mut detach_finished = false;
    let mut last_handoff_diagnostic = Vec::new();
    let mut last_host_diagnostic = Vec::new();
    let host_diagnostics = std::env::var_os("HYPERHUB_ATTACHMENT_DIAGNOSTICS").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    loop {
        members.retain(|_, member| {
            super::super::syscall_supervisor::process_birth(member.identity.pid as i32)
                == Some(member.identity.birth)
                && std::fs::read_to_string(format!("/proc/{}/stat", member.identity.pid))
                    .ok()
                    .and_then(|s| {
                        s.rsplit_once(") ")
                            .and_then(|(_, tail)| tail.chars().next())
                    })
                    .is_some_and(|state| !matches!(state, 'Z' | 'X'))
        });
        pending
            .borrow_mut()
            .retain(|attempt| publication_member_alive(&attempt.identity).unwrap_or(true));
        if members.is_empty() && pending.borrow().is_empty() {
            outcome(execution, manager, endpoint, Phase::Exited, vec![], vec![])?;
            return Ok(());
        }
        let requested = detach.load(Ordering::Acquire);
        if requested != detached {
            super::super::frida_core::diagnostic_stage(
                "monitor_transition",
                None,
                if requested {
                    "detach_observed"
                } else {
                    "activate_observed"
                },
            );
            detach_finished = false;
            let grant = authorization
                .lock()
                .map_err(|_| "attachment authorization state poisoned")?
                .clone();
            if requested {
                let needs_startup_cancellation = !pending.borrow().is_empty()
                    || members.values().any(|member| member.preparation_only);
                let reasons = detach_transition_fence(
                    needs_startup_cancellation,
                    || {
                        cancel_pending_startups(
                            execution,
                            &grant,
                            frida,
                            runtime,
                            payload,
                            handoff,
                            &mut members,
                            &pending,
                        )
                    },
                    || {
                        super::super::engine_control::control_runtime()?.block_on(
                            attachments::prepare_detach_session(execution, &grant, manager),
                        )
                    },
                );
                if !reasons.is_empty() {
                    outcome(
                        execution,
                        manager,
                        endpoint,
                        Phase::CleanupPending,
                        cleanup_members_snapshot(&members, &pending),
                        reasons,
                    )?;
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
            }
            if !requested {
                for member in members.values() {
                    let process = Process::from_pid(member.identity.pid)?;
                    if execution.spec.scope == Scope::Tree {
                        frida.prepare_fork_listener(process, runtime)?;
                    }
                    frida.exec_monitor(
                        process,
                        runtime,
                        super::super::frida_core::ExecMonitorAction::Prepare,
                    )?;
                    frida.enable_child_gating(process)?;
                    if execution.spec.scope != Scope::Tree {
                        frida.exec_monitor(
                            process,
                            runtime,
                            super::super::frida_core::ExecMonitorAction::Confirm,
                        )?;
                    }
                    if execution.spec.scope == Scope::Tree {
                        frida.arm_fork_listener(process, runtime)?;
                    }
                }
            }
            for member in members.values_mut() {
                super::super::frida_core::diagnostic_stage(
                    "monitor_transition",
                    Some(member.identity.pid as i32),
                    if requested {
                        "host_detach_begin"
                    } else {
                        "host_activate_begin"
                    },
                );
                let status = host(
                    member,
                    if requested {
                        HostCommand::Detach
                    } else {
                        HostCommand::Activate
                    },
                    Some(&grant),
                )?;
                super::super::frida_core::diagnostic_stage(
                    "monitor_transition",
                    Some(member.identity.pid as i32),
                    if requested {
                        "host_detach_complete"
                    } else {
                        "host_activate_complete"
                    },
                );
                member.bootstrap.approval_not_before_ms = member
                    .bootstrap
                    .approval_not_before_ms
                    .max(status.approval_not_before_ms);
                member.bootstrap.approval_inherited_public_key = status
                    .approval_public_key
                    .or(member.bootstrap.approval_inherited_public_key);
                member.bootstrap.alias_inherited = status.alias_inheritance;
            }
            persist_context(execution, payload, handoff, &members, &pending)?;
            if requested {
                // The Host first stops new fork reservations. Already admitted
                // reservations are completed below before child gating retires.
                outcome(
                    execution,
                    manager,
                    endpoint,
                    Phase::Detaching,
                    members_snapshot(&members),
                    vec![],
                )?;
            } else {
                outcome(
                    execution,
                    manager,
                    endpoint,
                    Phase::Active,
                    members_snapshot(&members),
                    vec![],
                )?;
            }
            detached = requested;
        }
        if host_diagnostics {
            // Observation is optional. Exec legitimately removes a member's
            // old listener, and diagnostic IO failures must never stop the
            // executor or abandon a Core startup gate. Missing fresh evidence
            // makes the diagnostic driver fail its barrier instead.
            let _ = record_host_states(execution, &members, &mut last_host_diagnostic);
        }
        let snapshot = handoff.snapshot().map_err(|e| e.to_string())?;
        let mut gated_children = frida.pending_children()?;
        if detached && (snapshot.pending_count != 0 || !gated_children.is_empty()) {
            detach_finished = false;
            outcome(
                execution,
                manager,
                endpoint,
                Phase::Detaching,
                members_snapshot(&members),
                vec!["captured_children_pending_detach".into()],
            )?;
        }
        let diagnostic=serde_json::to_vec(&serde_json::json!({"pending_reservations":snapshot.pending_count,"candidates":snapshot.candidates.iter().map(|candidate|serde_json::json!({"parent_pid":candidate.parent_pid,"child_pid":candidate.child_pid,"child_birth":candidate.child_birth,"ready":candidate.ready})).collect::<Vec<_>>(),"core_children":gated_children.iter().map(|child|serde_json::json!({"pid":child.process.pid(),"parent_pid":child.parent_pid,"origin":format!("{:?}",child.origin)})).collect::<Vec<_>>() })).map_err(|error|error.to_string())?;
        if diagnostic != last_handoff_diagnostic {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let path = execution.state_directory.join("handoff-progress.json");
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
            {
                let _ = file.write_all(&diagnostic);
            }
            last_handoff_diagnostic = diagnostic;
        }
        for candidate in snapshot
            .candidates
            .iter()
            .filter(|candidate| candidate.ready)
        {
            if !gated_children
                .iter()
                .any(|child| child.process.pid() as u32 == candidate.child_pid)
            {
                gated_children.push(super::super::frida_core::PendingChild {
                    process: Process::from_pid(candidate.child_pid)?,
                    parent_pid: candidate.parent_pid as i32,
                    origin: ChildOrigin::Fork,
                    skip_agent: false,
                });
            }
        }
        for mut child in gated_children {
            let pid = child.process.pid() as u32;
            if pending
                .borrow()
                .iter()
                .any(|attempt| attempt.identity.pid == pid)
            {
                // A prior dispatch is still owned. Only approved startup
                // cleanup may cancel it; never stack another SDK entry.
                continue;
            }
            // Exec events can identify the execing process itself as parent.
            // In particular, libc posix_spawn may reach this monitor only at
            // its exec boundary. Classify its actual kernel ancestry instead
            // of leaving an unrecognized, startup-held native child suspended.
            if child.origin == ChildOrigin::Exec && child.parent_pid as u32 == pid {
                child.parent_pid = match kernel_parent(pid) {
                    Ok(parent) => parent as i32,
                    Err(_) => continue,
                };
            }
            let known =
                members.contains_key(&(child.parent_pid as u32)) || members.contains_key(&pid);
            if !known
                && !super::super::syscall_supervisor::attachment_process_tree(
                    execution.spec.target.pid,
                    true,
                )?
                .contains(&pid)
            {
                continue;
            }
            if execution.spec.scope == Scope::Process && pid != execution.spec.target.pid {
                // The exec monitor is required for the approved process; its
                // fork/child events do not authorize enrolling descendants.
                frida.resume(child.process)?;
                continue;
            }
            if detached && child.origin != ChildOrigin::Fork {
                let _ = frida.resume(child.process);
                continue;
            }
            let identity = match inspect_attachment_target(pid) {
                Ok(identity) => identity,
                Err(_) => continue,
            };
            if child.origin == ChildOrigin::Exec && pid == execution.spec.target.pid {
                let previous = members
                    .get(&pid)
                    .ok_or("root exec has no previously verified process identity")?;
                // Core's exec startup gate still holds the original process.
                // Advance the authoritative epoch even when the ELF is the
                // same; a grant issued before this exec must not affect it.
                let transition_nonce = rand::random::<[u8; 32]>();
                super::super::engine_control::control_runtime()?.block_on(
                    attachments::report_attachment_exec(
                        execution,
                        manager,
                        &previous.identity,
                        &identity,
                        transition_nonce,
                    ),
                )?;
            }
            let candidate = if child.origin == ChildOrigin::Fork {
                let latest = handoff.snapshot().map_err(|e| e.to_string())?;
                let candidate = latest
                    .candidates
                    .into_iter()
                    .find(|candidate| {
                        candidate.child_pid == pid
                            && candidate.parent_pid == child.parent_pid as u32
                    })
                    .ok_or("fork child has no authenticated reservation")?;
                super::super::launcher::register_fork_child(
                    &super::super::launcher::SessionCredentials {
                        endpoint: execution.bootstrap.control_endpoint.clone(),
                        session_id: execution.bootstrap.session_id.clone(),
                        token: execution.bootstrap.token.clone(),
                    },
                    child.parent_pid as u32,
                    child.process,
                )?;
                frida.enable_child_gating(child.process)?;
                handoff
                    .mark_attached(candidate.lease_id)
                    .map_err(|e| e.to_string())?;
                // Core waits for permission before completing its fork return
                // listener. Retain ownership first, then let Core finish while
                // our native return gate continues to hold application code.
                // Rebuilding the Agent before that READY races Core globals.
                frida.resume(child.process)?;
                handoff
                    .wait_ready(candidate.lease_id)
                    .map_err(|e| e.to_string())?;
                Some(candidate)
            } else {
                None
            };
            let attempted_child = identity.clone();
            let parent = if candidate.is_none() {
                members
                    .get(&(child.parent_pid as u32))
                    .or_else(|| members.get(&pid))
            } else {
                None
            };
            let parent_status = if candidate.is_none() {
                parent
                    // Exec of an already managed PID has removed its old
                    // private listener. Its last OS-verified binding remains
                    // the creator provenance; the new Host must catch up from
                    // Core before becoming native-ready.
                    .filter(|parent| parent.identity.pid != pid)
                    .map(|parent| host(parent, HostCommand::Status, None))
                    .transpose()?
            } else {
                None
            };
            // A real fork retains the exact parent's cutoff at COW time.
            // Do not raise it to a later pending parent Detach: the same grant
            // must still be applicable to this already-admitted child.
            let approval_floor = if candidate.is_some() {
                0
            } else {
                parent_status.as_ref().map_or(
                    parent.map_or(execution.bootstrap.approval_not_before_ms, |parent| {
                        parent.bootstrap.approval_not_before_ms
                    }),
                    |status| status.approval_not_before_ms,
                )
            };
            let member = match inject(
                &frida,
                runtime,
                execution,
                identity,
                &handoff,
                candidate.is_some(),
                child.origin == ChildOrigin::Exec,
                true,
                approval_floor,
                parent_status
                    .as_ref()
                    .and_then(|status| status.approval_public_key)
                    .or_else(|| {
                        parent.and_then(|parent| {
                            parent
                                .bootstrap
                                .approval_inherited_public_key
                                .or(parent.bootstrap.approval_public_key)
                        })
                    }),
                parent_status
                    .and_then(|status| status.alias_inheritance)
                    .or_else(|| parent.and_then(|parent| parent.bootstrap.alias_inherited.clone())),
                None,
                InjectionJournal {
                    payload,
                    members: members.clone(),
                    pending: &pending,
                    cancellation: Some((detach.as_ref(), authorization.as_ref())),
                },
                None,
            ) {
                Ok(member) => member,
                Err(error) => {
                    // Keep the live manager and the exact journal after a
                    // failed child startup. Its original return gate stays
                    // protected until a newly accepted Detach cancels it.
                    let mut affected = cleanup_members_snapshot(&members, &pending);
                    if !affected.contains(&attempted_child) {
                        affected.push(attempted_child);
                    }
                    outcome(
                        execution,
                        manager,
                        endpoint,
                        Phase::CleanupPending,
                        affected,
                        vec![format!("child_handoff_failed:{pid}:{error}")],
                    )?;
                    continue;
                }
            };
            let grant = authorization
                .lock()
                .map_err(|_| "attachment authorization state poisoned")?
                .clone();
            if detached {
                host(&member, HostCommand::Detach, Some(&grant))?;
            } else if host(&member, HostCommand::Status, None)?.phase != HostPhase::Active {
                return Err(
                    "new approved-tree child did not activate under creation ownership".into(),
                );
            }
            let core_resumed = candidate.is_some();
            if let Some(candidate) = candidate {
                handoff
                    .complete(candidate.lease_id)
                    .map_err(|e| e.to_string())?;
                let published = execution
                    .state_directory
                    .join(format!("publish-{pid}-{:016x}", rand::random::<u64>()));
                if let Err(error) = frida.inject_with_timeout(
                    child.process,
                    runtime,
                    "frida_fork_publish_main",
                    &CString::new(published.as_os_str().as_encoded_bytes())
                        .map_err(|_| "invalid publish path")?,
                    ATTACH_INJECTION_TIMEOUT,
                ) {
                    if !publication_member_alive(&member.identity)? {
                        continue;
                    }
                    return Err(error.to_string());
                }
                if !wait_fork_publication(&published, &member.identity)? {
                    // Exit is normal member retirement, not a fabricated ACK.
                    // Keep supervising the remaining approved process tree.
                    continue;
                }
                if !publication_member_alive(&member.identity)? {
                    continue;
                }
            }
            if !core_resumed {
                frida.resume(child.process)?;
            }
            members.insert(pid, member);
            pending
                .borrow_mut()
                .retain(|attempt| attempt.identity.pid != pid);
            if detached {
                detach_finished = false;
            }
            persist_context(execution, &payload, &handoff, &members, &pending)?;
            outcome(
                execution,
                manager,
                endpoint,
                if detached {
                    Phase::Detaching
                } else {
                    Phase::Active
                },
                members_snapshot(&members),
                vec![],
            )?;
        }
        if detached && handoff.snapshot().map_err(|e| e.to_string())?.pending_count == 0 {
            // The broker proves no reserved native fork remains. Frida's own
            // startup queue must also be empty before Core checks every live
            // Host's spawn/publication counters and finishes this exact nonce.
            if !frida.pending_children()?.is_empty() {
                detach_finished = false;
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            if !detach_finished {
                let attempts = pending.borrow().clone();
                for attempt in attempts
                    .into_iter()
                    .filter(|attempt| attempt.dispatch_started)
                {
                    if !publication_member_alive(&attempt.identity)? {
                        pending
                            .borrow_mut()
                            .retain(|old| old.identity != attempt.identity);
                    }
                }
                if pending
                    .borrow()
                    .iter()
                    .any(|attempt| attempt.dispatch_started)
                {
                    return Err(
                        "live native injection attempts remain outside verified detach membership"
                            .into(),
                    );
                }
                let grant = authorization
                    .lock()
                    .map_err(|_| "attachment authorization state poisoned")?
                    .clone();
                detach_finished = super::super::engine_control::control_runtime()?.block_on(
                    attachments::finish_detach_session(execution, &grant, manager),
                )?;
                if !detach_finished {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                pending.borrow_mut().clear();
                persist_context(execution, payload, handoff, &members, &pending)?;
            }
            let mut reasons = std::collections::BTreeSet::new();
            for member in members.values() {
                frida.disable_child_gating(Process::from_pid(member.identity.pid)?)?;
                let status = host(member, HostCommand::Status, None)?;
                reasons.extend(status.compatibility_reasons);
                if status.phase != HostPhase::Detached {
                    reasons.insert("resident_native_module".into());
                }
            }
            // Physical dlclose is never inferred from hook removal. Frida's
            // resident module still owns native callbacks and remains visible.
            outcome(
                execution,
                manager,
                endpoint,
                Phase::DetachedResident,
                members_snapshot(&members),
                reasons.into_iter().collect(),
            )?;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn detach_transition_fence(
    needs_startup_cancellation: bool,
    cancel_pending: impl FnOnce() -> Vec<String>,
    prepare_session: impl FnOnce() -> Result<(), String>,
) -> Vec<String> {
    let mut reasons = if needs_startup_cancellation {
        cancel_pending()
    } else {
        Vec::new()
    };
    if reasons.is_empty() {
        if let Err(error) = prepare_session() {
            reasons.push(error);
        }
    }
    reasons
}

/// Foreground `run` keeps relaying its original terminal and waiting for its
/// original exit status while this background manager services approvals.
pub(crate) struct OwnedGumMonitor {
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}
impl OwnedGumMonitor {
    pub(crate) fn start(
        execution: Execution,
        frida: FridaCore,
        runtime: PathBuf,
    ) -> Result<Self, String> {
        let manager = inspect_attachment_target(std::process::id())?;
        let detach = Arc::new(AtomicBool::new(false));
        let listener = ManagerListener::start(&execution, detach.clone())?;
        let (send, receive) = mpsc::channel();
        let failure = send.clone();
        let thread = std::thread::Builder::new()
            .name("hyperhub-owned-gum".into())
            .spawn(move || {
                let result = run_with_runtime(
                    &execution,
                    &manager,
                    &listener.endpoint,
                    detach,
                    listener.authorization.clone(),
                    &frida,
                    &runtime,
                    true,
                    Some(send),
                );
                if let Err(error) = &result {
                    let _ = attachments::record_execution_error(
                        &execution.state_directory,
                        error.clone(),
                    );
                    let _ = failure.send(Err(error.clone()));
                }
                result
            })
            .map_err(|e| e.to_string())?;
        receive
            .recv_timeout(Duration::from_secs(35))
            .map_err(|_| "owned Gum initialization did not complete".to_string())??;
        Ok(Self {
            thread: Some(thread),
        })
    }
    pub(crate) fn stop(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn duplicate_native_pin(member: &Member, payload: &NativePayload) -> Result<std::fs::File, String> {
    use std::os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{FileExt, MetadataExt},
    };
    let native_pin = member
        .native_pin
        .as_ref()
        .ok_or("preparing Host has no pinned native payload")?;
    if !identity_alive(&member.identity)
        || native_pin.device != payload.device
        || native_pin.inode != payload.inode
    {
        return Err("resident native pin identity changed".into());
    }
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, member.identity.pid, 0) } as i32;
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            descriptor.as_raw_fd(),
            native_pin.fd,
            0,
        )
    } as i32;
    if fd < 0 {
        return Err(format!(
            "cannot duplicate resident native pin: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if metadata.dev() != payload.device
        || metadata.ino() != payload.inode
        || metadata.len() != payload.size
        || seals & required != required
        || payload.size > 256 * 1024 * 1024
    {
        return Err("resident payload is not the exact immutable approved inode".into());
    }
    let mut bytes = vec![0; payload.size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = file
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("resident native payload is truncated".into());
        }
        offset += count;
    }
    if attachments::digest(&bytes) != payload.sha256
        || !super::inspection::matches_pinned_agent(
            member.identity.pid,
            payload.device,
            payload.inode,
        )?
    {
        return Err("resident mapped native payload identity cannot be proven".into());
    }
    Ok(file)
}

pub(super) fn recover(
    execution: &Execution,
    record: &Record,
    context: serde_json::Value,
) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let context: GumRecovery =
        serde_json::from_value(context).map_err(|error| error.to_string())?;
    if context.schema != 1 || context.backend != "gum" {
        return Err("resident recovery context is incompatible".into());
    }
    let recovery_payload: crate::agent_runtime::AgentRuntime = {
        #[cfg(feature = "embedded-agent")]
        {
            let expected = crate::agent_runtime::AgentRuntime::embedded()?;
            expected.verify()?;
            let bytes = std::fs::read(expected.load_path()).map_err(|error| error.to_string())?;
            if attachments::digest(&bytes) != context.payload.sha256 {
                return Err(
                    "resident native base requires the original compatible embedded CLI payload"
                        .into(),
                );
            }
            expected
        }
        #[cfg(not(feature = "embedded-agent"))]
        {
            return Err(
                "resident recovery requires an authenticated embedded Agent payload".into(),
            );
        }
    };
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if context.payload.seals & required != required {
        return Err(
            "mutable native payload cannot be recovered as an immutable compatible base".into(),
        );
    }
    let pending = RefCell::new(context.pending_injections);
    let handoff = ForkHandoffBroker::restore(context.broker).map_err(|error| error.to_string())?;
    let frida = FridaCore::new()?;
    let removing = matches!(
        execution.authorization.request.action,
        Action::Detach { .. }
    );
    for attempt in pending.borrow().iter() {
        if (!removing && !record.members.contains(&attempt.identity))
            || attempt.bootstrap.attachment_id != execution.spec.id
            || attempt.bootstrap.session_id != execution.bootstrap.session_id
        {
            return Err("pending native injection differs from approved recovery scope".into());
        }
    }
    let mut members = BTreeMap::new();
    for member in context.members {
        if super::super::syscall_supervisor::process_birth(member.identity.pid as i32)
            != Some(member.identity.birth)
        {
            continue;
        }
        if !removing && !record.members.contains(&member.identity) {
            return Err("resident Host was not a known approved member".into());
        }
        members.insert(member.identity.pid, member);
    }
    prune_exited_members(&mut members)?;
    let attempts = pending.borrow().clone();
    for attempt in attempts {
        if !publication_member_alive(&attempt.identity)? {
            pending
                .borrow_mut()
                .retain(|old| old.identity != attempt.identity);
        }
    }
    if !removing
        && (!pending.borrow().is_empty() || members.values().any(|member| member.preparation_only))
    {
        return Err(
            "unfinished native initialization requires approved cleanup before activation".into(),
        );
    }
    let manager = inspect_attachment_target(std::process::id())?;
    if removing {
        // Authorize the complete raw roster before touching a pending target.
        // Core binds its original members, fences new registration/activation,
        // and keeps unreachable endpoints as unproven cleanup locators.
        let mut hosts = members
            .values()
            .map(|member| {
                (
                    member.identity.pid,
                    attachments::HostBootstrapBinding {
                        identity: member.identity.clone(),
                        bootstrap: member.bootstrap.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut unstarted = Vec::new();
        for attempt in pending.borrow().iter() {
            let binding = attachments::HostBootstrapBinding {
                identity: attempt.identity.clone(),
                bootstrap: attempt.bootstrap.clone(),
            };
            if attempt.dispatch_started {
                if let Some(existing) = hosts.get(&attempt.identity.pid) {
                    if existing.identity != binding.identity
                        || existing.bootstrap.host_endpoint != binding.bootstrap.host_endpoint
                        || existing.bootstrap.host_token != binding.bootstrap.host_token
                    {
                        return Err(
                            "pending cleanup roster contains conflicting native image bindings"
                                .into(),
                        );
                    }
                } else {
                    hosts.insert(attempt.identity.pid, binding);
                }
            } else {
                unstarted.push(binding);
            }
        }
        let hosts = hosts.into_values().collect::<Vec<_>>();
        let identities = hosts
            .iter()
            .map(|host| host.identity.clone())
            .collect::<Vec<_>>();
        super::super::engine_control::control_runtime()?.block_on(
            attachments::recover_session_with_startup_cleanup(
                execution,
                &manager,
                &identities,
                &hosts,
                &unstarted,
            ),
        )?;
    }
    let errors = reconcile_pending_hosts(
        execution,
        &frida,
        recovery_payload.load_path(),
        &context.payload,
        &handoff,
        &mut members,
        &pending,
        removing,
        removing,
    );
    if !removing && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let unresolved_dispatch = pending
        .borrow()
        .iter()
        .any(|attempt| attempt.dispatch_started);
    if !removing && unresolved_dispatch {
        return Err("native injection recovery remains pending".into());
    }
    if !removing
        && (!pending.borrow().is_empty() || members.values().any(|member| member.preparation_only))
    {
        return Err(
            "unfinished native initialization requires approved cleanup before activation".into(),
        );
    }
    let mut pin = None;
    for member in members.values_mut() {
        let status = host(member, HostCommand::Status, None)?;
        if removing
            && status.phase != HostPhase::Active
            && status
                .initialization
                .as_ref()
                .is_some_and(|startup| !status.native_ready || !startup.ever_active)
        {
            member.preparation_only = true;
        }
        if !member.preparation_only {
            let file = duplicate_native_pin(member, &context.payload)?;
            if pin.is_none() {
                pin = Some(file);
            }
        }
        member.bootstrap.approval_not_before_ms = member
            .bootstrap
            .approval_not_before_ms
            .max(status.approval_not_before_ms);
        member.bootstrap.approval_inherited_public_key = status
            .approval_public_key
            .or(member.bootstrap.approval_inherited_public_key);
        member.bootstrap.alias_inherited = status.alias_inheritance;
    }
    if members.is_empty() && (!removing || pending.borrow().is_empty()) {
        return Err("no surviving authenticated resident Host".into());
    }
    // Tree completeness prevents stacking during activation. Cleanup must still
    // cancel an authenticated never-active Host when another child is unknown.
    if !removing && execution.spec.scope == Scope::Tree {
        for member in members.values() {
            for pid in super::super::syscall_supervisor::attachment_process_tree(
                member.identity.pid,
                true,
            )? {
                if !members.contains_key(&pid) {
                    return Err("tree contains an unproven process created while management was unavailable; refusing stacked injection".into());
                }
            }
        }
    }
    let runtime = pin
        .as_ref()
        .map(|file| {
            PathBuf::from(format!(
                "/proc/{}/fd/{}",
                std::process::id(),
                file.as_raw_fd(),
            ))
        })
        .unwrap_or_else(|| recovery_payload.load_path().to_owned());
    let unstarted = pending
        .borrow()
        .iter()
        .filter(|attempt| !attempt.dispatch_started)
        .map(|attempt| attachments::HostBootstrapBinding {
            identity: attempt.identity.clone(),
            bootstrap: attempt.bootstrap.clone(),
        })
        .collect::<Vec<_>>();
    if !removing {
        super::super::engine_control::control_runtime()?.block_on(attachments::recover_session(
            execution,
            &manager,
            &members_snapshot(&members),
        ))?;
    }
    if matches!(
        execution.authorization.request.action,
        Action::Detach { .. }
    ) {
        // Cancellation must reach a never-active Host even when its unknown
        // inherited resources cannot satisfy the later Core drain barrier.
        // This changes policy only under the newly accepted Detach proof.
        let preparing = members
            .values()
            .filter(|member| member.preparation_only)
            .cloned()
            .collect::<Vec<_>>();
        for member in &preparing {
            if !publication_member_alive(&member.identity)? {
                continue;
            }
            if let Err(error) = host(member, HostCommand::Detach, Some(&execution.authorization)) {
                if !publication_member_alive(&member.identity)? {
                    continue;
                }
                return Err(error);
            }
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let status = match host(member, HostCommand::Status, None) {
                    Ok(status) => status,
                    Err(_) if !publication_member_alive(&member.identity)? => break,
                    Err(error) => return Err(error),
                };
                if status
                    .initialization
                    .as_ref()
                    .is_some_and(|startup| !startup.initializing)
                {
                    break;
                }
                if Instant::now() >= deadline {
                    persist_context(execution, &context.payload, &handoff, &members, &pending)?;
                    return Err(
                        "startup cancellation remains pending; native recovery context retained"
                            .into(),
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        prune_exited_members(&mut members)?;
        persist_context(execution, &context.payload, &handoff, &members, &pending)?;
        // An unreachable dispatched attempt stays fenced and unproven. It must
        // not prevent cancellation of other authenticated never-active Hosts,
        // and must not be omitted from a later full-completion roster.
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        if unresolved_dispatch {
            return Err("native injection recovery remains pending".into());
        }
        // Refresh the same scoped locators after cancellation. Only Core may
        // promote a real terminal Fresh/empty prefix; unknown inherited state
        // remains pending and must not acquire a fabricated completion receipt.
        let hosts = members
            .values()
            .map(|member| attachments::HostBootstrapBinding {
                identity: member.identity.clone(),
                bootstrap: member.bootstrap.clone(),
            })
            .collect::<Vec<_>>();
        super::super::engine_control::control_runtime()?.block_on(
            attachments::recover_session_with_startup_cleanup(
                execution,
                &manager,
                &members_snapshot(&members),
                &hosts,
                &unstarted,
            ),
        )?;
        persist_context(execution, &context.payload, &handoff, &members, &pending)?;
        super::super::engine_control::control_runtime()?.block_on(
            attachments::prepare_detach_session(execution, &execution.authorization, &manager),
        )?;
    }
    if members.is_empty() {
        if !super::super::engine_control::control_runtime()?.block_on(
            attachments::finish_detach_session(execution, &execution.authorization, &manager),
        )? {
            return Err("undispatched native cleanup has pending Core members".into());
        }
        pending.borrow_mut().clear();
        persist_context(execution, &context.payload, &handoff, &members, &pending)?;
        super::remove_dead_manager_endpoint(execution, record)?;
        outcome(
            execution,
            &manager,
            "",
            Phase::Detached,
            vec![],
            vec!["native_injection_never_dispatched".into()],
        )?;
        return Ok(());
    }
    super::remove_dead_manager_endpoint(execution, record)?;
    attachments::update_spec(&execution.state_directory, &execution.spec)?;
    let detach = Arc::new(AtomicBool::new(removing));
    let listener = ManagerListener::start(execution, detach.clone())?;
    outcome(
        execution,
        &manager,
        &listener.endpoint,
        Phase::Preparing,
        members_snapshot(&members),
        vec![],
    )?;
    for member in members.values_mut() {
        if removing && member.preparation_only {
            // A failed/unready initialization is only rolled back. Installing
            // fork/exec tracking here would create new mutation during cleanup.
        } else if execution.spec.scope == Scope::Tree {
            let process = Process::from_pid(member.identity.pid)?;
            frida.prepare_fork_listener(process, &runtime)?;
            frida.enable_child_gating(process)?;
            frida.arm_fork_listener(process, &runtime)?;
            handoff
                .allow_parent(member.identity.pid, member.identity.birth)
                .map_err(|error| error.to_string())?;
        } else if !removing {
            let process = Process::from_pid(member.identity.pid)?;
            frida.exec_monitor(
                process,
                &runtime,
                super::super::frida_core::ExecMonitorAction::Prepare,
            )?;
            frida.enable_child_gating(process)?;
            frida.exec_monitor(
                process,
                &runtime,
                super::super::frida_core::ExecMonitorAction::Confirm,
            )?;
        }
        let status = host(
            member,
            if removing {
                HostCommand::Detach
            } else {
                HostCommand::Activate
            },
            Some(&execution.authorization),
        )?;
        member.bootstrap.approval_not_before_ms = member
            .bootstrap
            .approval_not_before_ms
            .max(status.approval_not_before_ms);
    }
    persist_context(execution, &context.payload, &handoff, &members, &pending)?;
    outcome(
        execution,
        &manager,
        &listener.endpoint,
        if removing {
            Phase::Detaching
        } else {
            Phase::Active
        },
        members_snapshot(&members),
        vec![],
    )?;
    // The pinned original inode stays open for this manager's entire lifetime.
    // Future fork recovery references that same object; there is no dlopen of a
    // copied/new Agent over an existing base.
    monitor_members(
        execution,
        &manager,
        &listener.endpoint,
        detach,
        listener.authorization.clone(),
        &frida,
        &runtime,
        &context.payload,
        &handoff,
        members,
        pending,
        removing,
    )
}

#[cfg(test)]
mod publication_tests {
    use super::*;

    #[test]
    fn detach_fence_blocks_host_work_when_core_prepare_fails_without_pending_startups() {
        let events = RefCell::new(Vec::new());
        let reasons = detach_transition_fence(
            false,
            || panic!("no pending startup cancellation was required"),
            || {
                events.borrow_mut().push("prepare");
                Err("injected Core fence failure".to_owned())
            },
        );
        if reasons.is_empty() {
            events.borrow_mut().push("host_detach");
        }

        assert_eq!(&*events.borrow(), &["prepare"]);
        assert_eq!(reasons, vec!["injected Core fence failure"]);
    }

    #[test]
    fn detach_fence_orders_pending_cancellation_and_core_prepare_before_host_work() {
        let events = RefCell::new(Vec::new());
        let reasons = detach_transition_fence(
            true,
            || {
                events.borrow_mut().push("cancel_pending");
                Vec::new()
            },
            || {
                events.borrow_mut().push("prepare");
                Ok(())
            },
        );
        if reasons.is_empty() {
            events.borrow_mut().push("host_detach");
        }

        assert!(reasons.is_empty());
        assert_eq!(
            &*events.borrow(),
            &["cancel_pending", "prepare", "host_detach"]
        );
    }

    fn cleanup_authorization(action: Action, request_id: &str) -> Authorization {
        Authorization {
            request: attachments::Request {
                schema_version: 1,
                id: request_id.into(),
                instance_id: "i".repeat(64),
                created_at_ms: 1,
                action,
            },
            approved_at_ms: 1,
            expires_at_ms: u64::MAX,
            nonce: [0; 32],
            executor_sha256: "e".repeat(64),
            execution_digest: None,
            host_binding: None,
            core_attestation_public_key: None,
            manager_claimant: None,
            signature: vec![],
        }
    }

    fn cleanup_spec() -> attachments::Spec {
        attachments::Spec {
            recovery: None,
            capabilities: Default::default(),
            id: "attachment-fixture".into(),
            target: verified_member().identity,
            current_target: None,
            exec_epoch: 0,
            scope: Scope::Tree,
            backend: Backend::Gum,
            policy_digest: "p".repeat(64),
        }
    }

    fn verified_member() -> Member {
        Member {
            identity: ProcessIdentity {
                pid: 17,
                birth: 42,
                executable: "fixture".into(),
                executable_sha256: "a".repeat(64),
                owner: "fixture-user".into(),
            },
            bootstrap: serde_json::from_value(serde_json::json!({
                "attachment_id": "fixture", "session_id": "session", "token": "dummy",
                "control_endpoint": "control", "socks_address": "127.0.0.1:1",
                "tls_ca_pem": "", "observe": false, "firewall": null, "sandbox": null,
                "host_endpoint": "host", "host_token": "dummy-host-token", "scope_tree": true,
                "root_pid": 17, "approval_authority_file": "authority",
                "approval_instance_id": "instance", "approval_public_key": null,
                "approval_core_public_key": null, "approval_core_pid": 0,
                "approval_core_birth": 0, "approval_cli_sha256": ""
            }))
            .unwrap(),
            native_pin: Some(NativePin {
                fd: 19,
                device: 23,
                inode: 29,
            }),
            preparation_only: false,
        }
    }

    fn pending_attempt() -> PendingInjection {
        let member = verified_member();
        PendingInjection {
            identity: member.identity,
            bootstrap: member.bootstrap,
            ready_path: std::env::temp_dir()
                .join("unused-ready-fixture")
                .to_string_lossy()
                .into_owned(),
            dispatch_started: false,
            observation: None,
        }
    }

    #[test]
    fn preparation_budget_is_absolute_and_does_not_reset_per_operation() {
        let started = Instant::now();
        let deadline = PreparationDeadline::new_at(started);
        assert_eq!(
            deadline.operation_timeout_at(started).unwrap(),
            ATTACH_INJECTION_TIMEOUT
        );
        assert_eq!(
            deadline
                .operation_timeout_at(started + Duration::from_secs(7))
                .unwrap(),
            Duration::from_secs(13)
        );
        assert_eq!(
            deadline
                .operation_timeout_at(started + Duration::from_secs(19))
                .unwrap(),
            Duration::from_secs(1)
        );
        assert!(deadline
            .operation_timeout_at(started + ATTACH_PREPARATION_TIMEOUT)
            .is_err());
    }

    #[test]
    fn preparing_is_published_before_any_native_dispatch() {
        let events = RefCell::new(Vec::new());
        after_preparing_publication(
            || {
                events.borrow_mut().push("published_preparing");
                Ok(())
            },
            || {
                assert_eq!(events.borrow().as_slice(), ["published_preparing"]);
                events.borrow_mut().push("native_dispatch_started");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            events.into_inner(),
            ["published_preparing", "native_dispatch_started"]
        );
    }

    #[test]
    fn cleanup_pending_is_published_before_any_fallible_cleanup_work() {
        let events = RefCell::new(Vec::new());
        let (publication, value) = after_cleanup_pending_publication(
            || {
                events.borrow_mut().push("published_cleanup_pending");
                Ok(())
            },
            || {
                assert_eq!(events.borrow().as_slice(), ["published_cleanup_pending"]);
                events.borrow_mut().push("cleanup_started");
                "cleanup_result"
            },
        );
        publication.unwrap();
        assert_eq!(value, "cleanup_result");
        assert_eq!(
            events.into_inner(),
            ["published_cleanup_pending", "cleanup_started"]
        );
    }

    #[test]
    fn cleanup_still_runs_when_cleanup_pending_publication_fails() {
        let cleanup_started = std::cell::Cell::new(false);
        let (publication, ()) = after_cleanup_pending_publication(
            || Err("record write failed".into()),
            || cleanup_started.set(true),
        );
        assert_eq!(publication.unwrap_err(), "record write failed");
        assert!(cleanup_started.get());
    }

    #[test]
    fn preparation_cleanup_round_refreshes_a_later_detach_authorization() {
        let spec = cleanup_spec();
        let original = cleanup_authorization(
            Action::Attach { spec: spec.clone() },
            "attach-request-fixture",
        );
        let approved_detach = cleanup_authorization(
            Action::Detach {
                exec_epoch: spec.exec_epoch,
                attachment_id: spec.id.clone(),
                target: spec.target.clone(),
                policy_digest: spec.policy_digest.clone(),
                recovery: None,
            },
            "detach-request-fixture",
        );
        let shared = Mutex::new(original);
        let mut rounds = 0;
        let mut fenced_requests = Vec::new();
        let mut host_requests = Vec::new();
        let finish_calls = std::cell::Cell::new(0);

        loop {
            rounds += 1;
            let round_authorization = cleanup_authorization_for_round(&shared).unwrap();
            fenced_requests.push(round_authorization.request.id.clone());

            if !matches!(round_authorization.request.action, Action::Detach { .. }) {
                assert_eq!(
                    finish_calls.get(),
                    0,
                    "the original Attach cannot finish cleanup"
                );
                *shared.lock().unwrap() = approved_detach.clone();
                continue;
            }

            host_requests.push(round_authorization.request.id.clone());
            finish_calls.set(finish_calls.get() + 1);
            assert_eq!(round_authorization.request.id, approved_detach.request.id);
            break;
        }

        assert_eq!(rounds, 2);
        assert_eq!(
            fenced_requests,
            ["attach-request-fixture", "detach-request-fixture"]
        );
        assert_eq!(host_requests, ["detach-request-fixture"]);
        assert_eq!(finish_calls.get(), 1);
    }

    #[test]
    fn preparation_cleanup_orders_logical_detach_before_native_retirement() {
        let events = RefCell::new(Vec::new());
        let attempt = ordered_preparation_cleanup_attempt(
            &[41],
            true,
            |pid| {
                events.borrow_mut().push(format!("detach:{pid}"));
                Ok(())
            },
            |pid| {
                events.borrow_mut().push(format!("abort:{pid}"));
                Ok(())
            },
            |pid| {
                events.borrow_mut().push(format!("disable:{pid}"));
                Ok(())
            },
            || {
                events.borrow_mut().push("pending".into());
                Ok(vec![])
            },
            |pid| {
                events.borrow_mut().push(format!("resume:{pid}"));
                Ok(())
            },
        );
        assert_eq!(
            events.into_inner(),
            ["detach:41", "abort:41", "disable:41", "pending"]
        );
        assert_eq!(
            attempt,
            PreparationCleanupAttempt {
                complete: true,
                reasons: vec![]
            }
        );
    }

    #[test]
    fn preparation_cleanup_failure_stays_pending_and_skips_later_member_steps() {
        let events = RefCell::new(Vec::new());
        let attempt = ordered_preparation_cleanup_attempt(
            &[41],
            true,
            |pid| {
                events.borrow_mut().push(format!("detach:{pid}"));
                Err("host still propagating".into())
            },
            |pid| {
                events.borrow_mut().push(format!("abort:{pid}"));
                Ok(())
            },
            |pid| {
                events.borrow_mut().push(format!("disable:{pid}"));
                Ok(())
            },
            || {
                events.borrow_mut().push("pending".into());
                Ok(vec![(41, 52)])
            },
            |pid| {
                events.borrow_mut().push(format!("resume:{pid}"));
                Ok(())
            },
        );
        assert_eq!(events.into_inner(), ["detach:41", "pending"]);
        assert!(!attempt.complete);
        assert_eq!(
            attempt.reasons,
            ["rollback_incomplete:41:host still propagating"]
        );
    }

    #[test]
    fn preparation_cleanup_requires_a_fresh_empty_pending_child_observation() {
        let events = RefCell::new(Vec::new());
        let attempt = ordered_preparation_cleanup_attempt(
            &[41],
            true,
            |_| Ok(()),
            |_| Ok(()),
            |_| Ok(()),
            || Ok(vec![(41, 52)]),
            |pid| {
                events.borrow_mut().push(format!("resume:{pid}"));
                Ok(())
            },
        );
        assert_eq!(events.into_inner(), ["resume:52"]);
        assert!(!attempt.complete);
        assert!(attempt.reasons.is_empty());
    }

    #[test]
    fn approved_cleanup_waits_for_dispatch_journal_and_blocks_later_dispatch() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let saved = Arc::new(AtomicBool::new(false));
        let guard = admit_native_dispatch(Some(cancelled.as_ref())).unwrap();
        let (started_send, started_receive) = mpsc::channel();
        let (finished_send, finished_receive) = mpsc::channel();
        let control_cancelled = cancelled.clone();
        let control_saved = saved.clone();
        let control = std::thread::spawn(move || {
            started_send.send(()).unwrap();
            let _gate = dispatch_gate().unwrap();
            assert!(
                control_saved.load(Ordering::Acquire),
                "approval observed an uncommitted dispatch"
            );
            control_cancelled.store(true, Ordering::Release);
            finished_send.send(()).unwrap();
        });
        started_receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert!(matches!(
            finished_receive.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        saved.store(true, Ordering::Release);
        drop(guard);
        finished_receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        control.join().unwrap();
        assert!(admit_native_dispatch(Some(cancelled.as_ref())).is_err());
    }

    #[test]
    fn pending_journal_retains_ram_ownership_before_a_failed_save() {
        let pending = PendingInjections::default();
        let result = retain_pending(&pending, pending_attempt(), || {
            assert_eq!(pending.borrow().len(), 1);
            assert_eq!(pending.borrow()[0].bootstrap.host_token, "dummy-host-token");
            Err("cannot save journal".into())
        });
        assert_eq!(result.unwrap_err(), "cannot save journal");
        assert!(!pending.borrow()[0].dispatch_started);
    }

    #[test]
    fn either_journal_save_failure_prevents_the_actual_native_dispatch() {
        for fail_dispatched in [false, true] {
            let pending = PendingInjections::default();
            let dispatched = std::cell::Cell::new(false);
            let result = dispatch_injection(
                pending_attempt(),
                |attempt| {
                    let marker = attempt.dispatch_started;
                    retain_pending(&pending, attempt, || {
                        if marker == fail_dispatched {
                            Err("disk failure".into())
                        } else {
                            Ok(())
                        }
                    })
                },
                || {
                    dispatched.set(true);
                    Ok(17)
                },
            );
            assert_eq!(result.unwrap_err(), "disk failure");
            assert!(!dispatched.get());
            assert_eq!(pending.borrow()[0].dispatch_started, fail_dispatched);
        }
    }

    #[test]
    fn native_dispatch_observes_the_saved_started_state_and_cannot_silently_retry() {
        let pending = PendingInjections::default();
        let saved = RefCell::new(Vec::new());
        let result = dispatch_injection(
            pending_attempt(),
            |attempt| {
                retain_pending(&pending, attempt, || {
                    saved
                        .borrow_mut()
                        .push(pending.borrow()[0].dispatch_started);
                    Ok(())
                })
            },
            || {
                assert_eq!(*saved.borrow(), vec![false, true]);
                assert!(pending.borrow()[0].dispatch_started);
                Err::<(), _>("native startup failed".into())
            },
        );
        assert_eq!(result.unwrap_err(), "native startup failed");
        assert!(retain_pending(&pending, pending_attempt(), || Ok(())).is_err());
        for alter in [0, 1, 2] {
            let mut changed = pending.borrow()[0].clone();
            match alter {
                0 => changed.identity.birth += 1,
                1 => changed.bootstrap.host_token.push('x'),
                _ => changed.bootstrap.host_endpoint.push('x'),
            }
            assert!(retain_pending(&pending, changed, || Ok(())).is_err());
        }
    }

    #[test]
    fn alpha_contexts_without_pending_are_supported_but_unknown_dispatch_is_conservative() {
        let mut value = serde_json::to_value(pending_attempt()).unwrap();
        value.as_object_mut().unwrap().remove("dispatch_started");
        let attempt: PendingInjection = serde_json::from_value(value).unwrap();
        assert!(attempt.dispatch_started);
        let mut member = serde_json::to_value(verified_member()).unwrap();
        member.as_object_mut().unwrap().remove("preparation_only");
        let directory = std::env::temp_dir().join("unused-broker-fixture");
        let context: GumRecovery = serde_json::from_value(serde_json::json!({
            "schema": 1, "backend": "gum",
            "payload": { "device":23, "inode":29, "size":1, "sha256":"a".repeat(64), "seals":0 },
            "broker": { "directory":directory, "socket":directory.join("socket"), "secret":vec![9u8;32] },
            "members": [member]
        })).unwrap();
        assert!(context.pending_injections.is_empty());
        assert!(!context.members[0].preparation_only);
        assert_eq!(context.members[0].native_pin.as_ref().unwrap().inode, 29);
    }

    #[test]
    fn pending_host_evidence_routes_unready_hosts_only_to_cleanup_and_checks_scope_and_pin() {
        let attempt = pending_attempt();
        let payload = NativePayload {
            device: 23,
            inode: 29,
            size: 1,
            sha256: "a".repeat(64),
            seals: 0,
        };
        let mut status: hyperhub_runtime::attachment::HostStatus = serde_json::from_value(serde_json::json!({
            "protocol":1, "pid":17, "attachment_id":"fixture", "phase":"preparing", "active_calls":0,
            "unload_ready":false, "tracked_sockets":0, "fake_addresses":0, "compatibility_reasons":[],
            "initialization": { "origin":"fresh", "runtime_available":true, "ever_active":false,
                "stage":"failed", "initializing":false, "cancelled":false, "error":"fixture startup failure", "native_pin":null }
        })).unwrap();
        let member = member_from_pending_status(&attempt, &status, &payload).unwrap();
        assert!(member.preparation_only);
        assert!(member.native_pin.is_none());
        status.phase = HostPhase::Active;
        assert!(member_from_pending_status(&attempt, &status, &payload).is_err());
        status.phase = HostPhase::Preparing;
        status.initialization.as_mut().unwrap().native_pin =
            Some(hyperhub_runtime::attachment::InitializationNativePin {
                fd: 19,
                device: 24,
                inode: 29,
            });
        assert!(member_from_pending_status(&attempt, &status, &payload).is_err());
        status
            .initialization
            .as_mut()
            .unwrap()
            .native_pin
            .as_mut()
            .unwrap()
            .device = 23;
        assert!(member_from_pending_status(&attempt, &status, &payload).is_ok());
        // SDK entry/native arm completion is not proof that policy was active.
        // Never-active Ready Hosts must use cancellation without new tracking.
        status.native_ready = true;
        status.initialization.as_mut().unwrap().stage =
            hyperhub_runtime::attachment::InitializationStage::Ready;
        assert!(
            member_from_pending_status(&attempt, &status, &payload)
                .unwrap()
                .preparation_only
        );
        status.initialization.as_mut().unwrap().ever_active = true;
        assert!(
            !member_from_pending_status(&attempt, &status, &payload)
                .unwrap()
                .preparation_only
        );
        status.pid += 1;
        assert!(member_from_pending_status(&attempt, &status, &payload).is_err());
        status.pid -= 1;
        status.attachment_id.push('x');
        assert!(member_from_pending_status(&attempt, &status, &payload).is_err());
        status.attachment_id = "fixture".into();
        status.initialization = None;
        assert!(member_from_pending_status(&attempt, &status, &payload).is_err());
    }

    #[test]
    fn a_missing_payload_is_not_reclassified_as_never_dispatched_or_loader_quiescence() {
        let expected = verified_member().identity;
        assert!(matches!(
            missing_host_observation(&expected, &expected, false, "unreachable"),
            PendingObservation::PayloadAbsent
        ));
        let mut replacement = expected.clone();
        replacement.executable_sha256 = "b".repeat(64);
        assert!(matches!(
            missing_host_observation(&expected, &replacement, false, "unreachable"),
            PendingObservation::ReplacedImage { .. }
        ));
        assert!(matches!(
            missing_host_observation(&expected, &replacement, true, "unreachable"),
            PendingObservation::Unknown { .. }
        ));
        replacement.birth += 1;
        assert!(matches!(
            missing_host_observation(&expected, &replacement, false, "unreachable"),
            PendingObservation::Unknown { .. }
        ));
        replacement.birth = expected.birth;
        replacement.owner.push('x');
        assert!(matches!(
            missing_host_observation(&expected, &replacement, false, "unreachable"),
            PendingObservation::Unknown { .. }
        ));
    }

    #[test]
    fn verified_host_remains_in_ram_when_checkpoint_persistence_fails_before_tracking() {
        let mut members = BTreeMap::new();
        let tracked = std::cell::Cell::new(false);
        let result = track_verified_member(
            verified_member(),
            Some(&mut |member| {
                members.insert(member.identity.pid, member.clone());
                Err("checkpoint persistence failed".into())
            }),
            |_| {
                tracked.set(true);
                Ok(())
            },
        );
        assert_eq!(
            result.err().as_deref(),
            Some("checkpoint persistence failed")
        );
        assert!(!tracked.get());
        let member = members
            .get(&17)
            .expect("authorized rollback must see the Host");
        assert_eq!(member.identity.birth, 42);
        assert_eq!(member.bootstrap.host_token, "dummy-host-token");
        assert_eq!(member.native_pin.as_ref().unwrap().inode, 29);
    }

    #[test]
    fn tracking_busy_retains_the_verified_host_and_its_persisted_recovery_binding() {
        let mut members = BTreeMap::new();
        let mut recovery = Vec::new();
        let checkpoint_done = std::cell::Cell::new(false);
        let result = track_verified_member(
            verified_member(),
            Some(&mut |member| {
                members.insert(member.identity.pid, member.clone());
                recovery = serde_json::to_vec(&members).unwrap();
                checkpoint_done.set(true);
                Ok(())
            }),
            |_| {
                assert!(checkpoint_done.get());
                Err("activation_busy".into())
            },
        );
        assert_eq!(result.err().as_deref(), Some("activation_busy"));
        let restored: BTreeMap<u32, Member> = serde_json::from_slice(&recovery).unwrap();
        assert_eq!(members[&17].identity, restored[&17].identity);
        assert_eq!(restored[&17].bootstrap.host_token, "dummy-host-token");
        assert_eq!(restored[&17].native_pin.as_ref().unwrap().inode, 29);
    }
    fn stat(pid: u32, state: &str, birth: u64) -> String {
        let mut fields = vec!["0".to_owned(); 20];
        fields[0] = state.into();
        fields[19] = birth.to_string();
        format!("{pid} (a name with ) delimiters) {}", fields.join(" "))
    }
    #[test]
    fn publication_exit_requires_the_exact_incarnation_and_valid_os_record() {
        assert_eq!(publication_stat(&stat(17, "S", 42), 17).unwrap(), ("S", 42));
        assert_eq!(publication_stat(&stat(17, "Z", 42), 17).unwrap(), ("Z", 42));
        assert_eq!(publication_stat(&stat(17, "X", 42), 17).unwrap(), ("X", 42));
        assert_eq!(publication_stat(&stat(17, "S", 43), 17).unwrap(), ("S", 43));
        assert!(publication_stat(&stat(18, "S", 42), 17).is_err());
        assert!(publication_stat("17 malformed", 17).is_err());
        assert!(publication_stat(&stat(17, "S", 0), 17).is_err());
    }
}
