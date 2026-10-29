//! Approved live-process attachment. Handles here never own target termination.
use super::*;
use hyperhub_core::attachments::{
    self, Action, Authorization, Backend, Execution, ManagerListener, Outcome, Phase,
    ProcessIdentity, Record, Scope,
};
use hyperhub_runtime::attachment::windows_inject::{self, Module};
use hyperhub_runtime::attachment::{
    self as wire, AuthenticatedCommand, Bootstrap, HostCommand, HostPhase,
};
use std::io::Read;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::{
    Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    },
    Threading::{
        OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    },
};

const POSIX_FORK_EXPORTS: [&str; 4] = ["fork", "vfork", "cygwin_internal", "__errno"];

fn owned_entry_release_pending(origin: attachments::Origin, phase: Phase) -> bool {
    origin == attachments::Origin::Run && phase == Phase::Preparing
}

fn runtime_operation_blocked(
    origin: attachments::Origin,
    persisted: Phase,
    manager: Phase,
) -> bool {
    owned_entry_release_pending(origin, persisted)
        || matches!(manager, Phase::Preparing | Phase::Detaching)
}

fn posix_fork_abi(
    mut find_export: impl FnMut(&str) -> std::io::Result<usize>,
) -> std::io::Result<bool> {
    for name in POSIX_FORK_EXPORTS {
        match find_export(name) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn reject_posix_runtime_modules(modules: &[Module]) -> Result<(), String> {
    for module in modules {
        // A missing/unreadable module file is not evidence that its loaded
        // image lacks the runtime ABI. Keep the opened file alive for the probe.
        let _file = std::fs::File::open(&module.path).map_err(|error| {
            format!("cannot read loaded module for external runtime capability check: {error}")
        })?;
        let runtime = posix_fork_abi(|name| windows_inject::export_rva(&module.path, name))
            .map_err(|error| {
                format!("cannot establish loaded module runtime capabilities: {error}")
            })?;
        if runtime {
            return Err("unsupported_external_posix_runtime_fork: MSYS/Cygwin fork memory and socket continuation are unavailable for external attachment".into());
        }
    }
    Ok(())
}

pub(crate) fn validate_external_runtime(pid: u32) -> Result<(), String> {
    let modules = windows_inject::modules(pid).map_err(|error| {
        format!("cannot establish external target runtime capabilities: {error}")
    })?;
    reject_posix_runtime_modules(&modules)
}

#[cfg(test)]
mod posix_capability_tests {
    use super::*;
    #[test]
    fn posix_runtime_capability_requires_the_complete_runtime_abi() {
        assert!(posix_fork_abi(|_| Ok(1)).unwrap());
        for absent in POSIX_FORK_EXPORTS {
            assert!(!posix_fork_abi(|name| {
                if name == absent {
                    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
                } else {
                    Ok(1)
                }
            })
            .unwrap());
        }
        assert!(
            !posix_fork_abi(|_| Err(std::io::Error::from(std::io::ErrorKind::NotFound))).unwrap()
        );
    }
    #[test]
    fn unreadable_or_invalid_module_is_not_classified_as_missing_runtime_exports() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::Other,
        ] {
            assert_eq!(
                posix_fork_abi(|_| Err(std::io::Error::from(kind)))
                    .unwrap_err()
                    .kind(),
                kind
            );
        }
        let missing = Module {
            base: 1,
            size: 1,
            path: std::env::temp_dir().join(format!("hh-missing-module-{}", attachments::new_id())),
            name: "missing-capability-module".into(),
        };
        assert!(reject_posix_runtime_modules(&[missing])
            .unwrap_err()
            .starts_with("cannot read loaded module"));
    }
}

#[cfg(test)]
mod owned_startup_barrier_tests {
    use super::*;

    #[test]
    fn owned_preparing_is_not_runtime_operable() {
        assert!(owned_entry_release_pending(
            attachments::Origin::Run,
            Phase::Preparing
        ));
        assert!(!owned_entry_release_pending(
            attachments::Origin::Run,
            Phase::Active
        ));
        assert!(!owned_entry_release_pending(
            attachments::Origin::Attach,
            Phase::Preparing
        ));
        assert!(runtime_operation_blocked(
            attachments::Origin::Run,
            Phase::Preparing,
            Phase::Active
        ));
        assert!(runtime_operation_blocked(
            attachments::Origin::Run,
            Phase::Active,
            Phase::Preparing
        ));
        assert!(!runtime_operation_blocked(
            attachments::Origin::Run,
            Phase::Active,
            Phase::Active
        ));
    }
}

pub fn inspect_attachment_target(pid: u32) -> Result<ProcessIdentity, String> {
    if pid == std::process::id() {
        return Err("cannot attach the attachment manager to itself".into());
    }
    let identity = inspect_plain_target(pid)?;
    let native = windows_inject::modules(pid)
        .map_err(|e| e.to_string())?
        .iter()
        .any(|module| windows_inject::export_rva(&module.path, "hh_agent_abi_version").is_ok());
    if native {
        let compatible = attachments::directory()
            .and_then(|directory| attachments::records(&directory))
            .unwrap_or_default()
            .iter()
            .any(|record| {
                record.effective_target() == &identity
                    && record.spec.target.same_incarnation(&identity)
                    && matches!(
                        record.phase,
                        Phase::Active | Phase::Draining | Phase::DetachedResident
                    )
                    && record
                        .manager
                        .as_ref()
                        .is_some_and(|manager| attachments::verify_process(manager).is_ok())
                    && record.manager_endpoint.is_some()
            });
        if !compatible {
            return Err("target already has an injected native base without a compatible current-instance attachment".into());
        }
    }
    Ok(identity)
}
fn inspect_plain_target(pid: u32) -> Result<ProcessIdentity, String> {
    let identity = attachments::inspect_process(pid)?;
    doctor_target(Path::new(&identity.executable))?;
    let _ = open_target(pid)?;
    Ok(identity)
}
fn open_target(pid: u32) -> Result<OwnedHandle, String> {
    // PROCESS_TERMINATE is deliberately absent for externally owned processes.
    let handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_LIMITED_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(last_error("cannot open live target for attachment"));
    }
    Ok(OwnedHandle(handle))
}
fn process_gone(pid: u32) -> bool {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return unsafe { windows_sys::Win32::Foundation::GetLastError() }
            == windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
    }
    let handle = OwnedHandle(handle);
    (unsafe { WaitForSingleObject(handle.0, 0) }) != WAIT_TIMEOUT
}
fn processes() -> Result<Vec<(u32, u32)>, String> {
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_error("cannot enumerate attachment descendants"));
    }
    let handle = OwnedHandle(raw);
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut result = Vec::new();
    let mut success = unsafe { Process32FirstW(handle.0, &mut entry) };
    while success != 0 {
        result.push((entry.th32ProcessID, entry.th32ParentProcessID));
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        success = unsafe { Process32NextW(handle.0, &mut entry) };
    }
    Ok(result)
}
fn members(execution: &Execution) -> Result<Vec<ProcessIdentity>, String> {
    let root = inspect_plain_target(execution.spec.target.pid)?;
    if &root != execution.spec.effective_target() {
        return Err("attachment root identity changed".into());
    }
    let mut ids = std::collections::BTreeSet::from([root.pid]);
    if execution.spec.scope == Scope::Tree {
        let snapshot = processes()?;
        loop {
            let before = ids.len();
            for &(pid, parent) in &snapshot {
                if ids.contains(&parent) {
                    ids.insert(pid);
                }
            }
            if ids.len() == before {
                break;
            }
        }
    }
    if ids.contains(&std::process::id()) {
        return Err("attachment scope includes its own manager".into());
    }
    let mut result = Vec::new();
    for pid in ids {
        match inspect_plain_target(pid) {
            Ok(member) => result.push(member),
            Err(error) => {
                if pid == execution.spec.target.pid {
                    return Err(error);
                }
                // A naturally exiting descendant is not a failed tree attach.
                if !process_gone(pid) {
                    return Err(error);
                }
            }
        }
    }
    Ok(result)
}
fn runtime() -> Result<crate::agent_runtime::AgentRuntime, String> {
    #[cfg(feature = "embedded-agent")]
    {
        crate::agent_runtime::AgentRuntime::embedded()
    }
    #[cfg(not(feature = "embedded-agent"))]
    {
        Err("live Windows attachment requires a CLI with its verified embedded Agent".into())
    }
}
struct Target {
    module_sha256: String,
    _module_file: Option<std::fs::File>,
    identity: ProcessIdentity,
    process: OwnedHandle,
    module: Module,
    bootstrap: Bootstrap,
    last_detach_proof: Option<wire::ApprovalProof>,
    retired: bool,
    release_attempted: bool,
    unloaded: bool,
    release_reason: Option<String>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryContext {
    protocol: u32,
    members: Vec<RecoveryMember>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryMember {
    identity: ProcessIdentity,
    bootstrap: Bootstrap,
    module_path: std::path::PathBuf,
    module_base: usize,
    module_size: usize,
    module_sha256: String,
    last_detach_proof: Option<wire::ApprovalProof>,
    retired: bool,
    release_attempted: bool,
    unloaded: bool,
}
fn recovery_context(targets: &[Target]) -> Result<RecoveryContext, String> {
    let members = targets
        .iter()
        .map(|target| {
            Ok(RecoveryMember {
                identity: target.identity.clone(),
                bootstrap: target.bootstrap.clone(),
                module_path: target.module.path.clone(),
                module_base: target.module.base,
                module_size: target.module.size,
                module_sha256: target.module_sha256.clone(),
                last_detach_proof: target.last_detach_proof.clone(),
                retired: target.retired,
                release_attempted: target.release_attempted,
                unloaded: target.unloaded,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(RecoveryContext {
        protocol: wire::PROTOCOL,
        members,
    })
}
fn persist_recovery(
    execution: &Execution,
    targets: &[Target],
    previous: &mut String,
) -> Result<(), String> {
    let context = recovery_context(targets)?;
    let digest = attachments::digest(&serde_json::to_vec(&context).map_err(|e| e.to_string())?);
    if *previous != digest {
        crate::attachment::save_backend_recovery(execution, &context)?;
        *previous = digest;
    }
    Ok(())
}
unsafe impl Send for Target {}
fn host(target: &Target, command: HostCommand) -> Result<wire::HostStatus, String> {
    host_authorized(target, command, None)
}
fn host_authorized(
    target: &Target,
    command: HostCommand,
    proof: Option<wire::ApprovalProof>,
) -> Result<wire::HostStatus, String> {
    attachments::manager_host_command_with_proof(
        &target.bootstrap,
        &target.identity,
        command,
        proof,
    )
}
fn snapshot_outcome(targets: &[Target], manager: &ProcessIdentity, endpoint: &str) -> Outcome {
    let mut reasons = Vec::new();
    let mut phase = Phase::Active;
    let mut live = Vec::new();
    let mut pending_startup = false;
    for target in targets {
        if unsafe { WaitForSingleObject(target.process.0, 0) } != WAIT_TIMEOUT {
            continue;
        }
        live.push(target.identity.clone());
        if target.unloaded {
            continue;
        }
        if target.retired {
            phase = if target.release_attempted {
                Phase::DetachedResident
            } else {
                Phase::Detaching
            };
            reasons.push(
                target
                    .release_reason
                    .clone()
                    .unwrap_or_else(|| "native_unload_pending".into()),
            );
            continue;
        }
        match host(target, HostCommand::Status) {
            Ok(status) => {
                if status.phase == HostPhase::Active && !status.native_ready {
                    phase = Phase::Degraded;
                } else if status.phase != HostPhase::Active && phase != Phase::Degraded {
                    phase = Phase::DetachedResident;
                }
                if status.phase != HostPhase::Active && status.spawn_calls > 0 {
                    pending_startup = true;
                }
                reasons.extend(status.compatibility_reasons);
            }
            Err(_) => {
                phase = Phase::Degraded;
                reasons.push(format!("host_control_unavailable:{}", target.identity.pid));
            }
        }
    }
    if pending_startup && phase != Phase::Degraded {
        phase = Phase::Draining;
        reasons.push("in_flight_child_startup".into());
    }
    if live.is_empty() {
        phase = Phase::Exited;
    } else if targets
        .iter()
        .filter(|t| live.iter().any(|p| p.pid == t.identity.pid))
        .all(|t| t.unloaded)
    {
        phase = Phase::Detached;
    }
    reasons.sort();
    reasons.dedup();
    Outcome {
        phase,
        members: live,
        compatibility_reasons: reasons,
        manager: Some(manager.clone()),
        manager_endpoint: Some(endpoint.to_owned()),
    }
}
fn install_target(
    execution: &Execution,
    identity: ProcessIdentity,
    runtime: &Path,
) -> Result<Target, String> {
    let process = open_target(identity.pid)?;
    if attachments::inspect_process(identity.pid)? != identity {
        return Err("attachment target changed before injection".into());
    }
    let existing = windows_inject::modules(identity.pid).map_err(|e| e.to_string())?;
    if execution.origin == attachments::Origin::Attach {
        reject_posix_runtime_modules(&existing)?;
    }
    if existing
        .iter()
        .any(|m| windows_inject::export_rva(&m.path, "hh_agent_abi_version").is_ok())
    {
        return Err(
            "target already has an injected native base; use its compatible attachment manager"
                .into(),
        );
    }
    let directory = execution
        .state_directory
        .join(format!("host-{}", identity.pid));
    attachments::private_directory(&directory)?;
    let path = directory.join("hyperhub_gum_agent.dll");
    let data = std::fs::read(runtime).map_err(|e| e.to_string())?;
    // Fresh path prevents the legacy launcher's env-selected startup from
    // running inside an already executing target.
    attachments::create_private_file(&path, &data)?;
    use std::os::windows::fs::OpenOptionsExt;
    let module_file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let mut bootstrap = execution.bootstrap.clone();
    bootstrap.host_endpoint = format!("{}-{}", execution.bootstrap.host_endpoint, identity.pid);
    let module = unsafe { windows_inject::load(process.0, identity.pid, &path) }
        .map_err(|e| e.to_string())?;
    unsafe { windows_inject::start(process.0, &module, &bootstrap) }.map_err(|e| e.to_string())?;
    let target = Target {
        module_sha256: attachments::digest(&data),
        _module_file: Some(module_file),
        identity,
        process,
        module,
        bootstrap,
        last_detach_proof: None,
        retired: false,
        release_attempted: false,
        unloaded: false,
        release_reason: None,
    };
    let status = host(&target, HostCommand::Status)?;
    if status.pid != target.identity.pid {
        return Err("injected Host PID changed".into());
    }
    if status.phase != HostPhase::Preparing
        && !(target.bootstrap.initially_owned && status.phase == HostPhase::Active)
    {
        return Err("injected Host did not enter preparation".into());
    }
    Ok(target)
}
fn reconnect_target(execution: &Execution, identity: ProcessIdentity) -> Result<Target, String> {
    use std::os::windows::fs::OpenOptionsExt;
    let process = open_target(identity.pid)?;
    if attachments::inspect_process(identity.pid)? != identity {
        return Err("attachment member identity changed".into());
    }
    let mut bootstrap = execution.bootstrap.clone();
    bootstrap.host_endpoint = format!("{}-{}", bootstrap.host_endpoint, identity.pid);
    let status = wire::exchange_for_process(
        &bootstrap.host_endpoint,
        &AuthenticatedCommand {
            attachment_id: bootstrap.attachment_id.clone(),
            token: bootstrap.host_token.clone(),
            command: HostCommand::Status,
            proof: None,
            enrollment: None,
            aliases: None,
            root_image: None,
        },
        identity.pid,
    )
    .map_err(|e| e.to_string())?;
    if status.pid != identity.pid {
        return Err("attachment Host PID does not match process handle".into());
    }
    bootstrap.approval_not_before_ms = bootstrap
        .approval_not_before_ms
        .max(status.approval_not_before_ms);
    bootstrap.approval_inherited_public_key = status.approval_public_key;
    bootstrap.alias_inherited = status.alias_inheritance.clone();
    let state = execution
        .state_directory
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let module = windows_inject::modules(identity.pid)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|module| {
            module
                .path
                .canonicalize()
                .ok()
                .is_some_and(|path| path.starts_with(&state))
                && windows_inject::export_rva(&module.path, "hyperhub_attachment_start").is_ok()
        })
        .ok_or("compatible private native module is absent")?;
    let module_file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&module.path)
        .map_err(|e| e.to_string())?;
    Ok(Target {
        module_sha256: attachments::digest(
            &std::fs::read(&module.path).map_err(|e| e.to_string())?,
        ),
        _module_file: Some(module_file),
        identity,
        process,
        module,
        bootstrap,
        last_detach_proof: None,
        retired: false,
        release_attempted: false,
        unloaded: false,
        release_reason: None,
    })
}
fn discover_created_hosts(
    execution: &Execution,
    targets: &mut Vec<Target>,
    detach: Option<&wire::ApprovalProof>,
) -> Result<(), String> {
    if execution.spec.scope != Scope::Tree {
        return Ok(());
    }
    let snapshot = processes()?;
    let mut ids = std::collections::BTreeSet::from([execution.spec.target.pid]);
    ids.extend(targets.iter().map(|target| target.identity.pid));
    loop {
        let before = ids.len();
        for &(pid, parent) in &snapshot {
            if ids.contains(&parent) {
                ids.insert(pid);
            }
        }
        if ids.len() == before {
            break;
        }
    }
    for pid in ids {
        if targets.iter().any(|target| target.identity.pid == pid) {
            continue;
        }
        let Ok(identity) = attachments::inspect_process(pid) else {
            continue;
        };
        // Discovery never injects. Only an authenticated Host created by a
        // previously approved parent can join the manager's membership.
        let Ok(mut target) = reconnect_target(execution, identity) else {
            continue;
        };
        if let Some(proof) = detach {
            host_authorized(&target, HostCommand::Detach, Some(proof.clone()))?;
            target.last_detach_proof = Some(proof.clone());
        }
        targets.push(target);
    }
    Ok(())
}

fn cleanup_native_copies(execution: &Execution, targets: &mut [Target]) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    let metadata =
        std::fs::symlink_metadata(&execution.state_directory).map_err(|e| e.to_string())?;
    if !metadata.is_dir()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        return Err("attachment artifact root is not an owned ordinary directory".into());
    }
    let root = execution
        .state_directory
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let mut copies = std::collections::BTreeMap::new();
    for target in targets.iter() {
        if !target.unloaded && unsafe { WaitForSingleObject(target.process.0, 0) } == WAIT_TIMEOUT {
            return Err("cannot clean an artifact whose native module is still live".into());
        }
        let path = &target.module.path;
        let parent = path.parent().ok_or("artifact has no parent")?;
        let name = parent
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("artifact directory name is invalid")?;
        if path.file_name() != Some(std::ffi::OsStr::new("hyperhub_gum_agent.dll"))
            || name
                .strip_prefix("host-")
                .and_then(|pid| pid.parse::<u32>().ok())
                .is_none()
        {
            return Err("artifact is not a backend-owned Agent copy".into());
        }
        match std::fs::symlink_metadata(parent) {
            Ok(meta) => {
                if !meta.is_dir()
                    || meta.file_attributes()
                        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                        != 0
                    || parent
                        .parent()
                        .and_then(|parent| parent.canonicalize().ok())
                        .as_ref()
                        != Some(&root)
                {
                    return Err("artifact directory escapes its attachment owner".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        }
        if let Some(old) = copies.insert(path.clone(), target.module_sha256.clone()) {
            if old != target.module_sha256 {
                return Err("artifact identity is inconsistent".into());
            }
        }
    }
    // All file pins must be released together: descendants can share a parent's
    // copy. Otherwise one member's read-share pin prevents deletion for another.
    for target in targets.iter_mut() {
        drop(target._module_file.take());
    }
    for (path, expected) in copies {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.is_file()
                    || meta.file_attributes()
                        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                        != 0
                    || attachments::digest(&std::fs::read(&path).map_err(|e| e.to_string())?)
                        != expected
                {
                    return Err("backend-owned artifact identity changed before cleanup".into());
                }
                std::fs::remove_file(&path)
                    .map_err(|e| format!("native artifact removal pending: {e}"))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.to_string()),
        }
        if let Some(parent) = path.parent() {
            match std::fs::remove_dir(parent) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => {
                    return Err(format!(
                        "native artifact directory removal pending: {error}"
                    ))
                }
            }
        }
    }
    Ok(())
}

fn has_live_publisher(targets: &[Target]) -> bool {
    targets.iter().any(|target| {
        !target.unloaded
            && !target.retired
            && unsafe { WaitForSingleObject(target.process.0, 0) } == WAIT_TIMEOUT
    })
}

fn prepare_detach_aliases(
    execution: &Execution,
    authorization: &Authorization,
    manager: &ProcessIdentity,
) -> Result<(), String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(attachments::prepare_detach_session(
            execution,
            authorization,
            manager,
        ))
}

fn finish_detach_aliases(
    execution: &Execution,
    authorization: &Authorization,
    manager: &ProcessIdentity,
) -> Result<bool, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(attachments::finish_detach_session(
            execution,
            authorization,
            manager,
        ))
}

fn advance_unload(target: &mut Target) {
    if target.unloaded {
        return;
    }
    if !target.retired {
        let Ok(status) = host(target, HostCommand::Status) else {
            return;
        };
        if !status.unload_ready {
            return;
        }
        if host_authorized(
            target,
            HostCommand::Retire,
            target.last_detach_proof.clone(),
        )
        .is_err()
        {
            return;
        }
        target.retired = true;
    }
    if target.release_attempted {
        if windows_inject::find_module(target.identity.pid, &target.module.path)
            .ok()
            .flatten()
            .is_none()
        {
            target.unloaded = true;
        }
        return;
    }
    match unsafe { windows_inject::unload(target.process.0, target.identity.pid, &target.module) } {
        Ok(unloaded) => {
            target.release_attempted = true;
            target.unloaded = unloaded;
            if !unloaded {
                target.release_reason = Some("native_module_has_external_references".into());
            }
        }
        Err(error) => {
            target.release_reason = Some(error.to_string());
            if error.to_string().contains("cleanup_pending") {
                target.release_attempted = true;
            }
        }
    }
}
pub fn run_attachment_manager(execution: &Execution) -> Result<(), String> {
    if execution.spec.backend == Backend::Ptrace {
        return Err("ptrace is unavailable on Windows".into());
    }
    let authority = attachments::directory()?;
    attachments::verify_authorization(&authority, &execution.authorization)?;
    let manager = attachments::inspect_process(std::process::id())?;
    let initial = members(execution)?;
    if execution.origin == attachments::Origin::Attach {
        for member in &initial {
            validate_external_runtime(member.pid)?;
        }
    }
    let rt = runtime()?;
    rt.verify()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(attachments::activate_session(execution, &manager, &initial))?;
    let mut targets = Vec::new();
    for member in initial {
        match install_target(execution, member.clone(), rt.load_path()) {
            Ok(target) => targets.push(target),
            Err(error) => {
                if member.pid != execution.spec.target.pid && process_gone(member.pid) {
                    continue;
                }
                for target in &targets {
                    let _ = host_authorized(
                        target,
                        HostCommand::Detach,
                        attachments::host_proof(&execution.authorization).ok(),
                    );
                }
                return Err(format!(
                    "cleanup_pending: attachment preparation failed: {error}"
                ));
            }
        }
    }
    let boundary = (|| -> Result<(), String> {
        if execution.spec.scope != Scope::Tree {
            return Ok(());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(
                    "tree preparation did not reach a safe creation boundary before its deadline"
                        .into(),
                );
            }
            let current = members(execution)?;
            if current
                .iter()
                .any(|member| !targets.iter().any(|target| target.identity == *member))
            {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?
                    .block_on(attachments::activate_session(execution, &manager, &current))?;
                for member in current {
                    if !targets.iter().any(|target| target.identity == member) {
                        match install_target(execution, member.clone(), rt.load_path()) {
                            Ok(target) => targets.push(target),
                            Err(error) => {
                                if member.pid == execution.spec.target.pid
                                    || !process_gone(member.pid)
                                {
                                    return Err(error);
                                }
                            }
                        }
                    }
                }
                continue;
            }
            let mut settled = true;
            for target in &targets {
                if unsafe { WaitForSingleObject(target.process.0, 0) } != WAIT_TIMEOUT {
                    continue;
                }
                if host(target, HostCommand::Status)?.spawn_calls != 0 {
                    settled = false;
                    break;
                }
                match windows_inject::verify_spawn_quiescence(target.identity.pid) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        settled = false;
                        break;
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            if settled {
                // No untracked pre-gate native creation remains. New entries
                // stay behind each prepared Host's gate until activation.
                let after = members(execution)?;
                if after
                    .iter()
                    .all(|member| targets.iter().any(|target| target.identity == *member))
                {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    })();
    if let Err(error) = boundary {
        for target in &targets {
            let _ = host_authorized(
                target,
                HostCommand::Detach,
                attachments::host_proof(&execution.authorization).ok(),
            );
        }
        return Err(format!(
            "cleanup_pending: tree preparation rolled back: {error}"
        ));
    }
    serve_targets(execution.clone(), targets, manager, None)
}
fn serve_targets(
    execution: Execution,
    mut targets: Vec<Target>,
    manager: ProcessIdentity,
    ready: Option<std::sync::mpsc::SyncSender<()>>,
) -> Result<(), String> {
    let authority = attachments::directory()?;
    let endpoint = format!(
        r"\\.\pipe\hyperhub-attachment-manager-{}",
        execution.spec.id
    );
    let listener = ManagerListener::bind(&endpoint)?;
    let mut preparing = snapshot_outcome(&targets, &manager, &endpoint);
    preparing.phase = Phase::Preparing;
    attachments::update_record(&execution.state_directory, &preparing)?;
    let mut recovery_digest = String::new();
    persist_recovery(&execution, &targets, &mut recovery_digest)?;
    let initial_command = match execution.authorization.request.action {
        Action::Detach { .. } => HostCommand::Detach,
        Action::Attach { .. } => HostCommand::Activate,
    };
    let implicit_run = execution.origin == attachments::Origin::Run
        && execution.authorization.signature.is_empty();
    let initial_proof = if implicit_run {
        None
    } else {
        Some(attachments::host_proof(&execution.authorization)?)
    };
    if initial_command == HostCommand::Detach && has_live_publisher(&targets) {
        prepare_detach_aliases(&execution, &execution.authorization, &manager)?;
    }
    let mut alias_detach_finished = initial_command != HostCommand::Detach;
    for target in &mut targets {
        if target.unloaded || target.retired {
            if initial_command == HostCommand::Activate {
                return Err(
                    "a retired native base cannot reactivate before physical cleanup".into(),
                );
            }
            continue;
        }
        host_authorized(target, initial_command, initial_proof.clone())?;
        if initial_command == HostCommand::Detach {
            target.last_detach_proof = initial_proof.clone();
        }
    }
    if initial_command == HostCommand::Detach {
        alias_detach_finished = !has_live_publisher(&targets)
            || finish_detach_aliases(&execution, &execution.authorization, &manager)?;
    }
    persist_recovery(&execution, &targets, &mut recovery_digest)?;
    let active = snapshot_outcome(&targets, &manager, &endpoint);
    if implicit_run && active.phase != Phase::Active {
        return Err(format!(
            "owned target protection is not ready before entry release: {:?}",
            active.compatibility_reasons
        ));
    }
    let mut published = active.clone();
    if implicit_run {
        // The Host and recovery image are ready, but the launcher's entry gate
        // is still held. Preparing is a two-party barrier: both the persisted
        // record and the manager's in-memory state reject runtime operations.
        published.phase = Phase::Preparing;
    }
    attachments::update_record(&execution.state_directory, &published)?;
    if let Some(ready) = ready {
        let _ = ready.send(());
    }
    let stop = Arc::new(AtomicBool::new(false));
    let listener_stop = stop.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Authorization>(8);
    let state = Arc::new(Mutex::new(published));
    let public = state.clone();
    let record = execution.spec.clone();
    let authority_for_listener = authority.clone();
    let state_directory_for_listener = execution.state_directory.clone();
    let server = std::thread::Builder::new()
        .name("hyperhub-attachment-manager".into())
        .spawn(move || {
            listener.run(&listener_stop, |grant| {
                attachments::verify_authorization(&authority_for_listener, &grant)?;
                let current_record = attachments::load_record(&state_directory_for_listener)?;
                if grant.request.action.attachment_id() != record.id
                    || !grant
                        .request
                        .action
                        .target()
                        .same_incarnation(&record.target)
                    || grant.request.action.target() != current_record.effective_target()
                {
                    return Err("attachment authorization names another target".into());
                }
                if let Action::Attach { spec } = &grant.request.action {
                    if spec.scope != record.scope || spec.backend != record.backend {
                        return Err("resident attachment scope/backend is incompatible".into());
                    }
                }
                crate::attachment::validate_runtime_authorization(&grant)?;
                let mut current = public
                    .lock()
                    .map_err(|_| "attachment manager state unavailable")?;
                if runtime_operation_blocked(
                    current_record.origin,
                    current_record.phase,
                    current.phase,
                ) {
                    return Err("attachment operation is already in progress".into());
                }
                attachments::consume_authorization(&authority_for_listener, &grant)?;
                sender
                    .try_send(grant.clone())
                    .map_err(|_| "attachment operation is busy".to_owned())?;
                current.phase = match grant.request.action {
                    Action::Attach { .. } => Phase::Preparing,
                    Action::Detach { .. } => Phase::Detaching,
                };
                Ok(current.clone())
            })
        })
        .map_err(|e| e.to_string())?;
    if implicit_run {
        let mut release = [0u8; 1];
        std::io::stdin()
            .read_exact(&mut release)
            .map_err(|e| format!("owned target entry release was not delivered: {e}"))?;
        if release[0] != crate::attachment::ENTRY_RELEASE {
            return Err("invalid owned target entry release".into());
        }
        let current_record = attachments::load_record(&execution.state_directory)?;
        if current_record.phase != Phase::Preparing
            || current_record.manager.as_ref() != Some(&manager)
            || current_record.manager_endpoint.as_deref() != Some(endpoint.as_str())
        {
            return Err("owned target startup barrier changed before entry release".into());
        }
        let mut current = state
            .lock()
            .map_err(|_| "attachment manager state unavailable")?;
        if current.phase != Phase::Preparing {
            return Err("owned target startup barrier is not preparing".into());
        }
        // Keep the conservative in-memory barrier locked while publishing the
        // durable Active transition. The listener requires both views to be
        // Active, so it cannot observe a durable Active record whose manager
        // has already failed to complete the corresponding local transition.
        attachments::update_record(&execution.state_directory, &active)?;
        *current = active.clone();
    }
    let mut last_detach: Option<wire::ApprovalProof> = if initial_command == HostCommand::Detach {
        initial_proof.clone()
    } else {
        None
    };
    let mut last_detach_grant = if initial_command == HostCommand::Detach {
        Some(execution.authorization.clone())
    } else {
        None
    };
    while !stop.load(Ordering::Acquire) {
        if let Ok(grant) = receiver.recv_timeout(Duration::from_millis(100)) {
            let operation = match grant.request.action {
                Action::Attach { .. } => HostCommand::Activate,
                Action::Detach { .. } => HostCommand::Detach,
            };
            let proof = attachments::host_proof(&grant)?;
            if let Action::Attach { spec } = &grant.request.action {
                if targets.iter().any(|target| {
                    target.unloaded
                        && unsafe { WaitForSingleObject(target.process.0, 0) } == WAIT_TIMEOUT
                }) {
                    return Err("resident tree has fully unloaded live members; fresh tree reactivation requires a new atomic attachment".into());
                }
                let hosts = targets
                    .iter()
                    .filter(|target| {
                        !target.unloaded
                            && unsafe { WaitForSingleObject(target.process.0, 0) } == WAIT_TIMEOUT
                    })
                    .map(|target| attachments::HostBootstrapBinding {
                        identity: target.identity.clone(),
                        bootstrap: target.bootstrap.clone(),
                    })
                    .collect::<Vec<_>>();
                let members = hosts
                    .iter()
                    .map(|host| host.identity.clone())
                    .collect::<Vec<_>>();
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?
                    .block_on(attachments::reactivate_session(
                        &execution, &grant, &manager, &members, &hosts,
                    ))?;
                attachments::update_spec(&execution.state_directory, spec)?;
                last_detach = None;
                last_detach_grant = None;
                alias_detach_finished = true;
            } else {
                if has_live_publisher(&targets) {
                    prepare_detach_aliases(&execution, &grant, &manager)?;
                }
                alias_detach_finished = !has_live_publisher(&targets);
                last_detach = Some(proof.clone());
                last_detach_grant = Some(grant.clone());
            }
            for target in &mut targets {
                if target.retired && operation == HostCommand::Activate {
                    return Err("retired native base cannot be reactivated before unload".into());
                }
                if !target.unloaded
                    && unsafe { WaitForSingleObject(target.process.0, 0) } == WAIT_TIMEOUT
                {
                    host_authorized(target, operation, Some(proof.clone()))?;
                    if operation == HostCommand::Detach {
                        target.last_detach_proof = Some(proof.clone());
                    }
                }
            }
            if operation == HostCommand::Detach && !alias_detach_finished {
                alias_detach_finished = finish_detach_aliases(&execution, &grant, &manager)?;
            }
        }
        discover_created_hosts(&execution, &mut targets, last_detach.as_ref())?;
        if !alias_detach_finished {
            if let Some(grant) = last_detach_grant.as_ref() {
                alias_detach_finished = finish_detach_aliases(&execution, grant, &manager)?;
            }
        }
        // Keep every listener alive until the Core registration fence is
        // complete. A newly initializing child can still require its ACKs.
        if alias_detach_finished {
            for target in &mut targets {
                advance_unload(target);
            }
        }
        persist_recovery(&execution, &targets, &mut recovery_digest)?;
        let mut outcome = snapshot_outcome(&targets, &manager, &endpoint);
        if !alias_detach_finished && !matches!(outcome.phase, Phase::Exited | Phase::Detached) {
            outcome.phase = Phase::Detaching;
            outcome
                .compatibility_reasons
                .push("alias_detach_members_pending".into());
        }
        if outcome.phase == Phase::Detached {
            const ABSENT: &str = "physical_native_modules_absent_pending_session_revocation";
            outcome.phase = if state
                .lock()
                .map(|current| current.phase == Phase::CleanupPending)
                .unwrap_or(false)
            {
                Phase::CleanupPending
            } else {
                Phase::Detaching
            };
            outcome.compatibility_reasons.push(ABSENT.into());
            attachments::update_record(&execution.state_directory, &outcome)?;
            if let Ok(mut current) = state.lock() {
                *current = outcome.clone();
            }
            let completion = if let Some(grant) = last_detach_grant.as_ref() {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?
                    .block_on(async {
                        tokio::time::timeout(
                            Duration::from_secs(5),
                            attachments::complete_session(&execution, grant),
                        )
                        .await
                        .map_err(|_| "session revocation deadline expired".to_owned())?
                    })
            } else {
                Err("signed detach authorization is unavailable for session revocation".into())
            };
            match completion {
                Ok(()) => match cleanup_native_copies(&execution, &mut targets) {
                    Ok(()) => {
                        outcome.phase = Phase::Detached;
                        outcome
                            .compatibility_reasons
                            .retain(|reason| reason != ABSENT);
                    }
                    Err(error) => {
                        outcome.phase = Phase::CleanupPending;
                        outcome
                            .compatibility_reasons
                            .push(format!("native_artifact_cleanup_pending:{error}"));
                    }
                },
                Err(error) => {
                    outcome.phase = Phase::CleanupPending;
                    outcome
                        .compatibility_reasons
                        .push(format!("session_revocation_pending:{error}"));
                }
            }
        }
        attachments::update_record(&execution.state_directory, &outcome)?;
        if let Ok(mut current) = state.lock() {
            *current = outcome.clone();
        }
        if matches!(outcome.phase, Phase::Exited | Phase::Detached) {
            stop.store(true, Ordering::Release);
        }
    }
    server
        .join()
        .map_err(|_| "attachment manager listener panicked".to_owned())??;
    Ok(())
}

pub(super) fn start_owned_reversible(
    execution: &Execution,
    runtime: &Path,
) -> Result<crate::attachment::OwnedRunKeeperBarrier, String> {
    let target = install_target(execution, execution.spec.target.clone(), runtime)?;
    let mut digest = String::new();
    persist_recovery(execution, std::slice::from_ref(&target), &mut digest)?;
    // Persisting the original owner/native state precedes nonce delivery. The
    // caller keeps the program at its executable entrypoint until this keeper
    // has accepted the handoff, so any error is still a pre-entry failure.
    crate::attachment::spawn_owned_run_keeper(execution)
}

pub fn detach_attachment(
    record: &Record,
    authorization: &Authorization,
) -> Result<Outcome, String> {
    if owned_entry_release_pending(record.origin, record.phase) {
        return Err("owned target entry release is still pending".into());
    }
    let manager = record
        .manager
        .as_ref()
        .ok_or("attachment has no owning manager")?;
    if attachments::inspect_process(manager.pid)? != *manager {
        return Err("attachment manager identity changed".into());
    }
    let endpoint = record
        .manager_endpoint
        .as_ref()
        .ok_or("attachment manager endpoint is missing")?;
    attachments::manager_exchange_for_process(endpoint, authorization, manager.pid)
}
pub fn reattach_attachment(
    record: &Record,
    authorization: &Authorization,
) -> Result<Outcome, String> {
    detach_attachment(record, authorization)
}

/// Called only by the authenticated owned-run keeper entry. Reuse the prepared
/// Host; this entry cannot inject an arbitrary target from an API envelope.
pub fn run_owned_attachment_manager(execution: &Execution) -> Result<(), String> {
    if execution.origin != attachments::Origin::Run {
        return Err("owned keeper requires a run handoff".into());
    }
    let manager = attachments::inspect_process(std::process::id())?;
    let target = reconnect_target(execution, execution.spec.target.clone())?;
    serve_targets(execution.clone(), vec![target], manager, None)
}

/// A new administrator grant can recover only an existing native Host after
/// the old manager incarnation is proven dead. This path never injects.
pub fn run_attachment_recovery(execution: &Execution, record: &Record) -> Result<(), String> {
    let recovery = execution
        .authorization
        .request
        .action
        .recovery()
        .ok_or("recovery authorization has no old-manager binding")?;
    if record.manager.as_ref() != Some(&recovery.manager)
        || attachments::verify_process(&recovery.manager).is_ok()
    {
        return Err("old attachment manager is still alive or differs from approval".into());
    }
    let (context, digest) = crate::attachment::load_backend_recovery::<RecoveryContext>(execution)?;
    if context.protocol != wire::PROTOCOL || digest != recovery.context_digest {
        return Err("sealed recovery context differs from approved digest".into());
    }
    let mut targets = Vec::new();
    let binding = execution
        .bootstrap
        .approval_binding()
        .map_err(|e| e.to_string())?;
    for member in context.members {
        if process_gone(member.identity.pid) {
            continue;
        }
        attachments::verify_process(&member.identity)?;
        if member
            .bootstrap
            .approval_binding()
            .map_err(|e| e.to_string())?
            != binding
        {
            return Err("recovery Host belongs to a different bootstrap contract".into());
        }
        let process = open_target(member.identity.pid)?;
        let observed = windows_inject::find_module(member.identity.pid, &member.module_path)
            .map_err(|e| e.to_string())?;
        let absent = observed.is_none();
        if absent
            && !matches!(
                execution.authorization.request.action,
                Action::Detach { .. }
            )
        {
            return Err(
                "native Host is already absent; approve cleanup before a fresh attachment".into(),
            );
        }
        let module = observed.unwrap_or_else(|| Module {
            base: member.module_base,
            size: member.module_size,
            path: member.module_path.clone(),
            name: "hyperhub_gum_agent.dll".into(),
        });
        if module.base != member.module_base
            || module.size != member.module_size
            || (!absent
                && attachments::digest(&std::fs::read(&module.path).map_err(|e| e.to_string())?)
                    != member.module_sha256)
        {
            return Err("recovery native module identity changed".into());
        }
        let mut retired = member.retired;
        let mut release_attempted = member.release_attempted;
        if !absent {
            let entry = module
                .base
                .checked_add(
                    windows_inject::export_rva(&module.path, "hyperhub_attachment_state")
                        .map_err(|e| e.to_string())?,
                )
                .ok_or("recovery probe address overflow")?;
            let state = unsafe { windows_inject::call(process.0, entry, &[0]) }
                .map_err(|e| e.to_string())?;
            if state & 0xffff_0000 != 0x4855_0000 {
                return Err("native base does not expose a compatible recovery state".into());
            }
            retired = state & 1 != 0 && state & 4 != 0;
            release_attempted = state & 2 != 0;
        }
        use std::os::windows::fs::OpenOptionsExt;
        let module_file = if absent {
            None
        } else {
            Some(
                std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
                    .open(&module.path)
                    .map_err(|e| e.to_string())?,
            )
        };
        let mut target = Target {
            module_sha256: member.module_sha256,
            _module_file: module_file,
            identity: member.identity,
            process,
            module,
            bootstrap: member.bootstrap,
            last_detach_proof: member.last_detach_proof,
            retired,
            release_attempted,
            unloaded: absent,
            release_reason: None,
        };
        if !target.retired && !target.unloaded {
            let status = host(&target, HostCommand::Status)?;
            target.bootstrap.approval_not_before_ms = target
                .bootstrap
                .approval_not_before_ms
                .max(status.approval_not_before_ms);
            target.bootstrap.alias_inherited = status.alias_inheritance.clone();
            target.bootstrap.approval_inherited_public_key = status.approval_public_key;
            if status.attachment_id != execution.spec.id {
                return Err("recovery Host attachment identity changed".into());
            }
        }
        targets.push(target);
    }
    if targets.is_empty() {
        return Err("approved recovery has no surviving native Host members".into());
    }
    let manager = attachments::inspect_process(std::process::id())?;
    let live = targets
        .iter()
        .map(|target| target.identity.clone())
        .collect::<Vec<_>>();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(attachments::recover_session(execution, &manager, &live))?;
    attachments::update_spec(&execution.state_directory, &execution.spec)?;
    serve_targets(execution.clone(), targets, manager, None)
}
