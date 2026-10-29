use super::{Execution, Outcome, Phase, Record, Request, Spec};
use crate::config_store::{self, ConfigKeyring};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

// The IPC listener and backend reporter share this record. Serialize their
// read-modify-write operations so a policy refresh cannot be lost to a status ACK.
static RECORD_WRITER: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn record_writer() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    RECORD_WRITER
        .lock()
        .map_err(|_| "attachment record writer is poisoned".into())
}

pub fn directory() -> Result<PathBuf, String> {
    Ok(config_store::hyperhub_home()
        .map_err(|e| e.to_string())?
        .join("runtime")
        .join("attachments"))
}
pub fn private_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("attachment state directory is not a private directory".into());
        }
    } else {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                private_directory(parent)?;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.to_string()),
            }
        }
        #[cfg(not(unix))]
        std::fs::create_dir(path).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if m.uid() != unsafe { libc::geteuid() } {
            return Err("attachment state directory has another owner".into());
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    #[cfg(windows)]
    config_store::restrict_file_to_current_user(path).map_err(|e| e.to_string())?;
    Ok(())
}
pub fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    config_store::restrict_file_to_current_user(path).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}
pub fn read_private_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("attachment state is not a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err("attachment state file permissions are not private".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("attachment state exceeds its size limit".into());
    }
    Ok(bytes)
}
fn save_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    config_store::save_durable_private_bytes(path, &bytes).map_err(|e| e.to_string())
}
pub fn request_path(directory: &Path, id: &str) -> Result<PathBuf, String> {
    if !super::valid_id(id) {
        return Err("invalid runtime approval identifier".into());
    }
    Ok(directory.join("proposals").join(format!("{id}.json")))
}
pub fn save_request(directory: &Path, request: &Request) -> Result<(), String> {
    request.validate()?;
    private_directory(directory)?;
    private_directory(&directory.join("proposals"))?;
    let path = request_path(directory, &request.id)?;
    create_private_file(
        &path,
        &serde_json::to_vec_pretty(request).map_err(|e| e.to_string())?,
    )
}
pub fn load_request(directory: &Path, id: &str) -> Result<Request, String> {
    let r: Request = serde_json::from_slice(&read_private_file(
        &request_path(directory, id)?,
        1024 * 1024,
    )?)
    .map_err(|e| e.to_string())?;
    r.validate()?;
    if r.id != id {
        return Err("approval filename/id mismatch".into());
    }
    Ok(r)
}
pub fn stale_request_audit(
    directory: &Path,
    id: &str,
) -> Result<Option<super::StaleRequestAudit>, String> {
    request_path(directory, id)?;
    let history = directory.join("history");
    if !history.join(format!("{id}-stale.json")).exists() {
        return Ok(None);
    }
    let archived: Request = serde_json::from_slice(&read_private_file(
        &history.join(format!("{id}-stale.json")),
        1024 * 1024,
    )?)
    .map_err(|e| e.to_string())?;
    archived.validate()?;
    let audit: super::StaleRequestAudit = serde_json::from_slice(&read_private_file(
        &history.join(format!("{id}-stale-reason.json")),
        64 * 1024,
    )?)
    .map_err(|e| e.to_string())?;
    if archived.id != id || audit.schema_version != 1 || audit.request_id != id {
        return Err("stale approval audit identity mismatch".into());
    }
    Ok(Some(audit))
}
/// Archive the exact proposal bytes without signing or replacing the request.
/// The caller must retain this instance's OperationGuard across validation and
/// this transition. An unavailable validation result must never call here.
pub fn archive_stale_request(
    directory: &Path,
    request: &Request,
    reason: super::StaleRequestReason,
    guard: &OperationGuard,
) -> Result<(), String> {
    if guard.directory != directory.canonicalize().map_err(|e| e.to_string())? {
        return Err("approval archive uses another operation namespace".into());
    }
    let source = request_path(directory, &request.id)?;
    let history = directory.join("history");
    let target = history.join(format!("{}-stale.json", request.id));
    if !source.exists() {
        if stale_request_audit(directory, &request.id)?.is_some() {
            let archived: Request =
                serde_json::from_slice(&read_private_file(&target, 1024 * 1024)?)
                    .map_err(|e| e.to_string())?;
            if archived == *request {
                return Ok(());
            }
        }
        return Err("runtime request is no longer pending".into());
    }
    if load_request(directory, &request.id)? != *request {
        return Err("runtime request changed before stale archive".into());
    }
    private_directory(&history)?;
    if target.exists() {
        return Err("stale request audit already exists while proposal is pending".into());
    }
    let reason_path = history.join(format!("{}-stale-reason.json", request.id));
    if reason_path.exists() {
        let previous: super::StaleRequestAudit =
            serde_json::from_slice(&read_private_file(&reason_path, 64 * 1024)?)
                .map_err(|e| e.to_string())?;
        if previous.schema_version != 1 || previous.request_id != request.id {
            return Err("stale approval audit identity mismatch".into());
        }
    } else {
        save_json(
            &reason_path,
            &super::StaleRequestAudit {
                schema_version: 1,
                request_id: request.id.clone(),
                reason,
                archived_at_ms: crate::session::unix_timestamp_ms(),
            },
        )?;
    }
    std::fs::rename(source, target).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        std::fs::File::open(&history)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| e.to_string())?;
        std::fs::File::open(directory.join("proposals"))
            .and_then(|directory| directory.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn requests(directory: &Path) -> Result<Vec<Request>, String> {
    let path = directory.join("proposals");
    if !path.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(id) = name.strip_suffix(".json") {
            if super::valid_id(id) {
                out.push(load_request(directory, id)?);
            }
        }
    }
    out.sort_by_key(|r| r.created_at_ms);
    Ok(out)
}
pub fn attachment_directory(directory: &Path, id: &str) -> Result<PathBuf, String> {
    if !super::valid_id(id) {
        return Err("invalid attachment identifier".into());
    }
    Ok(directory.join(id))
}
pub fn create_record(directory: &Path, spec: Spec) -> Result<Record, String> {
    let dir = attachment_directory(directory, &spec.id)?;
    private_directory(&dir)?;
    let session_id = format!("attach-{}", spec.id);
    let record = Record {
        exec_epoch: spec.exec_epoch,
        current_target: spec.current_target.clone(),
        spec,
        host_binding: None,
        origin: super::Origin::Attach,
        session_id,
        phase: Phase::Preparing,
        members: vec![],
        manager: None,
        manager_endpoint: None,
        compatibility_reasons: vec![],
        error: None,
        updated_at_ms: crate::session::unix_timestamp_ms(),
    };
    create_private_file(
        &dir.join("record.json"),
        &serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
    )?;
    Ok(record)
}
pub fn load_record(directory: &Path) -> Result<Record, String> {
    serde_json::from_slice(&read_private_file(
        &directory.join("record.json"),
        1024 * 1024,
    )?)
    .map_err(|e| e.to_string())
}
pub fn update_record(directory: &Path, outcome: &Outcome) -> Result<Record, String> {
    let _writer = record_writer()?;
    let mut record = load_record(directory)?;
    record.phase = outcome.phase;
    record.members = outcome.members.clone();
    record.manager = outcome.manager.clone();
    record.manager_endpoint = outcome.manager_endpoint.clone();
    record.compatibility_reasons = outcome.compatibility_reasons.clone();
    record.error = None;
    record.updated_at_ms = crate::session::unix_timestamp_ms();
    save_json(&directory.join("record.json"), &record)?;
    Ok(record)
}
pub fn fail_record(directory: &Path, message: String) -> Result<(), String> {
    let _writer = record_writer()?;
    let mut r = load_record(directory)?;
    r.phase = Phase::Failed;
    r.error = Some(message);
    r.updated_at_ms = crate::session::unix_timestamp_ms();
    save_json(&directory.join("record.json"), &r)
}
pub fn records(directory: &Path) -> Result<Vec<Record>, String> {
    if !directory.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for e in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
        let e = e.map_err(|e| e.to_string())?;
        if e.file_name().to_str().is_some_and(super::valid_id) {
            let mut record = load_record(&e.path())?;
            // Root exit alone says nothing about live descendants. The owning
            // manager publishes Exited only after its actual member set drains.
            if !record.phase.is_terminal() {
                if let Some(manager) = &record.manager {
                    if super::process_incarnation_exited(manager.pid, manager.birth) {
                        record.phase = Phase::Degraded;
                        let reason = if record.spec.backend == super::Backend::Ptrace {
                            "ptrace_enforcement_lost"
                        } else {
                            "attachment_management_lost_hook_state_unknown"
                        };
                        if !record.compatibility_reasons.iter().any(|r| r == reason) {
                            record.compatibility_reasons.push(reason.into());
                        }
                        record.error.get_or_insert_with(||"attachment manager incarnation is no longer alive; target state requires revalidation".into());
                    }
                }
            }
            out.push(record);
        }
    }
    out.sort_by_key(|r| r.updated_at_ms);
    Ok(out)
}
pub fn save_execution(
    directory: &Path,
    execution: &Execution,
    keyring: &ConfigKeyring,
) -> Result<PathBuf, String> {
    private_directory(directory)?;
    let binding = execution
        .bootstrap
        .approval_binding()
        .map_err(|e| e.to_string())?;
    {
        let _writer = record_writer()?;
        let mut record = load_record(directory)?;
        if record
            .host_binding
            .as_ref()
            .is_some_and(|old| old != &binding)
        {
            return Err("attachment Host binding is immutable".into());
        }
        record.host_binding = Some(binding);
        save_json(&directory.join("record.json"), &record)?;
    }
    let path = directory.join("execution.bin");
    config_store::save_approval_state_with_keyring(
        &path,
        &serde_json::to_vec(execution).map_err(|e| e.to_string())?,
        keyring,
    )
    .map_err(|e| e.to_string())?;
    Ok(path)
}
pub fn load_execution(directory: &Path, keyring: &ConfigKeyring) -> Result<Execution, String> {
    let state = super::key_rotation::load_runtime_envelope(directory, "execution.bin", keyring)?;
    let e: Execution = serde_json::from_slice(&state.bytes).map_err(|e| e.to_string())?;
    if e.state_directory != directory {
        return Err("attachment execution directory mismatch".into());
    }
    Ok(e)
}

pub fn update_spec(directory: &Path, spec: &Spec) -> Result<Record, String> {
    let _writer = record_writer()?;
    let mut record = load_record(directory)?;
    if record.spec.id != spec.id
        || record.spec.target != spec.target
        || record.spec.scope != spec.scope
        || record.spec.backend != spec.backend
    {
        return Err("resident attachment contract cannot be silently rebound".into());
    }
    record.spec = spec.clone();
    record.updated_at_ms = crate::session::unix_timestamp_ms();
    save_json(&directory.join("record.json"), &record)?;
    Ok(record)
}

pub fn register_owned_run(
    directory: &Path,
    spec: Spec,
    session_id: String,
    manager: super::ProcessIdentity,
) -> Result<Record, String> {
    super::verify_process(&manager)?;
    super::verify_process(&spec.target)?;
    if manager.pid != std::process::id()
        || !crate::control::process_ancestors(spec.target.pid).contains(&manager.pid)
    {
        return Err("reversible run registration requires actual launcher-child ancestry".into());
    }
    let mut record = create_record(directory, spec)?;
    record.origin = super::Origin::Run;
    record.session_id = session_id;
    record.manager = Some(manager);
    record.members = vec![record.spec.target.clone()];
    save_json(
        &attachment_directory(directory, &record.spec.id)?.join("record.json"),
        &record,
    )?;
    Ok(record)
}

/// OS-released advisory lock. A crashed approval client cannot leave a stale
/// lock, and two approval terminals cannot race duplicate attachment creation.
pub struct OperationGuard {
    _file: std::fs::File,
    directory: PathBuf,
}
impl OperationGuard {
    pub(crate) fn protects(&self, directory: &Path) -> Result<(), String> {
        if self.directory != directory.canonicalize().map_err(|e| e.to_string())? {
            return Err("operation guard belongs to another configuration instance".into());
        }
        Ok(())
    }
    pub fn acquire(directory: &Path) -> Result<Self, String> {
        private_directory(directory)?;
        let path = directory.join("operation.lock");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(&path).map_err(|e| e.to_string())?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("runtime operation lock is not a regular file".into());
        }
        #[cfg(windows)]
        config_store::restrict_file_to_current_user(&path).map_err(|e| e.to_string())?;
        file.try_lock()
            .map_err(|e| format!("another runtime approval operation is in progress: {e}"))?;
        Ok(Self {
            _file: file,
            directory: directory.canonicalize().map_err(|e| e.to_string())?,
        })
    }
}

pub fn record_execution_error(directory: &Path, message: String) -> Result<(), String> {
    let _writer = record_writer()?;
    let mut record = load_record(directory)?;
    record.phase = match record.phase {
        Phase::Preparing => Phase::CleanupPending,
        Phase::Active => Phase::Degraded,
        other => other,
    };
    record.error = Some(message);
    record.updated_at_ms = crate::session::unix_timestamp_ms();
    save_json(&directory.join("record.json"), &record)
}

/// Backend reconnection metadata can contain broker credentials. It uses the
/// existing private runtime envelope and never enters public attachment status.
pub fn save_recovery_context<T: serde::Serialize>(
    directory: &Path,
    value: &T,
    keyring: &ConfigKeyring,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    config_store::save_approval_state_with_keyring(
        &directory.join("recovery.bin"),
        &bytes,
        keyring,
    )
    .map_err(|e| e.to_string())?;
    Ok(super::digest(&bytes))
}
pub fn load_recovery_context<T: serde::de::DeserializeOwned>(
    directory: &Path,
    keyring: &ConfigKeyring,
) -> Result<(T, String), String> {
    let value = super::key_rotation::load_runtime_envelope(directory, "recovery.bin", keyring)?;
    let digest = super::digest(&value.bytes);
    Ok((
        serde_json::from_slice(&value.bytes).map_err(|e| e.to_string())?,
        digest,
    ))
}

/// Lifetime ownership for private external/recovery managers. An approval can
/// time out while its manager is still validating targets; a second approval
/// must not start a competing controller for the same durable attachment.
pub struct ManagerGuard {
    _file: std::fs::File,
}
impl ManagerGuard {
    pub fn acquire(directory: &Path) -> Result<Self, String> {
        private_directory(directory)?;
        let path = directory.join("manager.lock");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(&path).map_err(|e| e.to_string())?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("manager lock is not a regular file".into());
        }
        #[cfg(windows)]
        config_store::restrict_file_to_current_user(&path).map_err(|e| e.to_string())?;
        file.try_lock()
            .map_err(|e| format!("attachment already has a live manager execution: {e}"))?;
        Ok(Self { _file: file })
    }
}

/// Only Core's authenticated exec bridge and a fresh approved actual image use
/// this update. Original Spec.target remains the initial approved incarnation.
pub(crate) fn update_current_target(
    directory: &Path,
    previous: &super::ProcessIdentity,
    current: &super::ProcessIdentity,
    exec_epoch: u64,
) -> Result<Record, String> {
    let _writer = record_writer()?;
    let mut record = load_record(directory)?;
    if !record.spec.target.same_incarnation(current) || !previous.same_incarnation(current) {
        return Err("exec transition changes approved process incarnation".into());
    }
    super::verify_process(current)?;
    if record.effective_target() == current && record.exec_epoch == exec_epoch {
        return Ok(record);
    }
    if exec_epoch < record.exec_epoch {
        return Err("root image audit cannot move backwards".into());
    }
    if record.effective_target() != previous {
        return Err("exec transition does not extend the current verified image".into());
    }
    record.current_target = Some(current.clone());
    record.exec_epoch = exec_epoch;
    record.updated_at_ms = crate::session::unix_timestamp_ms();
    save_json(&directory.join("record.json"), &record)?;
    Ok(record)
}
