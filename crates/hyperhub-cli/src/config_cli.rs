use crate::config_semantics::{
    describe_request, new_uuid, unique_valid_uuids, ConfigChangeDescription,
};
use hyperhub_core::config::Config;
use hyperhub_core::config_store::{
    self, default_config_path, load_approval_state_with_keyring, load_encrypted_with_keyring,
    read_descriptor, read_redacted_json, save_approval_state_with_keyring,
    save_encrypted_with_keyring, ConfigKeyring, KdfDescriptor, StoreError,
};
use hyperhub_core::control::{control_request, discovery_control_endpoint};
use hyperhub_core::session::{config_update_proof, ControlRequest, ControlResponse};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Show,
    Patch {
        patch: PathBuf,
        password_file: Option<PathBuf>,
    },
    Approve {
        password_file: Option<PathBuf>,
        editor: Option<PathBuf>,
    },
}

struct ActiveConfig {
    config: Config,
    keyring: ConfigKeyring,
    initialized: bool,
}

struct PreparedPatch {
    config: Config,
    approval_token: String,
    changes: Vec<Value>,
}

const APPROVAL_QUEUE_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ApprovalRequest {
    #[serde(default = "new_uuid")]
    uuid: String,
    source_index: usize,
    operations: Vec<Value>,
    #[serde(default)]
    edited: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct InFlightApproval {
    index: usize,
    operations: Vec<Value>,
    result_config_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ApprovalQueue {
    schema_version: u32,
    proposal_token: String,
    patch_digest: String,
    expected_config_digest: String,
    requests: Vec<ApprovalRequest>,
    cursor: usize,
    approved: usize,
    rejected: usize,
    #[serde(default)]
    in_flight: Option<InFlightApproval>,
}

#[derive(Debug)]
struct ApplyOutcome {
    live_update: bool,
    live_update_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectApplyOutcome {
    pub(crate) live_update: bool,
    pub(crate) live_update_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalDecision {
    Approve,
    Edit,
    Reject,
    Quit,
}

pub(crate) fn parse(args: &[OsString]) -> Result<Command, String> {
    let Some(action) = args.first().map(|value| value.to_string_lossy()) else {
        return Err("config command requires `patch`".into());
    };
    match action.as_ref() {
        "patch" => parse_patch(&args[1..]),
        value => Err(format!("unknown config action '{value}'")),
    }
}

fn parse_patch(args: &[OsString]) -> Result<Command, String> {
    let patch = args
        .first()
        .ok_or("config patch requires a JSON patch file or - for stdin")?
        .clone()
        .into();
    let mut password_file = None;
    let mut index = 1;
    while index < args.len() {
        let option = args[index].to_string_lossy();
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("{option} requires a value"))?
            .clone();
        match option.as_ref() {
            "--password-file" => password_file = Some(value.into()),
            _ => return Err(format!("unknown config patch option '{option}'")),
        }
        index += 1;
    }
    Ok(Command::Patch {
        patch,
        password_file,
    })
}

pub(crate) fn parse_show(args: &[OsString]) -> Result<Command, String> {
    if args.is_empty() {
        Ok(Command::Show)
    } else {
        Err("show accepts no options".into())
    }
}

pub(crate) fn parse_approve(args: &[OsString]) -> Result<Command, String> {
    let mut password_file = None;
    let mut editor = None;
    let mut index = 0;
    while index < args.len() {
        let option = args[index].to_string_lossy();
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("{option} requires a value"))?
            .clone();
        match option.as_ref() {
            "--password-file" => password_file = Some(value.into()),
            "--editor" => editor = Some(value.into()),
            _ => return Err(format!("unknown approve option '{option}'")),
        }
        index += 1;
    }
    Ok(Command::Approve {
        password_file,
        editor,
    })
}

pub(crate) fn save_direct_config(
    path: &Path,
    password: &Zeroizing<String>,
    config: Config,
) -> Result<DirectApplyOutcome, String> {
    config.validate().map_err(|error| error.to_string())?;
    let mut active = load_active_with_password(path, Zeroizing::new((**password).clone()), None)?;
    let prepared = PreparedPatch {
        config,
        approval_token: String::new(),
        changes: Vec::new(),
    };
    let outcome = persist_prepared(path, &mut active, &prepared)?;
    Ok(DirectApplyOutcome {
        live_update: outcome.live_update,
        live_update_error: outcome.live_update_error,
    })
}

pub(crate) fn run(command: Command) -> Result<i32, String> {
    match command {
        Command::Show => show(),
        Command::Patch {
            patch,
            password_file,
        } => patch_config(&patch, password_file.as_deref()),
        Command::Approve {
            password_file,
            editor,
        } => approve_config(password_file.as_deref(), editor.as_deref()),
    }
}

fn show() -> Result<i32, String> {
    let path = default_config_path().map_err(|error| error.to_string())?;
    let bytes = if path.is_file() {
        read_redacted_json(&path).map_err(|error| match error {
            StoreError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                "redacted configuration view is not initialized; run `hyperhub validate --password-file <file>` once to migrate the existing encrypted config".into()
            }
            other => other.to_string(),
        })?
    } else {
        let mut config = Config::default();
        config.apply_managed_audit_paths(&path);
        config.environment = crate::default_environment();
        let mut bytes =
            serde_json::to_vec_pretty(&config.redacted()).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        bytes
    };
    let text = String::from_utf8(bytes)
        .map_err(|_| "redacted configuration JSON is not UTF-8".to_string())?;
    print!("{text}");
    Ok(0)
}

fn patch_config(patch_path: &Path, password_file: Option<&Path>) -> Result<i32, String> {
    let path = default_config_path().map_err(|error| error.to_string())?;
    let queue_path = approval_queue_path(&path);
    let password =
        crate::password::acquire(password_file, !path.is_file() && !queue_path.is_file())?;
    let descriptor_hint = queue_path
        .is_file()
        .then(|| read_descriptor(&queue_path).map_err(|error| error.to_string()))
        .transpose()?;
    let active = load_active_with_password(&path, password, descriptor_hint)?;
    let mut patch = parse_patch_file(patch_path)?;
    collect_placeholders(&patch)?;
    let patch_digest = value_digest(b"hyperhub/config-patch/v1\0", &patch)?;

    if queue_path.is_file() {
        let (queue, descriptor) = load_queue(&queue_path, &active.keyring)?;
        ensure_queue_descriptor(&active, &descriptor)?;
        validate_queue(&queue)?;
        if queue.patch_digest != patch_digest {
            return Err(
                "another configuration approval is pending; run `hyperhub approve` before submitting a different patch"
                    .into(),
            );
        }
        print_json(&json!({
            "schema_version": 1,
            "status": "approval_pending",
            "approval_token": queue.proposal_token,
            "config_path": path,
            "request_count": queue.requests.len(),
            "completed": queue.cursor,
            "remaining": queue.requests.len().saturating_sub(queue.cursor),
        }))?;
        return Ok(0);
    }

    normalize_config_item_uuids(&active.config, &mut patch)?;
    let prepared = prepare_patch(&path, &active.config, &patch)?;
    if prepared.changes.is_empty() {
        return Err("JSON patch does not change the configuration".into());
    }
    let requests = build_approval_requests(&patch)?;
    let request_descriptions = describe_request_sequence(&path, &active.config, &requests)?;
    let queue = ApprovalQueue {
        schema_version: APPROVAL_QUEUE_SCHEMA,
        proposal_token: prepared.approval_token.clone(),
        patch_digest,
        expected_config_digest: config_digest(&active.config)?,
        requests,
        cursor: 0,
        approved: 0,
        rejected: 0,
        in_flight: None,
    };
    save_queue(&queue_path, &queue, &active)?;
    let request_views = queue
        .requests
        .iter()
        .zip(&request_descriptions)
        .enumerate()
        .map(|(index, (request, description))| {
            semantic_request_json(request, description, index, queue.requests.len())
        })
        .collect::<Vec<_>>();
    print_json(&json!({
        "schema_version": 1,
        "status": "approval_required",
        "approval_token": prepared.approval_token,
        "initialized": active.initialized,
        "serve_running": crate::serve_is_running(),
        "config_path": path,
        "request_count": queue.requests.len(),
        "requests": request_views,
        "changes": prepared.changes,
    }))?;
    Ok(0)
}

fn approve_config(password_file: Option<&Path>, editor: Option<&Path>) -> Result<i32, String> {
    let path = default_config_path().map_err(|error| error.to_string())?;
    let queue_path = approval_queue_path(&path);
    if !queue_path.is_file() {
        return Err("there are no pending configuration requests".into());
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err("approve requires an interactive terminal for human review".into());
    }

    let password = crate::password::acquire(password_file, false)?;
    let queue_descriptor = read_descriptor(&queue_path).map_err(|error| error.to_string())?;
    let mut active = load_active_with_password(&path, password, Some(queue_descriptor.clone()))?;
    let (mut queue, queue_descriptor) = load_queue(&queue_path, &active.keyring)?;
    validate_queue(&queue)?;
    ensure_queue_descriptor(&active, &queue_descriptor)?;
    // Persist UUIDs generated while loading queues created by older versions.
    save_queue(&queue_path, &queue, &active)?;

    recover_in_flight(&path, &queue_path, &mut active, &mut queue)?;
    let current_digest = config_digest(&active.config)?;
    if queue.expected_config_digest != current_digest {
        eprintln!(
            "hyperhub: warning: configuration changed while approval was pending; remaining requests will be reviewed against the current configuration"
        );
        queue.expected_config_digest = current_digest;
        save_queue(&queue_path, &queue, &active)?;
    }

    while queue.cursor < queue.requests.len() {
        let index = queue.cursor;
        let total = queue.requests.len();
        let request = queue.requests[index].clone();
        let patch = Value::Array(request.operations.clone());
        let preview = prepare_patch(&path, &active.config, &patch);
        let placeholders = collect_placeholders(&patch)?;
        let current_value =
            serde_json::to_value(&active.config).map_err(|error| error.to_string())?;
        let description = describe_request(&current_value, &request.operations)?;
        display_request(
            index,
            total,
            &request,
            &description,
            preview.as_ref(),
            &placeholders,
        )?;
        let decision = prompt_decision(preview.is_ok())?;
        match decision {
            ApprovalDecision::Quit => {
                print_json(&json!({
                    "schema_version": 1,
                    "status": "approval_pending",
                    "completed": queue.cursor,
                    "remaining": total - queue.cursor,
                    "next": queue.cursor + 1,
                    "total": total,
                }))?;
                return Ok(0);
            }
            ApprovalDecision::Edit => {
                let edited = edit_request(&request, editor)?;
                queue.requests[index] = edited;
                save_queue(&queue_path, &queue, &active)?;
            }
            ApprovalDecision::Reject => {
                queue.cursor += 1;
                queue.rejected += 1;
                save_queue(&queue_path, &queue, &active)?;
                eprintln!("[{}/{}] 已拒绝", index + 1, total);
            }
            ApprovalDecision::Approve => {
                let mut approved_operations = request.operations.clone();
                let placeholders =
                    collect_placeholders(&Value::Array(approved_operations.clone()))?;
                for (secret_index, placeholder) in placeholders.iter().enumerate() {
                    eprintln!(
                        "Sensitive value {}/{} for request {}/{}: {}",
                        secret_index + 1,
                        placeholders.len(),
                        index + 1,
                        total,
                        placeholder
                    );
                    let value = crate::password::prompt_secret("Enter value (masked): ")?;
                    eprintln!();
                    if value.is_empty() {
                        return Err(format!(
                            "approval placeholder '{placeholder}' cannot be empty; request {}/{} remains pending",
                            index + 1,
                            total
                        ));
                    }
                    for operation in &mut approved_operations {
                        replace_placeholder(operation, placeholder, &value);
                    }
                }
                let approved_patch = Value::Array(approved_operations.clone());
                let prepared = prepare_patch(&path, &active.config, &approved_patch).map_err(|error| {
                    format!(
                        "request {}/{} cannot be approved against the current configuration: {error}",
                        index + 1,
                        total
                    )
                })?;
                let result_digest = config_digest(&prepared.config)?;
                queue.in_flight = Some(InFlightApproval {
                    index,
                    operations: approved_operations,
                    result_config_digest: result_digest.clone(),
                });
                save_queue(&queue_path, &queue, &active)?;
                let outcome = persist_prepared(&path, &mut active, &prepared)?;
                queue.cursor += 1;
                queue.approved += 1;
                queue.expected_config_digest = result_digest;
                queue.in_flight = None;
                save_queue(&queue_path, &queue, &active)?;
                print_apply_progress(index, total, &outcome);
            }
        }
    }

    remove_queue(&queue_path)?;
    print_json(&json!({
        "schema_version": 1,
        "status": "completed",
        "config_path": path,
        "total": queue.requests.len(),
        "approved": queue.approved,
        "rejected": queue.rejected,
    }))?;
    Ok(0)
}

fn persist_prepared(
    path: &Path,
    active: &mut ActiveConfig,
    prepared: &PreparedPatch,
) -> Result<ApplyOutcome, String> {
    save_encrypted_with_keyring(path, &prepared.config, &active.keyring)
        .map_err(|error| error.to_string())?;
    let _ = config_store::reconcile_root_certificates(
        path,
        prepared
            .config
            .root_certificates
            .iter()
            .map(|certificate| certificate.fingerprint.as_str()),
    );
    let (live_update, live_update_error) = if crate::serve_is_running() {
        match push_live_update(&prepared.config, &active.keyring) {
            Ok(()) => (true, None),
            Err(error) => (false, Some(error)),
        }
    } else {
        (false, None)
    };
    active.config = prepared.config.clone();
    active.initialized = true;
    Ok(ApplyOutcome {
        live_update,
        live_update_error,
    })
}

fn load_active_with_password(
    path: &Path,
    password: Zeroizing<String>,
    descriptor_hint: Option<KdfDescriptor>,
) -> Result<ActiveConfig, String> {
    let initialized = path.is_file();
    let descriptor = if initialized {
        read_descriptor(path).map_err(|error| error.to_string())?
    } else {
        descriptor_hint.unwrap_or_else(config_store::new_descriptor)
    };
    let keyring = ConfigKeyring::derive(password.as_bytes(), descriptor)
        .map_err(|error| error.to_string())?;
    drop(password);
    if initialized {
        let unlocked =
            load_encrypted_with_keyring(path, &keyring).map_err(|error| error.to_string())?;
        Ok(ActiveConfig {
            config: unlocked.config,
            keyring,
            initialized,
        })
    } else {
        let mut config = Config::default();
        config.apply_managed_audit_paths(path);
        config.environment = crate::default_environment();
        Ok(ActiveConfig {
            config,
            keyring,
            initialized,
        })
    }
}

fn read_patch_bytes(path: &Path) -> Result<Vec<u8>, String> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read JSON patch from stdin: {error}"))?;
        Ok(bytes)
    } else {
        std::fs::read(path)
            .map_err(|error| format!("cannot read JSON patch {}: {error}", path.display()))
    }
}

fn parse_patch_file(path: &Path) -> Result<Value, String> {
    let bytes = read_patch_bytes(path)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid JSON patch: {error}"))
}

fn approval_queue_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("approval.bin")
}

fn load_queue(
    path: &Path,
    keyring: &ConfigKeyring,
) -> Result<(ApprovalQueue, KdfDescriptor), String> {
    let unlocked =
        load_approval_state_with_keyring(path, keyring).map_err(|error| error.to_string())?;
    let queue = serde_json::from_slice(&unlocked.bytes)
        .map_err(|error| format!("approval state is invalid: {error}"))?;
    Ok((queue, unlocked.descriptor))
}

fn save_queue(path: &Path, queue: &ApprovalQueue, active: &ActiveConfig) -> Result<(), String> {
    let bytes = serde_json::to_vec(queue).map_err(|error| error.to_string())?;
    save_approval_state_with_keyring(path, &bytes, &active.keyring)
        .map_err(|error| error.to_string())
}

fn remove_queue(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot remove completed approval state {}: {error}",
            path.display()
        )),
    }
}

fn ensure_queue_descriptor(
    active: &ActiveConfig,
    descriptor: &KdfDescriptor,
) -> Result<(), String> {
    if active.initialized && active.keyring.descriptor() != descriptor {
        Err("approval state belongs to a different configuration generation".into())
    } else {
        Ok(())
    }
}

fn validate_queue(queue: &ApprovalQueue) -> Result<(), String> {
    if queue.schema_version != APPROVAL_QUEUE_SCHEMA {
        return Err(format!(
            "unsupported approval state version {}",
            queue.schema_version
        ));
    }
    if queue.requests.is_empty() {
        return Err("approval state contains no requests".into());
    }
    if !unique_valid_uuids(queue.requests.iter().map(|request| request.uuid.as_str())) {
        return Err("approval state contains an invalid or duplicate request UUID".into());
    }
    if queue.cursor > queue.requests.len()
        || queue.approved + queue.rejected != queue.cursor
        || queue
            .in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight.index != queue.cursor)
    {
        return Err("approval state progress is inconsistent".into());
    }
    Ok(())
}

fn normalize_config_item_uuids(current: &Config, patch: &mut Value) -> Result<(), String> {
    let current = serde_json::to_value(current).map_err(|error| error.to_string())?;
    let operations = patch
        .as_array_mut()
        .ok_or("JSON patch must be an array of operations")?;
    for operation in operations {
        let Some(object) = operation.as_object_mut() else {
            continue;
        };
        let Some(action) = object.get("op").and_then(Value::as_str) else {
            continue;
        };
        if !matches!(action, "add" | "replace") {
            continue;
        }
        let Some(path) = object
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            continue;
        };
        let tokens = pointer_tokens(&path)?;
        if !is_config_item_path(&tokens) {
            continue;
        }
        let existing_uuid = if action == "replace" {
            current
                .pointer(&path)
                .and_then(|value| value.get("uuid"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        } else {
            None
        };
        let value = object
            .get_mut("value")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| format!("configuration item at {path} must be an object"))?;
        match value.get("uuid").and_then(Value::as_str) {
            Some(uuid) if hyperhub_core::config::valid_config_uuid(uuid) => {}
            Some(uuid) => {
                return Err(format!(
                    "configuration item at {path} has invalid UUID '{uuid}'"
                ))
            }
            None => {
                value.insert(
                    "uuid".into(),
                    Value::String(
                        existing_uuid.unwrap_or_else(hyperhub_core::config::new_config_uuid),
                    ),
                );
            }
        }
    }
    Ok(())
}

fn is_config_item_path(tokens: &[String]) -> bool {
    matches!(
        tokens,
        [root, _]
            if matches!(
                root.as_str(),
                "upstreams"
                    | "plugins"
                    | "protections"
                    | "routes"
                    | "environment"
                    | "root_certificates"
                    | "ssh_host_keys"
            )
    ) || matches!(tokens, [root, _, intelligence, providers, _]
        if root == "protections" && intelligence == "intelligence" && providers == "providers")
        || matches!(tokens, [root, rules, _] if root == "firewall" && rules == "rules")
        || matches!(
            tokens,
            [root, area, rules, _]
                if root == "sandbox"
                    && matches!(area.as_str(), "process" | "file")
                    && rules == "rules"
        )
}

fn build_approval_requests(patch: &Value) -> Result<Vec<ApprovalRequest>, String> {
    let operations = patch
        .as_array()
        .ok_or("JSON patch must be an array of operations")?;
    let mut requests = Vec::new();
    let mut preconditions = Vec::new();
    for (source_index, operation) in operations.iter().enumerate() {
        let action = operation
            .as_object()
            .and_then(|object| object.get("op"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("patch operation {source_index} is missing string field 'op'")
            })?;
        if action == "test" {
            preconditions.push(operation.clone());
            continue;
        }
        if !matches!(action, "add" | "replace" | "remove") {
            return Err(format!(
                "unsupported patch operation '{action}'; use add, replace, remove, or test"
            ));
        }
        let mut grouped = std::mem::take(&mut preconditions);
        grouped.push(operation.clone());
        requests.push(ApprovalRequest {
            uuid: new_uuid(),
            source_index,
            operations: grouped,
            edited: false,
        });
    }
    if requests.is_empty() {
        return Err("JSON patch contains no configuration requests".into());
    }
    if !preconditions.is_empty() {
        return Err("trailing test operations must precede a configuration request".into());
    }
    Ok(requests)
}

fn describe_request_sequence(
    path: &Path,
    current: &Config,
    requests: &[ApprovalRequest],
) -> Result<Vec<ConfigChangeDescription>, String> {
    let mut config = current.clone();
    let mut descriptions = Vec::with_capacity(requests.len());
    for (index, request) in requests.iter().enumerate() {
        let current_value = serde_json::to_value(&config).map_err(|error| error.to_string())?;
        descriptions.push(describe_request(&current_value, &request.operations)?);
        let prepared = prepare_patch(path, &config, &Value::Array(request.operations.clone()))
            .map_err(|error| {
                format!(
                    "configuration request {}/{} is not independently valid: {error}",
                    index + 1,
                    requests.len()
                )
            })?;
        config = prepared.config;
    }
    Ok(descriptions)
}

fn semantic_request_json(
    request: &ApprovalRequest,
    description: &ConfigChangeDescription,
    index: usize,
    total: usize,
) -> Value {
    json!({
        "uuid": request.uuid,
        "config_item_uuid": description.item_uuid,
        "progress": {"current": index + 1, "total": total},
        "action": description.action.label(),
        "section": description.section.breadcrumb(),
        "item_kind": description.item_kind,
        "item_name": description.item_name,
        "field": description.field,
        "details": description.details,
        "summary": description.summary,
        "edited": request.edited,
    })
}

fn recover_in_flight(
    path: &Path,
    queue_path: &Path,
    active: &mut ActiveConfig,
    queue: &mut ApprovalQueue,
) -> Result<(), String> {
    let Some(in_flight) = queue.in_flight.clone() else {
        return Ok(());
    };
    let current_digest = config_digest(&active.config)?;
    let outcome = if current_digest == queue.expected_config_digest {
        let prepared = prepare_patch(
            path,
            &active.config,
            &Value::Array(in_flight.operations.clone()),
        )?;
        if config_digest(&prepared.config)? != in_flight.result_config_digest {
            return Err("in-flight approval result no longer matches its recorded state".into());
        }
        persist_prepared(path, active, &prepared)?
    } else if current_digest == in_flight.result_config_digest {
        let serve_running = crate::serve_is_running();
        let live_update_error = if serve_running {
            push_live_update(&active.config, &active.keyring).err()
        } else {
            None
        };
        ApplyOutcome {
            live_update: serve_running && live_update_error.is_none(),
            live_update_error,
        }
    } else {
        return Err(
            "configuration changed during an in-flight approval; refusing ambiguous recovery"
                .into(),
        );
    };

    queue.cursor += 1;
    queue.approved += 1;
    queue.expected_config_digest = in_flight.result_config_digest;
    queue.in_flight = None;
    save_queue(queue_path, queue, active)?;
    print_apply_progress(in_flight.index, queue.requests.len(), &outcome);
    Ok(())
}

fn display_request(
    index: usize,
    total: usize,
    request: &ApprovalRequest,
    description: &ConfigChangeDescription,
    preview: Result<&PreparedPatch, &String>,
    placeholders: &[String],
) -> Result<(), String> {
    let mutation = request
        .operations
        .iter()
        .rev()
        .find(|operation| operation.get("op").and_then(Value::as_str) != Some("test"))
        .and_then(Value::as_object)
        .ok_or("approval request operation is invalid")?;
    let operation = mutation
        .get("op")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let path = mutation
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let rendered_description = match preview {
        Ok(prepared) if operation != "remove" => {
            let resulting =
                serde_json::to_value(&prepared.config).map_err(|error| error.to_string())?;
            describe_request(&resulting, &request.operations)
                .unwrap_or_else(|_| description.clone())
        }
        _ => description.clone(),
    };
    let validation_error = preview.err().map(String::as_str);
    eprintln!("\n[{}/{}] 配置审批项", index + 1, total);
    eprintln!(
        "{}",
        render_approval_review(
            request,
            &rendered_description,
            operation,
            path,
            placeholders,
            validation_error,
        )
    );
    Ok(())
}

fn render_approval_review(
    request: &ApprovalRequest,
    description: &ConfigChangeDescription,
    operation: &str,
    path: &str,
    placeholders: &[String],
    validation_error: Option<&str>,
) -> String {
    let object = match description.item_name.as_deref() {
        Some(name) => format!("{}「{name}」", description.item_kind),
        None => description.item_kind.clone(),
    };
    let mut lines = vec![
        format!("  操作          {}", description.action.label()),
        format!("  位置          {}", description.section.breadcrumb()),
        format!("  对象          {object}"),
    ];
    if let Some(uuid) = description.item_uuid.as_deref() {
        lines.push(format!("  配置 UUID     {uuid}"));
    }
    if let Some(field) = description.field.as_deref() {
        lines.push(format!("  字段          {field}"));
    }
    lines.push(format!("  摘要          {}", description.summary));
    if !description.details.is_empty() {
        lines.push("  配置详情".into());
        lines.extend(
            description
                .details
                .iter()
                .map(|detail| format!("    • {detail}")),
        );
    }
    if placeholders.is_empty() {
        lines.push("  敏感信息      无需额外输入".into());
    } else {
        lines.push(format!(
            "  敏感信息      {} 项，将在批准后隐藏输入",
            placeholders.len()
        ));
        lines.extend(
            placeholders
                .iter()
                .map(|placeholder| format!("    • {placeholder}")),
        );
    }
    match validation_error {
        Some(error) => lines.push(format!("  校验          失败：{error}")),
        None => lines.push("  校验          通过".into()),
    }
    lines.push(format!(
        "  审批请求      {}{}",
        request.uuid,
        if request.edited {
            "（已二次编辑）"
        } else {
            ""
        }
    ));
    lines.push(format!("  技术定位      {operation} {path}"));
    lines.join("\n")
}

fn prompt_decision(can_approve: bool) -> Result<ApprovalDecision, String> {
    loop {
        if can_approve {
            eprint!("选择 [a]批准、[e]编辑、[r]拒绝、[q]暂退: ");
        } else {
            eprint!("当前配置项无效；选择 [e]编辑、[r]拒绝、[q]暂退: ");
        }
        std::io::stderr()
            .flush()
            .map_err(|error| error.to_string())?;
        let mut answer = String::new();
        let count = std::io::stdin()
            .read_line(&mut answer)
            .map_err(|error| format!("cannot read approval decision: {error}"))?;
        if count == 0 {
            return Ok(ApprovalDecision::Quit);
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "a" | "approve" if can_approve => return Ok(ApprovalDecision::Approve),
            "e" | "edit" => return Ok(ApprovalDecision::Edit),
            "r" | "reject" => return Ok(ApprovalDecision::Reject),
            "q" | "quit" => return Ok(ApprovalDecision::Quit),
            _ => eprintln!("无效选择。"),
        }
    }
}

fn edit_request(
    request: &ApprovalRequest,
    explicit: Option<&Path>,
) -> Result<ApprovalRequest, String> {
    let mutation = request
        .operations
        .last()
        .cloned()
        .ok_or("approval request has no mutation")?;
    let review_path = create_review_file(&mutation)?;
    let result = (|| {
        open_editor(&review_path, explicit)?;
        let edited = parse_patch_file(&review_path)?;
        let object = edited
            .as_object()
            .ok_or("edited configuration request must be a JSON object")?;
        let action = object
            .get("op")
            .and_then(Value::as_str)
            .ok_or("edited configuration request is missing string field 'op'")?;
        if !matches!(action, "add" | "replace" | "remove") {
            return Err("edited configuration request must use add, replace, or remove".into());
        }
        if object.get("path").and_then(Value::as_str).is_none() {
            return Err("edited configuration request is missing string field 'path'".into());
        }
        collect_placeholders(&edited)?;
        let mut request = request.clone();
        *request.operations.last_mut().expect("mutation exists") = edited;
        request.edited = true;
        Ok(request)
    })();
    let _ = std::fs::remove_file(&review_path);
    result
}

fn create_review_file(value: &Value) -> Result<PathBuf, String> {
    let path = std::env::temp_dir().join(format!(
        "hyperhub-approve-{}-{:016x}.json",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| format!("cannot create approval review file: {error}"))?;
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .map_err(|error| format!("cannot write approval review file: {error}"))?;
    Ok(path)
}

fn open_editor(review_path: &Path, explicit: Option<&Path>) -> Result<(), String> {
    let editor = explicit
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HYPERHUB_EDITOR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(if cfg!(windows) { "notepad.exe" } else { "vi" }));
    let status = std::process::Command::new(&editor)
        .arg(review_path)
        .status()
        .map_err(|error| format!("cannot start approval editor {}: {error}", editor.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("approval editor exited with {status}"))
    }
}

fn print_apply_progress(index: usize, total: usize, outcome: &ApplyOutcome) {
    eprintln!(
        "[{}/{}] 已批准（live_update={}）",
        index + 1,
        total,
        outcome.live_update
    );
    if let Some(error) = &outcome.live_update_error {
        eprintln!("hyperhub: warning: configuration was saved but live update failed: {error}");
    }
}

fn value_digest(label: &[u8], value: &Value) -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(label);
    hash.update(serde_json::to_vec(value).map_err(|error| error.to_string())?);
    Ok(hex(&hash.finalize()))
}

fn config_digest(config: &Config) -> Result<String, String> {
    value_digest(
        b"hyperhub/config-state/v1\0",
        &serde_json::to_value(config).map_err(|error| error.to_string())?,
    )
}

fn collect_placeholders(value: &Value) -> Result<Vec<String>, String> {
    let mut placeholders = Vec::new();
    collect_placeholders_inner(value, &mut placeholders)?;
    placeholders.sort();
    placeholders.dedup();
    Ok(placeholders)
}

fn collect_placeholders_inner(value: &Value, output: &mut Vec<String>) -> Result<(), String> {
    match value {
        Value::String(value) => {
            if let Some(name) = parse_placeholder(value)? {
                output.push(name.to_owned());
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_placeholders_inner(value, output)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_placeholders_inner(value, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_placeholder(value: &str) -> Result<Option<&str>, String> {
    if !value.starts_with("${APPROVE:") {
        return Ok(None);
    }
    let Some(name) = value
        .strip_prefix("${APPROVE:")
        .and_then(|value| value.strip_suffix('}'))
    else {
        return Err(format!("invalid approval placeholder '{value}'"));
    };
    if name.is_empty()
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(format!("invalid approval placeholder name '{name}'"));
    }
    Ok(Some(name))
}

fn replace_placeholder(value: &mut Value, name: &str, replacement: &str) {
    match value {
        Value::String(value) if value == &format!("${{APPROVE:{name}}}") => {
            *value = replacement.to_owned();
        }
        Value::Array(values) => {
            for value in values {
                replace_placeholder(value, name, replacement);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_placeholder(value, name, replacement);
            }
        }
        _ => {}
    }
}

fn prepare_patch(path: &Path, current: &Config, patch: &Value) -> Result<PreparedPatch, String> {
    let current_value = serde_json::to_value(current).map_err(|error| error.to_string())?;
    let mut next_value = current_value.clone();
    apply_json_patch(&mut next_value, patch)?;
    let mut config: Config = serde_json::from_value(next_value.clone())
        .map_err(|error| format!("patched configuration has invalid shape: {error}"))?;
    config.apply_managed_audit_paths(path);
    config.validate().map_err(|error| error.to_string())?;
    next_value = serde_json::to_value(&config).map_err(|error| error.to_string())?;

    let mut hash = Sha256::new();
    hash.update(b"hyperhub/config-approval/v1\0");
    hash.update(serde_json::to_vec(&current_value).map_err(|error| error.to_string())?);
    hash.update([0]);
    hash.update(serde_json::to_vec(patch).map_err(|error| error.to_string())?);
    hash.update([0]);
    hash.update(serde_json::to_vec(&next_value).map_err(|error| error.to_string())?);
    let approval_token = hex(&hash.finalize());

    let before = serde_json::to_value(current.redacted()).map_err(|error| error.to_string())?;
    let after = serde_json::to_value(config.redacted()).map_err(|error| error.to_string())?;
    let mut changes = Vec::new();
    collect_changes("", &before, &after, &mut changes);
    Ok(PreparedPatch {
        config,
        approval_token,
        changes,
    })
}

fn apply_json_patch(document: &mut Value, patch: &Value) -> Result<(), String> {
    let operations = patch
        .as_array()
        .ok_or("JSON patch must be an array of operations")?;
    for (index, operation) in operations.iter().enumerate() {
        let object = operation
            .as_object()
            .ok_or_else(|| format!("patch operation {index} must be an object"))?;
        let action = object
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("patch operation {index} is missing string field 'op'"))?;
        let path = object
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("patch operation {index} is missing string field 'path'"))?;
        match action {
            "add" => patch_add(
                document,
                path,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| format!("patch add operation {index} is missing 'value'"))?,
            )?,
            "replace" => patch_replace(
                document,
                path,
                object
                    .get("value")
                    .cloned()
                    .ok_or_else(|| format!("patch replace operation {index} is missing 'value'"))?,
            )?,
            "remove" => patch_remove(document, path)?,
            "test" => {
                let expected = object
                    .get("value")
                    .ok_or_else(|| format!("patch test operation {index} is missing 'value'"))?;
                let actual = document
                    .pointer(path)
                    .ok_or_else(|| format!("patch test path does not exist: {path}"))?;
                if actual != expected {
                    return Err(format!("patch test failed at {path}"));
                }
            }
            other => {
                return Err(format!(
                    "unsupported patch operation '{other}'; use add, replace, remove, or test"
                ))
            }
        }
    }
    Ok(())
}

fn patch_add(document: &mut Value, path: &str, value: Value) -> Result<(), String> {
    if path.is_empty() {
        *document = value;
        return Ok(());
    }
    let (parent, token) = patch_parent(document, path)?;
    match parent {
        Value::Object(map) => {
            map.insert(token, value);
            Ok(())
        }
        Value::Array(array) if token == "-" => {
            array.push(value);
            Ok(())
        }
        Value::Array(array) => {
            let index = parse_array_index(&token, array.len(), true)?;
            array.insert(index, value);
            Ok(())
        }
        _ => Err(format!("patch add parent is not a container: {path}")),
    }
}

fn patch_replace(document: &mut Value, path: &str, value: Value) -> Result<(), String> {
    if path.is_empty() {
        *document = value;
        return Ok(());
    }
    let (parent, token) = patch_parent(document, path)?;
    match parent {
        Value::Object(map) if map.contains_key(&token) => {
            map.insert(token, value);
            Ok(())
        }
        Value::Array(array) => {
            let index = parse_array_index(&token, array.len(), false)?;
            array[index] = value;
            Ok(())
        }
        _ => Err(format!("patch replace path does not exist: {path}")),
    }
}

fn patch_remove(document: &mut Value, path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("removing the configuration root is not allowed".into());
    }
    let (parent, token) = patch_parent(document, path)?;
    match parent {
        Value::Object(map) => {
            if map.remove(&token).is_some() {
                Ok(())
            } else {
                Err(format!("patch remove path does not exist: {path}"))
            }
        }
        Value::Array(array) => {
            let index = parse_array_index(&token, array.len(), false)?;
            array.remove(index);
            Ok(())
        }
        _ => Err(format!("patch remove path does not exist: {path}")),
    }
}

fn patch_parent<'a>(
    document: &'a mut Value,
    path: &str,
) -> Result<(&'a mut Value, String), String> {
    let tokens = pointer_tokens(path)?;
    let (last, parents) = tokens.split_last().ok_or("patch path must not be empty")?;
    let mut current = document;
    for token in parents {
        current = match current {
            Value::Object(map) => map
                .get_mut(token)
                .ok_or_else(|| format!("patch path does not exist: {path}"))?,
            Value::Array(array) => {
                let index = parse_array_index(token, array.len(), false)?;
                &mut array[index]
            }
            _ => return Err(format!("patch path traverses a scalar: {path}")),
        };
    }
    Ok((current, last.clone()))
}

fn pointer_tokens(path: &str) -> Result<Vec<String>, String> {
    if !path.starts_with('/') {
        return Err(format!("JSON pointer must start with '/': {path}"));
    }
    path[1..]
        .split('/')
        .map(|token| {
            let mut decoded = String::new();
            let mut chars = token.chars();
            while let Some(character) = chars.next() {
                if character != '~' {
                    decoded.push(character);
                    continue;
                }
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => return Err(format!("invalid JSON pointer escape in {path}")),
                }
            }
            Ok(decoded)
        })
        .collect()
}

fn parse_array_index(token: &str, length: usize, allow_end: bool) -> Result<usize, String> {
    let index = token
        .parse::<usize>()
        .map_err(|_| format!("invalid array index '{token}'"))?;
    if index < length || (allow_end && index == length) {
        Ok(index)
    } else {
        Err(format!(
            "array index {index} is out of bounds for length {length}"
        ))
    }
}

fn collect_changes(path: &str, before: &Value, after: &Value, output: &mut Vec<Value>) {
    if before == after {
        return;
    }
    match (before, after) {
        (Value::Object(left), Value::Object(right)) => {
            let mut keys = left.keys().chain(right.keys()).collect::<Vec<_>>();
            keys.sort();
            keys.dedup();
            for key in keys {
                let next_path = format!("{path}/{}", escape_pointer(key));
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => collect_changes(&next_path, left, right, output),
                    (left, right) => output.push(json!({
                        "path": next_path,
                        "before": left.cloned().unwrap_or(Value::Null),
                        "after": right.cloned().unwrap_or(Value::Null),
                    })),
                }
            }
        }
        _ => output.push(json!({
            "path": if path.is_empty() { "/" } else { path },
            "before": before,
            "after": after,
        })),
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn push_live_update(config: &Config, keyring: &ConfigKeyring) -> Result<(), String> {
    let key = keyring
        .session_auth_key()
        .map_err(|error| error.to_string())?;
    let config_json = serde_json::to_string(config).map_err(|error| error.to_string())?;
    let proof = config_update_proof(&key, &config_json)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    match runtime
        .block_on(control_request(
            &discovery_control_endpoint(),
            &ControlRequest::UpdateConfig { proof, config_json },
        ))
        .map_err(|error| format!("cannot update running Serve: {error}"))?
    {
        ControlResponse::Ok => Ok(()),
        ControlResponse::Error { message } => Err(message),
        _ => Err("Serve returned an unexpected config update response".into()),
    }
}

fn print_json(value: &Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_review_is_human_readable_instead_of_raw_json() {
        let request = ApprovalRequest {
            uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            source_index: 0,
            operations: vec![json!({
                "op": "add",
                "path": "/routes/-",
                "value": {
                    "uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "id": "devboard-api",
                    "enabled": true,
                    "priority": 100,
                    "endpoints": [{
                        "target": "https://devboard.chaitin.net/devboard/api",
                        "port": 443
                    }],
                    "deny": false,
                    "plugins": ["devboard-token"]
                }
            })],
            edited: false,
        };
        let description = describe_request(&json!({"routes": []}), &request.operations).unwrap();
        let rendered = render_approval_review(
            &request,
            &description,
            "add",
            "/routes/-",
            &["devboard-token".into()],
            None,
        );

        assert!(rendered.contains("操作          新增"));
        assert!(rendered.contains("位置          网关 / 路由"));
        assert!(rendered.contains("对象          路由「devboard-api」"));
        assert!(rendered.contains("https://devboard.chaitin.net/devboard/api（端口 443）"));
        assert!(rendered.contains("敏感信息      1 项，将在批准后隐藏输入"));
        assert!(rendered.contains("校验          通过"));
        assert!(!rendered.contains("\"changes\""));
        assert!(!rendered.contains("\"schema_version\""));
        assert!(!rendered.contains('{'));
    }

    #[test]
    fn json_patch_add_replace_remove_and_test() {
        let mut value = json!({"routes": [{"id": "one"}], "debug": false});
        apply_json_patch(
            &mut value,
            &json!([
                {"op": "test", "path": "/debug", "value": false},
                {"op": "replace", "path": "/debug", "value": true},
                {"op": "add", "path": "/routes/-", "value": {"id": "two"}},
                {"op": "remove", "path": "/routes/0"}
            ]),
        )
        .unwrap();
        assert_eq!(value, json!({"routes": [{"id": "two"}], "debug": true}));
    }

    #[test]
    fn approval_token_changes_with_current_config_and_patch() {
        let directory = std::env::temp_dir();
        let path = directory.join("hyperhub-config-cli-test.bin");
        let config = Config::default();
        let first = prepare_patch(
            &path,
            &config,
            &json!([{"op": "replace", "path": "/debug", "value": true}]),
        )
        .unwrap();
        let second = prepare_patch(
            &path,
            &config,
            &json!([{"op": "replace", "path": "/debug", "value": false}]),
        )
        .unwrap();
        assert_ne!(first.approval_token, second.approval_token);
        assert_eq!(first.changes.len(), 1);
    }

    #[test]
    fn approval_placeholders_are_collected_and_replaced() {
        let mut patch = json!([
            {"op": "add", "path": "/one", "value": "${APPROVE:api-key}"},
            {"op": "add", "path": "/two", "value": "${APPROVE:api-key}"}
        ]);
        assert_eq!(collect_placeholders(&patch).unwrap(), ["api-key"]);
        replace_placeholder(&mut patch, "api-key", "real-secret");
        assert_eq!(collect_placeholders(&patch).unwrap(), Vec::<String>::new());
        assert_eq!(patch[0]["value"], "real-secret");
        assert_eq!(patch[1]["value"], "real-secret");
    }

    #[test]
    fn config_item_uuid_is_injected_and_preserved_for_replacement() {
        let mut config = Config::default();
        config.rules.push(hyperhub_core::config::RouteRule {
            uuid: hyperhub_core::config::new_config_uuid(),
            id: "existing".into(),
            enabled: true,
            priority: 1,
            endpoints: Vec::new(),
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: Vec::new(),
            legacy: Default::default(),
            protection: None,
            allow_sensitive_upload: false,
        });
        let existing = config.rules[0].uuid.clone();
        let mut patch = json!([
            {"op": "add", "path": "/routes/-", "value": {"id": "new"}},
            {"op": "replace", "path": "/routes/0", "value": {"id": "existing-renamed"}}
        ]);
        normalize_config_item_uuids(&config, &mut patch).unwrap();
        let added = patch[0]["value"]["uuid"].as_str().unwrap();
        assert!(hyperhub_core::config::valid_config_uuid(added));
        assert_ne!(added, existing);
        assert_eq!(patch[1]["value"]["uuid"], existing);
    }

    #[test]
    fn approval_requests_attach_tests_to_the_next_mutation() {
        let requests = build_approval_requests(&json!([
            {"op": "test", "path": "/debug", "value": false},
            {"op": "replace", "path": "/debug", "value": true},
            {"op": "add", "path": "/routes/-", "value": {"id": "two"}}
        ]))
        .unwrap();
        assert_eq!(requests.len(), 2);
        assert!(crate::config_semantics::valid_uuid(&requests[0].uuid));
        assert!(crate::config_semantics::valid_uuid(&requests[1].uuid));
        assert_ne!(requests[0].uuid, requests[1].uuid);
        assert_eq!(requests[0].source_index, 1);
        assert_eq!(requests[0].operations.len(), 2);
        assert_eq!(requests[1].source_index, 2);
        assert_eq!(requests[1].operations.len(), 1);
    }

    #[test]
    fn legacy_approval_requests_receive_a_valid_uuid() {
        let request: ApprovalRequest = serde_json::from_value(json!({
            "source_index": 0,
            "operations": [
                {"op": "replace", "path": "/debug", "value": true}
            ],
            "edited": false
        }))
        .unwrap();
        assert!(crate::config_semantics::valid_uuid(&request.uuid));
    }

    #[test]
    fn approval_queue_requires_consistent_progress() {
        let request = ApprovalRequest {
            uuid: new_uuid(),
            source_index: 0,
            operations: vec![json!({"op": "replace", "path": "/debug", "value": true})],
            edited: false,
        };
        let mut queue = ApprovalQueue {
            schema_version: APPROVAL_QUEUE_SCHEMA,
            proposal_token: "token".into(),
            patch_digest: "patch".into(),
            expected_config_digest: "config".into(),
            requests: vec![request],
            cursor: 0,
            approved: 0,
            rejected: 0,
            in_flight: None,
        };
        validate_queue(&queue).unwrap();
        queue.cursor = 1;
        assert!(validate_queue(&queue).is_err());
        queue.approved = 1;
        validate_queue(&queue).unwrap();
    }

    #[test]
    fn malformed_approval_placeholder_is_rejected() {
        let error = collect_placeholders(&json!("${APPROVE:bad name}")).unwrap_err();
        assert!(error.contains("invalid approval placeholder"));
    }
}
