use crate::config_semantics::{
    describe_request, new_uuid, unique_valid_uuids, ConfigChangeDescription,
};
use hyperhub_core::config::Config;
use hyperhub_core::config_document::ConfigDocument;
use hyperhub_core::config_store::{
    self, default_config_path, load_approval_state_with_keyring, load_encrypted_with_keyring,
    read_descriptor, read_redacted_json, save_approval_state_with_keyring, save_private_bytes,
    ConfigKeyring, KdfDescriptor, StoreError,
};
use hyperhub_core::control::{configuration_control_request, discovery_control_endpoint};
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
    },
    Approve {
        request_id: Option<String>,
        password_file: Option<PathBuf>,
        editor: Option<PathBuf>,
    },
}

struct ActiveConfig {
    config: Config,
    keyring: ConfigKeyring,
    initialized: bool,
    persistence_signer: hyperhub_core::config_persistence::ConfigPersistenceSigner,
}

struct PreparedPatch {
    config: Config,
    approval_token: String,
    changes: Vec<Value>,
    secret_writes: Vec<SecretWrite>,
}

#[derive(Clone)]
struct SecretWrite {
    path: String,
    operation_index: usize,
    value_pointer: String,
    placeholder: Option<String>,
    test_binding: bool,
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
    match args {
        [patch] => Ok(Command::Patch {
            patch: patch.clone().into(),
        }),
        [] => Err("config patch requires a JSON patch file or - for stdin".into()),
        _ => Err("config patch accepts only a JSON patch file or - for stdin; authentication happens during `hyperhub approve`".into()),
    }
}

pub(crate) fn parse_show(args: &[OsString]) -> Result<Command, String> {
    if args.is_empty() {
        Ok(Command::Show)
    } else {
        Err("show accepts no options".into())
    }
}

pub(crate) fn parse_approve(args: &[OsString]) -> Result<Command, String> {
    let mut request_id = None;
    let mut password_file = None;
    let mut editor = None;
    let mut index = 0;
    while index < args.len() {
        let option = args[index].to_string_lossy();
        index += 1;
        if !option.starts_with('-') {
            if request_id.is_some() || !hyperhub_core::attachments::valid_id(&option) {
                return Err("approve accepts at most one runtime request id".into());
            }
            request_id = Some(option.into_owned());
            continue;
        }
        let value = args
            .get(index)
            .ok_or_else(|| format!("{option} requires a value"))?
            .clone();
        match option.as_ref() {
            "--admin-password-file" => password_file = Some(value.into()),
            "--editor" => editor = Some(value.into()),
            "--password-file" => return Err(
                "approve uses --admin-password-file for administrator confirmation; runtime API keys are loaded automatically"
                    .into(),
            ),
            _ => return Err(format!("unknown approve option '{option}'")),
        }
        index += 1;
    }
    Ok(Command::Approve {
        request_id,
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
        secret_writes: Vec::new(),
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
        Command::Patch { patch } => patch_config(&patch),
        Command::Approve {
            request_id,
            password_file,
            editor,
        } => {
            match crate::attachment::approve(
                request_id.as_deref(),
                password_file.as_deref(),
                editor.as_deref(),
            )? {
                Some(code) => Ok(code),
                None => approve_config(password_file.as_deref(), editor.as_deref()),
            }
        }
    }
}

fn show() -> Result<i32, String> {
    let path = default_config_path().map_err(|error| error.to_string())?;
    let bytes = if path.is_file() {
        read_redacted_json(&path).map_err(|error| match error {
            StoreError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                "redacted configuration view is not initialized; run `hyperhub validate` to refresh it".into()
            }
            other => other.to_string(),
        })?
    } else {
        let mut config = Config::default();
        config.apply_managed_audit_paths(&path);
        config.environment = crate::default_environment();
        let mut bytes = serde_json::to_vec_pretty(&ConfigDocument::from_config(&config.redacted()))
            .map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        bytes
    };
    let text = String::from_utf8(bytes)
        .map_err(|_| "redacted configuration JSON is not UTF-8".to_string())?;
    let view: Value = serde_json::from_str(&text)
        .map_err(|error| format!("redacted configuration JSON is invalid: {error}"))?;
    if view.get("schema_version").and_then(Value::as_u64) != Some(2) {
        return Err("unsupported legacy configuration view; HyperHub v0.2 requires schema_version 2 and does not migrate old configurations".into());
    }
    print!("{text}");
    Ok(0)
}

fn patch_config(patch_path: &Path) -> Result<i32, String> {
    let path = default_config_path().map_err(|error| error.to_string())?;
    let queue_path = approval_queue_path(&path);
    let proposal_path = approval_proposal_path(&path);
    if queue_path.is_file() {
        print_json(&json!({
            "schema_version": 1,
            "status": "approval_pending",
            "config_path": path,
            "encrypted_review_in_progress": true,
        }))?;
        return Ok(0);
    }

    let mut patch = parse_patch_file(patch_path)?;
    ensure_proposal_contains_no_literal_secrets(&patch)?;
    collect_placeholders(&patch)?;
    let patch_digest = value_digest(b"hyperhub/config-patch/v1\0", &patch)?;

    if proposal_path.is_file() {
        let queue = load_proposal(&proposal_path)?;
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
            "completed": 0,
            "remaining": queue.requests.len(),
        }))?;
        return Ok(0);
    }

    let planning = load_planning_config(&path)?;
    normalize_config_item_uuids(&planning, &mut patch)?;
    let prepared = prepare_proposal_patch(&path, &planning, &patch)?;
    if prepared.changes.is_empty() {
        return Err("JSON patch does not change the configuration".into());
    }
    let (requests, request_descriptions) = prepare_approval_sequence(&path, &planning, &patch)?;
    let queue = ApprovalQueue {
        schema_version: APPROVAL_QUEUE_SCHEMA,
        proposal_token: prepared.approval_token.clone(),
        patch_digest,
        expected_config_digest: String::new(),
        requests,
        cursor: 0,
        approved: 0,
        rejected: 0,
        in_flight: None,
    };
    save_proposal(&proposal_path, &queue)?;
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
        "initialized": path.is_file(),
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
    let proposal_path = approval_proposal_path(&path);
    if !queue_path.is_file() && !proposal_path.is_file() {
        return Err("there are no pending configuration requests".into());
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err("approve requires an interactive terminal for human review".into());
    }

    let password = crate::password::acquire(password_file, !path.is_file())?;
    let descriptor_hint = queue_path
        .is_file()
        .then(|| read_descriptor(&queue_path).map_err(|error| error.to_string()))
        .transpose()?;
    let mut active = load_active_with_password(&path, password, descriptor_hint.clone())?;
    let mut queue = if queue_path.is_file() {
        let (queue, queue_descriptor) = load_queue(&queue_path, &active.keyring)?;
        ensure_queue_descriptor(&active, &queue_descriptor)?;
        queue
    } else {
        let mut queue = load_proposal(&proposal_path)?;
        validate_queue(&queue)?;
        describe_request_sequence(&path, &active.config, &queue.requests).map_err(|error| {
            format!("pending configuration proposal is no longer valid: {error}")
        })?;
        queue.expected_config_digest = config_digest(&active.config)?;
        save_queue(&queue_path, &queue, &active)?;
        remove_queue(&proposal_path)?;
        queue
    };
    validate_queue(&queue)?;
    if proposal_path.is_file() {
        remove_queue(&proposal_path)?;
    }
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
        let preview = prepare_proposal_patch(&path, &active.config, &patch);
        let secret_writes = preview
            .as_ref()
            .map(|prepared| prepared.secret_writes.clone())
            .unwrap_or_default();
        let placeholders = secret_input_names(&secret_writes);
        let current_value = config_value(&active.config)?;
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
                prepare_proposal_patch(
                    &path,
                    &active.config,
                    &Value::Array(edited.operations.clone()),
                )?;
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
                let placeholders = secret_input_names(&secret_writes);
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
                    replace_secret_inputs(
                        &mut approved_operations,
                        &secret_writes,
                        placeholder,
                        &value,
                    )?;
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
    remove_queue(&proposal_path)?;
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
    let live_update = crate::config_persistence::save(
        path,
        Some(&active.config),
        &prepared.config,
        &active.keyring,
        Some(&active.persistence_signer),
        crate::serve_is_running(),
    )?;
    crate::password::save_runtime_keyring(&active.keyring)?;
    let _ = config_store::reconcile_root_certificates(
        path,
        prepared
            .config
            .root_certificates
            .iter()
            .map(|certificate| certificate.fingerprint.as_str()),
    );
    active.config = prepared.config.clone();
    active.initialized = true;
    Ok(ApplyOutcome {
        live_update,
        live_update_error: None,
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
    let persistence_signer =
        hyperhub_core::config_persistence::ConfigPersistenceSigner::from_password(
            password.as_bytes(),
            keyring.descriptor(),
        )?;
    drop(password);
    if initialized {
        let unlocked =
            load_encrypted_with_keyring(path, &keyring).map_err(|error| error.to_string())?;
        Ok(ActiveConfig {
            config: unlocked.config,
            keyring,
            initialized,
            persistence_signer,
        })
    } else {
        let mut config = Config::default();
        config.apply_managed_audit_paths(path);
        config.environment = crate::default_environment();
        Ok(ActiveConfig {
            config,
            keyring,
            initialized,
            persistence_signer,
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

fn approval_proposal_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("approval.json")
}

fn load_planning_config(path: &Path) -> Result<Config, String> {
    if path.is_file() {
        let bytes = read_redacted_json(path).map_err(|error| match error {
            StoreError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                "redacted configuration view is not initialized; run `hyperhub validate` before submitting configuration requests".into()
            }
            other => other.to_string(),
        })?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("redacted configuration JSON is invalid: {error}"))?;
        let mut config = ConfigDocument::from_value(value)?;
        config.apply_managed_audit_paths(path);
        Ok(config)
    } else {
        let mut config = Config::default();
        config.apply_managed_audit_paths(path);
        config.environment = crate::default_environment();
        Ok(config)
    }
}

fn load_proposal(path: &Path) -> Result<ApprovalQueue, String> {
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "cannot read configuration proposal {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("configuration proposal is invalid: {error}"))
}

fn save_proposal(path: &Path, queue: &ApprovalQueue) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(queue).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    save_private_bytes(path, &bytes).map_err(|error| error.to_string())
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
    let current = config_value(current)?;
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
    matches!(tokens, [root, _] if root == "environment_variables")
        || matches!(tokens, [gateway, collection, _] if gateway == "gateway" && matches!(collection.as_str(), "proxies" | "credentials"))
        || matches!(tokens, [gateway, section, collection, _]
            if gateway == "gateway"
                && matches!((section.as_str(), collection.as_str()),
                    ("audit", "profiles")
                        | ("routing", "routes")
                        | ("trust", "tls_certificates")
                        | ("trust", "ssh_host_keys")))
        || matches!(tokens, [gateway, collection, _]
            if gateway == "gateway" && collection == "protections")
        || matches!(tokens, [gateway, collection, _, intelligence, provider]
            if gateway == "gateway"
                && collection == "protections"
                && intelligence == "intelligence"
                && provider == "provider")
        || matches!(tokens, [sandbox, area, rules, _]
            if sandbox == "sandbox"
                && matches!(area.as_str(), "network" | "file" | "process")
                && rules == "rules")
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

fn build_atomic_approval_request(patch: &Value) -> Result<Vec<ApprovalRequest>, String> {
    let operations = patch
        .as_array()
        .ok_or("JSON patch must be an array of operations")?;
    if !operations.iter().any(|operation| {
        matches!(
            operation.get("op").and_then(Value::as_str),
            Some("add" | "replace" | "remove")
        )
    }) {
        return Err("JSON patch contains no configuration requests".into());
    }
    Ok(vec![ApprovalRequest {
        uuid: new_uuid(),
        source_index: operations.len().saturating_sub(1),
        operations: operations.to_vec(),
        edited: false,
    }])
}

fn prepare_approval_sequence(
    path: &Path,
    current: &Config,
    patch: &Value,
) -> Result<(Vec<ApprovalRequest>, Vec<ConfigChangeDescription>), String> {
    let requests = build_approval_requests(patch)?;
    if requests.len() > 1 && secret_inputs_need_atomic(path, current, patch, &requests)? {
        let requests = build_atomic_approval_request(patch)?;
        let descriptions = describe_request_sequence(path, current, &requests)?;
        return Ok((requests, descriptions));
    }
    match describe_request_sequence(path, current, &requests) {
        Ok(descriptions) => Ok((requests, descriptions)),
        Err(granular_error) if requests.len() > 1 => {
            let atomic_requests = build_atomic_approval_request(patch)?;
            let descriptions = describe_request_sequence(path, current, &atomic_requests).map_err(
                |atomic_error| {
                    format!(
                        "configuration requests are not independently valid ({granular_error}); atomic approval also failed: {atomic_error}"
                    )
                },
            )?;
            Ok((atomic_requests, descriptions))
        }
        Err(error) => Err(error),
    }
}

fn secret_inputs_need_atomic(
    path: &Path,
    current: &Config,
    patch: &Value,
    requests: &[ApprovalRequest],
) -> Result<bool, String> {
    let final_preview = prepare_proposal_patch(path, current, patch)?;
    let final_inputs = final_preview
        .secret_writes
        .iter()
        .filter(|write| write.placeholder.is_some() && !write.test_binding)
        .collect::<Vec<_>>();
    let mut config = current.clone();
    for request in requests {
        let Ok(preview) =
            prepare_proposal_patch(path, &config, &Value::Array(request.operations.clone()))
        else {
            return Ok(false);
        };
        let first_index = request.source_index + 1 - request.operations.len();
        if preview
            .secret_writes
            .iter()
            .filter(|write| write.placeholder.is_some() && !write.test_binding)
            .any(|write| {
                !final_inputs.iter().any(|final_write| {
                    final_write.operation_index == first_index + write.operation_index
                        && final_write.value_pointer == write.value_pointer
                })
            })
        {
            return Ok(true);
        }
        config = preview.config;
    }
    Ok(false)
}

fn describe_request_sequence(
    path: &Path,
    current: &Config,
    requests: &[ApprovalRequest],
) -> Result<Vec<ConfigChangeDescription>, String> {
    let mut config = current.clone();
    let mut descriptions = Vec::with_capacity(requests.len());
    for (index, request) in requests.iter().enumerate() {
        let current_value = config_value(&config)?;
        let mut description = describe_request(&current_value, &request.operations)?;
        let prepared =
            prepare_proposal_patch(path, &config, &Value::Array(request.operations.clone()))
                .map_err(|error| {
                    format!(
                        "configuration request {}/{} is not independently valid: {error}",
                        index + 1,
                        requests.len()
                    )
                })?;
        describe_secret_inputs(&mut description, &prepared.secret_writes);
        descriptions.push(description);
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
            push_live_update(path, &active.config, &active.keyring).err()
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
    let mut rendered_description = match preview {
        Ok(prepared) if operation != "remove" => {
            let resulting = config_value(&prepared.config)?;
            describe_request(&resulting, &request.operations)
                .unwrap_or_else(|_| description.clone())
        }
        _ => description.clone(),
    };
    if let Ok(prepared) = preview {
        describe_secret_inputs(&mut rendered_description, &prepared.secret_writes);
    }
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

fn config_value(config: &Config) -> Result<Value, String> {
    ConfigDocument::to_value(config).map_err(|error| error.to_string())
}

fn config_digest(config: &Config) -> Result<String, String> {
    value_digest(b"hyperhub/config-state/v1\0", &config_value(config)?)
}

fn ensure_proposal_contains_no_literal_secrets(patch: &Value) -> Result<(), String> {
    let operations = patch
        .as_array()
        .ok_or("JSON patch must be an array of operations")?;
    for (index, operation) in operations.iter().enumerate() {
        let Some(object) = operation.as_object() else {
            continue;
        };
        let action = object.get("op").and_then(Value::as_str).unwrap_or("");
        if !matches!(action, "add" | "replace") {
            continue;
        }
        let path = object.get("path").and_then(Value::as_str).unwrap_or("");
        let Some(value) = object.get("value") else {
            continue;
        };
        if value.is_string() && is_sensitive_secret_leaf(path) {
            ensure_approval_placeholder(value.as_str().unwrap(), index, path)?;
        }
        ensure_nested_secret_values_are_placeholders(value, index, path)?;
    }
    Ok(())
}

fn ensure_nested_secret_values_are_placeholders(
    value: &Value,
    operation_index: usize,
    path: &str,
) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            for value in values {
                ensure_nested_secret_values_are_placeholders(value, operation_index, path)?;
            }
        }
        Value::Object(values) => {
            if values.len() == 1 {
                if let Some(Value::String(secret)) = values.get("value") {
                    ensure_approval_placeholder(secret, operation_index, path)?;
                    return Ok(());
                }
            }
            for value in values.values() {
                ensure_nested_secret_values_are_placeholders(value, operation_index, path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn ensure_approval_placeholder(value: &str, index: usize, path: &str) -> Result<(), String> {
    if parse_placeholder(value)?.is_none() {
        return Err(format!(
            "patch operation {index} at {path} contains an inline secret; use ${{APPROVE:name}}, an environment reference, or a protected file reference"
        ));
    }
    Ok(())
}

fn is_sensitive_secret_leaf(path: &str) -> bool {
    path.ends_with("/value")
        && (path.contains("/environment_variables/")
            || path.contains("/gateway/credentials/")
            || path.contains("/gateway/proxies/"))
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
        return Err("invalid approval placeholder; expected ${APPROVE:name}".into());
    };
    if name.is_empty()
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(
            "invalid approval placeholder name; use letters, digits, dash, underscore, or period"
                .into(),
        );
    }
    Ok(Some(name))
}

fn prepare_proposal_patch(
    path: &Path,
    current: &Config,
    patch: &Value,
) -> Result<PreparedPatch, String> {
    let mut prepared = prepare_patch(path, current, patch)?;
    let current_value = config_value(current)?;
    prepared.secret_writes = secret_writes(&current_value, patch, &prepared.config)?;
    for write in prepared
        .secret_writes
        .iter()
        .filter(|write| write.placeholder.is_some() && !write.test_binding)
    {
        prepared.changes.push(
            json!({"path":write.path, "kind":"secret_update", "status":"awaiting_human_input"}),
        );
    }
    Ok(prepared)
}

// Carry origin labels through RFC 6902 mutations. Looking only at the final
// string or patch pointer loses provenance after array shifts or overwrites.
fn secret_writes(
    current: &Value,
    patch: &Value,
    config: &Config,
) -> Result<Vec<SecretWrite>, String> {
    let marker = format!("__hyperhub_input_{}", new_uuid());
    let mask = format!("__hyperhub_secret_{}", new_uuid());
    let mut tracked = current.clone();
    let mut intermediate = current.clone();
    let mut origins = Vec::new();
    let mut tests = Vec::new();
    for (index, operation) in patch
        .as_array()
        .ok_or("JSON patch must be an array")?
        .iter()
        .enumerate()
    {
        if operation["op"] == "test" {
            if let (Some(value), Some(path)) = (operation.get("value"), operation["path"].as_str())
            {
                if let Some(actual) = tracked.pointer(path) {
                    collect_input_tests(
                        value, actual, "/value", index, &marker, &origins, &mut tests,
                    );
                }
            }
            continue;
        }
        let mut marked = operation.clone();
        if let Some(value) = marked.get_mut("value") {
            mark_input_origins(value, &marker, index, "/value", &mut origins)?;
        }
        apply_json_patch(&mut tracked, &Value::Array(vec![marked]))?;
        apply_json_patch(&mut intermediate, &Value::Array(vec![operation.clone()]))?;
        // Validate all submitted typed inputs, including ones overwritten or
        // removed later. Final surviving origins alone determine UI prompts.
        if operation.get("value").is_some_and(contains_string) {
            let masked_step = ConfigDocument::redacted_unvalidated_value(intermediate.clone(), &mask)
                .map_err(|_| format!("patch operation {index} cannot be inspected; use an atomic object replacement for shape changes"))?;
            let mut step_writes = Vec::new();
            collect_secret_writes(
                "",
                &masked_step,
                &tracked,
                &mask,
                &marker,
                &origins,
                &mut step_writes,
            );
            if let Some(write) = step_writes.iter().find(|write| write.placeholder.is_none()) {
                return Err(format!("patch operation {} at {} contains an inline secret; use ${{APPROVE:name}}, an environment reference, or a protected file reference", write.operation_index, write.path));
            }
        }
    }
    let masked = config_value(&config.redacted_with_placeholder(&mask))?;
    let mut result = Vec::new();
    collect_secret_writes("", &masked, &tracked, &mask, &marker, &origins, &mut result);
    for (origin_index, operation_index, value_pointer) in tests {
        let origin = &origins[origin_index];
        if let Some(selected) = result
            .iter()
            .find(|write| {
                !write.test_binding
                    && write.operation_index == origin.operation_index
                    && write.value_pointer == origin.value_pointer
            })
            .cloned()
        {
            result.push(SecretWrite {
                operation_index,
                value_pointer,
                test_binding: true,
                ..selected
            });
        }
    }
    Ok(result)
}

fn contains_string(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(values) => values.iter().any(contains_string),
        Value::Object(values) => values.values().any(contains_string),
        _ => false,
    }
}

fn mark_input_origins(
    value: &mut Value,
    marker: &str,
    operation_index: usize,
    pointer: &str,
    origins: &mut Vec<SecretWrite>,
) -> Result<(), String> {
    match value {
        Value::String(text) => {
            let placeholder = parse_placeholder(text)?.map(str::to_owned);
            let index = origins.len();
            origins.push(SecretWrite {
                path: String::new(),
                operation_index,
                value_pointer: pointer.into(),
                placeholder,
                test_binding: false,
            });
            let mut tagged = serde_json::Map::new();
            tagged.insert(marker.into(), Value::from(index));
            *value = Value::Object(tagged);
        }
        Value::Array(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                mark_input_origins(
                    value,
                    marker,
                    operation_index,
                    &format!("{pointer}/{index}"),
                    origins,
                )?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                mark_input_origins(
                    value,
                    marker,
                    operation_index,
                    &format!("{pointer}/{}", escape_pointer(key)),
                    origins,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_input_tests(
    expected: &Value,
    tracked: &Value,
    pointer: &str,
    operation_index: usize,
    marker: &str,
    origins: &[SecretWrite],
    tests: &mut Vec<(usize, usize, String)>,
) {
    if let Some(index) = tracked
        .get(marker)
        .and_then(Value::as_u64)
        .and_then(|index| usize::try_from(index).ok())
    {
        if let Some(origin) = origins.get(index) {
            if expected
                .as_str()
                .and_then(|value| parse_placeholder(value).ok().flatten())
                == origin.placeholder.as_deref()
                && origin.placeholder.is_some()
            {
                tests.push((index, operation_index, pointer.into()));
            }
        }
        return;
    }
    match expected {
        Value::Object(values) => {
            for (key, value) in values {
                if let Some(tracked) = tracked.get(key) {
                    collect_input_tests(
                        value,
                        tracked,
                        &format!("{pointer}/{}", escape_pointer(key)),
                        operation_index,
                        marker,
                        origins,
                        tests,
                    );
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if let Some(tracked) = tracked.get(index) {
                    collect_input_tests(
                        value,
                        tracked,
                        &format!("{pointer}/{index}"),
                        operation_index,
                        marker,
                        origins,
                        tests,
                    );
                }
            }
        }
        _ => {}
    }
}

fn collect_secret_writes(
    path: &str,
    masked: &Value,
    tracked: &Value,
    mask: &str,
    marker: &str,
    origins: &[SecretWrite],
    result: &mut Vec<SecretWrite>,
) {
    if masked.as_str() == Some(mask) {
        if let Some(index) = tracked
            .get(marker)
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
        {
            if let Some(origin) = origins.get(index) {
                let mut write = origin.clone();
                write.path = path.into();
                result.push(write);
            }
        }
        return;
    }
    match masked {
        Value::Object(values) => {
            for (key, value) in values {
                if let Some(tracked) = tracked.get(key) {
                    collect_secret_writes(
                        &format!("{path}/{}", escape_pointer(key)),
                        value,
                        tracked,
                        mask,
                        marker,
                        origins,
                        result,
                    );
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if let Some(tracked) = tracked.get(index) {
                    collect_secret_writes(
                        &format!("{path}/{index}"),
                        value,
                        tracked,
                        mask,
                        marker,
                        origins,
                        result,
                    );
                }
            }
        }
        _ => {}
    }
}

fn secret_input_names(writes: &[SecretWrite]) -> Vec<String> {
    let mut names = Vec::new();
    for write in writes {
        if let Some(name) = &write.placeholder {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
    }
    names
}

fn replace_secret_inputs(
    operations: &mut [Value],
    writes: &[SecretWrite],
    name: &str,
    value: &str,
) -> Result<(), String> {
    for write in writes
        .iter()
        .filter(|write| write.placeholder.as_deref() == Some(name))
    {
        let slot = operations
            .get_mut(write.operation_index)
            .and_then(|operation| operation.pointer_mut(&write.value_pointer))
            .ok_or("approved Secret input no longer matches its request")?;
        if slot.as_str() != Some(&format!("${{APPROVE:{name}}}")) {
            return Err("approved Secret placeholder no longer matches its request".into());
        }
        *slot = Value::String(value.into());
    }
    Ok(())
}

fn describe_secret_inputs(description: &mut ConfigChangeDescription, writes: &[SecretWrite]) {
    for write in writes
        .iter()
        .filter(|write| write.placeholder.is_some() && !write.test_binding)
    {
        description
            .details
            .push(format!("更新 Secret：{}；待人工输入", write.path));
    }
}

fn prepare_patch(path: &Path, current: &Config, patch: &Value) -> Result<PreparedPatch, String> {
    let current_value = config_value(current)?;
    let mut next_value = current_value.clone();
    apply_json_patch(&mut next_value, patch)?;
    let mut config = ConfigDocument::from_value(next_value.clone())
        .map_err(|error| format!("patched configuration has invalid shape: {error}"))?;
    config.apply_managed_audit_paths(path);
    config.validate().map_err(|error| error.to_string())?;
    next_value = config_value(&config)?;

    let mut hash = Sha256::new();
    hash.update(b"hyperhub/config-approval/v1\0");
    hash.update(serde_json::to_vec(&current_value).map_err(|error| error.to_string())?);
    hash.update([0]);
    hash.update(serde_json::to_vec(patch).map_err(|error| error.to_string())?);
    hash.update([0]);
    hash.update(serde_json::to_vec(&next_value).map_err(|error| error.to_string())?);
    let approval_token = hex(&hash.finalize());

    let before = config_value(&current.redacted())?;
    let after = config_value(&config.redacted())?;
    let mut changes = Vec::new();
    collect_changes("", &before, &after, &mut changes);
    Ok(PreparedPatch {
        config,
        approval_token,
        changes,
        secret_writes: Vec::new(),
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

fn push_live_update(path: &Path, config: &Config, keyring: &ConfigKeyring) -> Result<(), String> {
    let key = keyring
        .session_auth_key()
        .map_err(|error| error.to_string())?;
    let config_json = serde_json::to_string(&ConfigDocument::from_config(config))
        .map_err(|error| error.to_string())?;
    let proof = config_update_proof(&key, &config_json)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    match runtime
        .block_on(configuration_control_request(
            &discovery_control_endpoint(),
            path,
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
                "path": "/gateway/routing/routes/-",
                "value": {
                    "uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "id": "devboard-api",
                    "enabled": true,
                    "priority": 100,
                    "endpoints": [{
                        "target": "https://devboard.chaitin.net/devboard/api",
                        "port": 443
                    }],
                    "decision": {"action": "allow", "credentials": ["devboard-token"]}
                }
            })],
            edited: false,
        };
        let description = describe_request(
            &json!({"gateway": {"routing": {"routes": []}}}),
            &request.operations,
        )
        .unwrap();
        let rendered = render_approval_review(
            &request,
            &description,
            "add",
            "/gateway/routing/routes/-",
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
        let mut value =
            json!({"gateway": {"debug": false, "routing": {"routes": [{"id": "one"}]}}});
        apply_json_patch(
            &mut value,
            &json!([
                {"op": "test", "path": "/gateway/debug", "value": false},
                {"op": "replace", "path": "/gateway/debug", "value": true},
                {"op": "add", "path": "/gateway/routing/routes/-", "value": {"id": "two"}},
                {"op": "remove", "path": "/gateway/routing/routes/0"}
            ]),
        )
        .unwrap();
        assert_eq!(
            value,
            json!({"gateway": {"debug": true, "routing": {"routes": [{"id": "two"}]}}})
        );
    }

    #[test]
    fn approval_token_changes_with_current_config_and_patch() {
        let directory = std::env::temp_dir();
        let path = directory.join("hyperhub-config-cli-test.bin");
        let config = Config::default();
        let first = prepare_patch(
            &path,
            &config,
            &json!([{"op": "replace", "path": "/gateway/debug", "value": true}]),
        )
        .unwrap();
        let second = prepare_patch(
            &path,
            &config,
            &json!([{"op": "replace", "path": "/gateway/debug", "value": false}]),
        )
        .unwrap();
        assert_ne!(first.approval_token, second.approval_token);
        assert_eq!(first.changes.len(), 1);
    }

    #[test]
    fn secret_only_replacement_preserves_explicit_human_input_intent() {
        let path = std::env::temp_dir().join("hyperhub-secret-only-patch-test.bin");
        let mut config = Config::default();
        config
            .environment
            .push(hyperhub_core::config::EnvironmentVariable {
                uuid: hyperhub_core::config::new_config_uuid(),
                name: "EXAMPLE_TOKEN".into(),
                value: hyperhub_core::config::SecretValue::Inline {
                    value: "existing-secret".into(),
                },
            });
        let prepared = prepare_proposal_patch(
            &path,
            &config,
            &json!([{
                "op": "replace",
                "path": "/environment_variables/0/value/value",
                "value": "${APPROVE:replacement-token}"
            }]),
        )
        .unwrap();
        assert_eq!(
            prepared.changes,
            vec![
                json!({"path":"/environment_variables/0/value/value", "kind":"secret_update", "status":"awaiting_human_input"})
            ]
        );
        assert_eq!(
            secret_input_names(&prepared.secret_writes),
            ["replacement-token"]
        );
    }

    fn secret_rotation_config() -> Config {
        let mut value = config_value(&Config::default()).unwrap();
        value["environment_variables"] =
            json!([{"name":"DUMMY_TOKEN", "value":{"value":"canary-old-secret"}}]);
        value["gateway"]["credentials"] = json!([
            {"id":"basic", "type":"http_basic", "username":"dummy", "password":{"value":"canary-old-secret"}},
            {"id":"bearer", "type":"http_bearer", "secret":{"value":"canary-old-secret"}},
            {"id":"token", "type":"http_token", "username":"dummy", "secret":{"value":"canary-old-secret"}},
            {"id":"api", "type":"http_x_api_key", "secret":{"value":"canary-old-secret"}},
            {"id":"cookie", "type":"http_cookie", "name":"dummy", "secret":{"value":"canary-old-secret"}},
            {"id":"query", "type":"http_query_parameter", "name":"dummy", "secret":{"value":"canary-old-secret"}},
            {"id":"headers", "type":"http_custom_headers", "headers":{"X-Secret":{"value":"canary-old-secret"}}},
            {"id":"ssh", "type":"ssh", "accounts":[{"username":"dummy", "private_keys":[{"name":"dummy", "value":{"value":"canary-old-secret"}}], "passwords":[{"value":"canary-old-secret"}]}]}
        ]);
        value["gateway"]["proxies"] = json!([{"id":"proxy", "type":"socks5", "address":"127.0.0.1:1080", "timeout_milliseconds":1000, "authentication":{"username":{"value":"canary-old-secret"},"password":{"value":"canary-old-secret"}}, "headers":{"X-Proxy":{"value":"canary-old-secret"}}}]);
        value["gateway"]["protections"] = json!([{"id":"protection", "intelligence":{"provider":{"id":"provider", "protocol":"system_one", "endpoint":"https://127.0.0.1/v1/systemone", "model":"dummy", "api_key":{"value":"canary-old-secret"}}}}]);
        value["gateway"]["routing"]["default"]["decision"]["credentials"] = json!(["basic"]);
        ConfigDocument::from_value(value).unwrap()
    }

    #[test]
    fn all_schema_inline_secrets_rotate_without_changing_uuids_or_references() {
        let path = std::env::temp_dir().join("hyperhub-secret-rotation-matrix.bin");
        let config = secret_rotation_config();
        let before = config_value(&config.redacted()).unwrap();
        for field in [
            "/environment_variables/0/value/value",
            "/gateway/credentials/0/password/value",
            "/gateway/credentials/1/secret/value",
            "/gateway/credentials/2/secret/value",
            "/gateway/credentials/3/secret/value",
            "/gateway/credentials/4/secret/value",
            "/gateway/credentials/5/secret/value",
            "/gateway/credentials/6/headers/X-Secret/value",
            "/gateway/credentials/7/accounts/0/private_keys/0/value/value",
            "/gateway/credentials/7/accounts/0/passwords/0/value",
            "/gateway/proxies/0/authentication/username/value",
            "/gateway/proxies/0/authentication/password/value",
            "/gateway/proxies/0/headers/X-Proxy/value",
            "/gateway/protections/0/intelligence/provider/api_key/value",
        ] {
            let patch = json!([{"op":"replace", "path":field, "value":"${APPROVE:rotation}"}]);
            let prepared = prepare_proposal_patch(&path, &config, &patch).unwrap();
            assert_eq!(prepared.secret_writes.len(), 1, "{field}");
            assert_eq!(
                prepared.changes,
                [json!({"path":field,"kind":"secret_update","status":"awaiting_human_input"})],
                "{field}"
            );
            assert_eq!(
                config_value(&prepared.config.redacted()).unwrap(),
                before,
                "{field}"
            );
            let (requests, descriptions) =
                prepare_approval_sequence(&path, &config, &patch).unwrap();
            let rendered = render_approval_review(
                &requests[0],
                &descriptions[0],
                "replace",
                field,
                &["rotation".into()],
                None,
            );
            assert!(rendered.contains("更新 Secret"));
            assert!(rendered.contains("待人工输入"));
            assert!(!rendered.contains("canary-old-secret"));
            let literal = json!([{"op":"replace", "path":field, "value":"canary-new-secret"}]);
            assert!(
                prepare_proposal_patch(&path, &config, &literal)
                    .err()
                    .unwrap()
                    .contains("inline secret"),
                "{field}"
            );
        }
    }

    #[test]
    fn secret_input_origin_survives_arrays_and_drops_overwritten_or_removed_inputs() {
        let path = std::env::temp_dir().join("hyperhub-secret-origin-test.bin");
        let config = secret_rotation_config();
        let patch = json!([
            {"op":"add", "path":"/environment_variables/0", "value":{"name":"NEW_DUMMY", "value":{"value":"${APPROVE:shifted}"}}},
            {"op":"remove", "path":"/environment_variables/1"}
        ]);
        let prepared = prepare_proposal_patch(&path, &config, &patch).unwrap();
        assert_eq!(
            prepared.secret_writes[0].path,
            "/environment_variables/0/value/value"
        );
        assert_eq!(prepared.secret_writes[0].operation_index, 0);
        assert_eq!(
            prepared.secret_writes[0].value_pointer,
            "/value/value/value"
        );
        for final_operation in [
            json!({"op":"remove", "path":"/environment_variables/0"}),
            json!({"op":"replace", "path":"/environment_variables/0/value", "value":{"env":"DUMMY_TOKEN"}}),
        ] {
            let patch = json!([{"op":"replace", "path":"/environment_variables/0/value/value", "value":"${APPROVE:discarded}"}, final_operation]);
            let prepared = prepare_proposal_patch(&path, &config, &patch).unwrap();
            assert!(prepared.secret_writes.is_empty());
        }
    }

    #[test]
    fn secret_rotation_does_not_resolve_normal_fields_or_test_operands_with_same_name() {
        let path = std::env::temp_dir().join("hyperhub-secret-origin-scope.bin");
        let config = secret_rotation_config();
        let mut patch = json!([
            {"op":"replace", "path":"/gateway/protections/0/intelligence/provider/model", "value":"${APPROVE:shared}"},
            {"op":"test", "path":"/gateway/protections/0/intelligence/provider/model", "value":"${APPROVE:shared}"},
            {"op":"replace", "path":"/environment_variables/0/value/value", "value":"${APPROVE:shared}"}
        ]);
        let prepared = prepare_proposal_patch(&path, &config, &patch).unwrap();
        replace_secret_inputs(
            patch.as_array_mut().unwrap(),
            &prepared.secret_writes,
            "shared",
            "canary-old-secret",
        )
        .unwrap();
        assert_eq!(patch[0]["value"], "${APPROVE:shared}");
        assert_eq!(patch[1]["value"], "${APPROVE:shared}");
        assert_eq!(patch[2]["value"], "canary-old-secret");
        let approved = prepare_patch(&path, &config, &patch).unwrap();
        assert_eq!(
            config_value(&approved.config).unwrap()["environment_variables"],
            config_value(&config).unwrap()["environment_variables"]
        );
        assert!(approved
            .secret_writes
            .iter()
            .all(|write| write.placeholder.is_none()));
        let noop = json!([{"op":"test", "path":"/gateway/protections/0/intelligence/provider/model", "value":"dummy"}]);
        assert!(prepare_proposal_patch(&path, &config, &noop)
            .unwrap()
            .changes
            .is_empty());
        let normal = json!([{"op":"replace", "path":"/gateway/protections/0/intelligence/provider/model", "value":"${APPROVE:ordinary}"}]);
        assert!(prepare_proposal_patch(&path, &config, &normal)
            .unwrap()
            .secret_writes
            .is_empty());
    }

    #[test]
    fn overwritten_secret_inputs_are_reviewed_atomically_and_tests_follow_the_input_origin() {
        let path = std::env::temp_dir().join("hyperhub-secret-atomic.bin");
        let config = secret_rotation_config();
        let patch = json!([
            {"op":"replace","path":"/environment_variables/0/value/value","value":"${APPROVE:discarded}"},
            {"op":"replace","path":"/environment_variables/0/value/value","value":"${APPROVE:final}"},
            {"op":"test","path":"/environment_variables/0/value/value","value":"${APPROVE:final}"},
            {"op":"replace","path":"/gateway/debug","value":true}
        ]);
        let (requests, descriptions) = prepare_approval_sequence(&path, &config, &patch).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            descriptions[0]
                .details
                .iter()
                .filter(|detail| detail.contains("待人工输入"))
                .count(),
            1
        );
        let preview = prepare_proposal_patch(&path, &config, &patch).unwrap();
        assert_eq!(secret_input_names(&preview.secret_writes), ["final"]);
        let mut approved = patch.as_array().unwrap().clone();
        replace_secret_inputs(
            &mut approved,
            &preview.secret_writes,
            "final",
            "canary-old-secret",
        )
        .unwrap();
        assert_eq!(approved[0]["value"], "${APPROVE:discarded}");
        assert_eq!(approved[1]["value"], "canary-old-secret");
        assert_eq!(approved[2]["value"], "canary-old-secret");
        prepare_patch(&path, &config, &Value::Array(approved)).unwrap();
    }

    #[test]
    fn every_intermediate_typed_secret_input_is_checked_before_proposal_storage() {
        let path = std::env::temp_dir().join("hyperhub-intermediate-input-check.bin");
        let config = secret_rotation_config();
        let field = "/gateway/protections/0/intelligence/provider/api_key/value";
        for ending in [
            json!({"op":"replace","path":field,"value":"${APPROVE:final}"}),
            json!({"op":"remove","path":"/gateway/protections/0/intelligence/provider"}),
        ] {
            let patch =
                json!([{"op":"replace","path":field,"value":"dummy-intermediate-canary"}, ending]);
            let error = prepare_proposal_patch(&path, &config, &patch)
                .err()
                .unwrap();
            assert!(error.contains("inline secret"));
            assert!(!error.contains("dummy-intermediate-canary"));
        }
        let patch = json!([
            {"op":"replace","path":"/gateway/protections/0/intelligence/provider/api_key","value":{"value":"dummy-nested-canary","extra":true}},
            {"op":"replace","path":"/gateway/protections/0/intelligence/provider/api_key","value":{"value":"${APPROVE:final}"}}
        ]);
        let error = prepare_proposal_patch(&path, &config, &patch)
            .err()
            .unwrap();
        assert!(error.contains("inline secret"));
        assert!(!error.contains("dummy-nested-canary"));
        let patch = json!([
            {"op":"remove","path":"/gateway/credentials/0/password"},
            {"op":"test","path":"/gateway/debug","value":false},
            {"op":"add","path":"/gateway/credentials/0/password","value":{"value":"${APPROVE:replacement}"}}
        ]);
        assert_eq!(
            secret_input_names(
                &prepare_proposal_patch(&path, &config, &patch)
                    .unwrap()
                    .secret_writes
            ),
            ["replacement"]
        );
    }

    #[test]
    fn approved_text_and_recovery_are_verbatim_without_placeholder_interpretation() {
        let path = std::env::temp_dir().join("hyperhub-approved-text-test.bin");
        let config = secret_rotation_config();
        let patch = json!([{"op":"replace", "path":"/environment_variables/0/value/value", "value":"${APPROVE:input}"}]);
        let preview = prepare_proposal_patch(&path, &config, &patch).unwrap();
        for text in [
            "${APPROVE:dummy-sensitive-canary",
            "${APPROVE:dummy-sensitive-canary}",
            "${APPROVE:dummy invalid canary}",
        ] {
            let mut operations = patch.as_array().unwrap().clone();
            replace_secret_inputs(&mut operations, &preview.secret_writes, "input", text).unwrap();
            let resolved = Value::Array(operations);
            let approved = prepare_patch(&path, &config, &resolved).unwrap();
            assert_eq!(
                config_value(&approved.config)
                    .unwrap()
                    .pointer("/environment_variables/0/value/value")
                    .and_then(Value::as_str),
                Some(text)
            );
            assert!(approved.secret_writes.is_empty());
            let recovery = prepare_patch(&path, &config, &resolved).unwrap();
            assert_eq!(
                config_digest(&recovery.config).unwrap(),
                config_digest(&approved.config).unwrap()
            );
            let repeated = prepare_patch(&path, &approved.config, &resolved).unwrap();
            assert_eq!(
                config_digest(&repeated.config).unwrap(),
                config_digest(&approved.config).unwrap()
            );
            assert!(repeated.changes.is_empty());
            assert!(!serde_json::to_string(&approved.changes)
                .unwrap()
                .contains("dummy-sensitive-canary"));
        }
        let error = parse_placeholder("${APPROVE:dummy-sensitive-canary")
            .err()
            .unwrap();
        assert!(!error.contains("dummy-sensitive-canary"));
    }

    #[test]
    fn secret_references_and_noop_mutations_do_not_request_human_values() {
        let path = std::env::temp_dir().join("hyperhub-secret-reference.bin");
        let config = secret_rotation_config();
        for reference in [
            json!({"env":"DUMMY_REF"}),
            json!({"file":"dummy-reference-file", "prefix":"Bearer "}),
        ] {
            let patch = json!([{"op":"replace", "path":"/environment_variables/0/value", "value":reference}]);
            let prepared = prepare_proposal_patch(&path, &config, &patch).unwrap();
            assert!(prepared.secret_writes.is_empty());
            assert!(!prepared.changes.is_empty());
        }
        assert!(prepare_proposal_patch(
            &path,
            &config,
            &json!([{"op":"replace","path":"/gateway/debug","value":false}])
        )
        .unwrap()
        .changes
        .is_empty());
    }

    #[test]
    fn approval_placeholder_names_are_deduplicated() {
        let patch = json!([
            {"op": "add", "path": "/one", "value": "${APPROVE:api-key}"},
            {"op": "add", "path": "/two", "value": "${APPROVE:api-key}"}
        ]);
        assert_eq!(collect_placeholders(&patch).unwrap(), ["api-key"]);
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
            action: hyperhub_core::config::RuleAction::Pass,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: Vec::new(),
            protection: None,
            allow_sensitive_upload: false,
            legacy: Default::default(),
        });
        let existing = config.rules[0].uuid.clone();
        let mut patch = json!([
            {"op": "add", "path": "/gateway/routing/routes/-", "value": {"id": "new"}},
            {"op": "replace", "path": "/gateway/routing/routes/0", "value": {"id": "existing-renamed"}}
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
            {"op": "test", "path": "/gateway/debug", "value": false},
            {"op": "replace", "path": "/gateway/debug", "value": true},
            {"op": "add", "path": "/gateway/routing/routes/-", "value": {"id": "two"}}
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
    fn referenced_id_renames_fall_back_to_one_atomic_approval_request() {
        use hyperhub_core::config::{
            DataProtectionConfig, IntelligenceProtectionConfig, ProcessSandboxPattern,
            ProcessSandboxRule, ProtectionMode, ProtectionProfile, SandboxAction,
        };

        let path = std::env::temp_dir().join("hyperhub-atomic-approval-test.bin");
        let profile_uuid = hyperhub_core::config::new_config_uuid();
        let rule_uuid = hyperhub_core::config::new_config_uuid();
        let mut config = Config::default();
        config.apply_managed_audit_paths(&path);
        config.protections.push(ProtectionProfile {
            uuid: profile_uuid.clone(),
            id: "old-profile".into(),
            enabled: true,
            mode: ProtectionMode::Enforce,
            data: DataProtectionConfig::default(),
            intelligence: IntelligenceProtectionConfig::default(),
        });
        config.sandbox.process.enabled = true;
        config.sandbox.process.rules.push(ProcessSandboxRule {
            uuid: rule_uuid.clone(),
            id: "process-rule".into(),
            enabled: true,
            priority: 100,
            action: SandboxAction::Smart,
            patterns: vec![ProcessSandboxPattern {
                enabled: true,
                executable: ".*".into(),
                command_line: ".*".into(),
            }],
            protection: Some("old-profile".into()),
            legacy: Default::default(),
        });

        let patch = json!([
            {"op": "test", "path": "/gateway/protections/0/uuid", "value": profile_uuid},
            {"op": "test", "path": "/sandbox/process/rules/0/uuid", "value": rule_uuid},
            {"op": "replace", "path": "/gateway/protections/0/id", "value": "new-profile"},
            {"op": "replace", "path": "/sandbox/process/rules/0/protection", "value": "new-profile"}
        ]);
        let (requests, descriptions) = prepare_approval_sequence(&path, &config, &patch).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].operations.len(), 4);
        assert_eq!(descriptions.len(), 1);
        assert!(descriptions[0].summary.contains("智能防护"));
    }

    #[test]
    fn legacy_approval_requests_receive_a_valid_uuid() {
        let request: ApprovalRequest = serde_json::from_value(json!({
            "source_index": 0,
            "operations": [
                {"op": "replace", "path": "/gateway/debug", "value": true}
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
            operations: vec![json!({"op": "replace", "path": "/gateway/debug", "value": true})],
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
    fn passwordless_proposals_reject_literal_secrets() {
        let literal = json!([{
            "op": "add",
            "path": "/environment_variables/-",
            "value": {"name": "TOKEN", "value": {"value": "literal-secret"}}
        }]);
        assert!(ensure_proposal_contains_no_literal_secrets(&literal)
            .unwrap_err()
            .contains("use ${APPROVE:name}"));

        let placeholder = json!([{
            "op": "add",
            "path": "/gateway/credentials/-",
            "value": {"id": "api", "type": "http_bearer", "secret": {"value": "${APPROVE:api-token}"}}
        }]);
        ensure_proposal_contains_no_literal_secrets(&placeholder).unwrap();

        let file_reference = json!([{
            "op": "add",
            "path": "/environment_variables/-",
            "value": {"name": "TOKEN", "value": {"file": "/secure/token", "prefix": "Bearer "}}
        }]);
        ensure_proposal_contains_no_literal_secrets(&file_reference).unwrap();
    }

    #[test]
    fn malformed_approval_placeholder_is_rejected() {
        let error = collect_placeholders(&json!("${APPROVE:bad name}")).unwrap_err();
        assert!(error.contains("invalid approval placeholder"));
    }
}
