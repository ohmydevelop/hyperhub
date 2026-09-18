use hyperhub_core::config::Config;
use hyperhub_core::config_store::{
    self, default_config_path, load_encrypted, read_redacted_json, KdfDescriptor, StoreError,
};
use hyperhub_core::control::{control_request, discovery_control_endpoint};
use hyperhub_core::session::{config_update_proof, ControlRequest, ControlResponse};
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
        patch: PathBuf,
        password_file: Option<PathBuf>,
        token: String,
        editor: Option<PathBuf>,
    },
}

struct ActiveConfig {
    config: Config,
    descriptor: KdfDescriptor,
    password: Zeroizing<String>,
    initialized: bool,
}

struct PreparedPatch {
    config: Config,
    approval_token: String,
    changes: Vec<Value>,
}

pub(crate) fn parse(args: &[OsString]) -> Result<Command, String> {
    let Some(action) = args.first().map(|value| value.to_string_lossy()) else {
        return Err("config command requires `show` or `patch`".into());
    };
    match action.as_ref() {
        "show" => parse_show(&args[1..]),
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
    let patch = args
        .first()
        .ok_or("approve requires a JSON patch file")?
        .clone()
        .into();
    let mut password_file = None;
    let mut token = None;
    let mut editor = None;
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
            "--token" => token = Some(value.to_string_lossy().into_owned()),
            "--editor" => editor = Some(value.into()),
            _ => return Err(format!("unknown approve option '{option}'")),
        }
        index += 1;
    }
    Ok(Command::Approve {
        patch,
        password_file,
        token: token.ok_or("approve requires --token <approval-token>")?,
        editor,
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
            patch,
            password_file,
            token,
            editor,
        } => approve_config(&patch, password_file.as_deref(), &token, editor.as_deref()),
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
    let active = load_active(&path, password_file)?;
    let patch = parse_patch_file(patch_path)?;
    let prepared = prepare_patch(&path, &active.config, &patch)?;
    print_json(&json!({
        "schema_version": 1,
        "status": "approval_required",
        "approval_token": prepared.approval_token,
        "initialized": active.initialized,
        "serve_running": crate::serve_is_running(),
        "config_path": path,
        "changes": prepared.changes,
    }))?;
    Ok(0)
}

fn approve_config(
    patch_path: &Path,
    password_file: Option<&Path>,
    proposed_token: &str,
    editor: Option<&Path>,
) -> Result<i32, String> {
    if patch_path == Path::new("-") {
        return Err("approve requires a patch file so it can be reviewed in an editor".into());
    }
    let path = default_config_path().map_err(|error| error.to_string())?;
    let active = load_active(&path, password_file)?;
    let proposed_patch = parse_patch_file(patch_path)?;
    let proposed = prepare_patch(&path, &active.config, &proposed_patch)?;
    if proposed_token != proposed.approval_token {
        return Err(
            "approval token does not match the current configuration and proposed patch".into(),
        );
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err("approve requires an interactive terminal for human review".into());
    }

    let review_path = create_review_copy(patch_path)?;
    let result = (|| {
        open_editor(&review_path, editor)?;
        let mut reviewed_patch = parse_patch_file(&review_path)?;
        let placeholders = collect_placeholders(&reviewed_patch)?;
        for placeholder in placeholders {
            let value = crate::password::prompt_secret(&format!(
                "Value for approval placeholder '{placeholder}': "
            ))?;
            if value.is_empty() {
                return Err(format!(
                    "approval placeholder '{placeholder}' cannot be empty"
                ));
            }
            replace_placeholder(&mut reviewed_patch, &placeholder, &value);
        }
        let prepared = prepare_patch(&path, &active.config, &reviewed_patch)?;
        if prepared.changes.is_empty() {
            return Err("reviewed patch does not change the configuration".into());
        }
        let confirmation = &prepared.approval_token[..12];
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema_version": 1,
                "status": "human_review",
                "proposal_token": proposed.approval_token,
                "review_token": prepared.approval_token,
                "changes": prepared.changes,
            }))
            .map_err(|error| error.to_string())?
        );
        eprint!("Type APPLY {confirmation} to confirm: ");
        std::io::stderr()
            .flush()
            .map_err(|error| error.to_string())?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|error| format!("cannot read approval confirmation: {error}"))?;
        if answer.trim_end() != format!("APPLY {confirmation}") {
            return Err("configuration approval was cancelled".into());
        }
        apply_prepared(&path, &active, prepared)
    })();
    let _ = std::fs::remove_file(&review_path);
    result
}

fn apply_prepared(
    path: &Path,
    active: &ActiveConfig,
    prepared: PreparedPatch,
) -> Result<i32, String> {
    config_store::save_encrypted_with_descriptor(
        path,
        &prepared.config,
        active.password.as_bytes(),
        &active.descriptor,
    )
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
        match push_live_update(
            &prepared.config,
            active.password.as_bytes(),
            &active.descriptor,
        ) {
            Ok(()) => (true, None),
            Err(error) => (false, Some(error)),
        }
    } else {
        (false, None)
    };
    print_json(&json!({
        "schema_version": 1,
        "status": "applied",
        "review_token": prepared.approval_token,
        "config_path": path,
        "live_update": live_update,
        "live_update_error": live_update_error,
        "changes": prepared.changes,
    }))?;
    Ok(0)
}

fn load_active(path: &Path, password_file: Option<&Path>) -> Result<ActiveConfig, String> {
    let initialized = path.is_file();
    let password = crate::password::acquire(password_file, !initialized)?;
    if initialized {
        let unlocked =
            load_encrypted(path, password.as_bytes()).map_err(|error| error.to_string())?;
        Ok(ActiveConfig {
            config: unlocked.config,
            descriptor: unlocked.descriptor,
            password,
            initialized,
        })
    } else {
        let mut config = Config::default();
        config.apply_managed_audit_paths(path);
        config.environment = crate::default_environment();
        Ok(ActiveConfig {
            config,
            descriptor: config_store::new_descriptor(),
            password,
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

fn create_review_copy(source: &Path) -> Result<PathBuf, String> {
    let directory = std::env::temp_dir();
    let path = directory.join(format!(
        "hyperhub-approve-{}-{:016x}.json",
        std::process::id(),
        rand::random::<u64>()
    ));
    let bytes = std::fs::read(source)
        .map_err(|error| format!("cannot read JSON patch {}: {error}", source.display()))?;
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

fn push_live_update(
    config: &Config,
    password: &[u8],
    descriptor: &KdfDescriptor,
) -> Result<(), String> {
    let key = config_store::derive_session_auth_key(password, descriptor)
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
    fn malformed_approval_placeholder_is_rejected() {
        let error = collect_placeholders(&json!("${APPROVE:bad name}")).unwrap_err();
        assert!(error.contains("invalid approval placeholder"));
    }
}
