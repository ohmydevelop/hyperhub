use hyperhub_core::config::Config;
use hyperhub_core::config_store::{self, default_config_path, load_encrypted, KdfDescriptor};
use hyperhub_core::control::{control_request, discovery_control_endpoint};
use hyperhub_core::session::{config_update_proof, ControlRequest, ControlResponse};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Show {
        password_file: Option<PathBuf>,
    },
    Patch {
        patch: PathBuf,
        password_file: Option<PathBuf>,
        approval: Option<String>,
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
        "show" => {
            let password_file = parse_password_file("config show", &args[1..])?;
            Ok(Command::Show { password_file })
        }
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
    let mut approval = None;
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
            "--approve" => approval = Some(value.to_string_lossy().into_owned()),
            _ => return Err(format!("unknown config patch option '{option}'")),
        }
        index += 1;
    }
    Ok(Command::Patch {
        patch,
        password_file,
        approval,
    })
}

fn parse_password_file(command: &str, args: &[OsString]) -> Result<Option<PathBuf>, String> {
    match args {
        [] => Ok(None),
        [option, path] if option == "--password-file" => Ok(Some(path.clone().into())),
        _ => Err(format!("{command} accepts only --password-file <file>")),
    }
}

pub(crate) fn run(command: Command) -> Result<i32, String> {
    match command {
        Command::Show { password_file } => show(password_file.as_deref()),
        Command::Patch {
            patch,
            password_file,
            approval,
        } => patch_config(&patch, password_file.as_deref(), approval.as_deref()),
    }
}

fn show(password_file: Option<&Path>) -> Result<i32, String> {
    let path = default_config_path().map_err(|error| error.to_string())?;
    let (config, initialized) = if path.is_file() {
        let password = crate::password::acquire(password_file, false)?;
        let unlocked =
            load_encrypted(&path, password.as_bytes()).map_err(|error| error.to_string())?;
        (unlocked.config, true)
    } else {
        let mut config = Config::default();
        config.apply_managed_audit_paths(&path);
        config.environment = crate::default_environment();
        (config, false)
    };
    let mut value = serde_json::to_value(config).map_err(|error| error.to_string())?;
    redact_secrets(&mut value);
    print_json(&json!({
        "schema_version": 1,
        "initialized": initialized,
        "config_path": path,
        "config": value,
    }))?;
    Ok(0)
}

fn patch_config(
    patch_path: &Path,
    password_file: Option<&Path>,
    approval: Option<&str>,
) -> Result<i32, String> {
    let path = default_config_path().map_err(|error| error.to_string())?;
    let active = load_active(&path, password_file)?;
    let patch_bytes = read_patch(patch_path)?;
    let patch: Value = serde_json::from_slice(&patch_bytes)
        .map_err(|error| format!("invalid JSON patch: {error}"))?;
    let prepared = prepare_patch(&path, &active.config, &patch)?;
    let live = crate::serve_is_running();

    let Some(approval) = approval else {
        print_json(&json!({
            "schema_version": 1,
            "status": "approval_required",
            "approval_token": prepared.approval_token,
            "initialized": active.initialized,
            "serve_running": live,
            "config_path": path,
            "changes": prepared.changes,
        }))?;
        return Ok(0);
    };
    if approval != prepared.approval_token {
        return Err("approval token does not match the current configuration and patch".into());
    }
    if prepared.changes.is_empty() {
        print_json(&json!({
            "schema_version": 1,
            "status": "unchanged",
            "approval_token": prepared.approval_token,
            "config_path": path,
        }))?;
        return Ok(0);
    }

    config_store::save_encrypted_with_descriptor(
        &path,
        &prepared.config,
        active.password.as_bytes(),
        &active.descriptor,
    )
    .map_err(|error| error.to_string())?;
    let _ = config_store::reconcile_root_certificates(
        &path,
        prepared
            .config
            .root_certificates
            .iter()
            .map(|certificate| certificate.fingerprint.as_str()),
    );
    let live_update = if live {
        push_live_update(
            &prepared.config,
            active.password.as_bytes(),
            &active.descriptor,
        )?;
        true
    } else {
        false
    };
    print_json(&json!({
        "schema_version": 1,
        "status": "applied",
        "approval_token": prepared.approval_token,
        "config_path": path,
        "live_update": live_update,
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

fn read_patch(path: &Path) -> Result<Vec<u8>, String> {
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

    let mut before = current_value;
    let mut after = next_value;
    redact_secrets(&mut before);
    redact_secrets(&mut after);
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

fn redact_secrets(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if map.len() == 1 && matches!(map.get("value"), Some(Value::String(_))) {
                map.insert("value".into(), Value::String("<redacted>".into()));
                return;
            }
            for value in map.values_mut() {
                redact_secrets(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_secrets(value);
            }
        }
        _ => {}
    }
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
    fn inline_secrets_are_redacted() {
        let mut value = json!({"value": {"value": "secret"}});
        redact_secrets(&mut value);
        assert_eq!(value["value"]["value"], "<redacted>");
    }
}
