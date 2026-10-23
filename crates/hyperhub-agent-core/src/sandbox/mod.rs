mod network;
mod sanitizer;

use crate::snapshot::Snapshot;
pub(crate) use network::*;
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
use sanitizer::ProtectionContext;
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicU64;
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SandboxAction {
    #[default]
    Pass,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileSandboxOperation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SandboxSnapshot {
    pub(crate) version: u64,
    pub(crate) network: Option<FirewallSnapshot>,
    pub(crate) process: Option<ProcessSandboxSnapshot>,
    pub(crate) file: Option<FileSandboxSnapshot>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(not(all(windows, feature = "gum-agent")), allow(dead_code))]
pub(crate) struct ProcessSandboxSnapshot {
    pub(crate) default_action: SandboxAction,
    #[serde(default)]
    pub(crate) error_action: SandboxAction,
    pub(crate) rules: Vec<ProcessSandboxSnapshotRule>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(not(all(windows, feature = "gum-agent")), allow(dead_code))]
pub(crate) struct ProcessSandboxSnapshotRule {
    pub(crate) id: String,
    pub(crate) action: SandboxAction,
    pub(crate) patterns: Vec<ProcessSandboxPattern>,
    #[serde(default)]
    pub(crate) protection: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
pub(crate) struct ProcessSandboxPattern {
    pub(crate) executable: String,
    pub(crate) command_line: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(not(all(windows, feature = "gum-agent")), allow(dead_code))]
pub(crate) struct FileSandboxSnapshot {
    pub(crate) default_action: SandboxAction,
    #[serde(default)]
    pub(crate) error_action: SandboxAction,
    pub(crate) rules: Vec<FileSandboxSnapshotRule>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(not(all(windows, feature = "gum-agent")), allow(dead_code))]
pub(crate) struct FileSandboxSnapshotRule {
    pub(crate) id: String,
    pub(crate) action: SandboxAction,
    pub(crate) patterns: Vec<String>,
    pub(crate) operations: Vec<FileSandboxOperation>,
    #[serde(default)]
    pub(crate) protection: Option<String>,
}

#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
pub(crate) struct CompiledProcessSandboxSnapshot {
    pub(crate) error_action: SandboxAction,
    wire: serde_json::Value,
}
#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
pub(crate) struct CompiledFileSandboxSnapshot {
    pub(crate) error_action: SandboxAction,
    wire: serde_json::Value,
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SandboxAuditKind {
    Process,
    File,
}
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SandboxAuditEvent {
    pub(crate) kind: SandboxAuditKind,
    pub(crate) decision: SandboxAction,
    pub(crate) rule_id: Option<String>,
    pub(crate) source: String,
    pub(crate) operation: String,
    pub(crate) target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) process_argv_redacted: Option<Vec<String>>,
    pub(crate) target_argv_redacted: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    pub(crate) process_pid: u32,
    pub(crate) process_tid: u32,
    pub(crate) snapshot_version: u64,
}

#[cfg(all(target_os = "linux", feature = "gum-agent"))]
pub(crate) fn file_allows(path: &str, op: FileSandboxOperation) -> bool {
    file_decision_with_protection(path, op).0 != SandboxAction::Deny
}
#[cfg(all(target_os = "linux", feature = "gum-agent"))]
pub(crate) fn process_allows(exe: &str, cmd: &str) -> bool {
    process_decision_with_protection(exe, cmd).0 != SandboxAction::Deny
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
fn parse_action(action: &str) -> SandboxAction {
    if action == "pass" {
        SandboxAction::Pass
    } else {
        SandboxAction::Deny
    }
}
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
fn engine_policy(
    snapshot: &serde_json::Value,
    operation: u32,
    target: &str,
    op: &str,
    command_line: &str,
) -> Result<hyperhub_engine::contract::PolicyDecision, i32> {
    let engine = crate::state()
        .lock()
        .map_err(|_| crate::HH_ERR_INVALID)?
        .engine
        .clone();
    let lease = crate::engine_call::calling(&engine)?;
    hyperhub_engine::policy(
        &lease,
        operation,
        &hyperhub_engine::contract::PolicyInput {
            snapshot: snapshot.clone(),
            target: target.into(),
            operation: op.into(),
            command_line: command_line.into(),
        },
    )
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn file_sandbox_decision(
    snapshot: &CompiledFileSandboxSnapshot,
    path: &str,
    op: FileSandboxOperation,
) -> (SandboxAction, Option<String>, String) {
    engine_policy(
        &snapshot.wire,
        hyperhub_engine::contract::FILE_POLICY,
        path,
        &serde_json::to_value(op)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        "",
    )
    .map(|decision| {
        (
            parse_action(&decision.action),
            decision.rule_id,
            decision.source,
        )
    })
    .unwrap_or((snapshot.error_action, None, "error".into()))
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn process_sandbox_decision(
    snapshot: &CompiledProcessSandboxSnapshot,
    exe: &str,
    cmd: &str,
) -> (SandboxAction, Option<String>, String) {
    engine_policy(
        &snapshot.wire,
        hyperhub_engine::contract::PROCESS_POLICY,
        exe,
        "",
        cmd,
    )
    .map(|decision| {
        (
            parse_action(&decision.action),
            decision.rule_id,
            decision.source,
        )
    })
    .unwrap_or((snapshot.error_action, None, "error".into()))
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn file_decision_with_protection(
    path: &str,
    operation: FileSandboxOperation,
) -> (SandboxAction, Option<String>, String) {
    let requested = file_requested_decision(path, operation);
    if requested.0 == SandboxAction::Deny {
        return requested;
    }
    let resolved = if matches!(
        operation,
        FileSandboxOperation::Read | FileSandboxOperation::Write
    ) {
        resolved_content_path(path)
    } else {
        resolved_namespace_path(path)
    };
    if let Some(resolved) = resolved {
        if resolved != path {
            let decision = file_requested_decision(&resolved, operation);
            if decision.0 == SandboxAction::Deny {
                return decision;
            }
        }
    }
    requested
}

// This is a path check at the Hook boundary, not an atomic object capability:
// an unmediated concurrent namespace change can still race the target syscall.
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
fn resolved_content_path(path: &str) -> Option<String> {
    let resolved = std::fs::canonicalize(path)
        .ok()?
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let resolved = if let Some(unc) = resolved.strip_prefix(r"\\?\UNC\") {
        format!("//{unc}").replace('\\', "/")
    } else {
        resolved.trim_start_matches(r"\\?\").replace('\\', "/")
    };
    Some(resolved)
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
fn resolved_namespace_path(path: &str) -> Option<String> {
    let path = std::path::Path::new(path);
    let parent = resolved_content_path(&path.parent()?.to_string_lossy())?;
    let resolved = std::path::Path::new(&parent)
        .join(path.file_name()?)
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let resolved = resolved.replace('\\', "/");
    Some(resolved)
}

#[cfg(all(target_os = "linux", feature = "gum-agent"))]
pub(crate) fn file_link_source_allows(path: &str, follow: bool) -> bool {
    let read = if follow {
        file_decision_with_protection(path, FileSandboxOperation::Read)
    } else {
        file_requested_decision(path, FileSandboxOperation::Read)
    };
    if read.0 == SandboxAction::Deny {
        return false;
    }
    if !follow {
        if let Some(resolved) = resolved_namespace_path(path) {
            if file_requested_decision(&resolved, FileSandboxOperation::Read).0
                == SandboxAction::Deny
            {
                return false;
            }
        }
    }
    let write = if follow {
        file_decision_with_protection(path, FileSandboxOperation::Write)
    } else {
        file_requested_decision(path, FileSandboxOperation::Write)
    };
    if write.0 == SandboxAction::Deny {
        return false;
    }
    if !follow {
        if let Some(resolved) = resolved_namespace_path(path) {
            if file_requested_decision(&resolved, FileSandboxOperation::Write).0
                == SandboxAction::Deny
            {
                return false;
            }
        }
    }
    file_decision_with_protection(path, FileSandboxOperation::Rename).0 != SandboxAction::Deny
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
fn file_requested_decision(
    path: &str,
    operation: FileSandboxOperation,
) -> (SandboxAction, Option<String>, String) {
    let Some(snapshot) = file_sandbox_snapshot() else {
        return (SandboxAction::Pass, None, "disabled".into());
    };
    let (action, rule_id, source) = file_sandbox_decision(&snapshot, path, operation);
    if action == SandboxAction::Deny {
        return (action, rule_id, source);
    }
    let Some((matched_rule_id, protection_id)) = file_protection_id(&snapshot, path, operation)
    else {
        return (action, rule_id, source);
    };
    let context = ProtectionContext::default();
    let sanitized = sanitizer::sanitize(path, &[path.to_owned()], &context);
    let executable = std::env::current_exe()
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());
    let mut context_value =
        serde_json::to_value(&context).unwrap_or_else(|_| serde_json::json!({}));
    context_value["local_deny"] = serde_json::json!(sanitized.local_deny);
    match query_protection_gateway(
        &protection_id,
        Some(&matched_rule_id),
        &format!("file_{operation:?}").to_ascii_lowercase(),
        &executable,
        &sanitized.redacted_argv,
        &sanitized.features,
        &context_value,
    ) {
        Ok(true) => (
            SandboxAction::Deny,
            Some(matched_rule_id),
            "smart_protection".into(),
        ),
        Ok(false) => (
            SandboxAction::Pass,
            Some(matched_rule_id),
            "smart_protection_pass".into(),
        ),
        Err(_) => (
            snapshot.error_action,
            Some(matched_rule_id),
            "smart_protection_error".into(),
        ),
    }
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn process_decision_with_protection(
    executable: &str,
    command_line: &str,
) -> (SandboxAction, Option<String>, String) {
    let Some(snapshot) = process_sandbox_snapshot() else {
        return (SandboxAction::Pass, None, "disabled".into());
    };
    let (action, rule_id, source) = process_sandbox_decision(&snapshot, executable, command_line);
    if action == SandboxAction::Deny {
        return (action, rule_id, source);
    }
    let Some((matched_rule_id, protection_id)) =
        process_protection_id(&snapshot, executable, command_line)
    else {
        return (action, rule_id, source);
    };
    let argv = command_line
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let context = ProtectionContext::default();
    let sanitized = sanitizer::sanitize(executable, &argv, &context);
    let mut context_value =
        serde_json::to_value(&context).unwrap_or_else(|_| serde_json::json!({}));
    context_value["local_deny"] = serde_json::json!(sanitized.local_deny);
    match query_protection_gateway(
        &protection_id,
        Some(&matched_rule_id),
        "process_create",
        executable,
        &sanitized.redacted_argv,
        &sanitized.features,
        &context_value,
    ) {
        Ok(true) => (
            SandboxAction::Deny,
            Some(matched_rule_id),
            "smart_protection".into(),
        ),
        Ok(false) => (
            SandboxAction::Pass,
            Some(matched_rule_id),
            "smart_protection_pass".into(),
        ),
        Err(_) => (
            snapshot.error_action,
            Some(matched_rule_id),
            "smart_protection_error".into(),
        ),
    }
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn process_protection_id(
    snapshot: &CompiledProcessSandboxSnapshot,
    executable: &str,
    command_line: &str,
) -> Option<(String, String)> {
    let decision = engine_policy(
        &snapshot.wire,
        hyperhub_engine::contract::PROCESS_POLICY,
        executable,
        "",
        command_line,
    )
    .ok()?;
    Some((decision.protection_rule_id?, decision.protection?))
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn file_protection_id(
    snapshot: &CompiledFileSandboxSnapshot,
    path: &str,
    operation: FileSandboxOperation,
) -> Option<(String, String)> {
    let op = serde_json::to_value(operation).ok()?.as_str()?.to_owned();
    let decision = engine_policy(
        &snapshot.wire,
        hyperhub_engine::contract::FILE_POLICY,
        path,
        &op,
        "",
    )
    .ok()?;
    Some((decision.protection_rule_id?, decision.protection?))
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn query_protection_gateway(
    protection_id: &str,
    rule_id: Option<&str>,
    stage: &str,
    executable: &str,
    argv: &[String],
    features: &[String],
    context: &serde_json::Value,
) -> Result<bool, i32> {
    let (endpoint, session_id, token) = {
        let runtime = crate::state().lock().map_err(|_| crate::HH_ERR_PROTOCOL)?;
        (
            runtime.session.control_endpoint.clone(),
            runtime.session.session_id.clone(),
            runtime.session.token.clone(),
        )
    };
    crate::smart_protection_check(
        &endpoint,
        &session_id,
        &token,
        protection_id,
        rule_id,
        stage,
        executable,
        argv,
        features,
        context,
    )
}

#[cfg(test)]
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn resolved_content_path_follows_symlinks_but_does_not_guess_missing_targets() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "hyperhub-alias-unit-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("protected"), b"dummy").unwrap();
        symlink(root.join("protected"), root.join("alias")).unwrap();
        assert_eq!(
            resolved_content_path(&root.join("alias").to_string_lossy()).unwrap(),
            root.join("protected").to_string_lossy()
        );
        assert_eq!(
            resolved_namespace_path(&root.join("alias").to_string_lossy()).unwrap(),
            root.join("alias").to_string_lossy()
        );
        std::fs::create_dir(root.join("actual")).unwrap();
        std::fs::write(root.join("actual/key"), b"dummy").unwrap();
        symlink(root.join("actual"), root.join("directory-alias")).unwrap();
        assert_eq!(
            resolved_namespace_path(&root.join("directory-alias/key").to_string_lossy()).unwrap(),
            root.join("actual/key").to_string_lossy()
        );
        assert!(resolved_content_path(&root.join("absent").to_string_lossy()).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compiled_file_patterns_match_only_selected_operations() {
        let snapshot = compile_file_snapshot(FileSandboxSnapshot {
            default_action: SandboxAction::Pass,
            error_action: SandboxAction::Pass,
            rules: vec![FileSandboxSnapshotRule {
                id: "secret".into(),
                action: SandboxAction::Deny,
                patterns: vec![r"^C:/secret(?:/|$)".into()],
                operations: vec![FileSandboxOperation::Read],
                protection: None,
            }],
        })
        .unwrap();
        assert_eq!(
            file_sandbox_decision(&snapshot, "C:/secret/key", FileSandboxOperation::Read).0,
            SandboxAction::Deny
        );
        assert_eq!(
            file_sandbox_decision(&snapshot, "C:/secret/key", FileSandboxOperation::Write).0,
            SandboxAction::Pass
        );
    }

    #[test]
    fn compiled_process_pattern_binds_executable_and_command_line() {
        let snapshot = compile_process_snapshot(ProcessSandboxSnapshot {
            default_action: SandboxAction::Pass,
            error_action: SandboxAction::Pass,
            rules: vec![ProcessSandboxSnapshotRule {
                id: "blocked-tool".into(),
                action: SandboxAction::Deny,
                patterns: vec![ProcessSandboxPattern {
                    executable: r"(?i)tool\.exe$".into(),
                    command_line: r"--danger(?:\s|$)".into(),
                }],
                protection: None,
            }],
        })
        .unwrap();
        assert_eq!(
            process_sandbox_decision(&snapshot, "C:/bin/tool.exe", "tool.exe --danger").0,
            SandboxAction::Deny
        );
        assert_eq!(
            process_sandbox_decision(&snapshot, "C:/bin/tool.exe", "tool.exe --safe").0,
            SandboxAction::Pass
        );
        assert_eq!(
            process_sandbox_decision(&snapshot, "C:/bin/other.exe", "other.exe --danger").0,
            SandboxAction::Pass
        );
    }
}

pub(crate) struct SandboxState {
    pub(crate) firewall: Option<Arc<FirewallSnapshot>>,
    pub(crate) process: Arc<Snapshot<CompiledProcessSandboxSnapshot>>,
    pub(crate) file: Arc<Snapshot<CompiledFileSandboxSnapshot>>,
    pub(crate) version: Arc<AtomicU64>,
}
impl Default for SandboxState {
    fn default() -> Self {
        Self {
            firewall: None,
            process: Arc::new(Snapshot::empty()),
            file: Arc::new(Snapshot::empty()),
            version: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn apply_sandbox_snapshot(snapshot: SandboxSnapshot) {
    let Some(process) = snapshot
        .process
        .map(compile_process_snapshot)
        .transpose()
        .ok()
    else {
        return;
    };
    let Some(file) = snapshot.file.map(compile_file_snapshot).transpose().ok() else {
        return;
    };
    if let Ok(mut core) = crate::state().lock() {
        if snapshot.version < core.sandbox.version.load(Ordering::Acquire) {
            return;
        }
        core.sandbox.firewall = snapshot.network.map(Arc::new);
        core.sandbox.process.store(process.map(Arc::new));
        core.sandbox.file.store(file.map(Arc::new));
        core.sandbox
            .version
            .store(snapshot.version, Ordering::Release);
    }
}
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn process_sandbox_snapshot() -> Option<Arc<CompiledProcessSandboxSnapshot>> {
    crate::state().lock().ok()?.sandbox.process.load_full()
}
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn file_sandbox_snapshot() -> Option<Arc<CompiledFileSandboxSnapshot>> {
    crate::state().lock().ok()?.sandbox.file.load_full()
}

#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
pub(crate) fn compile_process_snapshot(
    snapshot: ProcessSandboxSnapshot,
) -> Result<CompiledProcessSandboxSnapshot, regex::Error> {
    for rule in &snapshot.rules {
        for pattern in &rule.patterns {
            if !pattern.executable.is_empty() {
                regex::Regex::new(&pattern.executable)?;
            }
            if !pattern.command_line.is_empty() {
                regex::Regex::new(&pattern.command_line)?;
            }
        }
    }
    Ok(CompiledProcessSandboxSnapshot {
        error_action: snapshot.error_action,
        wire: serde_json::to_value(snapshot).expect("serializable policy"),
    })
}

#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
pub(crate) fn compile_file_snapshot(
    snapshot: FileSandboxSnapshot,
) -> Result<CompiledFileSandboxSnapshot, regex::Error> {
    for rule in &snapshot.rules {
        for pattern in &rule.patterns {
            regex::Regex::new(pattern)?;
        }
    }
    Ok(CompiledFileSandboxSnapshot {
        error_action: snapshot.error_action,
        wire: serde_json::to_value(snapshot).expect("serializable policy"),
    })
}
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn sandbox_version() -> u64 {
    crate::state()
        .lock()
        .map(|c| c.sandbox.version.load(Ordering::Acquire))
        .unwrap_or(0)
}
