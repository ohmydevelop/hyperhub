mod network;
mod sanitizer;

use arc_swap::ArcSwapOption;
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

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SandboxSnapshot {
    pub(crate) version: u64,
    pub(crate) network: Option<FirewallSnapshot>,
    pub(crate) process: Option<ProcessSandboxSnapshot>,
    pub(crate) file: Option<FileSandboxSnapshot>,
}
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(not(all(windows, feature = "gum-agent")), allow(dead_code))]
pub(crate) struct ProcessSandboxSnapshot {
    pub(crate) default_action: SandboxAction,
    #[serde(default)]
    pub(crate) error_action: SandboxAction,
    pub(crate) rules: Vec<ProcessSandboxSnapshotRule>,
}
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(not(all(windows, feature = "gum-agent")), allow(dead_code))]
pub(crate) struct ProcessSandboxSnapshotRule {
    pub(crate) id: String,
    pub(crate) action: SandboxAction,
    pub(crate) patterns: Vec<ProcessSandboxPattern>,
    #[serde(default)]
    pub(crate) protection: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
pub(crate) struct ProcessSandboxPattern {
    pub(crate) executable: String,
    pub(crate) command_line: String,
}
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(not(all(windows, feature = "gum-agent")), allow(dead_code))]
pub(crate) struct FileSandboxSnapshot {
    pub(crate) default_action: SandboxAction,
    #[serde(default)]
    pub(crate) error_action: SandboxAction,
    pub(crate) rules: Vec<FileSandboxSnapshotRule>,
}
#[derive(Clone, Debug, Deserialize)]
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
    pub(crate) default_action: SandboxAction,
    pub(crate) error_action: SandboxAction,
    rules: Vec<CompiledProcessSandboxRule>,
}
#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
struct CompiledProcessSandboxRule {
    id: String,
    action: SandboxAction,
    patterns: Vec<CompiledProcessSandboxPattern>,
    protection: Option<String>,
}
#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
struct CompiledProcessSandboxPattern {
    executable: Option<regex::Regex>,
    command_line: Option<regex::Regex>,
}
#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
pub(crate) struct CompiledFileSandboxSnapshot {
    pub(crate) default_action: SandboxAction,
    pub(crate) error_action: SandboxAction,
    rules: Vec<CompiledFileSandboxRule>,
}
#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
struct CompiledFileSandboxRule {
    id: String,
    action: SandboxAction,
    patterns: Vec<regex::Regex>,
    operations: Vec<FileSandboxOperation>,
    protection: Option<String>,
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
    pub(crate) process_pid: u32,
    pub(crate) process_tid: u32,
    pub(crate) snapshot_version: u64,
}

#[cfg(all(target_os = "linux", feature = "gum-agent"))]
pub(crate) fn file_allows(path: &str, op: FileSandboxOperation) -> bool {
    file_decision_with_protection(path, op).0 == SandboxAction::Pass
}
#[cfg(all(target_os = "linux", feature = "gum-agent"))]
pub(crate) fn process_allows(exe: &str, cmd: &str) -> bool {
    process_decision_with_protection(exe, cmd).0 == SandboxAction::Pass
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn file_sandbox_decision(
    snapshot: &CompiledFileSandboxSnapshot,
    path: &str,
    op: FileSandboxOperation,
) -> (SandboxAction, Option<String>, String) {
    for rule in &snapshot.rules {
        if rule.operations.contains(&op)
            && rule.patterns.iter().any(|pattern| pattern.is_match(path))
        {
            return (rule.action, Some(rule.id.clone()), "rule".into());
        }
    }
    (snapshot.default_action, None, "default".into())
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn process_sandbox_decision(
    snapshot: &CompiledProcessSandboxSnapshot,
    exe: &str,
    cmd: &str,
) -> (SandboxAction, Option<String>, String) {
    for rule in &snapshot.rules {
        if rule.patterns.iter().any(|pattern| {
            pattern
                .executable
                .as_ref()
                .is_none_or(|regex| regex.is_match(exe))
                && pattern
                    .command_line
                    .as_ref()
                    .is_none_or(|regex| regex.is_match(cmd))
        }) {
            return (rule.action, Some(rule.id.clone()), "rule".into());
        }
    }
    (snapshot.default_action, None, "default".into())
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn file_decision_with_protection(
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
    snapshot.rules.iter().find_map(|rule| {
        if rule.protection.is_none()
            || !rule.patterns.iter().any(|pattern| {
                pattern
                    .executable
                    .as_ref()
                    .is_none_or(|regex| regex.is_match(executable))
                    && pattern
                        .command_line
                        .as_ref()
                        .is_none_or(|regex| regex.is_match(command_line))
            })
        {
            return None;
        }
        Some((rule.id.clone(), rule.protection.clone()?))
    })
}

#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn file_protection_id(
    snapshot: &CompiledFileSandboxSnapshot,
    path: &str,
    operation: FileSandboxOperation,
) -> Option<(String, String)> {
    snapshot.rules.iter().find_map(|rule| {
        if rule.protection.is_none()
            || !rule.operations.contains(&operation)
            || !rule.patterns.iter().any(|pattern| pattern.is_match(path))
        {
            return None;
        }
        Some((rule.id.clone(), rule.protection.clone()?))
    })
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

#[cfg(all(test, any(windows, unix), feature = "gum-agent"))]
mod tests {
    use super::*;

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
    pub(crate) process: Arc<ArcSwapOption<CompiledProcessSandboxSnapshot>>,
    pub(crate) file: Arc<ArcSwapOption<CompiledFileSandboxSnapshot>>,
    pub(crate) version: Arc<AtomicU64>,
}
impl Default for SandboxState {
    fn default() -> Self {
        Self {
            firewall: None,
            process: Arc::new(ArcSwapOption::empty()),
            file: Arc::new(ArcSwapOption::empty()),
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
    let rules = snapshot
        .rules
        .into_iter()
        .map(|rule| {
            let patterns = rule
                .patterns
                .into_iter()
                .map(|pattern| {
                    Ok(CompiledProcessSandboxPattern {
                        executable: (!pattern.executable.is_empty())
                            .then(|| regex::Regex::new(&pattern.executable))
                            .transpose()?,
                        command_line: (!pattern.command_line.is_empty())
                            .then(|| regex::Regex::new(&pattern.command_line))
                            .transpose()?,
                    })
                })
                .collect::<Result<_, regex::Error>>()?;
            Ok(CompiledProcessSandboxRule {
                id: rule.id,
                action: rule.action,
                patterns,
                protection: rule.protection,
            })
        })
        .collect::<Result<_, regex::Error>>()?;
    Ok(CompiledProcessSandboxSnapshot {
        default_action: snapshot.default_action,
        error_action: snapshot.error_action,
        rules,
    })
}

#[cfg_attr(not(all(any(windows, unix), feature = "gum-agent")), allow(dead_code))]
pub(crate) fn compile_file_snapshot(
    snapshot: FileSandboxSnapshot,
) -> Result<CompiledFileSandboxSnapshot, regex::Error> {
    let rules = snapshot
        .rules
        .into_iter()
        .map(|rule| {
            Ok(CompiledFileSandboxRule {
                id: rule.id,
                action: rule.action,
                patterns: rule
                    .patterns
                    .into_iter()
                    .map(|pattern| regex::Regex::new(&pattern))
                    .collect::<Result<_, _>>()?,
                operations: rule.operations,
                protection: rule.protection,
            })
        })
        .collect::<Result<_, regex::Error>>()?;
    Ok(CompiledFileSandboxSnapshot {
        default_action: snapshot.default_action,
        error_action: snapshot.error_action,
        rules,
    })
}
#[cfg(all(any(windows, unix), feature = "gum-agent"))]
pub(crate) fn sandbox_version() -> u64 {
    crate::state()
        .lock()
        .map(|c| c.sandbox.version.load(Ordering::Acquire))
        .unwrap_or(0)
}
