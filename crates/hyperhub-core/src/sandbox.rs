use crate::config::{Config, FileSandboxOperation, PrefilterPolicy, SandboxAction};
use crate::firewall::{compile_snapshot as compile_firewall, FirewallSnapshot};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxSnapshot {
    pub version: u64,
    pub network: Option<FirewallSnapshot>,
    pub process: Option<ProcessSandboxSnapshot>,
    pub file: Option<FileSandboxSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessSandboxSnapshot {
    pub default_action: SandboxAction,
    #[serde(default)]
    pub error_action: SandboxAction,
    pub rules: Vec<ProcessSandboxSnapshotRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessSandboxSnapshotRule {
    pub id: String,
    pub action: SandboxAction,
    pub patterns: Vec<ProcessSandboxSnapshotPattern>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<String>,
    #[serde(default)]
    pub prefilter_policy: PrefilterPolicy,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessSandboxSnapshotPattern {
    pub executable: String,
    pub command_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileSandboxSnapshot {
    pub default_action: SandboxAction,
    #[serde(default)]
    pub error_action: SandboxAction,
    pub rules: Vec<FileSandboxSnapshotRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileSandboxSnapshotRule {
    pub id: String,
    pub action: SandboxAction,
    pub patterns: Vec<String>,
    pub operations: Vec<FileSandboxOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<String>,
    #[serde(default)]
    pub prefilter_policy: PrefilterPolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxAuditKind {
    Process,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxAuditEvent {
    pub kind: SandboxAuditKind,
    pub decision: SandboxAction,
    pub rule_id: Option<String>,
    pub source: String,
    pub operation: String,
    pub target: String,
    pub process_pid: u32,
    pub process_tid: u32,
    pub snapshot_version: u64,
}

#[derive(Debug)]
pub struct CompiledSandboxSnapshot {
    pub version: u64,
    pub process: Option<CompiledProcessSandboxSnapshot>,
    pub file: Option<CompiledFileSandboxSnapshot>,
}

#[derive(Debug)]
pub struct CompiledProcessSandboxSnapshot {
    default_action: SandboxAction,
    error_action: SandboxAction,
    rules: Vec<CompiledProcessSandboxRule>,
}

#[derive(Debug)]
struct CompiledProcessSandboxRule {
    id: String,
    action: SandboxAction,
    patterns: Vec<CompiledProcessSandboxPattern>,
    protection: Option<String>,
    prefilter_policy: PrefilterPolicy,
}

#[derive(Debug)]
struct CompiledProcessSandboxPattern {
    executable: Option<regex::Regex>,
    command_line: Option<regex::Regex>,
}

#[derive(Debug)]
pub struct CompiledFileSandboxSnapshot {
    default_action: SandboxAction,
    error_action: SandboxAction,
    rules: Vec<CompiledFileSandboxRule>,
}

#[derive(Debug)]
struct CompiledFileSandboxRule {
    id: String,
    action: SandboxAction,
    patterns: Vec<regex::Regex>,
    operations: Vec<FileSandboxOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxDecision {
    pub action: SandboxAction,
    pub rule_id: Option<String>,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessProtectionBinding {
    pub rule_id: String,
    pub protection_id: String,
    pub prefilter_policy: PrefilterPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPrefilterContext {
    #[serde(default)]
    pub sensitive_files_read: u32,
    #[serde(default)]
    pub sensitive_bytes_read: u64,
    #[serde(default)]
    pub external_input_seen: bool,
    #[serde(default)]
    pub prompt_injection_seen: bool,
    #[serde(default)]
    pub destination_authorized: Option<bool>,
    #[serde(default)]
    pub managed_secret_match: bool,
    #[serde(default)]
    pub static_sandbox_deny: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessPrefilterDecision {
    pub score: u32,
    pub hard_deny: bool,
    pub should_query_gateway: bool,
    pub features: Vec<String>,
    pub redacted_argv: Vec<String>,
}

pub fn compile_runtime_snapshot(
    snapshot: SandboxSnapshot,
) -> Result<CompiledSandboxSnapshot, regex::Error> {
    let process = snapshot
        .process
        .map(|process| {
            let rules = process
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
                        .collect::<Result<Vec<_>, regex::Error>>()?;
                    Ok(CompiledProcessSandboxRule {
                        id: rule.id,
                        action: rule.action,
                        patterns,
                        protection: rule.protection,
                        prefilter_policy: rule.prefilter_policy,
                    })
                })
                .collect::<Result<Vec<_>, regex::Error>>()?;
            Ok(CompiledProcessSandboxSnapshot {
                default_action: process.default_action,
                error_action: process.error_action,
                rules,
            })
        })
        .transpose()?;
    let file = snapshot
        .file
        .map(|file| {
            let rules = file
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
                            .collect::<Result<Vec<_>, _>>()?,
                        operations: rule.operations,
                    })
                })
                .collect::<Result<Vec<_>, regex::Error>>()?;
            Ok(CompiledFileSandboxSnapshot {
                default_action: file.default_action,
                error_action: file.error_action,
                rules,
            })
        })
        .transpose()?;
    Ok(CompiledSandboxSnapshot {
        version: snapshot.version,
        process,
        file,
    })
}

pub fn decide_file(
    snapshot: &CompiledFileSandboxSnapshot,
    path: &str,
    operation: FileSandboxOperation,
) -> SandboxDecision {
    for rule in &snapshot.rules {
        if rule.operations.contains(&operation)
            && rule.patterns.iter().any(|pattern| pattern.is_match(path))
        {
            return SandboxDecision {
                action: rule.action,
                rule_id: Some(rule.id.clone()),
                source: "rule",
            };
        }
    }
    SandboxDecision {
        action: snapshot.default_action,
        rule_id: None,
        source: "default",
    }
}

pub fn decide_process(
    snapshot: &CompiledProcessSandboxSnapshot,
    executable: &str,
    command_line: &str,
) -> SandboxDecision {
    for rule in &snapshot.rules {
        if rule.patterns.iter().any(|pattern| {
            pattern
                .executable
                .as_ref()
                .is_none_or(|regex| regex.is_match(executable))
                && pattern
                    .command_line
                    .as_ref()
                    .is_none_or(|regex| regex.is_match(command_line))
        }) {
            return SandboxDecision {
                action: rule.action,
                rule_id: Some(rule.id.clone()),
                source: "rule",
            };
        }
    }
    SandboxDecision {
        action: snapshot.default_action,
        rule_id: None,
        source: "default",
    }
}

pub fn process_protection_binding(
    snapshot: &CompiledProcessSandboxSnapshot,
    executable: &str,
    command_line: &str,
) -> Option<ProcessProtectionBinding> {
    snapshot.rules.iter().find_map(|rule| {
        let protection_id = rule.protection.as_ref()?;
        rule.patterns
            .iter()
            .any(|pattern| {
                pattern
                    .executable
                    .as_ref()
                    .is_none_or(|regex| regex.is_match(executable))
                    && pattern
                        .command_line
                        .as_ref()
                        .is_none_or(|regex| regex.is_match(command_line))
            })
            .then(|| ProcessProtectionBinding {
                rule_id: rule.id.clone(),
                protection_id: protection_id.clone(),
                prefilter_policy: rule.prefilter_policy,
            })
    })
}

pub fn evaluate_process_prefilter(
    policy: PrefilterPolicy,
    executable: &str,
    argv: &[String],
    context: &ProcessPrefilterContext,
) -> ProcessPrefilterDecision {
    const QUERY_THRESHOLD: u32 = 60;
    let mut score = 0u32;
    let mut features = std::collections::BTreeSet::new();
    let joined = std::iter::once(executable)
        .chain(argv.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let lower = joined.to_ascii_lowercase();
    let network = ["curl", "wget", "scp", "sftp", "rsync", "git"];
    let upload = [
        "--data",
        "--data-raw",
        "--data-binary",
        "--upload-file",
        "--post-file",
        " -t ",
        " -t",
    ];
    let archive = ["tar", "zip", "gzip", "7z", "base64", "openssl"];

    if matches!(
        policy,
        PrefilterPolicy::NetworkUpload
            | PrefilterPolicy::ArchiveOrEncode
            | PrefilterPolicy::NetworkEgress
    ) && network
        .iter()
        .any(|tool| lower.split_whitespace().any(|part| part == *tool))
    {
        score += 20;
        features.insert("network_tool".to_owned());
    }
    if matches!(
        policy,
        PrefilterPolicy::NetworkUpload
            | PrefilterPolicy::ArchiveOrEncode
            | PrefilterPolicy::NetworkEgress
    ) && upload.iter().any(|marker| lower.contains(marker))
    {
        score += 20;
        features.insert("upload_argument".to_owned());
    }
    if matches!(policy, PrefilterPolicy::ArchiveOrEncode)
        && archive
            .iter()
            .any(|tool| lower.split_whitespace().any(|part| part == *tool))
    {
        score += 15;
        features.insert("archive_or_encode".to_owned());
    }
    if lower.contains("--request post")
        || lower.contains("--request put")
        || lower.contains("--request patch")
        || lower.contains("--request delete")
    {
        score += 10;
        features.insert("state_change_method".to_owned());
    }
    if [
        "delete",
        "destroy",
        "shutdown",
        "drop",
        "purge",
        "--force",
        "production",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        score += 20;
        features.insert("dangerous_marker".to_owned());
    }
    if lower.contains(".env")
        || lower.contains("credentials")
        || lower.contains("id_rsa")
        || lower.contains("id_ed25519")
        || lower.contains(".ssh")
        || lower.contains("secret")
    {
        score += 30;
        features.insert("sensitive_file_reference".to_owned());
    }
    if context.sensitive_files_read > 0 {
        score += 25;
        features.insert("sensitive_file_read".to_owned());
    }
    if context.external_input_seen {
        features.insert("external_input_seen".to_owned());
    }
    if context.prompt_injection_seen {
        score += 20;
        features.insert("prompt_injection_source".to_owned());
    }
    if context.destination_authorized == Some(false) {
        score += 10;
        features.insert("external_destination".to_owned());
    }
    if context.managed_secret_match {
        features.insert("managed_secret_match".to_owned());
    }
    let hard_deny = context.static_sandbox_deny || context.managed_secret_match;
    let score = score.min(100);
    ProcessPrefilterDecision {
        score,
        hard_deny,
        should_query_gateway: !hard_deny && score >= QUERY_THRESHOLD,
        features: features.into_iter().collect(),
        redacted_argv: redact_process_argv(argv),
    }
}

fn redact_process_argv(argv: &[String]) -> Vec<String> {
    let mut result = Vec::with_capacity(argv.len());
    let mut redact_next = false;
    let mut previous = "";
    for raw in argv {
        let mut value = raw.clone();
        if redact_next {
            value = "<redacted>".into();
            redact_next = false;
        }
        if matches!(previous, "--header" | "-H")
            && ["authorization:", "cookie:", "proxy-authorization:"]
                .iter()
                .any(|prefix| value.to_ascii_lowercase().starts_with(prefix))
        {
            if let Some((name, _)) = value.split_once(':') {
                value = format!("{name}: <redacted>");
            }
        }
        if let Some((prefix, _)) = value.split_once("Bearer ") {
            value = format!("{prefix}Bearer <redacted>");
        }
        for marker in ["--password=", "--token=", "--secret=", "--api-key="] {
            if value.to_ascii_lowercase().starts_with(marker) {
                value = format!("{marker}<redacted>");
            }
        }
        if matches!(
            raw.as_str(),
            "--password" | "--token" | "--secret" | "--api-key" | "--header" | "-H"
        ) {
            redact_next = true;
        }
        previous = raw;
        result.push(value);
    }
    result
}

/// Decide whether a child process should inherit the Agent runtime.
/// Command-line matching is intentionally not required here: at this stage the
/// launcher only has the executable path, and the child Agent will perform the
/// full command-line sandbox/protection decision before exec/spawn.
pub fn decide_process_hook(
    snapshot: &CompiledProcessSandboxSnapshot,
    executable: &str,
) -> SandboxDecision {
    for rule in &snapshot.rules {
        if rule.patterns.iter().any(|pattern| {
            pattern
                .executable
                .as_ref()
                .is_none_or(|regex| regex.is_match(executable))
        }) {
            return SandboxDecision {
                action: rule.action,
                rule_id: Some(rule.id.clone()),
                source: "rule",
            };
        }
    }
    SandboxDecision {
        action: snapshot.default_action,
        rule_id: None,
        source: "default",
    }
}

pub fn file_error_decision(snapshot: &CompiledFileSandboxSnapshot) -> SandboxDecision {
    SandboxDecision {
        action: snapshot.error_action,
        rule_id: None,
        source: "error",
    }
}

pub fn process_error_decision(snapshot: &CompiledProcessSandboxSnapshot) -> SandboxDecision {
    SandboxDecision {
        action: snapshot.error_action,
        rule_id: None,
        source: "error",
    }
}

pub fn compile_snapshot(config: &Config, version: u64) -> Result<SandboxSnapshot, String> {
    let network = compile_firewall(config, version)?;
    let process = if config.sandbox.process.enabled {
        let mut rules = Vec::new();
        for (order, rule) in config.sandbox.process.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            rules.push((
                rule.priority,
                order,
                ProcessSandboxSnapshotRule {
                    id: rule.id.clone(),
                    action: rule.action,
                    patterns: rule
                        .patterns
                        .iter()
                        .filter(|p| p.enabled)
                        .map(|p| ProcessSandboxSnapshotPattern {
                            executable: p.executable.clone(),
                            command_line: p.command_line.clone(),
                        })
                        .collect(),
                    protection: rule.protection.clone(),
                    prefilter_policy: rule.prefilter_policy,
                },
            ));
        }
        rules.sort_by_key(|(priority, order, _)| (std::cmp::Reverse(*priority), *order));
        Some(ProcessSandboxSnapshot {
            default_action: config.sandbox.process.default.action,
            error_action: config.sandbox.process.error_action,
            rules: rules.into_iter().map(|(_, _, r)| r).collect(),
        })
    } else {
        None
    };
    let file = if config.sandbox.file.enabled {
        let mut rules = Vec::new();
        for (order, rule) in config.sandbox.file.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            rules.push((
                rule.priority,
                order,
                FileSandboxSnapshotRule {
                    id: rule.id.clone(),
                    action: rule.action,
                    patterns: rule
                        .patterns
                        .iter()
                        .filter(|p| p.enabled)
                        .map(|p| p.pattern.clone())
                        .collect(),
                    operations: rule.operations.clone(),
                    protection: rule.protection.clone(),
                    prefilter_policy: rule.prefilter_policy,
                },
            ));
        }
        rules.sort_by_key(|(priority, order, _)| (std::cmp::Reverse(*priority), *order));
        Some(FileSandboxSnapshot {
            default_action: config.sandbox.file.default.action,
            error_action: config.sandbox.file.error_action,
            rules: rules.into_iter().map(|(_, _, r)| r).collect(),
        })
    } else {
        None
    };
    Ok(SandboxSnapshot {
        version,
        network,
        process,
        file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn compiles_ordered_process_and_file_snapshots() {
        let mut config = Config::default();
        config.sandbox.process.enabled = true;
        config.sandbox.process.rules.push(ProcessSandboxRule {
            uuid: crate::config::new_config_uuid(),
            id: "p".into(),
            enabled: true,
            priority: 2,
            action: SandboxAction::Deny,
            patterns: vec![
                ProcessSandboxPattern {
                    enabled: true,
                    executable: "shell.exe".into(),
                    command_line: "--secret".into(),
                },
                ProcessSandboxPattern {
                    enabled: false,
                    executable: "ignored.exe".into(),
                    command_line: String::new(),
                },
            ],
            protection: None,
            prefilter_policy: PrefilterPolicy::None,
            legacy: Default::default(),
        });
        config.sandbox.file.enabled = true;
        config.sandbox.file.rules.push(FileSandboxRule {
            uuid: crate::config::new_config_uuid(),
            id: "f".into(),
            enabled: true,
            priority: 1,
            action: SandboxAction::Deny,
            patterns: vec![
                FileSandboxPattern {
                    enabled: true,
                    pattern: "C:/secret".into(),
                },
                FileSandboxPattern {
                    enabled: false,
                    pattern: "C:/ignored".into(),
                },
            ],
            operations: vec![FileSandboxOperation::Read],
            protection: None,
            prefilter_policy: PrefilterPolicy::None,
            legacy: Default::default(),
        });
        let snapshot = compile_snapshot(&config, 7).unwrap();
        assert_eq!(snapshot.version, 7);
        let process = snapshot.process.unwrap();
        assert_eq!(process.rules[0].patterns.len(), 1);
        assert_eq!(process.rules[0].patterns[0].executable, "shell.exe");
        let file = snapshot.file.unwrap();
        assert_eq!(file.rules[0].patterns, vec!["C:/secret"]);
    }

    #[test]
    fn compiled_runtime_decides_file_and_process_intents() {
        let snapshot = SandboxSnapshot {
            version: 9,
            network: None,
            process: Some(ProcessSandboxSnapshot {
                default_action: SandboxAction::Pass,
                error_action: SandboxAction::Deny,
                rules: vec![ProcessSandboxSnapshotRule {
                    id: "deny-shell".into(),
                    action: SandboxAction::Deny,
                    patterns: vec![ProcessSandboxSnapshotPattern {
                        executable: r"/bin/sh$".into(),
                        command_line: r"--danger".into(),
                    }],
                    protection: None,
                    prefilter_policy: PrefilterPolicy::None,
                }],
            }),
            file: Some(FileSandboxSnapshot {
                default_action: SandboxAction::Pass,
                error_action: SandboxAction::Deny,
                rules: vec![FileSandboxSnapshotRule {
                    id: "deny-secret".into(),
                    action: SandboxAction::Deny,
                    patterns: vec![r"/secret(?:/|$)".into()],
                    operations: vec![FileSandboxOperation::Read],
                    protection: None,
                    prefilter_policy: PrefilterPolicy::None,
                }],
            }),
        };
        let compiled = compile_runtime_snapshot(snapshot).unwrap();
        assert_eq!(compiled.version, 9);
        assert_eq!(
            decide_file(
                compiled.file.as_ref().unwrap(),
                "/secret/value",
                FileSandboxOperation::Read,
            )
            .action,
            SandboxAction::Deny
        );
        assert_eq!(
            decide_process(compiled.process.as_ref().unwrap(), "/bin/sh", "sh --danger",).action,
            SandboxAction::Deny
        );
    }
    #[test]
    fn process_protection_prefilter_queries_and_redacts_full_argv() {
        let snapshot = SandboxSnapshot {
            version: 10,
            network: None,
            process: Some(ProcessSandboxSnapshot {
                default_action: SandboxAction::Pass,
                error_action: SandboxAction::Pass,
                rules: vec![ProcessSandboxSnapshotRule {
                    id: "protect-curl".into(),
                    action: SandboxAction::Pass,
                    patterns: vec![ProcessSandboxSnapshotPattern {
                        executable: r"curl$".into(),
                        command_line: r"curl".into(),
                    }],
                    protection: Some("jev".into()),
                    prefilter_policy: PrefilterPolicy::NetworkUpload,
                }],
            }),
            file: None,
        };
        let compiled = compile_runtime_snapshot(snapshot).unwrap();
        let process = compiled.process.as_ref().unwrap();
        let argv = vec![
            "curl".into(),
            "--request".into(),
            "POST".into(),
            "--header".into(),
            "Authorization: Bearer benchmark-secret".into(),
            "--data-binary".into(),
            "@/tmp/.env".into(),
        ];
        let command_line = argv.join(" ");
        let binding = process_protection_binding(process, "/usr/bin/curl", &command_line).unwrap();
        assert_eq!(binding.protection_id, "jev");
        let decision = evaluate_process_prefilter(
            binding.prefilter_policy,
            "/usr/bin/curl",
            &argv,
            &ProcessPrefilterContext::default(),
        );
        assert!(decision.should_query_gateway);
        assert!(decision
            .features
            .contains(&"sensitive_file_reference".into()));
        assert!(!decision
            .redacted_argv
            .iter()
            .any(|argument| argument.contains("benchmark-secret")));
    }
}
