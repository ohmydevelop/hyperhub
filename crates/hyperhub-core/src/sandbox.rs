use crate::config::{Config, FileSandboxOperation, SandboxAction};
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
            legacy: Default::default(),
        });
        config.sandbox.file.enabled = true;
        config.sandbox.file.rules.push(FileSandboxRule {
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
}
