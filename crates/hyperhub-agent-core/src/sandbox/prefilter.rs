use super::PrefilterPolicy;
use serde::Serialize;
use std::collections::BTreeSet;

pub(crate) const QUERY_THRESHOLD: u32 = 60;

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct PrefilterContext {
    pub(crate) sensitive_files_read: u32,
    pub(crate) sensitive_bytes_read: u64,
    pub(crate) external_input_seen: bool,
    pub(crate) prompt_injection_seen: bool,
    pub(crate) destination_authorized: Option<bool>,
    pub(crate) managed_secret_match: bool,
    pub(crate) static_sandbox_deny: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct PrefilterDecision {
    pub(crate) score: u32,
    pub(crate) hard_deny: bool,
    pub(crate) should_query_gateway: bool,
    pub(crate) features: Vec<String>,
    pub(crate) redacted_argv: Vec<String>,
}

pub(crate) fn evaluate(
    policy: PrefilterPolicy,
    executable: &str,
    argv: &[String],
    context: &PrefilterContext,
) -> PrefilterDecision {
    let mut score = 0u32;
    let mut features = BTreeSet::new();
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
        " -T",
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
    let should_query_gateway = !hard_deny && score >= QUERY_THRESHOLD;
    let redacted_argv = redact_argv(argv);
    PrefilterDecision {
        score,
        hard_deny,
        should_query_gateway,
        features: features.into_iter().collect(),
        redacted_argv,
    }
}

fn redact_argv(argv: &[String]) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_command_does_not_query() {
        let result = evaluate(
            PrefilterPolicy::NetworkUpload,
            "curl",
            &["curl".into(), "https://api.example.test/health".into()],
            &PrefilterContext {
                destination_authorized: Some(true),
                ..Default::default()
            },
        );
        assert!(!result.should_query_gateway);
        assert!(!result.hard_deny);
    }

    #[test]
    fn sensitive_upload_queries_and_redacts_header() {
        let result = evaluate(
            PrefilterPolicy::NetworkUpload,
            "curl",
            &[
                "curl".into(),
                "--request".into(),
                "POST".into(),
                "--header".into(),
                "Authorization: Bearer test-token".into(),
                "--data-binary".into(),
                "@/tmp/.env".into(),
            ],
            &PrefilterContext {
                sensitive_files_read: 1,
                prompt_injection_seen: true,
                destination_authorized: Some(false),
                ..Default::default()
            },
        );
        assert!(result.should_query_gateway);
        assert!(result.features.contains(&"sensitive_file_read".into()));
        assert!(!result
            .redacted_argv
            .iter()
            .any(|value| value.contains("test-token")));
        assert!(result
            .redacted_argv
            .iter()
            .any(|value| value.contains("<redacted>")));
    }

    #[test]
    fn managed_secret_is_local_hard_deny_without_query() {
        let result = evaluate(
            PrefilterPolicy::NetworkUpload,
            "curl",
            &["curl".into(), "--data-binary".into(), "@export.txt".into()],
            &PrefilterContext {
                managed_secret_match: true,
                ..Default::default()
            },
        );
        assert!(result.hard_deny);
        assert!(!result.should_query_gateway);
    }
}

pub(crate) fn process_prefilter(
    snapshot: &super::CompiledProcessSandboxSnapshot,
    executable: &str,
    command_line: &str,
    context: &PrefilterContext,
) -> Option<(String, PrefilterDecision)> {
    let rule = snapshot.rules.iter().find(|rule| {
        rule.patterns.iter().any(|pattern| {
            pattern
                .executable
                .as_ref()
                .is_none_or(|regex| regex.is_match(executable))
                && pattern
                    .command_line
                    .as_ref()
                    .is_none_or(|regex| regex.is_match(command_line))
        })
    })?;
    if rule.protection.is_none() {
        return None;
    }
    let argv = command_line
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    Some((
        rule.id.clone(),
        evaluate(rule.prefilter_policy, executable, &argv, context),
    ))
}

pub(crate) fn file_prefilter(
    snapshot: &super::CompiledFileSandboxSnapshot,
    path: &str,
    operation: super::FileSandboxOperation,
    context: &PrefilterContext,
) -> Option<(String, PrefilterDecision)> {
    let rule = snapshot.rules.iter().find(|rule| {
        rule.operations.contains(&operation)
            && rule.patterns.iter().any(|pattern| pattern.is_match(path))
    })?;
    if rule.protection.is_none() {
        return None;
    }
    Some((
        rule.id.clone(),
        evaluate(rule.prefilter_policy, path, &[path.to_owned()], context),
    ))
}
