use crate::contract::INVALID;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectionContext {
    pub sensitive_files_read: u32,
    pub sensitive_bytes_read: u64,
    pub external_input_seen: bool,
    pub prompt_injection_seen: bool,
    pub destination_authorized: Option<bool>,
    pub managed_secret_match: bool,
    pub static_sandbox_deny: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SanitizedAction {
    pub local_deny: bool,
    pub features: Vec<String>,
    pub redacted_argv: Vec<String>,
}

pub fn sanitize(executable: &str, argv: &[String], context: &ProtectionContext) -> SanitizedAction {
    let mut features = BTreeSet::new();
    let joined = std::iter::once(executable)
        .chain(argv.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let lower = joined.to_ascii_lowercase();
    for (feature, markers) in [
        (
            "network_tool",
            &["curl", "wget", "scp", "sftp", "rsync", "git"][..],
        ),
        (
            "upload_argument",
            &[
                "--data",
                "--data-raw",
                "--data-binary",
                "--upload-file",
                "--post-file",
                "--request",
            ][..],
        ),
        (
            "archive_or_encode",
            &["tar", "zip", "gzip", "7z", "base64", "openssl"][..],
        ),
        (
            "dangerous_marker",
            &[
                "delete",
                "destroy",
                "shutdown",
                "drop",
                "purge",
                "--force",
                "production",
            ][..],
        ),
    ] {
        if markers.iter().any(|marker| lower.contains(marker)) {
            features.insert(feature.to_owned());
        }
    }
    if lower.contains("--request post")
        || lower.contains("--request put")
        || lower.contains("--request patch")
        || lower.contains("--request delete")
    {
        features.insert("state_change_method".to_owned());
    }
    if lower.contains(".env")
        || lower.contains("credentials")
        || lower.contains("id_rsa")
        || lower.contains("id_ed25519")
        || lower.contains(".ssh")
        || lower.contains("secret")
    {
        features.insert("sensitive_file_reference".to_owned());
    }
    if context.sensitive_files_read > 0 {
        features.insert("sensitive_file_read".to_owned());
    }
    if context.external_input_seen {
        features.insert("external_input_seen".to_owned());
    }
    if context.prompt_injection_seen {
        features.insert("prompt_injection_source".to_owned());
    }
    if context.destination_authorized == Some(false) {
        features.insert("external_destination".to_owned());
    }
    if context.managed_secret_match {
        features.insert("managed_secret_match".to_owned());
    }
    let redacted_argv = redact_argv(argv);
    let secret_redacted = redacted_argv != argv;
    if secret_redacted {
        features.insert("secret_argument".to_owned());
    }
    SanitizedAction {
        local_deny: context.static_sandbox_deny || context.managed_secret_match || secret_redacted,
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

#[derive(Deserialize)]
struct Input {
    executable: String,
    argv: Vec<String>,
    context: ProtectionContext,
}
pub(crate) fn execute(input: &[u8]) -> Result<Vec<u8>, i32> {
    let input: Input = serde_json::from_slice(input).map_err(|_| INVALID)?;
    serde_json::to_vec(&sanitize(&input.executable, &input.argv, &input.context))
        .map_err(|_| INVALID)
}
