use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct ProtectionContext {
    pub(crate) sensitive_files_read: u32,
    pub(crate) sensitive_bytes_read: u64,
    pub(crate) external_input_seen: bool,
    pub(crate) prompt_injection_seen: bool,
    pub(crate) destination_authorized: Option<bool>,
    pub(crate) managed_secret_match: bool,
    pub(crate) static_sandbox_deny: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SanitizedAction {
    pub(crate) local_deny: bool,
    pub(crate) features: Vec<String>,
    pub(crate) redacted_argv: Vec<String>,
}

pub(crate) fn sanitize(
    executable: &str,
    argv: &[String],
    context: &ProtectionContext,
) -> SanitizedAction {
    let engine = crate::state().lock().ok().map(|state| state.engine.clone());
    let result = engine.and_then(|engine| {
        let lease = crate::engine_call::calling(&engine).ok()?;
        let bytes = hyperhub_engine::call(
            &lease,
            hyperhub_engine::contract::SANITIZE_ACTION,
            &serde_json::json!({"executable": executable, "argv": argv, "context": context}),
        )
        .ok()?;
        serde_json::from_slice(&bytes).ok()
    });
    // A module error must not send unredacted secrets to the protection service.
    result.unwrap_or_else(|| SanitizedAction {
        local_deny: true,
        features: vec!["engine_error".into()],
        redacted_argv: vec!["<redacted>".into(); argv.len()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secret_arguments_and_marks_local_deny() {
        let result = sanitize(
            "curl",
            &[
                "curl".into(),
                "--header".into(),
                "Authorization: Bearer secret".into(),
            ],
            &ProtectionContext::default(),
        );
        assert!(result.local_deny);
        assert!(!result
            .redacted_argv
            .iter()
            .any(|value| value.contains("secret")));
    }

    #[test]
    fn safe_action_still_produces_model_features() {
        let result = sanitize(
            "curl",
            &["curl".into(), "https://example.test/health".into()],
            &ProtectionContext::default(),
        );
        assert!(!result.local_deny);
        assert!(result.features.contains(&"network_tool".into()));
    }
}
