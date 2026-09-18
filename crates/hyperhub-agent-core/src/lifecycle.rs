use crate::{
    exchange_control, state, AgentControlRequest, AgentControlResponse, HH_ERR_INVALID,
    HH_ERR_NOT_INITIALIZED, HH_ERR_PROTOCOL,
};

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn register_child_control(
    parent_pid: u32,
    child_pid: u32,
    executable: &str,
    policy: &crate::ProcessHookDecision,
) -> Result<(), i32> {
    let (endpoint, session_id, token) = {
        let core = state().lock().map_err(|_| HH_ERR_INVALID)?;
        if !core.session.initialized {
            return Err(HH_ERR_NOT_INITIALIZED);
        }
        (
            core.session.control_endpoint.clone(),
            core.session.session_id.clone(),
            core.session.token.clone(),
        )
    };
    let request = AgentControlRequest::RegisterChild {
        session_id: &session_id,
        token: &token,
        parent_pid,
        child_pid,
        executable,
        process_policy_version: policy.version,
        process_rule_id: policy.rule_id.as_deref(),
        process_decision_source: &policy.source,
    };
    match exchange_control(&endpoint, &request)? {
        AgentControlResponse::Ok => Ok(()),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn report_child_injection_failure(
    parent_pid: u32,
    child_pid: u32,
    executable: Option<&str>,
    stage: &str,
    error_code: u32,
) {
    let values = state().lock().ok().and_then(|core| {
        core.session.initialized.then(|| {
            (
                core.session.control_endpoint.clone(),
                core.session.session_id.clone(),
                core.session.token.clone(),
            )
        })
    });
    let Some((endpoint, session_id, token)) = values else {
        return;
    };
    let request = AgentControlRequest::ReportChildInjectionFailure {
        session_id: &session_id,
        token: &token,
        parent_pid,
        child_pid,
        executable,
        stage,
        error_code,
    };
    let _ = exchange_control(&endpoint, &request);
}
