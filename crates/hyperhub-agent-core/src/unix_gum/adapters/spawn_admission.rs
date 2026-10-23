//! Keep a spawned child's original parent alive until registration is observed.
use crate::control::{AgentControlRequest, AgentControlResponse, StartupDeadline};

fn child_identity(pid: libc::pid_t) -> Option<(libc::pid_t, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    Some((fields.get(1)?.parse().ok()?, fields.get(19)?.parse().ok()?))
}

/// This is a registration barrier, not a replacement for the manager's gated
/// child bootstrap. Failure must not misreport an already-created POSIX child,
/// change its PID result, or signal a numeric PID that could have been reused.
pub(super) fn await_registration(pid: libc::pid_t) -> Result<(), ()> {
    let deadline = StartupDeadline::new();
    let identity = child_identity(pid).ok_or(())?;
    if identity.0 != unsafe { libc::getpid() } || identity.1 == 0 {
        return Err(());
    }
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|_| ())?
        .to_string_lossy()
        .into_owned();
    let (endpoint, session_id, token) = {
        let state = crate::state().lock().map_err(|_| ())?;
        (
            state.session.control_endpoint.clone(),
            state.session.session_id.clone(),
            state.session.token.clone(),
        )
    };
    let response = deadline
        .exchange(
            &endpoint,
            &AgentControlRequest::RegisterChild {
                session_id: &session_id,
                token: &token,
                parent_pid: identity.0 as u32,
                child_pid: pid as u32,
                executable: &executable,
                process_policy_version: 0,
                process_rule_id: None,
                process_decision_source: "posix_spawn",
            },
        )
        .map_err(|_| ())?;
    if matches!(response, AgentControlResponse::Ok) && child_identity(pid) == Some(identity) {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_process_cannot_be_claimed_as_a_spawned_child() {
        // The current process has its own parent, not itself. No control
        // connection or environment credential is read for this rejection.
        assert!(await_registration(unsafe { libc::getpid() }).is_err());
        assert!(await_registration(0).is_err());
    }
}
