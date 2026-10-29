//! Propagate the approved reversible Host to a child created suspended by us.
//! The parent's environment and the child's caller-supplied environment are
//! untouched. This path is never used to seize an unrelated existing process.
use hyperhub_runtime::attachment::{self, AuthenticatedCommand, HostCommand, HostPhase};
use windows_sys::Win32::Foundation::HANDLE;

pub(super) unsafe fn inject_created_child(
    process: HANDLE,
    child_pid: u32,
    executable: &str,
    decision: &crate::ProcessHookDecision,
) -> Result<(), u32> {
    let mut bootstrap = crate::attachment::bootstrap().ok_or(crate::HH_ERR_PROTOCOL as u32)?;
    let floor = loop {
        let before = crate::attachment::approval_not_before_ms();
        let propagate = crate::attachment::propagating();
        let after = crate::attachment::approval_not_before_ms();
        if before == after {
            if !bootstrap.scope_tree || !propagate {
                return Ok(());
            }
            break after;
        }
    };
    // Snapshot the accepted parent epoch before any blocking registration. A
    // later pending detach must remain a newer valid operation for this child.
    bootstrap.approval_not_before_ms = floor;
    crate::register_child_control(std::process::id(), child_pid, executable, decision)
        .map_err(|code| code as u32)?;
    let suffix = format!("-{}", std::process::id());
    let base = bootstrap
        .host_endpoint
        .strip_suffix(&suffix)
        .ok_or(crate::HH_ERR_PROTOCOL as u32)?;
    bootstrap.host_endpoint = format!("{base}-{child_pid}");
    // Immutable startup ownership is granted only in this creation path. Later
    // detach/reactivate still require the administrator's signed approval.
    bootstrap.initially_owned = true;
    bootstrap.approval_inherited_public_key = crate::attachment::approval_public_key();
    bootstrap.alias_inherited = crate::alias_namespace::inheritance();
    let path = super::windows::agent_module_path().ok_or(crate::HH_ERR_PROTOCOL as u32)?;
    let module = attachment::windows_inject::load(process, child_pid, &path)
        .map_err(|_| crate::HH_ERR_PROTOCOL as u32)?;
    attachment::windows_inject::start(process, &module, &bootstrap)
        .map_err(|_| crate::HH_ERR_PROTOCOL as u32)?;
    let status = match attachment::exchange_for_process(
        &bootstrap.host_endpoint,
        &AuthenticatedCommand {
            attachment_id: bootstrap.attachment_id.clone(),
            token: bootstrap.host_token.clone(),
            command: HostCommand::Status,
            proof: None,
            enrollment: None,
            aliases: None,
            root_image: None,
        },
        child_pid,
    ) {
        Ok(status) => status,
        // Our child completed native initialization. A concurrent approved parent
        // detach can retire its channel before this final startup observation.
        Err(_) if !crate::attachment::propagating() => return Ok(()),
        Err(_) => return Err(crate::HH_ERR_PROTOCOL as u32),
    };
    if !matches!(
        status.phase,
        HostPhase::Active
            | HostPhase::DetachedResident
            | HostPhase::Detaching
            | HostPhase::Detached
    ) {
        return Err(crate::HH_ERR_PROTOCOL as u32);
    }
    Ok(())
}
