use crate::hook_runtime::{
    AgentHookPlugin, CallbackCategory, HookDecision, HookError, HookFailureMode,
};
use crate::windows_gum::runtime::{PluginRegistrar, ProcessCreateContext};
use std::sync::{
    mpsc::{sync_channel, SyncSender},
    Arc,
};
use windows_sys::Win32::Foundation::{SetLastError, ERROR_ACCESS_DENIED};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022u32 as i32;
struct ProcessSandboxPlugin {
    audit: Option<SyncSender<crate::SandboxAuditEvent>>,
}
impl ProcessSandboxPlugin {
    fn new() -> Self {
        let (tx, rx) = sync_channel(256);
        let audit = if cfg!(test) {
            None
        } else {
            std::thread::Builder::new()
                .name("hyperhub-process-sandbox-audit".into())
                .spawn(move || {
                    while let Ok(e) = rx.recv() {
                        let _ = crate::report_sandbox_audit(&e);
                    }
                })
                .ok()
                .map(|_| tx)
        };
        Self { audit }
    }
    fn decide(
        &self,
        exe: Option<&str>,
        cmd: Option<&str>,
    ) -> (crate::SandboxAction, Option<String>, String) {
        let Some(s) = crate::process_sandbox_snapshot() else {
            return (crate::SandboxAction::Pass, None, "disabled".into());
        };
        let (Some(exe), Some(cmd)) = (exe, cmd) else {
            return (s.error_action, None, "error".into());
        };
        crate::process_decision_with_protection(exe, cmd)
    }
    fn failure_mode(&self) -> HookFailureMode {
        match crate::process_sandbox_snapshot() {
            Some(snapshot) if snapshot.error_action == crate::SandboxAction::Deny => {
                HookFailureMode::FailClosed
            }
            _ => HookFailureMode::FailOpen,
        }
    }
    fn audit(
        &self,
        decision: crate::SandboxAction,
        rule_id: Option<String>,
        source: String,
        target: String,
    ) {
        if let Some(tx) = &self.audit {
            let _ = tx.try_send(crate::SandboxAuditEvent {
                kind: crate::SandboxAuditKind::Process,
                decision,
                rule_id,
                source,
                operation: "create".into(),
                target,
                process_pid: unsafe { GetCurrentProcessId() },
                process_tid: unsafe { GetCurrentThreadId() },
                snapshot_version: crate::sandbox_version(),
            });
        }
    }
}
impl AgentHookPlugin for ProcessSandboxPlugin {
    fn id(&self) -> &'static str {
        "process-sandbox"
    }
}
pub(crate) fn register(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    let p = Arc::new(ProcessSandboxPlugin::new());
    let cb = p.clone();
    let provider = p.clone();
    registrar.process_create_before_with_failure_mode_provider(
        p.id(),
        CallbackCategory::Control,
        HookFailureMode::FailOpen,
        move || provider.failure_mode(),
        move |ctx| {
            let (exe, cmd, native) = match ctx {
                ProcessCreateContext::Win32(c) => {
                    (c.executable.as_deref(), c.command_line.as_deref(), false)
                }
                ProcessCreateContext::Native(c) => {
                    (c.executable.as_deref(), c.command_line.as_deref(), true)
                }
            };
            let normalized_exe = exe.map(|exe| exe.replace('\\', "/"));
            let (a, id, src) = cb.decide(normalized_exe.as_deref(), cmd);
            if src == "error" || a == crate::SandboxAction::Deny {
                cb.audit(
                    a,
                    id.clone(),
                    src.clone(),
                    exe.unwrap_or("<unresolved>").to_owned(),
                );
            }
            if a == crate::SandboxAction::Deny {
                if native {
                    Ok(HookDecision::Deny(STATUS_ACCESS_DENIED))
                } else {
                    unsafe { SetLastError(ERROR_ACCESS_DENIED) };
                    Ok(HookDecision::Deny(0))
                }
            } else {
                Ok(HookDecision::Continue)
            }
        },
    );
    registrar.retain_plugin(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_snapshot_passes() {
        let p = ProcessSandboxPlugin { audit: None };
        assert_eq!(p.decide(Some("x"), Some("y")).0, crate::SandboxAction::Pass);
    }
}
