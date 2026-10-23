use crate::hook_runtime::{
    AgentHookPlugin, CallbackCategory, HookDecision, HookError, HookFailureMode,
};
use crate::windows_gum::runtime::{FileOperation, FileOperationContext, PluginRegistrar};
use std::sync::{
    mpsc::{sync_channel, SyncSender},
    Arc,
};
use windows_sys::Win32::Foundation::{GetLastError, SetLastError, HANDLE};
use windows_sys::Win32::Storage::FileSystem::GetFileType;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

fn unresolved_handle_reason(handle: usize) -> String {
    let _last_error = crate::engine_call::WindowsLastErrorGuard::capture();
    let (kind, error) = unsafe {
        SetLastError(0);
        let kind = GetFileType(handle as HANDLE);
        (kind, GetLastError())
    };
    format!(
        "unresolved_file_path handle=0x{handle:x} pre_open={} file_type={kind} type_error={error}",
        handle == 0
    )
}

struct FileSandboxPlugin {
    audit: Option<SyncSender<crate::SandboxAuditEvent>>,
}

impl FileSandboxPlugin {
    fn new() -> Self {
        let (tx, rx) = sync_channel(256);
        let audit = if cfg!(test) {
            None
        } else {
            std::thread::Builder::new()
                .name("hyperhub-file-sandbox-audit".into())
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
        path: Option<&str>,
        op: FileOperation,
    ) -> (crate::SandboxAction, Option<String>, String) {
        let snapshot = crate::file_sandbox_snapshot();
        Self::decide_with_snapshot(snapshot.as_deref(), path, op)
    }
    fn decide_with_snapshot(
        snapshot: Option<&crate::CompiledFileSandboxSnapshot>,
        path: Option<&str>,
        op: FileOperation,
    ) -> (crate::SandboxAction, Option<String>, String) {
        let Some(s) = snapshot else {
            return (crate::SandboxAction::Pass, None, "disabled".into());
        };
        if path.is_none() {
            return (s.error_action, None, "error".into());
        }
        let mapped = match op {
            FileOperation::Read => crate::FileSandboxOperation::Read,
            FileOperation::Write => crate::FileSandboxOperation::Write,
            FileOperation::Create => crate::FileSandboxOperation::Create,
            FileOperation::Delete => crate::FileSandboxOperation::Delete,
            FileOperation::Rename => crate::FileSandboxOperation::Rename,
        };
        crate::file_decision_with_protection(path.unwrap_or_default(), mapped)
    }
    fn failure_mode(&self) -> HookFailureMode {
        match crate::file_sandbox_snapshot() {
            Some(snapshot) if snapshot.error_action == crate::SandboxAction::Deny => {
                HookFailureMode::FailClosed
            }
            _ => HookFailureMode::FailOpen,
        }
    }
    fn audit(
        &self,
        decision: crate::SandboxAction,
        id: Option<String>,
        source: String,
        op: FileOperation,
        path: String,
        reason: Option<String>,
    ) {
        let _last_error = crate::engine_call::WindowsLastErrorGuard::capture();
        if let Some(tx) = &self.audit {
            let _ = tx.try_send(crate::SandboxAuditEvent {
                kind: crate::SandboxAuditKind::File,
                decision,
                rule_id: id,
                source,
                operation: format!("{op:?}").to_ascii_lowercase(),
                target: path,
                process_argv_redacted: None,
                target_argv_redacted: None,
                reason,
                process_pid: unsafe { GetCurrentProcessId() },
                process_tid: unsafe { GetCurrentThreadId() },
                snapshot_version: crate::sandbox_version(),
            });
        }
    }
}
impl AgentHookPlugin for FileSandboxPlugin {
    fn id(&self) -> &'static str {
        "file-sandbox"
    }
}
pub(crate) fn register(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    let p = Arc::new(FileSandboxPlugin::new());
    let cb = p.clone();
    let provider = p.clone();
    registrar.file_operation_before_with_failure_mode_provider(
        p.id(),
        CallbackCategory::Control,
        HookFailureMode::FailOpen,
        move || provider.failure_mode(),
        move |c: &mut FileOperationContext| {
            let path = c.path.as_deref();
            let (a, id, src) = cb.decide(path, c.operation);
            if src == "error" || a == crate::SandboxAction::Deny {
                cb.audit(
                    a,
                    id.clone(),
                    src.clone(),
                    c.operation,
                    path.unwrap_or("<unresolved>").to_owned(),
                    (a == crate::SandboxAction::Deny && path.is_none())
                        .then(|| unresolved_handle_reason(c._handle)),
                );
            }
            if a == crate::SandboxAction::Deny {
                Ok(HookDecision::Deny(0xC000_0022u32 as i32))
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
    fn unresolved_handle_metadata_is_bounded_and_preserves_caller_errors() {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Networking::WinSock::{WSAGetLastError, WSASetLastError};
        use windows_sys::Win32::System::Pipes::CreatePipe;
        unsafe {
            let mut read = std::ptr::null_mut();
            let mut write = std::ptr::null_mut();
            assert_ne!(CreatePipe(&mut read, &mut write, std::ptr::null(), 0), 0);
            let read = OwnedHandle::from_raw_handle(read);
            let _write = OwnedHandle::from_raw_handle(write);
            WSASetLastError(12345);
            let reason = unresolved_handle_reason(read.as_raw_handle() as usize);
            assert!(reason.contains("pre_open=false file_type=3 type_error=0"));
            assert!(reason.len() <= 160);
            assert_eq!(GetLastError(), 12345);
            assert_eq!(WSAGetLastError(), 12345);
            let reason = unresolved_handle_reason(0);
            assert!(reason.contains("handle=0x0 pre_open=true"));
            assert!(reason.len() <= 160);
            assert_eq!(GetLastError(), 12345);
            assert_eq!(WSAGetLastError(), 12345);
        }
    }

    #[test]
    fn unresolved_reads_use_error_action() {
        let snapshot = crate::compile_file_snapshot(crate::FileSandboxSnapshot {
            default_action: crate::SandboxAction::Deny,
            error_action: crate::SandboxAction::Pass,
            rules: Vec::new(),
        })
        .unwrap();
        let decision =
            FileSandboxPlugin::decide_with_snapshot(Some(&snapshot), None, FileOperation::Read);
        assert_eq!(decision.0, crate::SandboxAction::Pass);
        assert_eq!(decision.1, None);
        assert_eq!(decision.2, "error");
    }

    #[test]
    fn missing_snapshot_passes() {
        let p = FileSandboxPlugin { audit: None };
        assert_eq!(
            p.decide(Some("C:/x"), FileOperation::Read).0,
            crate::SandboxAction::Pass
        );
    }
}
