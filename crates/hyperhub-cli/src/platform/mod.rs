use std::ffi::OsString;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetBackend {
    GumInterceptor,
    #[cfg(target_os = "linux")]
    PtraceSyscall,
}

impl TargetBackend {
    pub const fn requires_agent_runtime(self) -> bool {
        matches!(self, Self::GumInterceptor)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::GumInterceptor => "frida-core+gum-interceptor",
            #[cfg(target_os = "linux")]
            Self::PtraceSyscall => "ptrace-syscall",
        }
    }
}

pub fn backend_trust_environment(
    backend: TargetBackend,
    tls_ca_pem: &str,
) -> Result<Vec<(OsString, OsString)>, String> {
    #[cfg(target_os = "linux")]
    {
        return linux::backend_trust_environment(backend, tls_ca_pem);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (backend, tls_ca_pem);
        Ok(Vec::new())
    }
}

pub fn same_executable_path(left: &Path, right: &Path) -> bool {
    left == right
}

pub fn run_internal(args: &[OsString]) -> Option<Result<i32, String>> {
    #[cfg(target_os = "linux")]
    {
        return linux::run_internal(args);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        None
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub const INJECTOR_NAME: &str = "frida-gum-rust";
#[cfg(target_os = "linux")]
pub const INJECTOR_NAME: &str = "frida-core+gum/ptrace-syscall";
#[cfg(not(any(windows, target_os = "linux")))]
pub const INJECTOR_NAME: &str = "unsupported";

#[cfg(windows)]
pub fn target_backend(_target: &Path, requested: Option<&str>) -> Result<TargetBackend, String> {
    match requested {
        None | Some("gum") => Ok(TargetBackend::GumInterceptor),
        Some("ptrace") => Err("ptrace backend is only available on Linux".into()),
        Some(value) => Err(format!("unknown backend '{value}'; use gum")),
    }
}

#[cfg(target_os = "linux")]
pub fn target_backend(target: &Path, requested: Option<&str>) -> Result<TargetBackend, String> {
    linux::target_backend(target, requested)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn target_backend(_target: &Path, _requested: Option<&str>) -> Result<TargetBackend, String> {
    Err("unsupported platform".into())
}

#[cfg(windows)]
pub fn doctor_target(target: &Path) -> Result<String, String> {
    windows::doctor_target(target)
}

#[cfg(windows)]
pub fn validate_target_runtime(target: &Path, runtime: &Path) -> Result<(), String> {
    windows::validate_target_runtime(target, runtime)
}

#[cfg(target_os = "linux")]
pub fn validate_target_runtime(target: &Path, runtime: &Path) -> Result<(), String> {
    linux::validate_target_runtime(target, runtime)
}
#[cfg(not(any(windows, target_os = "linux")))]
pub fn validate_target_runtime(_target: &Path, _runtime: &Path) -> Result<(), String> {
    Err("unsupported platform".into())
}

#[cfg(target_os = "linux")]
pub fn doctor_target(target: &Path) -> Result<String, String> {
    linux::doctor_target(target)
}
#[cfg(not(any(windows, target_os = "linux")))]
pub fn doctor_target(_target: &Path) -> Result<String, String> {
    Err("unsupported platform".into())
}

#[cfg(windows)]
pub fn run_injected<F>(
    target: &OsString,
    argv0: &OsString,
    args: &[OsString],
    backend: TargetBackend,
    runtime: Option<&Path>,
    env: &[(OsString, OsString)],
    sandbox: Option<&hyperhub_core::sandbox::SandboxSnapshot>,
    activate: F,
) -> Result<i32, String>
where
    F: FnOnce(u32, &std::ffi::OsStr) -> Result<bool, String>,
{
    let _ = sandbox;
    if backend != TargetBackend::GumInterceptor {
        return Err("Windows supports only the Gum backend".into());
    }
    windows::run_injected(target, argv0, args, runtime, env, activate)
}

#[cfg(target_os = "linux")]
pub fn run_injected<F>(
    target: &OsString,
    argv0: &OsString,
    args: &[OsString],
    backend: TargetBackend,
    runtime: Option<&Path>,
    env: &[(OsString, OsString)],
    sandbox: Option<&hyperhub_core::sandbox::SandboxSnapshot>,
    activate: F,
) -> Result<i32, String>
where
    F: FnOnce(u32, &std::ffi::OsStr) -> Result<bool, String>,
{
    linux::run_injected(
        target, argv0, args, backend, runtime, env, sandbox, activate,
    )
}
#[cfg(not(any(windows, target_os = "linux")))]
pub fn run_injected<F>(
    _target: &OsString,
    _argv0: &OsString,
    _args: &[OsString],
    _backend: TargetBackend,
    _runtime: Option<&Path>,
    _env: &[(OsString, OsString)],
    _activate: F,
) -> Result<i32, String>
where
    F: FnOnce(u32, &std::ffi::OsStr) -> Result<bool, String>,
{
    Err("unsupported platform".into())
}

/// Inspect a live target without granting authority to alter it.
pub fn inspect_attachment_target(
    pid: u32,
) -> Result<hyperhub_core::attachments::ProcessIdentity, String> {
    #[cfg(target_os = "linux")]
    {
        return linux::inspect_attachment_target(pid);
    }
    #[cfg(windows)]
    {
        return windows::inspect_attachment_target(pid);
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        Err("dynamic attachment is unsupported on this platform".into())
    }
}
pub fn validate_attachment_backend(
    pid: u32,
    scope: hyperhub_core::attachments::Scope,
    backend: hyperhub_core::attachments::Backend,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux::validate_attachment_backend(pid, scope, backend)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, scope, backend);
        Ok(())
    }
}

pub fn validate_external_runtime(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::validate_external_runtime(pid)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Ok(())
    }
}

pub fn run_attachment_manager(
    execution: &hyperhub_core::attachments::Execution,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        return linux::run_attachment_manager(execution);
    }
    #[cfg(windows)]
    {
        return windows::run_attachment_manager(execution);
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = execution;
        Err("dynamic attachment is unsupported on this platform".into())
    }
}
pub fn run_attachment_recovery(
    execution: &hyperhub_core::attachments::Execution,
    record: &hyperhub_core::attachments::Record,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        return linux::run_attachment_recovery(execution, record);
    }
    #[cfg(windows)]
    {
        return windows::run_attachment_recovery(execution, record);
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (execution, record);
        Err("attachment recovery is not supported on this platform".into())
    }
}
pub fn run_owned_attachment_manager(
    execution: &hyperhub_core::attachments::Execution,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        return windows::run_owned_attachment_manager(execution);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = execution;
        return Err(
            "Linux foreground attachment managers cannot transfer ownership to a second keeper"
                .into(),
        );
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = execution;
        Err("reversible attachment keepers are not supported on this platform".into())
    }
}
pub fn detach_attachment(
    record: &hyperhub_core::attachments::Record,
    authorization: &hyperhub_core::attachments::Authorization,
) -> Result<hyperhub_core::attachments::Outcome, String> {
    #[cfg(target_os = "linux")]
    {
        return linux::detach_attachment(record, authorization);
    }
    #[cfg(windows)]
    {
        return windows::detach_attachment(record, authorization);
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (record, authorization);
        Err("dynamic attachment is unsupported on this platform".into())
    }
}
pub fn reattach_attachment(
    record: &hyperhub_core::attachments::Record,
    authorization: &hyperhub_core::attachments::Authorization,
) -> Result<hyperhub_core::attachments::Outcome, String> {
    #[cfg(target_os = "linux")]
    {
        return linux::reattach_attachment(record, authorization);
    }
    #[cfg(windows)]
    {
        return windows::reattach_attachment(record, authorization);
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (record, authorization);
        Err("dynamic attachment is unsupported on this platform".into())
    }
}
