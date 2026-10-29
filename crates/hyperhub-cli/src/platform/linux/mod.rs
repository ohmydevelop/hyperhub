mod dns_tracking;
mod fork_handoff;
mod frida_core;
mod hook_manifest;
mod launcher;
mod pty;
mod syscall_supervisor;
mod terminal_recovery;

pub use launcher::{
    backend_trust_environment, doctor_target, run_injected, target_backend, validate_target_runtime,
};
pub use pty::run_internal;
mod engine_control;

mod attachment;
mod attachment_permissions;
pub use attachment::{
    detach_attachment, inspect_attachment_target, reattach_attachment, run_attachment_manager,
    run_attachment_recovery,
};
pub use attachment_permissions::validate_attachment_backend;
