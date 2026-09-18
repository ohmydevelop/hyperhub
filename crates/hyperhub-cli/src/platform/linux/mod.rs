mod frida_core;
mod hook_manifest;
mod launcher;
mod pty;
mod syscall_supervisor;

pub use launcher::{doctor_target, run_injected, target_backend, validate_target_runtime};
pub use pty::run_internal;
