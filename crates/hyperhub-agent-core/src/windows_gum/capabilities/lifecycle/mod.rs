pub(super) mod child_process;
mod windows;

pub(in crate::windows_gum) use windows::inject_fork_candidate;
pub(crate) use windows::{agent_module_path, inherited_child_event_name};

use crate::hook_runtime::HookError;
use crate::windows_gum::runtime::PluginRegistrar;

pub(in crate::windows_gum) fn register(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    child_process::register(registrar)
}
