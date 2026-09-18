mod file;
pub(super) mod network;
mod process;

use crate::hook_runtime::HookError;
use crate::windows_gum::runtime::PluginRegistrar;

pub(in crate::windows_gum) fn register(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    network::register(registrar)?;
    process::register(registrar)?;
    file::register(registrar)
}
