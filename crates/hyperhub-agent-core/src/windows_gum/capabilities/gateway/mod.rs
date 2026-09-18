pub(super) mod ca_trust;
mod network;
pub(super) mod network_redirect;
mod trust_service;

use crate::hook_runtime::HookError;
use crate::windows_gum::runtime::PluginRegistrar;

pub(in crate::windows_gum) fn register(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    network_redirect::register(registrar)?;
    ca_trust::register(registrar)
}
