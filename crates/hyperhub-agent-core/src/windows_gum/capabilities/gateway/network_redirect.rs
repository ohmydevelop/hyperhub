use std::ffi::CString;
use std::sync::Arc;

use windows_sys::Win32::Networking::WinSock::FIONBIO;

use crate::hook_runtime::{AgentHookPlugin, CallbackCategory, HookDecision, HookError};
use crate::windows_gum::runtime::{ConnectKind, PluginRegistrar};
use crate::{hh_agent_close_socket, hh_agent_note_nonblocking};

const SOCKET_ERROR: i32 = -1;

struct NetworkRedirectPlugin;

impl AgentHookPlugin for NetworkRedirectPlugin {
    fn id(&self) -> &'static str {
        "network-redirect"
    }
}

pub(crate) fn register(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    let plugin = Arc::new(NetworkRedirectPlugin);
    let plugin_id = plugin.id();

    registrar.dns_before(plugin_id, CallbackCategory::Transform, |context| {
        let hostname = CString::new(context.hostname.as_str())
            .map_err(|_| HookError::new("DNS hostname contains an interior NUL"))?;
        context.replacement = super::network::resolve_fake_hostname(&hostname, context.family);
        if context.replacement.is_some() {
            Ok(HookDecision::Continue)
        } else {
            Ok(HookDecision::Deny(()))
        }
    });
    registrar.connect_before(plugin_id, CallbackCategory::Transform, |context| {
        if let Some((family, target)) =
            super::network::proxy_target(context.socket, context.source_family(), context.source())
        {
            context.redirect_to_proxy(family, target);
        }
        Ok(HookDecision::Continue)
    });
    registrar.connect_after(plugin_id, CallbackCategory::Control, |context, _result| {
        context.ensure_handshake_blocking =
            matches!(context.kind, ConnectKind::Blocking) && context.is_proxy_redirected();
        Ok(HookDecision::Continue)
    });
    registrar.socket_io_before(plugin_id, CallbackCategory::Control, |context| {
        let _ = context.direction;
        context.ensure_gateway_handshake = true;
        Ok(HookDecision::Continue)
    });
    registrar.socket_close_before(plugin_id, CallbackCategory::Observe, |context| {
        hh_agent_close_socket(context.socket as u64);
        Ok(HookDecision::Continue)
    });
    registrar.socket_mode_after(plugin_id, CallbackCategory::Observe, |context, result| {
        if *result != SOCKET_ERROR && context.command == FIONBIO && !context.argument.is_null() {
            unsafe {
                hh_agent_note_nonblocking(context.socket as u64, u32::from(*context.argument != 0))
            };
        }
        Ok(HookDecision::Continue)
    });

    registrar.retain_plugin(plugin)
}
