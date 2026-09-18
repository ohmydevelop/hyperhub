use windows_sys::Win32::Networking::WinSock::SOCKET;

use crate::hook_runtime::HookDecision;
use crate::windows_gum::SOCKET_ERROR;

pub(in crate::windows_gum) struct DnsContext {
    pub(in crate::windows_gum) hostname: String,
    pub(in crate::windows_gum) family: i32,
    pub(in crate::windows_gum) replacement: Option<(String, i32)>,
    pub(in crate::windows_gum) denied_error: Option<i32>,
}

impl DnsContext {
    pub(in crate::windows_gum) fn deny(&mut self, error: i32) -> HookDecision<()> {
        self.denied_error = Some(error);
        HookDecision::Deny(())
    }
}

#[derive(Clone, Copy)]
pub(in crate::windows_gum) enum ConnectKind {
    Blocking,
    Extended,
}

pub(in crate::windows_gum) struct ConnectContext {
    pub(in crate::windows_gum) kind: ConnectKind,
    pub(in crate::windows_gum) socket: SOCKET,
    source_family: Option<i32>,
    destination_family: Option<i32>,
    proxy_redirected: bool,
    source: Option<crate::FirewallConnectTarget>,
    destination: Option<crate::FirewallConnectTarget>,
    pub(in crate::windows_gum) ensure_handshake_blocking: bool,
    pub(in crate::windows_gum) denied_error: Option<i32>,
    pub(in crate::windows_gum) result: i32,
    pub(in crate::windows_gum) error: i32,
}

impl ConnectContext {
    pub(in crate::windows_gum) fn new(
        kind: ConnectKind,
        socket: SOCKET,
        source_family: Option<i32>,
        source: Option<crate::FirewallConnectTarget>,
    ) -> Self {
        Self {
            kind,
            socket,
            source_family,
            destination_family: source_family,
            proxy_redirected: false,
            destination: source.clone(),
            source,
            ensure_handshake_blocking: false,
            denied_error: None,
            result: SOCKET_ERROR,
            error: 0,
        }
    }

    pub(in crate::windows_gum) fn source_family(&self) -> Option<i32> {
        self.source_family
    }

    pub(in crate::windows_gum) fn source(&self) -> Option<&crate::FirewallConnectTarget> {
        self.source.as_ref()
    }

    pub(in crate::windows_gum) fn destination(&self) -> Option<&crate::FirewallConnectTarget> {
        self.destination.as_ref()
    }

    pub(in crate::windows_gum) fn redirect_to_proxy(
        &mut self,
        family: i32,
        target: crate::FirewallConnectTarget,
    ) {
        self.destination_family = Some(family);
        self.destination = Some(target);
        self.proxy_redirected = true;
    }

    pub(in crate::windows_gum) fn is_proxy_redirected(&self) -> bool {
        self.proxy_redirected
    }

    pub(in crate::windows_gum) fn deny(&mut self, error: i32) -> HookDecision<i32> {
        self.denied_error = Some(error);
        HookDecision::Deny(self.denied_result())
    }

    pub(in crate::windows_gum) fn denied_result(&self) -> i32 {
        match self.kind {
            ConnectKind::Blocking => SOCKET_ERROR,
            ConnectKind::Extended => 0,
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::windows_gum) enum SocketIoDirection {
    Send,
    Receive,
}

pub(in crate::windows_gum) struct SocketIoContext {
    pub(in crate::windows_gum) socket: SOCKET,
    pub(in crate::windows_gum) direction: SocketIoDirection,
    pub(in crate::windows_gum) ensure_gateway_handshake: bool,
}

pub(in crate::windows_gum) struct SocketCloseContext {
    pub(in crate::windows_gum) socket: SOCKET,
    pub(in crate::windows_gum) result: i32,
}

pub(in crate::windows_gum) struct SocketModeContext {
    pub(in crate::windows_gum) socket: SOCKET,
    pub(in crate::windows_gum) command: i32,
    pub(in crate::windows_gum) argument: *mut u32,
    pub(in crate::windows_gum) result: i32,
}
