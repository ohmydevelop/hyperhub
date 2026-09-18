use std::sync::Arc;

use windows_sys::Win32::Security::Cryptography::HCERTSTORE;

use crate::hook_runtime::{
    AgentHookPlugin, CallbackCategory, HookError, HookFailureMode, HookPointBuilder,
};

use super::contexts::*;
use super::PluginRuntime;

pub(in crate::windows_gum) struct PluginRegistrar {
    plugins: Vec<Arc<dyn AgentHookPlugin>>,
    dns: HookPointBuilder<DnsContext, ()>,
    connect: HookPointBuilder<ConnectContext, i32>,
    socket_io: HookPointBuilder<SocketIoContext, i32>,
    socket_close: HookPointBuilder<SocketCloseContext, i32>,
    socket_mode: HookPointBuilder<SocketModeContext, i32>,
    root_store: HookPointBuilder<RootStoreContext, HCERTSTORE>,
    cert_chain: HookPointBuilder<CertChainContext, i32>,
    cert_policy: HookPointBuilder<CertPolicyContext, i32>,
    acquire_credentials: HookPointBuilder<AcquireCredentialsContext, i32>,
    schannel: HookPointBuilder<SchannelContext, i32>,
    process_create: HookPointBuilder<ProcessCreateContext, i32>,
    file_operation: HookPointBuilder<FileOperationContext, i32>,
}

impl PluginRegistrar {
    pub(in crate::windows_gum) fn new() -> Self {
        Self {
            plugins: Vec::new(),
            dns: HookPointBuilder::new("dns.resolve", HookFailureMode::FailClosed),
            connect: HookPointBuilder::new("socket.connect", HookFailureMode::FailClosed),
            socket_io: HookPointBuilder::new("socket.io", HookFailureMode::FailClosed),
            socket_close: HookPointBuilder::new("socket.close", HookFailureMode::FailOpen),
            socket_mode: HookPointBuilder::new("socket.mode", HookFailureMode::FailOpen),
            root_store: HookPointBuilder::new("trust.root_store", HookFailureMode::FailClosed),
            cert_chain: HookPointBuilder::new("trust.cert_chain", HookFailureMode::FailClosed),
            cert_policy: HookPointBuilder::new("trust.cert_policy", HookFailureMode::FailClosed),
            acquire_credentials: HookPointBuilder::new(
                "trust.acquire_credentials",
                HookFailureMode::FailClosed,
            ),
            schannel: HookPointBuilder::new("trust.schannel", HookFailureMode::FailClosed),
            process_create: HookPointBuilder::new("process.create", HookFailureMode::FailClosed),
            file_operation: HookPointBuilder::new("file.operation", HookFailureMode::FailClosed),
        }
    }

    pub(in crate::windows_gum) fn dns_before_with_failure_mode<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        failure_mode: HookFailureMode,
        callback: F,
    ) where
        F: Fn(&mut DnsContext) -> crate::hook_runtime::HookCallbackResult<()>
            + Send
            + Sync
            + 'static,
    {
        self.dns
            .before_with_failure_mode(plugin, category, failure_mode, callback);
    }

    pub(in crate::windows_gum) fn dns_before<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut DnsContext) -> crate::hook_runtime::HookCallbackResult<()>
            + Send
            + Sync
            + 'static,
    {
        self.dns.before(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn connect_before_with_failure_mode<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        failure_mode: HookFailureMode,
        callback: F,
    ) where
        F: Fn(&mut ConnectContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.connect
            .before_with_failure_mode(plugin, category, failure_mode, callback);
    }

    pub(in crate::windows_gum) fn connect_before<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut ConnectContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.connect.before(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn connect_after<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut ConnectContext, &mut i32) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.connect.after(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn socket_io_before<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut SocketIoContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.socket_io.before(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn socket_close_before<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut SocketCloseContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.socket_close.before(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn socket_mode_after<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut SocketModeContext, &mut i32) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.socket_mode.after(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn root_store_after<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(
                &mut RootStoreContext,
                &mut HCERTSTORE,
            ) -> crate::hook_runtime::HookCallbackResult<HCERTSTORE>
            + Send
            + Sync
            + 'static,
    {
        self.root_store.after(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn cert_chain_before<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut CertChainContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.cert_chain.before(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn cert_chain_after<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut CertChainContext, &mut i32) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.cert_chain.after(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn cert_policy_after<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut CertPolicyContext, &mut i32) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.cert_policy.after(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn acquire_credentials_before<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut AcquireCredentialsContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.acquire_credentials.before(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn schannel_before<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut SchannelContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.schannel.before(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn schannel_after<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut SchannelContext, &mut i32) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.schannel.after(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn process_create_before_with_failure_mode_provider<F, P>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        failure_mode: HookFailureMode,
        provider: P,
        callback: F,
    ) where
        F: Fn(&mut ProcessCreateContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
        P: Fn() -> HookFailureMode + Send + Sync + 'static,
    {
        self.process_create.before_with_failure_mode_provider(
            plugin,
            category,
            failure_mode,
            provider,
            callback,
        );
    }

    pub(in crate::windows_gum) fn process_create_before<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut ProcessCreateContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.process_create.before(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn process_create_after<F>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut ProcessCreateContext, &mut i32) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
    {
        self.process_create.after(plugin, category, callback);
    }

    pub(in crate::windows_gum) fn file_operation_before_with_failure_mode_provider<F, P>(
        &mut self,
        plugin: &'static str,
        category: CallbackCategory,
        failure_mode: HookFailureMode,
        provider: P,
        callback: F,
    ) where
        F: Fn(&mut FileOperationContext) -> crate::hook_runtime::HookCallbackResult<i32>
            + Send
            + Sync
            + 'static,
        P: Fn() -> HookFailureMode + Send + Sync + 'static,
    {
        self.file_operation.before_with_failure_mode_provider(
            plugin,
            category,
            failure_mode,
            provider,
            callback,
        );
    }

    pub(in crate::windows_gum) fn retain_plugin<P>(
        &mut self,
        plugin: Arc<P>,
    ) -> Result<(), HookError>
    where
        P: AgentHookPlugin + 'static,
    {
        plugin.initialize()?;
        self.plugins.push(plugin);
        Ok(())
    }

    pub(in crate::windows_gum) fn freeze(self) -> PluginRuntime {
        PluginRuntime {
            plugins: self.plugins.into_boxed_slice(),
            dns: self.dns.freeze(),
            connect: self.connect.freeze(),
            socket_io: self.socket_io.freeze(),
            socket_close: self.socket_close.freeze(),
            socket_mode: self.socket_mode.freeze(),
            root_store: self.root_store.freeze(),
            cert_chain: self.cert_chain.freeze(),
            cert_policy: self.cert_policy.freeze(),
            acquire_credentials: self.acquire_credentials.freeze(),
            schannel: self.schannel.freeze(),
            process_create: self.process_create.freeze(),
            file_operation: self.file_operation.freeze(),
        }
    }
}
