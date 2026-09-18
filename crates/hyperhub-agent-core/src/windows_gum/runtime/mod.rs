use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, OnceLock};

use windows_sys::Win32::Security::Cryptography::HCERTSTORE;

use crate::hook_runtime::{AgentHookPlugin, HookError, HookPoint, HookPointManifest};

use super::capabilities;
use super::manager;

mod contexts;
mod registrar;

pub(in crate::windows_gum) use contexts::*;
pub(in crate::windows_gum) use registrar::PluginRegistrar;

pub(in crate::windows_gum) struct PluginRuntime {
    plugins: Box<[Arc<dyn AgentHookPlugin>]>,
    pub(in crate::windows_gum) dns: HookPoint<DnsContext, ()>,
    pub(in crate::windows_gum) connect: HookPoint<ConnectContext, i32>,
    pub(in crate::windows_gum) socket_io: HookPoint<SocketIoContext, i32>,
    pub(in crate::windows_gum) socket_close: HookPoint<SocketCloseContext, i32>,
    pub(in crate::windows_gum) socket_mode: HookPoint<SocketModeContext, i32>,
    pub(in crate::windows_gum) root_store: HookPoint<RootStoreContext, HCERTSTORE>,
    pub(in crate::windows_gum) cert_chain: HookPoint<CertChainContext, i32>,
    pub(in crate::windows_gum) cert_policy: HookPoint<CertPolicyContext, i32>,
    pub(in crate::windows_gum) acquire_credentials: HookPoint<AcquireCredentialsContext, i32>,
    pub(in crate::windows_gum) schannel: HookPoint<SchannelContext, i32>,
    pub(in crate::windows_gum) process_create: HookPoint<ProcessCreateContext, i32>,
    pub(in crate::windows_gum) file_operation: HookPoint<FileOperationContext, i32>,
}

impl PluginRuntime {
    pub(in crate::windows_gum) fn manifest(&self) -> PluginRuntimeManifest {
        PluginRuntimeManifest {
            plugins: self.plugins.iter().map(|plugin| plugin.id()).collect(),
            hooks: vec![
                self.dns.manifest(),
                self.connect.manifest(),
                self.socket_io.manifest(),
                self.socket_close.manifest(),
                self.socket_mode.manifest(),
                self.root_store.manifest(),
                self.cert_chain.manifest(),
                self.cert_policy.manifest(),
                self.acquire_credentials.manifest(),
                self.schannel.manifest(),
                self.process_create.manifest(),
                self.file_operation.manifest(),
            ],
        }
    }
}

impl Drop for PluginRuntime {
    fn drop(&mut self) {
        for plugin in self.plugins.iter().rev() {
            plugin.shutdown();
        }
    }
}

#[derive(Debug)]
pub(in crate::windows_gum) struct PluginRuntimeManifest {
    pub(in crate::windows_gum) plugins: Vec<&'static str>,
    pub(in crate::windows_gum) hooks: Vec<HookPointManifest>,
}

#[derive(Debug)]
pub(in crate::windows_gum) struct AgentHookRuntimeManifest {
    pub(in crate::windows_gum) native_hooks: Vec<manager::HookInstallEntry>,
    pub(in crate::windows_gum) plugins: Vec<&'static str>,
    pub(in crate::windows_gum) semantic_hooks: Vec<HookPointManifest>,
}

static PLUGIN_RUNTIME: AtomicPtr<PluginRuntime> = AtomicPtr::new(null_mut());
static AGENT_HOOK_MANIFEST: OnceLock<AgentHookRuntimeManifest> = OnceLock::new();

pub(in crate::windows_gum) fn initialize_builtin_plugins() -> Result<(), HookError> {
    let mut registrar = PluginRegistrar::new();
    register_builtin_plugins(&mut registrar)?;
    let runtime = Box::into_raw(Box::new(registrar.freeze()));
    if PLUGIN_RUNTIME
        .compare_exchange(null_mut(), runtime, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // SAFETY: compare_exchange failed, so no callback can have observed this allocation.
        unsafe { drop(Box::from_raw(runtime)) };
        return Err(HookError::new("plugin runtime was already initialized"));
    }
    Ok(())
}

pub(in crate::windows_gum) fn rebuild_builtin_plugins_after_fork() -> Result<(), HookError> {
    let mut registrar = PluginRegistrar::new();
    register_builtin_plugins(&mut registrar)?;
    let runtime = Box::into_raw(Box::new(registrar.freeze()));
    let _copied_runtime = PLUGIN_RUNTIME.swap(runtime, Ordering::AcqRel);
    // The copied parent runtime is intentionally not dropped: its synchronization primitives and
    // worker handles describe threads that do not exist in the fork child.
    Ok(())
}

fn register_builtin_plugins(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    capabilities::sandbox::register(registrar)?;
    capabilities::gateway::register(registrar)?;
    capabilities::lifecycle::register(registrar)
}

pub(in crate::windows_gum) fn publish_runtime_manifest(
    report: &manager::HookInstallReport,
) -> Result<(), HookError> {
    let plugin_manifest = runtime().manifest();
    AGENT_HOOK_MANIFEST
        .set(AgentHookRuntimeManifest {
            native_hooks: report.hooks.clone(),
            plugins: plugin_manifest.plugins,
            semantic_hooks: plugin_manifest.hooks,
        })
        .map_err(|_| HookError::new("hook runtime manifest was already published"))
}

pub(in crate::windows_gum) fn runtime_manifest() -> &'static AgentHookRuntimeManifest {
    AGENT_HOOK_MANIFEST
        .get()
        .expect("hook runtime manifest must be published after hook installation")
}

pub(in crate::windows_gum) fn runtime() -> &'static PluginRuntime {
    let pointer = PLUGIN_RUNTIME.load(Ordering::Acquire);
    assert!(
        !pointer.is_null(),
        "plugin runtime must be initialized before hooks are installed"
    );
    // SAFETY: published runtimes remain allocated for the process lifetime. Post-fork replacement
    // intentionally leaks the copied parent instance so in-flight callbacks cannot use freed data.
    unsafe { &*pointer }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook_runtime::HookFailureMode;
    use crate::windows_gum::{
        CREATE_PROCESS_A, CREATE_PROCESS_INTERNAL_A, CREATE_PROCESS_INTERNAL_W, CREATE_PROCESS_W,
        NT_CREATE_USER_PROCESS, SOCKET_ERROR,
    };

    fn builtin_manifest() -> PluginRuntimeManifest {
        let mut registrar = PluginRegistrar::new();
        register_builtin_plugins(&mut registrar).expect("register built-in plugins");
        registrar.freeze().manifest()
    }

    #[test]
    fn freezing_registry_preserves_plugin_and_callback_order() {
        let first = builtin_manifest();
        let second = builtin_manifest();

        assert_eq!(
            first.plugins,
            [
                "firewall",
                "process-sandbox",
                "file-sandbox",
                "network-redirect",
                "ca-trust",
                "child-process"
            ]
        );
        assert_eq!(first.plugins, second.plugins);
        let dns = first
            .hooks
            .iter()
            .find(|hook| hook.name == "dns.resolve")
            .unwrap();
        assert_eq!(dns.before[0].plugin_id, "firewall");
        assert_eq!(dns.before[0].failure_mode, HookFailureMode::FailOpen);
        let connect = first
            .hooks
            .iter()
            .find(|hook| hook.name == "socket.connect")
            .unwrap();
        assert_eq!(
            connect
                .before
                .iter()
                .map(|callback| callback.plugin_id)
                .collect::<Vec<_>>(),
            ["firewall", "network-redirect"]
        );
        assert_eq!(
            first.hooks.iter().map(|hook| hook.name).collect::<Vec<_>>(),
            second
                .hooks
                .iter()
                .map(|hook| hook.name)
                .collect::<Vec<_>>()
        );
        for (left, right) in first.hooks.iter().zip(&second.hooks) {
            assert_eq!(left.before, right.before);
            assert_eq!(left.after, right.after);
        }
    }

    #[test]
    fn connect_denial_result_matches_the_native_adapter_kind() {
        let blocking = ConnectContext::new(ConnectKind::Blocking, 0, None, None);
        assert_eq!(blocking.denied_result(), SOCKET_ERROR);
        let extended = ConnectContext::new(ConnectKind::Extended, 0, None, None);
        assert_eq!(extended.denied_result(), 0);
    }

    #[test]
    fn all_child_creation_adapters_share_one_semantic_chain() {
        let manifest = builtin_manifest();
        let process_hooks = manifest
            .hooks
            .iter()
            .filter(|hook| hook.name == "process.create")
            .collect::<Vec<_>>();
        assert_eq!(process_hooks.len(), 1);
        assert_eq!(process_hooks[0].before[0].plugin_id, "process-sandbox");
        assert_eq!(process_hooks[0].before[1].plugin_id, "child-process");
        assert_eq!(process_hooks[0].after[0].plugin_id, "child-process");

        let native_process_hooks = manager::BUILTIN_HOOKS
            .iter()
            .filter(|hook| {
                matches!(
                    hook.id,
                    CREATE_PROCESS_A
                        | CREATE_PROCESS_W
                        | CREATE_PROCESS_INTERNAL_A
                        | CREATE_PROCESS_INTERNAL_W
                        | NT_CREATE_USER_PROCESS
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(native_process_hooks.len(), 5);
        assert!(native_process_hooks
            .iter()
            .all(|hook| hook.semantic_hook == "process.create"));
    }
}
