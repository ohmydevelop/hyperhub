use super::trust_service::{
    chain_uses_hyperhub_root, combined_root_store, hyperhub_root_store, remember_context_target,
    target_for_context, trust_hyperhub_root_only, validate_schannel_peer, virtualize_root_store,
};
use crate::hook_runtime::{AgentHookPlugin, CallbackCategory, HookDecision, HookError};
use crate::windows_gum::runtime::{CredentialAuthData, PluginRegistrar};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use windows_sys::Win32::Foundation::{CERT_E_UNTRUSTEDROOT, SEC_E_CERT_UNKNOWN, SEC_E_OK};
use windows_sys::Win32::Security::Authentication::Identity::{
    SCHANNEL_CRED, SCHANNEL_CRED_VERSION, SCH_CREDENTIALS, SCH_CREDENTIALS_VERSION,
    SCH_CRED_AUTO_CRED_VALIDATION, SCH_CRED_MANUAL_CRED_VALIDATION,
};
use windows_sys::Win32::Security::Cryptography::{
    CertAddStoreToCollection, CertCloseStore, CertOpenStore, CERT_STORE_CREATE_NEW_FLAG,
    CERT_STORE_PROV_COLLECTION,
};

struct CaTrustPlugin;

impl AgentHookPlugin for CaTrustPlugin {
    fn id(&self) -> &'static str {
        "ca-trust"
    }
}

pub(crate) fn register(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    let plugin = Arc::new(CaTrustPlugin);
    let plugin_id = plugin.id();

    registrar.root_store_after(plugin_id, CallbackCategory::Transform, |context, result| {
        context.store = *result;
        let store = unsafe { virtualize_root_store(*result) };
        Ok(HookDecision::Return(store))
    });
    registrar.cert_chain_before(plugin_id, CallbackCategory::Transform, |context| {
        let root_store = unsafe { hyperhub_root_store() };
        if root_store.is_null() {
            return Ok(HookDecision::Continue);
        }
        let collection = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_COLLECTION,
                0,
                0,
                CERT_STORE_CREATE_NEW_FLAG,
                null(),
            )
        };
        if collection.is_null() {
            return Ok(HookDecision::Continue);
        }
        unsafe {
            CertAddStoreToCollection(collection, root_store, 0, 0);
            if !context.additional_store().is_null() {
                CertAddStoreToCollection(collection, context.additional_store(), 0, 0);
            }
        }
        context.collection = collection;
        context.effective_additional_store = collection;
        Ok(HookDecision::Continue)
    });
    registrar.cert_chain_after(plugin_id, CallbackCategory::Transform, |context, result| {
        context.result = *result;
        if !context.collection.is_null() {
            unsafe { CertCloseStore(context.collection, 0) };
            context.collection = null_mut();
        }
        if context.result != 0 && !context.chain.is_null() && unsafe { !(*context.chain).is_null() }
        {
            unsafe { trust_hyperhub_root_only(*context.chain) };
            if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
                unsafe {
                    eprintln!(
                        "hyperhub-gum: CertGetCertificateChain trust=0x{:08x} hyperhub_root={}",
                        (**context.chain).TrustStatus.dwErrorStatus,
                        chain_uses_hyperhub_root(*context.chain)
                    );
                }
            }
        }
        Ok(HookDecision::Continue)
    });
    registrar.cert_policy_after(plugin_id, CallbackCategory::Transform, |context, result| {
        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() && !context.status.is_null() {
            unsafe {
                eprintln!(
                    "hyperhub-gum: CertVerifyCertificateChainPolicy error=0x{:08x} hyperhub_root={}",
                    (*context.status).dwError,
                    chain_uses_hyperhub_root(context.chain)
                );
            }
        }
        context.result = *result;
        if *result != 0
            && !context.status.is_null()
            && unsafe { (*context.status).dwError == CERT_E_UNTRUSTEDROOT as u32 }
            && unsafe { chain_uses_hyperhub_root(context.chain) }
        {
            unsafe {
                (*context.status).dwError = 0;
                (*context.status).lChainIndex = -1;
                (*context.status).lElementIndex = -1;
            }
        }
        Ok(HookDecision::Continue)
    });
    registrar.acquire_credentials_before(plugin_id, CallbackCategory::Transform, |context| {
        let root_store = unsafe { combined_root_store() };
        if context.auth_data.is_null() || root_store.is_null() || !context.package_is_schannel {
            return Ok(HookDecision::Continue);
        }
        let version = unsafe { *(context.auth_data as *const u32) };
        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
            eprintln!("hyperhub-gum: AcquireCredentialsHandle version={version}");
        }
        if version == SCHANNEL_CRED_VERSION {
            let mut configured = unsafe { *(context.auth_data as *const SCHANNEL_CRED) };
            configured.hRootStore = root_store;
            configured.dwFlags &= !SCH_CRED_AUTO_CRED_VALIDATION;
            configured.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
            context.configured = CredentialAuthData::Schannel(Box::new(configured));
        } else if version == SCH_CREDENTIALS_VERSION {
            let mut configured = unsafe { *(context.auth_data as *const SCH_CREDENTIALS) };
            configured.hRootStore = root_store;
            configured.dwFlags &= !SCH_CRED_AUTO_CRED_VALIDATION;
            configured.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
            context.configured = CredentialAuthData::SchCredentials(Box::new(configured));
        }
        Ok(HookDecision::Continue)
    });
    registrar.schannel_before(plugin_id, CallbackCategory::Observe, |context| {
        context.target = unsafe { target_for_context(context.old_context, context.target.take()) };
        Ok(HookDecision::Continue)
    });
    registrar.schannel_after(plugin_id, CallbackCategory::Control, |context, result| {
        context.result = *result;
        let active_context = if context.new_context.is_null() {
            context.old_context
        } else {
            context.new_context
        };
        if let Some(target) = context.target.as_deref() {
            unsafe { remember_context_target(active_context, target) };
        }
        if *result != SEC_E_OK {
            return Ok(HookDecision::Continue);
        }
        let Some(query) = context.query else {
            return Ok(HookDecision::Deny(SEC_E_CERT_UNKNOWN));
        };
        let (Some(get_chain), Some(verify_policy)) =
            (context.cert_get_chain, context.cert_verify_policy)
        else {
            return Ok(HookDecision::Deny(SEC_E_CERT_UNKNOWN));
        };
        if !context.target.as_mut().is_some_and(|target| unsafe {
            validate_schannel_peer(active_context, target, query, get_chain, verify_policy)
        }) {
            return Ok(HookDecision::Deny(SEC_E_CERT_UNKNOWN));
        }
        Ok(HookDecision::Continue)
    });

    registrar.retain_plugin(plugin)
}
