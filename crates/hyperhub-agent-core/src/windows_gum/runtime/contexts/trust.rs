use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::Security::Credentials::SecHandle;
use windows_sys::Win32::Security::Cryptography::{
    CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS,
    CERT_CONTEXT, HCERTCHAINENGINE, HCERTSTORE,
};

use windows_sys::Win32::Security::Authentication::Identity::{SCHANNEL_CRED, SCH_CREDENTIALS};
use windows_sys::Win32::Security::Cryptography::CertCloseStore;

pub(in crate::windows_gum) type CertGetChainFn = unsafe extern "system" fn(
    HCERTCHAINENGINE,
    *const CERT_CONTEXT,
    *const FILETIME,
    HCERTSTORE,
    *const CERT_CHAIN_PARA,
    u32,
    *const c_void,
    *mut *mut CERT_CHAIN_CONTEXT,
) -> i32;
pub(in crate::windows_gum) type CertVerifyPolicyFn = unsafe extern "system" fn(
    *const u8,
    *const CERT_CHAIN_CONTEXT,
    *const CERT_CHAIN_POLICY_PARA,
    *mut CERT_CHAIN_POLICY_STATUS,
) -> i32;
pub(in crate::windows_gum) type QueryContextAttributesFn =
    unsafe extern "system" fn(*mut SecHandle, u32, *mut c_void) -> i32;

pub(in crate::windows_gum) struct RootStoreContext {
    pub(in crate::windows_gum) store: HCERTSTORE,
}

pub(in crate::windows_gum) struct CertChainContext {
    pub(in crate::windows_gum) engine: HCERTCHAINENGINE,
    pub(in crate::windows_gum) certificate: *const CERT_CONTEXT,
    pub(in crate::windows_gum) time: *const FILETIME,
    additional_store: HCERTSTORE,
    pub(in crate::windows_gum) effective_additional_store: HCERTSTORE,
    pub(in crate::windows_gum) parameters: *const CERT_CHAIN_PARA,
    pub(in crate::windows_gum) flags: u32,
    pub(in crate::windows_gum) reserved: *const c_void,
    pub(in crate::windows_gum) chain: *mut *mut CERT_CHAIN_CONTEXT,
    pub(in crate::windows_gum) collection: HCERTSTORE,
    pub(in crate::windows_gum) result: i32,
}

impl CertChainContext {
    pub(in crate::windows_gum) fn additional_store(&self) -> HCERTSTORE {
        self.additional_store
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::windows_gum) fn new(
        engine: HCERTCHAINENGINE,
        certificate: *const CERT_CONTEXT,
        time: *const FILETIME,
        additional_store: HCERTSTORE,
        parameters: *const CERT_CHAIN_PARA,
        flags: u32,
        reserved: *const c_void,
        chain: *mut *mut CERT_CHAIN_CONTEXT,
    ) -> Self {
        Self {
            engine,
            certificate,
            time,
            additional_store,
            effective_additional_store: additional_store,
            parameters,
            flags,
            reserved,
            chain,
            collection: null_mut(),
            result: 0,
        }
    }
}

impl Drop for CertChainContext {
    fn drop(&mut self) {
        if !self.collection.is_null() {
            unsafe { CertCloseStore(self.collection, 0) };
            self.collection = null_mut();
        }
    }
}

pub(in crate::windows_gum) struct CertPolicyContext {
    pub(in crate::windows_gum) policy: *const u8,
    pub(in crate::windows_gum) chain: *const CERT_CHAIN_CONTEXT,
    pub(in crate::windows_gum) parameters: *const CERT_CHAIN_POLICY_PARA,
    pub(in crate::windows_gum) status: *mut CERT_CHAIN_POLICY_STATUS,
    pub(in crate::windows_gum) result: i32,
}

pub(in crate::windows_gum) enum CredentialAuthData {
    Original,
    Schannel(Box<SCHANNEL_CRED>),
    SchCredentials(Box<SCH_CREDENTIALS>),
}

pub(in crate::windows_gum) struct AcquireCredentialsContext {
    pub(in crate::windows_gum) package_is_schannel: bool,
    pub(in crate::windows_gum) auth_data: *mut c_void,
    pub(in crate::windows_gum) configured: CredentialAuthData,
}

impl AcquireCredentialsContext {
    pub(in crate::windows_gum) fn effective_auth_data(&mut self) -> *mut c_void {
        match &mut self.configured {
            CredentialAuthData::Original => self.auth_data,
            CredentialAuthData::Schannel(value) => (value.as_mut() as *mut SCHANNEL_CRED).cast(),
            CredentialAuthData::SchCredentials(value) => {
                (value.as_mut() as *mut SCH_CREDENTIALS).cast()
            }
        }
    }
}

pub(in crate::windows_gum) struct SchannelContext {
    pub(in crate::windows_gum) old_context: *mut SecHandle,
    pub(in crate::windows_gum) new_context: *mut SecHandle,
    pub(in crate::windows_gum) target: Option<Vec<u16>>,
    pub(in crate::windows_gum) query: Option<QueryContextAttributesFn>,
    pub(in crate::windows_gum) cert_get_chain: Option<CertGetChainFn>,
    pub(in crate::windows_gum) cert_verify_policy: Option<CertVerifyPolicyFn>,
    pub(in crate::windows_gum) result: i32,
}
