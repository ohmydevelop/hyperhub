use std::collections::HashMap;
use std::ptr::{null, null_mut};
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::SEC_E_OK;
use windows_sys::Win32::Security::Authentication::Identity::SECPKG_ATTR_REMOTE_CERT_CONTEXT;
use windows_sys::Win32::Security::Credentials::SecHandle;
use windows_sys::Win32::Security::Cryptography::{
    szOID_PKIX_KP_SERVER_AUTH, CertAddCertificateContextToStore, CertAddStoreToCollection,
    CertCloseStore, CertCreateCertificateContext, CertEnumCertificatesInStore,
    CertFreeCertificateChain, CertFreeCertificateContext, CertOpenStore, CertOpenSystemStoreW,
    AUTHTYPE_SERVER, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_PARA,
    CERT_CHAIN_POLICY_SSL, CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT, CERT_STORE_ADD_ALWAYS,
    CERT_STORE_CREATE_NEW_FLAG, CERT_STORE_PROV_COLLECTION, CERT_STORE_PROV_MEMORY,
    CERT_TRUST_IS_UNTRUSTED_ROOT, HCERTSTORE, PKCS_7_ASN_ENCODING, USAGE_MATCH_TYPE_OR,
    X509_ASN_ENCODING,
};

use crate::windows_gum::runtime::{CertGetChainFn, CertVerifyPolicyFn, QueryContextAttributesFn};
use crate::{hh_agent_tls_ca_der, HH_ERR_BUFFER_TOO_SMALL, HH_OK};

#[repr(C)]
struct SslExtraCertChainPolicyPara {
    cb_size: u32,
    auth_type: u32,
    checks: u32,
    server_name: *mut u16,
}

type SchannelTargets = Mutex<HashMap<(usize, usize), Vec<u16>>>;
static HYPERHUB_ROOT_CONTEXT: OnceLock<usize> = OnceLock::new();
static HYPERHUB_ROOT_STORE: OnceLock<usize> = OnceLock::new();
static COMBINED_ROOT_STORE: OnceLock<usize> = OnceLock::new();
static SCHANNEL_TARGETS: OnceLock<SchannelTargets> = OnceLock::new();

pub(super) unsafe fn hyperhub_root_context() -> *const CERT_CONTEXT {
    *HYPERHUB_ROOT_CONTEXT.get_or_init(|| {
        let mut length = 0;
        if hh_agent_tls_ca_der(null_mut(), 0, &mut length) != HH_ERR_BUFFER_TOO_SMALL
            || length == 0
            || length > u32::MAX as usize
        {
            return 0;
        }
        let mut der = vec![0_u8; length];
        if hh_agent_tls_ca_der(der.as_mut_ptr(), der.len(), &mut length) != HH_OK {
            return 0;
        }
        CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.as_ptr(),
            length as u32,
        ) as usize
    }) as *const CERT_CONTEXT
}

pub(super) unsafe fn hyperhub_root_store() -> HCERTSTORE {
    *HYPERHUB_ROOT_STORE.get_or_init(|| {
        let root = hyperhub_root_context();
        if root.is_null() {
            return 0;
        }
        let store = CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            0,
            0,
            CERT_STORE_CREATE_NEW_FLAG,
            null(),
        );
        if store.is_null()
            || CertAddCertificateContextToStore(store, root, CERT_STORE_ADD_ALWAYS, null_mut()) == 0
        {
            if !store.is_null() {
                CertCloseStore(store, 0);
            }
            return 0;
        }
        store as usize
    }) as HCERTSTORE
}

pub(super) unsafe fn virtualize_root_store(system: HCERTSTORE) -> HCERTSTORE {
    if system.is_null() {
        return system;
    }
    let root = hyperhub_root_context();
    if root.is_null() {
        return system;
    }
    let private_store = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        0,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        null(),
    );
    if private_store.is_null() {
        return system;
    }

    let mut certificate: *const CERT_CONTEXT = null();
    loop {
        certificate = CertEnumCertificatesInStore(system, certificate);
        if certificate.is_null() {
            break;
        }
        if CertAddCertificateContextToStore(
            private_store,
            certificate,
            CERT_STORE_ADD_ALWAYS,
            null_mut(),
        ) == 0
        {
            CertCloseStore(private_store, 0);
            return system;
        }
    }
    if CertAddCertificateContextToStore(private_store, root, CERT_STORE_ADD_ALWAYS, null_mut()) == 0
    {
        CertCloseStore(private_store, 0);
        return system;
    }

    CertCloseStore(system, 0);
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
        eprintln!("hyperhub-gum: virtualized process-local ROOT certificate store");
    }
    private_store
}

pub(super) unsafe fn combined_root_store() -> HCERTSTORE {
    *COMBINED_ROOT_STORE.get_or_init(|| {
        const ROOT: [u16; 5] = [b'R' as u16, b'O' as u16, b'O' as u16, b'T' as u16, 0];
        let hyperhub = hyperhub_root_store();
        if hyperhub.is_null() {
            return 0;
        }
        let system = CertOpenSystemStoreW(0, ROOT.as_ptr());
        let collection = CertOpenStore(
            CERT_STORE_PROV_COLLECTION,
            0,
            0,
            CERT_STORE_CREATE_NEW_FLAG,
            null(),
        );
        if system.is_null() || collection.is_null() {
            if !system.is_null() {
                CertCloseStore(system, 0);
            }
            if !collection.is_null() {
                CertCloseStore(collection, 0);
            }
            return 0;
        }
        if CertAddStoreToCollection(collection, system, 0, 0) == 0
            || CertAddStoreToCollection(collection, hyperhub, 0, 0) == 0
        {
            CertCloseStore(collection, 0);
            CertCloseStore(system, 0);
            return 0;
        }
        // The collection and its sibling stores live for the Agent lifetime.
        collection as usize
    }) as HCERTSTORE
}

pub(super) unsafe fn chain_uses_hyperhub_root(chain: *const CERT_CHAIN_CONTEXT) -> bool {
    let root = hyperhub_root_context();
    if chain.is_null() || root.is_null() || (*chain).rgpChain.is_null() {
        return false;
    }
    let root_der =
        std::slice::from_raw_parts((*root).pbCertEncoded, (*root).cbCertEncoded as usize);
    for chain_index in 0..(*chain).cChain as usize {
        let simple = *(*chain).rgpChain.add(chain_index);
        if simple.is_null() || (*simple).cElement == 0 || (*simple).rgpElement.is_null() {
            continue;
        }
        let element = *(*simple).rgpElement.add((*simple).cElement as usize - 1);
        if element.is_null() || (*element).pCertContext.is_null() {
            continue;
        }
        let certificate = (*element).pCertContext;
        let certificate_der = std::slice::from_raw_parts(
            (*certificate).pbCertEncoded,
            (*certificate).cbCertEncoded as usize,
        );
        if certificate_der == root_der {
            return true;
        }
    }
    false
}

pub(super) unsafe fn trust_hyperhub_root_only(chain: *mut CERT_CHAIN_CONTEXT) {
    if !chain_uses_hyperhub_root(chain) {
        return;
    }
    (*chain).TrustStatus.dwErrorStatus &= !CERT_TRUST_IS_UNTRUSTED_ROOT;
    for chain_index in 0..(*chain).cChain as usize {
        let simple = *(*chain).rgpChain.add(chain_index);
        if simple.is_null() {
            continue;
        }
        (*simple).TrustStatus.dwErrorStatus &= !CERT_TRUST_IS_UNTRUSTED_ROOT;
        for element_index in 0..(*simple).cElement as usize {
            let element = *(*simple).rgpElement.add(element_index);
            if !element.is_null() {
                (*element).TrustStatus.dwErrorStatus &= !CERT_TRUST_IS_UNTRUSTED_ROOT;
            }
        }
    }
}

pub(super) fn schannel_targets() -> &'static Mutex<HashMap<(usize, usize), Vec<u16>>> {
    SCHANNEL_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) unsafe fn context_key(context: *mut SecHandle) -> Option<(usize, usize)> {
    (!context.is_null()).then(|| ((*context).dwLower, (*context).dwUpper))
}

pub(super) unsafe fn target_for_context(
    old_context: *mut SecHandle,
    supplied: Option<Vec<u16>>,
) -> Option<Vec<u16>> {
    if supplied.is_some() {
        return supplied;
    }
    let key = context_key(old_context)?;
    schannel_targets().lock().ok()?.get(&key).cloned()
}

pub(super) unsafe fn remember_context_target(context: *mut SecHandle, target: &[u16]) {
    if let Some(key) = context_key(context) {
        if let Ok(mut targets) = schannel_targets().lock() {
            targets.insert(key, target.to_vec());
        }
    }
}

pub(super) unsafe fn validate_schannel_peer(
    context: *mut SecHandle,
    target: &mut [u16],
    query: QueryContextAttributesFn,
    get_chain: CertGetChainFn,
    verify_policy: CertVerifyPolicyFn,
) -> bool {
    let root_store = combined_root_store();
    if context.is_null() || target.is_empty() || root_store.is_null() {
        return false;
    }

    let mut certificate: *mut CERT_CONTEXT = null_mut();
    if query(
        context,
        SECPKG_ATTR_REMOTE_CERT_CONTEXT,
        (&mut certificate as *mut *mut CERT_CONTEXT).cast(),
    ) != SEC_E_OK
        || certificate.is_null()
    {
        return false;
    }

    let mut server_auth = szOID_PKIX_KP_SERVER_AUTH.cast_mut();
    let mut chain_parameters = CERT_CHAIN_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    chain_parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chain_parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
    chain_parameters.RequestedUsage.Usage.rgpszUsageIdentifier = &mut server_auth;
    let mut chain: *mut CERT_CHAIN_CONTEXT = null_mut();
    let built = get_chain(
        null_mut(),
        certificate,
        null(),
        root_store,
        &chain_parameters,
        0,
        null(),
        &mut chain,
    );
    CertFreeCertificateContext(certificate);
    if built == 0 || chain.is_null() {
        return false;
    }

    trust_hyperhub_root_only(chain);
    if (*chain).TrustStatus.dwErrorStatus != 0 {
        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
            eprintln!(
                "hyperhub-gum: Schannel chain rejected trust=0x{:08x}",
                (*chain).TrustStatus.dwErrorStatus
            );
        }
        CertFreeCertificateChain(chain);
        return false;
    }

    let mut ssl = SslExtraCertChainPolicyPara {
        cb_size: std::mem::size_of::<SslExtraCertChainPolicyPara>() as u32,
        auth_type: AUTHTYPE_SERVER,
        checks: 0,
        server_name: target.as_mut_ptr(),
    };
    let policy_parameters = CERT_CHAIN_POLICY_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
        pvExtraPolicyPara: (&mut ssl as *mut SslExtraCertChainPolicyPara).cast(),
        ..Default::default()
    };
    let mut status = CERT_CHAIN_POLICY_STATUS {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
        ..Default::default()
    };
    let verified = verify_policy(
        CERT_CHAIN_POLICY_SSL,
        chain,
        &policy_parameters,
        &mut status,
    );
    CertFreeCertificateChain(chain);
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
        eprintln!(
            "hyperhub-gum: Schannel manual validation result={} error=0x{:08x}",
            verified, status.dwError
        );
    }
    verified != 0 && status.dwError == 0
}
