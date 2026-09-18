use super::network::wide_string;
use crate::windows_gum::gum::{hook_result, original, HookGuard, INSIDE_HOOK};
use crate::windows_gum::runtime::{CertGetChainFn, CertVerifyPolicyFn, QueryContextAttributesFn};
use crate::windows_gum::shared::*;
pub(in crate::windows_gum) type CertOpenSystemStoreAFn =
    unsafe extern "system" fn(usize, *const u8) -> HCERTSTORE;
pub(in crate::windows_gum) type CertOpenSystemStoreWFn =
    unsafe extern "system" fn(usize, *const u16) -> HCERTSTORE;
pub(in crate::windows_gum) type AcquireCredentialsAFn = unsafe extern "system" fn(
    *mut i8,
    *mut i8,
    u32,
    *mut c_void,
    *mut c_void,
    SEC_GET_KEY_FN,
    *mut c_void,
    *mut SecHandle,
    *mut i64,
) -> i32;
pub(in crate::windows_gum) type AcquireCredentialsWFn = unsafe extern "system" fn(
    *mut u16,
    *mut u16,
    u32,
    *mut c_void,
    *mut c_void,
    SEC_GET_KEY_FN,
    *mut c_void,
    *mut SecHandle,
    *mut i64,
) -> i32;
pub(in crate::windows_gum) type InitializeSecurityContextAFn = unsafe extern "system" fn(
    *mut SecHandle,
    *mut SecHandle,
    *mut i8,
    u32,
    u32,
    u32,
    *mut SecBufferDesc,
    u32,
    *mut SecHandle,
    *mut SecBufferDesc,
    *mut u32,
    *mut i64,
) -> i32;
pub(in crate::windows_gum) type InitializeSecurityContextWFn = unsafe extern "system" fn(
    *mut SecHandle,
    *mut SecHandle,
    *mut u16,
    u32,
    u32,
    u32,
    *mut SecBufferDesc,
    u32,
    *mut SecHandle,
    *mut SecBufferDesc,
    *mut u32,
    *mut i64,
) -> i32;
pub(in crate::windows_gum) static ORIGINAL_CERT_GET_CHAIN: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CERT_VERIFY_POLICY: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_ACQUIRE_CREDENTIALS_A: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_ACQUIRE_CREDENTIALS_W: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_INITIALIZE_SECURITY_CONTEXT_A: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_INITIALIZE_SECURITY_CONTEXT_W: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CERT_OPEN_SYSTEM_STORE_A: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static ORIGINAL_CERT_OPEN_SYSTEM_STORE_W: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static QUERY_CONTEXT_ATTRIBUTES_A: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());
pub(in crate::windows_gum) static QUERY_CONTEXT_ATTRIBUTES_W: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());

pub(in crate::windows_gum) unsafe fn is_root_store_name_a(name: *const u8) -> bool {
    !name.is_null()
        && (*name).eq_ignore_ascii_case(&b'R')
        && (*name.add(1)).eq_ignore_ascii_case(&b'O')
        && (*name.add(2)).eq_ignore_ascii_case(&b'O')
        && (*name.add(3)).eq_ignore_ascii_case(&b'T')
        && *name.add(4) == 0
}

pub(in crate::windows_gum) unsafe fn is_root_store_name_w(name: *const u16) -> bool {
    !name.is_null()
        && (*name == b'R' as u16 || *name == b'r' as u16)
        && (*name.add(1) == b'O' as u16 || *name.add(1) == b'o' as u16)
        && (*name.add(2) == b'O' as u16 || *name.add(2) == b'o' as u16)
        && (*name.add(3) == b'T' as u16 || *name.add(3) == b't' as u16)
        && *name.add(4) == 0
}

/// Build a private snapshot instead of adding HyperHub's root to a persistent
/// Windows certificate store. Consumers such as Go's crypto/x509 enumerate
/// this handle and therefore see the same system roots plus the session root.

pub(in crate::windows_gum) unsafe extern "system" fn hook_cert_open_system_store_a(
    provider: usize,
    subsystem: *const u8,
) -> HCERTSTORE {
    let Some(original) = original!(ORIGINAL_CERT_OPEN_SYSTEM_STORE_A, CertOpenSystemStoreAFn)
    else {
        return null_mut();
    };
    if INSIDE_HOOK.with(Cell::get) || !is_root_store_name_a(subsystem) {
        return original(provider, subsystem);
    }
    hook_result(
        None,
        || original(provider, subsystem),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(provider, subsystem);
            };
            let mut context = RootStoreContext { store: null_mut() };
            runtime().root_store.dispatch(
                &mut context,
                |context| {
                    context.store = original(provider, subsystem);
                    context.store
                },
                |_, _, _| null_mut(),
            )
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_cert_open_system_store_w(
    provider: usize,
    subsystem: *const u16,
) -> HCERTSTORE {
    let Some(original) = original!(ORIGINAL_CERT_OPEN_SYSTEM_STORE_W, CertOpenSystemStoreWFn)
    else {
        return null_mut();
    };
    if INSIDE_HOOK.with(Cell::get) || !is_root_store_name_w(subsystem) {
        return original(provider, subsystem);
    }
    hook_result(
        None,
        || original(provider, subsystem),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(provider, subsystem);
            };
            let mut context = RootStoreContext { store: null_mut() };
            runtime().root_store.dispatch(
                &mut context,
                |context| {
                    context.store = original(provider, subsystem);
                    context.store
                },
                |_, _, _| null_mut(),
            )
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_cert_get_chain(
    engine: HCERTCHAINENGINE,
    certificate: *const CERT_CONTEXT,
    time: *const FILETIME,
    additional_store: HCERTSTORE,
    parameters: *const CERT_CHAIN_PARA,
    flags: u32,
    reserved: *const c_void,
    chain: *mut *mut CERT_CHAIN_CONTEXT,
) -> i32 {
    let Some(original) = original!(ORIGINAL_CERT_GET_CHAIN, CertGetChainFn) else {
        return 0;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(
            engine,
            certificate,
            time,
            additional_store,
            parameters,
            flags,
            reserved,
            chain,
        );
    }
    hook_result(
        None,
        || {
            original(
                engine,
                certificate,
                time,
                additional_store,
                parameters,
                flags,
                reserved,
                chain,
            )
        },
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(
                    engine,
                    certificate,
                    time,
                    additional_store,
                    parameters,
                    flags,
                    reserved,
                    chain,
                );
            };
            let mut context = CertChainContext::new(
                engine,
                certificate,
                time,
                additional_store,
                parameters,
                flags,
                reserved,
                chain,
            );
            runtime().cert_chain.dispatch(
                &mut context,
                |context| {
                    context.result = original(
                        context.engine,
                        context.certificate,
                        context.time,
                        context.effective_additional_store,
                        context.parameters,
                        context.flags,
                        context.reserved,
                        context.chain,
                    );
                    context.result
                },
                |_, _, _| 0,
            )
        },
    )
}

pub(in crate::windows_gum) unsafe extern "system" fn hook_cert_verify_policy(
    policy: *const u8,
    chain: *const CERT_CHAIN_CONTEXT,
    parameters: *const CERT_CHAIN_POLICY_PARA,
    status: *mut CERT_CHAIN_POLICY_STATUS,
) -> i32 {
    let Some(original) = original!(ORIGINAL_CERT_VERIFY_POLICY, CertVerifyPolicyFn) else {
        return 0;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(policy, chain, parameters, status);
    }
    hook_result(
        None,
        || original(policy, chain, parameters, status),
        || {
            let Some(_guard) = HookGuard::enter() else {
                return original(policy, chain, parameters, status);
            };
            let mut context = CertPolicyContext {
                policy,
                chain,
                parameters,
                status,
                result: 0,
            };
            runtime().cert_policy.dispatch(
                &mut context,
                |context| {
                    context.result = original(
                        context.policy,
                        context.chain,
                        context.parameters,
                        context.status,
                    );
                    context.result
                },
                |_, _, _| 0,
            )
        },
    )
}

pub(in crate::windows_gum) unsafe fn is_schannel_package_a(package: *mut i8) -> bool {
    if package.is_null() {
        return false;
    }
    let name = CStr::from_ptr(package.cast::<c_char>())
        .to_string_lossy()
        .to_ascii_lowercase();
    name == "schannel" || name.contains("unified security protocol provider")
}

pub(in crate::windows_gum) unsafe fn is_schannel_package_w(package: *mut u16) -> bool {
    if package.is_null() {
        return false;
    }
    let name = wide_string(package).to_ascii_lowercase();
    name == "schannel" || name.contains("unified security protocol provider")
}

#[allow(clippy::too_many_arguments)]

pub(in crate::windows_gum) unsafe extern "system" fn hook_acquire_credentials_a(
    principal: *mut i8,
    package: *mut i8,
    credential_use: u32,
    logon_id: *mut c_void,
    auth_data: *mut c_void,
    get_key: SEC_GET_KEY_FN,
    get_key_argument: *mut c_void,
    credential: *mut SecHandle,
    expiry: *mut i64,
) -> i32 {
    let Some(original) = original!(ORIGINAL_ACQUIRE_CREDENTIALS_A, AcquireCredentialsAFn) else {
        return -1;
    };
    hook_result(
        None,
        || {
            original(
                principal,
                package,
                credential_use,
                logon_id,
                auth_data,
                get_key,
                get_key_argument,
                credential,
                expiry,
            )
        },
        || {
            let mut context = AcquireCredentialsContext {
                package_is_schannel: is_schannel_package_a(package),
                auth_data,
                configured: CredentialAuthData::Original,
            };
            runtime().acquire_credentials.dispatch(
                &mut context,
                |context| {
                    original(
                        principal,
                        package,
                        credential_use,
                        logon_id,
                        context.effective_auth_data(),
                        get_key,
                        get_key_argument,
                        credential,
                        expiry,
                    )
                },
                |_, _, _| -1,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]

pub(in crate::windows_gum) unsafe extern "system" fn hook_acquire_credentials_w(
    principal: *mut u16,
    package: *mut u16,
    credential_use: u32,
    logon_id: *mut c_void,
    auth_data: *mut c_void,
    get_key: SEC_GET_KEY_FN,
    get_key_argument: *mut c_void,
    credential: *mut SecHandle,
    expiry: *mut i64,
) -> i32 {
    let Some(original) = original!(ORIGINAL_ACQUIRE_CREDENTIALS_W, AcquireCredentialsWFn) else {
        return -1;
    };
    hook_result(
        None,
        || {
            original(
                principal,
                package,
                credential_use,
                logon_id,
                auth_data,
                get_key,
                get_key_argument,
                credential,
                expiry,
            )
        },
        || {
            let mut context = AcquireCredentialsContext {
                package_is_schannel: is_schannel_package_w(package),
                auth_data,
                configured: CredentialAuthData::Original,
            };
            runtime().acquire_credentials.dispatch(
                &mut context,
                |context| {
                    original(
                        principal,
                        package,
                        credential_use,
                        logon_id,
                        context.effective_auth_data(),
                        get_key,
                        get_key_argument,
                        credential,
                        expiry,
                    )
                },
                |_, _, _| -1,
            )
        },
    )
}

pub(in crate::windows_gum) unsafe fn supplied_target_a(target: *mut i8) -> Option<Vec<u16>> {
    if target.is_null() {
        return None;
    }
    let mut wide: Vec<u16> = CStr::from_ptr(target.cast())
        .to_string_lossy()
        .encode_utf16()
        .collect();
    wide.push(0);
    Some(wide)
}

pub(in crate::windows_gum) unsafe fn supplied_target_w(target: *mut u16) -> Option<Vec<u16>> {
    if target.is_null() {
        return None;
    }
    let mut length = 0;
    while *target.add(length) != 0 && length < 32_768 {
        length += 1;
    }
    let mut wide = std::slice::from_raw_parts(target, length).to_vec();
    wide.push(0);
    Some(wide)
}

unsafe fn pointer_fn(pointer: *mut c_void) -> Option<QueryContextAttributesFn> {
    (!pointer.is_null()).then(|| std::mem::transmute(pointer))
}

#[allow(clippy::too_many_arguments)]
pub(in crate::windows_gum) unsafe extern "system" fn hook_initialize_security_context_a(
    credential: *mut SecHandle,
    old_context: *mut SecHandle,
    target_name: *mut i8,
    context_requirements: u32,
    reserved1: u32,
    target_data_rep: u32,
    input: *mut SecBufferDesc,
    reserved2: u32,
    new_context: *mut SecHandle,
    output: *mut SecBufferDesc,
    context_attributes: *mut u32,
    expiry: *mut i64,
) -> i32 {
    let Some(original) = original!(
        ORIGINAL_INITIALIZE_SECURITY_CONTEXT_A,
        InitializeSecurityContextAFn
    ) else {
        return SEC_E_CERT_UNKNOWN;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(
            credential,
            old_context,
            target_name,
            context_requirements,
            reserved1,
            target_data_rep,
            input,
            reserved2,
            new_context,
            output,
            context_attributes,
            expiry,
        );
    }
    let Some(_guard) = HookGuard::enter() else {
        return SEC_E_CERT_UNKNOWN;
    };
    let mut context = SchannelContext {
        old_context,
        new_context,
        target: supplied_target_a(target_name),
        query: pointer_fn(QUERY_CONTEXT_ATTRIBUTES_A.load(Ordering::Acquire)),
        cert_get_chain: original!(ORIGINAL_CERT_GET_CHAIN, CertGetChainFn),
        cert_verify_policy: original!(ORIGINAL_CERT_VERIFY_POLICY, CertVerifyPolicyFn),
        result: SEC_E_CERT_UNKNOWN,
    };
    runtime().schannel.dispatch(
        &mut context,
        |context| {
            context.result = original(
                credential,
                old_context,
                target_name,
                context_requirements,
                reserved1,
                target_data_rep,
                input,
                reserved2,
                new_context,
                output,
                context_attributes,
                expiry,
            );
            context.result
        },
        |_, _, _| SEC_E_CERT_UNKNOWN,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::windows_gum) unsafe extern "system" fn hook_initialize_security_context_w(
    credential: *mut SecHandle,
    old_context: *mut SecHandle,
    target_name: *mut u16,
    context_requirements: u32,
    reserved1: u32,
    target_data_rep: u32,
    input: *mut SecBufferDesc,
    reserved2: u32,
    new_context: *mut SecHandle,
    output: *mut SecBufferDesc,
    context_attributes: *mut u32,
    expiry: *mut i64,
) -> i32 {
    let Some(original) = original!(
        ORIGINAL_INITIALIZE_SECURITY_CONTEXT_W,
        InitializeSecurityContextWFn
    ) else {
        return SEC_E_CERT_UNKNOWN;
    };
    if INSIDE_HOOK.with(Cell::get) {
        return original(
            credential,
            old_context,
            target_name,
            context_requirements,
            reserved1,
            target_data_rep,
            input,
            reserved2,
            new_context,
            output,
            context_attributes,
            expiry,
        );
    }
    let Some(_guard) = HookGuard::enter() else {
        return SEC_E_CERT_UNKNOWN;
    };
    let mut context = SchannelContext {
        old_context,
        new_context,
        target: supplied_target_w(target_name),
        query: pointer_fn(QUERY_CONTEXT_ATTRIBUTES_W.load(Ordering::Acquire)),
        cert_get_chain: original!(ORIGINAL_CERT_GET_CHAIN, CertGetChainFn),
        cert_verify_policy: original!(ORIGINAL_CERT_VERIFY_POLICY, CertVerifyPolicyFn),
        result: SEC_E_CERT_UNKNOWN,
    };
    runtime().schannel.dispatch(
        &mut context,
        |context| {
            context.result = original(
                credential,
                old_context,
                target_name,
                context_requirements,
                reserved1,
                target_data_rep,
                input,
                reserved2,
                new_context,
                output,
                context_attributes,
                expiry,
            );
            context.result
        },
        |_, _, _| SEC_E_CERT_UNKNOWN,
    )
}
