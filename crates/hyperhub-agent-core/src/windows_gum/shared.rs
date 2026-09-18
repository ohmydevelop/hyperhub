#![allow(unused_imports)]

//! Shared Win32 ABI namespace consumed by native adapters only.

pub(in crate::windows_gum) use std::cell::Cell;
pub(in crate::windows_gum) use std::collections::{BTreeMap, HashMap};
pub(in crate::windows_gum) use std::ffi::{c_char, c_void, CStr, CString, OsStr};
pub(in crate::windows_gum) use std::net::IpAddr;
pub(in crate::windows_gum) use std::os::windows::ffi::OsStrExt;
pub(in crate::windows_gum) use std::ptr::{null, null_mut};
pub(in crate::windows_gum) use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
pub(in crate::windows_gum) use std::sync::{Mutex, OnceLock};

pub(in crate::windows_gum) use windows_sys::Win32::Foundation::{
    CloseHandle, SetLastError, CERT_E_UNTRUSTEDROOT, ERROR_DLL_INIT_FAILED, FILETIME, HANDLE,
    HMODULE, SEC_E_CERT_UNKNOWN, SEC_E_OK, WAIT_OBJECT_0,
};
pub(in crate::windows_gum) use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_ACP};
pub(in crate::windows_gum) use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSASetLastError, ADDRINFOA, ADDRINFOW, AF_INET, AF_INET6, AF_UNSPEC,
    AI_CANONNAME, AI_NUMERICHOST, FD_SET, FIONBIO, LPWSAOVERLAPPED_COMPLETION_ROUTINE, QOS,
    SOCKADDR, SOCKADDR_STORAGE, SOCKET, TIMEVAL, WSABUF, WSAECONNRESET, WSAEWOULDBLOCK,
};
pub(in crate::windows_gum) use windows_sys::Win32::Security::Authentication::Identity::{
    SecBufferDesc, SCHANNEL_CRED, SCHANNEL_CRED_VERSION, SCH_CREDENTIALS, SCH_CREDENTIALS_VERSION,
    SCH_CRED_AUTO_CRED_VALIDATION, SCH_CRED_MANUAL_CRED_VALIDATION,
    SECPKG_ATTR_REMOTE_CERT_CONTEXT, SEC_GET_KEY_FN,
};
pub(in crate::windows_gum) use windows_sys::Win32::Security::Credentials::SecHandle;
pub(in crate::windows_gum) use windows_sys::Win32::Security::Cryptography::{
    szOID_PKIX_KP_SERVER_AUTH, CertAddCertificateContextToStore, CertAddStoreToCollection,
    CertCloseStore, CertCreateCertificateContext, CertEnumCertificatesInStore,
    CertFreeCertificateChain, CertFreeCertificateContext, CertOpenStore, CertOpenSystemStoreW,
    AUTHTYPE_SERVER, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_PARA,
    CERT_CHAIN_POLICY_SSL, CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT, CERT_STORE_ADD_ALWAYS,
    CERT_STORE_CREATE_NEW_FLAG, CERT_STORE_PROV_COLLECTION, CERT_STORE_PROV_MEMORY,
    CERT_TRUST_IS_UNTRUSTED_ROOT, HCERTCHAINENGINE, HCERTSTORE, PKCS_7_ASN_ENCODING,
    USAGE_MATCH_TYPE_OR, X509_ASN_ENCODING,
};
pub(in crate::windows_gum) use windows_sys::Win32::System::Threading::{
    TerminateProcess, PROCESS_INFORMATION, STARTUPINFOA, STARTUPINFOW,
};
pub(in crate::windows_gum) use windows_sys::Win32::System::IO::OVERLAPPED;

pub(in crate::windows_gum) use super::runtime::*;
pub(in crate::windows_gum) use super::{
    SOCKET_ERROR, STATUS_DLL_INIT_FAILED, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, WSATRY_AGAIN,
};
pub(in crate::windows_gum) use crate::{
    hh_agent_build_handshake, hh_agent_close_socket, hh_agent_handshake_complete,
    hh_agent_note_nonblocking, hh_agent_set_handshake_complete, hh_agent_socket_nonblocking,
    hh_agent_tls_ca_der, hh_agent_validate_handshake_reply, HH_ERR_BUFFER_TOO_SMALL, HH_OK,
};
