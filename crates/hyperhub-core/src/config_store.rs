use crate::config::{Config, ConfigError};
use crate::config_document::ConfigDocument;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"HHCFGBIN";
const VERSION: u16 = 1;
const FLAG_ENCRYPTED: u8 = 1;
const HEADER_LEN: usize = 120;
const CONFIG_LABEL: &[u8] = b"hyperhub/config-aead/v1";
const APPROVAL_STATE_LABEL: &[u8] = b"hyperhub/approval-state-aead/v1";
const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_LANES: u32 = 1;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("cannot access configuration {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("configuration container is invalid: {0}")]
    Format(String),
    #[error("configuration password is incorrect or the file is damaged")]
    Authentication,
    #[error(transparent)]
    Config(Box<ConfigError>),
    #[error("cannot serialize TOML configuration: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("cannot serialize JSON configuration view: {0}")]
    JsonSerialize(#[from] serde_json::Error),
}

impl From<ConfigError> for StoreError {
    fn from(value: ConfigError) -> Self {
        Self::Config(Box::new(value))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfDescriptor {
    pub config_id: [u8; 16],
    pub salt: [u8; 16],
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

/// Password-derived key material for one configuration generation.
///
/// Argon2 is intentionally expensive, so interactive workflows derive it once
/// after password entry and use domain-separated HKDF subkeys for config,
/// approval-state, certificate, and control operations. The master key is
/// zeroized when this value is dropped.
pub struct ConfigKeyring {
    descriptor: KdfDescriptor,
    master: Zeroizing<Vec<u8>>,
}

impl ConfigKeyring {
    pub fn derive(password: &[u8], descriptor: KdfDescriptor) -> Result<Self, StoreError> {
        let master = derive_master(password, &descriptor)?;
        Ok(Self { descriptor, master })
    }

    pub fn descriptor(&self) -> &KdfDescriptor {
        &self.descriptor
    }

    pub fn session_auth_key(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.subkey(b"hyperhub/session-auth/v1")
    }

    fn subkey(&self, label: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        derive_subkey(&self.master, &self.descriptor, label)
    }
}

#[derive(Clone)]
pub struct UnlockedConfig {
    pub config: Config,
    pub descriptor: KdfDescriptor,
    pub session_auth_key: Zeroizing<Vec<u8>>,
}

pub struct UnlockedApprovalState {
    pub bytes: Zeroizing<Vec<u8>>,
    pub descriptor: KdfDescriptor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    EncryptedBin,
    PlainBin,
    Toml,
}

pub fn default_config_path() -> Result<PathBuf, StoreError> {
    let home =
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).ok_or_else(|| {
            StoreError::Format("cannot determine the current user's home directory".into())
        })?;
    Ok(PathBuf::from(home).join(".hyperhub").join("config.bin"))
}

pub fn redacted_config_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("redacted.json")
}

pub fn save_redacted_json(config_path: &Path, config: &Config) -> Result<(), StoreError> {
    let mut bytes = serde_json::to_vec_pretty(&ConfigDocument::from_config(&config.redacted()))?;
    bytes.push(b'\n');
    atomic_write(&redacted_config_path(config_path), &bytes)
}

pub fn read_redacted_json(config_path: &Path) -> Result<Vec<u8>, StoreError> {
    read(&redacted_config_path(config_path))
}

pub fn new_descriptor() -> KdfDescriptor {
    let mut config_id = [0u8; 16];
    let mut salt = [0u8; 16];
    rand::fill(&mut config_id);
    rand::fill(&mut salt);
    KdfDescriptor {
        config_id,
        salt,
        memory_kib: DEFAULT_MEMORY_KIB,
        iterations: DEFAULT_ITERATIONS,
        lanes: DEFAULT_LANES,
    }
}

pub fn read_descriptor(path: &Path) -> Result<KdfDescriptor, StoreError> {
    let bytes = read(path)?;
    let header = parse_header(&bytes)?;
    if !header.encrypted {
        return Err(StoreError::Format(
            "the active configuration must be encrypted".into(),
        ));
    }
    Ok(header.descriptor)
}

pub fn derive_session_auth_key(
    password: &[u8],
    descriptor: &KdfDescriptor,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    ConfigKeyring::derive(password, descriptor.clone())?.session_auth_key()
}

pub fn load_encrypted(path: &Path, password: &[u8]) -> Result<UnlockedConfig, StoreError> {
    let descriptor = read_descriptor(path)?;
    let keyring = ConfigKeyring::derive(password, descriptor)?;
    load_encrypted_with_keyring(path, &keyring)
}

pub fn load_encrypted_with_keyring(
    path: &Path,
    keyring: &ConfigKeyring,
) -> Result<UnlockedConfig, StoreError> {
    let bytes = read(path)?;
    let header = parse_header(&bytes)?;
    if !header.encrypted {
        return Err(StoreError::Format(
            "the active configuration must be encrypted".into(),
        ));
    }
    ensure_keyring_descriptor(keyring, &header.descriptor)?;
    let plaintext = decrypt_payload_with_keyring(&bytes, keyring, CONFIG_LABEL)?;
    let config = parse_document_toml(&plaintext, path)?;
    let session_auth_key = keyring.session_auth_key()?;
    Ok(UnlockedConfig {
        config,
        descriptor: header.descriptor,
        session_auth_key,
    })
}

/// Persist the resumable human-approval queue with a key domain separated from
/// the active configuration. The queue may temporarily contain secrets entered
/// during an in-flight approval, so it must never be stored as plain JSON.
pub fn save_approval_state(
    path: &Path,
    bytes: &[u8],
    password: &[u8],
    descriptor: &KdfDescriptor,
) -> Result<(), StoreError> {
    let keyring = ConfigKeyring::derive(password, descriptor.clone())?;
    save_approval_state_with_keyring(path, bytes, &keyring)
}

pub fn save_approval_state_with_keyring(
    path: &Path,
    bytes: &[u8],
    keyring: &ConfigKeyring,
) -> Result<(), StoreError> {
    let encrypted = encrypt_payload_with_keyring(bytes, keyring, APPROVAL_STATE_LABEL)?;
    atomic_write(path, &encrypted)
}

pub fn load_approval_state(
    path: &Path,
    password: &[u8],
) -> Result<UnlockedApprovalState, StoreError> {
    let descriptor = read_descriptor(path)?;
    let keyring = ConfigKeyring::derive(password, descriptor)?;
    load_approval_state_with_keyring(path, &keyring)
}

pub fn load_approval_state_with_keyring(
    path: &Path,
    keyring: &ConfigKeyring,
) -> Result<UnlockedApprovalState, StoreError> {
    let bytes = read(path)?;
    let header = parse_header(&bytes)?;
    if !header.encrypted {
        return Err(StoreError::Format(
            "the approval state must be encrypted".into(),
        ));
    }
    ensure_keyring_descriptor(keyring, &header.descriptor)?;
    let plaintext = decrypt_payload_with_keyring(&bytes, keyring, APPROVAL_STATE_LABEL)?;
    Ok(UnlockedApprovalState {
        bytes: plaintext,
        descriptor: header.descriptor,
    })
}

pub fn import(path: &Path, password: Option<&[u8]>) -> Result<Config, StoreError> {
    let bytes = read(path)?;
    if bytes.starts_with(MAGIC) {
        let header = parse_header(&bytes)?;
        let plaintext = if header.encrypted {
            decrypt_payload(&bytes, password.ok_or(StoreError::Authentication)?)?
        } else {
            Zeroizing::new(verify_plain_payload(&bytes, &header)?)
        };
        parse_document_toml(&plaintext, path)
    } else {
        parse_document_toml(&bytes, path)
    }
}

pub fn save_encrypted(path: &Path, config: &Config, password: &[u8]) -> Result<(), StoreError> {
    save_encrypted_with_descriptor(path, config, password, &new_descriptor())
}

pub fn save_encrypted_with_descriptor(
    path: &Path,
    config: &Config,
    password: &[u8],
    descriptor: &KdfDescriptor,
) -> Result<(), StoreError> {
    let keyring = ConfigKeyring::derive(password, descriptor.clone())?;
    save_encrypted_with_keyring(path, config, &keyring)
}

pub fn save_encrypted_with_keyring(
    path: &Path,
    config: &Config,
    keyring: &ConfigKeyring,
) -> Result<(), StoreError> {
    let document = ConfigDocument::from_config(config);
    let plaintext = Zeroizing::new(toml::to_string_pretty(&document)?.into_bytes());
    let bytes = encrypt_payload_with_keyring(&plaintext, keyring, CONFIG_LABEL)?;
    atomic_write(path, &bytes)?;
    save_redacted_json(path, config)
}

pub fn export(
    path: &Path,
    config: &Config,
    format: ExportFormat,
    password: Option<&[u8]>,
) -> Result<(), StoreError> {
    let document = ConfigDocument::from_config(config);
    let payload = toml::to_string_pretty(&document)?.into_bytes();
    let bytes = match format {
        ExportFormat::EncryptedBin => encrypt_payload(
            &payload,
            password.ok_or(StoreError::Authentication)?,
            &new_descriptor(),
            CONFIG_LABEL,
        )?,
        ExportFormat::PlainBin => encode_plain_payload(&payload),
        ExportFormat::Toml => payload,
    };
    atomic_write(path, &bytes)
}

fn encrypt_payload(
    plaintext: &[u8],
    password: &[u8],
    descriptor: &KdfDescriptor,
    label: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let keyring = ConfigKeyring::derive(password, descriptor.clone())?;
    encrypt_payload_with_keyring(plaintext, &keyring, label)
}

fn encrypt_payload_with_keyring(
    plaintext: &[u8],
    keyring: &ConfigKeyring,
    label: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let key = keyring.subkey(label)?;
    let mut nonce = [0u8; 24];
    rand::fill(&mut nonce);
    let payload_len = plaintext.len() as u64 + 16;
    let header = build_header(true, keyring.descriptor(), nonce, payload_len, [0; 32]);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| StoreError::Authentication)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| StoreError::Authentication)?;
    let mut output = header;
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn encode_plain_payload(payload: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::digest(payload).into();
    let descriptor = new_descriptor();
    let mut output = build_header(false, &descriptor, [0; 24], payload.len() as u64, digest);
    output.extend_from_slice(payload);
    output
}

struct ParsedHeader {
    encrypted: bool,
    descriptor: KdfDescriptor,
    nonce: [u8; 24],
    payload_len: usize,
    digest: [u8; 32],
}

fn build_header(
    encrypted: bool,
    descriptor: &KdfDescriptor,
    nonce: [u8; 24],
    payload_len: u64,
    digest: [u8; 32],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.push(u8::from(encrypted) * FLAG_ENCRYPTED);
    header.push(0);
    header.extend_from_slice(&descriptor.memory_kib.to_le_bytes());
    header.extend_from_slice(&descriptor.iterations.to_le_bytes());
    header.extend_from_slice(&descriptor.lanes.to_le_bytes());
    header.extend_from_slice(&descriptor.salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&descriptor.config_id);
    header.extend_from_slice(&payload_len.to_le_bytes());
    header.extend_from_slice(&digest);
    debug_assert_eq!(header.len(), HEADER_LEN);
    header
}

fn parse_header(bytes: &[u8]) -> Result<ParsedHeader, StoreError> {
    if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
        return Err(StoreError::Format("missing HyperHub BIN header".into()));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != VERSION {
        return Err(StoreError::Format(format!(
            "unsupported container version {version}"
        )));
    }
    if bytes[10] & !FLAG_ENCRYPTED != 0 {
        return Err(StoreError::Format("unknown container flags".into()));
    }
    let descriptor = KdfDescriptor {
        memory_kib: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        iterations: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        lanes: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        salt: bytes[24..40].try_into().unwrap(),
        config_id: bytes[64..80].try_into().unwrap(),
    };
    validate_descriptor(&descriptor)?;
    let payload_len = usize::try_from(u64::from_le_bytes(bytes[80..88].try_into().unwrap()))
        .map_err(|_| StoreError::Format("payload is too large".into()))?;
    if payload_len > 16 * 1024 * 1024 || bytes.len() != HEADER_LEN + payload_len {
        return Err(StoreError::Format("container length is invalid".into()));
    }
    Ok(ParsedHeader {
        encrypted: bytes[10] & FLAG_ENCRYPTED != 0,
        descriptor,
        nonce: bytes[40..64].try_into().unwrap(),
        payload_len,
        digest: bytes[88..120].try_into().unwrap(),
    })
}

fn ensure_keyring_descriptor(
    keyring: &ConfigKeyring,
    descriptor: &KdfDescriptor,
) -> Result<(), StoreError> {
    if keyring.descriptor() == descriptor {
        Ok(())
    } else {
        Err(StoreError::Authentication)
    }
}

fn validate_descriptor(descriptor: &KdfDescriptor) -> Result<(), StoreError> {
    if !(8 * 1024..=1024 * 1024).contains(&descriptor.memory_kib)
        || !(1..=10).contains(&descriptor.iterations)
        || !(1..=16).contains(&descriptor.lanes)
    {
        return Err(StoreError::Format(
            "unsafe or unsupported Argon2 parameters".into(),
        ));
    }
    Ok(())
}

fn derive_master(
    password: &[u8],
    descriptor: &KdfDescriptor,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    validate_descriptor(descriptor)?;
    let params = Params::new(
        descriptor.memory_kib,
        descriptor.iterations,
        descriptor.lanes,
        Some(32),
    )
    .map_err(|error| StoreError::Format(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new(vec![0u8; 32]);
    argon2
        .hash_password_into(password, &descriptor.salt, &mut output)
        .map_err(|error| StoreError::Format(error.to_string()))?;
    Ok(output)
}

fn derive_subkey(
    master: &[u8],
    descriptor: &KdfDescriptor,
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&descriptor.config_id), master);
    let mut output = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(label, &mut output)
        .map_err(|_| StoreError::Authentication)?;
    Ok(output)
}

fn decrypt_payload_with_label(
    bytes: &[u8],
    password: &[u8],
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let header = parse_header(bytes)?;
    let keyring = ConfigKeyring::derive(password, header.descriptor.clone())?;
    decrypt_payload_with_keyring(bytes, &keyring, label)
}

fn decrypt_payload_with_keyring(
    bytes: &[u8],
    keyring: &ConfigKeyring,
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let header = parse_header(bytes)?;
    if !header.encrypted {
        return Err(StoreError::Format("payload is not encrypted".into()));
    }
    ensure_keyring_descriptor(keyring, &header.descriptor)?;
    let key = keyring.subkey(label)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| StoreError::Authentication)?;
    cipher
        .decrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: &bytes[HEADER_LEN..HEADER_LEN + header.payload_len],
                aad: &bytes[..HEADER_LEN],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| StoreError::Authentication)
}

fn decrypt_payload(bytes: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    decrypt_payload_with_label(bytes, password, b"hyperhub/config-aead/v1")
}

fn verify_plain_payload(bytes: &[u8], header: &ParsedHeader) -> Result<Vec<u8>, StoreError> {
    let payload = bytes[HEADER_LEN..HEADER_LEN + header.payload_len].to_vec();
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    if digest != header.digest {
        return Err(StoreError::Format(
            "plain BIN checksum does not match".into(),
        ));
    }
    Ok(payload)
}

fn parse_document_toml(bytes: &[u8], path: &Path) -> Result<Config, StoreError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| StoreError::Format("configuration TOML is not UTF-8".into()))?;
    let document: ConfigDocument = toml::from_str(text)
        .map_err(|error| StoreError::Format(format!("invalid configuration schema v2: {error}")))?;
    let mut config = document.into_config().map_err(StoreError::Format)?;
    config.apply_managed_audit_paths(path);
    Ok(config)
}

fn read(path: &Path) -> Result<Vec<u8>, StoreError> {
    fs::read(path).map_err(|source| StoreError::Io {
        path: path.to_owned(),
        source,
    })
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::Format("configuration path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|source| StoreError::Io {
        path: parent.to_owned(),
        source,
    })?;
    let temporary = parent.join(format!(
        ".config-{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        restrict_file_to_current_user(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|source| StoreError::Io {
        path: path.to_owned(),
        source,
    })
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let mut source: Vec<u16> = source.as_os_str().encode_wide().collect();
    let mut destination: Vec<u16> = destination.as_os_str().encode_wide().collect();
    source.push(0);
    destination.push(0);
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn restrict_file_to_current_user(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn restrict_file_to_current_user(path: &Path) -> io::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    unsafe {
        let result = (|| {
            let sid_value = current_user_sid_string()?;
            let sddl = format!("D:P(A;;FA;;;{sid_value})");
            let sddl: Vec<u16> = OsStr::new(&sddl).encode_wide().chain(Some(0)).collect();
            let mut descriptor = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let ok = SetFileSecurityW(
                path.as_mut_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            );
            LocalFree(descriptor.cast());
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        })();
        result
    }
}

#[cfg(windows)]
pub(crate) fn current_user_sid_string() -> io::Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut length = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
            if length < std::mem::size_of::<TOKEN_USER>() as u32 {
                return Err(io::Error::last_os_error());
            }
            let words = (length as usize).div_ceil(std::mem::size_of::<usize>());
            let mut buffer = vec![0usize; words];
            if GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
            let mut sid = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut count = 0usize;
            while *sid.add(count) != 0 {
                count += 1;
            }
            let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid, count));
            LocalFree(sid.cast());
            Ok(value)
        })();
        CloseHandle(token);
        result
    }
}

// ---------------------------------------------------------------------------
// Encrypted root certificate store.
//
// Every imported root certificate lives in its own file under
// `<config home>/root-certificates/<fingerprint>.bin`, encrypted with the same
// master password that protects the configuration. The SHA-256 fingerprint of
// the DER is the identity and the storage file name; source paths and display
// IDs are never persisted.
// ---------------------------------------------------------------------------

pub const ROOT_CERTIFICATE_DIR: &str = "root-certificates";
const ROOT_CERTIFICATE_LABEL: &[u8] = b"hyperhub/root-cert/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedRootCertificate {
    pub fingerprint: String,
}

pub fn root_certificates_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(ROOT_CERTIFICATE_DIR)
}

fn root_certificate_path(config_path: &Path, fingerprint: &str) -> PathBuf {
    root_certificates_dir(config_path).join(format!("{fingerprint}.bin"))
}

/// Parses the source file and stores every certificate it contains as its own
/// encrypted file, returning the imported fingerprints.
pub fn import_root_certificates(
    source: &Path,
    config_path: &Path,
    password: &[u8],
) -> Result<Vec<ImportedRootCertificate>, StoreError> {
    let certificates =
        crate::certificate::load_root_certificates(source).map_err(|error| StoreError::Io {
            path: source.to_owned(),
            source: error,
        })?;
    import_root_certificates_from_der(config_path, password, &certificates)
}

/// 把内存中的 DER 证书逐个加密落盘，返回导入的指纹。
pub fn import_root_certificates_from_der(
    config_path: &Path,
    password: &[u8],
    certificates: &[CertificateDer<'_>],
) -> Result<Vec<ImportedRootCertificate>, StoreError> {
    let descriptor = read_descriptor(config_path)?;
    let mut imported = Vec::new();
    for certificate in certificates {
        let fingerprint = crate::certificate::fingerprint(certificate);
        let destination = root_certificate_path(config_path, &fingerprint);
        let encrypted = encrypt_payload(
            certificate.as_ref(),
            password,
            &descriptor,
            ROOT_CERTIFICATE_LABEL,
        )?;
        atomic_write(&destination, &encrypted)?;
        imported.push(ImportedRootCertificate { fingerprint });
    }
    Ok(imported)
}

pub fn read_root_certificate(
    config_path: &Path,
    password: &[u8],
    fingerprint: &str,
) -> Result<CertificateDer<'static>, StoreError> {
    let path = root_certificate_path(config_path, fingerprint);
    let bytes = read(&path)?;
    let plaintext = decrypt_payload_with_label(&bytes, password, ROOT_CERTIFICATE_LABEL)?;
    Ok(CertificateDer::from(plaintext.to_vec()))
}

pub fn load_root_certificates<'a>(
    config_path: &Path,
    password: &[u8],
    fingerprints: impl Iterator<Item = &'a str>,
) -> Result<Vec<CertificateDer<'static>>, StoreError> {
    fingerprints
        .map(|fingerprint| read_root_certificate(config_path, password, fingerprint))
        .collect()
}

pub fn delete_root_certificate(config_path: &Path, fingerprint: &str) -> Result<(), StoreError> {
    let path = root_certificate_path(config_path, fingerprint);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StoreError::Io { path, source }),
    }
}

/// Re-encrypts every stored certificate with the new password and descriptor.
/// Used when the master password changes.
pub fn reencrypt_root_certificates(
    config_path: &Path,
    old_password: &[u8],
    new_password: &[u8],
    new_descriptor: &KdfDescriptor,
) -> Result<(), StoreError> {
    let directory = root_certificates_dir(config_path);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(StoreError::Io {
                path: directory,
                source,
            })
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| StoreError::Io {
            path: directory.clone(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("bin") {
            continue;
        }
        let bytes = read(&path)?;
        let plaintext =
            match decrypt_payload_with_label(&bytes, old_password, ROOT_CERTIFICATE_LABEL) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    // Already encrypted with the new password (imported after the
                    // password changed but before saving); leave it untouched.
                    decrypt_payload_with_label(&bytes, new_password, ROOT_CERTIFICATE_LABEL)?;
                    continue;
                }
            };
        let reencrypted = encrypt_payload(
            &plaintext,
            new_password,
            new_descriptor,
            ROOT_CERTIFICATE_LABEL,
        )?;
        atomic_write(&path, &reencrypted)?;
    }
    Ok(())
}

/// Removes stored certificate files that are no longer referenced by the
/// configuration.
pub fn reconcile_root_certificates<'a>(
    config_path: &Path,
    fingerprints: impl Iterator<Item = &'a str>,
) -> Result<(), StoreError> {
    let keep = fingerprints.collect::<std::collections::HashSet<_>>();
    let directory = root_certificates_dir(config_path);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(StoreError::Io {
                path: directory,
                source,
            })
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| StoreError::Io {
            path: directory.clone(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("bin") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        if !keep.contains(name) {
            if let Err(source) = fs::remove_file(&path) {
                if source.kind() != io::ErrorKind::NotFound {
                    return Err(StoreError::Io { path, source });
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hyperhub-{name}-{}-{}.bin",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn encrypted_container_round_trips_and_rejects_tampering() {
        let path = temp_path("encrypted-config");
        let config = Config::default();
        save_encrypted(&path, &config, b"correct horse battery staple").unwrap();
        let unlocked = load_encrypted(&path, b"correct horse battery staple").unwrap();
        assert_eq!(
            unlocked.config.listener.socks_listen,
            config.listener.socks_listen
        );
        assert!(matches!(
            load_encrypted(&path, b"wrong"),
            Err(StoreError::Authentication)
        ));
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            load_encrypted(&path, b"correct horse battery staple"),
            Err(StoreError::Authentication)
        ));
        fs::remove_file(&path).unwrap();
        fs::remove_file(redacted_config_path(&path)).unwrap();
    }

    #[test]
    fn encrypted_save_writes_a_complete_redacted_json_view() {
        let path = temp_path("redacted-view");
        let mut config = Config::default();
        config.environment.push(crate::config::EnvironmentVariable {
            uuid: crate::config::new_config_uuid(),
            name: "TOKEN".into(),
            value: crate::config::SecretValue::Inline {
                value: "actual-secret".into(),
            },
        });
        save_encrypted(&path, &config, b"correct horse battery staple").unwrap();
        let view_path = redacted_config_path(&path);
        assert_eq!(view_path, path.with_extension("redacted.json"));
        let text = fs::read_to_string(&view_path).unwrap();
        assert!(!text.contains("actual-secret"));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["environment_variables"][0]["name"], "TOKEN");
        assert_eq!(
            value["environment_variables"][0]["value"]["value"],
            "<redacted>"
        );
        fs::remove_file(path).unwrap();
        fs::remove_file(view_path).unwrap();
    }

    #[test]
    fn imports_plain_bin_and_toml() {
        let config = Config::default();
        let bin = temp_path("plain-config");
        export(&bin, &config, ExportFormat::PlainBin, None).unwrap();
        assert_eq!(
            import(&bin, None).unwrap().listener.socks_listen,
            config.listener.socks_listen
        );
        let toml_path = bin.with_extension("toml");
        export(&toml_path, &config, ExportFormat::Toml, None).unwrap();
        assert_eq!(
            import(&toml_path, None).unwrap().listener.socks_listen,
            config.listener.socks_listen
        );
        fs::remove_file(bin).unwrap();
        fs::remove_file(toml_path).unwrap();
    }

    #[test]
    fn rejects_truncated_and_header_tampered_containers() {
        let path = temp_path("damaged-config");
        let config = Config::default();
        save_encrypted(&path, &config, b"correct horse battery staple").unwrap();
        let original = fs::read(&path).unwrap();

        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(matches!(
            load_encrypted(&path, b"correct horse battery staple"),
            Err(StoreError::Format(_))
        ));

        let mut tampered = original;
        tampered[40] ^= 1;
        fs::write(&path, tampered).unwrap();
        assert!(matches!(
            load_encrypted(&path, b"correct horse battery staple"),
            Err(StoreError::Authentication)
        ));
        fs::remove_file(&path).unwrap();
        fs::remove_file(redacted_config_path(&path)).unwrap();
    }

    fn temp_certificate_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hyperhub-{name}-{}-{}.pem",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    fn write_test_ca(path: &Path) -> (String, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HyperHub Stored Root");
        let certificate = params.self_signed(&key).unwrap();
        fs::write(path, certificate.pem()).unwrap();
        let der = certificate.der().clone();
        (crate::certificate::fingerprint(&der), der.as_ref().to_vec())
    }

    #[test]
    fn root_certificates_import_read_reencrypt_and_reconcile() {
        let config_path = temp_path("cert-config");
        let config = Config::default();
        save_encrypted(&config_path, &config, b"old password").unwrap();

        let source = temp_certificate_path("source-ca");
        let (fingerprint, der) = write_test_ca(&source);
        let imported = import_root_certificates(&source, &config_path, b"old password").unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].fingerprint, fingerprint);

        let stored = root_certificates_dir(&config_path).join(format!("{fingerprint}.bin"));
        assert!(stored.is_file());
        assert!(source.is_file());

        let loaded = read_root_certificate(&config_path, b"old password", &fingerprint).unwrap();
        assert_eq!(loaded.as_ref(), der.as_slice());

        assert!(matches!(
            read_root_certificate(&config_path, b"wrong password", &fingerprint),
            Err(StoreError::Authentication)
        ));

        let descriptor = new_descriptor();
        reencrypt_root_certificates(&config_path, b"old password", b"new password", &descriptor)
            .unwrap();
        assert!(matches!(
            read_root_certificate(&config_path, b"old password", &fingerprint),
            Err(StoreError::Authentication)
        ));
        assert!(read_root_certificate(&config_path, b"new password", &fingerprint).is_ok());

        let orphan = root_certificates_dir(&config_path).join(format!("{fingerprint}.bin"));
        let extra = root_certificates_dir(&config_path).join("deadbeef.bin");
        fs::copy(&orphan, &extra).unwrap();
        reconcile_root_certificates(&config_path, std::iter::once(fingerprint.as_str())).unwrap();
        assert!(stored.is_file());
        assert!(!extra.exists());

        delete_root_certificate(&config_path, &fingerprint).unwrap();
        assert!(!stored.exists());
        assert!(delete_root_certificate(&config_path, &fingerprint).is_ok());

        fs::remove_file(&config_path).unwrap();
        fs::remove_file(redacted_config_path(&config_path)).unwrap();
        fs::remove_dir_all(root_certificates_dir(&config_path)).ok();
    }

    #[test]
    fn cached_keyring_reuses_one_master_for_config_approval_and_session_keys() {
        let config_path = temp_path("cached-keyring-config");
        let approval_path = temp_path("cached-keyring-approval");
        let mut descriptor = new_descriptor();
        descriptor.memory_kib = 8 * 1024;
        descriptor.iterations = 1;
        let keyring = ConfigKeyring::derive(b"cached password", descriptor.clone()).unwrap();
        let mut config = Config::default();
        config.debug = true;

        save_encrypted_with_keyring(&config_path, &config, &keyring).unwrap();
        let unlocked = load_encrypted_with_keyring(&config_path, &keyring).unwrap();
        assert!(unlocked.config.debug);
        assert_eq!(unlocked.descriptor, descriptor);
        assert_eq!(unlocked.session_auth_key.len(), 32);

        let approval = br#"{"cursor":1}"#;
        save_approval_state_with_keyring(&approval_path, approval, &keyring).unwrap();
        let unlocked = load_approval_state_with_keyring(&approval_path, &keyring).unwrap();
        assert_eq!(unlocked.bytes.as_slice(), approval);
        assert_eq!(keyring.session_auth_key().unwrap().len(), 32);

        let mut other_descriptor = descriptor;
        other_descriptor.config_id[0] ^= 1;
        let other = ConfigKeyring::derive(b"cached password", other_descriptor).unwrap();
        assert!(matches!(
            load_approval_state_with_keyring(&approval_path, &other),
            Err(StoreError::Authentication)
        ));

        fs::remove_file(&config_path).unwrap();
        fs::remove_file(redacted_config_path(&config_path)).unwrap();
        fs::remove_file(approval_path).unwrap();
    }

    #[test]
    fn approval_state_round_trips_with_separate_key_domain() {
        let path = temp_path("approval-state");
        let descriptor = new_descriptor();
        let payload = br#"{"cursor":2,"secret":"temporary-value"}"#;
        save_approval_state(&path, payload, b"correct horse battery staple", &descriptor).unwrap();
        let stored = std::fs::read(&path).unwrap();
        assert!(!stored
            .windows(b"temporary-value".len())
            .any(|window| window == b"temporary-value"));

        let unlocked = load_approval_state(&path, b"correct horse battery staple").unwrap();
        assert_eq!(unlocked.bytes.as_slice(), payload);
        assert_eq!(unlocked.descriptor, descriptor);
        assert!(matches!(
            load_approval_state(&path, b"wrong password"),
            Err(StoreError::Authentication)
        ));
        assert!(matches!(
            load_encrypted(&path, b"correct horse battery staple"),
            Err(StoreError::Authentication)
        ));

        std::fs::remove_file(path).unwrap();
    }
}
