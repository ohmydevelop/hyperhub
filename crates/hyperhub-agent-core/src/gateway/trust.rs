use std::path::Path;

use base64::Engine;

use crate::HH_ERR_PROTOCOL;

pub(crate) fn stable_hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ (*byte as u64)).wrapping_mul(0x100000001b3)
    })
}

pub(crate) fn decode_first_pem_certificate(pem: &str) -> Result<Vec<u8>, i32> {
    let body = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .and_then(|value| value.split("-----END CERTIFICATE-----").next())
        .ok_or(HH_ERR_PROTOCOL)?;
    let body: String = body
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| HH_ERR_PROTOCOL)
}

const CA_ENVIRONMENT_VARIABLES: &[&str] = &["SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"];

pub(crate) fn materialize_root_ca(pem: &str) -> Result<String, i32> {
    let mut existing = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for variable in CA_ENVIRONMENT_VARIABLES {
        let Some(value) = std::env::var_os(variable).filter(|value| !value.is_empty()) else {
            continue;
        };
        if *variable == "SSL_CERT_DIR" {
            for directory in std::env::split_paths(&value) {
                let Ok(entries) = std::fs::read_dir(directory) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    let _ = append_ca_source(&path, &mut seen, &mut existing);
                }
            }
        } else {
            append_ca_source(&value, &mut seen, &mut existing)?;
        }
    }
    let system_roots = system_root_ca_bundle()?;
    if !system_roots.is_empty() {
        existing.push(system_roots);
    }
    let output_data = compose_ca_bundle(&existing, pem.as_bytes());
    let root = agent_ca_directory().ok_or(HH_ERR_PROTOCOL)?;
    std::fs::create_dir_all(&root).map_err(|_| HH_ERR_PROTOCOL)?;
    let output = root.join(format!("root-{:016x}.pem", stable_hash(&output_data)));
    if !output.is_file() {
        std::fs::write(&output, output_data).map_err(|_| HH_ERR_PROTOCOL)?;
        set_private_file(&output).map_err(|_| HH_ERR_PROTOCOL)?;
    }
    Ok(normalize_path(&output.to_string_lossy()))
}

fn append_ca_source(
    path: impl AsRef<Path>,
    seen: &mut std::collections::HashSet<String>,
    existing: &mut Vec<Vec<u8>>,
) -> Result<(), i32> {
    let path = path.as_ref();
    let identity = normalize_path(&path.to_string_lossy());
    if !seen.insert(identity) {
        return Ok(());
    }
    let source = std::fs::read(path).map_err(|_| HH_ERR_PROTOCOL)?;
    if !is_ca_bundle_data(&source) {
        return Err(HH_ERR_PROTOCOL);
    }
    existing.push(source);
    Ok(())
}

#[cfg(windows)]
pub(crate) fn system_root_ca_bundle() -> Result<Vec<u8>, i32> {
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertOpenSystemStoreW, CERT_CONTEXT,
    };

    const ROOT: [u16; 5] = [b'R' as u16, b'O' as u16, b'O' as u16, b'T' as u16, 0];
    let store = unsafe { CertOpenSystemStoreW(0, ROOT.as_ptr()) };
    if store.is_null() {
        return Err(HH_ERR_PROTOCOL);
    }

    let mut output = Vec::new();
    let mut current: *const CERT_CONTEXT = std::ptr::null();
    loop {
        current = unsafe { CertEnumCertificatesInStore(store, current) };
        if current.is_null() {
            break;
        }
        let certificate = unsafe { &*current };
        if certificate.pbCertEncoded.is_null() || certificate.cbCertEncoded == 0 {
            continue;
        }
        let der = unsafe {
            std::slice::from_raw_parts(
                certificate.pbCertEncoded,
                certificate.cbCertEncoded as usize,
            )
        };
        append_pem_certificate(&mut output, der);
    }
    unsafe { CertCloseStore(store, 0) };
    Ok(output)
}

#[cfg(target_os = "linux")]
pub(crate) fn system_root_ca_bundle() -> Result<Vec<u8>, i32> {
    const SYSTEM_BUNDLE_PATHS: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];

    for path in SYSTEM_BUNDLE_PATHS {
        let Ok(source) = std::fs::read(path) else {
            continue;
        };
        if is_ca_bundle_data(&source) {
            return Ok(source);
        }
    }
    Ok(Vec::new())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) fn system_root_ca_bundle() -> Result<Vec<u8>, i32> {
    Ok(Vec::new())
}

#[cfg(windows)]
pub(crate) fn append_pem_certificate(output: &mut Vec<u8>, der: &[u8]) {
    output.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    for line in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(b"-----END CERTIFICATE-----\n");
}

pub(crate) fn compose_ca_bundle(existing: &[Vec<u8>], hyperhub_root: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    for source in existing {
        output.extend_from_slice(source);
        if !output.ends_with(b"\n") {
            output.push(b'\n');
        }
    }
    if !output
        .windows(hyperhub_root.len())
        .any(|window| window == hyperhub_root)
    {
        output.extend_from_slice(hyperhub_root);
        if !output.ends_with(b"\n") {
            output.push(b'\n');
        }
    }
    output
}

pub(crate) fn install_ca_environment(path: &str) -> Result<(), i32> {
    if path.is_empty() || path.contains('\0') {
        return Err(HH_ERR_PROTOCOL);
    }
    let directory = Path::new(path)
        .parent()
        .filter(|directory| !directory.as_os_str().is_empty())
        .ok_or(HH_ERR_PROTOCOL)?;
    for variable in CA_ENVIRONMENT_VARIABLES {
        match *variable {
            "SSL_CERT_DIR" => std::env::set_var(variable, directory),
            _ => std::env::set_var(variable, path),
        }
    }
    std::env::set_var("HYPERHUB_CA_BUNDLE", path);
    Ok(())
}

fn is_ca_bundle_data(data: &[u8]) -> bool {
    data.len() <= 32 * 1024 * 1024
        && data
            .windows(b"-----BEGIN CERTIFICATE-----".len())
            .any(|window| window == b"-----BEGIN CERTIFICATE-----")
        && !data
            .windows(b"PRIVATE KEY-----".len())
            .any(|window| window == b"PRIVATE KEY-----")
}

pub(crate) fn is_ca_bundle_candidate(path: &Path, data: &[u8]) -> bool {
    if !is_ca_bundle_data(data) {
        return false;
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(extension.as_str(), "pem" | "crt" | "cer")
}

pub(crate) fn set_private_file(_path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_certificate_or_private_key_data() {
        assert!(!is_ca_bundle_data(b"not a certificate"));
        assert!(!is_ca_bundle_data(
            b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
        ));
        assert!(is_ca_bundle_data(
            b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----"
        ));
    }

    #[test]
    fn system_bundle_is_empty_or_valid() {
        let bundle = system_root_ca_bundle().unwrap();
        assert!(bundle.is_empty() || is_ca_bundle_data(&bundle));
    }
}

pub(crate) fn normalize_path(value: &str) -> String {
    let resolved = std::fs::canonicalize(Path::new(value))
        .unwrap_or_else(|_| Path::new(value).to_path_buf())
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    {
        resolved
            .strip_prefix(r"\\?\")
            .unwrap_or(&resolved)
            .replace('/', "\\")
    }
    #[cfg(not(windows))]
    {
        resolved
    }
}

#[derive(Default)]
pub(crate) struct TrustState {
    pub(crate) tls_ca_pem: Vec<u8>,
    pub(crate) tls_ca_der: Vec<u8>,
    pub(crate) tls_ca_path: String,
    pub(crate) bundle_mappings: std::collections::HashMap<String, String>,
}

impl TrustState {
    pub(crate) fn redirect_ca_bundle(&mut self, input: &str) -> Option<String> {
        let input = normalize_path(input);
        if let Some(replacement) = self.bundle_mappings.get(&input) {
            return Some(replacement.clone());
        }
        if self.tls_ca_pem.is_empty() {
            return None;
        }
        let path = Path::new(&input);
        let mut source = std::fs::read(path).ok()?;
        if !is_ca_bundle_candidate(path, &source) {
            return None;
        }
        if source
            .windows(self.tls_ca_pem.len())
            .any(|window| window == self.tls_ca_pem.as_slice())
        {
            return None;
        }
        if !source.ends_with(b"\n") {
            source.push(b'\n');
        }
        source.extend_from_slice(&self.tls_ca_pem);
        if !source.ends_with(b"\n") {
            source.push(b'\n');
        }
        let root = agent_ca_directory()?;
        std::fs::create_dir_all(&root).ok()?;
        let identity = format!("{}:{}", input, stable_hash(&self.tls_ca_pem));
        let output = root.join(format!(
            "bundle-{:016x}.pem",
            stable_hash(identity.as_bytes())
        ));
        if !output.is_file() {
            let temporary = output.with_extension("tmp");
            std::fs::write(&temporary, source).ok()?;
            set_private_file(&temporary).ok()?;
            if std::fs::rename(&temporary, &output).is_err() {
                let _ = std::fs::remove_file(&temporary);
                if !output.is_file() {
                    return None;
                }
            }
        }
        let replacement = normalize_path(&output.to_string_lossy());
        self.bundle_mappings.insert(input, replacement.clone());
        Some(replacement)
    }
}

fn agent_ca_directory() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let uid = unsafe { libc::geteuid() };
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            .filter(|path| linux_private_directory(path, uid).is_ok())
            .unwrap_or_else(|| std::env::temp_dir().join(format!("hyperhub-{uid}")));
        ensure_linux_private_directory(&base, uid).ok()?;
        let namespace = base.join("hyperhub");
        ensure_linux_private_directory(&namespace, uid).ok()?;
        return Some(namespace.join(format!("agent-{}", std::process::id())));
    }

    #[cfg(not(target_os = "linux"))]
    Some(
        std::env::temp_dir()
            .join("hyperhub")
            .join(format!("agent-{}", std::process::id())),
    )
}

#[cfg(target_os = "linux")]
fn linux_private_directory(path: &std::path::Path, uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is not private to the current user",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_linux_private_directory(path: &std::path::Path, uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "directory is not owned by the current user",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)?;
        }
        Err(error) => return Err(error),
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    linux_private_directory(path, uid)
}
