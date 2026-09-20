use crate::audit::AuditWriter;
use crate::config::{new_config_uuid, Config, RootCertificate, SshHostKey};
use crate::config_store::{self, KdfDescriptor};
use crate::runtime::RuntimeState;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use serde_json::json;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct TrustStore(Arc<TrustStoreInner>);

struct TrustStoreInner {
    config_path: PathBuf,
    password: Zeroizing<Vec<u8>>,
    descriptor: KdfDescriptor,
    runtime: RuntimeState,
    audit: AuditWriter,
    mutation: Mutex<()>,
    cache: Mutex<Option<TrustCache>>,
}

struct TrustCache {
    version: u64,
    roots: Arc<RootCertStore>,
    host_certificates: HashMap<String, CertificateDer<'static>>,
}

#[derive(Clone)]
pub struct TlsTrustMaterial {
    pub roots: Arc<RootCertStore>,
    pub host_certificate: Option<CertificateDer<'static>>,
}

impl TrustStore {
    pub fn new(
        config_path: PathBuf,
        password: Vec<u8>,
        descriptor: KdfDescriptor,
        runtime: RuntimeState,
        audit: AuditWriter,
    ) -> Self {
        Self(Arc::new(TrustStoreInner {
            config_path,
            password: Zeroizing::new(password),
            descriptor,
            runtime,
            audit,
            mutation: Mutex::new(()),
            cache: Mutex::new(None),
        }))
    }

    pub fn tls_material(&self, host: &str, port: u16) -> io::Result<TlsTrustMaterial> {
        let authority = trust_authority(host, port);
        let snapshot = self.0.runtime.snapshot();
        let mut cache = self
            .0
            .cache
            .lock()
            .map_err(|_| io::Error::other("TLS trust cache poisoned"))?;
        if cache
            .as_ref()
            .is_none_or(|cache| cache.version != snapshot.updated_at_ms)
        {
            *cache = Some(self.load_cache(&snapshot.config, snapshot.updated_at_ms)?);
        }
        let cache = cache.as_ref().expect("TLS trust cache initialized");
        Ok(TlsTrustMaterial {
            roots: cache.roots.clone(),
            host_certificate: cache.host_certificates.get(&authority).cloned(),
        })
    }

    pub fn trust_tls_host(
        &self,
        host: &str,
        port: u16,
        certificate: &CertificateDer<'_>,
    ) -> io::Result<()> {
        let _mutation = self
            .0
            .mutation
            .lock()
            .map_err(|_| io::Error::other("trust configuration lock poisoned"))?;
        let authority = trust_authority(host, port);
        let fingerprint = crate::certificate::fingerprint(certificate);
        let snapshot = self.0.runtime.snapshot();
        let mut config = (*snapshot.config).clone();
        if let Some(existing) = config
            .root_certificates
            .iter()
            .find(|item| item.host.as_deref() == Some(authority.as_str()))
        {
            if !existing.enabled {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("TLS host trust is disabled for {authority}"),
                ));
            }
            if existing.fingerprint.eq_ignore_ascii_case(&fingerprint) {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("TLS certificate changed for {authority}"),
            ));
        }
        config_store::import_root_certificates_from_der(
            &self.0.config_path,
            self.0.password.as_slice(),
            std::slice::from_ref(certificate),
        )
        .map_err(io::Error::other)?;
        config.root_certificates.push(RootCertificate {
            uuid: new_config_uuid(),
            fingerprint: fingerprint.clone(),
            host: Some(authority.clone()),
            enabled: true,
        });
        self.persist(config)?;
        self.0.audit.system_event(
            "tls_host_trusted_first_use",
            json!({"host": authority, "fingerprint": fingerprint}),
        );
        Ok(())
    }

    pub fn trust_ssh_host(
        &self,
        host: &str,
        port: u16,
        key_type: &str,
        key_blob: &str,
    ) -> io::Result<()> {
        let _mutation = self
            .0
            .mutation
            .lock()
            .map_err(|_| io::Error::other("trust configuration lock poisoned"))?;
        let authority = trust_authority(host, port);
        let snapshot = self.0.runtime.snapshot();
        let mut config = (*snapshot.config).clone();
        if let Some(existing) = config
            .ssh_host_keys
            .iter()
            .find(|item| item.host.eq_ignore_ascii_case(&authority))
        {
            if !existing.enabled {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("SSH host trust is disabled for {authority}"),
                ));
            }
            if existing.key_type == key_type && existing.key_blob == key_blob {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("SSH host key changed for {authority}"),
            ));
        }
        config.ssh_host_keys.push(SshHostKey {
            uuid: new_config_uuid(),
            host: authority.clone(),
            key_type: key_type.to_owned(),
            key_blob: key_blob.to_owned(),
            enabled: true,
        });
        self.persist(config)?;
        self.0.audit.system_event(
            "ssh_host_trusted_first_use",
            json!({"host": authority, "key_type": key_type}),
        );
        Ok(())
    }

    fn persist(&self, config: Config) -> io::Result<()> {
        config.validate().map_err(io::Error::other)?;
        config_store::save_encrypted_with_descriptor(
            &self.0.config_path,
            &config,
            self.0.password.as_slice(),
            &self.0.descriptor,
        )
        .map_err(io::Error::other)?;
        let prepared = self
            .0
            .runtime
            .prepare_update(Arc::new(config))
            .map_err(io::Error::other)?;
        self.0.runtime.commit_update(prepared);
        *self
            .0
            .cache
            .lock()
            .map_err(|_| io::Error::other("TLS trust cache poisoned"))? = None;
        Ok(())
    }

    fn load_cache(&self, config: &Config, version: u64) -> io::Result<TrustCache> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut host_certificates = HashMap::new();
        for item in config.root_certificates.iter().filter(|item| item.enabled) {
            let certificate = config_store::read_root_certificate(
                &self.0.config_path,
                self.0.password.as_slice(),
                &item.fingerprint,
            )
            .map_err(io::Error::other)?;
            if let Some(host) = item.host.as_deref() {
                host_certificates.insert(host.to_ascii_lowercase(), certificate);
            } else {
                roots.add(certificate).map_err(|error| {
                    io::Error::other(format!("root certificate could not be trusted: {error}"))
                })?;
            }
        }
        Ok(TrustCache {
            version,
            roots: Arc::new(roots),
            host_certificates,
        })
    }
}

pub fn trust_authority(host: &str, port: u16) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    #[test]
    fn first_use_trust_persists_tls_and_ssh_and_rejects_changes() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-trust-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.bin");
        let password = b"trust-test-password";
        let mut config = Config::default();
        config.apply_managed_audit_paths(&path);
        config_store::save_encrypted(&path, &config, password).unwrap();
        let unlocked = config_store::load_encrypted(&path, password).unwrap();
        let runtime = RuntimeState::new(Arc::new(unlocked.config)).unwrap();
        let audit = AuditWriter::open(None).unwrap();
        let store = TrustStore::new(
            path.clone(),
            password.to_vec(),
            unlocked.descriptor,
            runtime,
            audit,
        );

        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        store
            .trust_tls_host("localhost", 8443, certificate.der())
            .unwrap();
        let material = store.tls_material("localhost", 8443).unwrap();
        assert_eq!(
            material.host_certificate.unwrap().as_ref(),
            certificate.der().as_ref()
        );
        let other_key = KeyPair::generate().unwrap();
        let other = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&other_key)
            .unwrap();
        assert!(store
            .trust_tls_host("localhost", 8443, other.der())
            .is_err());

        store
            .trust_ssh_host("localhost", 2222, "ssh-ed25519", "first-key")
            .unwrap();
        assert!(store
            .trust_ssh_host("localhost", 2222, "ssh-ed25519", "second-key")
            .is_err());
        let saved = config_store::load_encrypted(&path, password)
            .unwrap()
            .config;
        assert_eq!(saved.root_certificates.len(), 1);
        assert_eq!(
            saved.root_certificates[0].host.as_deref(),
            Some("localhost:8443")
        );
        assert_eq!(saved.ssh_host_keys[0].host, "localhost:2222");
        std::fs::remove_dir_all(root).ok();
    }
}
