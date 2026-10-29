//! Password-authorized configuration persistence. Runtime/API material cannot
//! sign this separate domain. The running Core owns validation, write and publish.
use crate::{
    config::Config,
    config_document::ConfigDocument,
    config_store::{self, ConfigKeyring, KdfDescriptor},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;

pub fn configuration_digest(config: &Config) -> Result<String, String> {
    let value = ConfigDocument::to_value(config).map_err(|e| e.to_string())?;
    Ok(crate::attachments::digest(
        &serde_json::to_vec(&value).map_err(|e| e.to_string())?,
    ))
}

/// Offline writes and Core startup share the approval-operation namespace.
/// Do not infer an offline instance from an unresponsive live Core socket.
pub fn offline_configuration_guard(
    path: &Path,
    config: &Config,
) -> Result<crate::attachments::OperationGuard, String> {
    let directory = crate::attachments::configuration_attachment_directory(path)?;
    let guard = crate::attachments::configuration_guard(&directory, config)?;
    let _core_absent = configuration_core_guard(path)?;
    if crate::attachments::process_attachment_identity_available()
        && crate::serve_lease::has_live_core(path)?
    {
        return Err(
            "a live Core owns this configuration; use live persistence or stop Serve".into(),
        );
    }
    Ok(guard)
}

fn configuration_core_guard(path: &Path) -> Result<crate::attachments::ManagerGuard, String> {
    let directory = path
        .parent()
        .ok_or("configuration has no parent")?
        .join("runtime")
        .join("configuration-core");
    crate::attachments::ManagerGuard::acquire(&directory)
        .map_err(|e| format!("a running Core owns configuration persistence; use live persistence or stop Serve: {e}"))
}

pub struct ConfigPersistenceSigner(SigningKey);
impl ConfigPersistenceSigner {
    pub fn from_password(password: &[u8], descriptor: &KdfDescriptor) -> Result<Self, String> {
        let seed = config_store::derive_password_approval_seed(password, descriptor)
            .map_err(|e| e.to_string())?;
        let mut bytes = Zeroizing::new([0; 32]);
        bytes.copy_from_slice(&seed);
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }
    pub fn authorize(
        &self,
        path: &Path,
        descriptor: &KdfDescriptor,
        core_epoch: [u8; 32],
        expected_digest: String,
        config: &Config,
        now: u64,
    ) -> Result<ConfigWriteAuthorization, String> {
        let mut authorization = ConfigWriteAuthorization {
            instance_id: crate::attachments::instance_id(path, descriptor),
            core_epoch,
            expected_digest,
            config_digest: configuration_digest(config)?,
            nonce: rand::random(),
            issued_at_ms: now,
            expires_at_ms: now
                .checked_add(30_000)
                .ok_or("configuration authorization time overflow")?,
            signature: Vec::new(),
        };
        authorization.signature = self
            .0
            .sign(&authorization.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(authorization)
    }
}
impl std::fmt::Debug for ConfigPersistenceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfigPersistenceSigner { key: <redacted> }")
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigWriteAuthorization {
    pub instance_id: String,
    pub core_epoch: [u8; 32],
    pub expected_digest: String,
    pub config_digest: String,
    pub nonce: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: Vec<u8>,
}
impl ConfigWriteAuthorization {
    fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let mut bytes = b"hyperhub/config-persistence/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?);
        Ok(bytes)
    }
    pub(crate) fn verify(
        &self,
        public_key: &[u8; 32],
        instance: &str,
        core_epoch: &[u8; 32],
        config: &Config,
        now: u64,
    ) -> Result<(), String> {
        if self.instance_id != instance
            || self.core_epoch == [0; 32]
            || &self.core_epoch != core_epoch
            || self.config_digest != configuration_digest(config)?
            || self.nonce == [0; 32]
            || self.issued_at_ms > now
            || self.expires_at_ms < now
            || self.expires_at_ms.checked_sub(self.issued_at_ms) != Some(30_000)
        {
            return Err(
                "configuration persistence authorization binding or lifetime mismatch".into(),
            );
        }
        let key = VerifyingKey::from_bytes(public_key).map_err(|e| e.to_string())?;
        let signature = Signature::from_slice(&self.signature).map_err(|e| e.to_string())?;
        key.verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| "invalid password-derived configuration persistence signature".into())
    }
}

pub(crate) struct ConfigurationStore {
    _owner: crate::attachments::ManagerGuard,
    pub(crate) path: PathBuf,
    pub(crate) keyring: ConfigKeyring,
    pub(crate) anchor: Option<[u8; 32]>,
    pub(crate) instance_id: String,
    pub(crate) core_epoch: [u8; 32],
    nonces: Mutex<HashMap<[u8; 32], u64>>,
    publication_warning: Mutex<Option<(String, String)>>,
}
impl ConfigurationStore {
    pub(crate) fn new(path: PathBuf, keyring: ConfigKeyring) -> Result<Self, String> {
        let owner = configuration_core_guard(&path)?;
        let unlocked = config_store::load_encrypted_with_keyring(&path, &keyring)
            .map_err(|e| e.to_string())?;
        let instance_id = crate::attachments::instance_id(&path, keyring.descriptor());
        let core_epoch = loop {
            let value = rand::random();
            if value != [0; 32] {
                break value;
            }
        };
        Ok(Self {
            _owner: owner,
            path,
            keyring,
            anchor: unlocked.approval_public_key,
            instance_id,
            core_epoch,
            nonces: Mutex::new(HashMap::new()),
            publication_warning: Mutex::new(None),
        })
    }
    pub(crate) fn consume(
        &self,
        authorization: &ConfigWriteAuthorization,
        config: &Config,
        now: u64,
    ) -> Result<(), String> {
        authorization.verify(&self.anchor.ok_or("configuration lacks a password-derived anchor; save it offline before using live persistence")?, &self.instance_id, &self.core_epoch, config, now)?;
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| "configuration authorization state unavailable")?;
        nonces.retain(|_, expires| *expires >= now);
        if nonces.len() >= 4096
            || nonces
                .insert(authorization.nonce, authorization.expires_at_ms)
                .is_some()
        {
            return Err(
                "configuration persistence authorization is used or the queue is full".into(),
            );
        }
        Ok(())
    }
    pub(crate) fn persisted_digest(&self) -> Result<String, String> {
        configuration_digest(
            &config_store::load_encrypted_with_keyring(&self.path, &self.keyring)
                .map_err(|e| e.to_string())?
                .config,
        )
    }
    pub(crate) fn record_publication(&self, digest: &str, warning: Option<&str>) {
        *self
            .publication_warning
            .lock()
            .expect("configuration publication state poisoned") =
            warning.map(|warning| (digest.into(), warning.into()));
    }
    pub(crate) fn publication_warning(&self, digest: &str) -> Option<String> {
        self.publication_warning
            .lock()
            .ok()?
            .as_ref()
            .filter(|(revision, _)| revision == digest)
            .map(|(_, message)| message.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persistence_signature_is_password_only_and_binds_revision_namespace_and_lifetime() {
        let mut descriptor = config_store::new_descriptor();
        descriptor.memory_kib = 8 * 1024;
        descriptor.iterations = 1;
        let password = b"private-config-test-password";
        let signer = ConfigPersistenceSigner::from_password(password, &descriptor).unwrap();
        let keyring = ConfigKeyring::derive(password, descriptor.clone()).unwrap();
        let config = Config::default();
        let path = std::env::temp_dir().join("private-config-signature.bin");
        let expected = configuration_digest(&config).unwrap();
        let authorization = signer
            .authorize(
                &path,
                &descriptor,
                [9; 32],
                expected.clone(),
                &config,
                1_000,
            )
            .unwrap();
        let instance = crate::attachments::instance_id(&path, &descriptor);
        let public_key = signer.0.verifying_key().to_bytes();
        authorization
            .verify(&public_key, &instance, &[9; 32], &config, 1_001)
            .unwrap();
        assert!(authorization
            .verify(&public_key, "other-instance", &[9; 32], &config, 1_001)
            .is_err());
        assert!(authorization
            .verify(&public_key, &instance, &[9; 32], &config, 999)
            .is_err());
        assert!(authorization
            .verify(&public_key, &instance, &[9; 32], &config, 31_001)
            .is_err());
        let mut edited = config.clone();
        edited.debug = true;
        assert!(authorization
            .verify(&public_key, &instance, &[9; 32], &edited, 1_001)
            .is_err());
        let mut changed = authorization.clone();
        changed.expected_digest.push('0');
        assert!(changed
            .verify(&public_key, &instance, &[9; 32], &config, 1_001)
            .is_err());
        let mut runtime_forgery = authorization;
        runtime_forgery.signature = crate::session::config_update_proof(
            &keyring.session_auth_key().unwrap(),
            &serde_json::to_string(&ConfigDocument::from_config(&config)).unwrap(),
        )
        .unwrap();
        assert!(runtime_forgery
            .verify(&public_key, &instance, &[9; 32], &config, 1_001)
            .is_err());
        assert!(format!("{signer:?}").contains("<redacted>"));
    }
}
