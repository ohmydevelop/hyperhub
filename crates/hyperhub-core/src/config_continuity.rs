//! Continuity metadata is committed with configuration ciphertext. No separate
//! candidate file can make an unsuccessful password save an accepted root.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use hyperhub_runtime::attachment::{self as wire, SignedApprovalRootTransition};
const METADATA: &str = "_hyperhub_approval_continuity";

pub(super) fn decode(
    bytes: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<SignedApprovalRootTransition>), StoreError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| StoreError::Format("configuration TOML is not UTF-8".into()))?;
    let mut value: toml::Value = toml::from_str(text)
        .map_err(|e| StoreError::Format(format!("invalid configuration: {e}")))?;
    let metadata = value
        .as_table_mut()
        .and_then(|table| table.remove(METADATA));
    let chain = match metadata {
        None => Vec::new(),
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| StoreError::Format("invalid approval continuity metadata".into()))?;
            serde_json::from_str(text)
                .map_err(|_| StoreError::Format("invalid approval continuity metadata".into()))?
        }
    };
    Ok((Zeroizing::new(toml::to_string(&value)?.into_bytes()), chain))
}
pub(super) fn encode(
    document: &ConfigDocument,
    chain: &[SignedApprovalRootTransition],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let mut value = toml::Value::try_from(document)?;
    if !chain.is_empty() {
        value
            .as_table_mut()
            .ok_or_else(|| StoreError::Format("invalid configuration document".into()))?
            .insert(
                METADATA.into(),
                toml::Value::String(serde_json::to_string(chain)?),
            );
    }
    Ok(Zeroizing::new(toml::to_string_pretty(&value)?.into_bytes()))
}
fn signing_key(password: &[u8], descriptor: &KdfDescriptor) -> Result<SigningKey, StoreError> {
    let seed = derive_password_approval_seed(password, descriptor)?;
    let seed: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Authentication)?;
    Ok(SigningKey::from_bytes(seed))
}
impl ConfigKeyring {
    /// Requires the real old password and validates the exact persisted config.
    /// The returned ring has no private approval seed, only dual-signed metadata.
    pub fn with_password_rotation(
        mut self,
        path: &Path,
        old_password: &[u8],
        new_password: &[u8],
    ) -> Result<Self, StoreError> {
        let old = load_encrypted(path, old_password)?;
        let previous = signing_key(old_password, &old.descriptor)?;
        let next = signing_key(new_password, &self.descriptor)?;
        if self.approval_public_key != Some(next.verifying_key().to_bytes())
            || old.descriptor.config_id == self.descriptor.config_id
        {
            return Err(StoreError::Format(
                "password rotation generation is invalid".into(),
            ));
        }
        let mut chain = old.approval_continuity;
        if !chain.is_empty() {
            let (key, _, id) = wire::verify_approval_root_chain(
                &crate::attachments::instance_id(path, &old.descriptor),
                &chain,
            )
            .map_err(|e| StoreError::Format(e.to_string()))?;
            if key != previous.verifying_key().to_bytes() || id != old.descriptor.config_id {
                return Err(StoreError::Authentication);
            }
        }
        let transition = wire::ApprovalRootTransition {
            schema_version: 1,
            instance_id: crate::attachments::instance_id(path, &old.descriptor),
            generation: chain.len() as u64 + 1,
            previous_public_key: previous.verifying_key().to_bytes(),
            public_key: next.verifying_key().to_bytes(),
            previous_config_id: old.descriptor.config_id,
            config_id: self.descriptor.config_id,
        };
        let bytes = wire::approval_transition_bytes(&transition)
            .map_err(|e| StoreError::Format(e.to_string()))?;
        chain.push(wire::SignedApprovalRootTransition {
            transition,
            previous_signature: previous.sign(&bytes).to_bytes().to_vec(),
            signature: next.sign(&bytes).to_bytes().to_vec(),
        });
        wire::verify_approval_root_chain(
            &crate::attachments::instance_id(path, &self.descriptor),
            &chain,
        )
        .map_err(|e| StoreError::Format(e.to_string()))?;
        self.approval_continuity = Some(chain);
        Ok(self)
    }
}
/// Sign only a typed nonce-bound metadata transition after authenticating the
/// current committed configuration with the real current password.
pub fn approval_rotation_certificate(
    path: &Path,
    password: &[u8],
    bootstrap: &wire::Bootstrap,
    challenge: &wire::ApprovalEnrollmentChallenge,
    now: u64,
) -> Result<wire::ApprovalRootCertificate, StoreError> {
    let config = load_encrypted(path, password)?;
    let instance = crate::attachments::instance_id(path, &config.descriptor);
    let key = signing_key(password, &config.descriptor)?;
    let (current, _, id) = wire::verify_approval_root_chain(&instance, &config.approval_continuity)
        .map_err(|e| StoreError::Format(e.to_string()))?;
    if instance != bootstrap.approval_instance_id
        || current != key.verifying_key().to_bytes()
        || id != config.descriptor.config_id
        || challenge.expires_at_ms <= now
        || challenge.expires_at_ms > now.saturating_add(60_000)
    {
        return Err(StoreError::Authentication);
    }
    let payload = wire::approval_rotation_enrollment_bytes(&wire::ApprovalRotationEnrollment {
        schema_version: 1,
        instance_id: instance,
        attachment_id: bootstrap.attachment_id.clone(),
        root_pid: bootstrap.root_pid,
        challenge: challenge.clone(),
        issued_at_ms: now,
        chain: config.approval_continuity,
    })
    .map_err(|e| StoreError::Format(e.to_string()))?;
    let signature = key.sign(&payload).to_bytes().to_vec();
    Ok(wire::ApprovalRootCertificate { payload, signature })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn committed_ciphertext_owns_history_and_failed_save_cannot_publish_a_candidate() {
        let root =
            std::env::temp_dir().join(format!("hh-continuity-{}", crate::attachments::new_id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("config.bin");
        let mut descriptor = new_descriptor();
        descriptor.memory_kib = 8192;
        descriptor.iterations = 1;
        let old = ConfigKeyring::derive(b"fixture-password-a", descriptor).unwrap();
        save_encrypted_with_keyring(&path, &Config::default(), &old).unwrap();
        let initial = load_encrypted(&path, b"fixture-password-a").unwrap();
        assert!(initial.approval_continuity.is_empty());
        let instance = crate::attachments::instance_id(&path, old.descriptor());
        let candidate = |old_password: &[u8], new_password: &[u8]| {
            let mut next = new_descriptor();
            next.memory_kib = 8192;
            next.iterations = 1;
            ConfigKeyring::derive(new_password, next)
                .unwrap()
                .with_password_rotation(&path, old_password, new_password)
                .unwrap()
        };
        let first = candidate(b"fixture-password-a", b"fixture-password-b");
        // A prepared ring is private RAM metadata. Merely preparing it cannot
        // publish a proof or change the decryptable config generation.
        assert_eq!(
            load_encrypted(&path, b"fixture-password-a")
                .unwrap()
                .descriptor,
            initial.descriptor
        );
        assert!(load_encrypted(&path, b"fixture-password-b").is_err());
        let blocked = root.join("destination-is-a-directory");
        std::fs::create_dir(&blocked).unwrap();
        let entries = || {
            std::fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>()
        };
        let before_failed_save = entries();
        assert!(save_encrypted_with_keyring(&blocked, &Config::default(), &first).is_err());
        assert_eq!(entries(), before_failed_save);
        assert!(load_encrypted(&path, b"fixture-password-a")
            .unwrap()
            .approval_continuity
            .is_empty());
        save_encrypted_with_keyring(&path, &Config::default(), &first).unwrap();
        let committed = load_encrypted(&path, b"fixture-password-b").unwrap();
        assert_eq!(committed.approval_continuity.len(), 1);
        assert_eq!(
            crate::attachments::instance_id(&path, &committed.descriptor),
            instance
        );
        let runtime =
            ConfigKeyring::from_runtime_master(first.descriptor().clone(), first.runtime_master())
                .unwrap();
        save_encrypted_with_keyring(&path, &Config::default(), &runtime).unwrap();
        assert_eq!(
            load_encrypted(&path, b"fixture-password-b")
                .unwrap()
                .approval_continuity,
            committed.approval_continuity
        );
        let second = candidate(b"fixture-password-b", b"fixture-password-c");
        save_encrypted_with_keyring(&path, &Config::default(), &second).unwrap();
        let final_config = load_encrypted(&path, b"fixture-password-c").unwrap();
        assert_eq!(final_config.approval_continuity.len(), 2);
        assert_eq!(
            wire::verify_approval_root_chain(&instance, &final_config.approval_continuity)
                .unwrap()
                .1,
            2
        );
        assert!(load_encrypted(&path, b"fixture-password-a").is_err());
        assert!(load_encrypted(&path, b"fixture-password-b").is_err());
        assert!(import(&path, Some(b"fixture-password-c")).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
