//! Recovery envelopes outlive password generations. Only runtime envelope keys
//! are wrapped here; password-derived approval signing seeds are never persisted.
use crate::config_store::{self, ConfigKeyring, KdfDescriptor, UnlockedApprovalState};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};
#[derive(Serialize, Deserialize)]
struct RetiredKey {
    descriptor: KdfDescriptor,
    master: Vec<u8>,
}
impl Drop for RetiredKey {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}
#[derive(Default, Serialize, Deserialize)]
struct KeyHistory {
    keys: Vec<RetiredKey>,
}
fn journal(base: &Path, descriptor: &KdfDescriptor) -> PathBuf {
    let id: String = descriptor
        .config_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    base.join(format!("runtime-keys-{id}.bin"))
}
/// Called with a verified old administrator password before the config save.
/// Each generation gets its own atomic journal, so a failed config save leaves
/// the old generation's journal readable and retry does not lose recovery keys.
pub fn prepare_runtime_key_rotation(
    config_path: &Path,
    old_password: &[u8],
    new_password: &[u8],
    next: &KdfDescriptor,
) -> Result<(), String> {
    let Some(parent) = config_path.parent() else {
        return Ok(());
    };
    let base = parent.join("runtime").join("attachments");
    if !base.exists() {
        return Ok(());
    }
    let old = ConfigKeyring::derive(
        old_password,
        config_store::read_descriptor(config_path).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    config_store::load_encrypted_with_keyring(config_path, &old).map_err(|e| e.to_string())?;
    if next.config_id == old.descriptor().config_id {
        return Err(
            "runtime key rotation requires a new configuration generation identifier".into(),
        );
    }
    let new = ConfigKeyring::derive(new_password, next.clone()).map_err(|e| e.to_string())?;
    let path = journal(&base, old.descriptor());
    let mut history = if path.exists() {
        let state = config_store::load_approval_state_with_keyring(&path, &old)
            .map_err(|e| e.to_string())?;
        serde_json::from_slice::<KeyHistory>(&state.bytes).map_err(|e| e.to_string())?
    } else {
        KeyHistory::default()
    };
    if !history
        .keys
        .iter()
        .any(|k| &k.descriptor == old.descriptor())
    {
        history.keys.push(RetiredKey {
            descriptor: old.descriptor().clone(),
            master: old.runtime_master().to_vec(),
        });
    }
    // Keep only keys which still protect an actual recorded backend envelope.
    let mut required = Vec::new();
    for entry in std::fs::read_dir(&base).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_name().to_str().is_some_and(super::valid_id) {
            for name in ["execution.bin", "recovery.bin"] {
                let path = entry.path().join(name);
                if path.exists() {
                    required.push(config_store::read_descriptor(&path).map_err(|e| e.to_string())?);
                }
            }
        }
    }
    history
        .keys
        .retain(|key| required.contains(&key.descriptor));
    if history.keys.len() > 64 {
        return Err("too many unresolved runtime-key generations; complete attachment cleanup before rotating again".into());
    }
    let bytes = Zeroizing::new(serde_json::to_vec(&history).map_err(|e| e.to_string())?);
    config_store::save_approval_state_with_keyring(&journal(&base, next), &bytes, &new)
        .map_err(|e| e.to_string())
}
pub(super) fn load_runtime_envelope(
    directory: &Path,
    name: &str,
    keyring: &ConfigKeyring,
) -> Result<UnlockedApprovalState, String> {
    let path = directory.join(name);
    match config_store::load_approval_state_with_keyring(&path, keyring) {
        Ok(state) => Ok(state),
        Err(original) => {
            let base = directory
                .parent()
                .ok_or("runtime state has no instance directory")?;
            let state = config_store::load_approval_state_with_keyring(
                &journal(base, keyring.descriptor()),
                keyring,
            )
            .map_err(|_| original.to_string())?;
            let history: KeyHistory =
                serde_json::from_slice(&state.bytes).map_err(|e| e.to_string())?;
            let descriptor = config_store::read_descriptor(&path).map_err(|e| e.to_string())?;
            let key = history
                .keys
                .iter()
                .find(|k| k.descriptor == descriptor)
                .ok_or_else(|| original.to_string())?;
            let retired =
                ConfigKeyring::from_runtime_master(descriptor, Zeroizing::new(key.master.clone()))
                    .map_err(|e| e.to_string())?;
            config_store::load_approval_state_with_keyring(&path, &retired)
                .map_err(|e| e.to_string())
        }
    }
}
