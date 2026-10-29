use hyperhub_core::{
    config::Config,
    config_document::ConfigDocument,
    config_persistence::{
        configuration_digest, offline_configuration_guard, ConfigPersistenceSigner,
    },
    config_store::{self, ConfigKeyring},
};
use std::path::Path;

/// One persistence route for interactive configuration and approved patches.
/// A running Core validates before touching disk and owns runtime publication.
pub(crate) fn save(
    path: &Path,
    expected: Option<&Config>,
    config: &Config,
    keyring: &ConfigKeyring,
    signer: Option<&ConfigPersistenceSigner>,
    live: bool,
) -> Result<bool, String> {
    if !live {
        let guard = offline_configuration_guard(path, config)?;
        let warning =
            config_store::save_encrypted_with_keyring_guarded(path, config, keyring, &guard)
                .map_err(|e| e.to_string())?;
        if let Some(warning) = warning {
            eprintln!("hyperhub: configuration committed, but the redacted display could not be refreshed: {warning}");
        }
        return Ok(false);
    }
    let signer = signer.ok_or("live configuration persistence requires password authorization")?;
    let current;
    let expected = match expected {
        Some(expected) => expected,
        None => {
            current = config_store::load_encrypted_with_keyring(path, keyring)
                .map_err(|e| e.to_string())?
                .config;
            &current
        }
    };
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let endpoint = hyperhub_core::control::discovery_control_endpoint();
    let (_, _, core_epoch) = runtime.block_on(hyperhub_core::control::configuration_revision(
        &endpoint, path,
    ))?;
    let authorization = signer.authorize(
        path,
        keyring.descriptor(),
        core_epoch,
        configuration_digest(expected)?,
        config,
        hyperhub_core::session::unix_timestamp_ms(),
    )?;
    let config_json =
        serde_json::to_string(&ConfigDocument::from_config(config)).map_err(|e| e.to_string())?;
    let warning = runtime.block_on(hyperhub_core::control::persist_configuration(
        &endpoint,
        path,
        authorization,
        config_json,
    ))?;
    if let Some(warning) = warning {
        eprintln!("hyperhub: configuration committed with a warning: {warning}");
    }
    Ok(true)
}
