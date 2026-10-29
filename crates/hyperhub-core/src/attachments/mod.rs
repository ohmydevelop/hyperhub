//! Human-approved process attachment transactions. Runtime API keys do not
//! create the password-derived signing authority used by this module.
mod authority;
mod capabilities;
mod completion_evidence;
mod configuration;
mod enrollment_origins;
mod host_command_client;
mod key_rotation;
mod manager;
mod operation;
mod preparation;
mod process;
mod root_image;
mod startup_cleanup;
mod store;
mod transport;
mod trust;
mod types;
pub use authority::*;
pub use capabilities::*;
pub(crate) use completion_evidence::{finalize_durable_completion, record_operation_acceptance};
pub use configuration::*;
pub use host_command_client::*;
pub(crate) use host_command_client::{execute_detach_barrier_plan, DETACH_BARRIER_BATCH_LIMIT};
pub use key_rotation::prepare_runtime_key_rotation;
pub use manager::*;
pub use operation::*;
pub use preparation::*;
pub(crate) use preparation::{save_abort_receipt, verify_preparation};
pub use process::*;
pub use root_image::manager_root_image;
pub(crate) use root_image::{
    adopt_manager_root_image, challenged_root_image, initialize_root_image, observe_root_exec,
    remember_manager_root_image, restore_root_image, root_image_profile, root_image_state,
    under_root_image_scope, verify_root_image_bootstrap, verify_root_image_scope,
};
pub(crate) use startup_cleanup::verify_unstarted;
pub use startup_cleanup::*;
pub use store::*;
pub use transport::*;
pub(crate) use trust::require_initial_mutation_gate;
pub use trust::*;
pub(crate) use trust::{
    apply_preparation, pin_approval_continuity, register_initial_preparation,
    sign_accepted_operation,
};
pub use types::*;

use sha2::{Digest, Sha256};

pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn new_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuccessorAttachmentState {
    trust: trust::CoreTrustTransfer,
    roots: Vec<u8>,
}
pub(crate) fn export_successor_state(
    directory: &std::path::Path,
) -> Result<SuccessorAttachmentState, String> {
    Ok(SuccessorAttachmentState {
        trust: trust::export_successor(directory)?,
        roots: root_image::export_successor(directory)?,
    })
}
pub(crate) fn import_successor_state(
    directory: &std::path::Path,
    state: SuccessorAttachmentState,
) -> Result<(), String> {
    // This child has not published a listener. Any failure aborts its startup;
    // partially imported memory can never serve a management request.
    root_image::import_successor(directory, &state.roots)?;
    trust::import_successor(directory, state.trust)
}

pub(crate) fn validate_successor_configuration(
    state: &SuccessorAttachmentState,
    config: &std::path::Path,
    unlocked: &crate::config_store::UnlockedConfig,
) -> Result<(), String> {
    trust::validate_successor_configuration(&state.trust, config, unlocked)
}

pub(crate) fn validate_successor_parent(
    state: &SuccessorAttachmentState,
    parent: &ProcessIdentity,
    child: &ProcessIdentity,
) -> Result<(), String> {
    trust::validate_successor_parent(&state.trust, parent, child)
}
