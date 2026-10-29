//! Configuration admission uses the live manager, never a displayed disk phase.
use super::{self as attachments, OperationGuard, Phase};
use crate::config::Config;
use std::path::{Path, PathBuf};

pub fn configuration_attachment_directory(config_path: &Path) -> Result<PathBuf, String> {
    Ok(config_path
        .parent()
        .ok_or("configuration has no parent directory")?
        .join("runtime")
        .join("attachments"))
}

/// Retain the returned guard until persistence and runtime publication finish.
/// Approval CLI owns the same guard across manager admission; an accepted
/// reactivation therefore cannot appear between this check and the write.
pub fn configuration_guard(directory: &Path, config: &Config) -> Result<OperationGuard, String> {
    let guard = OperationGuard::acquire(directory)?;
    validate_configuration_admission(directory, config, &guard)?;
    Ok(guard)
}
pub fn validate_configuration_admission(
    directory: &Path,
    config: &Config,
    guard: &OperationGuard,
) -> Result<(), String> {
    guard.protects(directory)?;
    for record in attachments::records(directory)? {
        let live_manager = record.manager.as_ref().is_some_and(|manager| {
            !attachments::process_incarnation_exited(manager.pid, manager.birth)
        });
        if !live_manager {
            let live_member = std::iter::once(record.effective_target())
                .chain(record.members.iter())
                .any(|member| attachments::process_birth(member.pid) == Some(member.birth));
            if !live_member
                && matches!(
                    record.phase,
                    Phase::Detached | Phase::Exited | Phase::Failed
                )
            {
                continue;
            }
            // Core must be able to start for an orphan's explicit recovery.
            // Missing provenance cannot authorize a less restrictive mode, but
            // a policy supported by *both* external backends is safe without
            // assuming this record's origin/backend fields are authoritative.
            for backend in [attachments::Backend::Gum, attachments::Backend::Ptrace] {
                attachments::dynamic_capabilities_for_origin(config, backend, attachments::Origin::Attach)
                    .require_supported().map_err(|error| format!("attachment {} lacks a live policy admission proof: {error}; recover before enabling this configuration", record.spec.id))?;
            }
            continue;
        }
        if matches!(
            record.phase,
            Phase::Preparing
                | Phase::Active
                | Phase::Detaching
                | Phase::Degraded
                | Phase::CleanupPending
        ) {
            let profile = attachments::root_image_profile(directory, &record.spec.id)
                .or_else(|_| attachments::manager_profile_for_record(&record))?;
            profile.validate_record(&record)?;
            if profile.origin == attachments::Origin::Attach {
                attachments::dynamic_capabilities_for_origin(
                    config,
                    record.spec.backend,
                    profile.origin,
                )
                .require_supported()?;
            }
            continue;
        }
        let admission =
            attachments::manager_policy_admission_for_record(&record).map_err(|error| {
                format!(
                    "attachment {} configuration admission: {error}",
                    record.spec.id
                )
            })?;
        if admission.policy_required && admission.profile.origin == attachments::Origin::Attach {
            attachments::dynamic_capabilities_for_origin(
                config,
                record.spec.backend,
                admission.profile.origin,
            )
            .require_supported()?;
        }
    }
    Ok(())
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;
    #[test]
    fn orphan_recovery_can_start_with_conservative_policy_but_disk_phase_cannot_enable_hostname_policy(
    ) {
        let root = std::env::temp_dir().join(format!("hh-orphan-config-{}", attachments::new_id()));
        let spec = attachments::Spec {
            id: attachments::new_id(),
            target: attachments::inspect_process(std::process::id()).unwrap(),
            current_target: None,
            exec_epoch: 0,
            scope: attachments::Scope::Tree,
            backend: attachments::Backend::Ptrace,
            policy_digest: "cd".repeat(32),
            capabilities: Default::default(),
            recovery: None,
        };
        let mut record = attachments::create_record(&root, spec).unwrap();
        let state = attachments::attachment_directory(&root, &record.spec.id).unwrap();
        let ordinary = Config::default();
        assert!(
            configuration_guard(&root, &ordinary).is_ok(),
            "safe Core startup must remain available for explicit recovery"
        );
        let mut named = ordinary.clone();
        named.rules.push(serde_json::from_value(serde_json::json!({"id":"hostname-rule","action":"deny","endpoints":[{"target":"example.test"}]})).unwrap());
        named.ensure_item_uuids();
        for phase in [
            Phase::Preparing,
            Phase::Active,
            Phase::DetachedResident,
            Phase::Detached,
            Phase::Exited,
            Phase::Failed,
        ] {
            record.phase = phase;
            record.origin = attachments::Origin::Run;
            crate::config_store::save_private_bytes(
                &state.join("record.json"),
                &serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
            assert!(
                configuration_guard(&root, &named).is_err(),
                "an orphan with a living incarnation has no trusted owned-mode or detach proof"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
