//! A resident may finish unloading while its human approval is being reviewed.
//! Terminal attachment ids never receive a new session, token or consumption epoch.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Replan {
    Unchanged,
    AttachTerminal { superseded_request_id: String },
    DetachRecovery { superseded_request_id: String },
}

impl Replan {
    pub(super) fn superseded_request_id(&self) -> Option<&str> {
        match self {
            Self::Unchanged => None,
            Self::AttachTerminal {
                superseded_request_id,
            }
            | Self::DetachRecovery {
                superseded_request_id,
            } => Some(superseded_request_id),
        }
    }

    pub(super) fn fresh_review_reason(&self) -> Option<&'static str> {
        matches!(self, Self::DetachRecovery { .. })
            .then_some("attachment_manager_exited_during_review")
    }
}

enum Replacement {
    AttachTerminal(Request),
    DetachRecovery(Request),
}

fn replacement(
    request: &Request,
    record: &attachments::Record,
    recovery_binding: impl FnOnce(
        &attachments::Record,
    ) -> Result<Option<attachments::RecoveryBinding>, String>,
) -> Result<Option<Replacement>, String> {
    if let Action::Detach { recovery, .. } = &request.action {
        if recovery.is_some() {
            return Ok(None);
        }
        let Some(binding) = recovery_binding(record)? else {
            return Ok(None);
        };
        let mut next = request.clone();
        next.id = attachments::new_id();
        next.created_at_ms = unix_timestamp_ms();
        let Action::Detach { recovery, .. } = &mut next.action else {
            unreachable!()
        };
        *recovery = Some(binding);
        return Ok(Some(Replacement::DetachRecovery(next)));
    }
    let Action::Attach { spec } = &request.action else {
        return Ok(None);
    };
    if !matches!(record.phase, Phase::Detached | Phase::Exited) {
        return Ok(None);
    }
    if record.spec.id != spec.id
        || record.spec.target != spec.target
        || record.spec.scope != spec.scope
        || record.spec.backend != spec.backend
    {
        return Err("attachment contract changed during review; submit a new proposal".into());
    }
    let mut next = request.clone();
    next.id = attachments::new_id();
    next.created_at_ms = unix_timestamp_ms();
    let Action::Attach { spec } = &mut next.action else {
        unreachable!()
    };
    // A physically new attachment starts its immutable identity at the image
    // the human actually reviewed, while preserving those review semantics.
    spec.target = spec.effective_target().clone();
    spec.current_target = None;
    spec.exec_epoch = 0;
    spec.id = attachments::new_id();
    spec.recovery = None;
    Ok(Some(Replacement::AttachTerminal(next)))
}

fn refresh_with(
    request: &mut Request,
    directory: &Path,
    recovery_binding: impl FnOnce(
        &attachments::Record,
    ) -> Result<Option<attachments::RecoveryBinding>, String>,
) -> Result<Replan, String> {
    let state = attachments::attachment_directory(directory, request.action.attachment_id())?;
    if !state.join("record.json").exists() {
        return Ok(Replan::Unchanged);
    }
    let record = attachments::load_record(&state)?;
    let Some(replacement) = replacement(request, &record, recovery_binding)? else {
        return Ok(Replan::Unchanged);
    };
    let superseded_request_id = request.id.clone();
    let (next, replan) = match replacement {
        Replacement::AttachTerminal(next) => (
            next,
            Replan::AttachTerminal {
                superseded_request_id,
            },
        ),
        Replacement::DetachRecovery(next) => (
            next,
            Replan::DetachRecovery {
                superseded_request_id,
            },
        ),
    };
    attachments::save_request(directory, &next)?;
    archive_request(directory, request, "superseded")?;
    match &replan {
        Replan::AttachTerminal { .. } => eprintln!("Previous attachment {} is fully unloaded or exited; using fresh attachment {} for the same target, scope, backend and policy. Request {} supersedes {}.",request.action.attachment_id(),next.action.attachment_id(),next.id,request.id),
        Replan::DetachRecovery { .. } => eprintln!("Attachment manager for {} exited; recovery cleanup requires a fresh approval. Request {} supersedes {}.",request.action.attachment_id(),next.id,request.id),
        Replan::Unchanged => unreachable!(),
    }
    *request = next;
    Ok(replan)
}

pub(super) fn refresh(request: &mut Request, directory: &Path) -> Result<Replan, String> {
    refresh_with(request, directory, recovery::binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, Request, attachments::Record) {
        let directory =
            std::env::temp_dir().join(format!("hh-terminal-replan-{}", attachments::new_id()));
        let spec = Spec {
            exec_epoch: 0,
            current_target: None,
            id: attachments::new_id(),
            target: attachments::ProcessIdentity {
                pid: 42,
                birth: 9,
                executable: "fixture".into(),
                executable_sha256: "ab".repeat(32),
                owner: "fixture-owner".into(),
            },
            scope: Scope::Tree,
            backend: Backend::Ptrace,
            policy_digest: "cd".repeat(32),
            capabilities: Default::default(),
            recovery: None,
        };
        let record = attachments::create_record(&directory, spec.clone()).unwrap();
        let request = Request {
            schema_version: 1,
            id: attachments::new_id(),
            instance_id: "ef".repeat(32),
            created_at_ms: 1,
            action: Action::Attach { spec },
        };
        attachments::save_request(&directory, &request).unwrap();
        (directory, request, record)
    }

    fn detach_fixture(
        recovery: Option<attachments::RecoveryBinding>,
    ) -> (
        PathBuf,
        Request,
        attachments::Record,
        attachments::ProcessIdentity,
    ) {
        let (directory, attach_request, record) = fixture();
        std::fs::remove_file(attachments::request_path(&directory, &attach_request.id).unwrap())
            .unwrap();
        let manager = attachments::ProcessIdentity {
            pid: 84,
            birth: 12,
            executable: "fixture-manager".into(),
            executable_sha256: "12".repeat(32),
            owner: "fixture-owner".into(),
        };
        let state = attachments::attachment_directory(&directory, &record.spec.id).unwrap();
        let record = attachments::update_record(
            &state,
            &attachments::Outcome {
                phase: Phase::CleanupPending,
                members: vec![],
                manager: Some(manager.clone()),
                manager_endpoint: Some("fixture-manager-endpoint".into()),
                compatibility_reasons: vec![],
            },
        )
        .unwrap();
        let request = Request {
            schema_version: 1,
            id: attachments::new_id(),
            instance_id: attach_request.instance_id,
            created_at_ms: 2,
            action: Action::Detach {
                exec_epoch: record.spec.exec_epoch,
                attachment_id: record.spec.id.clone(),
                target: record.spec.target.clone(),
                policy_digest: record.spec.policy_digest.clone(),
                recovery,
            },
        };
        attachments::save_request(&directory, &request).unwrap();
        (directory, request, record, manager)
    }

    #[test]
    fn draining_to_terminal_during_review_allocates_fresh_ids_and_preserves_old_epoch() {
        let (directory, mut request, record) = fixture();
        let original = request.clone();
        let state = attachments::attachment_directory(&directory, &record.spec.id).unwrap();
        for phase in [Phase::Draining, Phase::Detached] {
            attachments::update_record(
                &state,
                &attachments::Outcome {
                    phase,
                    members: vec![],
                    manager: None,
                    manager_endpoint: None,
                    compatibility_reasons: vec![],
                },
            )
            .unwrap();
            if phase == Phase::Draining {
                assert_eq!(
                    refresh_with(&mut request, &directory, |_| Ok(None)).unwrap(),
                    Replan::Unchanged
                );
                assert_eq!(request, original);
            }
        }
        let old_receipt = state.join("old-epoch-sentinel");
        attachments::create_private_file(&old_receipt, b"old token and receipt epoch").unwrap();
        assert_eq!(
            refresh_with(&mut request, &directory, |_| Ok(None)).unwrap(),
            Replan::AttachTerminal {
                superseded_request_id: original.id.clone()
            }
        );
        assert_ne!(request.id, original.id);
        assert_ne!(
            request.action.attachment_id(),
            original.action.attachment_id()
        );
        let (Action::Attach { spec: old }, Action::Attach { spec: new }) =
            (&original.action, &request.action)
        else {
            unreachable!()
        };
        assert_eq!(old.target, new.target);
        assert_eq!(old.scope, new.scope);
        assert_eq!(old.backend, new.backend);
        assert_eq!(old.policy_digest, new.policy_digest);
        assert_eq!(old.capabilities, new.capabilities);
        assert_eq!(
            attachments::load_record(&state).unwrap().phase,
            Phase::Detached
        );
        assert_eq!(
            std::fs::read(old_receipt).unwrap(),
            b"old token and receipt epoch"
        );
        let fresh = attachments::create_record(&directory, new.clone()).unwrap();
        assert_ne!(fresh.session_id, record.session_id);
        assert!(directory
            .join("history")
            .join(format!("{}-superseded.json", original.id))
            .exists());
        assert!(attachments::load_request(&directory, &request.id).is_ok());
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn terminal_replan_never_changes_a_different_target_scope_or_backend() {
        let (directory, request, mut record) = fixture();
        record.phase = Phase::Detached;
        for change in 0..3 {
            let mut altered = record.clone();
            match change {
                0 => altered.spec.target.birth += 1,
                1 => altered.spec.scope = Scope::Process,
                _ => altered.spec.backend = Backend::Gum,
            };
            assert!(replacement(&request, &altered, |_| Ok(None)).is_err());
        }
        record.phase = Phase::DetachedResident;
        assert!(replacement(&request, &record, |_| Ok(None))
            .unwrap()
            .is_none());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn dead_manager_replans_detach_as_recovery_and_requires_fresh_review() {
        let (directory, mut request, record, manager) = detach_fixture(None);
        let original = request.clone();
        let binding = attachments::RecoveryBinding {
            manager: manager.clone(),
            context_digest: "34".repeat(32),
        };

        let replan = refresh_with(&mut request, &directory, |loaded| {
            assert_eq!(loaded.spec.id, record.spec.id);
            assert_eq!(loaded.manager.as_ref(), Some(&manager));
            Ok(Some(binding.clone()))
        })
        .unwrap();

        assert_eq!(
            replan,
            Replan::DetachRecovery {
                superseded_request_id: original.id.clone()
            }
        );
        assert_eq!(
            replan.fresh_review_reason(),
            Some("attachment_manager_exited_during_review")
        );
        assert_ne!(request.id, original.id);
        assert_eq!(request.instance_id, original.instance_id);
        let (
            Action::Detach {
                exec_epoch: old_epoch,
                attachment_id: old_attachment,
                target: old_target,
                policy_digest: old_policy,
                recovery: None,
            },
            Action::Detach {
                exec_epoch: new_epoch,
                attachment_id: new_attachment,
                target: new_target,
                policy_digest: new_policy,
                recovery: Some(new_binding),
            },
        ) = (&original.action, &request.action)
        else {
            panic!("expected detach requests")
        };
        assert_eq!(new_epoch, old_epoch);
        assert_eq!(new_attachment, old_attachment);
        assert_eq!(new_target, old_target);
        assert_eq!(new_policy, old_policy);
        assert_eq!(new_binding, &binding);
        assert!(!attachments::request_path(&directory, &original.id)
            .unwrap()
            .exists());
        assert!(directory
            .join("history")
            .join(format!("{}-superseded.json", original.id))
            .exists());
        assert_eq!(attachments::requests(&directory).unwrap(), vec![request]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn live_manager_leaves_detach_request_and_human_review_unchanged() {
        let (directory, mut request, _, _) = detach_fixture(None);
        let original = request.clone();

        assert_eq!(
            refresh_with(&mut request, &directory, |_| Ok(None)).unwrap(),
            Replan::Unchanged
        );
        assert_eq!(request, original);
        assert_eq!(attachments::requests(&directory).unwrap(), vec![original]);
        assert!(!directory.join("history").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn existing_recovery_binding_is_never_replanned_for_a_changed_manager() {
        let approved_manager = attachments::ProcessIdentity {
            pid: 83,
            birth: 11,
            executable: "approved-manager".into(),
            executable_sha256: "56".repeat(32),
            owner: "fixture-owner".into(),
        };
        let approved_binding = attachments::RecoveryBinding {
            manager: approved_manager,
            context_digest: "78".repeat(32),
        };
        let (directory, mut request, _, current_manager) =
            detach_fixture(Some(approved_binding.clone()));
        assert_ne!(approved_binding.manager, current_manager);
        let original = request.clone();

        let replan = refresh_with(
            &mut request,
            &directory,
            |_| -> Result<Option<attachments::RecoveryBinding>, String> {
                panic!("an approved recovery binding must never be replaced")
            },
        )
        .unwrap();

        assert_eq!(replan, Replan::Unchanged);
        assert_eq!(request, original);
        assert_eq!(attachments::requests(&directory).unwrap(), vec![original]);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
