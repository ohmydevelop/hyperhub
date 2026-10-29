use super::*;
const INSTANCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const POLICY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        Self {
            root: std::env::temp_dir().join(format!("hh-stale-queue-{}", attachments::new_id())),
        }
    }
    fn request(&self, slot: &str, epoch: u64, created: u64) -> Request {
        Request {
            schema_version: 1,
            id: attachments::new_id(),
            instance_id: INSTANCE.into(),
            created_at_ms: created,
            action: Action::Detach {
                exec_epoch: epoch,
                attachment_id: slot.into(),
                target: attachments::ProcessIdentity {
                    pid: 42,
                    birth: 9,
                    executable: "unit-target".into(),
                    executable_sha256: "cd".repeat(32),
                    owner: "unit-owner".into(),
                },
                policy_digest: POLICY.into(),
                recovery: None,
            },
        }
    }
    fn save(&self, request: &Request) {
        attachments::save_request(&self.root, request).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn stale_epoch_is_archived_byte_exactly_without_blocking_config_queue_or_reapproval() {
    let f = Fixture::new();
    let request = f.request(&attachments::new_id(), 0, 1);
    f.save(&request);
    let pending_path = attachments::request_path(&f.root, &request.id).unwrap();
    let original = std::fs::read(&pending_path).unwrap();
    let config = f.root.join("config.bin").with_extension("approval.json");
    let config_plan =
        b"{\"approval_token\":\"config-plan\",\"requests\":[{\"uuid\":\"exact-config-request\"}]}";
    attachments::create_private_file(&config, config_plan).unwrap();
    assert!(filter_pending(&f.root, INSTANCE, POLICY, |_| Ok(Some(1)))
        .unwrap()
        .is_empty());
    assert!(!pending_path.exists());
    assert!(
        attachments::requests(&f.root).unwrap().is_empty(),
        "generic approve must now fall through to the untouched config approval"
    );
    assert_eq!(std::fs::read(&config).unwrap(), config_plan);
    assert_eq!(
        std::fs::read(
            f.root
                .join("history")
                .join(format!("{}-stale.json", request.id))
        )
        .unwrap(),
        original
    );
    let audit = attachments::stale_request_audit(&f.root, &request.id)
        .unwrap()
        .unwrap();
    assert_eq!(
        audit.reason,
        StaleRequestReason::ExecutableEpochChanged {
            expected: 0,
            current: 1
        }
    );
    assert!(archived_error(&f.root, &request.id)
        .unwrap()
        .unwrap()
        .contains("stale and archived"));
    let guard = attachments::OperationGuard::acquire(&f.root).unwrap();
    attachments::archive_stale_request(
        &f.root,
        &request,
        StaleRequestReason::ExecutableEpochChanged {
            expected: 0,
            current: 2,
        },
        &guard,
    )
    .unwrap();
    assert_eq!(
        attachments::stale_request_audit(&f.root, &request.id)
            .unwrap()
            .unwrap(),
        audit,
        "idempotence must preserve first terminal audit"
    );
    assert_eq!(
        std::fs::read_dir(f.root.join("history")).unwrap().count(),
        2
    );
}
#[test]
fn unavailable_core_or_profile_remains_pending_without_an_archive() {
    let f = Fixture::new();
    let request = f.request(&attachments::new_id(), 2, 1);
    f.save(&request);
    let path = attachments::request_path(&f.root, &request.id).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        filter_pending(&f.root, INSTANCE, POLICY, |_| Err(
            "Core temporarily unavailable".into()
        ))
        .unwrap(),
        vec![request.clone()]
    );
    let guard = attachments::OperationGuard::acquire(&f.root).unwrap();
    assert!(
        validate_selected(&f.root, &request, INSTANCE, POLICY, &guard, |_| Err(
            "profile read timeout".into()
        ))
        .unwrap_err()
        .contains("request remains pending")
    );
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(!f.root.join("history").exists());
}
#[test]
fn epoch_filter_is_per_attachment_slot_and_probes_each_slot_once() {
    let f = Fixture::new();
    let a = attachments::new_id();
    let b = attachments::new_id();
    let current = f.request(&a, 2, 1);
    let stale = f.request(&a, 1, 2);
    let other = f.request(&b, 0, 3);
    for request in [&current, &stale, &other] {
        f.save(request);
    }
    let mut calls = std::collections::HashMap::new();
    let pending = filter_pending(&f.root, INSTANCE, POLICY, |request| {
        *calls
            .entry(request.action.attachment_id().to_owned())
            .or_insert(0) += 1;
        Ok(Some(if request.action.attachment_id() == a {
            2
        } else {
            0
        }))
    })
    .unwrap();
    assert_eq!(pending, vec![current, other]);
    assert_eq!(calls.get(&a), Some(&1));
    assert_eq!(calls.get(&b), Some(&1));
    assert_eq!(
        attachments::stale_request_audit(&f.root, &stale.id)
            .unwrap()
            .unwrap()
            .reason,
        StaleRequestReason::ExecutableEpochChanged {
            expected: 1,
            current: 2
        }
    );
}
#[test]
fn selected_request_is_rechecked_under_guard_after_human_review() {
    let f = Fixture::new();
    let request = f.request(&attachments::new_id(), 4, 1);
    f.save(&request);
    let guard = attachments::OperationGuard::acquire(&f.root).unwrap();
    validate_selected(&f.root, &request, INSTANCE, POLICY, &guard, |_| Ok(Some(4))).unwrap();
    assert!(
        validate_selected(&f.root, &request, INSTANCE, POLICY, &guard, |_| Ok(Some(5)))
            .unwrap_err()
            .contains("stale and archived")
    );
    assert!(attachments::requests(&f.root).unwrap().is_empty());
    assert_eq!(
        attachments::stale_request_audit(&f.root, &request.id)
            .unwrap()
            .unwrap()
            .reason,
        StaleRequestReason::ExecutableEpochChanged {
            expected: 4,
            current: 5
        }
    );
}
#[test]
fn confirmed_policy_and_instance_changes_do_not_depend_on_core_availability() {
    let f = Fixture::new();
    let mut instance = f.request(&attachments::new_id(), 0, 1);
    instance.instance_id = "ef".repeat(32);
    let mut policy = f.request(&attachments::new_id(), 0, 2);
    if let Action::Detach { policy_digest, .. } = &mut policy.action {
        *policy_digest = "01".repeat(32);
    }
    f.save(&instance);
    f.save(&policy);
    assert!(filter_pending(&f.root, INSTANCE, POLICY, |_| panic!(
        "changed local binding must not query Core"
    ))
    .unwrap()
    .is_empty());
    assert_eq!(
        attachments::stale_request_audit(&f.root, &instance.id)
            .unwrap()
            .unwrap()
            .reason,
        StaleRequestReason::InstanceChanged
    );
    assert_eq!(
        attachments::stale_request_audit(&f.root, &policy.id)
            .unwrap()
            .unwrap()
            .reason,
        StaleRequestReason::PolicyChanged
    );
}
#[test]
fn archival_cannot_use_another_guard_or_remove_a_replaced_proposal() {
    let f = Fixture::new();
    let request = f.request(&attachments::new_id(), 0, 1);
    f.save(&request);
    let other = Fixture::new();
    let wrong = attachments::OperationGuard::acquire(&other.root).unwrap();
    assert!(attachments::archive_stale_request(
        &f.root,
        &request,
        StaleRequestReason::PolicyChanged,
        &wrong
    )
    .unwrap_err()
    .contains("another operation namespace"));
    let guard = attachments::OperationGuard::acquire(&f.root).unwrap();
    let mut changed = request.clone();
    changed.created_at_ms += 1;
    let path = attachments::request_path(&f.root, &request.id).unwrap();
    config_store::save_private_bytes(&path, &serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(attachments::archive_stale_request(
        &f.root,
        &request,
        StaleRequestReason::PolicyChanged,
        &guard
    )
    .unwrap_err()
    .contains("changed before stale archive"));
    assert_eq!(
        attachments::load_request(&f.root, &request.id).unwrap(),
        changed
    );
    assert!(!f.root.join("history").exists());
}
