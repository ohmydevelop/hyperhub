use super::*;
fn snapshot(denied: &str, error_action: SandboxAction) -> Arc<CompiledFileSandboxSnapshot> {
    snapshot_for_operation(denied, FileSandboxOperation::Read, error_action)
}
fn snapshot_for_operation(
    denied: &str,
    operation: FileSandboxOperation,
    error_action: SandboxAction,
) -> Arc<CompiledFileSandboxSnapshot> {
    Arc::new(
        compile_file_snapshot(FileSandboxSnapshot {
            default_action: SandboxAction::Pass,
            error_action,
            rules: vec![FileSandboxSnapshotRule {
                id: format!("deny-{denied}"),
                action: SandboxAction::Deny,
                patterns: vec![format!("^{denied}$")],
                operations: vec![operation],
                protection: None,
            }],
        })
        .unwrap(),
    )
}
fn decide(
    reader: &FilePolicyReader,
    path: &str,
    operation: FileSandboxOperation,
) -> (SandboxAction, Option<String>, String) {
    let Some(snapshot) = reader.snapshot.as_ref() else {
        return (reader.error_action(), None, "error".into());
    };
    let decision = hyperhub_engine::policy(
        &hyperhub_engine::resident().acquire(),
        hyperhub_engine::contract::FILE_POLICY,
        &hyperhub_engine::contract::PolicyInput {
            snapshot: snapshot.wire.clone(),
            target: path.into(),
            operation: format!("{operation:?}").to_ascii_lowercase(),
            command_line: String::new(),
        },
    )
    .unwrap();
    (
        if decision.action == "deny" {
            SandboxAction::Deny
        } else {
            SandboxAction::Pass
        },
        decision.rule_id,
        decision.source,
    )
}
#[test]
fn hot_update_between_requested_and_resolved_paths_cannot_combine_two_denials_into_pass() {
    let first = snapshot("A", SandboxAction::Deny);
    let second = snapshot("B", SandboxAction::Pass);
    let slot = Snapshot::from(Some(first));
    let reader = FilePolicyReader::from_snapshot(slot.load_full(), 1);
    // This is the actual former mixed-version result: B passes V1 and A passes
    // V2, while a complete V1 or V2 must reject this alias operation.
    assert_eq!(
        decide(&reader, "B", FileSandboxOperation::Read).0,
        SandboxAction::Pass
    );
    let new_reader = FilePolicyReader::from_snapshot(Some(second.clone()), 2);
    assert_eq!(
        decide(&new_reader, "A", FileSandboxOperation::Read).0,
        SandboxAction::Pass
    );
    let result = file_paths_decision(&reader, "B", FileSandboxOperation::Read, decide, |_, _| {
        slot.store(Some(second));
        Some("A".into())
    });
    assert_eq!(result.0, SandboxAction::Deny);
    assert_eq!(result.1.as_deref(), Some("deny-A"));
    assert_eq!(reader.version, 1);
    let current = FilePolicyReader::from_snapshot(slot.load_full(), 2);
    assert_eq!(
        file_paths_decision(&current, "B", FileSandboxOperation::Read, decide, |_, _| {
            Some("A".into())
        })
        .0,
        SandboxAction::Deny
    );
}
#[test]
fn captured_error_action_and_audit_version_survive_a_concurrent_publication() {
    let slot = Snapshot::from(Some(snapshot("A", SandboxAction::Deny)));
    let reader = FilePolicyReader::from_snapshot(slot.load_full(), 7);
    let result = reader.evaluate(|| {
        slot.store(Some(snapshot("B", SandboxAction::Pass)));
        panic!("fixture policy evaluation failure")
    });
    assert_eq!(result.0, SandboxAction::Deny);
    assert_eq!(result.2, "error");
    assert_eq!(reader.version, 7);
    let current = FilePolicyReader::from_snapshot(slot.load_full(), 8);
    assert_eq!(current.error_action(), SandboxAction::Pass);
    assert_eq!(current.version, 8);
}

#[test]
fn one_read_write_operation_cannot_combine_allowed_effects_from_two_denials() {
    let first = snapshot_for_operation("file", FileSandboxOperation::Write, SandboxAction::Deny);
    let second = snapshot_for_operation("file", FileSandboxOperation::Read, SandboxAction::Pass);
    let slot = Snapshot::from(Some(first));
    let reader = FilePolicyReader::from_snapshot(slot.load_full(), 11);
    assert_eq!(
        decide(&reader, "file", FileSandboxOperation::Read).0,
        SandboxAction::Pass
    );
    slot.store(Some(second));
    let current = FilePolicyReader::from_snapshot(slot.load_full(), 12);
    // Reacquiring for the second effect would allow both effects, even though
    // neither complete policy allows this read/write operation.
    assert_eq!(
        decide(&current, "file", FileSandboxOperation::Write).0,
        SandboxAction::Pass
    );
    assert_eq!(
        decide(&reader, "file", FileSandboxOperation::Write).0,
        SandboxAction::Deny
    );
    assert_eq!(
        decide(&current, "file", FileSandboxOperation::Read).0,
        SandboxAction::Deny
    );
    assert_eq!(reader.version, 11);
}

#[test]
fn one_namespace_operation_pins_the_source_and_destination_checks() {
    for (source_operation, destination_operation) in [
        (FileSandboxOperation::Rename, FileSandboxOperation::Create),
        (FileSandboxOperation::Read, FileSandboxOperation::Create),
    ] {
        let first =
            snapshot_for_operation("destination", destination_operation, SandboxAction::Deny);
        let second = snapshot_for_operation("source", source_operation, SandboxAction::Pass);
        let slot = Snapshot::from(Some(first));
        let reader = FilePolicyReader::from_snapshot(slot.load_full(), 21);
        assert_eq!(
            decide(&reader, "source", source_operation).0,
            SandboxAction::Pass
        );
        slot.store(Some(second));
        let current = FilePolicyReader::from_snapshot(slot.load_full(), 22);
        assert_eq!(
            decide(&current, "destination", destination_operation).0,
            SandboxAction::Pass
        );
        assert_eq!(
            decide(&reader, "destination", destination_operation).0,
            SandboxAction::Deny
        );
        assert_eq!(
            decide(&current, "source", source_operation).0,
            SandboxAction::Deny
        );
        assert_eq!(reader.version, 21);
    }
}
