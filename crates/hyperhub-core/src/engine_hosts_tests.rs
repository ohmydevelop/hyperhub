use super::*;
use hyperhub_engine::host;

fn register(registry: &EngineHosts) -> Registration {
    registry
        .register(
            "test".into(),
            Backend::LinuxPtrace,
            1,
            2,
            3,
            Some(4),
            host::report(&hyperhub_engine::resident()).unwrap(),
        )
        .unwrap()
}
fn request(registration: &Registration, id: &str) -> OwnerCommand {
    OwnerCommand {
        request_id: id.into(),
        host_id: registration.id.clone(),
        issued_at_ms: 100_000,
        command: Command::Query,
    }
}
#[test]
fn owner_proof_binds_every_command_field_time_and_purpose() {
    let registry = EngineHosts::default();
    let host = register(&registry);
    let request = request(&host, "signed");
    let proof = request.proof(b"owner key").unwrap();
    for now in [70_000, 100_000, 130_000] {
        assert!(request.authenticate(b"owner key", &proof, now));
    }
    for now in [69_999, 130_001] {
        assert!(!request.authenticate(b"owner key", &proof, now));
    }
    assert!(!request.authenticate(b"wrong key", &proof, 100_000));
    assert!(!request.authenticate(b"owner key", &proof[..31], 100_000));
    let mut modified = request.clone();
    modified.command = Command::Observe;
    assert!(!modified.authenticate(b"owner key", &proof, 100_000));
    modified = request.clone();
    modified.host_id.push('a');
    assert!(!modified.authenticate(b"owner key", &proof, 100_000));
    modified = request.clone();
    modified.request_id.push('a');
    assert!(!modified.authenticate(b"owner key", &proof, 100_000));
    let config_proof = crate::session::config_update_proof(
        b"owner key",
        &serde_json::to_string(&request).unwrap(),
    )
    .unwrap();
    assert!(!request.authenticate(b"owner key", &config_proof, 100_000));
}
#[test]
fn acknowledgement_is_not_inferred_from_delivery_and_lost_results_are_unknown() {
    let registry = EngineHosts::default();
    let mut host = register(&registry);
    let request = request(&host, "idempotent");
    assert_eq!(
        registry.dispatch(request.clone()).unwrap().state,
        DeliveryState::Accepted
    );
    assert_eq!(
        registry.dispatch(request.clone()).unwrap().state,
        DeliveryState::Accepted
    );
    assert_eq!(host.receiver.try_recv().unwrap().request_id, "idempotent");
    assert!(host.receiver.try_recv().is_err());
    let mut conflict = request.clone();
    conflict.command = Command::Observe;
    assert!(registry.dispatch(conflict).is_err());
    assert!(registry.delivered("other-host", "idempotent").is_err());
    registry.delivered(&host.id, "idempotent").unwrap();
    assert_eq!(registry.commands()[0].state, DeliveryState::Delivered);
    drop(host);
    assert!(!registry.hosts()[0].online);
    assert_eq!(registry.commands()[0].state, DeliveryState::Unknown);
    assert!(registry.commands()[0].reply.is_none());
    assert_eq!(
        registry.dispatch(request).unwrap().state,
        DeliveryState::Unknown
    );
}
#[test]
fn queue_and_registration_limits_reject_without_consuming_new_ids() {
    let registry = EngineHosts::default();
    let mut host = register(&registry);
    assert!(registry
        .register(
            "test".into(),
            Backend::LinuxPtrace,
            1,
            2,
            3,
            Some(4),
            host::report(&hyperhub_engine::resident()).unwrap()
        )
        .is_err());
    for n in 0..16 {
        registry
            .dispatch(request(&host, &format!("q-{n}")))
            .unwrap();
    }
    let request = request(&host, "retry-when-space");
    assert!(registry.dispatch(request.clone()).is_err());
    assert_eq!(registry.commands().len(), 16);
    host.receiver.try_recv().unwrap();
    registry.dispatch(request).unwrap();
    assert_eq!(registry.commands().len(), 17);
}
#[test]
fn only_the_matching_acknowledgement_can_publish_a_snapshot_or_result() {
    let registry = EngineHosts::default();
    let host = register(&registry);
    registry.dispatch(request(&host, "ack")).unwrap();
    let ack = || Acknowledgement {
        request_id: "ack".into(),
        reply: Reply::Ok,
        snapshot: host::report(&hyperhub_engine::resident()).unwrap(),
    };
    assert!(registry.acknowledge(&host.id, ack(), false).is_err());
    registry.delivered(&host.id, "ack").unwrap();
    let mut wrong = ack();
    wrong.snapshot.host.state_schema += 1;
    assert!(registry.acknowledge(&host.id, wrong, false).is_err());
    assert_eq!(registry.commands()[0].state, DeliveryState::Delivered);
    registry.acknowledge(&host.id, ack(), false).unwrap();
    assert_eq!(registry.commands()[0].state, DeliveryState::Acknowledged);
    assert!(matches!(registry.commands()[0].reply, Some(Reply::Ok)));
    assert!(registry.acknowledge(&host.id, ack(), false).is_err());
    drop(host);
    assert_eq!(registry.commands()[0].state, DeliveryState::Acknowledged);
}

#[test]
fn command_history_rejects_new_work_when_full_without_evicting_idempotency() {
    let registry = EngineHosts::default();
    let mut host = register(&registry);
    let snapshot = host::report(&hyperhub_engine::resident()).unwrap();
    for n in 0..MAX_REQUESTS {
        let id = format!("history-{n}");
        registry.dispatch(request(&host, &id)).unwrap();
        assert_eq!(host.receiver.try_recv().unwrap().request_id, id);
        registry.delivered(&host.id, &id).unwrap();
        registry
            .acknowledge(
                &host.id,
                Acknowledgement {
                    request_id: id,
                    reply: Reply::Ok,
                    snapshot: snapshot.clone(),
                },
                false,
            )
            .unwrap();
    }
    assert!(registry.dispatch(request(&host, "new-id")).is_err());
    assert_eq!(
        registry
            .dispatch(request(&host, "history-0"))
            .unwrap()
            .state,
        DeliveryState::Acknowledged
    );
    assert!(host.receiver.try_recv().is_err());
    let mut oversized = request(&host, "oversized");
    oversized.command = Command::Rollback {
        id: "any".into(),
        reason: "a".repeat(16 * 1024),
    };
    assert!(registry.dispatch(oversized).is_err());
    assert!(host.receiver.try_recv().is_err());

    // A full manual history must not strand a partially committed coordinated
    // transaction. Its durable log replaces the transport's result history.
    let first = request(&host, "rollout-capacity-0-1");
    assert!(registry.dispatch(first.clone()).is_err());
    for sequence in 1..=MAX_REQUESTS + 16 {
        let id = format!("rollout-capacity-0-{sequence}");
        let coordinated = request(&host, &id);
        registry.dispatch_coordinated(coordinated.clone()).unwrap();
        registry.dispatch_coordinated(coordinated.clone()).unwrap();
        assert_eq!(host.receiver.try_recv().unwrap().request_id, id);
        assert!(host.receiver.try_recv().is_err());
        registry.retire_coordinated(&Default::default());
        assert!(
            registry.command(&id).is_some(),
            "pending delivery was removed"
        );
        registry.delivered(&host.id, &id).unwrap();
        registry
            .acknowledge(
                &host.id,
                Acknowledgement {
                    request_id: id.clone(),
                    reply: Reply::Ok,
                    snapshot: snapshot.clone(),
                },
                false,
            )
            .unwrap();
        registry.retire_coordinated(&std::collections::BTreeSet::from([id.clone()]));
        assert!(
            registry.command(&id).is_some(),
            "unapplied result was removed"
        );
        registry.retire_coordinated(&Default::default());
        assert_eq!(registry.commands().len(), MAX_REQUESTS);
        assert!(registry.dispatch_coordinated(coordinated).is_err());
        assert!(registry.dispatch_coordinated(first.clone()).is_err());
    }
}
