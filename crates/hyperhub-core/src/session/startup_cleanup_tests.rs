use super::*;

fn fixture() -> (SessionRegistry, crate::attachments::HostBootstrapBinding) {
    let identity = crate::attachments::inspect_process(std::process::id()).unwrap();
    let session = SessionRegistry::default();
    let token = "t".repeat(64);
    session
        .prepare_approved_attachment("startup-cleanup", &token, &identity.executable, &[])
        .unwrap();
    assert!(session.activate_with_policy(
        "startup-cleanup",
        &token,
        identity.pid,
        ProcessHookMetadata {
            hook_status: "preparing".into(),
            decision_source: "attachment_approval".into(),
            ..Default::default()
        }
    ));
    let bootstrap: hyperhub_runtime::attachment::Bootstrap = serde_json::from_value(serde_json::json!({
        "attachment_id":"fixture","session_id":"startup-cleanup","token":token,"control_endpoint":"unused","socks_address":"127.0.0.1:1","tls_ca_pem":"unused","observe":false,"firewall":null,"sandbox":null,"host_endpoint":"unused","host_token":"h".repeat(64),"scope_tree":true,"root_pid":identity.pid,"approval_authority_file":"unused","approval_instance_id":"instance","initially_owned":false,"approval_core_public_key":null,"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":identity.executable_sha256
    })).unwrap();
    (
        session,
        crate::attachments::HostBootstrapBinding {
            identity,
            bootstrap,
        },
    )
}
#[test]
fn unstarted_member_requires_exact_incarnation_and_monotonic_absence_of_native_activity() {
    let (session, binding) = fixture();
    let bindings = [binding.clone()];
    let check = |session: &SessionRegistry| {
        session.validate_unstarted_members(
            "startup-cleanup",
            &binding.bootstrap.token,
            &bindings,
            true,
        )
    };
    assert!(check(&session).is_ok());
    let mut wrong = binding.clone();
    wrong.identity.birth += 1;
    assert!(session
        .validate_unstarted_members("startup-cleanup", &binding.bootstrap.token, &[wrong], true)
        .is_err());
    assert!(session
        .validate_unstarted_members("startup-cleanup", "wrong", &bindings, true)
        .is_err());
    assert!(session.note_agent(
        "startup-cleanup",
        &binding.bootstrap.token,
        binding.identity.pid,
        1
    ));
    {
        // Heartbeat expiry or reattach metadata cannot erase lifetime evidence.
        let mut state = session.0.lock().unwrap();
        let record = state.sessions.get_mut("startup-cleanup").unwrap();
        record.agent_heartbeats.clear();
        record
            .process_policies
            .get_mut(&binding.identity.pid)
            .unwrap()
            .hook_status = "preparing".into();
    }
    assert!(check(&session).is_err());
    assert!(
        session.authenticate_member(
            "startup-cleanup",
            &binding.bootstrap.token,
            binding.identity.pid
        ),
        "rejection must preserve existing membership"
    );
}
#[test]
fn unstarted_evidence_survives_private_successor_but_cold_restore_is_unknown() {
    let (session, binding) = fixture();
    let descriptor = session.0.lock().unwrap().descriptor.clone();
    let check = |session: &SessionRegistry| {
        session.validate_unstarted_members(
            "startup-cleanup",
            &binding.bootstrap.token,
            &[binding.clone()],
            true,
        )
    };
    let child = SessionRegistry::new(Zeroizing::new(vec![0; 32]), descriptor.clone());
    child
        .import_successor(session.export_successor().unwrap())
        .unwrap();
    assert!(check(&child).is_ok());
    session.note_native_observed(
        "startup-cleanup",
        &binding.bootstrap.token,
        binding.identity.pid,
    );
    let successor = SessionRegistry::new(Zeroizing::new(vec![0; 32]), descriptor);
    successor
        .import_successor(session.export_successor().unwrap())
        .unwrap();
    assert!(check(&successor).is_err());
    let (fresh, _) = fixture();
    let cold = SessionRegistry::default();
    let now = unix_timestamp_ms();
    cold.restore_durable_state(fresh.durable_snapshot(now, 60_000), now);
    assert!(
        check(&cold).is_err(),
        "ordinary disk recovery cannot invent pre-dispatch RAM history"
    );
}
#[test]
fn empty_startup_cleanup_rejects_core_aliases_or_nonpreparing_policy() {
    let (session, binding) = fixture();
    let bindings = [binding.clone()];
    {
        let mut state = session.0.lock().unwrap();
        let record = state.sessions.get_mut("startup-cleanup").unwrap();
        record
            .name_by_fake
            .insert("198.18.1.2".parse().unwrap(), "fixture.test".into());
    }
    assert!(!session.startup_aliases_empty("startup-cleanup", &binding.bootstrap.token));
    assert!(session
        .validate_unstarted_members("startup-cleanup", &binding.bootstrap.token, &bindings, true)
        .is_err());
    {
        let mut state = session.0.lock().unwrap();
        let record = state.sessions.get_mut("startup-cleanup").unwrap();
        record.name_by_fake.clear();
        record
            .process_policies
            .get_mut(&binding.identity.pid)
            .unwrap()
            .hook_status = "hook".into();
    }
    assert!(session
        .validate_unstarted_members("startup-cleanup", &binding.bootstrap.token, &bindings, true)
        .is_err());
}

#[test]
fn cleanup_fence_closes_new_work_keeps_cleanup_authentication_and_survives_successor() {
    let (session, binding) = fixture();
    let sid = &binding.bootstrap.session_id;
    let token = &binding.bootstrap.token;
    let pid = binding.identity.pid;
    let username = format!("hh2:{sid}:{pid}:1");
    assert!(session.authenticate(&username, token).is_some());
    assert!(session
        .fence_attachment_cleanup(sid, "wrong", [1; 32])
        .is_err());
    assert!(!session.cleanup_fenced(sid, token));
    session
        .fence_attachment_cleanup(sid, token, [1; 32])
        .unwrap();
    assert!(session.cleanup_fenced(sid, token));
    assert!(session.authenticate_member(sid, token, pid));
    assert!(session.authenticate_control(sid, token));
    assert!(session.authenticate(&username, token).is_none());
    assert!(session
        .resolve_fake(sid, token, "new.fixture.test", 4)
        .is_none());
    assert!(session
        .begin_fork_lease(sid, token, pid, Duration::from_secs(1))
        .is_none());
    assert!(!session.register_child(
        sid,
        token,
        pid,
        pid + 1,
        binding.identity.executable.clone()
    ));
    assert!(session
        .inherit_member(pid, pid + 1, binding.identity.executable.clone())
        .is_none());
    assert!(session
        .begin_inherited(
            "fenced-child".into(),
            binding.identity.executable.clone(),
            pid,
            Duration::from_secs(1)
        )
        .is_none());
    assert!(!session.refresh_member_with_policy(
        sid,
        token,
        pid,
        binding.identity.executable.clone(),
        ProcessHookMetadata::default()
    ));
    assert!(!session.cleanup_fenced("not-created-yet", token));
    let descriptor = session.0.lock().unwrap().descriptor.clone();
    let child = SessionRegistry::new(Zeroizing::new(vec![0; 32]), descriptor);
    child
        .import_successor(session.export_successor().unwrap())
        .unwrap();
    assert!(child.cleanup_fenced(sid, token));
    assert!(child.authenticate_member(sid, token, pid));
    assert!(child.authenticate(&username, token).is_none());
    // A fresh accepted Detach can replace the continuation nonce, never reopen.
    child.fence_attachment_cleanup(sid, token, [2; 32]).unwrap();
    assert!(child.cleanup_fenced(sid, token));
}

#[test]
fn live_startup_cleanup_requires_fence_and_every_live_core_incarnation() {
    let (session, binding) = fixture();
    let sid = &binding.bootstrap.session_id;
    let token = &binding.bootstrap.token;
    let members = [binding.identity.clone()];
    assert!(session
        .validate_live_cleanup_roster(sid, token, &members, &[])
        .is_err());
    session
        .fence_attachment_cleanup(sid, token, [5; 32])
        .unwrap();
    assert!(session
        .validate_live_cleanup_roster(sid, token, &members, &[])
        .is_ok());
    assert!(session
        .validate_live_cleanup_roster(sid, token, &[], &[])
        .is_err());
    let mut wrong = binding.identity.clone();
    wrong.birth += 1;
    assert!(session
        .validate_live_cleanup_roster(sid, token, &[wrong], &[])
        .is_err());
    assert!(session
        .validate_live_cleanup_roster(sid, "wrong", &members, &[])
        .is_err());
    assert!(session
        .validate_live_cleanup_roster(sid, token, &[], &[binding.clone()])
        .is_ok());
    // A roster entry cannot erase Core's monotonic proof of native activity.
    session.note_native_observed(sid, token, binding.identity.pid);
    assert!(session
        .validate_unstarted_members(sid, token, &[binding.clone()], false)
        .is_err());
    assert!(session
        .validate_live_cleanup_roster(sid, token, &members, &[])
        .is_ok());
}
