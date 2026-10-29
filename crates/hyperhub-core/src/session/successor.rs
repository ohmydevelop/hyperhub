//! Trusted in-memory session continuation, distinct from cold disk recovery.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuccessorSessions {
    durable: DurableSessionState,
    descriptor: KdfDescriptor,
    auth_digest: String,
    api_digest: Option<String>,
    members: HashMap<String, MemberMetadata>,
    next_member_instance: u64,
    password_authorized: bool,
    failed_attempts: u8,
    blocked_remaining_ms: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberMetadata {
    instances: HashMap<u32, u64>,
    policies: HashMap<u32, ProcessHookMetadata>,
    native_observed: std::collections::HashSet<(u32, u64)>,
    cleanup_fence: Option<[u8; 32]>,
}

/// Bound borrowed source records before `durable_snapshot_locked` or metadata
/// cloning allocates a transfer-sized copy. Tuple-key lookup indexes are rebuilt
/// from these same records and do not need their own serialized copy.
fn preflight_sessions(state: &SessionState) -> Result<(), String> {
    #[derive(Serialize)]
    struct Record<'a> {
        session_id: &'a str,
        token: &'a str,
        executable: &'a str,
        members: &'a HashMap<u32, String>,
        member_births: &'a HashMap<u32, u64>,
        member_instances: &'a HashMap<u32, u64>,
        process_policies: &'a HashMap<u32, ProcessHookMetadata>,
        native_observed: &'a std::collections::HashSet<(u32, u64)>,
        name_by_fake: &'a HashMap<IpAddr, String>,
        native_by_fake: &'a HashMap<IpAddr, hyperhub_runtime::attachment::NativeFallback>,
    }
    struct Records<'a>(&'a HashMap<String, SessionRecord>);
    impl Serialize for Records<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
            for record in self.0.values() {
                sequence.serialize_element(&Record {
                    session_id: &record.session_id,
                    token: &record.token,
                    executable: &record.executable,
                    members: &record.members,
                    member_births: &record.member_births,
                    member_instances: &record.member_instances,
                    process_policies: &record.process_policies,
                    native_observed: &record.native_observed,
                    name_by_fake: &record.name_by_fake,
                    native_by_fake: &record.native_by_fake,
                })?;
            }
            sequence.end()
        }
    }
    #[derive(Serialize)]
    struct Preview<'a> {
        sessions: Records<'a>,
        managers: &'a HashMap<String, HashMap<u32, DurableEngineManager>>,
    }
    crate::successor::bounded_json::check(
        &Preview {
            sessions: Records(&state.sessions),
            managers: &state.engine_managers,
        },
        crate::successor::MAX_STATE,
    )
}
impl SessionRegistry {
    pub(crate) fn export_successor(&self) -> Result<SuccessorSessions, String> {
        let state = self.0.lock().map_err(|_| "session state unavailable")?;
        preflight_sessions(&state)?;
        let durable = durable_snapshot_locked(&state, unix_timestamp_ms(), 60_000);
        if state.sessions.values().any(|record| {
            record.lifecycle != SessionLifecycle::RootProcess
                || record
                    .fork_leases
                    .values()
                    .any(|lease| lease.expires_at > Instant::now())
        }) {
            return Err(
                "session creation or fork admission is in progress; retry Core succession".into(),
            );
        }
        if state
            .challenges
            .values()
            .any(|challenge| challenge.expires_at > Instant::now())
        {
            return Err("session authentication is in progress; retry Core succession".into());
        }
        Ok(SuccessorSessions {
            durable,
            descriptor: state.descriptor.clone(),
            auth_digest: crate::attachments::digest(&state.auth_key),
            api_digest: state
                .api_key
                .as_ref()
                .map(|key| crate::attachments::digest(key)),
            members: state
                .sessions
                .iter()
                .map(|(id, record)| {
                    (
                        id.clone(),
                        MemberMetadata {
                            instances: record.member_instances.clone(),
                            policies: record.process_policies.clone(),
                            native_observed: record.native_observed.clone(),
                            cleanup_fence: record.cleanup_fence,
                        },
                    )
                })
                .collect(),
            next_member_instance: state.next_member_instance,
            password_authorized: state.password_authorized,
            failed_attempts: state.failed_attempts,
            blocked_remaining_ms: state.blocked_until.map(|until| {
                until
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(u64::MAX as u128) as u64
            }),
        })
    }
    pub(crate) fn import_successor(
        &self,
        incoming: SuccessorSessions,
    ) -> Result<DurableSessionState, String> {
        {
            let state = self.0.lock().map_err(|_| "session state unavailable")?;
            if !state.sessions.is_empty()
                || state.descriptor != incoming.descriptor
                || crate::attachments::digest(&state.auth_key) != incoming.auth_digest
                || state
                    .api_key
                    .as_ref()
                    .map(|key| crate::attachments::digest(key))
                    != incoming.api_digest
            {
                return Err("successor sessions do not match the authenticated configuration and empty startup state".into());
            }
        }
        let durable = incoming.durable;
        self.restore_durable_state(durable.clone(), unix_timestamp_ms());
        let mut state = self.0.lock().map_err(|_| "session state unavailable")?;
        for (id, metadata) in incoming.members {
            let Some(record) = state.sessions.get_mut(&id) else {
                continue;
            };
            for (pid, instance) in metadata.instances {
                if instance == 0 || instance >= incoming.next_member_instance {
                    return Err("successor session member generation is invalid".into());
                }
                if record.members.contains_key(&pid) {
                    record.member_instances.insert(pid, instance);
                }
            }
            record.native_observed = metadata.native_observed;
            record.cleanup_fence = metadata.cleanup_fence;
            record.process_policies = metadata
                .policies
                .into_iter()
                .filter(|(pid, _)| record.members.contains_key(pid))
                .collect();
        }
        state.next_member_instance = state
            .next_member_instance
            .max(incoming.next_member_instance);
        state.password_authorized = incoming.password_authorized;
        state.failed_attempts = incoming.failed_attempts;
        state.blocked_until = incoming
            .blocked_remaining_ms
            .and_then(|ms| Instant::now().checked_add(Duration::from_millis(ms)));
        Ok(durable)
    }
}

impl SuccessorSessions {
    pub(crate) fn validate_successor_configuration(
        &self,
        unlocked: &crate::config_store::UnlockedConfig,
    ) -> Result<(), String> {
        if self.descriptor != unlocked.descriptor
            || self.auth_digest != crate::attachments::digest(&unlocked.session_auth_key)
        {
            return Err("successor session key differs from authenticated configuration".into());
        }
        Ok(())
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;
    #[test]
    fn successor_session_keeps_member_generations_policy_aliases_and_rejects_another_key() {
        let descriptor = crate::config_store::new_descriptor();
        let registry = SessionRegistry::new(Zeroizing::new(vec![7; 32]), descriptor.clone());
        let pid = std::process::id();
        let birth = process_start_time(pid).unwrap();
        let executable = crate::control::process_path(pid)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let now = unix_timestamp_ms();
        registry.restore_durable_state(
            DurableSessionState {
                schema_version: 1,
                saved_at_ms: now,
                expires_at_ms: now + 60_000,
                sessions: vec![DurableSessionRecord {
                    session_id: "private-successor-session".into(),
                    token: "private-successor-token".into(),
                    root_pid: pid,
                    root_start_time: birth,
                    executable: executable.clone(),
                    members: vec![DurableSessionMember {
                        pid,
                        executable,
                        start_time: birth,
                    }],
                    engine_managers: vec![],
                    fake_by_name: vec![DurableFakeAddress {
                        hostname: "private.invalid".into(),
                        family: 4,
                        address: "198.18.1.2".parse().unwrap(),
                        native_fallback: None,
                    }],
                    next_fake_id: 259,
                }],
            },
            now,
        );
        {
            let mut state = registry.0.lock().unwrap();
            state.next_member_instance = 43;
            let record = state.sessions.get_mut("private-successor-session").unwrap();
            record.member_instances.insert(pid, 42);
            record.process_policies.insert(
                pid,
                ProcessHookMetadata {
                    hook_status: "attached".into(),
                    policy_version: 9,
                    rule_id: Some("private-test-rule".into()),
                    decision_source: "private-test".into(),
                },
            );
            state.failed_attempts = 2;
        }
        let bytes = serde_json::to_vec(&registry.export_successor().unwrap()).unwrap();
        let wrong = SessionRegistry::new(Zeroizing::new(vec![8; 32]), descriptor.clone());
        assert!(wrong
            .import_successor(serde_json::from_slice(&bytes).unwrap())
            .is_err());
        let child = SessionRegistry::new(Zeroizing::new(vec![7; 32]), descriptor);
        child
            .import_successor(serde_json::from_slice(&bytes).unwrap())
            .unwrap();
        assert_eq!(
            child.member_instance("private-successor-session", "private-successor-token", pid),
            Some(42)
        );
        assert_eq!(
            child.restore_fake("private-successor-session", "198.18.1.2".parse().unwrap()),
            Some("private.invalid".into())
        );
        let state = child.0.lock().unwrap();
        assert_eq!(state.failed_attempts, 2);
        assert_eq!(
            state.sessions["private-successor-session"].process_policies[&pid].policy_version,
            9
        );
        assert!(state.next_member_instance >= 43);
        drop(state);
        assert!(child
            .import_successor(serde_json::from_slice(&bytes).unwrap())
            .is_err());
        // An oversized retained alias is rejected from borrowed source memory,
        // before constructing another durable/metadata clone of that string.
        registry
            .0
            .lock()
            .unwrap()
            .sessions
            .get_mut("private-successor-session")
            .unwrap()
            .name_by_fake
            .insert(
                "198.18.1.3".parse().unwrap(),
                "x".repeat(crate::successor::MAX_STATE + 1),
            );
        assert!(registry.export_successor().is_err());
        assert_eq!(
            registry.0.lock().unwrap().sessions["private-successor-session"].member_instances[&pid],
            42
        );
    }
}

pub(super) fn durable_snapshot_locked(
    state: &SessionState,
    now_ms: u64,
    ttl_ms: u64,
) -> DurableSessionState {
    let sessions = state
        .sessions
        .values()
        .filter(|record| record.lifecycle == SessionLifecycle::RootProcess)
        .map(|record| DurableSessionRecord {
            session_id: record.session_id.clone(),
            token: record.token.clone(),
            root_pid: record.root_pid,
            root_start_time: record
                .member_births
                .get(&record.root_pid)
                .copied()
                .unwrap_or(0),
            executable: record.executable.clone(),
            members: record
                .members
                .iter()
                .map(|(pid, executable)| DurableSessionMember {
                    pid: *pid,
                    executable: executable.clone(),
                    start_time: record.member_births.get(pid).copied().unwrap_or(0),
                })
                .collect(),
            engine_managers: state
                .engine_managers
                .get(&record.session_id)
                .into_iter()
                .flat_map(|managers| managers.iter())
                .map(|(_, manager)| manager.clone())
                .collect(),
            fake_by_name: record
                .name_by_fake
                .iter()
                .map(|(address, hostname)| DurableFakeAddress {
                    hostname: hostname.clone(),
                    family: if address.is_ipv4() { 4 } else { 6 },
                    address: *address,
                    native_fallback: record.native_by_fake.get(address).cloned(),
                })
                .collect(),
            next_fake_id: record.next_fake_id,
        })
        .collect();
    DurableSessionState {
        schema_version: 1,
        saved_at_ms: now_ms,
        expires_at_ms: now_ms.saturating_add(ttl_ms),
        sessions,
    }
}
