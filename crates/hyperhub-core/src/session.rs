use crate::config_store::KdfDescriptor;
use crate::policy::{Destination, Protocol};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const CHALLENGE_TTL: Duration = Duration::from_secs(30);
const MAX_CHALLENGES: usize = 64;
const MAX_FORK_LEASES: usize = 64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionLifecycle {
    Pending,
    RootProcess,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub session_id: String,
    pub token: String,
    pub root_pid: u32,
    pub executable: String,
    pub lifecycle: SessionLifecycle,
    pending_expires_at: Option<Instant>,
    members: HashMap<u32, String>,
    member_instances: HashMap<u32, u64>,
    process_policies: HashMap<u32, ProcessHookMetadata>,
    agent_heartbeats: HashMap<u32, AgentHeartbeat>,
    fork_leases: HashMap<String, ForkLease>,
    fake_by_name: HashMap<(String, u8), IpAddr>,
    name_by_fake: HashMap<IpAddr, String>,
    next_fake_id: u32,
    cancellation: CancellationToken,
}

#[derive(Clone)]
pub struct SessionRegistry(Arc<Mutex<SessionState>>);

#[derive(Debug, Clone)]
struct AgentHeartbeat {
    last_seen_ms: u64,
    firewall_version: u64,
}

#[derive(Debug, Clone)]
struct ForkLease {
    parent_pid: u32,
    expires_at: Instant,
    candidate_pid: Option<u32>,
    attested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkLeaseStatus {
    Preparing,
    Candidate,
    Attested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinishedForkLease {
    pub candidate_pid: Option<u32>,
    pub attested: bool,
}

struct SessionState {
    auth_key: Zeroizing<Vec<u8>>,
    descriptor: KdfDescriptor,
    sessions: HashMap<String, SessionRecord>,
    challenges: HashMap<String, ChallengeRecord>,
    password_authorized: bool,
    failed_attempts: u8,
    blocked_until: Option<Instant>,
    next_member_instance: u64,
}

struct ChallengeRecord {
    challenge: SessionChallenge,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub session_id: String,
    pub pid: u32,
    pub connection_id: u64,
    pub executable: String,
    pub cancellation: CancellationToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub root_pid: u32,
    pub executable: String,
    pub lifecycle: SessionLifecycle,
    pub expires_at_ms: Option<u64>,
    pub process_count: usize,
    #[serde(default)]
    pub processes: Vec<InjectedProcessSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InjectedProcessSnapshot {
    pub pid: u32,
    pub executable: String,
    pub root: bool,
    pub last_seen_ms: u64,
    pub firewall_version: u64,
    #[serde(default = "default_hook_status")]
    pub hook_status: String,
    #[serde(default)]
    pub process_policy_version: u64,
    #[serde(default)]
    pub process_rule_id: Option<String>,
    #[serde(default = "default_unknown_source")]
    pub process_decision_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessHookMetadata {
    pub hook_status: String,
    pub policy_version: u64,
    pub rule_id: Option<String>,
    pub decision_source: String,
}

impl Default for ProcessHookMetadata {
    fn default() -> Self {
        Self {
            hook_status: "unknown".into(),
            policy_version: 0,
            rule_id: None,
            decision_source: "unknown".into(),
        }
    }
}

fn default_hook_status() -> String {
    "hook".into()
}
fn default_unknown_source() -> String {
    "unknown".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionChallenge {
    pub challenge_id: String,
    pub session_id: String,
    pub executable: String,
    pub client_nonce: [u8; 32],
    pub server_nonce: [u8; 32],
    pub descriptor: KdfDescriptor,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFlags {
    pub observe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientProxySnapshot {
    pub protocol: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub session_id: String,
    pub connection_id: u64,
    pub pid: u32,
    pub executable: String,
    pub original_destination: Destination,
    pub destination: Destination,
    pub protocol: Protocol,
    pub rule_id: Option<String>,
    pub action: String,
    pub route_upstream: Option<String>,
    pub client_proxy: Option<ClientProxySnapshot>,
    pub phase: String,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionRegistry(Arc<Mutex<HashMap<(String, u32, u64), ConnectionSnapshot>>>);

pub struct ActiveConnection {
    registry: ConnectionRegistry,
    key: (String, u32, u64),
}

impl ConnectionRegistry {
    pub fn track(&self, snapshot: ConnectionSnapshot) -> ActiveConnection {
        let key = (
            snapshot.session_id.clone(),
            snapshot.pid,
            snapshot.connection_id,
        );
        if let Ok(mut connections) = self.0.lock() {
            connections.insert(key.clone(), snapshot);
        }
        ActiveConnection {
            registry: self.clone(),
            key,
        }
    }

    pub fn snapshot(&self) -> Vec<ConnectionSnapshot> {
        let mut snapshots = self
            .0
            .lock()
            .map(|connections| connections.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        snapshots.sort_by(|left, right| {
            left.session_id
                .cmp(&right.session_id)
                .then(left.pid.cmp(&right.pid))
                .then(left.connection_id.cmp(&right.connection_id))
        });
        snapshots
    }
}

impl ActiveConnection {
    pub fn update(
        &self,
        destination: &Destination,
        protocol: Protocol,
        rule_id: Option<&str>,
        action: &str,
        route_upstream: Option<&str>,
        client_proxy: Option<ClientProxySnapshot>,
        phase: &str,
    ) {
        if let Ok(mut connections) = self.registry.0.lock() {
            if let Some(snapshot) = connections.get_mut(&self.key) {
                snapshot.destination = destination.clone();
                snapshot.protocol = protocol;
                snapshot.rule_id = rule_id.map(str::to_owned);
                snapshot.action = action.to_owned();
                snapshot.route_upstream = route_upstream.map(str::to_owned);
                snapshot.client_proxy = client_proxy;
                snapshot.phase = phase.to_owned();
                snapshot.updated_at_ms = unix_timestamp_ms();
            }
        }
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        if let Ok(mut connections) = self.registry.0.lock() {
            connections.remove(&self.key);
        }
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new(
            Zeroizing::new(vec![0; 32]),
            crate::config_store::new_descriptor(),
        )
    }
}

impl SessionRegistry {
    pub fn new(auth_key: Zeroizing<Vec<u8>>, descriptor: KdfDescriptor) -> Self {
        Self(Arc::new(Mutex::new(SessionState {
            auth_key,
            descriptor,
            sessions: HashMap::new(),
            challenges: HashMap::new(),
            password_authorized: false,
            failed_attempts: 0,
            blocked_until: None,
            next_member_instance: 1,
        })))
    }

    pub fn begin_auth(
        &self,
        session_id: String,
        executable: String,
        client_nonce: [u8; 32],
    ) -> Option<SessionChallenge> {
        if session_id.is_empty() || executable.is_empty() {
            return None;
        }
        let mut state = self.0.lock().ok()?;
        let now = Instant::now();
        cleanup(&mut state, now);
        if state.blocked_until.is_some_and(|until| until > now)
            || state.challenges.len() >= MAX_CHALLENGES
        {
            return None;
        }
        let challenge_id = random_token(24);
        let mut server_nonce = [0u8; 32];
        rand::fill(&mut server_nonce);
        let challenge = SessionChallenge {
            challenge_id: challenge_id.clone(),
            session_id,
            executable,
            client_nonce,
            server_nonce,
            descriptor: state.descriptor.clone(),
            expires_at_ms: unix_timestamp_after(CHALLENGE_TTL),
        };
        state.challenges.insert(
            challenge_id,
            ChallengeRecord {
                challenge: challenge.clone(),
                expires_at: now + CHALLENGE_TTL,
            },
        );
        Some(challenge)
    }

    pub fn finish_auth(
        &self,
        challenge_id: &str,
        proof: &[u8],
        pending_ttl: Duration,
    ) -> Option<SessionRecord> {
        let mut state = self.0.lock().ok()?;
        let now = Instant::now();
        cleanup(&mut state, now);
        let record = state.challenges.remove(challenge_id)?;
        let expected = session_proof(&state.auth_key, &record.challenge).ok()?;
        if !constant_time_eq(&expected, proof) {
            state.failed_attempts = state.failed_attempts.saturating_add(1);
            let delay = 1u64 << state.failed_attempts.min(3);
            state.blocked_until = Some(now + Duration::from_secs(delay));
            return None;
        }
        state.failed_attempts = 0;
        state.blocked_until = None;
        state.password_authorized = true;
        if state.sessions.contains_key(&record.challenge.session_id) {
            return None;
        }
        let session = pending_session(
            record.challenge.session_id.clone(),
            record.challenge.executable,
            now,
            pending_ttl,
        );
        state
            .sessions
            .insert(session.session_id.clone(), session.clone());
        Some(session)
    }

    pub fn begin_cached_auth(
        &self,
        session_id: String,
        executable: String,
        pending_ttl: Duration,
    ) -> Option<SessionRecord> {
        if session_id.is_empty() || executable.is_empty() {
            return None;
        }
        let mut state = self.0.lock().ok()?;
        let now = Instant::now();
        cleanup(&mut state, now);
        if !state.password_authorized || state.sessions.contains_key(&session_id) {
            return None;
        }
        let session = pending_session(session_id, executable, now, pending_ttl);
        state
            .sessions
            .insert(session.session_id.clone(), session.clone());
        Some(session)
    }

    pub fn clear_password_authorization(&self) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        state.password_authorized = false;
        true
    }

    pub fn member_executable(&self, pid: u32) -> Option<String> {
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        state.sessions.values().find_map(|record| {
            (record.lifecycle == SessionLifecycle::RootProcess)
                .then(|| record.members.get(&pid))
                .flatten()
                .cloned()
        })
    }

    pub fn begin_inherited(
        &self,
        session_id: String,
        executable: String,
        authorizing_pid: u32,
        pending_ttl: Duration,
    ) -> Option<SessionRecord> {
        if session_id.is_empty() || executable.is_empty() || authorizing_pid == 0 {
            return None;
        }
        let mut state = self.0.lock().ok()?;
        let now = Instant::now();
        cleanup(&mut state, now);
        if state.sessions.contains_key(&session_id)
            || !state.sessions.values().any(|record| {
                record.lifecycle == SessionLifecycle::RootProcess
                    && record.members.contains_key(&authorizing_pid)
            })
        {
            return None;
        }
        let session = pending_session(session_id, executable, now, pending_ttl);
        state
            .sessions
            .insert(session.session_id.clone(), session.clone());
        Some(session)
    }

    pub fn inherit_member(
        &self,
        authorizing_pid: u32,
        child_pid: u32,
        executable: String,
    ) -> Option<SessionRecord> {
        if authorizing_pid == 0 || child_pid == 0 || executable.is_empty() {
            return None;
        }
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        let instance = next_member_instance(&mut state);
        let record = state.sessions.values_mut().find(|record| {
            record.lifecycle == SessionLifecycle::RootProcess
                && record.members.contains_key(&authorizing_pid)
        })?;
        match record.members.get(&child_pid) {
            Some(existing) if existing != &executable => return None,
            Some(_) => {}
            None => {
                record.members.insert(child_pid, executable);
                record.member_instances.insert(child_pid, instance);
                record
                    .process_policies
                    .insert(child_pid, ProcessHookMetadata::default());
            }
        }
        Some(record.clone())
    }

    pub fn activate(&self, session_id: &str, token: &str, root_pid: u32) -> bool {
        self.activate_with_policy(
            session_id,
            token,
            root_pid,
            ProcessHookMetadata {
                hook_status: "hook".into(),
                ..ProcessHookMetadata::default()
            },
        )
    }

    pub fn activate_with_policy(
        &self,
        session_id: &str,
        token: &str,
        root_pid: u32,
        policy: ProcessHookMetadata,
    ) -> bool {
        if root_pid == 0 {
            return false;
        }
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        cleanup(&mut state, Instant::now());
        let instance = next_member_instance(&mut state);
        let Some(record) = state.sessions.get_mut(session_id) else {
            return false;
        };
        if record.lifecycle != SessionLifecycle::Pending
            || !constant_time_eq(record.token.as_bytes(), token.as_bytes())
        {
            return false;
        }
        record.root_pid = root_pid;
        record.members.insert(root_pid, record.executable.clone());
        record.member_instances.insert(root_pid, instance);
        record.process_policies.insert(root_pid, policy);
        record.lifecycle = SessionLifecycle::RootProcess;
        record.pending_expires_at = None;
        true
    }

    pub fn register_child(
        &self,
        session_id: &str,
        token: &str,
        parent_pid: u32,
        child_pid: u32,
        executable: String,
    ) -> bool {
        self.register_child_with_policy(
            session_id,
            token,
            parent_pid,
            child_pid,
            executable,
            ProcessHookMetadata {
                hook_status: "hook".into(),
                ..ProcessHookMetadata::default()
            },
        )
    }

    pub fn register_child_with_policy(
        &self,
        session_id: &str,
        token: &str,
        parent_pid: u32,
        child_pid: u32,
        executable: String,
        policy: ProcessHookMetadata,
    ) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        cleanup(&mut state, Instant::now());
        let instance = next_member_instance(&mut state);
        let Some(record) = state.sessions.get_mut(session_id) else {
            return false;
        };
        if record.lifecycle != SessionLifecycle::RootProcess
            || !record.members.contains_key(&parent_pid)
            || !constant_time_eq(record.token.as_bytes(), token.as_bytes())
        {
            return false;
        }
        match record.members.get(&child_pid) {
            Some(existing) if existing != &executable => false,
            Some(_) => {
                record.member_instances.insert(child_pid, instance);
                record.process_policies.insert(child_pid, policy);
                true
            }
            None => {
                record.members.insert(child_pid, executable);
                record.member_instances.insert(child_pid, instance);
                record.process_policies.insert(child_pid, policy);
                true
            }
        }
    }

    pub fn begin_fork_lease(
        &self,
        session_id: &str,
        token: &str,
        parent_pid: u32,
        ttl: Duration,
    ) -> Option<String> {
        let mut state = self.0.lock().ok()?;
        let now = Instant::now();
        cleanup(&mut state, now);
        let record = state.sessions.get_mut(session_id)?;
        if record.lifecycle != SessionLifecycle::RootProcess
            || !record.members.contains_key(&parent_pid)
            || !constant_time_eq(record.token.as_bytes(), token.as_bytes())
            || record.fork_leases.len() >= MAX_FORK_LEASES
        {
            return None;
        }
        let lease_id = random_token(24);
        record.fork_leases.insert(
            lease_id.clone(),
            ForkLease {
                parent_pid,
                expires_at: now + ttl,
                candidate_pid: None,
                attested: false,
            },
        );
        Some(lease_id)
    }

    pub fn register_fork_candidate(
        &self,
        session_id: &str,
        token: &str,
        lease_id: &str,
        parent_pid: u32,
        child_pid: u32,
        executable: String,
    ) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        let now = Instant::now();
        cleanup(&mut state, now);
        let instance = next_member_instance(&mut state);
        let Some(record) = state.sessions.get_mut(session_id) else {
            return false;
        };
        if record.lifecycle != SessionLifecycle::RootProcess
            || !constant_time_eq(record.token.as_bytes(), token.as_bytes())
            || child_pid == 0
            || executable.is_empty()
            || record.members.contains_key(&child_pid)
        {
            return false;
        }
        let Some(lease) = record.fork_leases.get_mut(lease_id) else {
            return false;
        };
        if lease.parent_pid != parent_pid
            || lease.expires_at <= now
            || lease.candidate_pid.is_some()
        {
            return false;
        }
        lease.candidate_pid = Some(child_pid);
        record.members.insert(child_pid, executable);
        record.member_instances.insert(child_pid, instance);
        record.process_policies.insert(
            child_pid,
            ProcessHookMetadata {
                hook_status: "fork_pending".into(),
                decision_source: "msys_fork".into(),
                ..ProcessHookMetadata::default()
            },
        );
        true
    }

    pub fn attest_fork_child(
        &self,
        session_id: &str,
        token: &str,
        lease_id: &str,
        child_pid: u32,
        policy_version: u64,
    ) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        let now = Instant::now();
        cleanup(&mut state, now);
        let Some(record) = state.sessions.get_mut(session_id) else {
            return false;
        };
        if record.lifecycle != SessionLifecycle::RootProcess
            || !constant_time_eq(record.token.as_bytes(), token.as_bytes())
            || !record.members.contains_key(&child_pid)
        {
            return false;
        }
        let Some(lease) = record.fork_leases.get_mut(lease_id) else {
            return false;
        };
        if lease.candidate_pid != Some(child_pid) || lease.expires_at <= now {
            return false;
        }
        lease.attested = true;
        record.process_policies.insert(
            child_pid,
            ProcessHookMetadata {
                hook_status: "hook".into(),
                policy_version,
                rule_id: None,
                decision_source: "msys_fork_attested".into(),
            },
        );
        true
    }

    pub fn fork_lease_status(
        &self,
        session_id: &str,
        token: &str,
        lease_id: &str,
        parent_pid: u32,
    ) -> Option<ForkLeaseStatus> {
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        let record = state.sessions.get(session_id)?;
        if !constant_time_eq(record.token.as_bytes(), token.as_bytes()) {
            return None;
        }
        let lease = record.fork_leases.get(lease_id)?;
        if lease.parent_pid != parent_pid && lease.candidate_pid != Some(parent_pid) {
            return None;
        }
        Some(if lease.attested {
            ForkLeaseStatus::Attested
        } else if lease.candidate_pid.is_some() {
            ForkLeaseStatus::Candidate
        } else {
            ForkLeaseStatus::Preparing
        })
    }

    pub fn is_fork_candidate(
        &self,
        session_id: &str,
        token: &str,
        lease_id: &str,
        pid: u32,
    ) -> bool {
        let Ok(state) = self.0.lock() else {
            return false;
        };
        state.sessions.get(session_id).is_some_and(|record| {
            constant_time_eq(record.token.as_bytes(), token.as_bytes())
                && record
                    .fork_leases
                    .get(lease_id)
                    .is_some_and(|lease| lease.candidate_pid == Some(pid))
        })
    }

    pub fn pending_fork_lease_for_candidate(
        &self,
        session_id: &str,
        token: &str,
        candidate_pid: u32,
    ) -> Option<String> {
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        let record = state.sessions.get(session_id)?;
        if !constant_time_eq(record.token.as_bytes(), token.as_bytes()) {
            return None;
        }
        record.fork_leases.iter().find_map(|(lease_id, lease)| {
            (lease.candidate_pid == Some(candidate_pid) && !lease.attested)
                .then(|| lease_id.clone())
        })
    }

    pub fn finish_fork_lease(
        &self,
        session_id: &str,
        token: &str,
        lease_id: &str,
        require_attested: bool,
    ) -> Option<FinishedForkLease> {
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        let record = state.sessions.get_mut(session_id)?;
        if !constant_time_eq(record.token.as_bytes(), token.as_bytes()) {
            return None;
        }
        let lease = record.fork_leases.get(lease_id)?;
        if require_attested && !lease.attested {
            return None;
        }
        record
            .fork_leases
            .remove(lease_id)
            .map(|lease| FinishedForkLease {
                candidate_pid: lease.candidate_pid,
                attested: lease.attested,
            })
    }

    pub fn expire_fork_candidate(
        &self,
        session_id: &str,
        lease_id: &str,
        candidate_pid: u32,
    ) -> Option<u32> {
        let mut state = self.0.lock().ok()?;
        let record = state.sessions.get_mut(session_id)?;
        let lease = record.fork_leases.get(lease_id)?;
        if lease.candidate_pid != Some(candidate_pid) || lease.attested {
            return None;
        }
        record.fork_leases.remove(lease_id);
        Some(candidate_pid)
    }

    pub fn member_instance(&self, session_id: &str, token: &str, pid: u32) -> Option<u64> {
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        let record = state.sessions.get(session_id)?;
        (record.lifecycle == SessionLifecycle::RootProcess
            && constant_time_eq(record.token.as_bytes(), token.as_bytes()))
        .then(|| record.member_instances.get(&pid).copied())
        .flatten()
    }

    pub fn member_exited(&self, session_id: &str, pid: u32, instance: u64) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        let remove_session = {
            let Some(record) = state.sessions.get_mut(session_id) else {
                return false;
            };
            if record.member_instances.get(&pid).copied() != Some(instance) {
                return false;
            }
            record.members.remove(&pid);
            record.member_instances.remove(&pid);
            record.process_policies.remove(&pid);
            record.agent_heartbeats.remove(&pid);
            record.members.is_empty() && record.fork_leases.is_empty()
        };
        if remove_session {
            if let Some(record) = state.sessions.remove(session_id) {
                record.cancellation.cancel();
            }
        }
        true
    }

    pub fn refresh_member_with_policy(
        &self,
        session_id: &str,
        token: &str,
        pid: u32,
        executable: String,
        policy: ProcessHookMetadata,
    ) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        cleanup(&mut state, Instant::now());
        let Some(record) = state.sessions.get_mut(session_id) else {
            return false;
        };
        if record.lifecycle != SessionLifecycle::RootProcess
            || !record.members.contains_key(&pid)
            || !constant_time_eq(record.token.as_bytes(), token.as_bytes())
        {
            return false;
        }
        record.members.insert(pid, executable);
        record.process_policies.insert(pid, policy);
        true
    }

    pub fn authorize_process_decision(
        &self,
        session_id: &str,
        token: &str,
        executable: &str,
        peer_pid: Option<u32>,
    ) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        cleanup(&mut state, Instant::now());
        let Some(record) = state.sessions.get(session_id) else {
            return false;
        };
        if !constant_time_eq(record.token.as_bytes(), token.as_bytes()) {
            return false;
        }
        record.lifecycle == SessionLifecycle::RootProcess
            && peer_pid.is_some_and(|pid| record.members.contains_key(&pid))
            && !executable.is_empty()
    }

    pub fn revoke(&self, session_id: &str) -> bool {
        self.0
            .lock()
            .map(|mut state| {
                state.sessions.remove(session_id).is_some_and(|record| {
                    record.cancellation.cancel();
                    true
                })
            })
            .unwrap_or(false)
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Option<AuthenticatedSession> {
        let mut parts = username.split(':');
        if parts.next()? != "hh2" {
            return None;
        }
        let session_id = parts.next()?;
        let pid = parts.next()?.parse().ok()?;
        let connection_id = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        let record = state.sessions.get(session_id)?;
        if record.lifecycle != SessionLifecycle::RootProcess
            || !record.members.contains_key(&pid)
            || !constant_time_eq(record.token.as_bytes(), password.as_bytes())
        {
            return None;
        }
        Some(AuthenticatedSession {
            session_id: record.session_id.clone(),
            pid,
            connection_id,
            executable: record.members.get(&pid)?.clone(),
            cancellation: record.cancellation.clone(),
        })
    }

    pub fn resolve_fake(
        &self,
        session_id: &str,
        token: &str,
        hostname: &str,
        family: u8,
    ) -> Option<IpAddr> {
        if !matches!(family, 4 | 6) {
            return None;
        }
        let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
        if hostname.is_empty() || hostname.len() > 253 {
            return None;
        }
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        let record = state.sessions.get_mut(session_id)?;
        if record.lifecycle != SessionLifecycle::RootProcess
            || !constant_time_eq(record.token.as_bytes(), token.as_bytes())
        {
            return None;
        }
        if let Some(address) = record.fake_by_name.get(&(hostname.clone(), family)) {
            return Some(*address);
        }
        let id = record.next_fake_id;
        record.next_fake_id = record.next_fake_id.checked_add(1)?;
        let address = if family == 4 {
            if id >= (1 << 17) {
                return None;
            }
            IpAddr::V4(Ipv4Addr::new(
                198,
                18 + ((id >> 16) as u8),
                ((id >> 8) & 0xff) as u8,
                (id & 0xff) as u8,
            ))
        } else {
            IpAddr::V6(Ipv6Addr::new(
                0xfdfe,
                0x6879,
                0x7065,
                0x7268,
                0x7562,
                0,
                (id >> 16) as u16,
                id as u16,
            ))
        };
        record
            .fake_by_name
            .insert((hostname.clone(), family), address);
        record.name_by_fake.insert(address, hostname);
        Some(address)
    }

    pub fn restore_fake(&self, session_id: &str, address: IpAddr) -> Option<String> {
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        state
            .sessions
            .get(session_id)?
            .name_by_fake
            .get(&address)
            .cloned()
    }

    pub fn authenticate_pending(&self, session_id: &str, token: &str) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        cleanup(&mut state, Instant::now());
        state.sessions.get(session_id).is_some_and(|record| {
            record.lifecycle == SessionLifecycle::Pending
                && constant_time_eq(record.token.as_bytes(), token.as_bytes())
        })
    }

    pub fn authenticate_control(&self, session_id: &str, token: &str) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        cleanup(&mut state, Instant::now());
        state.sessions.get(session_id).is_some_and(|record| {
            record.lifecycle == SessionLifecycle::RootProcess
                && constant_time_eq(record.token.as_bytes(), token.as_bytes())
        })
    }

    pub fn authenticate_member(&self, session_id: &str, token: &str, pid: u32) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        cleanup(&mut state, Instant::now());
        state.sessions.get(session_id).is_some_and(|record| {
            record.lifecycle == SessionLifecycle::RootProcess
                && record.members.contains_key(&pid)
                && constant_time_eq(record.token.as_bytes(), token.as_bytes())
        })
    }

    pub fn note_agent(
        &self,
        session_id: &str,
        token: &str,
        pid: u32,
        firewall_version: u64,
    ) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        cleanup(&mut state, Instant::now());
        let Some(record) = state.sessions.get_mut(session_id) else {
            return false;
        };
        if record.lifecycle != SessionLifecycle::RootProcess
            || !record.members.contains_key(&pid)
            || !constant_time_eq(record.token.as_bytes(), token.as_bytes())
        {
            return false;
        }
        record.agent_heartbeats.insert(
            pid,
            AgentHeartbeat {
                last_seen_ms: unix_timestamp_ms(),
                firewall_version,
            },
        );
        true
    }

    pub fn pending_executable(&self, session_id: &str, token: &str) -> Option<String> {
        let mut state = self.0.lock().ok()?;
        cleanup(&mut state, Instant::now());
        let record = state.sessions.get(session_id)?;
        (record.lifecycle == SessionLifecycle::Pending
            && constant_time_eq(record.token.as_bytes(), token.as_bytes()))
        .then(|| record.executable.clone())
    }

    pub fn snapshot(&self) -> Vec<SessionSnapshot> {
        let now = Instant::now();
        let mut snapshots = self
            .0
            .lock()
            .map(|mut state| {
                cleanup(&mut state, now);
                let now_ms = unix_timestamp_ms();
                for record in state.sessions.values_mut() {
                    record.agent_heartbeats.retain(|_, heartbeat| {
                        now_ms.saturating_sub(heartbeat.last_seen_ms) <= 60_000
                    });
                }
                state
                    .sessions
                    .values()
                    .map(|record| {
                        // `members` is the source of truth for every managed process.
                        // Gum agents add heartbeat/firewall telemetry, while the ptrace
                        // backend intentionally has no in-process heartbeat. Filtering by
                        // heartbeats made active ptrace processes disappear from status/TUI.
                        let mut processes = record
                            .members
                            .iter()
                            .map(|(pid, executable)| {
                                let heartbeat =
                                    record.agent_heartbeats.get(pid).filter(|heartbeat| {
                                        now_ms.saturating_sub(heartbeat.last_seen_ms) <= 5_000
                                    });
                                InjectedProcessSnapshot {
                                    pid: *pid,
                                    executable: executable.clone(),
                                    root: *pid == record.root_pid,
                                    last_seen_ms: heartbeat
                                        .map(|heartbeat| heartbeat.last_seen_ms)
                                        .unwrap_or_default(),
                                    firewall_version: heartbeat
                                        .map(|heartbeat| heartbeat.firewall_version)
                                        .unwrap_or_default(),
                                    hook_status: record
                                        .process_policies
                                        .get(pid)
                                        .map(|policy| policy.hook_status.clone())
                                        .unwrap_or_else(default_hook_status),
                                    process_policy_version: record
                                        .process_policies
                                        .get(pid)
                                        .map(|policy| policy.policy_version)
                                        .unwrap_or_default(),
                                    process_rule_id: record
                                        .process_policies
                                        .get(pid)
                                        .and_then(|policy| policy.rule_id.clone()),
                                    process_decision_source: record
                                        .process_policies
                                        .get(pid)
                                        .map(|policy| policy.decision_source.clone())
                                        .unwrap_or_else(default_unknown_source),
                                }
                            })
                            .collect::<Vec<_>>();
                        processes.sort_by_key(|process| process.pid);
                        SessionSnapshot {
                            session_id: record.session_id.clone(),
                            root_pid: record.root_pid,
                            executable: record.executable.clone(),
                            lifecycle: record.lifecycle,
                            expires_at_ms: record.pending_expires_at.map(|expires| {
                                unix_timestamp_after(expires.saturating_duration_since(now))
                            }),
                            process_count: record.members.len(),
                            processes,
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        snapshots.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        snapshots
    }
}

fn pending_session(
    session_id: String,
    executable: String,
    now: Instant,
    pending_ttl: Duration,
) -> SessionRecord {
    SessionRecord {
        session_id,
        token: random_token(32),
        root_pid: 0,
        executable,
        lifecycle: SessionLifecycle::Pending,
        pending_expires_at: Some(now + pending_ttl),
        members: HashMap::new(),
        member_instances: HashMap::new(),
        process_policies: HashMap::new(),
        agent_heartbeats: HashMap::new(),
        fork_leases: HashMap::new(),
        fake_by_name: HashMap::new(),
        name_by_fake: HashMap::new(),
        next_fake_id: 1,
        cancellation: CancellationToken::new(),
    }
}

fn next_member_instance(state: &mut SessionState) -> u64 {
    let instance = state.next_member_instance;
    state.next_member_instance = state.next_member_instance.wrapping_add(1).max(1);
    instance
}

fn cleanup(state: &mut SessionState, now: Instant) {
    state.challenges.retain(|_, value| value.expires_at > now);
    for record in state.sessions.values_mut() {
        record
            .fork_leases
            .retain(|_, lease| lease.candidate_pid.is_some() || lease.expires_at > now);
    }
    let expired = state
        .sessions
        .iter()
        .filter(|(_, value)| {
            (value.lifecycle == SessionLifecycle::Pending
                && value
                    .pending_expires_at
                    .is_some_and(|expires| expires <= now))
                || (value.lifecycle == SessionLifecycle::RootProcess
                    && value.members.is_empty()
                    && value.fork_leases.is_empty())
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in expired {
        if let Some(record) = state.sessions.remove(&id) {
            record.cancellation.cancel();
        }
    }
}

fn random_token(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn session_proof(key: &[u8], challenge: &SessionChallenge) -> Result<Vec<u8>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|error| error.to_string())?;
    mac.update(b"hyperhub/session-proof/v1\0");
    update_field(&mut mac, challenge.challenge_id.as_bytes());
    update_field(&mut mac, challenge.session_id.as_bytes());
    update_field(&mut mac, challenge.executable.as_bytes());
    update_field(&mut mac, &challenge.client_nonce);
    update_field(&mut mac, &challenge.server_nonce);
    update_field(&mut mac, &challenge.descriptor.config_id);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// 配置热更新证明：CLI 用与会话相同的派生密钥对配置 JSON 做 HMAC，serve 用持有的
/// 同一密钥验证，防止控制管道上的伪造配置注入。
pub fn config_update_proof(key: &[u8], config_json: &str) -> Result<Vec<u8>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|error| error.to_string())?;
    mac.update(b"hyperhub/config-update/v1\0");
    update_field(&mut mac, config_json.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify_config_update_proof(key: &[u8], config_json: &str, proof: &[u8]) -> bool {
    match config_update_proof(key, config_json) {
        Ok(expected) => constant_time_eq(&expected, proof),
        Err(_) => false,
    }
}

fn update_field(mac: &mut Hmac<Sha256>, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlRequest {
    BeginSessionAuth {
        session_id: String,
        executable: String,
        client_nonce: [u8; 32],
    },
    FinishSessionAuth {
        challenge_id: String,
        proof: Vec<u8>,
    },
    BootstrapChild,
    ActivateSession {
        session_id: String,
        token: String,
        root_pid: u32,
        executable: String,
        #[serde(default)]
        root_executable: Option<String>,
        #[serde(default)]
        process_policy_version: u64,
        #[serde(default)]
        process_rule_id: Option<String>,
        #[serde(default = "default_unknown_source")]
        process_decision_source: String,
    },
    DecideProcessHook {
        session_id: String,
        token: String,
        executable: String,
        root: bool,
    },
    CheckRootProcessProtection {
        session_id: String,
        token: String,
        executable: String,
        argv: Vec<String>,
    },
    RegisterChild {
        session_id: String,
        token: String,
        parent_pid: u32,
        child_pid: u32,
        executable: String,
        #[serde(default)]
        process_policy_version: u64,
        #[serde(default)]
        process_rule_id: Option<String>,
        #[serde(default = "default_unknown_source")]
        process_decision_source: String,
    },
    BeginFork {
        session_id: String,
        token: String,
        parent_pid: u32,
    },
    RegisterForkCandidate {
        session_id: String,
        token: String,
        lease_id: String,
        parent_pid: u32,
        child_pid: u32,
        executable: String,
    },
    GetPendingForkLease {
        session_id: String,
        token: String,
    },
    AttestForkChild {
        session_id: String,
        token: String,
        lease_id: String,
        runtime_generation: u64,
        hook_manifest: Vec<String>,
        policy_version: u64,
    },
    GetForkStatus {
        session_id: String,
        token: String,
        lease_id: String,
    },
    FinishFork {
        session_id: String,
        token: String,
        lease_id: String,
        require_attested: bool,
    },
    ReportChildInjectionFailure {
        session_id: String,
        token: String,
        parent_pid: u32,
        child_pid: u32,
        executable: Option<String>,
        stage: String,
        error_code: u32,
    },
    RevokeSession {
        session_id: String,
    },
    ClearPasswordAuthorization,
    Ping,
    ResolveName {
        session_id: String,
        token: String,
        hostname: String,
        family: u8,
    },
    GetTrust {
        session_id: String,
        token: String,
    },
    ReportFirewallAudit {
        session_id: String,
        token: String,
        event: crate::firewall::FirewallAuditEvent,
    },
    RefreshFirewall {
        session_id: String,
        token: String,
        current_version: u64,
    },
    RefreshSandbox {
        session_id: String,
        token: String,
        root_pid: u32,
        current_version: u64,
    },
    SubscribeSandbox {
        session_id: String,
        token: String,
        current_version: u64,
    },
    ReportSandboxAudit {
        session_id: String,
        token: String,
        event: crate::sandbox::SandboxAuditEvent,
    },
    SmartProtectionCheck {
        session_id: String,
        token: String,
        protection_id: String,
        rule_id: Option<String>,
        stage: String,
        executable: String,
        argv: Vec<String>,
        features: Vec<String>,
        context: serde_json::Value,
    },
    StaticSmartProtectionCheck {
        session_id: String,
        token: String,
        root_pid: u32,
        process_pid: u32,
        protection_id: String,
        rule_id: Option<String>,
        stage: String,
        executable: String,
        argv: Vec<String>,
        features: Vec<String>,
        context: serde_json::Value,
    },
    ReportStaticSandboxAudit {
        session_id: String,
        token: String,
        root_pid: u32,
        event: crate::sandbox::SandboxAuditEvent,
    },
    UpdateConfig {
        proof: Vec<u8>,
        config_json: String,
    },
    GetStatus,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlResponse {
    SessionChallenge {
        challenge: SessionChallenge,
    },
    SessionBootstrap {
        socks_address: String,
        session_id: String,
        token: String,
        expires_at_ms: u64,
        lifecycle: SessionLifecycle,
        agent_flags: AgentFlags,
        tls_ca_pem: String,
        environment: Vec<SessionEnvironmentVariable>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox: Option<crate::sandbox::SandboxSnapshot>,
    },
    AgentBootstrap {
        socks_address: String,
        control_endpoint: String,
        session_id: String,
        token: String,
        tls_ca_pem: String,
        agent_flags: AgentFlags,
        environment: Vec<SessionEnvironmentVariable>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        firewall: Option<crate::firewall::FirewallSnapshot>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox: Option<crate::sandbox::SandboxSnapshot>,
    },
    ForkLease {
        lease_id: String,
    },
    ForkStatus {
        attested: bool,
    },
    Ok,
    ResolvedName {
        address: String,
        ttl_secs: u32,
    },
    TrustBootstrap {
        socks_address: String,
        agent_flags: AgentFlags,
        environment: Vec<SessionEnvironmentVariable>,
        tls_ca_pem: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        firewall: Option<crate::firewall::FirewallSnapshot>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox: Option<crate::sandbox::SandboxSnapshot>,
    },
    FirewallRefresh {
        version: u64,
        changed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        firewall: Option<crate::firewall::FirewallSnapshot>,
    },
    ProcessHookDecision {
        hook: bool,
        rule_id: Option<String>,
        source: String,
        version: u64,
    },
    SandboxUpdate {
        version: u64,
        changed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox: Option<crate::sandbox::SandboxSnapshot>,
    },
    SandboxRefresh {
        version: u64,
        changed: bool,
        enforce: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox: Option<crate::sandbox::SandboxSnapshot>,
    },
    Status {
        pid: u32,
        started_at_ms: u64,
        generated_at_ms: u64,
        sessions: Vec<SessionSnapshot>,
        connections: Vec<ConnectionSnapshot>,
    },
    SmartProtectionDecision {
        action: crate::config::SandboxAction,
        reason: String,
        risk_level: Option<String>,
        confidence: Option<f64>,
        cache_hit: bool,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionEnvironmentVariable {
    pub name: String,
    pub value: String,
}

pub fn unix_timestamp_after(ttl: Duration) -> u64 {
    (unix_timestamp_ms() as u128 + ttl.as_millis()).min(u64::MAX as u128) as u64
}

pub fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authenticated_registry() -> (SessionRegistry, SessionRecord) {
        let key = Zeroizing::new(vec![7; 32]);
        let registry = SessionRegistry::new(key.clone(), crate::config_store::new_descriptor());
        let client_nonce = [3; 32];
        let challenge = registry
            .begin_auth("s".into(), "curl".into(), client_nonce)
            .unwrap();
        let proof = session_proof(&key, &challenge).unwrap();
        let record = registry
            .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(10))
            .unwrap();
        assert!(registry.activate("s", &record.token, 7));
        (registry, record)
    }

    #[test]
    fn challenge_is_single_use_and_session_lives_until_revoke() {
        let (registry, record) = authenticated_registry();
        let auth = registry.authenticate("hh2:s:7:9", &record.token).unwrap();
        assert_eq!(auth.connection_id, 9);
        assert!(registry.revoke("s"));
        assert!(auth.cancellation.is_cancelled());
        assert!(registry.authenticate("hh2:s:7:10", &record.token).is_none());
    }

    #[test]
    fn child_must_be_registered() {
        let (registry, record) = authenticated_registry();
        assert!(registry.authenticate("hh2:s:8:1", &record.token).is_none());
        assert!(registry.register_child("s", &record.token, 7, 8, "child".into()));
        let child = registry.authenticate("hh2:s:8:1", &record.token).unwrap();
        assert_eq!(child.executable, "child");
    }

    #[test]
    fn session_lives_until_the_last_member_exits() {
        let (registry, record) = authenticated_registry();
        assert!(registry.register_child("s", &record.token, 7, 8, "child".into()));
        let root_instance = registry.member_instance("s", &record.token, 7).unwrap();
        let child_instance = registry.member_instance("s", &record.token, 8).unwrap();
        let auth = registry.authenticate("hh2:s:8:1", &record.token).unwrap();

        assert!(registry.member_exited("s", 7, root_instance));
        assert!(registry.authenticate("hh2:s:8:2", &record.token).is_some());
        assert!(!auth.cancellation.is_cancelled());

        assert!(registry.member_exited("s", 8, child_instance));
        assert!(auth.cancellation.is_cancelled());
        assert!(registry.authenticate("hh2:s:8:3", &record.token).is_none());
    }

    #[test]
    fn fork_lease_keeps_session_alive_and_requires_attestation() {
        let (registry, record) = authenticated_registry();
        let root_instance = registry.member_instance("s", &record.token, 7).unwrap();
        let lease = registry
            .begin_fork_lease("s", &record.token, 7, Duration::from_secs(1))
            .unwrap();
        assert!(registry.member_exited("s", 7, root_instance));
        assert_eq!(
            registry.fork_lease_status("s", &record.token, &lease, 7),
            Some(ForkLeaseStatus::Preparing)
        );
        assert!(registry.register_fork_candidate("s", &record.token, &lease, 7, 8, "child".into(),));
        assert_eq!(
            registry.fork_lease_status("s", &record.token, &lease, 7),
            Some(ForkLeaseStatus::Candidate)
        );
        assert!(registry.attest_fork_child("s", &record.token, &lease, 8, 42));
        assert_eq!(
            registry.fork_lease_status("s", &record.token, &lease, 7),
            Some(ForkLeaseStatus::Attested)
        );
        let finished = registry
            .finish_fork_lease("s", &record.token, &lease, true)
            .unwrap();
        assert_eq!(finished.candidate_pid, Some(8));
        assert!(finished.attested);
        assert!(registry.authenticate("hh2:s:8:1", &record.token).is_some());
    }

    #[test]
    fn unattested_fork_candidate_can_be_expired_once() {
        let (registry, record) = authenticated_registry();
        let lease = registry
            .begin_fork_lease("s", &record.token, 7, Duration::from_secs(1))
            .unwrap();
        assert!(registry.register_fork_candidate("s", &record.token, &lease, 7, 8, "child".into(),));
        assert_eq!(registry.expire_fork_candidate("s", &lease, 8), Some(8));
        assert_eq!(registry.expire_fork_candidate("s", &lease, 8), None);
        assert!(!registry.attest_fork_child("s", &record.token, &lease, 8, 1));
    }

    #[test]
    fn stale_process_monitor_cannot_remove_a_reused_pid() {
        let (registry, record) = authenticated_registry();
        assert!(registry.register_child("s", &record.token, 7, 8, "child".into()));
        let stale_instance = registry.member_instance("s", &record.token, 8).unwrap();
        assert!(registry.register_child("s", &record.token, 7, 8, "child".into()));
        let current_instance = registry.member_instance("s", &record.token, 8).unwrap();
        assert_ne!(stale_instance, current_instance);

        assert!(!registry.member_exited("s", 8, stale_instance));
        assert!(registry.authenticate("hh2:s:8:1", &record.token).is_some());
        assert!(registry.member_exited("s", 8, current_instance));
    }

    #[test]
    fn registered_member_can_refresh_after_exec() {
        let (registry, record) = authenticated_registry();
        assert!(registry.register_child("s", &record.token, 7, 8, "child-old".into()));
        assert!(registry.refresh_member_with_policy(
            "s",
            &record.token,
            8,
            "child-new".into(),
            ProcessHookMetadata {
                hook_status: "hook".into(),
                policy_version: 12,
                rule_id: Some("exec-rule".into()),
                decision_source: "rule".into(),
            },
        ));
        let child = registry.authenticate("hh2:s:8:1", &record.token).unwrap();
        assert_eq!(child.executable, "child-new");
        assert!(registry.note_agent("s", &record.token, 8, 0));
        let snapshot = registry.snapshot();
        let child = snapshot[0]
            .processes
            .iter()
            .find(|process| process.pid == 8)
            .unwrap();
        assert_eq!(child.process_policy_version, 12);
        assert_eq!(child.process_rule_id.as_deref(), Some("exec-rule"));
    }

    #[test]
    fn snapshots_managed_processes_without_agent_heartbeats() {
        let (registry, record) = authenticated_registry();
        assert!(registry.register_child("s", &record.token, 7, 8, "child".into()));

        let sessions = registry.snapshot();
        assert_eq!(sessions[0].process_count, 2);
        assert_eq!(sessions[0].processes.len(), 2);
        assert!(sessions[0].processes[0].root);
        assert_eq!(sessions[0].processes[0].pid, 7);
        assert_eq!(sessions[0].processes[0].last_seen_ms, 0);
        assert_eq!(sessions[0].processes[0].firewall_version, 0);
        assert_eq!(sessions[0].processes[1].pid, 8);
        assert_eq!(sessions[0].processes[1].executable, "child");
    }

    #[test]
    fn snapshots_managed_processes_with_agent_telemetry() {
        let (registry, record) = authenticated_registry();
        assert!(registry.register_child("s", &record.token, 7, 8, "child".into()));
        assert!(registry.note_agent("s", &record.token, 7, 10));
        assert!(registry.note_agent("s", &record.token, 8, 11));
        assert!(!registry.note_agent("s", "wrong", 8, 12));

        let sessions = registry.snapshot();
        assert_eq!(sessions[0].process_count, 2);
        assert_eq!(sessions[0].processes.len(), 2);
        assert!(sessions[0].processes[0].root);
        assert_eq!(sessions[0].processes[0].firewall_version, 10);
        assert_eq!(sessions[0].processes[1].executable, "child");
        assert_eq!(sessions[0].processes[1].firewall_version, 11);
    }

    #[test]
    fn active_parent_member_can_create_a_pending_session_without_a_password() {
        let (registry, _) = authenticated_registry();
        let inherited = registry
            .begin_inherited(
                "child-session".into(),
                "child.exe".into(),
                7,
                Duration::from_secs(10),
            )
            .unwrap();
        assert_eq!(inherited.lifecycle, SessionLifecycle::Pending);
        assert_eq!(inherited.executable, "child.exe");
        assert!(registry
            .begin_inherited(
                "unrelated".into(),
                "child.exe".into(),
                999,
                Duration::from_secs(10),
            )
            .is_none());
        let child = registry
            .inherit_member(7, 8, "direct-native-child.exe".into())
            .unwrap();
        assert!(registry.authenticate("hh2:s:8:1", &child.token).is_some());
    }

    #[test]
    fn password_auth_enables_cached_authorization_until_cleared() {
        let key = Zeroizing::new(vec![8; 32]);
        let registry = SessionRegistry::new(key.clone(), crate::config_store::new_descriptor());
        let challenge = registry
            .begin_auth("first".into(), "bash".into(), [4; 32])
            .unwrap();
        let proof = session_proof(&key, &challenge).unwrap();
        assert!(registry
            .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(10))
            .is_some());

        let cached = registry
            .begin_cached_auth("second".into(), "curl".into(), Duration::from_secs(10))
            .unwrap();
        assert_eq!(cached.executable, "curl");
        assert!(registry.clear_password_authorization());
        assert!(registry
            .begin_cached_auth("third".into(), "ssh".into(), Duration::from_secs(10))
            .is_none());
    }

    #[test]
    fn clearing_authorization_does_not_revoke_existing_sessions() {
        let (registry, _record) = authenticated_registry();
        assert_eq!(registry.member_executable(7).as_deref(), Some("curl"));
        assert!(registry.clear_password_authorization());
        assert_eq!(registry.member_executable(7).as_deref(), Some("curl"));
    }

    #[test]
    fn activated_session_ignores_the_pending_ttl() {
        let key = Zeroizing::new(vec![7; 32]);
        let registry = SessionRegistry::new(key.clone(), crate::config_store::new_descriptor());
        let challenge = registry
            .begin_auth("long".into(), "target".into(), [3; 32])
            .unwrap();
        let proof = session_proof(&key, &challenge).unwrap();
        let record = registry
            .finish_auth(&challenge.challenge_id, &proof, Duration::from_millis(1))
            .unwrap();
        assert!(registry.activate("long", &record.token, 9));
        std::thread::sleep(Duration::from_millis(5));
        assert!(registry
            .authenticate("hh2:long:9:1", &record.token)
            .is_some());
    }

    #[test]
    fn rejects_wrong_and_replayed_proofs() {
        let key = Zeroizing::new(vec![9; 32]);
        let registry = SessionRegistry::new(key, crate::config_store::new_descriptor());
        let challenge = registry
            .begin_auth("s".into(), "curl".into(), [1; 32])
            .unwrap();
        assert!(registry
            .finish_auth(&challenge.challenge_id, &[0; 32], Duration::from_secs(10))
            .is_none());
        assert!(registry
            .finish_auth(&challenge.challenge_id, &[0; 32], Duration::from_secs(10))
            .is_none());
    }

    #[test]
    fn allocates_and_restores_session_fake_addresses() {
        let (registry, record) = authenticated_registry();
        let first = registry
            .resolve_fake("s", &record.token, "Api.Example.test.", 4)
            .unwrap();
        let again = registry
            .resolve_fake("s", &record.token, "api.example.test", 4)
            .unwrap();
        assert_eq!(first, again);
        assert_eq!(first, "198.18.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            registry.restore_fake("s", first).as_deref(),
            Some("api.example.test")
        );
    }

    #[test]
    fn snapshots_active_connections_without_tokens() {
        let (sessions, _) = authenticated_registry();
        let snapshots = sessions.snapshot();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].lifecycle, SessionLifecycle::RootProcess);

        let connections = ConnectionRegistry::default();
        let destination = Destination {
            ip: "127.0.0.1".parse().unwrap(),
            port: 7897,
            hostnames: Vec::new(),
        };
        let now = unix_timestamp_ms();
        let active = connections.track(ConnectionSnapshot {
            session_id: "s".into(),
            connection_id: 9,
            pid: 7,
            executable: "curl".into(),
            original_destination: destination.clone(),
            destination: destination.clone(),
            protocol: Protocol::Unknown,
            rule_id: None,
            action: "pending".into(),
            route_upstream: None,
            client_proxy: None,
            phase: "routing".into(),
            started_at_ms: now,
            updated_at_ms: now,
        });
        active.update(
            &destination,
            Protocol::Tls,
            Some("rule"),
            "proxy",
            None,
            None,
            "connected",
        );
        assert_eq!(connections.snapshot()[0].phase, "connected");
        drop(active);
        assert!(connections.snapshot().is_empty());
    }
}
