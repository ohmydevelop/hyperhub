//! Core-owned issuance history. A numeric alias becomes public only after every
//! admitted live Host acknowledges the same signed provenance prefix.
use super::*;
use crate::attachments::{self, Authorization, ProcessIdentity};
use hyperhub_runtime::attachment as wire;
use std::collections::HashMap;
use std::sync::Mutex;

type SharedHistory = Arc<Mutex<History>>;
#[derive(Clone, Default)]
pub(super) struct AliasHistories(Arc<Mutex<HashMap<String, SharedHistory>>>);
#[derive(serde::Serialize, serde::Deserialize)]
struct History {
    #[serde(skip)]
    operation: Arc<Mutex<()>>,
    bootstrap: wire::Bootstrap,
    records: Vec<wire::IssuedRecord>,
    heads: Vec<[u8; 32]>,
    hosts: HashMap<u32, Host>,
    proof: Option<wire::ApprovalProof>,
    // Cleanup-only locators can outlive an unknown inherited prefix. Never
    // publish or acknowledge full completion until real history is restored.
    #[serde(default)]
    cleanup_unproven: bool,
    durable_sequence: u64,
    detaching: Option<[u8; 32]>,
    barrier_scan: Option<DetachBarrierScan>,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct DetachBarrierScan {
    nonce: [u8; 32],
    cancel: bool,
    roster: [u8; 32],
    cursor: usize,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Host {
    identity: ProcessIdentity,
    bootstrap: wire::Bootstrap,
    sequence: u64,
    ready: bool,
    #[serde(default)]
    startup_cleanup_only: bool,
    #[serde(default)]
    startup_pristine: bool,
    signer: [u8; 32],
}
/// A never-active Fresh Host may have no local alias ACK yet. It must not
/// hide an already issued Core prefix behind its empty initialization runtime.
fn verify_startup_cleanup_prefix(
    status: &wire::HostStatus,
    history_empty: bool,
) -> Result<(), String> {
    if !status.native_ready
        && status
            .initialization
            .as_ref()
            .is_some_and(|initialization| {
                initialization.origin == wire::InitializationOrigin::Fresh
                    && !initialization.ever_active
            })
        && !history_empty
    {
        return Err("startup cleanup requires an empty Core alias history".into());
    }
    Ok(())
}
fn startup_pristine(status: &wire::HostStatus) -> bool {
    status
        .initialization
        .as_ref()
        .is_some_and(|initialization| {
            initialization.origin == wire::InitializationOrigin::Fresh
                && !initialization.ever_active
                && !initialization.initializing
                && initialization.runtime_available
        })
        && status.active_calls == 0
        && status.phase != wire::HostPhase::Active
        && status
            .alias_inheritance
            .as_ref()
            .is_none_or(|anchor| anchor.sequence == 0 && anchor.head == [0; 32])
        && status.fake_addresses == 0
        && status.tracked_sockets == 0
        && status.pending_alias_publications == 0
        && status.spawn_calls == 0
}
fn detach_status_acknowledges(status: &wire::HostStatus) -> bool {
    // Logical detachment closes policy admission before native callbacks can
    // necessarily return.  A resident Host must keep reporting those calls so
    // physical retirement cannot unload their return path, but Core must not
    // hold the attachment record in Detaching until an application unblocks.
    // A Host that claims full Detached state has no such allowance.
    (status.phase == wire::HostPhase::DetachedResident
        || (status.phase == wire::HostPhase::Detached && status.active_calls == 0))
        && status.pending_alias_publications == 0
        && status.spawn_calls == 0
        // Resident is not full completion when inherited resources are unknown.
        && !status.initialization.as_ref().is_some_and(|initialization| !initialization.runtime_available || initialization.initializing)
}
fn live_barrier_roster(history: &History) -> Vec<attachments::HostCommandTarget> {
    let mut roster = history
        .hosts
        .values()
        .filter(|host| attachments::process_birth(host.identity.pid) == Some(host.identity.birth))
        .map(|host| attachments::HostCommandTarget {
            identity: host.identity.clone(),
            endpoint: host.bootstrap.host_endpoint.clone(),
            token: host.bootstrap.host_token.clone(),
        })
        .collect::<Vec<_>>();
    roster.sort_by_key(|target| (target.identity.pid, target.identity.birth));
    roster
}
fn barrier_roster_digest(roster: &[attachments::HostCommandTarget]) -> Result<[u8; 32], String> {
    use sha2::Digest;
    Ok(sha2::Sha256::digest(serde_json::to_vec(roster).map_err(|e| e.to_string())?).into())
}
fn bounded_barrier_plan(
    nonce: [u8; 32],
    command: wire::HostLifecycleCommand,
    mut targets: Vec<attachments::HostCommandTarget>,
) -> Result<ControlResponse, String> {
    targets.truncate(attachments::DETACH_BARRIER_BATCH_LIMIT);
    loop {
        let response = ControlResponse::AttachmentDetachPlan {
            plan: attachments::DetachBarrierPlan {
                authorization_nonce: nonce,
                command,
                targets: targets.clone(),
            },
        };
        if serde_json::to_vec(&response)
            .map_err(|e| e.to_string())?
            .len()
            <= wire::MAX_FRAME / 2
        {
            return Ok(response);
        }
        if targets.len() <= 1 {
            return Err("one Host locator exceeds the bounded barrier frame".into());
        }
        targets.pop();
    }
}
/// Alias catchup can already know the new Core key while RootImage still pins
/// the previous key. A live root challenge needs the same fresh administrator
/// endorsement, but an old/expired or pre-exec proof must not poison normal
/// same-Core registration after an execution transition.
fn registration_proof(
    directory: &std::path::Path,
    bootstrap: &wire::Bootstrap,
    proof: Option<&wire::ApprovalProof>,
    signer: [u8; 32],
    root_image: Option<&wire::SignedRootImage>,
    now: u64,
    recipient_pid: u32,
) -> Option<wire::ApprovalProof> {
    let current = attachments::approval_trust(directory).ok()?.core_public_key;
    let proof = proof?;
    if let Some(packet) = root_image {
        let authority = attachments::trusted_authority(directory).ok()?;
        let claims = wire::verify_proof_with_key_for_recipient(
            bootstrap,
            &authority.public_key,
            proof,
            now,
            recipient_pid,
        )
        .ok()?;
        let snapshot = wire::decode_root_image(bootstrap, &current, packet).ok()?;
        if snapshot.host_pid != Some(recipient_pid)
            || claims.core_attestation_public_key != Some(current)
            || claims.root_image.as_ref() != Some(&snapshot.current.identity)
            || claims.exec_epoch != snapshot.current.exec_epoch
        {
            return None;
        }
        Some(proof.clone())
    } else if signer != current {
        Some(proof.clone())
    } else {
        None
    }
}
impl History {
    fn head(&self, sequence: u64) -> Result<[u8; 32], String> {
        self.heads
            .get(usize::try_from(sequence).map_err(|_| "invalid alias cursor")?)
            .copied()
            .ok_or_else(|| "alias cursor exceeds proven history".into())
    }
    fn page(
        &self,
        directory: &std::path::Path,
        base: u64,
    ) -> Result<wire::SignedSessionAliasSnapshot, String> {
        let previous_head = self.head(base)?;
        let mut end = (base as usize + 64).min(self.records.len());
        loop {
            let snapshot = attachments::sign_session_aliases(
                directory,
                &wire::AliasSnapshotPayload {
                    schema_version: 1,
                    instance_id: self.bootstrap.approval_instance_id.clone(),
                    attachment_id: self.bootstrap.attachment_id.clone(),
                    root_pid: self.bootstrap.root_pid,
                    session_id: self.bootstrap.session_id.clone(),
                    host_binding: self
                        .bootstrap
                        .approval_binding()
                        .map_err(|e| e.to_string())?,
                    base_sequence: base,
                    previous_head,
                    sequence: end as u64,
                    head: self.head(end as u64)?,
                    records: self.records[base as usize..end].to_vec(),
                    complete: true,
                },
            )?;
            // Vec<u8> JSON encoding expands the signed bytes. Bound the actual
            // outer response, not just the canonical payload.
            let size = serde_json::to_vec(&ControlResponse::AliasHostRegistration {
                ready: false,
                snapshot: Some(snapshot.clone()),
                proof: self.proof.clone(),
                root_image: None,
            })
            .map_err(|e| e.to_string())?
            .len();
            if size < wire::MAX_FRAME / 2 {
                return Ok(snapshot);
            }
            if end <= base as usize + 1 {
                return Err("one alias record exceeds the bounded transport".into());
            }
            end = base as usize + (end - base as usize) / 2;
        }
    }
}
impl ControlService {
    /// Retain real Host endpoints for approved cleanup even if startup never
    /// reached alias registration. An unknown inherited prefix remains unknown.
    pub(super) fn register_startup_cleanup_hosts(
        &self,
        bindings: &[attachments::HostBootstrapBinding],
    ) -> Result<(), String> {
        let directory = self
            .attachment_directory
            .as_ref()
            .ok_or("attachments unavailable")?;
        let signer = attachments::approval_trust(directory)?.core_public_key;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        for binding in bindings {
            // Authorization and the Core session fence precede this helper.
            // An unreachable endpoint is still a real scoped pending attempt;
            // it must not prevent the manager from reopening that exact Base.
            let status = if std::time::Instant::now() < deadline {
                wire::exchange_for_process(
                    &binding.bootstrap.host_endpoint,
                    &wire::AuthenticatedCommand {
                        attachment_id: binding.bootstrap.attachment_id.clone(),
                        token: binding.bootstrap.host_token.clone(),
                        command: wire::HostCommand::Status,
                        proof: None,
                        enrollment: None,
                        aliases: None,
                        root_image: None,
                    },
                    binding.identity.pid,
                )
                .ok()
            } else {
                None
            };
            attachments::verify_process(&binding.identity)?;
            if status.as_ref().is_some_and(|status| {
                status.pid != binding.identity.pid
                    || status.attachment_id != binding.bootstrap.attachment_id
            }) {
                return Err("startup cleanup Host status has a different incarnation scope".into());
            }
            let pristine = status
                .as_ref()
                .is_some_and(|status| startup_pristine(status))
                && self
                    .sessions
                    .startup_aliases_empty(&binding.bootstrap.session_id, &binding.bootstrap.token);
            let mut histories = self
                .alias_histories
                .0
                .lock()
                .map_err(|_| "alias histories unavailable")?;
            let shared = histories
                .entry(binding.bootstrap.session_id.clone())
                .or_insert_with(|| {
                    Arc::new(Mutex::new(History {
                        operation: Arc::new(Mutex::new(())),
                        bootstrap: binding.bootstrap.clone(),
                        records: vec![],
                        heads: vec![[0; 32]],
                        hosts: HashMap::new(),
                        proof: None,
                        cleanup_unproven: !pristine,
                        durable_sequence: 0,
                        detaching: None,
                        barrier_scan: None,
                    }))
                })
                .clone();
            drop(histories);
            let mut history = shared.lock().map_err(|_| "alias history unavailable")?;
            if history
                .bootstrap
                .approval_binding()
                .map_err(|e| e.to_string())?
                != binding
                    .bootstrap
                    .approval_binding()
                    .map_err(|e| e.to_string())?
            {
                return Err("startup cleanup Host changed the retained immutable binding".into());
            }
            if let Some(host) = history.hosts.get_mut(&binding.identity.pid) {
                if host.identity != binding.identity
                    || host.bootstrap.host_endpoint != binding.bootstrap.host_endpoint
                    || host.bootstrap.host_token != binding.bootstrap.host_token
                {
                    return Err(
                        "startup cleanup cannot replace a registered Host incarnation".into(),
                    );
                }
                if host.startup_cleanup_only {
                    host.startup_pristine = pristine;
                }
            } else {
                let proven_cursor = status
                    .as_ref()
                    .and_then(|status| status.alias_inheritance.as_ref())
                    .filter(|anchor| history.head(anchor.sequence).ok() == Some(anchor.head));
                if !pristine && proven_cursor.is_none() {
                    history.cleanup_unproven = true;
                }
                history.hosts.insert(
                    binding.identity.pid,
                    Host {
                        identity: binding.identity.clone(),
                        bootstrap: binding.bootstrap.clone(),
                        ready: false,
                        startup_cleanup_only: true,
                        startup_pristine: pristine,
                        sequence: proven_cursor.map(|anchor| anchor.sequence).unwrap_or(0),
                        signer: proven_cursor
                            .map(|anchor| anchor.public_key)
                            .or(binding.bootstrap.approval_core_public_key)
                            .unwrap_or(signer),
                    },
                );
            }
            if history
                .hosts
                .values()
                .any(|host| host.startup_cleanup_only && !host.startup_pristine)
            {
                history.cleanup_unproven = true;
            } else if history.cleanup_unproven
                && history.records.is_empty()
                && history.durable_sequence == 0
            {
                // Real repeated Status observations, not a replayed display
                // phase, can prove the original Fresh initializer has ended.
                history.cleanup_unproven = false;
            }
            self.sessions.note_native_observed(
                &binding.bootstrap.session_id,
                &binding.bootstrap.token,
                binding.identity.pid,
            );
        }
        Ok(())
    }
    pub(super) fn validate_unstarted_aliases(
        &self,
        session: &str,
        unstarted: &[attachments::HostBootstrapBinding],
        empty_hosts: bool,
    ) -> Result<(), String> {
        let histories = self
            .alias_histories
            .0
            .lock()
            .map_err(|_| "alias histories unavailable")?;
        if let Some(shared) = histories.get(session) {
            let history = shared.lock().map_err(|_| "alias history unavailable")?;
            if (empty_hosts
                && (!history.hosts.is_empty()
                    || !history.records.is_empty()
                    || history.durable_sequence != 0))
                || unstarted.iter().any(|binding| {
                    history.hosts.contains_key(&binding.identity.pid)
                        || history.records.iter().any(|record| {
                            record.issuer_pid == binding.identity.pid
                                && record.issuer_birth == binding.identity.birth
                        })
                })
            {
                return Err(
                    "unstarted cleanup conflicts with registered alias Hosts or issuance".into(),
                );
            }
        }
        Ok(())
    }
    fn alias_history(&self, bootstrap: &wire::Bootstrap) -> Result<SharedHistory, String> {
        let directory = self
            .attachment_directory
            .as_ref()
            .ok_or("session alias publication is unavailable")?;
        let record = attachments::load_record(&attachments::attachment_directory(
            directory,
            &bootstrap.attachment_id,
        )?)?;
        if record.session_id != bootstrap.session_id
            || record.spec.target.pid != bootstrap.root_pid
            || record.host_binding.as_deref()
                != Some(&bootstrap.approval_binding().map_err(|e| e.to_string())?)
            || !self
                .sessions
                .authenticate_control(&bootstrap.session_id, &bootstrap.token)
        {
            return Err("alias Host does not match an authenticated attachment Bootstrap".into());
        }
        let mut histories = self
            .alias_histories
            .0
            .lock()
            .map_err(|_| "alias histories unavailable")?;
        if let Some(history) = histories.get(&bootstrap.session_id) {
            if history
                .lock()
                .map_err(|_| "alias history unavailable")?
                .cleanup_unproven
            {
                return Err("startup cleanup retains an unproven inherited alias prefix".into());
            }
            return Ok(history.clone());
        }
        let current = attachments::approval_trust(directory)?.core_public_key;
        if bootstrap.approval_core_public_key != Some(current) {
            return Err(
                "alias history needs a fresh approved Core endorsement and proven prior prefix"
                    .into(),
            );
        }
        if bootstrap
            .alias_inherited
            .as_ref()
            .is_some_and(|anchor| anchor.sequence != 0 || anchor.head != [0; 32])
        {
            return Err(
                "nonempty inherited alias history must be restored from authenticated Hosts".into(),
            );
        }
        let history = Arc::new(Mutex::new(History {
            operation: Arc::new(Mutex::new(())),
            bootstrap: bootstrap.clone(),
            records: vec![],
            heads: vec![[0; 32]],
            hosts: HashMap::new(),
            proof: None,
            cleanup_unproven: false,
            durable_sequence: 0,
            detaching: None,
            barrier_scan: None,
        }));
        histories.insert(bootstrap.session_id.clone(), history.clone());
        Ok(history)
    }
    pub(super) fn register_alias_host(
        &self,
        identity: Option<ProcessIdentity>,
        bootstrap: wire::Bootstrap,
        sequence: u64,
        head: [u8; 32],
        root_image_challenge: Option<[u8; 32]>,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            let peer = peer_pid.ok_or("alias registration requires an OS peer")?;
            if self
                .sessions
                .cleanup_fenced(&bootstrap.session_id, &bootstrap.token)
            {
                return Err("startup cleanup has fenced alias Host registration".into());
            }
            let identity = match identity {
                None => attachments::inspect_process(peer)?,
                Some(identity) => {
                    let birth = attachments::process_birth(peer).ok_or("alias manager exited")?;
                    if self.sessions.engine_manager_start(
                        &bootstrap.session_id,
                        &bootstrap.token,
                        peer,
                    ) != Some(birth)
                    {
                        return Err(
                            "alias Host hint requires the actual authenticated manager".into()
                        );
                    }
                    attachments::verify_process(&identity)?;
                    identity
                }
            };
            if !self.sessions.authenticate_member(
                &bootstrap.session_id,
                &bootstrap.token,
                identity.pid,
            ) {
                return Err("alias registration requires an existing live session member".into());
            }
            self.sessions.note_native_observed(
                &bootstrap.session_id,
                &bootstrap.token,
                identity.pid,
            );
            let shared = self.alias_history(&bootstrap)?;
            let mut history = shared.lock().map_err(|_| "alias history unavailable")?;
            if history
                .bootstrap
                .approval_binding()
                .map_err(|e| e.to_string())?
                != bootstrap.approval_binding().map_err(|e| e.to_string())?
                || history.head(sequence)? != head
            {
                return Err(
                    "alias registration cursor or immutable Bootstrap differs from proven history"
                        .into(),
                );
            }
            let signer = bootstrap
                .alias_inherited
                .as_ref()
                .map(|anchor| anchor.public_key)
                .or(bootstrap.approval_core_public_key)
                .ok_or("Host has no trusted alias signer")?;
            let ready = history.detaching.is_none()
                && sequence == history.records.len() as u64
                && signer
                    == attachments::approval_trust(self.attachment_directory.as_ref().unwrap())?
                        .core_public_key;
            // Root identity must be established before an alias signer anchor
            // page can validate the fresh operation's executable epoch.
            let root_image = root_image_challenge
                .map(|challenge| {
                    attachments::challenged_root_image(
                        self.attachment_directory.as_ref().unwrap(),
                        &bootstrap,
                        &identity,
                        challenge,
                    )
                })
                .transpose()?;
            let proof = registration_proof(
                self.attachment_directory.as_ref().unwrap(),
                &bootstrap,
                history.proof.as_ref(),
                signer,
                root_image.as_ref(),
                unix_timestamp_ms(),
                identity.pid,
            );
            history.hosts.insert(
                identity.pid,
                Host {
                    identity,
                    bootstrap,
                    sequence,
                    ready,
                    startup_cleanup_only: false,
                    startup_pristine: false,
                    signer,
                },
            );
            Ok(ControlResponse::AliasHostRegistration {
                ready,
                snapshot: if ready
                    || (history.detaching.is_some()
                        && sequence == history.records.len() as u64
                        && signer
                            == attachments::approval_trust(
                                self.attachment_directory.as_ref().unwrap(),
                            )?
                            .core_public_key)
                {
                    None
                } else {
                    Some(history.page(self.attachment_directory.as_ref().unwrap(), sequence)?)
                },
                proof,
                root_image,
            })
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    pub(super) fn resolve_session_alias(
        &self,
        session_id: String,
        token: String,
        hostname: String,
        family: u8,
        native: Option<wire::NativeFallback>,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            let pid = peer_pid.ok_or("alias publication requires an OS member")?;
            if !self.sessions.authenticate_member(&session_id, &token, pid) {
                return Err("alias publisher is not a live session member".into());
            }
            let native = native.ok_or(
                "synthetic DNS requires explicit native provenance and signed Host admission",
            )?;
            native.validate_synthesis().map_err(|e| e.to_string())?;
            if native.family != u32::from(family) {
                return Err("native provenance address family differs from request".into());
            }
            let shared = self
                .alias_histories
                .0
                .lock()
                .map_err(|_| "alias histories unavailable")?
                .get(&session_id)
                .cloned()
                .ok_or("alias publisher has not completed Host admission")?;
            let operation = shared
                .lock()
                .map_err(|_| "alias history unavailable")?
                .operation
                .clone();
            let _operation = operation
                .lock()
                .map_err(|_| "alias publication unavailable")?;
            let mut history = shared.lock().map_err(|_| "alias history unavailable")?;
            let host = history
                .hosts
                .get(&pid)
                .ok_or("alias publisher has no registered Host")?;
            if !host.ready || attachments::process_birth(pid) != Some(host.identity.birth) {
                return Err("alias publisher has not caught up or changed incarnation".into());
            }
            let name = hostname.trim_end_matches('.').to_ascii_lowercase();
            let address = self
                .sessions
                .resolve_fake_native(&session_id, &token, &name, &native)
                .ok_or("invalid alias request or exhausted address pool")?;
            let index = if let Some(index) = history
                .records
                .iter()
                .position(|record| record.address == address)
            {
                index
            } else {
                let record = wire::IssuedRecord {
                    sequence: history.records.len() as u64 + 1,
                    address,
                    hostname: name,
                    native_fallback: native,
                    issuer_pid: pid,
                    issuer_birth: host.identity.birth,
                    ambiguous: false,
                };
                let head = wire::alias_record_head(history.heads.last().unwrap(), &record)
                    .map_err(|e| e.to_string())?;
                history.records.push(record);
                history.heads.push(head);
                history.records.len() - 1
            };
            self.persist_alias_tail(&mut history)?;
            let issued_head = history.head(index as u64 + 1)?;
            drop(history);
            self.publish_aliases(&shared)?;
            Ok(ControlResponse::ResolvedName {
                address: address.to_string(),
                ttl_secs: 60,
                issued_sequence: Some(index as u64 + 1),
                issued_head: Some(issued_head),
            })
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    pub(super) fn restore_alias_history(
        &self,
        authorization: &Authorization,
        sources: &[(
            attachments::HostBootstrapBinding,
            wire::AliasSnapshot,
            Option<wire::AliasInheritance>,
            Option<wire::RootImageState>,
        )],
    ) -> Result<(), String> {
        let directory = self
            .attachment_directory
            .as_ref()
            .ok_or("alias history unavailable")?;
        let current = attachments::approval_trust(directory)?.core_public_key;
        if authorization.core_attestation_public_key != Some(current) {
            return Err("alias restoration lacks the exact fresh Core endorsement".into());
        }
        let proof = attachments::host_proof(authorization)?;
        let (first, _, _, _) = sources
            .first()
            .ok_or("alias restoration has no authenticated source")?;
        let binding = first
            .bootstrap
            .approval_binding()
            .map_err(|e| e.to_string())?;
        let mut records: Vec<wire::IssuedRecord> = Vec::new();
        let mut known_keys = vec![current];
        for (host, snapshot, inheritance, _) in sources {
            if host
                .bootstrap
                .approval_binding()
                .map_err(|e| e.to_string())?
                != binding
                || !snapshot.complete
            {
                return Err("alias source binding or publication completeness differs".into());
            }
            let anchor = inheritance
                .as_ref()
                .ok_or("alias source has no authenticated namespace anchor")?;
            if anchor.sequence != snapshot.history_records.len() as u64 {
                return Err("alias source full history is missing a retained prefix".into());
            }
            let mut head = [0; 32];
            for (index, record) in snapshot.history_records.iter().enumerate() {
                if record.sequence != index as u64 + 1
                    || record.issuer_pid == 0
                    || record.issuer_birth == 0
                {
                    return Err("alias source sequence or issuer invalid".into());
                }
                head = wire::alias_record_head(&head, record).map_err(|e| e.to_string())?;
            }
            if head != anchor.head {
                return Err("alias source history head differs from retained anchor".into());
            }
            let common = records.len().min(snapshot.history_records.len());
            if records[..common] != snapshot.history_records[..common] {
                return Err("authenticated alias consumers disagree on issuance history".into());
            }
            if snapshot.history_records.len() > records.len() {
                records = snapshot.history_records.clone();
            }
            if !known_keys.contains(&anchor.public_key) {
                known_keys.push(anchor.public_key);
            }
        }
        let mut heads = vec![[0; 32]];
        for record in &records {
            heads.push(
                wire::alias_record_head(heads.last().unwrap(), record)
                    .map_err(|e| e.to_string())?,
            );
        }
        let journal = directory
            .join("alias-history")
            .join(attachments::digest(first.bootstrap.session_id.as_bytes()));
        if journal.exists() {
            let mut paths = std::fs::read_dir(&journal)
                .map_err(|e| e.to_string())?
                .map(|entry| entry.map(|e| e.path()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            paths.sort();
            for path in paths {
                let snapshot: wire::SignedSessionAliasSnapshot = serde_json::from_slice(
                    &attachments::read_private_file(&path, wire::MAX_FRAME as u64)?,
                )
                .map_err(|e| e.to_string())?;
                let covered: wire::AliasSnapshotPayload = serde_json::from_slice(
                    snapshot
                        .payload
                        .strip_prefix(wire::SESSION_ALIAS_DOMAIN)
                        .ok_or("alias journal domain invalid")?,
                )
                .map_err(|e| e.to_string())?;
                // An authenticated live Host already proves the entire covered
                // prefix. A file cannot contribute any new authority there.
                let payload = if covered.sequence <= records.len() as u64 {
                    if covered.schema_version != 1
                        || covered.instance_id != first.bootstrap.approval_instance_id
                        || covered.attachment_id != first.bootstrap.attachment_id
                        || covered.session_id != first.bootstrap.session_id
                        || covered.root_pid != first.bootstrap.root_pid
                        || covered.host_binding != binding
                        || !covered.complete
                        || covered.base_sequence > covered.sequence
                    {
                        return Err("covered alias journal scope differs".into());
                    }
                    covered
                } else {
                    known_keys.iter().find_map(|key|wire::decode_alias_snapshot(&first.bootstrap,key,&snapshot).ok()).ok_or("alias journal tail is not signed by an authenticated retained Core signer")?
                };
                if payload.sequence <= records.len() as u64 {
                    if heads.get(payload.base_sequence as usize) != Some(&payload.previous_head)
                        || records.get(payload.base_sequence as usize..payload.sequence as usize)
                            != Some(payload.records.as_slice())
                    {
                        return Err(
                            "alias journal conflicts with authenticated retained prefix".into()
                        );
                    }
                } else {
                    if payload.base_sequence != records.len() as u64
                        || payload.previous_head != *heads.last().unwrap()
                    {
                        return Err("alias journal has an unproven gap or missing tail".into());
                    }
                    for record in payload.records {
                        heads.push(
                            wire::alias_record_head(heads.last().unwrap(), &record)
                                .map_err(|e| e.to_string())?,
                        );
                        records.push(record);
                    }
                }
            }
        }
        let roots = sources
            .iter()
            .map(|(_, _, _, root)| {
                root.clone()
                    .ok_or("authenticated Host omitted retained root image epoch")
            })
            .collect::<Result<Vec<_>, _>>()?;
        attachments::restore_root_image(directory, &first.bootstrap, &roots)?;
        self.sessions.merge_approved_issued_records(
            &first.bootstrap.session_id,
            &first.bootstrap.token,
            &records,
        )?;
        let mut histories = self
            .alias_histories
            .0
            .lock()
            .map_err(|_| "alias histories unavailable")?;
        let shared = histories
            .entry(first.bootstrap.session_id.clone())
            .or_insert_with(|| {
                Arc::new(Mutex::new(History {
                    operation: Arc::new(Mutex::new(())),
                    bootstrap: first.bootstrap.clone(),
                    records: vec![],
                    heads: vec![[0; 32]],
                    hosts: HashMap::new(),
                    proof: None,
                    cleanup_unproven: false,
                    durable_sequence: 0,
                    detaching: None,
                    barrier_scan: None,
                }))
            })
            .clone();
        drop(histories);
        let operation = shared
            .lock()
            .map_err(|_| "alias history unavailable")?
            .operation
            .clone();
        let _operation = operation
            .lock()
            .map_err(|_| "alias publication unavailable")?;
        let mut history = shared.lock().map_err(|_| "alias history unavailable")?;
        let common = history.records.len().min(records.len());
        if history.records[..common] != records[..common] {
            return Err("restored history conflicts with live publisher".into());
        }
        if history.records.len() > records.len() {
            return Err("restoration would roll back a live issuance history".into());
        }
        history.records = records;
        history.heads = heads;
        history.proof = Some(proof);
        history.cleanup_unproven = false;
        history.detaching = None;
        history.barrier_scan = None;
        for (host, _, anchor, _) in sources {
            let sequence = anchor.as_ref().unwrap().sequence;
            history.hosts.insert(
                host.identity.pid,
                Host {
                    identity: host.identity.clone(),
                    bootstrap: host.bootstrap.clone(),
                    sequence,
                    ready: true,
                    startup_cleanup_only: false,
                    startup_pristine: false,
                    signer: anchor.as_ref().unwrap().public_key,
                },
            );
        }
        self.persist_alias_tail(&mut history)?;
        drop(history);
        self.publish_aliases(&shared)?;
        Ok(())
    }
    fn detach_history(
        &self,
        authorization: &Authorization,
        session_id: &str,
        token: &str,
        manager: &ProcessIdentity,
        peer_pid: Option<u32>,
    ) -> Result<Option<SharedHistory>, String> {
        let directory = self
            .attachment_directory
            .as_ref()
            .ok_or("attachments unavailable")?;
        let attachments::Action::Detach { attachment_id, .. } = &authorization.request.action
        else {
            return Err("alias detach barrier requires a Detach approval".into());
        };
        if peer_pid != Some(manager.pid) {
            return Err("alias detach barrier requires the actual accepted claimant".into());
        }
        attachments::verify_consumed_continuation(directory, authorization, manager.pid)?;
        attachments::verify_process(manager)?;
        if self
            .sessions
            .engine_manager_start(session_id, token, manager.pid)
            != Some(manager.birth)
        {
            return Err("alias detach barrier requires current manager membership".into());
        }
        let shared = self
            .alias_histories
            .0
            .lock()
            .map_err(|_| "alias histories unavailable")?
            .get(session_id)
            .cloned();
        if let Some(shared) = &shared {
            let history = shared.lock().map_err(|_| "alias history unavailable")?;
            if history.bootstrap.attachment_id != *attachment_id || history.bootstrap.token != token
            {
                return Err("alias detach barrier scope mismatch".into());
            }
        }
        Ok(shared)
    }
    pub(super) fn prepare_attachment_detach(
        &self,
        authorization: Authorization,
        session_id: String,
        token: String,
        manager: ProcessIdentity,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        self.attachment_detach_plan(authorization, session_id, token, manager, peer_pid, false)
    }
    pub(super) fn cancel_attachment_detach(
        &self,
        authorization: Authorization,
        session_id: String,
        token: String,
        manager: ProcessIdentity,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        self.attachment_detach_plan(authorization, session_id, token, manager, peer_pid, true)
    }
    /// Each RPC observes one bounded batch. Lifecycle messages are executed by
    /// the accepted manager between RPCs; Core never asks it to sign a callback.
    fn attachment_detach_plan(
        &self,
        authorization: Authorization,
        session_id: String,
        token: String,
        manager: ProcessIdentity,
        peer_pid: Option<u32>,
        cancel: bool,
    ) -> ControlResponse {
        let result = (|| {
            let Some(shared) =
                self.detach_history(&authorization, &session_id, &token, &manager, peer_pid)?
            else {
                return Ok(ControlResponse::Ok);
            };
            self.observe_attachment_detach(
                &shared,
                authorization.nonce,
                authorization.request.action.attachment_id(),
                cancel,
            )
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    /// Caller has already authenticated the consumed manager continuation.
    /// Kept separate so concurrent publication can be tested without a second
    /// password/consumption fixture. This helper is never a control entry point.
    fn observe_attachment_detach(
        &self,
        shared: &SharedHistory,
        nonce: [u8; 32],
        attachment_id: &str,
        cancel: bool,
    ) -> Result<ControlResponse, String> {
        let operation = shared
            .lock()
            .map_err(|_| "alias history unavailable")?
            .operation
            .clone();
        let (roster, roster_digest, cursor) = {
            let _operation = operation
                .lock()
                .map_err(|_| "alias publication unavailable")?;
            let mut history = shared.lock().map_err(|_| "alias history unavailable")?;
            if cancel && history.detaching.is_none() {
                return Ok(ControlResponse::Ok);
            }
            if history
                .detaching
                .is_some_and(|pending_nonce| pending_nonce != nonce)
            {
                return Err("another detach admission barrier is already pending".into());
            }
            history.detaching = Some(nonce);
            let roster = live_barrier_roster(&history);
            let roster_digest = barrier_roster_digest(&roster)?;
            if !history.barrier_scan.as_ref().is_some_and(|scan| {
                scan.nonce == nonce && scan.cancel == cancel && scan.roster == roster_digest
            }) {
                history.barrier_scan = Some(DetachBarrierScan {
                    nonce: nonce,
                    cancel,
                    roster: roster_digest,
                    cursor: 0,
                });
            }
            let cursor = history.barrier_scan.as_ref().unwrap().cursor;
            (roster, roster_digest, cursor)
        };
        let end = (cursor + attachments::DETACH_BARRIER_BATCH_LIMIT).min(roster.len());
        let mut targets = Vec::new();
        let mut pending = false;
        // No publication/state lock spans these RPCs. An in-flight DNS
        // producer must be able to publish before its Host counter drains.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        for target in &roster[cursor..end] {
            if std::time::Instant::now() >= deadline {
                return Err("alias_publication_busy".into());
            }
            let status = wire::exchange_for_process(
                &target.endpoint,
                &wire::AuthenticatedCommand {
                    attachment_id: attachment_id.into(),
                    token: target.token.clone(),
                    command: wire::HostCommand::Status,
                    proof: None,
                    enrollment: None,
                    aliases: None,
                    root_image: None,
                },
                target.identity.pid,
            )
            .map_err(|e| format!("cannot observe alias admission barrier: {e}"))?;
            if attachments::process_birth(target.identity.pid) != Some(target.identity.birth) {
                return Err("alias_publication_busy".into());
            }
            let history_empty = shared
                .lock()
                .map_err(|_| "alias history unavailable")?
                .records
                .is_empty();
            if !cancel {
                verify_startup_cleanup_prefix(&status, history_empty)?;
            }
            let off = matches!(
                status.phase,
                wire::HostPhase::Detaching
                    | wire::HostPhase::DetachedResident
                    | wire::HostPhase::Detached
            );
            if if cancel {
                status.alias_publication_paused
            } else {
                !off && !status.alias_publication_paused
            } {
                targets.push(target.clone());
            }
            pending |= !cancel && status.pending_alias_publications != 0;
        }
        let purpose = if cancel {
            wire::HostLifecycleCommand::CancelDetachmentPreparation
        } else {
            wire::HostLifecycleCommand::PrepareDetachment
        };
        if !targets.is_empty() {
            return bounded_barrier_plan(nonce, purpose, targets);
        }
        if pending {
            return Err("alias_publication_busy".into());
        }
        let _operation = operation
            .lock()
            .map_err(|_| "alias publication unavailable")?;
        let mut history = shared.lock().map_err(|_| "alias history unavailable")?;
        if history.detaching != Some(nonce)
            || barrier_roster_digest(&live_barrier_roster(&history))? != roster_digest
            || !history.barrier_scan.as_ref().is_some_and(|scan| {
                scan.nonce == nonce
                    && scan.cancel == cancel
                    && scan.roster == roster_digest
                    && scan.cursor == cursor
            })
        {
            history.barrier_scan = None;
            return Err("alias_publication_busy".into());
        }
        history.barrier_scan.as_mut().unwrap().cursor = end;
        if end < roster.len() {
            return bounded_barrier_plan(nonce, purpose, Vec::new());
        }
        if cancel {
            history.detaching = None;
            history.barrier_scan = None;
            return Ok(ControlResponse::Ok);
        }
        if history.cleanup_unproven {
            return Err("alias_detach_members_pending".into());
        }
        self.persist_alias_tail(&mut history)?;
        drop(history);
        self.publish_aliases(&shared)?;
        Ok(ControlResponse::Ok)
    }
    pub(super) fn finish_attachment_detach(
        &self,
        authorization: Authorization,
        session_id: String,
        token: String,
        manager: ProcessIdentity,
        peer_pid: Option<u32>,
    ) -> ControlResponse {
        let result = (|| {
            let Some(shared) =
                self.detach_history(&authorization, &session_id, &token, &manager, peer_pid)?
            else {
                return Ok(ControlResponse::Ok);
            };
            let operation = shared
                .lock()
                .map_err(|_| "alias history unavailable")?
                .operation
                .clone();
            let _operation = operation
                .lock()
                .map_err(|_| "alias publication unavailable")?;
            let hosts = {
                let history = shared.lock().map_err(|_| "alias history unavailable")?;
                if history.cleanup_unproven {
                    return Err("alias_detach_members_pending".into());
                }
                if history.detaching.is_none() {
                    return Ok(ControlResponse::Ok);
                }
                if history.detaching != Some(authorization.nonce) {
                    return Err("detach completion has a different admission epoch".into());
                }
                history
                    .hosts
                    .values()
                    .map(|host| (host.identity.clone(), host.bootstrap.clone()))
                    .collect::<Vec<_>>()
            };
            let mut acknowledged = HashMap::new();
            for (identity, bootstrap) in hosts {
                if attachments::process_birth(identity.pid) != Some(identity.birth) {
                    continue;
                }
                let status = wire::exchange_for_process(
                    &bootstrap.host_endpoint,
                    &wire::AuthenticatedCommand {
                        attachment_id: bootstrap.attachment_id.clone(),
                        token: bootstrap.host_token.clone(),
                        command: wire::HostCommand::Status,
                        proof: None,
                        enrollment: None,
                        aliases: None,
                        root_image: None,
                    },
                    identity.pid,
                )
                .map_err(|e| e.to_string())?;
                let history_empty = shared
                    .lock()
                    .map_err(|_| "alias history unavailable")?
                    .records
                    .is_empty();
                verify_startup_cleanup_prefix(&status, history_empty)?;
                if !detach_status_acknowledges(&status) {
                    return Err("alias_detach_members_pending".into());
                }
                acknowledged.insert(identity.pid, (identity, bootstrap.host_endpoint));
            }
            let mut history = shared.lock().map_err(|_| "alias history unavailable")?;
            if history.detaching != Some(authorization.nonce) {
                return Err("detach completion was superseded".into());
            }
            if history.hosts.values().any(|host| {
                attachments::process_birth(host.identity.pid) == Some(host.identity.birth)
                    && acknowledged.get(&host.identity.pid)
                        != Some(&(host.identity.clone(), host.bootstrap.host_endpoint.clone()))
            }) {
                return Err("alias_detach_members_pending".into());
            }
            history.detaching = None;
            history.barrier_scan = None;
            Ok(ControlResponse::Ok)
        })();
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }
    pub(super) fn commit_root_exec(
        &self,
        attachment_id: &str,
        previous: &ProcessIdentity,
        current: &ProcessIdentity,
        nonce: [u8; 32],
    ) -> Result<wire::RootImageState, String> {
        let base = self
            .attachment_directory
            .as_ref()
            .ok_or("root image lifecycle unavailable")?;
        let directory = attachments::attachment_directory(base, attachment_id)?;
        let record = attachments::load_record(&directory)?;
        let shared = self
            .alias_histories
            .0
            .lock()
            .map_err(|_| "alias histories unavailable")?
            .get(&record.session_id)
            .cloned();
        let operation = shared
            .as_ref()
            .map(|shared| {
                shared
                    .lock()
                    .map(|history| history.operation.clone())
                    .map_err(|_| "alias history unavailable")
            })
            .transpose()?;
        let _operation = operation
            .as_ref()
            .map(|operation| {
                operation
                    .lock()
                    .map_err(|_| "root image publication unavailable")
            })
            .transpose()?;
        let (state, certificate) =
            attachments::observe_root_exec(base, attachment_id, previous, current, nonce)?;
        attachments::update_current_target(&directory, previous, current, state.exec_epoch)?;
        if let Some(shared) = shared {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut acknowledged = HashMap::new();
            loop {
                if std::time::Instant::now() >= deadline {
                    return Err("root image member ACK deadline exceeded".into());
                }
                let hosts = {
                    let history = shared.lock().map_err(|_| "alias history unavailable")?;
                    history
                        .hosts
                        .values()
                        .filter(|host| {
                            host.identity.pid != current.pid
                                && acknowledged.get(&host.identity.pid)
                                    != Some(&(
                                        host.identity.birth,
                                        host.bootstrap.host_endpoint.clone(),
                                    ))
                        })
                        .map(|host| (host.identity.clone(), host.bootstrap.clone()))
                        .collect::<Vec<_>>()
                };
                for (identity, bootstrap) in hosts {
                    if attachments::process_birth(identity.pid) != Some(identity.birth) {
                        continue;
                    }
                    let status = wire::exchange_for_process(
                        &bootstrap.host_endpoint,
                        &wire::AuthenticatedCommand {
                            attachment_id: bootstrap.attachment_id.clone(),
                            token: bootstrap.host_token.clone(),
                            command: wire::HostCommand::ApplyRootImage,
                            proof: None,
                            enrollment: None,
                            aliases: None,
                            root_image: Some(certificate.clone()),
                        },
                        identity.pid,
                    )
                    .map_err(|e| {
                        format!("root executable epoch was not acknowledged by a live member: {e}")
                    })?;
                    if status.root_image.as_ref() != Some(&state) {
                        return Err("member root image ACK differs from actual exec epoch".into());
                    }
                    acknowledged.insert(identity.pid, (identity.birth, bootstrap.host_endpoint));
                }
                let history = shared.lock().map_err(|_| "alias history unavailable")?;
                if history.hosts.values().all(|host| {
                    host.identity.pid == current.pid
                        || attachments::process_birth(host.identity.pid)
                            != Some(host.identity.birth)
                        || acknowledged.get(&host.identity.pid)
                            == Some(&(host.identity.birth, host.bootstrap.host_endpoint.clone()))
                }) {
                    break;
                }
            }
        }
        Ok(state)
    }
    fn persist_alias_tail(&self, history: &mut History) -> Result<(), String> {
        let directory = self
            .attachment_directory
            .as_ref()
            .ok_or("alias journal unavailable")?;
        let journal = directory
            .join("alias-history")
            .join(attachments::digest(history.bootstrap.session_id.as_bytes()));
        attachments::private_directory(&journal)?;
        while history.durable_sequence < history.records.len() as u64 {
            let sequence = history.durable_sequence + 1;
            let payload = wire::AliasSnapshotPayload {
                schema_version: 1,
                instance_id: history.bootstrap.approval_instance_id.clone(),
                attachment_id: history.bootstrap.attachment_id.clone(),
                root_pid: history.bootstrap.root_pid,
                session_id: history.bootstrap.session_id.clone(),
                host_binding: history
                    .bootstrap
                    .approval_binding()
                    .map_err(|e| e.to_string())?,
                base_sequence: sequence - 1,
                previous_head: history.head(sequence - 1)?,
                sequence,
                head: history.head(sequence)?,
                records: vec![history.records[sequence as usize - 1].clone()],
                complete: true,
            };
            let snapshot = attachments::sign_session_aliases(directory, &payload)?;
            let path = journal.join(format!("{sequence:020}.json"));
            if path.exists() {
                let previous: wire::SignedSessionAliasSnapshot = serde_json::from_slice(
                    &attachments::read_private_file(&path, wire::MAX_FRAME as u64)?,
                )
                .map_err(|e| e.to_string())?;
                let previous: wire::AliasSnapshotPayload = serde_json::from_slice(
                    previous
                        .payload
                        .strip_prefix(wire::SESSION_ALIAS_DOMAIN)
                        .ok_or("alias journal domain invalid")?,
                )
                .map_err(|e| e.to_string())?;
                if previous != payload {
                    return Err("alias journal would overwrite a different issuance meaning".into());
                }
            } else {
                attachments::create_private_file(
                    &path,
                    &serde_json::to_vec(&snapshot).map_err(|e| e.to_string())?,
                )?;
            }
            // Existing files were verified against retained Host prefixes by
            // restoration. Never overwrite an old Core signature with a new key.
            #[cfg(unix)]
            std::fs::File::open(&journal)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
            history.durable_sequence = sequence;
        }
        Ok(())
    }
    fn publish_aliases(&self, shared: &SharedHistory) -> Result<(), String> {
        let directory = self
            .attachment_directory
            .as_ref()
            .ok_or("alias publisher unavailable")?;
        if shared
            .lock()
            .map_err(|_| "alias history unavailable")?
            .cleanup_unproven
        {
            return Err("cannot publish an unproven startup cleanup alias prefix".into());
        }
        let current = attachments::approval_trust(directory)?.core_public_key;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let hosts = {
                let history = shared.lock().map_err(|_| "alias history unavailable")?;
                history
                    .hosts
                    .values()
                    .filter(|host| {
                        !host.startup_cleanup_only && (host.ready || history.detaching.is_some())
                    })
                    .map(|host| (host.identity.clone(), host.bootstrap.clone()))
                    .collect::<Vec<_>>()
            };
            for (identity, bootstrap) in hosts {
                if attachments::process_birth(identity.pid) != Some(identity.birth) {
                    continue;
                }
                loop {
                    if std::time::Instant::now() >= deadline {
                        return Err("alias publication ACK deadline exceeded".into());
                    }
                    let request = {
                        let history = shared.lock().map_err(|_| "alias history unavailable")?;
                        let Some(host) = history.hosts.get(&identity.pid) else {
                            break;
                        };
                        if host.identity != identity
                            || host.bootstrap.host_endpoint != bootstrap.host_endpoint
                        {
                            break;
                        }
                        if host.sequence == history.records.len() as u64 && host.signer == current {
                            break;
                        }
                        (
                            history.page(directory, host.sequence)?,
                            if host.signer == current {
                                None
                            } else {
                                history.proof.clone()
                            },
                            host.sequence,
                            host.signer,
                        )
                    };
                    let status = wire::exchange_for_process(
                        &bootstrap.host_endpoint,
                        &wire::AuthenticatedCommand {
                            attachment_id: bootstrap.attachment_id.clone(),
                            token: bootstrap.host_token.clone(),
                            command: wire::HostCommand::ApplySessionAliases,
                            proof: request.1,
                            enrollment: None,
                            aliases: Some(request.0),
                            root_image: None,
                        },
                        identity.pid,
                    )
                    .map_err(|e| format!("alias consumer did not acknowledge publication: {e}"))?;
                    let anchor = status
                        .alias_inheritance
                        .ok_or("alias consumer omitted verified history ACK")?;
                    let mut history = shared.lock().map_err(|_| "alias history unavailable")?;
                    if anchor.public_key != current
                        || anchor.sequence < request.2
                        || (anchor.sequence == request.2 && request.3 == current)
                        || history.head(anchor.sequence)? != anchor.head
                    {
                        return Err("alias consumer ACK does not match signed prefix".into());
                    }
                    if let Some(host) = history.hosts.get_mut(&identity.pid) {
                        if host.identity == identity
                            && host.bootstrap.host_endpoint == bootstrap.host_endpoint
                        {
                            host.sequence = host.sequence.max(anchor.sequence);
                            host.signer = anchor.public_key;
                        }
                    }
                }
            }
            let mut history = shared.lock().map_err(|_| "alias history unavailable")?;
            history.hosts.retain(|_, host| {
                attachments::process_birth(host.identity.pid) == Some(host.identity.birth)
            });
            // A new inline registration may appear while reverse RPC waits.
            // Its exact prefix ACK counts; every other ready member must catch
            // up before the producer can expose the address to application code.
            if history.hosts.values().all(|host| {
                (host.startup_cleanup_only && history.records.is_empty())
                    || (!host.ready && history.detaching.is_none())
                    || (host.sequence == history.records.len() as u64 && host.signer == current)
            }) {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err("alias publication member-set deadline exceeded".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn proof_for_root(
        directory: &std::path::Path,
        bootstrap: &wire::Bootstrap,
        proof: Option<&wire::ApprovalProof>,
        signer: [u8; 32],
        packet: Option<&wire::SignedRootImage>,
        now: u64,
    ) -> Option<wire::ApprovalProof> {
        super::registration_proof(
            directory,
            bootstrap,
            proof,
            signer,
            packet,
            now,
            bootstrap.root_pid,
        )
    }
    #[test]
    fn root_challenge_gets_only_fresh_matching_endorsement_even_after_alias_key_advanced() {
        use ed25519_dalek::{Signer, SigningKey};
        for scope_tree in [true, false] {
            let directory = std::env::temp_dir().join(format!(
                "hh-root-alias-endorsement-{}",
                attachments::new_id()
            ));
            attachments::private_directory(&directory).unwrap();
            let admin = SigningKey::from_bytes(&[7; 32]);
            let old = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
            let current = attachments::approval_trust(&directory)
                .unwrap()
                .core_public_key;
            attachments::pin_authority(
                &directory,
                attachments::ApprovalAuthority {
                    instance_id: "instance".into(),
                    config_id: [9; 16],
                    public_key: admin.verifying_key().to_bytes(),
                    generation: 0,
                },
                None,
            )
            .unwrap();
            let mut bootstrap = history().bootstrap;
            bootstrap.scope_tree = scope_tree;
            bootstrap.root_pid = if std::process::id() == 123 { 124 } else { 123 };
            let identity = attachments::ProcessIdentity {
                pid: bootstrap.root_pid,
                birth: 42,
                executable: "unit-root".into(),
                executable_sha256: "ab".repeat(32),
                owner: "unit-owner".into(),
            };
            bootstrap.approval_public_key = Some(admin.verifying_key().to_bytes());
            bootstrap.approval_core_public_key = Some(old);
            bootstrap.approval_root_identity = Some(identity.root_image_identity());
            let grant = Authorization {
                request: attachments::Request {
                    schema_version: 1,
                    id: attachments::new_id(),
                    instance_id: "instance".into(),
                    created_at_ms: 100,
                    action: attachments::Action::Attach {
                        spec: attachments::Spec {
                            id: bootstrap.attachment_id.clone(),
                            target: identity.clone(),
                            current_target: None,
                            exec_epoch: 0,
                            scope: if scope_tree {
                                attachments::Scope::Tree
                            } else {
                                attachments::Scope::Process
                            },
                            backend: attachments::Backend::Gum,
                            policy_digest: "cd".repeat(32),
                            recovery: None,
                            capabilities: Default::default(),
                        },
                    },
                },
                approved_at_ms: 100,
                expires_at_ms: 1_000,
                nonce: [3; 32],
                executor_sha256: "ef".repeat(32),
                execution_digest: None,
                host_binding: Some(bootstrap.approval_binding().unwrap()),
                core_attestation_public_key: Some(current),
                manager_claimant: None,
                signature: vec![],
            };
            let sign = |mut grant: Authorization| {
                grant.signature = admin
                    .sign(&attachments::host_proof(&grant).unwrap().payload)
                    .to_bytes()
                    .to_vec();
                attachments::host_proof(&grant).unwrap()
            };
            let packet = |epoch, recipient_pid| {
                let state = wire::RootImageState {
                    identity: identity.root_image_identity(),
                    exec_epoch: epoch,
                    observed_at_ms: epoch,
                    head: [epoch as u8; 32],
                };
                attachments::sign_root_image_payload(
                    &directory,
                    &wire::RootImagePayload {
                        schema_version: 1,
                        instance_id: bootstrap.approval_instance_id.clone(),
                        attachment_id: bootstrap.attachment_id.clone(),
                        session_id: bootstrap.session_id.clone(),
                        host_binding: bootstrap.approval_binding().unwrap(),
                        initial_identity: identity.root_image_identity(),
                        previous: state.clone(),
                        current: state,
                        transition_nonce: [4; 32],
                        challenge: Some([5; 32]),
                        host_pid: Some(recipient_pid),
                        host_birth: Some(identity.birth),
                    },
                )
                .unwrap()
            };
            let proof = sign(grant.clone());
            let snapshot = packet(0, identity.pid);
            assert!(
                super::registration_proof(
                    &directory,
                    &bootstrap,
                    Some(&proof),
                    current,
                    Some(&snapshot),
                    200,
                    identity.pid + 1
                )
                .is_none(),
                "recipient must match the actual challenged Host"
            );
            if scope_tree {
                assert_eq!(
                    super::registration_proof(
                        &directory,
                        &bootstrap,
                        Some(&proof),
                        current,
                        Some(&packet(0, identity.pid + 1)),
                        200,
                        identity.pid + 1
                    ),
                    Some(proof.clone())
                );
            } else {
                assert!(
                    wire::verify_proof_with_key(
                        &bootstrap,
                        &admin.verifying_key().to_bytes(),
                        &proof,
                        200
                    )
                    .is_err(),
                    "old Core-side ownPID wrapper must reproduce the process-only refusal"
                );
            }
            assert_eq!(
                proof_for_root(
                    &directory,
                    &bootstrap,
                    Some(&proof),
                    current,
                    Some(&snapshot),
                    200
                ),
                Some(proof.clone()),
                "alias key already current must not suppress RootImage endorsement"
            );
            assert!(
                proof_for_root(&directory, &bootstrap, Some(&proof), current, None, 200).is_none()
            );
            assert!(proof_for_root(
                &directory,
                &bootstrap,
                Some(&proof),
                current,
                Some(&snapshot),
                1_000
            )
            .is_none());
            assert!(
                proof_for_root(
                    &directory,
                    &bootstrap,
                    Some(&proof),
                    current,
                    Some(&packet(1, identity.pid)),
                    200
                )
                .is_none(),
                "post-exec same-Core registration must not receive pre-exec proof"
            );
            let mut wrong = grant.clone();
            wrong.core_attestation_public_key = Some(old);
            assert!(proof_for_root(
                &directory,
                &bootstrap,
                Some(&sign(wrong)),
                current,
                Some(&snapshot),
                200
            )
            .is_none());
            let mut wrong = grant.clone();
            wrong.request.instance_id = "other-instance".into();
            assert!(proof_for_root(
                &directory,
                &bootstrap,
                Some(&sign(wrong)),
                current,
                Some(&snapshot),
                200
            )
            .is_none());
            let mut wrong = grant;
            if let attachments::Action::Attach { spec } = &mut wrong.request.action {
                spec.target.executable_sha256 = "01".repeat(32);
            }
            assert!(proof_for_root(
                &directory,
                &bootstrap,
                Some(&sign(wrong)),
                current,
                Some(&snapshot),
                200
            )
            .is_none());
            std::fs::remove_dir_all(directory).unwrap();
        }
    }
    fn history() -> History {
        let bootstrap:wire::Bootstrap=serde_json::from_value(serde_json::json!({
            "attachment_id":"alias-fixture","session_id":"alias-session","token":"t".repeat(64),"control_endpoint":"unused","socks_address":"127.0.0.1:1","tls_ca_pem":"unused","observe":false,"firewall":null,"sandbox":null,"host_endpoint":"unused","host_token":"h".repeat(64),"scope_tree":true,"root_pid":123,"approval_authority_file":"unused","approval_instance_id":"instance","initially_owned":false,"approval_core_public_key":null,"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":"c".repeat(64)
        })).unwrap();
        History {
            operation: Arc::new(Mutex::new(())),
            bootstrap,
            records: vec![],
            heads: vec![[0; 32]],
            hosts: HashMap::new(),
            proof: None,
            cleanup_unproven: false,
            durable_sequence: 0,
            detaching: None,
            barrier_scan: None,
        }
    }
    #[test]
    fn successor_alias_export_borrows_records_and_rejects_oversized_history_without_mutation() {
        let histories = AliasHistories::default();
        let mut original = history();
        append(&mut original, 1);
        let id = original.bootstrap.session_id.clone();
        assert_ne!(id, original.bootstrap.attachment_id);
        let shared = Arc::new(Mutex::new(original));
        histories
            .0
            .lock()
            .unwrap()
            .insert(id.clone(), shared.clone());
        let normal = histories.export_successor().unwrap();
        let child = AliasHistories::default();
        child.import_successor(&normal).unwrap();
        assert_eq!(
            child.0.lock().unwrap()[&id].lock().unwrap().records[0].hostname,
            "producer-1.fixture.test"
        );
        shared.lock().unwrap().bootstrap.tls_ca_pem = "x".repeat(crate::successor::MAX_STATE + 1);
        assert!(histories.export_successor().is_err());
        {
            let history = shared.lock().unwrap();
            assert_eq!(history.records.len(), 1);
            assert_eq!(history.heads.len(), 2);
            assert_eq!(
                history.bootstrap.tls_ca_pem.len(),
                crate::successor::MAX_STATE + 1
            );
        }
        shared.lock().unwrap().bootstrap.tls_ca_pem = "private-test-restored".into();
        assert!(histories.export_successor().is_ok());
    }
    #[test]
    fn successor_alias_session_index_preserves_each_mapping_bootstrap_proof_and_host_cursor() {
        let parent = AliasHistories::default();
        for index in 0..2 {
            let mut history = history();
            history.bootstrap.session_id = format!("private-session-{index}");
            history.bootstrap.attachment_id = format!("private-attachment-{index}");
            history.bootstrap.approval_not_before_ms = 1234 + index;
            history.bootstrap.initially_owned = index == 0;
            history.bootstrap.native_dns_mode = if index == 0 {
                wire::NativeDnsMode::SyntheticPool
            } else {
                wire::NativeDnsMode::PreserveAnswers
            };
            append(&mut history, 1);
            append(&mut history, 2);
            history.records[0]
                .native_fallback
                .addresses
                .push(wire::NativeAddress {
                    ip: "127.0.0.2".parse().unwrap(),
                    scope_id: 0,
                    flowinfo: 0,
                });
            history.records[1].ambiguous = true;
            history.heads = vec![[0; 32]];
            for record in &history.records {
                history
                    .heads
                    .push(wire::alias_record_head(history.heads.last().unwrap(), record).unwrap());
            }
            history.durable_sequence = 1;
            history.proof = Some(wire::ApprovalProof {
                payload: br#"{"purpose":"attach","approved_at_ms":101,"expires_at_ms":202}"#
                    .to_vec(),
                signature: vec![7; 64],
            });
            for (pid, sequence, ready, signer) in
                [(456, 1, false, [8; 32]), (457, 2, true, [9; 32])]
            {
                let mut bootstrap = history.bootstrap.clone();
                bootstrap.host_endpoint = format!("private-host-{pid}");
                history.hosts.insert(
                    pid,
                    Host {
                        identity: ProcessIdentity {
                            pid,
                            birth: 789 + u64::from(pid),
                            executable: "private-executor".into(),
                            executable_sha256: "ab".repeat(32),
                            owner: "private-owner".into(),
                        },
                        bootstrap,
                        sequence,
                        ready,
                        startup_cleanup_only: false,
                        startup_pristine: false,
                        signer,
                    },
                );
            }
            parent.0.lock().unwrap().insert(
                history.bootstrap.session_id.clone(),
                Arc::new(Mutex::new(history)),
            );
        }
        let encoded = parent.export_successor().unwrap();
        let expected: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert!(expected.get("private-session-0").is_some());
        assert!(expected.get("private-attachment-0").is_none());
        let child = AliasHistories::default();
        child.import_successor(&encoded).unwrap();
        let actual: serde_json::Value =
            serde_json::from_slice(&child.export_successor().unwrap()).unwrap();
        assert_eq!(actual,expected,"succession changed native fallback order, provenance, cursor, proof timing/purpose or Bootstrap mode");
        assert!(
            child.import_successor(&encoded).is_err(),
            "a live history must never be overwritten"
        );
        let after: serde_json::Value =
            serde_json::from_slice(&child.export_successor().unwrap()).unwrap();
        assert_eq!(after, expected);
    }
    #[test]
    fn successor_alias_rejects_attachment_or_wrong_session_keys_without_partial_installation() {
        let mut history = history();
        append(&mut history, 1);
        let session = history.bootstrap.session_id.clone();
        let attachment = history.bootstrap.attachment_id.clone();
        let value = serde_json::to_value(&history).unwrap();
        for bad_key in [attachment, "another-session".into()] {
            let child = AliasHistories::default();
            let mut malformed = serde_json::Map::new();
            malformed.insert(session.clone(), value.clone());
            malformed.insert(bad_key, value.clone());
            let encoded = serde_json::to_vec(&malformed).unwrap();
            assert!(child.import_successor(&encoded).is_err());
            assert!(child.0.lock().unwrap().is_empty());
            let mut valid = serde_json::Map::new();
            valid.insert(session.clone(), value.clone());
            let valid = serde_json::to_vec(&valid).unwrap();
            child.import_successor(&valid).unwrap();
            assert_eq!(
                child.0.lock().unwrap()[&session].lock().unwrap().records[0].address,
                history.records[0].address
            );
        }
        let child = AliasHistories::default();
        assert!(child
            .import_successor(&vec![b' '; crate::successor::MAX_STATE + 1])
            .is_err());
        assert!(child.0.lock().unwrap().is_empty());
    }
    fn append(history: &mut History, sequence: u64) {
        let record = wire::IssuedRecord {
            sequence,
            address: std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                0xc6120000u32 + sequence as u32,
            )),
            hostname: format!("producer-{sequence}.fixture.test"),
            native_fallback: wire::NativeFallback {
                family: 4,
                addresses: vec![wire::NativeAddress {
                    ip: "127.0.0.1".parse().unwrap(),
                    scope_id: 0,
                    flowinfo: 0,
                }],
                failure: None,
                unavailable: None,
            },
            issuer_pid: 456,
            issuer_birth: 789,
            ambiguous: false,
        };
        history
            .heads
            .push(wire::alias_record_head(history.heads.last().unwrap(), &record).unwrap());
        history.records.push(record);
    }
    #[test]
    fn signed_history_pages_preserve_dead_producer_provenance_and_exact_prefix() {
        let directory =
            std::env::temp_dir().join(format!("hh-alias-pages-{}", attachments::new_id()));
        let mut history = history();
        for sequence in 1..=150 {
            append(&mut history, sequence);
        }
        let key = attachments::approval_trust(&directory)
            .unwrap()
            .core_public_key;
        let mut cursor = 0;
        let mut records = vec![];
        while cursor < 150 {
            let signed = history.page(&directory, cursor).unwrap();
            let encoded = serde_json::to_vec(&ControlResponse::AliasHostRegistration {
                ready: false,
                snapshot: Some(signed.clone()),
                proof: None,
                root_image: None,
            })
            .unwrap();
            assert!(encoded.len() < wire::MAX_FRAME / 2);
            let page = wire::decode_alias_snapshot(&history.bootstrap, &key, &signed).unwrap();
            assert_eq!(page.base_sequence, cursor);
            assert_eq!(page.previous_head, history.head(cursor).unwrap());
            assert!(page.sequence > cursor);
            cursor = page.sequence;
            records.extend(page.records);
        }
        assert_eq!(records, history.records);
        assert!(records
            .iter()
            .all(|record| record.issuer_pid == 456 && record.issuer_birth == 789));
        assert!(history.page(&directory, 151).is_err());
        let final_anchor = wire::decode_alias_snapshot(
            &history.bootstrap,
            &key,
            &history.page(&directory, 150).unwrap(),
        )
        .unwrap();
        assert!(final_anchor.records.is_empty());
        assert_eq!(final_anchor.head, history.head(150).unwrap());
    }
    #[test]
    fn signed_history_wire_rejects_tampered_native_meaning_or_scope() {
        let directory =
            std::env::temp_dir().join(format!("hh-alias-binding-{}", attachments::new_id()));
        let mut history = history();
        append(&mut history, 1);
        let key = attachments::approval_trust(&directory)
            .unwrap()
            .core_public_key;
        let mut snapshot = history.page(&directory, 0).unwrap();
        let mut changed = history.bootstrap.clone();
        changed.session_id.push('x');
        assert!(wire::decode_alias_snapshot(&changed, &key, &snapshot).is_err());
        let index = snapshot.payload.len() - 2;
        snapshot.payload[index] ^= 1;
        assert!(wire::decode_alias_snapshot(&history.bootstrap, &key, &snapshot).is_err());
    }
    #[test]
    fn registered_alias_publication_requires_signed_host_ack() {
        publication_fixture(false);
    }
    #[test]
    fn inline_registration_can_progress_while_publisher_awaits_host_ack() {
        publication_fixture(true);
    }
    fn publication_fixture(interleave: bool) {
        use std::sync::atomic::{AtomicBool, Ordering};
        let root =
            std::env::temp_dir().join(format!("hh-alias-publisher-{}", attachments::new_id()));
        attachments::private_directory(&root).unwrap();
        let directory = root.join("attachments");
        attachments::private_directory(&directory).unwrap();
        let identity = attachments::inspect_process(std::process::id()).unwrap();
        let key = Zeroizing::new(vec![7; 32]);
        let sessions = SessionRegistry::new(key.clone(), crate::config_store::new_descriptor());
        let id = attachments::new_id();
        let session_id = format!("attach-{id}");
        let challenge = sessions
            .begin_auth(session_id.clone(), identity.executable.clone(), [1; 32])
            .unwrap();
        let proof = crate::session::session_proof(&key, &challenge).unwrap();
        let session = sessions
            .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(60))
            .unwrap();
        assert!(sessions.activate(&session_id, &session.token, identity.pid));
        let mut bootstrap = history().bootstrap;
        bootstrap.attachment_id = id.clone();
        bootstrap.session_id = session_id.clone();
        bootstrap.token = session.token.clone();
        bootstrap.root_pid = identity.pid;
        bootstrap.approval_core_public_key = Some(
            attachments::approval_trust(&directory)
                .unwrap()
                .core_public_key,
        );
        let home = root.join("host");
        attachments::private_directory(&home).unwrap();
        attachments::private_directory(&home.join("runtime")).unwrap();
        bootstrap.host_endpoint = crate::control::instance_control_endpoint(&home);
        let spec = attachments::Spec {
            exec_epoch: 0,
            current_target: None,
            recovery: None,
            capabilities: Default::default(),
            id: id.clone(),
            target: identity.clone(),
            scope: attachments::Scope::Tree,
            backend: attachments::Backend::Gum,
            policy_digest: "ab".repeat(32),
        };
        let mut record = attachments::create_record(&directory, spec).unwrap();
        record.host_binding = Some(bootstrap.approval_binding().unwrap());
        crate::config_store::save_durable_private_bytes(
            &directory.join(&id).join("record.json"),
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let listener = wire::Listener::bind(&bootstrap.host_endpoint).unwrap();
        let reject = Arc::new(AtomicBool::new(true));
        let reject_server = reject.clone();
        let received = Arc::new(Mutex::new(Vec::<wire::IssuedRecord>::new()));
        let server_received = received.clone();
        let service_slot: Arc<Mutex<Option<ControlService>>> = Arc::new(Mutex::new(None));
        let server_service = service_slot.clone();
        let inline = Arc::new(AtomicBool::new(false));
        let server_inline = inline.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let server_bootstrap = bootstrap.clone();
        let public = bootstrap.approval_core_public_key.unwrap();
        let handle = std::thread::spawn(move || {
            listener.run(&server_stop,move|request|{
            if request.command!=wire::HostCommand::ApplySessionAliases{return Err("unexpected fixture command".into());}
            let page=wire::decode_alias_snapshot(&server_bootstrap,&public,request.aliases.as_ref().ok_or("missing signed aliases")?).map_err(|e|e.to_string())?;
            if reject_server.load(Ordering::Acquire){return Err("fixture withheld publication ACK".into());}
            let mut records=server_received.lock().unwrap();if records.len()as u64!=page.base_sequence{return Err("fixture prefix mismatch".into());}records.extend(page.records);
            if server_inline.load(Ordering::Acquire){
                let service=server_service.lock().unwrap().clone().ok_or("fixture service missing")?;
                if !matches!(service.register_alias_host(None,server_bootstrap.clone(),page.sequence,page.head,None,Some(std::process::id())),ControlResponse::AliasHostRegistration{ready:true,..}){return Err("inline registration did not progress during publication".into());}
            }
            serde_json::from_value(serde_json::json!({"protocol":wire::PROTOCOL,"pid":std::process::id(),"attachment_id":server_bootstrap.attachment_id,"phase":"active","active_calls":0,"unload_ready":false,"tracked_sockets":0,"fake_addresses":records.len(),"compatibility_reasons":[],"alias_inheritance":{"public_key":public,"sequence":page.sequence,"head":page.head,"endorsement_approved_at_ms":0,"endorsement_nonce":null},"alias_history_ready":true})).map_err(|e|e.to_string())
        })
        });
        struct HostGuard {
            stop: Arc<AtomicBool>,
            handle: Option<std::thread::JoinHandle<std::io::Result<()>>>,
        }
        impl Drop for HostGuard {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Release);
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
            }
        }
        let guard = HostGuard {
            stop,
            handle: Some(handle),
        };
        let service = ControlService::new(
            sessions,
            ConnectionRegistry::default(),
            "unused".into(),
            crate::audit::AuditWriter::open(None).unwrap(),
            RuntimeState::new(Arc::new(crate::config::Config::default())).unwrap(),
            Zeroizing::new(vec![0; 32]),
        )
        .with_attachment_directory(directory.clone());
        *service_slot.lock().unwrap() = Some(service.clone());
        assert!(matches!(
            service.register_alias_host(
                None,
                bootstrap.clone(),
                0,
                [0; 32],
                None,
                Some(identity.pid)
            ),
            ControlResponse::AliasHostRegistration { ready: true, .. }
        ));
        let native = wire::NativeFallback {
            family: 4,
            addresses: vec![wire::NativeAddress {
                ip: "127.0.0.1".parse().unwrap(),
                scope_id: 0,
                flowinfo: 0,
            }],
            failure: None,
            unavailable: None,
        };
        assert!(
            matches!(service.resolve_session_alias(session_id.clone(),session.token.clone(),"shared.fixture.test".into(),4,Some(native.clone()),Some(identity.pid)),ControlResponse::Error{message} if message.contains("withheld publication ACK"))
        );
        assert!(received.lock().unwrap().is_empty());
        reject.store(false, Ordering::Release);
        assert!(matches!(
            service.resolve_session_alias(
                session_id.clone(),
                session.token.clone(),
                "shared.fixture.test".into(),
                4,
                Some(native.clone()),
                Some(identity.pid)
            ),
            ControlResponse::ResolvedName {
                issued_sequence: Some(1),
                issued_head: Some(_),
                ..
            }
        ));
        let records = received.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].issuer_pid, identity.pid);
        assert_eq!(records[0].issuer_birth, identity.birth);
        assert_eq!(records[0].native_fallback, native);
        drop(records);
        if interleave {
            inline.store(true, Ordering::Release);
            assert!(matches!(
                service.resolve_session_alias(
                    session_id,
                    session.token,
                    "late.fixture.test".into(),
                    4,
                    Some(native),
                    Some(identity.pid)
                ),
                ControlResponse::ResolvedName {
                    issued_sequence: Some(2),
                    ..
                }
            ));
            assert_eq!(received.lock().unwrap().len(), 2);
        }
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
#[path = "alias_detach_plan_tests.rs"]
mod detach_barrier_tests;

impl AliasHistories {
    pub(super) fn export_successor(&self) -> Result<Vec<u8>, String> {
        let histories = self.0.lock().map_err(|_| "alias histories unavailable")?;
        struct BorrowedHistories<'a>(&'a HashMap<String, SharedHistory>);
        impl serde::Serialize for BorrowedHistories<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::{Error, SerializeMap};
                let mut map = serializer.serialize_map(Some(self.0.len()))?;
                for (id, history) in self.0 {
                    let history = history
                        .lock()
                        .map_err(|_| S::Error::custom("alias history unavailable"))?;
                    if history.detaching.is_some() || history.barrier_scan.is_some() {
                        return Err(S::Error::custom(
                            "alias detachment barrier is in progress; retry Core succession",
                        ));
                    }
                    // Serialize one borrowed, locked History at a time. The
                    // budget stops inside a large history; no JSON Value copy.
                    map.serialize_entry(id, &*history)?;
                }
                map.end()
            }
        }
        crate::successor::bounded_json::to_vec(
            &BorrowedHistories(&histories),
            crate::successor::MAX_STATE,
        )
    }
    pub(super) fn import_successor(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > crate::successor::MAX_STATE {
            return Err("successor alias histories exceed the bounded pipe limit".into());
        }
        let incoming: HashMap<String, History> =
            serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let mut histories = self.0.lock().map_err(|_| "alias histories unavailable")?;
        if !histories.is_empty() {
            return Err("successor alias histories already initialized".into());
        }
        // Both live publication and authenticated Host restoration index by
        // session_id. The attachment_id is a different immutable identity and
        // remains inside each Bootstrap; never reinterpret it as the map key.
        // Validate every entry before installing any of the transferred state.
        for (session_id, history) in &incoming {
            if session_id != &history.bootstrap.session_id
                || history.heads.len() != history.records.len() + 1
                || history.durable_sequence > history.records.len() as u64
                || history.detaching.is_some()
                || history.barrier_scan.is_some()
            {
                return Err("invalid successor alias history".into());
            }
        }
        for (session_id, history) in incoming {
            histories.insert(session_id, Arc::new(Mutex::new(history)));
        }
        Ok(())
    }
}
