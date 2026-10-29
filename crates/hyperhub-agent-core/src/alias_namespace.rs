//! Process-local verifier for the shared session issuance history. No namespace
//! lock is held while a producer waits for Core: its metadata callback must be
//! able to publish the signed delta before that DNS request returns.
use crate::{GatewayState, HH_ERR_PROTOCOL};
use hyperhub_runtime::attachment::{
    self as wire, AliasInheritance, AliasSnapshotPayload, ApprovalProof, Bootstrap, IssuedRecord,
    SignedSessionAliasSnapshot,
};
use std::sync::atomic::{AtomicBool, Ordering};
static ADMISSION_READY: AtomicBool = AtomicBool::new(false);
#[derive(Clone, Default)]
pub(crate) struct Namespace {
    pub(crate) anchor: Option<AliasInheritance>,
    pub(crate) records: Vec<IssuedRecord>,
    pub(crate) stored_head: [u8; 32],
    prefix_heads: Vec<[u8; 32]>,
    pub(crate) history_ready: bool,
    pub(crate) registered: bool,
}
impl Namespace {
    pub(crate) fn from_bootstrap(bootstrap: &Bootstrap) -> Self {
        let anchor = bootstrap.alias_inherited.clone().or_else(|| {
            bootstrap
                .approval_core_public_key
                .map(|public_key| AliasInheritance {
                    metadata_only: false,
                    public_key,
                    sequence: 0,
                    head: [0; 32],
                    endorsement_approved_at_ms: 0,
                    endorsement_nonce: None,
                })
        });
        Self {
            history_ready: anchor
                .as_ref()
                .is_some_and(|anchor| anchor.sequence == 0 && anchor.head == [0; 32]),
            anchor,
            records: Vec::new(),
            stored_head: [0; 32],
            prefix_heads: Vec::new(),
            registered: false,
        }
    }
    fn head_at(&self, sequence: u64) -> Result<[u8; 32], String> {
        if sequence == 0 {
            return Ok([0; 32]);
        }
        if sequence == self.records.len() as u64 {
            return Ok(self.stored_head);
        }
        if sequence > self.records.len() as u64 {
            return Err("alias prefix has not been caught up".into());
        }
        self.prefix_heads
            .get(sequence as usize - 1)
            .copied()
            .ok_or_else(|| "alias prefix index is incomplete".into())
    }
}
pub(crate) fn reset_after_fork() {
    ADMISSION_READY.store(false, Ordering::Release);
}
pub(crate) fn admission_ready() -> bool {
    ADMISSION_READY.load(Ordering::Acquire)
}
pub(crate) fn inheritance() -> Option<AliasInheritance> {
    let _access = crate::runtime::host_access()?;
    crate::state().lock().ok()?.gateway.namespace.anchor.clone()
}
pub(crate) fn history_ready() -> bool {
    let Some(_access) = crate::runtime::host_access() else {
        return false;
    };
    crate::state()
        .lock()
        .map(|state| state.gateway.namespace.history_ready && state.gateway.namespace.registered)
        .unwrap_or(false)
}
pub(crate) fn supports_issuance() -> bool {
    crate::state()
        .lock()
        .map(|state| {
            state
                .gateway
                .namespace
                .anchor
                .as_ref()
                .is_some_and(|anchor| !anchor.metadata_only)
                && state.gateway.namespace.history_ready
                && state.gateway.namespace.registered
        })
        .unwrap_or(false)
}
fn compatible(old: &crate::IssuedAlias, record: &IssuedRecord) -> bool {
    old.hostname == record.hostname && old.native_fallback == record.native_fallback
}
fn validate_merge(gateway: &GatewayState, payload: &AliasSnapshotPayload) -> Result<(), String> {
    let mut introduced = std::collections::HashMap::<std::net::IpAddr, &IssuedRecord>::new();
    for record in &payload.records {
        if gateway
            .issued_aliases
            .get(&record.address)
            .is_some_and(|old| !compatible(old, record))
            || gateway
                .dns
                .get(&record.address)
                .is_some_and(|hostname| hostname != &record.hostname)
        {
            return Err("issued alias collides with an existing address origin".into());
        }
        if introduced
            .insert(record.address, record)
            .is_some_and(|old| {
                old.hostname != record.hostname
                    || old.native_fallback != record.native_fallback
                    || (old.ambiguous && !record.ambiguous)
            })
        {
            return Err("signed alias history reassigns an issued address".into());
        }
    }
    Ok(())
}
pub(crate) fn apply(
    bootstrap: &Bootstrap,
    signed: &SignedSessionAliasSnapshot,
    proof: Option<&ApprovalProof>,
) -> Result<(), String> {
    let previous = crate::state()
        .lock()
        .map_err(|_| "alias namespace unavailable")?
        .gateway
        .namespace
        .anchor
        .clone();
    let endorsement = proof
        .map(crate::attachment::verify_alias_endorsement)
        .transpose()?;
    let endorsed = endorsement
        .as_ref()
        .and_then(|claims| claims.core_attestation_public_key);
    let public_key = endorsed
        .or_else(|| previous.as_ref().map(|anchor| anchor.public_key))
        .ok_or("no pinned alias authority is available")?;
    let payload =
        wire::decode_alias_snapshot(bootstrap, &public_key, signed).map_err(|e| e.to_string())?;
    let _gate = crate::attachment::state_gate()?;
    crate::attachment::startup::check().map_err(|_| "attachment initialization was cancelled")?;
    let mut state = crate::state()
        .lock()
        .map_err(|_| "alias namespace unavailable")?;
    let gateway = &mut state.gateway;
    if gateway.namespace.anchor != previous {
        return Err("alias namespace changed; retry the signed snapshot".into());
    }
    apply_verified(gateway, payload, previous, public_key, endorsement)
}
fn apply_verified(
    gateway: &mut GatewayState,
    payload: AliasSnapshotPayload,
    previous: Option<AliasInheritance>,
    public_key: [u8; 32],
    endorsement: Option<wire::ApprovalClaims>,
) -> Result<(), String> {
    let known_sequence = previous.as_ref().map_or(0, |anchor| anchor.sequence);
    let known_head = previous.as_ref().map_or([0; 32], |anchor| anchor.head);
    let signer_changed = previous
        .as_ref()
        .is_none_or(|anchor| anchor.public_key != public_key);
    if signer_changed && endorsement.is_none() {
        return Err("alias signer replacement requires fresh scoped endorsement".into());
    }
    if let (Some(old), Some(claims)) = (&previous, &endorsement) {
        if claims.approved_at_ms < old.endorsement_approved_at_ms
            || (claims.approved_at_ms == old.endorsement_approved_at_ms
                && old.endorsement_nonce != Some(claims.nonce))
        {
            return Err("alias authority endorsement predates the accepted epoch".into());
        }
    }
    let mut anchor = previous.clone().unwrap_or(AliasInheritance {
        metadata_only: false,
        public_key,
        sequence: 0,
        head: [0; 32],
        endorsement_approved_at_ms: 0,
        endorsement_nonce: None,
    });
    anchor.public_key = public_key;
    if let Some(claims) = endorsement {
        anchor.endorsement_approved_at_ms = claims.approved_at_ms;
        anchor.endorsement_nonce = Some(claims.nonce);
        anchor.metadata_only = claims.action == wire::ApprovedAction::Detach;
    }
    // A fresh administrator may endorse a new Core exactly at the retained
    // prefix. This small anchor frame permits bounded subsequent data pages.
    let authority_anchor = signer_changed
        && payload.base_sequence == known_sequence
        && payload.sequence == known_sequence
        && payload.previous_head == known_head
        && payload.head == known_head
        && payload.records.is_empty();
    if authority_anchor {
        gateway.namespace.history_ready = gateway.namespace.history_ready || known_sequence == 0;
        gateway.namespace.anchor = Some(anchor);
        gateway.namespace.registered = false;
        ADMISSION_READY.store(false, Ordering::Release);
        return Ok(());
    }
    let stored = gateway.namespace.records.len() as u64;
    if payload.base_sequence > stored {
        return Err("alias delta has a missing stored prefix".into());
    }
    if gateway.namespace.head_at(payload.base_sequence)? != payload.previous_head {
        return Err("alias delta does not extend the retained prefix".into());
    }
    let overlap = stored
        .min(payload.sequence)
        .saturating_sub(payload.base_sequence) as usize;
    let start = payload.base_sequence as usize;
    if gateway.namespace.records.get(start..start + overlap) != payload.records.get(..overlap) {
        return Err("alias delta rewrites retained issuance provenance".into());
    }
    if payload.sequence <= stored {
        if payload.head != gateway.namespace.head_at(payload.sequence)? || signer_changed {
            return Err("alias snapshot would roll back the issued history".into());
        }
        gateway.namespace.anchor = Some(anchor);
        return Ok(());
    }
    // Until the creator-pinned high-water head has been reproduced, pages are
    // staging only: they cannot redirect the application's cached addresses.
    let becomes_ready = payload.sequence >= known_sequence;
    if becomes_ready && stored < known_sequence {
        let mut prefix = payload.previous_head;
        for record in payload
            .records
            .iter()
            .take(known_sequence.saturating_sub(payload.base_sequence) as usize)
        {
            prefix = wire::alias_record_head(&prefix, record).map_err(|e| e.to_string())?;
        }
        if prefix != known_head {
            return Err("alias catchup changes the creator-pinned prefix".into());
        }
    }
    let suffix = stored.saturating_sub(payload.base_sequence) as usize;
    if becomes_ready {
        validate_merge(gateway, &payload)?;
        if !gateway.namespace.history_ready {
            let staged = AliasSnapshotPayload {
                records: gateway.namespace.records.clone(),
                ..payload.clone()
            };
            validate_merge(gateway, &staged)?;
            for record in staged.records {
                merge_record(gateway, &record)?;
            }
        }
        for record in payload.records.iter().skip(suffix) {
            merge_record(gateway, record)?;
        }
    }
    let mut head = gateway.namespace.stored_head;
    for record in payload.records.into_iter().skip(suffix) {
        head = wire::alias_record_head(&head, &record).map_err(|e| e.to_string())?;
        gateway.namespace.prefix_heads.push(head);
        gateway.namespace.records.push(record);
    }
    gateway.namespace.stored_head = payload.head;
    if becomes_ready {
        anchor.sequence = payload.sequence;
        anchor.head = payload.head;
    }
    gateway.namespace.anchor = Some(anchor);
    gateway.namespace.history_ready = becomes_ready;
    if signer_changed {
        gateway.namespace.registered = false;
        ADMISSION_READY.store(false, Ordering::Release);
    }
    Ok(())
}
fn merge_record(gateway: &mut GatewayState, record: &IssuedRecord) -> Result<(), String> {
    if let Some(existing) = gateway.issued_aliases.get(&record.address) {
        if existing.hostname != record.hostname
            || existing.native_fallback != record.native_fallback
        {
            return Err("signed alias changes an already published address identity".into());
        }
        if record.ambiguous {
            gateway.ambiguous_aliases.insert(record.address);
            crate::native_alias_snapshot::publish_conflict(record.address)
                .map_err(|code| format!("cannot mark signed alias ambiguity: {code}"))?;
        }
        return Ok(());
    }
    gateway
        .issue_native_alias(
            record.address,
            record.hostname.clone(),
            record.native_fallback.clone(),
        )
        .map_err(|code| format!("cannot merge signed alias: {code}"))?;
    if record.ambiguous {
        gateway.ambiguous_aliases.insert(record.address);
        crate::native_alias_snapshot::publish_conflict(record.address)
            .map_err(|code| format!("cannot mark signed alias ambiguity: {code}"))?;
    }
    Ok(())
}
/// Called after the private listener exists and outside native loader/fork
/// callbacks. Core returns a catchup frame instead of dialing this same thread.
pub(crate) fn initialize_host() -> Result<(), i32> {
    initialize_host_detailed().map_err(|_| HH_ERR_PROTOCOL)
}
/// Private management errors retain the failed verification stage. Native ABI
/// callers continue to receive the stable numeric error; neither path logs to
/// the application's standard streams.
pub(crate) fn initialize_host_detailed() -> Result<(), String> {
    initialize_host_detailed_until(crate::control::StartupDeadline::new())
}
pub(crate) fn initialize_host_detailed_until(
    deadline: crate::control::StartupDeadline,
) -> Result<(), String> {
    let mut bootstrap = crate::attachment::bootstrap().ok_or("attachment bootstrap unavailable")?;
    crate::attachment::with_state_mutation(|| {
        crate::attachment::startup::check()
            .map_err(|_| "attachment initialization was cancelled")?;
        ADMISSION_READY.store(false, Ordering::Release);
        crate::state()
            .lock()
            .map_err(|_| "alias admission state unavailable")?
            .gateway
            .namespace
            .registered = false;
        Ok(())
    })?;
    let recipient = if bootstrap.approval_root_identity.is_some() {
        Some(
            crate::root_image::self_identity()
                .map_err(|code| format!("alias recipient identity: {code}"))?,
        )
    } else {
        None
    };
    let mut challenge = if recipient.is_some() {
        use rand::TryRng;
        let mut value = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut value)
            .map_err(|_| "alias admission random challenge unavailable")?;
        Some(value)
    } else {
        None
    };

    if recipient.is_some() {
        crate::attachment::with_state_mutation(|| {
            crate::root_image::clear_challenge();
            crate::state()
                .lock()
                .map_err(|_| "alias admission state unavailable")?
                .gateway
                .root_image_challenged = false;
            Ok(())
        })?;
    }
    loop {
        crate::attachment::startup::check()
            .map_err(|_| "attachment initialization was cancelled")?;
        deadline
            .remaining()
            .map_err(|_| "alias admission deadline exceeded")?;
        let anchor = crate::state()
            .lock()
            .map_err(|_| "alias admission state unavailable")?
            .gateway
            .namespace
            .anchor
            .clone();
        let Some(anchor) = anchor else {
            return crate::attachment::with_state_mutation(|| {
                crate::attachment::startup::check()
                    .map_err(|_| "attachment initialization was cancelled")?;
                ADMISSION_READY.store(true, Ordering::Release);
                Ok(())
            });
        };
        bootstrap.alias_inherited = Some(anchor.clone());
        let (cursor, head) = {
            let state = crate::state()
                .lock()
                .map_err(|_| "alias admission state unavailable")?;
            (
                state.gateway.namespace.records.len() as u64,
                state.gateway.namespace.stored_head,
            )
        };
        let registration = crate::control::register_alias_host_control(
            &bootstrap, cursor, head, &deadline, challenge,
        )?;
        crate::attachment::startup::check()
            .map_err(|_| "attachment initialization was cancelled")?;
        if let (Some(expected_challenge), Some(recipient)) = (&challenge, &recipient) {
            if let Err(error) = crate::root_image::accept_snapshot(
                &bootstrap,
                registration
                    .root_image
                    .as_ref()
                    .ok_or("root image snapshot missing")?,
                expected_challenge,
                recipient,
                registration.proof.as_ref(),
            ) {
                if error == "root_image_snapshot_stale" {
                    use rand::TryRng;
                    let mut value = [0u8; 32];
                    rand::rngs::SysRng
                        .try_fill_bytes(&mut value)
                        .map_err(|_| "alias admission random challenge unavailable")?;
                    challenge = Some(value);
                    continue;
                }
                return Err(format!("root image attestation: {error}"));
            }
        }
        if let Some(snapshot) = registration.snapshot {
            apply(&bootstrap, &snapshot, registration.proof.as_ref())
                .map_err(|error| format!("alias history verification: {error}"))?;
            continue;
        }
        if !registration.ready {
            if crate::attachment::logically_detached() {
                let state = crate::state()
                    .lock()
                    .map_err(|_| "alias admission state unavailable")?;
                if state.gateway.namespace.history_ready
                    && state.gateway.namespace.records.len() as u64 == cursor
                    && state.gateway.namespace.stored_head == head
                {
                    ADMISSION_READY.store(true, Ordering::Release);
                    return Ok(());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        let _gate = crate::attachment::state_gate()?;
        crate::attachment::startup::check()
            .map_err(|_| "attachment initialization was cancelled")?;
        let mut state = crate::state()
            .lock()
            .map_err(|_| "alias admission state unavailable")?;
        if !state.gateway.namespace.history_ready
            || state
                .gateway
                .namespace
                .head_at(cursor)
                .map_err(|_| "alias admission state unavailable")?
                != head
        {
            return Err("alias registration changed the retained prefix".into());
        }
        state.gateway.namespace.registered = true;
        ADMISSION_READY.store(true, Ordering::Release);
        return Ok(());
    }
}

pub(crate) fn confirm_publication(
    gateway: &GatewayState,
    address: std::net::IpAddr,
    name: &str,
    native: &wire::NativeFallback,
    sequence: u64,
    head: [u8; 32],
) -> Result<(), i32> {
    let namespace = &gateway.namespace;
    if !namespace.registered
        || !namespace.history_ready
        || sequence == 0
        || sequence > namespace.records.len() as u64
        || namespace.head_at(sequence).map_err(|_| HH_ERR_PROTOCOL)? != head
    {
        return Err(HH_ERR_PROTOCOL);
    }
    let record = &namespace.records[sequence as usize - 1];
    if record.address != address
        || record.hostname != name
        || record.native_fallback != *native
        || record.ambiguous
        || gateway.ambiguous_aliases.contains(&address)
    {
        return Err(HH_ERR_PROTOCOL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(sequence: u64) -> IssuedRecord {
        IssuedRecord {
            sequence,
            address: format!("198.18.27.{sequence}").parse().unwrap(),
            hostname: format!("n{sequence}.namespace.test"),
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
            issuer_pid: 12,
            issuer_birth: 56,
            ambiguous: false,
        }
    }
    fn page(base: u64, previous: [u8; 32], records: Vec<IssuedRecord>) -> AliasSnapshotPayload {
        let mut head = previous;
        for record in &records {
            head = wire::alias_record_head(&head, record).unwrap();
        }
        AliasSnapshotPayload {
            schema_version: 1,
            instance_id: String::new(),
            attachment_id: String::new(),
            root_pid: 12,
            session_id: String::new(),
            host_binding: String::new(),
            base_sequence: base,
            previous_head: previous,
            sequence: base + records.len() as u64,
            head,
            records,
            complete: true,
        }
    }
    fn accept(
        gateway: &mut GatewayState,
        payload: AliasSnapshotPayload,
        key: [u8; 32],
        claims: Option<wire::ApprovalClaims>,
    ) -> Result<(), String> {
        let previous = gateway.namespace.anchor.clone();
        apply_verified(gateway, payload, previous, key, claims)
    }
    fn claims(at: u64, nonce: u8, key: [u8; 32]) -> wire::ApprovalClaims {
        wire::ApprovalClaims {
            manager_claimant: None,
            action: wire::ApprovedAction::Attach,
            nonce: [nonce; 32],
            approved_at_ms: at,
            expires_at_ms: at + 1000,
            core_attestation_public_key: Some(key),
            root_image: None,
            exec_epoch: 0,
        }
    }
    #[test]
    fn creator_highwater_is_reproduced_before_native_cache_is_published() {
        let first = page(0, [0; 32], vec![record(1)]);
        let second = page(1, first.head, vec![record(2)]);
        let key = [7; 32];
        let mut gateway = GatewayState::default();
        gateway.namespace.anchor = Some(AliasInheritance {
            metadata_only: false,
            public_key: key,
            sequence: 2,
            head: second.head,
            endorsement_approved_at_ms: 10,
            endorsement_nonce: Some([1; 32]),
        });
        accept(&mut gateway, first.clone(), key, None).unwrap();
        assert!(!gateway.namespace.history_ready);
        assert!(gateway.issued_aliases.is_empty());
        let mut bad = second.clone();
        bad.records[0].hostname = "rewritten.test".into();
        bad.head = wire::alias_record_head(&bad.previous_head, &bad.records[0]).unwrap();
        assert!(accept(&mut gateway, bad, key, None).is_err());
        assert!(gateway.issued_aliases.is_empty());
        accept(&mut gateway, second.clone(), key, None).unwrap();
        assert!(gateway.namespace.history_ready);
        assert_eq!(gateway.namespace.records.len(), 2);
        assert_eq!(gateway.issued_aliases.len(), 2);
        accept(&mut gateway, first, key, None).unwrap();
        assert_eq!(gateway.namespace.anchor.as_ref().unwrap().sequence, 2);
        assert_eq!(gateway.namespace.stored_head, second.head);
        assert!(confirm_publication(
            &gateway,
            record(1).address,
            &record(1).hostname,
            &record(1).native_fallback,
            1,
            gateway.namespace.head_at(1).unwrap()
        )
        .is_err());
        gateway.namespace.registered = true;
        confirm_publication(
            &gateway,
            record(1).address,
            &record(1).hostname,
            &record(1).native_fallback,
            1,
            gateway.namespace.head_at(1).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn new_signer_requires_fresh_endorsement_and_exact_retained_prefix() {
        let key = [8; 32];
        let nextkey = [9; 32];
        let mut gateway = GatewayState::default();
        gateway.namespace.anchor = Some(AliasInheritance {
            metadata_only: false,
            public_key: key,
            sequence: 0,
            head: [0; 32],
            endorsement_approved_at_ms: 20,
            endorsement_nonce: Some([2; 32]),
        });
        gateway.namespace.history_ready = true;
        let first = page(0, [0; 32], vec![record(1)]);
        accept(&mut gateway, first.clone(), key, None).unwrap();
        let anchor = page(1, first.head, vec![]);
        assert!(accept(&mut gateway, anchor.clone(), nextkey, None).is_err());
        assert!(accept(
            &mut gateway,
            anchor.clone(),
            nextkey,
            Some(claims(19, 3, nextkey))
        )
        .is_err());
        assert!(accept(
            &mut gateway,
            anchor.clone(),
            nextkey,
            Some(claims(20, 3, nextkey))
        )
        .is_err());
        let mut wrong = anchor.clone();
        wrong.previous_head = [4; 32];
        wrong.head = [4; 32];
        assert!(accept(&mut gateway, wrong, nextkey, Some(claims(21, 3, nextkey))).is_err());
        accept(
            &mut gateway,
            anchor.clone(),
            nextkey,
            Some(claims(21, 3, nextkey)),
        )
        .unwrap();
        assert_eq!(
            gateway.namespace.anchor.as_ref().unwrap().public_key,
            nextkey
        );
        assert_eq!(gateway.namespace.records.len(), 1);
        assert!(accept(&mut gateway, anchor, key, Some(claims(20, 2, key))).is_err());
        let second = page(1, first.head, vec![record(2)]);
        accept(&mut gateway, second, nextkey, None).unwrap();
        assert_eq!(gateway.namespace.records.len(), 2);
    }
}
