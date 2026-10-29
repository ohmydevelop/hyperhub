//! Signed, ordered session-wide issuance history. A native fallback describes
//! the producer's original resolution; consumers never substitute another DNS
//! lookup or continue the former routing/firewall policy after detach.
use super::Bootstrap;
use serde::{Deserialize, Serialize};
use std::{io, net::IpAddr};
pub const SESSION_ALIAS_DOMAIN: &[u8] = b"hyperhub/session-issued-alias-snapshot/v1\0";
pub const SESSION_ALIAS_CHAIN_DOMAIN: &[u8] = b"hyperhub/session-issued-alias-chain/v1\0";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAddress {
    pub ip: IpAddr,
    pub scope_id: u32,
    pub flowinfo: u32,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeUnavailable {
    SuppressedByActivePolicy,
    UnsupportedOriginalResolver,
    InvalidNativeAnswer,
    NoCompatibleAddress,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeFallback {
    pub family: u32,
    pub addresses: Vec<NativeAddress>,
    pub failure: Option<i32>,
    pub unavailable: Option<NativeUnavailable>,
}
impl NativeFallback {
    /// Synthetic publication requires a disjoint native result. A resolver
    /// address already in our pool remains an external/observed origin.
    pub fn validate_synthesis(&self) -> io::Result<()> {
        self.validate()?;
        if self
            .addresses
            .iter()
            .any(|address| super::is_synthetic_alias_address(address.ip))
        {
            return Err(invalid(
                "native resolver result overlaps the synthetic address pool",
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> io::Result<()> {
        if !matches!(self.family, 4 | 6)
            || (self.failure.is_some() && self.unavailable.is_some())
            || ((self.failure.is_some() || self.unavailable.is_some())
                && !self.addresses.is_empty())
            || self.failure == Some(0)
            || self.addresses.iter().any(|address| {
                address.ip.is_ipv4() != (self.family == 4)
                    || (address.ip.is_ipv4() && (address.scope_id != 0 || address.flowinfo != 0))
            })
        {
            return Err(invalid("invalid producer native fallback"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuedRecord {
    pub sequence: u64,
    pub address: IpAddr,
    pub hostname: String,
    pub native_fallback: NativeFallback,
    pub issuer_pid: u32,
    pub issuer_birth: u64,
    pub ambiguous: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AliasSnapshotPayload {
    pub schema_version: u32,
    pub instance_id: String,
    pub attachment_id: String,
    pub root_pid: u32,
    pub session_id: String,
    pub host_binding: String,
    pub base_sequence: u64,
    pub previous_head: [u8; 32],
    pub sequence: u64,
    pub head: [u8; 32],
    pub records: Vec<IssuedRecord>,
    pub complete: bool,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedSessionAliasSnapshot {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
impl std::fmt::Debug for SignedSessionAliasSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedSessionAliasSnapshot")
            .field("snapshot", &"<redacted>")
            .finish()
    }
}
/// A creator-proved derivative. The original Bootstrap remains the immutable
/// approval binding; new children inherit actual verified key/head state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AliasInheritance {
    #[serde(default)]
    pub metadata_only: bool,
    pub public_key: [u8; 32],
    pub sequence: u64,
    pub head: [u8; 32],
    pub endorsement_approved_at_ms: u64,
    pub endorsement_nonce: Option<[u8; 32]>,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
pub fn canonical_alias_bytes<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    fn canonical(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(values) => {
                let sorted: std::collections::BTreeMap<_, _> = values
                    .into_iter()
                    .map(|(key, value)| (key, canonical(value)))
                    .collect();
                serde_json::Value::Object(sorted.into_iter().collect())
            }
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(canonical).collect())
            }
            other => other,
        }
    }
    serde_json::to_vec(&canonical(
        serde_json::to_value(value).map_err(io::Error::other)?,
    ))
    .map_err(io::Error::other)
}
pub fn native_fallback_fingerprint(fallback: &NativeFallback) -> io::Result<[u8; 32]> {
    fallback.validate()?;
    use sha2::Digest;
    Ok(sha2::Sha256::digest(canonical_alias_bytes(fallback)?).into())
}
pub fn alias_record_head(previous: &[u8; 32], record: &IssuedRecord) -> io::Result<[u8; 32]> {
    record.native_fallback.validate_synthesis()?;
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    hash.update(SESSION_ALIAS_CHAIN_DOMAIN);
    hash.update(previous);
    hash.update(canonical_alias_bytes(record)?);
    Ok(hash.finalize().into())
}
pub fn encode_alias_payload(payload: &AliasSnapshotPayload) -> io::Result<Vec<u8>> {
    let mut bytes = SESSION_ALIAS_DOMAIN.to_vec();
    bytes.extend(canonical_alias_bytes(payload)?);
    if bytes.len() > super::MAX_FRAME {
        return Err(invalid("session alias snapshot exceeds bounded frame"));
    }
    Ok(bytes)
}
pub fn decode_alias_snapshot(
    bootstrap: &Bootstrap,
    public_key: &[u8; 32],
    snapshot: &SignedSessionAliasSnapshot,
) -> io::Result<AliasSnapshotPayload> {
    use ed25519_dalek::{Signature, VerifyingKey};
    if snapshot.payload.len() <= SESSION_ALIAS_DOMAIN.len()
        || snapshot.payload.len() > super::MAX_FRAME
        || !snapshot.payload.starts_with(SESSION_ALIAS_DOMAIN)
    {
        return Err(invalid("invalid session alias signature domain"));
    }
    VerifyingKey::from_bytes(public_key)
        .map_err(|_| invalid("invalid pinned alias signer"))?
        .verify_strict(
            &snapshot.payload,
            &Signature::from_slice(&snapshot.signature)
                .map_err(|_| invalid("invalid alias signature"))?,
        )
        .map_err(|_| invalid("session alias signature rejected"))?;
    let payload: AliasSnapshotPayload =
        serde_json::from_slice(&snapshot.payload[SESSION_ALIAS_DOMAIN.len()..])
            .map_err(|_| invalid("invalid signed alias payload"))?;
    if payload.schema_version != 1
        || payload.instance_id != bootstrap.approval_instance_id
        || payload.attachment_id != bootstrap.attachment_id
        || payload.root_pid != bootstrap.root_pid
        || payload.session_id != bootstrap.session_id
        || payload.host_binding != bootstrap.approval_binding()?
        || !payload.complete
        || payload.base_sequence > payload.sequence
        || payload.sequence.checked_sub(payload.base_sequence) != Some(payload.records.len() as u64)
        || (payload.base_sequence == 0 && payload.previous_head != [0; 32])
    {
        return Err(invalid(
            "session alias snapshot binding or completeness rejected",
        ));
    }
    let mut head = payload.previous_head;
    for (index, record) in payload.records.iter().enumerate() {
        if record.sequence
            != payload
                .base_sequence
                .checked_add(index as u64 + 1)
                .ok_or_else(|| invalid("alias sequence overflow"))?
            || record.issuer_pid == 0
            || record.issuer_birth == 0
            || record.hostname.is_empty()
            || record.address.is_ipv4() != (record.native_fallback.family == 4)
        {
            return Err(invalid("invalid issued alias sequence or source"));
        }
        head = alias_record_head(&head, record)?;
    }
    if head != payload.head {
        return Err(invalid("session alias chain head rejected"));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn bootstrap() -> Bootstrap {
        serde_json::from_value(serde_json::json!({
            "attachment_id":"alias-fixture","session_id":"session","token":"t".repeat(64),"control_endpoint":"control","socks_address":"127.0.0.1:1","tls_ca_pem":"unused",
            "observe":false,"firewall":null,"sandbox":null,"host_endpoint":"host","host_token":"h".repeat(64),"scope_tree":true,"root_pid":123,
            "approval_authority_file":"unused","approval_instance_id":"instance","initially_owned":false,"approval_public_key":null,"approval_inherited_public_key":null,"approval_core_public_key":null,"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":"c".repeat(64)
        })).unwrap()
    }
    #[test]
    fn child_startup_ownership_preserves_the_approved_native_dns_mode() {
        let bootstrap = bootstrap();
        let mut child = bootstrap.clone();
        child.initially_owned = true;
        assert_eq!(
            child.native_dns_mode,
            super::super::NativeDnsMode::PreserveAnswers
        );
        assert_eq!(
            child.approval_binding().unwrap(),
            bootstrap.approval_binding().unwrap()
        );
        child.native_dns_mode = super::super::NativeDnsMode::SyntheticPool;
        assert_ne!(
            child.approval_binding().unwrap(),
            bootstrap.approval_binding().unwrap()
        );
    }
    pub(super) fn record(sequence: u64) -> IssuedRecord {
        IssuedRecord {
            sequence,
            address: format!("198.18.20.{sequence}").parse().unwrap(),
            hostname: format!("h{sequence}.fixture.test"),
            native_fallback: NativeFallback {
                family: 4,
                addresses: vec![NativeAddress {
                    ip: "127.0.0.1".parse().unwrap(),
                    scope_id: 0,
                    flowinfo: 0,
                }],
                failure: None,
                unavailable: None,
            },
            issuer_pid: 45,
            issuer_birth: 89,
            ambiguous: false,
        }
    }
    fn payload(
        bootstrap: &Bootstrap,
        base: u64,
        previous: [u8; 32],
        records: Vec<IssuedRecord>,
    ) -> AliasSnapshotPayload {
        let mut head = previous;
        for record in &records {
            head = alias_record_head(&head, record).unwrap();
        }
        AliasSnapshotPayload {
            schema_version: 1,
            instance_id: bootstrap.approval_instance_id.clone(),
            attachment_id: bootstrap.attachment_id.clone(),
            root_pid: bootstrap.root_pid,
            session_id: bootstrap.session_id.clone(),
            host_binding: bootstrap.approval_binding().unwrap(),
            base_sequence: base,
            previous_head: previous,
            sequence: base + records.len() as u64,
            head,
            records,
            complete: true,
        }
    }
    fn signed(key: &SigningKey, payload: &AliasSnapshotPayload) -> SignedSessionAliasSnapshot {
        let payload = encode_alias_payload(payload).unwrap();
        let signature = key.sign(&payload).to_bytes().to_vec();
        SignedSessionAliasSnapshot { payload, signature }
    }
    #[test]
    fn signed_pages_bind_exact_host_scope_and_ordered_provenance() {
        let bootstrap = bootstrap();
        let key = SigningKey::from_bytes(&[31; 32]);
        let first = payload(&bootstrap, 0, [0; 32], vec![record(1)]);
        let next = payload(&bootstrap, 1, first.head, vec![record(2)]);
        assert_eq!(
            decode_alias_snapshot(
                &bootstrap,
                &key.verifying_key().to_bytes(),
                &signed(&key, &first)
            )
            .unwrap(),
            first
        );
        assert_eq!(
            decode_alias_snapshot(
                &bootstrap,
                &key.verifying_key().to_bytes(),
                &signed(&key, &next)
            )
            .unwrap(),
            next
        );
        let mut changed = bootstrap.clone();
        changed.session_id.push('x');
        assert!(decode_alias_snapshot(
            &changed,
            &key.verifying_key().to_bytes(),
            &signed(&key, &next)
        )
        .is_err());
        assert!(decode_alias_snapshot(
            &bootstrap,
            &SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes(),
            &signed(&key, &next)
        )
        .is_err());
        let mut corrupt = next.clone();
        corrupt.records[0].native_fallback.addresses[0].ip = "127.0.0.2".parse().unwrap();
        assert!(decode_alias_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &signed(&key, &corrupt)
        )
        .is_err());
        let mut incomplete = next.clone();
        incomplete.complete = false;
        assert!(decode_alias_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &signed(&key, &incomplete)
        )
        .is_err());
        let anchor = payload(&bootstrap, 2, next.head, vec![]);
        assert!(decode_alias_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &signed(&key, &anchor)
        )
        .is_ok());
    }

    #[test]
    fn native_pool_overlap_cannot_be_reclassified_as_new_issuance() {
        for ip in [
            "198.18.0.1",
            "198.19.255.255",
            "::ffff:198.18.0.1",
            "::ffff:198.19.255.255",
            "fdfe:6879:7065:7268:7562::1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            let native = NativeFallback {
                family: if ip.is_ipv4() { 4 } else { 6 },
                addresses: vec![NativeAddress {
                    ip,
                    scope_id: 0,
                    flowinfo: 0,
                }],
                failure: None,
                unavailable: None,
            };
            assert!(native.validate().is_ok());
            assert!(native.validate_synthesis().is_err());
        }
        for ip in [
            "198.17.255.255",
            "198.20.0.1",
            "::ffff:198.20.0.1",
            "::198.18.0.1",
            "64:ff9b::c612:1",
            "fdfe:6879:7065:7268:7562:1::1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            let native = NativeFallback {
                family: if ip.is_ipv4() { 4 } else { 6 },
                addresses: vec![NativeAddress {
                    ip,
                    scope_id: 0,
                    flowinfo: 0,
                }],
                failure: None,
                unavailable: None,
            };
            assert!(native.validate_synthesis().is_ok());
        }
    }
    #[test]
    fn native_answer_fingerprint_preserves_order_error_scope_and_unavailability() {
        let mut fallback = record(1).native_fallback;
        fallback.addresses.push(NativeAddress {
            ip: "127.0.0.2".parse().unwrap(),
            scope_id: 0,
            flowinfo: 0,
        });
        let original = native_fallback_fingerprint(&fallback).unwrap();
        fallback.addresses.reverse();
        assert_ne!(native_fallback_fingerprint(&fallback).unwrap(), original);
        fallback.addresses[0].scope_id = 1;
        assert!(fallback.validate().is_err());
        fallback.addresses = vec![NativeAddress {
            ip: "::1".parse().unwrap(),
            scope_id: 4,
            flowinfo: 7,
        }];
        assert!(fallback.validate().is_err());
        fallback.family = 6;
        assert!(fallback.validate().is_ok());
        fallback.addresses.clear();
        fallback.failure = Some(-2);
        let failed = native_fallback_fingerprint(&fallback).unwrap();
        fallback.failure = None;
        fallback.unavailable = Some(NativeUnavailable::SuppressedByActivePolicy);
        assert_ne!(native_fallback_fingerprint(&fallback).unwrap(), failed);
        fallback.failure = Some(2);
        assert!(fallback.validate().is_err());
    }
}
