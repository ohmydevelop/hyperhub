//! Live, nonce-challenged executable epochs. A stored certificate cannot prove
//! that a fresh SDK belongs to the current execution of the same process image.
use super::{canonical_alias_bytes, Bootstrap, MAX_FRAME};
use serde::{Deserialize, Serialize};
use std::io;
pub const ROOT_IMAGE_DOMAIN: &[u8] = b"hyperhub/attachment-root-image/v1\0";
pub const ROOT_IMAGE_CHAIN_DOMAIN: &[u8] = b"hyperhub/attachment-root-image-chain/v1\0";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootImageIdentity {
    pub pid: u32,
    pub birth: u64,
    pub executable_sha256: String,
}
impl RootImageIdentity {
    pub fn same_incarnation(&self, other: &Self) -> bool {
        self.pid == other.pid && self.birth == other.birth
    }
    fn validate(&self) -> io::Result<()> {
        if self.pid == 0
            || self.birth == 0
            || self.executable_sha256.len() != 64
            || !self
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("invalid root image identity"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootImageState {
    pub identity: RootImageIdentity,
    pub exec_epoch: u64,
    pub observed_at_ms: u64,
    pub head: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootImagePayload {
    pub schema_version: u32,
    pub instance_id: String,
    pub attachment_id: String,
    pub session_id: String,
    pub host_binding: String,
    pub initial_identity: RootImageIdentity,
    pub previous: RootImageState,
    pub current: RootImageState,
    pub transition_nonce: [u8; 32],
    pub challenge: Option<[u8; 32]>,
    pub host_pid: Option<u32>,
    pub host_birth: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRootImage {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
impl std::fmt::Debug for SignedRootImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedRootImage")
            .field("certificate", &"<redacted>")
            .finish()
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
pub fn root_image_head(
    previous: &RootImageState,
    identity: &RootImageIdentity,
    exec_epoch: u64,
    observed_at_ms: u64,
    nonce: &[u8; 32],
) -> io::Result<[u8; 32]> {
    use sha2::Digest;
    identity.validate()?;
    let mut hash = sha2::Sha256::new();
    hash.update(ROOT_IMAGE_CHAIN_DOMAIN);
    hash.update(previous.head);
    hash.update(canonical_alias_bytes(&(
        previous,
        identity,
        exec_epoch,
        observed_at_ms,
        nonce,
    ))?);
    Ok(hash.finalize().into())
}
pub fn encode_root_image_payload(payload: &RootImagePayload) -> io::Result<Vec<u8>> {
    let mut bytes = ROOT_IMAGE_DOMAIN.to_vec();
    bytes.extend(canonical_alias_bytes(payload)?);
    if bytes.len() > MAX_FRAME {
        return Err(invalid("root image certificate exceeds frame"));
    }
    Ok(bytes)
}
pub fn decode_root_image(
    bootstrap: &Bootstrap,
    public_key: &[u8; 32],
    signed: &SignedRootImage,
) -> io::Result<RootImagePayload> {
    use ed25519_dalek::{Signature, VerifyingKey};
    if signed.payload.len() <= ROOT_IMAGE_DOMAIN.len()
        || signed.payload.len() > MAX_FRAME
        || !signed.payload.starts_with(ROOT_IMAGE_DOMAIN)
    {
        return Err(invalid("root image signature domain rejected"));
    }
    VerifyingKey::from_bytes(public_key)
        .map_err(|_| invalid("invalid root image signer"))?
        .verify_strict(
            &signed.payload,
            &Signature::from_slice(&signed.signature)
                .map_err(|_| invalid("invalid root image signature"))?,
        )
        .map_err(|_| invalid("root image signature rejected"))?;
    let value: RootImagePayload =
        serde_json::from_slice(&signed.payload[ROOT_IMAGE_DOMAIN.len()..])
            .map_err(|_| invalid("root image payload rejected"))?;
    value.initial_identity.validate()?;
    value.previous.identity.validate()?;
    value.current.identity.validate()?;
    if value.schema_version != 1
        || value.instance_id != bootstrap.approval_instance_id
        || value.attachment_id != bootstrap.attachment_id
        || value.session_id != bootstrap.session_id
        || value.host_binding != bootstrap.approval_binding()?
        || bootstrap.approval_root_identity.as_ref() != Some(&value.initial_identity)
        || !value
            .current
            .identity
            .same_incarnation(&value.initial_identity)
        || !value
            .previous
            .identity
            .same_incarnation(&value.initial_identity)
    {
        return Err(invalid("root image scope or incarnation mismatch"));
    }
    for state in [&value.previous, &value.current] {
        if state.exec_epoch == 0
            && (state.identity != value.initial_identity
                || state.observed_at_ms != 0
                || state.head != [0; 32])
        {
            return Err(invalid(
                "root image genesis does not match the immutable initial identity",
            ));
        }
    }
    if value.challenge.is_some() {
        if value.previous != value.current
            || value.host_pid == Some(0)
            || value.host_pid.is_none()
            || value.host_birth == Some(0)
            || value.host_birth.is_none()
        {
            return Err(invalid(
                "root image challenge does not bind a current recipient snapshot",
            ));
        }
    } else {
        if value.host_pid.is_some()
            || value.host_birth.is_some()
            || value.current.exec_epoch
                != value
                    .previous
                    .exec_epoch
                    .checked_add(1)
                    .ok_or_else(|| invalid("root image epoch overflow"))?
            || value.current.observed_at_ms < value.previous.observed_at_ms
            || root_image_head(
                &value.previous,
                &value.current.identity,
                value.current.exec_epoch,
                value.current.observed_at_ms,
                &value.transition_nonce,
            )? != value.current.head
        {
            return Err(invalid("root image transition is not contiguous"));
        }
    }
    Ok(value)
}

pub fn verify_root_image_snapshot(
    bootstrap: &Bootstrap,
    key: &[u8; 32],
    signed: &SignedRootImage,
    challenge: &[u8; 32],
    recipient: &RootImageIdentity,
) -> io::Result<RootImagePayload> {
    let value = decode_root_image(bootstrap, key, signed)?;
    if value.challenge.as_ref() != Some(challenge)
        || value.host_pid != Some(recipient.pid)
        || value.host_birth != Some(recipient.birth)
        || (recipient.pid == bootstrap.root_pid && value.current.identity != *recipient)
    {
        return Err(invalid(
            "root image snapshot does not bind this live Host challenge and executable",
        ));
    }
    Ok(value)
}
pub fn verify_root_image_continuation(
    previous: &RootImageState,
    value: &RootImagePayload,
) -> io::Result<()> {
    if value.challenge.is_some() || (value.current != *previous && value.previous != *previous) {
        return Err(invalid(
            "root image transition does not extend the retained epoch",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn fixture() -> (Bootstrap, SigningKey, RootImageState) {
        let identity = RootImageIdentity {
            pid: 123,
            birth: 45,
            executable_sha256: "a".repeat(64),
        };
        let bootstrap=serde_json::from_value(serde_json::json!({"approval_root_identity":identity,"attachment_id":"root-image","session_id":"session","token":"t".repeat(64),"control_endpoint":"control","socks_address":"127.0.0.1:1","tls_ca_pem":"unused","observe":false,"firewall":null,"sandbox":null,"host_endpoint":"host","host_token":"h".repeat(64),"scope_tree":true,"root_pid":123,"approval_authority_file":"unused","approval_instance_id":"instance","initially_owned":false,"approval_public_key":null,"approval_inherited_public_key":null,"approval_core_public_key":null,"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":"c".repeat(64)})).unwrap();
        (
            bootstrap,
            SigningKey::from_bytes(&[61; 32]),
            RootImageState {
                identity,
                exec_epoch: 0,
                observed_at_ms: 0,
                head: [0; 32],
            },
        )
    }
    fn payload(
        bootstrap: &Bootstrap,
        previous: RootImageState,
        current: RootImageState,
    ) -> RootImagePayload {
        RootImagePayload {
            schema_version: 1,
            instance_id: bootstrap.approval_instance_id.clone(),
            attachment_id: bootstrap.attachment_id.clone(),
            session_id: bootstrap.session_id.clone(),
            host_binding: bootstrap.approval_binding().unwrap(),
            initial_identity: bootstrap.approval_root_identity.clone().unwrap(),
            previous,
            current,
            transition_nonce: [7; 32],
            challenge: None,
            host_pid: None,
            host_birth: None,
        }
    }
    fn sign(key: &SigningKey, value: &RootImagePayload) -> SignedRootImage {
        let payload = encode_root_image_payload(value).unwrap();
        SignedRootImage {
            signature: key.sign(&payload).to_bytes().to_vec(),
            payload,
        }
    }
    fn next(previous: &RootImageState, identity: RootImageIdentity) -> RootImageState {
        let exec_epoch = previous.exec_epoch + 1;
        let observed_at_ms = previous.observed_at_ms + 1;
        let head =
            root_image_head(previous, &identity, exec_epoch, observed_at_ms, &[7; 32]).unwrap();
        RootImageState {
            identity,
            exec_epoch,
            observed_at_ms,
            head,
        }
    }
    #[test]
    fn two_same_image_execs_still_advance_and_reject_old_transition() {
        let (bootstrap, key, genesis) = fixture();
        let first = next(&genesis, genesis.identity.clone());
        let second = next(&first, first.identity.clone());
        let one = decode_root_image(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &sign(&key, &payload(&bootstrap, genesis.clone(), first.clone())),
        )
        .unwrap();
        let two = decode_root_image(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &sign(&key, &payload(&bootstrap, first.clone(), second.clone())),
        )
        .unwrap();
        verify_root_image_continuation(&genesis, &one).unwrap();
        verify_root_image_continuation(&first, &one).unwrap();
        verify_root_image_continuation(&first, &two).unwrap();
        assert!(verify_root_image_continuation(&second, &one).is_err());
        let mut wrong = two.clone();
        wrong.previous = genesis;
        assert!(decode_root_image(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &sign(&key, &wrong)
        )
        .is_err());
    }
    #[test]
    fn fresh_snapshot_requires_new_nonce_exact_recipient_and_actual_root_image() {
        let (bootstrap, key, state) = fixture();
        let mut snapshot = payload(&bootstrap, state.clone(), state.clone());
        snapshot.challenge = Some([1; 32]);
        snapshot.host_pid = Some(state.identity.pid);
        snapshot.host_birth = Some(state.identity.birth);
        let signed = sign(&key, &snapshot);
        verify_root_image_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &signed,
            &[1; 32],
            &state.identity,
        )
        .unwrap();
        assert!(verify_root_image_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &signed,
            &[2; 32],
            &state.identity
        )
        .is_err());
        let mut changed = state.identity.clone();
        changed.birth += 1;
        assert!(verify_root_image_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &signed,
            &[1; 32],
            &changed
        )
        .is_err());
        changed = state.identity.clone();
        changed.executable_sha256 = "b".repeat(64);
        assert!(verify_root_image_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &signed,
            &[1; 32],
            &changed
        )
        .is_err());
        assert!(verify_root_image_continuation(&state, &snapshot).is_err());
    }

    #[test]
    fn broadcast_before_old_snapshot_requires_fresh_challenge_without_rollback() {
        let (bootstrap, key, zero) = fixture();
        let one = next(&zero, zero.identity.clone());
        let transition = decode_root_image(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &sign(&key, &payload(&bootstrap, zero.clone(), one.clone())),
        )
        .unwrap();
        let retained = transition.current;
        let mut old = payload(&bootstrap, zero.clone(), zero.clone());
        old.challenge = Some([1; 32]);
        old.host_pid = Some(123);
        old.host_birth = Some(45);
        let old_packet = sign(&key, &old);
        let delayed = verify_root_image_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &old_packet,
            &[1; 32],
            &zero.identity,
        )
        .unwrap();
        assert!(!root_image_snapshot_is_current(&retained, &delayed.current).unwrap());
        assert_eq!(retained.exec_epoch, 1);
        let mut fresh = payload(&bootstrap, one.clone(), one);
        fresh.challenge = Some([2; 32]);
        fresh.host_pid = Some(123);
        fresh.host_birth = Some(45);
        let current = verify_root_image_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &sign(&key, &fresh),
            &[2; 32],
            &zero.identity,
        )
        .unwrap();
        assert!(root_image_snapshot_is_current(&retained, &current.current).unwrap());
        assert!(verify_root_image_snapshot(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &old_packet,
            &[2; 32],
            &zero.identity
        )
        .is_err());
    }
    #[test]
    fn foreign_scope_key_and_rewritten_image_are_rejected() {
        let (bootstrap, key, state) = fixture();
        let next = next(
            &state,
            RootImageIdentity {
                executable_sha256: "b".repeat(64),
                ..state.identity.clone()
            },
        );
        let value = payload(&bootstrap, state, next);
        let signed = sign(&key, &value);
        assert!(decode_root_image(
            &bootstrap,
            &SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
            &signed
        )
        .is_err());
        let mut foreign = bootstrap.clone();
        foreign.session_id.push('x');
        assert!(decode_root_image(&foreign, &key.verifying_key().to_bytes(), &signed).is_err());
        let mut bad = value;
        bad.current.identity.executable_sha256 = "c".repeat(64);
        assert!(decode_root_image(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &sign(&key, &bad)
        )
        .is_err());
    }
}

/// An older in-flight snapshot is a retry condition; an equal-epoch rewrite is
/// an integrity failure. Neither can replace the retained current state.
pub fn root_image_snapshot_is_current(
    previous: &RootImageState,
    current: &RootImageState,
) -> io::Result<bool> {
    if current.exec_epoch < previous.exec_epoch {
        return Ok(false);
    }
    if current.exec_epoch == previous.exec_epoch && current != previous {
        return Err(invalid("root image snapshot rewrites the retained epoch"));
    }
    Ok(true)
}
