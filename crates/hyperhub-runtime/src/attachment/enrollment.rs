//! Approval-root enrollment is independent of API/session credentials and files.
use super::Bootstrap;
use serde::{Deserialize, Serialize};
use std::io;
pub const ENROLLMENT_DOMAIN: &[u8] = b"hyperhub/attachment-root-enrollment/v1\0";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnrollmentChallenge {
    pub challenge: [u8; 32],
    pub host_pid: u32,
    pub host_birth: u64,
    pub expires_at_ms: u64,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRootCertificate {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
impl std::fmt::Debug for ApprovalRootCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalRootCertificate")
            .field("certificate", &"<redacted>")
            .finish()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentPayload {
    pub schema_version: u32,
    pub source: String,
    pub instance_id: String,
    pub attachment_id: String,
    pub root_pid: u32,
    pub host_pid: u32,
    pub host_birth: u64,
    pub challenge: [u8; 32],
    pub approval_public_key: [u8; 32],
    pub generation: u64,
    pub core_pid: u32,
    pub core_birth: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
pub fn verify_enrollment(
    bootstrap: &Bootstrap,
    challenge: &ApprovalEnrollmentChallenge,
    certificate: &ApprovalRootCertificate,
    _peer_pid: u32,
    now: u64,
) -> io::Result<[u8; 32]> {
    use ed25519_dalek::{Signature, VerifyingKey};
    fn deny() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approval-root enrollment rejected",
        )
    }
    if certificate.payload.len() <= ENROLLMENT_DOMAIN.len()
        || certificate.payload.len() > super::MAX_FRAME
        || !certificate.payload.starts_with(ENROLLMENT_DOMAIN)
    {
        return Err(deny());
    }
    let payload: EnrollmentPayload =
        serde_json::from_slice(&certificate.payload[ENROLLMENT_DOMAIN.len()..])
            .map_err(|_| deny())?;
    if payload.schema_version != 1
        || payload.generation != 0
        || payload.instance_id != bootstrap.approval_instance_id
        || payload.attachment_id != bootstrap.attachment_id
        || payload.root_pid != bootstrap.root_pid
        || payload.host_pid != challenge.host_pid
        || payload.host_birth != challenge.host_birth
        || payload.challenge != challenge.challenge
        || payload.issued_at_ms > now
        || payload.expires_at_ms <= now
        || payload.expires_at_ms > challenge.expires_at_ms
        || payload.expires_at_ms.saturating_sub(payload.issued_at_ms) > 60_000
    {
        return Err(deny());
    }
    let verifying = match payload.source.as_str() {
        "core" => {
            if payload.core_pid != bootstrap.approval_core_pid
                || payload.core_birth != bootstrap.approval_core_birth
                || payload.core_pid == 0
            {
                return Err(deny());
            }
            bootstrap.approval_core_public_key.ok_or_else(deny)?
        }
        // An executable-name/hash or pipe-opener identity cannot prove which
        // process wrote bytes through a duplicated handle. Only the pinned
        // original Core can attest a legacy empty Host's approval root.
        _ => return Err(deny()),
    };
    let key = VerifyingKey::from_bytes(&verifying).map_err(|_| deny())?;
    key.verify_strict(
        &certificate.payload,
        &Signature::from_slice(&certificate.signature).map_err(|_| deny())?,
    )
    .map_err(|_| deny())?;
    VerifyingKey::from_bytes(&payload.approval_public_key).map_err(|_| deny())?;
    Ok(payload.approval_public_key)
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn fixture() -> (
        Bootstrap,
        ApprovalEnrollmentChallenge,
        EnrollmentPayload,
        SigningKey,
    ) {
        let key = SigningKey::from_bytes(&[45; 32]);
        let bootstrap = Bootstrap {
            attachment_id: "fixture-attachment".into(),
            session_id: "session".into(),
            token: "t".repeat(64),
            control_endpoint: "control".into(),
            socks_address: "127.0.0.1:1".into(),
            tls_ca_pem: "-----BEGIN CERTIFICATE-----fixture".into(),
            observe: false,
            firewall: None,
            sandbox: None,
            host_endpoint: "host".into(),
            host_token: "h".repeat(64),
            scope_tree: true,
            root_pid: 123,
            approval_authority_file: "unused".into(),
            approval_instance_id: "instance".into(),
            initially_owned: true,
            external_attachment: true,
            native_dns_mode: crate::attachment::NativeDnsMode::PreserveAnswers,
            approval_not_before_ms: 0,
            approval_public_key: None,
            approval_inherited_public_key: None,
            approval_root_identity: None,
            alias_inherited: None,
            approval_core_public_key: Some(key.verifying_key().to_bytes()),
            approval_core_pid: 456,
            approval_core_birth: 789,
            approval_cli_sha256: "c".repeat(64),
        };
        let challenge = ApprovalEnrollmentChallenge {
            challenge: [7; 32],
            host_pid: 321,
            host_birth: 654,
            expires_at_ms: 500,
        };
        let payload = EnrollmentPayload {
            schema_version: 1,
            source: "core".into(),
            instance_id: "instance".into(),
            attachment_id: "fixture-attachment".into(),
            root_pid: 123,
            host_pid: 321,
            host_birth: 654,
            challenge: [7; 32],
            approval_public_key: SigningKey::from_bytes(&[46; 32]).verifying_key().to_bytes(),
            generation: 0,
            core_pid: 456,
            core_birth: 789,
            issued_at_ms: 100,
            expires_at_ms: 500,
        };
        (bootstrap, challenge, payload, key)
    }
    fn sign(payload: &EnrollmentPayload, key: &SigningKey) -> ApprovalRootCertificate {
        let mut bytes = ENROLLMENT_DOMAIN.to_vec();
        bytes.extend(serde_json::to_vec(payload).unwrap());
        ApprovalRootCertificate {
            signature: key.sign(&bytes).to_bytes().to_vec(),
            payload: bytes,
        }
    }
    #[test]
    fn core_enrollment_binds_host_challenge_incarnation_root_and_lifetime() {
        let (bootstrap, challenge, payload, key) = fixture();
        let certificate = sign(&payload, &key);
        assert_eq!(
            verify_enrollment(&bootstrap, &challenge, &certificate, 0, 200).unwrap(),
            payload.approval_public_key
        );
        assert!(verify_enrollment(&bootstrap, &challenge, &certificate, 0, 500).is_err());
        for changed in [
            "host",
            "birth",
            "root",
            "challenge",
            "core",
            "instance",
            "future",
            "generation",
        ] {
            let mut value = payload.clone();
            match changed {
                "host" => value.host_pid += 1,
                "birth" => value.host_birth += 1,
                "root" => value.root_pid += 1,
                "challenge" => value.challenge[0] ^= 1,
                "core" => value.core_birth += 1,
                "instance" => value.instance_id.push('x'),
                "future" => value.issued_at_ms = 201,
                "generation" => value.generation = 1,
                _ => unreachable!(),
            };
            assert!(
                verify_enrollment(&bootstrap, &challenge, &sign(&value, &key), 0, 200).is_err(),
                "unbound {changed}"
            );
        }
        let forged = sign(&payload, &SigningKey::from_bytes(&[47; 32]));
        assert!(verify_enrollment(&bootstrap, &challenge, &forged, 0, 200).is_err());
    }
    #[test]
    fn runtime_tokens_and_candidate_self_signature_are_not_core_attestation() {
        let (bootstrap, challenge, mut payload, _) = fixture();
        let attacker = SigningKey::from_bytes(&[48; 32]);
        payload.approval_public_key = attacker.verifying_key().to_bytes();
        assert!(
            verify_enrollment(&bootstrap, &challenge, &sign(&payload, &attacker), 0, 200).is_err()
        );
        payload.source = "password_cli".into();
        payload.core_pid = 0;
        payload.core_birth = 0;
        assert!(
            verify_enrollment(&bootstrap, &challenge, &sign(&payload, &attacker), 0, 200).is_err()
        );
    }
}
