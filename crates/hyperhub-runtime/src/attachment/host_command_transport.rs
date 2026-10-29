//! Outer lifecycle envelope. Evidence is excluded from the semantic command
//! body so its digest never depends on the signature which authorizes it.
use super::{
    AcceptedOperationCertificate, AuthenticatedCommand, HostCommandChallenge,
    HostCommandPossessionProof, HostLifecycleCommand, HostStatus, PROTOCOL,
};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Serialize, Deserialize)]
#[serde(tag = "host_lifecycle", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostLifecycleEnvelope {
    Challenge {
        request: AuthenticatedCommand,
        certificate: AcceptedOperationCertificate,
        purpose: HostLifecycleCommand,
    },
    Execute {
        request: AuthenticatedCommand,
        certificate: AcceptedOperationCertificate,
        purpose: HostLifecycleCommand,
        nonce: [u8; 32],
        possession: HostCommandPossessionProof,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLifecycleReply {
    pub challenge: Option<HostCommandChallenge>,
    pub status: Option<HostStatus>,
    pub error: Option<String>,
}
impl HostLifecycleReply {
    pub fn challenge(challenge: HostCommandChallenge) -> Self {
        Self {
            challenge: Some(challenge),
            status: None,
            error: None,
        }
    }
    pub fn status(status: HostStatus) -> Self {
        Self {
            challenge: None,
            status: Some(status),
            error: None,
        }
    }
    pub fn error(error: impl Into<String>) -> Self {
        Self {
            challenge: None,
            status: None,
            error: Some(error.into()),
        }
    }
}

/// The signer must independently validate the accepted scope and exact
/// challenge before using its manager-memory key. Both exchanges pin the
/// actual OS peer PID; birth is checked against the Host-issued challenge.
pub fn exchange_lifecycle_for_process(
    endpoint: &str,
    request: &AuthenticatedCommand,
    certificate: &AcceptedOperationCertificate,
    purpose: HostLifecycleCommand,
    pid: u32,
    birth: u64,
    sign: impl FnOnce(&HostCommandChallenge) -> io::Result<HostCommandPossessionProof>,
) -> io::Result<HostStatus> {
    let exchange = |envelope: HostLifecycleEnvelope| -> io::Result<HostLifecycleReply> {
        let value = serde_json::to_value(envelope).map_err(io::Error::other)?;
        let value = super::exchange_raw_for_process(endpoint, &value, pid)?;
        serde_json::from_value(value).map_err(|_| invalid("invalid lifecycle reply"))
    };
    let reply = exchange(HostLifecycleEnvelope::Challenge {
        request: request.clone(),
        certificate: certificate.clone(),
        purpose,
    })?;
    let challenge = match (reply.challenge, reply.status, reply.error) {
        (Some(challenge), None, None) => challenge,
        (None, None, Some(error)) => return Err(invalid(&error)),
        _ => return Err(invalid("unexpected lifecycle challenge reply")),
    };
    if challenge.host_pid != pid || challenge.host_birth != birth {
        return Err(invalid(
            "lifecycle challenge belongs to another Host incarnation",
        ));
    }
    let possession = sign(&challenge)?;
    let reply = exchange(HostLifecycleEnvelope::Execute {
        request: request.clone(),
        certificate: certificate.clone(),
        purpose,
        nonce: challenge.nonce,
        possession,
    })?;
    match (reply.challenge, reply.status, reply.error) {
        (None, Some(status), None)
            if status.protocol == PROTOCOL
                && status.pid == pid
                && status.attachment_id == request.attachment_id =>
        {
            Ok(status)
        }
        (None, None, Some(error)) => Err(invalid(&error)),
        _ => Err(invalid("unexpected lifecycle execution reply")),
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
