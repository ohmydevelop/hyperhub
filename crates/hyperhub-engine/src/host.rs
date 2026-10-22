//! Authenticated local-control wire types. Transport authentication belongs to
//! the resident Serve; the module never receives a session token or API key.
use crate::management::{self, Command, Reply};
use hmac::{Hmac, Mac};
use hyperhub_runtime::{Runtime, Snapshot};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const MAX_FRAME: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    LinuxPtrace,
    LinuxGum,
    WindowsGum,
}

#[derive(Serialize)]
pub struct Enrollment<'a> {
    #[serde(rename = "type")]
    pub kind: &'a str,
    pub session_id: &'a str,
    pub token: &'a str,
    pub root_pid: u32,
    pub backend: Backend,
    pub native_base_sha256: &'a str,
    pub snapshot: Snapshot,
    pub nonce: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub request_id: String,
    pub command: Command,
    pub proof: Vec<u8>,
}

pub fn delivery_proof(
    token: &str,
    nonce: &[u8; 32],
    id: &str,
    command: &Command,
) -> io::Result<Vec<u8>> {
    Ok(delivery_mac(token, nonce, id, command)?
        .finalize()
        .into_bytes()
        .to_vec())
}
fn delivery_mac(
    token: &str,
    nonce: &[u8; 32],
    id: &str,
    command: &Command,
) -> io::Result<Hmac<sha2::Sha256>> {
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(token.as_bytes()).map_err(io::Error::other)?;
    mac.update(b"hyperhub-engine-delivery-v1\0");
    mac.update(nonce);
    mac.update(&(id.len() as u64).to_be_bytes());
    mac.update(id.as_bytes());
    mac.update(&serde_json::to_vec(command).map_err(io::Error::other)?);
    Ok(mac)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub request_id: String,
    pub reply: Reply,
    pub snapshot: Snapshot,
}

/// Keep wire reports bounded without discarding the Runtime's idempotency log.
pub fn report(runtime: &Runtime) -> Result<Snapshot, hyperhub_runtime::Error> {
    runtime.snapshot_limited(32)
}

pub fn write_frame(stream: &mut (impl Write + ?Sized), value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::other("engine control frame exceeds limit"));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

pub fn read_frame<T: DeserializeOwned>(stream: &mut (impl Read + ?Sized)) -> io::Result<T> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::other("engine control frame exceeds limit"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

/// # Safety
/// The stream must connect to the authenticated resident Serve. Only that
/// trusted peer may request loading native code. Do not hold target-state locks.
pub unsafe fn serve(
    stream: &mut (impl Read + Write + ?Sized),
    runtime: &Runtime,
    token: &str,
    nonce: &[u8; 32],
) -> io::Result<()> {
    loop {
        let delivery: Delivery = read_frame(stream)?;
        unsafe {
            apply_delivery(stream, runtime, token, nonce, delivery)?;
        }
    }
}
unsafe fn apply_delivery(
    stream: &mut (impl Read + Write + ?Sized),
    runtime: &Runtime,
    token: &str,
    nonce: &[u8; 32],
    delivery: Delivery,
) -> io::Result<()> {
    delivery_mac(token, nonce, &delivery.request_id, &delivery.command)?
        .verify_slice(&delivery.proof)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid engine command proof",
            )
        })?;
    let reply = if matches!(delivery.command, Command::Query) {
        Reply::Snapshot {
            snapshot: report(runtime).map_err(io::Error::other)?,
        }
    } else {
        unsafe { management::execute(runtime, delivery.command) }
    };
    write_frame(
        stream,
        &Acknowledgement {
            request_id: delivery.request_id,
            reply,
            snapshot: report(runtime).map_err(io::Error::other)?,
        },
    )
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Enrolled {
    #[serde(rename = "type")]
    pub kind: String,
    pub host_id: String,
    pub nonce: [u8; 32],
    pub proof: Vec<u8>,
}
fn enrolled_mac(token: &str, nonce: &[u8; 32], host_id: &str) -> io::Result<Hmac<sha2::Sha256>> {
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(token.as_bytes()).map_err(io::Error::other)?;
    mac.update(b"hyperhub-engine-enrolled-v1\0");
    mac.update(nonce);
    mac.update(&(host_id.len() as u64).to_be_bytes());
    mac.update(host_id.as_bytes());
    Ok(mac)
}
impl Enrolled {
    pub fn sign(host_id: String, nonce: [u8; 32], token: &str) -> io::Result<Self> {
        let proof = enrolled_mac(token, &nonce, &host_id)?
            .finalize()
            .into_bytes()
            .to_vec();
        Ok(Self {
            kind: "engine_host_enrolled".into(),
            host_id,
            nonce,
            proof,
        })
    }
    pub fn verify(&self, token: &str, nonce: &[u8; 32]) -> bool {
        self.kind == "engine_host_enrolled"
            && self.nonce == *nonce
            && !self.host_id.is_empty()
            && enrolled_mac(token, nonce, &self.host_id)
                .is_ok_and(|mac| mac.verify_slice(&self.proof).is_ok())
    }
}
/// Execute correction commands while the target remains suspended, then accept
/// only the resident's authenticated durable-enrollment acknowledgement.
/// # Safety
/// Same native-loading requirements as `serve`; no Host lock may be held.
pub unsafe fn await_enrollment(
    stream: &mut (impl Read + Write + ?Sized),
    runtime: &Runtime,
    token: &str,
    nonce: &[u8; 32],
) -> io::Result<String> {
    loop {
        let value: serde_json::Value = read_frame(stream)?;
        if value.get("type").and_then(|v| v.as_str()) == Some("engine_host_enrolled") {
            let ack: Enrolled = serde_json::from_value(value).map_err(io::Error::other)?;
            if !ack.verify(token, nonce) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid engine enrollment proof",
                ));
            }
            return Ok(ack.host_id);
        }
        let delivery = serde_json::from_value(value).map_err(io::Error::other)?;
        unsafe {
            apply_delivery(stream, runtime, token, nonce, delivery)?;
        }
    }
}
