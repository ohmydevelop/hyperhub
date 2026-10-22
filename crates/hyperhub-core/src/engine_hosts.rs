//! Resident control-plane ownership of authenticated Engine Host channels.
//! A delivery is accepted before it is acknowledged. Losing a channel makes
//! outstanding results unknown; it must never fabricate success or rollback.
use crate::session::unix_timestamp_ms;
use hmac::{Hmac, Mac};
use hyperhub_engine::host::{self, Acknowledgement, Backend, Delivery};
use hyperhub_engine::management::{Command, Reply};
use hyperhub_runtime::Snapshot;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const MAX_HOSTS: usize = 256;
const MAX_REQUESTS: usize = 4096;
const MAX_COORDINATED_REQUESTS: usize = 8192;
const MAX_COORDINATED_STREAMS: usize = 128 * 256;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerCommand {
    pub request_id: String,
    pub host_id: String,
    pub issued_at_ms: u64,
    pub command: Command,
}
impl OwnerCommand {
    fn mac(&self, key: &[u8]) -> io::Result<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(io::Error::other)?;
        mac.update(b"hyperhub-engine-owner-v1\0");
        mac.update(&serde_json::to_vec(self).map_err(io::Error::other)?);
        Ok(mac)
    }
    pub fn proof(&self, key: &[u8]) -> io::Result<Vec<u8>> {
        Ok(self.mac(key)?.finalize().into_bytes().to_vec())
    }
    pub fn authenticate(&self, key: &[u8], proof: &[u8], now: u64) -> bool {
        self.issued_at_ms.abs_diff(now) <= 30_000
            && valid_id(&self.request_id)
            && valid_id(&self.host_id)
            && self
                .mac(key)
                .is_ok_and(|mac| mac.verify_slice(proof).is_ok())
    }
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Accepted,
    Delivered,
    Acknowledged,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommandStatus {
    pub request_id: String,
    pub host_id: String,
    pub state: DeliveryState,
    pub reply: Option<Reply>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostStatus {
    pub host_id: String,
    pub backend: Backend,
    pub host_pid: u32,
    pub root_pid: u32,
    pub root_start_time: Option<u64>,
    pub member_instance: u64,
    pub online: bool,
    pub last_seen_ms: u64,
    pub snapshot: Snapshot,
}

struct Host {
    status: HostStatus,
    session_id: String,
    sender: mpsc::Sender<Delivery>,
    // Credentials are held only by the per-channel Serve task, never in status.
}
#[derive(Default)]
struct State {
    hosts: BTreeMap<String, Host>,
    requests: BTreeMap<String, (Vec<u8>, CommandStatus)>,
    coordinated_high_water: BTreeMap<String, u64>,
}
#[derive(Clone, Default)]
pub struct EngineHosts(Arc<Mutex<State>>);

pub(crate) struct Registration {
    pub id: String,
    pub receiver: mpsc::Receiver<Delivery>,
    registry: EngineHosts,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.0.lock() {
            if let Some(host) = state.hosts.get_mut(&self.id) {
                host.status.online = false;
            }
            for (_, request) in state.requests.values_mut() {
                if request.host_id == self.id && request.state != DeliveryState::Acknowledged {
                    request.state = DeliveryState::Unknown;
                }
            }
        }
    }
}
impl EngineHosts {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register(
        &self,
        session_id: String,
        backend: Backend,
        host_pid: u32,
        root_pid: u32,
        member_instance: u64,
        root_start_time: Option<u64>,
        snapshot: Snapshot,
    ) -> io::Result<Registration> {
        snapshot.host.validate().map_err(io::Error::other)?;
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("engine registry poisoned"))?;
        if state.hosts.values().any(|h| {
            h.status.online
                && h.session_id == session_id
                && h.status.host_pid == host_pid
                && h.status.root_pid == root_pid
                && h.status.member_instance == member_instance
        }) {
            return Err(io::Error::other("engine Host already registered"));
        }
        if state.hosts.len() >= MAX_HOSTS {
            let stale = state
                .hosts
                .iter()
                .find(|(_, h)| !h.status.online)
                .map(|(id, _)| id.clone());
            if let Some(id) = stale {
                state.hosts.remove(&id);
            } else {
                return Err(io::Error::other("engine Host limit reached"));
            }
        }
        let random: [u8; 32] = rand::random();
        let id = hyperhub_runtime::artifact::hex(&random);
        let (sender, receiver) = mpsc::channel(16);
        state.hosts.insert(
            id.clone(),
            Host {
                session_id,
                sender,
                status: HostStatus {
                    host_id: id.clone(),
                    backend,
                    host_pid,
                    root_pid,
                    root_start_time,
                    member_instance,
                    online: true,
                    last_seen_ms: unix_timestamp_ms(),
                    snapshot,
                },
            },
        );
        Ok(Registration {
            id,
            receiver,
            registry: self.clone(),
        })
    }

    /// Authentication must precede this method. Request IDs have bounded,
    /// non-evicting idempotency history. A full registry rejects new commands.
    pub(crate) fn dispatch(&self, request: OwnerCommand) -> io::Result<CommandStatus> {
        if request.request_id.starts_with("rollout-") {
            return Err(io::Error::other("reserved coordinator request ID"));
        }
        self.dispatch_inner(request, false)
    }
    pub(crate) fn dispatch_coordinated(&self, request: OwnerCommand) -> io::Result<CommandStatus> {
        self.dispatch_inner(request, true)
    }
    fn dispatch_inner(
        &self,
        request: OwnerCommand,
        coordinated: bool,
    ) -> io::Result<CommandStatus> {
        if serde_json::to_vec(&request.command)
            .map_err(io::Error::other)?
            .len()
            > hyperhub_engine::management::MAX_COMMAND
        {
            return Err(io::Error::other("engine command exceeds limit"));
        }
        let bytes = serde_json::to_vec(&request).map_err(io::Error::other)?;
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("engine registry poisoned"))?;
        if let Some((previous, status)) = state.requests.get(&request.request_id) {
            if previous != &bytes {
                return Err(io::Error::other("engine request ID conflict"));
            }
            return Ok(status.clone());
        }
        let sequence = if coordinated {
            let (stream, sequence) = request
                .request_id
                .rsplit_once('-')
                .filter(|(stream, _)| stream.starts_with("rollout-"))
                .ok_or_else(|| io::Error::other("invalid coordinator sequence"))?;
            let sequence: u64 = sequence
                .parse()
                .map_err(|_| io::Error::other("invalid coordinator sequence"))?;
            if sequence == 0
                || state
                    .coordinated_high_water
                    .get(stream)
                    .is_some_and(|old| sequence <= *old)
            {
                return Err(io::Error::other("coordinator request was superseded"));
            }
            if !state.coordinated_high_water.contains_key(stream)
                && state.coordinated_high_water.len() >= MAX_COORDINATED_STREAMS
            {
                return Err(io::Error::other("coordinator stream limit reached"));
            }
            Some((stream.to_owned(), sequence))
        } else {
            None
        };
        let count = state
            .requests
            .keys()
            .filter(|id| id.starts_with("rollout-") == coordinated)
            .count();
        if count
            >= if coordinated {
                MAX_COORDINATED_REQUESTS
            } else {
                MAX_REQUESTS
            }
        {
            return Err(io::Error::other("engine request limit reached"));
        }
        let host = state
            .hosts
            .get(&request.host_id)
            .filter(|h| h.status.online)
            .ok_or_else(|| io::Error::other("engine Host unavailable"))?;
        // The channel task adds a session-specific proof immediately before IO.
        host.sender
            .try_send(Delivery {
                request_id: request.request_id.clone(),
                command: request.command,
                proof: vec![],
            })
            .map_err(|_| io::Error::other("engine Host command queue unavailable"))?;
        let status = CommandStatus {
            request_id: request.request_id.clone(),
            host_id: request.host_id,
            state: DeliveryState::Accepted,
            reply: None,
        };
        state
            .requests
            .insert(request.request_id, (bytes, status.clone()));
        if let Some((stream, sequence)) = sequence {
            state.coordinated_high_water.insert(stream, sequence);
        }
        Ok(status)
    }
    /// Call only after the journal no longer needs these results. Keep a compact
    /// sequence watermark to reject replay, and retain every unacknowledged
    /// delivery until it completes or its channel is lost. Manual history is
    /// non-evicting and cannot consume the coordinator's recovery capacity.
    pub(crate) fn retire_coordinated(&self, pending: &std::collections::BTreeSet<String>) {
        if let Ok(mut state) = self.0.lock() {
            state.requests.retain(|id, (_, status)| {
                !id.starts_with("rollout-")
                    || pending.contains(id)
                    || !matches!(
                        status.state,
                        DeliveryState::Acknowledged | DeliveryState::Unknown
                    )
            });
        }
    }
    pub(crate) fn delivered(&self, host_id: &str, request_id: &str) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("engine registry poisoned"))?;
        let status = &mut state
            .requests
            .get_mut(request_id)
            .ok_or_else(|| io::Error::other("unknown engine request"))?
            .1;
        if status.host_id != host_id || status.state != DeliveryState::Accepted {
            return Err(io::Error::other("invalid engine delivery"));
        }
        status.state = DeliveryState::Delivered;
        Ok(())
    }
    pub(crate) fn acknowledge(
        &self,
        host_id: &str,
        ack: Acknowledgement,
        heartbeat: bool,
    ) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("engine registry poisoned"))?;
        let host = state
            .hosts
            .get_mut(host_id)
            .ok_or_else(|| io::Error::other("unknown engine Host"))?;
        if ack.snapshot.host != host.status.snapshot.host {
            return Err(io::Error::other("resident Host identity changed"));
        }
        if !heartbeat {
            let status = &mut state
                .requests
                .get_mut(&ack.request_id)
                .ok_or_else(|| io::Error::other("unknown engine acknowledgement"))?
                .1;
            if status.host_id != host_id || status.state != DeliveryState::Delivered {
                return Err(io::Error::other("invalid engine acknowledgement"));
            }
            status.state = DeliveryState::Acknowledged;
            status.reply = Some(ack.reply);
        }
        let host = state.hosts.get_mut(host_id).unwrap();
        host.status.snapshot = ack.snapshot;
        host.status.last_seen_ms = unix_timestamp_ms();
        Ok(())
    }
    pub fn hosts(&self) -> Vec<HostStatus> {
        self.host(None)
    }
    pub fn host(&self, id: Option<&str>) -> Vec<HostStatus> {
        self.0
            .lock()
            .map(|s| {
                s.hosts
                    .values()
                    .filter(|h| id.is_none_or(|id| h.status.host_id == id))
                    .map(|h| {
                        let mut status = h.status.clone();
                        // Aggregate status is bounded. Query a specific Host for the
                        // detailed report, or a transaction ID for recovery history.
                        if id.is_none() && status.snapshot.transactions.len() > 1 {
                            status.snapshot.transactions_omitted +=
                                status.snapshot.transactions.len() - 1;
                            status
                                .snapshot
                                .transactions
                                .drain(..status.snapshot.transactions.len() - 1);
                        }
                        status
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn commands(&self) -> Vec<CommandStatus> {
        self.0
            .lock()
            .map(|s| s.requests.values().map(|(_, v)| v.clone()).collect())
            .unwrap_or_default()
    }
    pub fn command(&self, id: &str) -> Option<CommandStatus> {
        self.0
            .lock()
            .ok()?
            .requests
            .get(id)
            .map(|(_, status)| status.clone())
    }
}

pub(crate) fn sign_delivery(
    delivery: &mut Delivery,
    token: &str,
    nonce: &[u8; 32],
) -> io::Result<()> {
    delivery.proof = host::delivery_proof(token, nonce, &delivery.request_id, &delivery.command)?;
    Ok(())
}

#[cfg(test)]
#[path = "engine_hosts_tests.rs"]
mod tests;
