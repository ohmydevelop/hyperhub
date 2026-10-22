use super::protocol::{Frame, Identity, VERSION};
use super::{rpc, wire};
use crate::session::AuthenticatedSession;
use crate::socks::SocksService;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct Pending {
    stream: TcpStream,
    service: SocksService,
    identity: Identity,
    cancellation: CancellationToken,
}
struct Active {
    cancellation: CancellationToken,
    probe: Option<Arc<TcpStream>>,
}
struct CloseSocket(Arc<TcpStream>);
impl Drop for CloseSocket {
    fn drop(&mut self) {
        let _ = super::cancellation::mark_closed(&self.0);
    }
}

fn cancellation_probe(stream: &TcpStream) -> io::Result<Arc<TcpStream>> {
    let probe = stream.try_clone().and_then(|stream| {
        stream.set_nonblocking(true)?;
        Ok(Arc::new(stream))
    });
    if probe.is_err() {
        // No CloseSocket guard can be constructed. Publish completion through
        // the original shared socket even if Finished cannot reach the parent.
        let _ = super::cancellation::mark_closed(stream);
    }
    probe
}

#[cfg(all(test, unix))]
mod tests;

enum Event {
    Message(Frame, Option<TcpStream>),
    Finished(u64, io::Result<()>),
    Disconnected(String),
}

pub(crate) async fn run() -> io::Result<()> {
    let wire = wire::from_stdio()?;
    let receiver = wire.clone();
    let (frame, socket) = tokio::task::spawn_blocking(move || receiver.receive::<Frame>())
        .await
        .map_err(io::Error::other)??;
    if socket.is_some() {
        return Err(io::Error::other("worker bootstrap must not carry a socket"));
    }
    let Frame::Bootstrap {
        protocol,
        parent_pid,
        worker_pid,
        generation,
        nonce,
        material,
    } = frame
    else {
        return Err(io::Error::other("worker bootstrap is missing"));
    };
    if protocol != VERSION
        || parent_pid == 0
        || worker_pid != std::process::id()
        || generation == 0
        || nonce.len() != 32
        || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::Error::other(
            "worker bootstrap identity or protocol is incompatible",
        ));
    }
    #[cfg(unix)]
    if unsafe { libc::getppid() } as u32 != parent_pid {
        return Err(io::Error::other(
            "worker bootstrap parent PID differs from OS parent",
        ));
    }
    if let Some(engine) = &material.engine {
        use hyperhub_runtime::Engine;
        let validation = (|| {
            let artifact = hyperhub_runtime::artifact::Artifact::install(
                &engine.cache,
                &engine.manifest,
                std::fs::File::open(&engine.source)
                    .map_err(|error| hyperhub_runtime::Error::Artifact(error.to_string()))?,
            )?;
            // Only the authenticated, hash-verified candidate child loads this
            // table. A constructor or C ABI failure cannot corrupt Serve.
            let module = unsafe { hyperhub_runtime::native::NativeEngine::load(artifact, None) }?;
            if !module.health() {
                return Err(hyperhub_runtime::Error::Artifact(
                    "candidate native Engine health check failed".into(),
                ));
            }
            drop(module);
            Ok(())
        })();
        if let Err(error) = validation {
            let requires_restart = matches!(error, hyperhub_runtime::Error::RequiresRestart);
            let _ = wire.send(&Frame::Rejected { requires_restart }, None);
            return Err(io::Error::other("candidate native Engine preflight failed"));
        }
    }
    let peer = rpc::Peer::new(wire.clone());
    let template = SocksService::worker_template(&material, peer.client(0))?;
    drop(material);
    wire.send(
        &Frame::Booted {
            protocol: VERSION,
            parent_pid,
            worker_pid,
            generation,
            nonce,
            version: env!("CARGO_PKG_VERSION").into(),
        },
        None,
    )?;
    let (sender, mut events) = mpsc::channel(32);
    let read_wire = wire.clone();
    let read_peer = peer.clone();
    let read_sender = sender.clone();
    std::thread::Builder::new()
        .name("hh-forward-worker-rpc".into())
        .spawn(move || {
            loop {
                match read_wire.receive::<Frame>() {
                    Ok((Frame::Reply { id, response }, None)) => {
                        if let Err(error) = read_peer.reply(id, response) {
                            let _ =
                                read_sender.blocking_send(Event::Disconnected(error.to_string()));
                            break;
                        }
                    }
                    Ok((Frame::Ping { nonce }, None)) => {
                        if nonce == 0 || read_wire.send(&Frame::Pong { nonce }, None).is_err() {
                            let _ = read_sender.blocking_send(Event::Disconnected(
                                "worker heartbeat failed".into(),
                            ));
                            break;
                        }
                    }
                    Ok((frame, socket)) => {
                        if read_sender
                            .blocking_send(Event::Message(frame, socket))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = read_sender.blocking_send(Event::Disconnected(error.to_string()));
                        break;
                    }
                }
            }
            read_peer.disconnected();
        })?;
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut active: HashMap<u64, Active> = HashMap::new();
    let mut last_offer = 0;
    let mut seen_offers = BTreeMap::new();
    let mut draining = false;
    let mut disconnected: Option<String> = None;
    let mut cancellation_tick = tokio::time::interval(Duration::from_millis(250));
    cancellation_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let outcome = loop {
        let event = tokio::select! {
            event = events.recv() => match event {
                Some(event) => event,
                None => break Err(io::Error::other("worker event channel ended")),
            },
            _ = cancellation_tick.tick(), if disconnected.is_some() => {
                // At most4096 active offers. Only a lost control plane needs
                // this bounded fallback; healthy traffic has no probe work.
                for connection in active.values() {
                    if connection.probe.as_ref().is_some_and(|probe| super::cancellation::locally_closed(probe)) {
                        connection.cancellation.cancel();
                    }
                }
                continue;
            }
        };
        let result = match event {
            Event::Message(
                Frame::Offer {
                    id,
                    identity,
                    config,
                    audit_log,
                    transcript_dir,
                },
                Some(stream),
            ) if !draining => {
                if id == 0
                    || seen_offers
                        .range(..=id)
                        .next_back()
                        .is_some_and(|(_, end)| id <= *end)
                    || identity.session_id.is_empty()
                    || identity.pid == 0
                    || identity.connection_id == 0
                    || pending.len() + active.len() >= 4096
                {
                    Err(io::Error::other(
                        "invalid or duplicate forwarding socket offer",
                    ))
                } else {
                    last_offer = last_offer.max(id);
                    remember(&mut seen_offers, id);
                    if seen_offers.len() > 4096 {
                        break Err(io::Error::other("worker offer ordering window exhausted"));
                    }
                    match template.worker_connection(
                        peer.client(id),
                        *config,
                        audit_log,
                        transcript_dir,
                    ) {
                        Ok(service) => {
                            pending.insert(
                                id,
                                Pending {
                                    stream,
                                    service,
                                    identity,
                                    cancellation: CancellationToken::new(),
                                },
                            );
                            wire.send(&Frame::Ready { id }, None)
                        }
                        Err(error) => wire.send(
                            &Frame::Finished {
                                id,
                                error: Some(error.to_string()),
                            },
                            None,
                        ),
                    }
                }
            }
            Event::Message(Frame::Grant { id }, None) => {
                if let Some(offer) = pending.remove(&id) {
                    let cancellation = offer.cancellation.clone();
                    let probe = cancellation_probe(&offer.stream);
                    active.insert(
                        id,
                        Active {
                            cancellation: cancellation.clone(),
                            probe: probe.as_ref().ok().cloned(),
                        },
                    );
                    let sender = sender.clone();
                    tokio::spawn(async move {
                        let result=async {
                            let _shutdown=CloseSocket(probe?);
                            offer.stream.set_nonblocking(true)?;
                            let stream=tokio::net::TcpStream::from_std(offer.stream)?;
                            let session=AuthenticatedSession {session_id:offer.identity.session_id,pid:offer.identity.pid,connection_id:offer.identity.connection_id,executable:offer.identity.executable,cancellation:cancellation.clone()};
                            tokio::select! {
                                result=offer.service.forward_authenticated(stream,session)=>result,
                                _=cancellation.cancelled()=>Err(io::Error::new(io::ErrorKind::ConnectionAborted,"resident Serve cancelled the connection")),
                            }
                        }.await;
                        let _ = sender.send(Event::Finished(id, result)).await;
                    });
                    Ok(())
                } else {
                    Err(io::Error::other(
                        "ownership grant does not match a ready socket offer",
                    ))
                }
            }
            Event::Message(Frame::Cancel { id }, None) => {
                if let Some(offer) = pending.remove(&id) {
                    drop(offer);
                    wire.send(
                        &Frame::Finished {
                            id,
                            error: Some("socket offer cancelled before ownership grant".into()),
                        },
                        None,
                    )
                } else if let Some(connection) = active.get(&id) {
                    connection.cancellation.cancel();
                    Ok(())
                } else if id > 0 && id <= last_offer {
                    Ok(())
                } else {
                    Err(io::Error::other(
                        "cancellation references an unknown socket offer",
                    ))
                }
            }
            Event::Finished(id, result) => {
                if active.remove(&id).is_none() {
                    Err(io::Error::other("worker completed an unknown connection"))
                } else if disconnected.is_some() {
                    Ok(())
                } else {
                    wire.send(
                        &Frame::Finished {
                            id,
                            error: result
                                .err()
                                .map(|error| error.to_string().chars().take(256).collect()),
                        },
                        None,
                    )
                }
            }
            Event::Message(Frame::Drain, None) => {
                draining = true;
                Ok(())
            }
            Event::Disconnected(reason) => Err(io::Error::new(io::ErrorKind::BrokenPipe, reason)),
            _ => Err(io::Error::other(
                "unexpected worker control message or socket for this lifecycle phase",
            )),
        };
        if let Err(error) = result {
            pending.clear();
            peer.disconnected();
            wire.shutdown();
            disconnected.get_or_insert_with(|| error.to_string());
            draining = true;
        }
        if draining && pending.is_empty() && active.is_empty() {
            break if let Some(reason) = disconnected {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, reason))
            } else {
                wire.send(&Frame::Drained, None)
            };
        }
    };
    for connection in active.values() {
        connection.cancellation.cancel();
    }
    drop(pending);
    peer.disconnected();
    wire.shutdown();
    outcome
}

fn remember(ranges: &mut BTreeMap<u64, u64>, id: u64) {
    let left = ranges
        .range(..id)
        .next_back()
        .filter(|(_, end)| end.checked_add(1) == Some(id))
        .map(|(start, _)| *start);
    let right = id.checked_add(1).and_then(|next| ranges.remove(&next));
    let end = right.unwrap_or(id);
    if let Some(start) = left {
        *ranges.get_mut(&start).unwrap() = end;
    } else {
        ranges.insert(id, end);
    }
}
