use super::authority::{Request, Response, Rpc};
use super::protocol::{Frame, TIMEOUT};
use super::wire::Wire;
use std::collections::HashMap;
use std::io;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};

pub(super) struct Peer {
    wire: Wire,
    next: AtomicU64,
    pending: Mutex<HashMap<u64, mpsc::Sender<io::Result<Response>>>>,
}
impl Peer {
    pub(super) fn new(wire: Wire) -> Arc<Self> {
        Arc::new(Self {
            wire,
            next: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        })
    }
    pub(super) fn client(self: &Arc<Self>, offer: u64) -> super::authority::Client {
        super::authority::Client::new(Caller {
            peer: self.clone(),
            offer,
        })
    }
    pub(super) fn reply(&self, id: u64, response: Response) -> io::Result<()> {
        let sender = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("worker RPC state poisoned"))?
            .remove(&id);
        if let Some(sender) = sender {
            let _ = sender.send(Ok(response));
        } else if id == 0 || id >= self.next.load(Ordering::Acquire) {
            return Err(io::Error::other("unsolicited resident authority response"));
        }
        Ok(())
    }
    pub(super) fn disconnected(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            for (_, sender) in pending.drain() {
                let _ = sender.send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "resident authority channel disconnected",
                )));
            }
        }
    }
}
struct Caller {
    peer: Arc<Peer>,
    offer: u64,
}
impl Rpc for Caller {
    fn call(&self, request: Request) -> io::Result<Response> {
        let id = self.peer.next.fetch_add(1, Ordering::AcqRel);
        if id == 0 || id == u64::MAX {
            return Err(io::Error::other("worker RPC sequence exhausted"));
        }
        let (sender, receiver) = mpsc::channel();
        {
            let mut pending = self
                .peer
                .pending
                .lock()
                .map_err(|_| io::Error::other("worker RPC state poisoned"))?;
            if pending.len() >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "worker RPC capacity reached",
                ));
            }
            pending.insert(id, sender);
        }
        let result = self
            .peer
            .wire
            .send(
                &Frame::Rpc {
                    id,
                    offer: self.offer,
                    request,
                },
                None,
            )
            .and_then(|()| {
                receiver.recv_timeout(TIMEOUT).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("resident authority response unavailable: {error}"),
                    )
                })?
            });
        self.peer
            .pending
            .lock()
            .map_err(|_| io::Error::other("worker RPC state poisoned"))?
            .remove(&id);
        result
    }
}
