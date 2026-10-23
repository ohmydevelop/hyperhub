use super::*;
impl WorkerManager {
    pub(crate) async fn dispatch(
        &self,
        stream: tokio::net::TcpStream,
        session: AuthenticatedSession,
    ) -> io::Result<()> {
        let cancellation = session.cancellation.clone();
        let stream = stream.into_std()?;
        super::super::cancellation::initialize(&stream)?;
        let (ready, ready_receiver) = mpsc::channel();
        let (done, done_receiver) = oneshot::channel();
        // Admission and dispatch selection share the switching lock. A worker
        // cannot observe zero leases, receive Drain, then get a delayed offer
        // that had selected it just before the generation switch.
        let (worker, id) = {
            let state = self
                .0
                .state
                .lock()
                .map_err(|_| io::Error::other("worker group state poisoned"))?;
            if self.0.closing.load(Ordering::Acquire) {
                return Err(io::Error::other(
                    "forwarding worker manager is shutting down",
                ));
            }
            let worker = state
                .workers
                .get(&state.active)
                .filter(|worker| worker.healthy() && !worker.retiring.load(Ordering::Acquire))
                .cloned()
                .ok_or_else(|| io::Error::other("active forwarding worker is unavailable"))?;
            let mut offers = worker
                .offers
                .lock()
                .map_err(|_| io::Error::other("worker offer state poisoned"))?;
            if offers.len() >= 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "worker connection capacity reached",
                ));
            }
            let id = worker.next_offer.fetch_add(1, Ordering::AcqRel);
            if id == 0 || id == u64::MAX {
                return Err(io::Error::other("worker offer sequence exhausted"));
            }
            if let Err(error) = worker.authority.bind(id, session.clone()) {
                worker.next_offer.fetch_sub(1, Ordering::AcqRel);
                return Err(error);
            }
            offers.insert(
                id,
                Offer {
                    ready: Some(ready),
                    done: Some(done),
                    granted: false,
                    sent: false,
                    cancelled: false,
                    cancellation_socket: None,
                },
            );
            drop(offers);
            (worker, id)
        };
        let config = self.0.service.runtime().snapshot().config;
        let offer = Frame::Offer {
            id,
            identity: Identity::from(&session),
            config: Box::new((*config).clone()),
            audit_log: config.audit.log.clone(),
            transcript_dir: config.audit.transcript_dir.clone(),
        };
        let sender = worker.clone();
        let delivery =
            tokio::task::spawn_blocking(move || sender.offer(id, offer, stream, ready_receiver));
        tokio::select! {
            result=delivery=>{result.map_err(io::Error::other)??;},
            _=cancellation.cancelled()=>{worker.cancel(id);return Err(io::Error::new(io::ErrorKind::ConnectionAborted,"session was revoked during worker handoff"));}
        }
        tokio::select! {
            result=done_receiver=>result.map_err(|_|io::Error::new(io::ErrorKind::BrokenPipe,"forwarding worker stopped before connection completion"))?,
            _=cancellation.cancelled()=>{worker.cancel(id);Err(io::Error::new(io::ErrorKind::ConnectionAborted,"session was revoked"))}
        }
    }
}
