use super::*;
use crate::forward::authority::Response;
use std::time::Duration;

#[cfg(test)]
mod tests;

fn disconnect_offers(offers: &mut HashMap<u64, Offer>, reason: &str) -> Vec<u64> {
    let mut abandoned = Vec::new();
    offers.retain(|id, offer| {
        if let Some(sender) = offer.ready.take() {
            let _ = sender.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                reason.to_owned(),
            )));
        }
        // Granted streams keep their cancellation watchers after IPC loss.
        // No business IO is permitted before Grant, so all other claims can
        // be released immediately without waiting for this worker to exit.
        if offer.granted {
            return true;
        }
        if let Some(sender) = offer.done.take() {
            let _ = sender.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                reason.to_owned(),
            )));
        }
        abandoned.push(*id);
        false
    });
    abandoned
}

struct Startup(Option<Arc<Worker>>);
impl Drop for Startup {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            worker.wire.shutdown();
            if let Ok(mut child) = worker.child.lock() {
                let _ = child.kill();
                let _ = child.wait();
            }
            worker.exited.store(true, Ordering::Release);
            worker.authority.clear();
        }
    }
}

impl Worker {
    pub(super) fn start(
        service: &SocksService,
        generation: u64,
        executable: artifact::Executable,
        claims: Arc<Mutex<HashSet<(String, u32, u64)>>>,
        engine: Option<EnginePreflight>,
    ) -> io::Result<Arc<Self>> {
        let mut material = service.worker_bootstrap()?;
        material.engine = engine;
        let mut command = Command::new(executable.path());
        command.arg("forward-worker");
        let (wire, mut child) = wire::spawn(&mut command)?;
        let deadlines = match super::super::deadline::Scheduler::new(wire.clone()) {
            Ok(deadlines) => deadlines,
            Err(error) => {
                wire.shutdown();
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let pid = child.id();
        let (boot_sender, boot_receiver) = mpsc::channel();
        let (rpc_sender, rpc_receiver) = mpsc::sync_channel::<RpcWork>(64);
        let worker = Arc::new(Self {
            generation,
            pid,
            start_time: crate::session::process_start_time(pid),
            executable,
            wire,
            deadlines,
            authority: ResidentAuthority::new(service.clone(), claims),
            child: Mutex::new(child),
            version: Mutex::new(String::new()),
            offers: Mutex::new(HashMap::new()),
            next_offer: AtomicU64::new(1),
            connected: AtomicBool::new(true),
            retiring: AtomicBool::new(false),
            drain_sent: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            last_pong: Mutex::new(std::time::Instant::now()),
            ping: AtomicU64::new(0),
            rpc_queue: Mutex::new(Some(rpc_sender)),
            booted: Mutex::new(Some(boot_sender)),
            reason: Mutex::new(None),
        });
        let mut startup = Startup(Some(worker.clone()));
        let rpc_receiver = Arc::new(Mutex::new(rpc_receiver));
        for _ in 0..4 {
            let receiver = rpc_receiver.clone();
            let actor = Arc::downgrade(&worker);
            std::thread::Builder::new()
                .name("hh-worker-authority".into())
                .spawn(move || loop {
                    let work = receiver
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .recv();
                    let Ok((id, offer, request)) = work else {
                        break;
                    };
                    let Some(worker) = actor.upgrade() else {
                        break;
                    };
                    let response = worker
                        .authority
                        .call(offer, request)
                        .unwrap_or_else(|error| Response::Error {
                            message: error.to_string(),
                        });
                    let _ = worker.wire.send(&Frame::Reply { id, response }, None);
                })?;
        }
        let mut random = [0u8; 16];
        rand::fill(&mut random);
        let nonce: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let reader = Arc::downgrade(&worker);
        let expected = nonce.clone();
        std::thread::Builder::new()
            .name("hh-worker-control".into())
            .spawn(move || {
                let mut booted = false;
                loop {
                    let Some(worker) = reader.upgrade() else {
                        break;
                    };
                    let message = worker.wire.receive::<Frame>();
                    let result = message.and_then(|(frame, socket)| {
                        if socket.is_some() {
                            return Err(io::Error::other("worker sent an unexpected socket"));
                        }
                        match frame {
                            Frame::Booted {
                                protocol,
                                parent_pid,
                                worker_pid,
                                generation,
                                nonce,
                                version,
                            } if !booted
                                && protocol == VERSION
                                && parent_pid == std::process::id()
                                && worker_pid == worker.pid
                                && generation == worker.generation
                                && nonce == expected
                                && !version.is_empty()
                                && version.len() <= 128 =>
                            {
                                booted = true;
                                *worker.version.lock().map_err(|_| {
                                    io::Error::other("worker version state poisoned")
                                })? = version.clone();
                                if let Some(sender) = worker
                                    .booted
                                    .lock()
                                    .map_err(|_| {
                                        io::Error::other("worker bootstrap state poisoned")
                                    })?
                                    .take()
                                {
                                    let _ = sender.send(Ok(version));
                                }
                                Ok(())
                            }
                            Frame::Rejected { requires_restart } if !booted => {
                                let error = io::Error::new(
                                    if requires_restart {
                                        io::ErrorKind::Unsupported
                                    } else {
                                        io::ErrorKind::InvalidData
                                    },
                                    if requires_restart {
                                        "candidate native Engine requires a resident restart"
                                    } else {
                                        "candidate native Engine preflight failed"
                                    },
                                );
                                if let Some(sender) = worker
                                    .booted
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .take()
                                {
                                    let _ = sender.send(Err(error));
                                }
                                Err(io::Error::other(
                                    "candidate native Engine preflight rejected the bundle",
                                ))
                            }
                            frame if booted => worker.receive(frame),
                            _ => Err(io::Error::other(
                                "invalid forwarding worker bootstrap acknowledgement",
                            )),
                        }
                    });
                    if let Err(error) = result {
                        worker.disconnected(&error.to_string());
                        break;
                    }
                }
            })?;
        let _deadline = worker.deadlines.start(TIMEOUT)?;
        let result = worker
            .wire
            .send(
                &Frame::Bootstrap {
                    protocol: VERSION,
                    parent_pid: std::process::id(),
                    worker_pid: pid,
                    generation,
                    nonce,
                    material: Box::new(material),
                },
                None,
            )
            .and_then(|()| {
                boot_receiver.recv_timeout(TIMEOUT).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("forwarding worker startup did not complete: {error}"),
                    )
                })?
            });
        if let Err(error) = result {
            worker.wire.shutdown();
            if let Ok(mut child) = worker.child.lock() {
                let _ = child.kill();
                let _ = child.wait();
            }
            worker.exited.store(true, Ordering::Release);
            worker.authority.clear();
            return Err(error);
        }
        let monitor = Arc::downgrade(&worker);
        std::thread::Builder::new()
            .name("hh-worker-lifecycle".into())
            .spawn(move || {
                let mut last_ping = std::time::Instant::now();
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                    let Some(worker) = monitor.upgrade() else {
                        break;
                    };
                    let status = worker
                        .child
                        .lock()
                        .map_err(|_| io::Error::other("worker child state poisoned"))
                        .and_then(|mut child| child.try_wait());
                    match status {
                        Ok(Some(status)) => {
                            worker.exited.store(true, Ordering::Release);
                            worker.disconnected(&format!("forwarding worker exited: {status}"));
                            worker.authority.clear();
                            worker
                                .offers
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .clear();
                            break;
                        }
                        Err(error) => {
                            *worker
                                .reason
                                .lock()
                                .unwrap_or_else(|error| error.into_inner()) =
                                Some(error.to_string());
                        }
                        Ok(None) => {}
                    }
                    if !worker.connected.load(Ordering::Acquire) {
                        worker.reap_closed_offers();
                    }
                    if worker.retiring.load(Ordering::Acquire)
                        && worker.authority.count() == 0
                        && (!worker.connected.load(Ordering::Acquire)
                            || (worker.drain_sent.load(Ordering::Acquire) && !worker.healthy()))
                    {
                        if let Ok(mut child) = worker.child.lock() {
                            let _ = child.kill();
                        }
                    }
                    if worker.retiring.load(Ordering::Acquire)
                        && worker.authority.count() == 0
                        && !worker.drain_sent.swap(true, Ordering::AcqRel)
                    {
                        if let Err(error) = worker.send_health(&Frame::Drain) {
                            worker.disconnected(&error.to_string());
                        }
                    }
                    if worker.connected.load(Ordering::Acquire) && !worker.healthy() {
                        worker.disconnected("forwarding worker health deadline expired");
                    }
                    if last_ping.elapsed() >= Duration::from_secs(1)
                        && worker.connected.load(Ordering::Acquire)
                    {
                        let nonce = worker.ping.fetch_add(1, Ordering::AcqRel) + 1;
                        if let Err(error) = worker.send_health(&Frame::Ping { nonce }) {
                            worker.disconnected(&error.to_string());
                        }
                        last_ping = std::time::Instant::now();
                    }
                }
            })?;
        startup.0.take();
        Ok(worker)
    }
    fn send_health(&self, frame: &Frame) -> io::Result<()> {
        let remaining = TIMEOUT.saturating_sub(
            self.last_pong
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .elapsed(),
        );
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "forwarding worker health deadline expired",
            ));
        }
        let _deadline = self.deadlines.start(remaining)?;
        self.wire.send(frame, None)
    }
    fn receive(self: &Arc<Self>, frame: Frame) -> io::Result<()> {
        match frame {
            Frame::Ready { id } => {
                let sender = self
                    .offers
                    .lock()
                    .map_err(|_| io::Error::other("worker offer state poisoned"))?
                    .get_mut(&id)
                    .and_then(|offer| offer.ready.take())
                    .ok_or_else(|| {
                        io::Error::other(
                            "unsolicited or duplicate worker readiness acknowledgement",
                        )
                    })?;
                let _ = sender.send(Ok(()));
                Ok(())
            }
            Frame::Finished { id, error } => {
                let offer = self
                    .offers
                    .lock()
                    .map_err(|_| io::Error::other("worker offer state poisoned"))?
                    .remove(&id)
                    .ok_or_else(|| io::Error::other("worker completed an unknown socket offer"))?;
                self.authority.finish(id);
                if let Some(done) = offer.done {
                    let result = error.map_or(Ok(()), |error| Err(io::Error::other(error)));
                    let _ = done.send(result);
                }
                Ok(())
            }
            Frame::Pong { nonce } => {
                let expected = self.ping.load(Ordering::Acquire);
                if nonce == 0 || nonce > expected {
                    return Err(io::Error::other("unsolicited worker heartbeat"));
                }
                if nonce == expected {
                    *self
                        .last_pong
                        .lock()
                        .map_err(|_| io::Error::other("worker heartbeat state poisoned"))? =
                        std::time::Instant::now();
                }
                Ok(())
            }
            Frame::Rpc { id, offer, request } => {
                if id == 0 {
                    return Err(io::Error::other("invalid worker RPC id"));
                }
                let result = self
                    .rpc_queue
                    .lock()
                    .map_err(|_| io::Error::other("worker RPC queue poisoned"))?
                    .as_ref()
                    .ok_or_else(|| io::Error::other("worker RPC queue is closed"))?
                    .try_send((id, offer, request));
                match result {
                    Ok(()) => Ok(()),
                    Err(mpsc::TrySendError::Full(_)) => self.wire.send(
                        &Frame::Reply {
                            id,
                            response: Response::Error {
                                message: "resident authority RPC capacity reached".into(),
                            },
                        },
                        None,
                    ),
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        Err(io::Error::other("resident authority RPC workers stopped"))
                    }
                }
            }
            Frame::Drained
                if self.drain_sent.load(Ordering::Acquire) && self.authority.count() == 0 =>
            {
                Ok(())
            }
            _ => Err(io::Error::other(
                "unexpected forwarding worker message for this lifecycle phase",
            )),
        }
    }
    fn reap_closed_offers(&self) {
        let closed = {
            let mut offers = self
                .offers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let closed: Vec<_> = offers
                .iter()
                .filter_map(|(&id, offer)| {
                    offer
                        .cancellation_socket
                        .as_ref()
                        .is_some_and(super::super::cancellation::locally_closed)
                        .then_some(id)
                })
                .collect();
            closed
                .into_iter()
                .filter_map(|id| offers.remove(&id).map(|offer| (id, offer)))
                .collect::<Vec<_>>()
        };
        for (id, offer) in closed {
            self.authority.finish(id);
            if let Some(done) = offer.done {
                let _ = done.send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "forwarding connection closed after its control channel was lost",
                )));
            }
        }
    }
    pub(super) fn disconnected(&self, reason: &str) {
        self.connected.store(false, Ordering::Release);
        self.rpc_queue
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        *self
            .reason
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(reason.chars().take(256).collect());
        if let Some(sender) = self
            .booted
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _ = sender.send(Err(io::Error::other(reason.to_owned())));
        }
        let abandoned = self
            .offers
            .lock()
            .map(|mut offers| disconnect_offers(&mut offers, reason))
            .unwrap_or_default();
        for id in abandoned {
            self.authority.finish(id);
        }
        self.wire.shutdown();
    }
    pub(super) fn healthy(&self) -> bool {
        self.connected.load(Ordering::Acquire)
            && !self.wire.is_closed()
            && !self.exited.load(Ordering::Acquire)
            && self
                .last_pong
                .lock()
                .is_ok_and(|last| last.elapsed() <= TIMEOUT)
    }
    pub(super) fn status(&self) -> WorkerStatus {
        WorkerStatus {
            generation: self.generation,
            pid: self.pid,
            start_time: self.start_time,
            version: self
                .version
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
            sha256: self.executable.sha256.clone(),
            phase: if self.exited.load(Ordering::Acquire) {
                "exited"
            } else if self.retiring.load(Ordering::Acquire) {
                "draining"
            } else {
                "ready"
            }
            .into(),
            live_connections: self.authority.count(),
            healthy: self.healthy(),
            reason: self
                .reason
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
        }
    }
    pub(super) fn offer(
        &self,
        id: u64,
        offer: Frame,
        stream: std::net::TcpStream,
        ready: mpsc::Receiver<io::Result<()>>,
    ) -> io::Result<()> {
        let _deadline = match self.deadlines.start(TIMEOUT) {
            Ok(deadline) => deadline,
            Err(error) => {
                self.offers
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&id);
                self.authority.finish(id);
                return Err(error);
            }
        };
        if let Err(error) = self.wire.send(&offer, Some(&stream)) {
            self.offers
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&id);
            self.authority.finish(id);
            return Err(error);
        }
        let cancelled = {
            let mut offers = self
                .offers
                .lock()
                .map_err(|_| io::Error::other("worker offer state poisoned"))?;
            let offer = offers
                .get_mut(&id)
                .ok_or_else(|| io::Error::other("worker socket offer disappeared"))?;
            offer.sent = true;
            offer.cancelled
        };
        if cancelled {
            let _ = self.wire.send(&Frame::Cancel { id }, None);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "session was revoked before worker readiness",
            ));
        }
        let result = (|| {
            ready.recv_timeout(TIMEOUT).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("worker socket readiness unavailable: {error}"),
                )
            })??;
            self.authority.grant(id)?;
            let mut offers = self
                .offers
                .lock()
                .map_err(|_| io::Error::other("worker offer state poisoned"))?;
            let offer = offers
                .get_mut(&id)
                .ok_or_else(|| io::Error::other("worker socket offer disappeared"))?;
            if offer.cancelled {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "session was revoked before worker ownership grant",
                ));
            }
            offer.cancellation_socket = Some(stream);
            offer.granted = true;
            // Serialize the small grant decision against cancellation. From
            // here, delivery uncertainty must never retry the business stream.
            self.wire.send(&Frame::Grant { id }, None)
        })();
        if result.is_err() {
            // A failed/uncertain grant is never retried. Close only this offer,
            // including when its child never received Grant and cannot send a
            // Finished acknowledgement after losing the private channel.
            if let Some(socket) = self
                .offers
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get(&id)
                .and_then(|offer| offer.cancellation_socket.as_ref())
            {
                let _ = super::super::cancellation::mark_closed(socket);
            }
            let _ = self.wire.send(&Frame::Cancel { id }, None);
        }
        result
    }
    pub(super) fn cancel(self: &Arc<Self>, id: u64) {
        let should_send = {
            let mut offers = self
                .offers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(offer) = offers.get_mut(&id) {
                offer.cancelled = true;
                if let Some(socket) = &offer.cancellation_socket {
                    let _ = super::super::cancellation::mark_closed(socket);
                }
                offer.sent
            } else {
                false
            }
        };
        if should_send {
            let worker = self.clone();
            let _ = std::thread::Builder::new()
                .name("hh-worker-cancel".into())
                .spawn(move || {
                    let _ = worker.wire.send(&Frame::Cancel { id }, None);
                });
        }
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(state) = self.state.lock() {
            for worker in state.workers.values() {
                worker.retiring.store(true, Ordering::Release);
            }
        }
    }
}
