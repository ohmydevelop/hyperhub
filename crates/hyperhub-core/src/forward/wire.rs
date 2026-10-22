//! Bounded private inherited IPC for forwarding workers.
//!
//! This transports bytes and socket offers. The protocol above it must validate
//! bootstrap identity and must not use an offered socket until an ownership grant.
use serde::{de::DeserializeOwned, Serialize};
use std::io;
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
#[path = "wire/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "wire/windows.rs"]
mod platform;

pub const MAX_FRAME: usize = 2 * 1024 * 1024;

/// Clones share one serialized sender and one serialized receiver. Sending does
/// not hold the receive lock, so RPC replies can flow while a reader waits.
#[derive(Clone)]
pub struct Wire {
    inner: Arc<Inner>,
}
struct Inner {
    sender: Mutex<platform::Sender>,
    receiver: Mutex<platform::Receiver>,
    control: platform::Control,
}
impl Wire {
    fn new(
        sender: platform::Sender,
        receiver: platform::Receiver,
        control: platform::Control,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                sender: Mutex::new(sender),
                receiver: Mutex::new(receiver),
                control,
            }),
        }
    }
    pub fn send<T: Serialize>(&self, frame: &T, socket: Option<&TcpStream>) -> io::Result<()> {
        let mut encoded = BoundedPayload(Vec::new());
        serde_json::to_writer(&mut encoded, frame).map_err(invalid)?;
        let payload = Zeroizing::new(std::mem::take(&mut encoded.0));
        if payload.is_empty() || payload.len() > MAX_FRAME {
            return Err(invalid("worker frame exceeds the size limit"));
        }
        let mut sender = self
            .inner
            .sender
            .lock()
            .map_err(|_| invalid("worker sender lock poisoned"))?;
        self.inner.control.check()?;
        let result = sender.send(&payload, socket);
        drop(sender);
        if result.is_err() {
            self.shutdown();
        }
        result
    }
    pub fn receive<T: DeserializeOwned>(&self) -> io::Result<(T, Option<TcpStream>)> {
        let mut receiver = self
            .inner
            .receiver
            .lock()
            .map_err(|_| invalid("worker receiver lock poisoned"))?;
        self.inner.control.check()?;
        let result = receiver.receive().and_then(|(mut payload, socket)| {
            let frame = serde_json::from_slice(&payload)
                .map_err(|_| invalid("invalid worker message JSON or schema"));
            payload.zeroize();
            Ok((frame?, socket))
        });
        drop(receiver);
        if result.is_err() {
            self.shutdown();
        }
        result
    }
    /// Stop all clones and wake outstanding reads/writes. No socket ownership
    /// grant is inferred by this operation.
    pub fn shutdown(&self) {
        self.inner.control.shutdown();
        // Cancel active IO before taking these locks. Closing parent pipe ends
        // then also wakes the peer on Windows, even while the parent stays alive.
        self.inner
            .sender
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .close();
        self.inner
            .receiver
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .close();
    }
    pub fn is_closed(&self) -> bool {
        self.inner.control.check().is_err()
    }
}

/// Spawn with a private inherited channel. Set command arguments, environment
/// and stderr before calling. Unix stdout is null; Windows stdout is protocol.
pub fn spawn(command: &mut Command) -> io::Result<(Wire, Child)> {
    platform::spawn(command)
}

/// Attach the worker side to inherited stdio. Never print to stdout on Windows.
/// The original standard handles remain owned by the process. The worker entry
/// point must exit after stopping its channel; dropping this duplicate alone
/// does not signal process termination to its parent.
pub fn from_stdio() -> io::Result<Wire> {
    platform::from_stdio()
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

struct BoundedPayload(Vec<u8>);
impl Drop for BoundedPayload {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl io::Write for BoundedPayload {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_FRAME.saturating_sub(self.0.len()) {
            return Err(invalid("worker frame exceeds the size limit"));
        }
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let capacity = needed
                .max(self.0.capacity().saturating_mul(2))
                .min(MAX_FRAME);
            self.0.reserve_exact(capacity - self.0.len());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "wire/tests.rs"]
mod tests;
