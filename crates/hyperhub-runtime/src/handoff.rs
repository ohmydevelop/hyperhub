//! Accepted TCP socket transfer between a stable ingress and versioned workers.
//!
//! This is the transport primitive, not a worker coordinator. The authenticated
//! control channel must establish peer identity and transaction ownership. A
//! receiver must acknowledge readiness and wait for an explicit ownership grant
//! before it reads/writes the socket. Keep the sender's original socket until
//! that handshake finishes. Never retry delivery after an ownership grant.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{receive, send};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{duplicate, import, SocketOffer};
