//! Resident-host upgrade primitives. This crate does not install hooks or restart processes.
//!
//! Only `abi` types cross a native module boundary. The Host owns process state;
//! callers retain a `Lease` through syscall exits, callbacks and cancellation.
pub mod abi;
pub mod artifact;
pub mod generation;
pub mod native;

pub use generation::{Engine, Error, Lease, Runtime, Settings, Snapshot, Stage};

use serde::{Deserialize, Serialize};

/// Supplied by the trusted release manifest, not by an unverified module.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: String,
    pub target: String,
    pub abi: u32,
    pub state_schema: u32,
    pub hooks: u64,
    pub sha256: String,
    pub size: u64,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version.is_empty()
            || self.version.len() > 128
            || !self
                .version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".+-_".contains(&c))
            || self.target.is_empty()
            || self.target.len() > 128
            || !self
                .target
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || self.size == 0
        {
            return Err(Error::InvalidManifest);
        }
        Ok(())
    }

    pub fn compatible_with(&self, host: &Manifest) -> bool {
        self.target == host.target
            && self.abi == host.abi
            && self.state_schema == host.state_schema
            // V1 cannot add OR remove resident native bridges.
            && self.hooks == host.hooks
    }
}
