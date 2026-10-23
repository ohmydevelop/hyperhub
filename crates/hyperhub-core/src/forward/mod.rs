//! Private services shared by resident ingress and versioned forwarding workers.
pub(crate) mod authority;
mod cancellation;
pub(crate) mod wire;

pub(crate) mod manager;
pub(crate) mod protocol;
mod rpc;
pub(crate) mod worker;

pub(crate) mod cleanup;
mod deadline;
