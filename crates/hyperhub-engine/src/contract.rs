//! JSON byte encodings for the network Engine V1. Native structures never cross
//! the module boundary. Host state is supplied by value; mutations stay in Host.
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

pub const STATE_SCHEMA: u32 = 1;
pub const NETWORK_OPERATIONS: u64 = 0xf;
pub const NORMALIZE_DNS: u32 = 1;
pub const PLAN_CONNECT: u32 = 2;
pub const BUILD_HANDSHAKE: u32 = 3;
pub const VALIDATE_REPLY: u32 = 4;
pub const INVALID: i32 = -101;
pub const PROTOCOL: i32 = -102;
pub const CAPACITY: i32 = -103;
pub const MAX_REQUEST: usize = 16 * 1024;
pub const MAX_RESPONSE: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TargetAddress {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectInput {
    pub proxy: SocketAddr,
    pub ip: IpAddr,
    pub port: u16,
    pub hostname: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectOutput {
    pub intercept: bool,
    pub family: i32,
    pub address: [u8; 16],
    pub port: u16,
    pub target: TargetAddress,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeInput {
    pub phase: u32,
    pub username: String,
    pub password: Vec<u8>,
    pub target: TargetAddress,
    pub port: u16,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyInput {
    pub phase: u32,
    pub bytes: Vec<u8>,
    /// ptrace consumes the four-byte CONNECT header before reading its address.
    pub header_only: bool,
}
