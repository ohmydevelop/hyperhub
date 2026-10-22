//! Byte encodings for the resident Engine. Native structures never cross
//! the module boundary. Host state is supplied by value; mutations stay in Host.
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

pub const STATE_SCHEMA: u32 = 2;
pub const NETWORK_OPERATIONS: u64 = 0xf;
pub const REQUIRED_OPERATIONS: u64 = 0x1fff;
pub const FILE_POLICY: u32 = 5;
pub const PROCESS_POLICY: u32 = 6;
pub const FIREWALL_POLICY: u32 = 7;
pub const TRUST_BUNDLE: u32 = 8;
pub const CHILD_PLAN: u32 = 9;
pub const SANITIZE_ACTION: u32 = 10;
/// Child-only cache reset, executed before any inherited processing resumes.
pub const FORK_RESET: u32 = 11;
/// Empty request returns one little-endian u64 module ownership epoch.
pub const MODULE_RETAIN: u32 = 12;
/// Release one logical owner using the exact eight epoch bytes from retain.
pub const MODULE_RELEASE: u32 = 13;
pub const MAX_POLICY_REQUEST: usize = 2 * 1024 * 1024;
pub const MAX_TRUST_REQUEST: usize = 33 * 1024 * 1024;
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

/// Policy snapshots are immutable JSON values. Their wire structure is independent
/// of the Host's Rust structs and compiled regular expressions.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInput {
    pub snapshot: serde_json::Value,
    pub target: String,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub command_line: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub action: String,
    pub rule_id: Option<String>,
    pub source: String,
    pub protection: Option<String>,
    pub protection_rule_id: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallInput {
    pub snapshot: serde_json::Value,
    pub hostname: Option<String>,
    pub ip: IpAddr,
    pub port: u16,
    pub bypass: bool,
    #[serde(default)]
    pub dns: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildInput {
    pub hook: bool,
    pub caller_suspended: bool,
    pub creation_flags: u32,
    pub suspended_flag: u32,
    pub unicode_environment_flag: u32,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildPlan {
    pub inject: bool,
    pub creation_flags: u32,
    pub resume_after_ready: bool,
}
