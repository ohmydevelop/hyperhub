use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::HH_ERR_INVALID;

#[derive(Clone, Debug)]
pub(crate) enum TargetAddress {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Clone, Debug)]
pub(crate) struct SocketState {
    pub(crate) connection_id: u64,
    pub(crate) target: TargetAddress,
    pub(crate) port: u16,
    pub(crate) last_io_result: i64,
    pub(crate) ready_mask: u32,
    pub(crate) nonblocking: bool,
    pub(crate) handshake_complete: bool,
}

pub(crate) struct GatewayState {
    pub(crate) proxy: Option<SocketAddr>,
    pub(crate) next_connection_id: u64,
    pub(crate) dns: HashMap<(i32, Vec<u8>), String>,
    pub(crate) sockets: HashMap<u64, SocketState>,
    pub(crate) nonblocking_sockets: HashSet<u64>,
}

impl Default for GatewayState {
    fn default() -> Self {
        Self {
            proxy: None,
            next_connection_id: 1,
            dns: HashMap::new(),
            sockets: HashMap::new(),
            nonblocking_sockets: HashSet::new(),
        }
    }
}

pub(crate) fn parse_ip(address: &[u8]) -> Result<IpAddr, i32> {
    match address.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        ))),
        16 => {
            let bytes: [u8; 16] = address.try_into().map_err(|_| HH_ERR_INVALID)?;
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => Err(HH_ERR_INVALID),
    }
}
