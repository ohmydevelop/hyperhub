use crate::contract::*;
use std::net::IpAddr;

pub(crate) fn execute(operation: u32, input: &[u8]) -> Result<Vec<u8>, i32> {
    if input.len() > MAX_REQUEST {
        return Err(INVALID);
    }
    match operation {
        NORMALIZE_DNS => {
            let name: String = serde_json::from_slice(input).map_err(|_| INVALID)?;
            let normalized = name.trim_end_matches('.').to_ascii_lowercase();
            if normalized.is_empty() {
                return Err(INVALID);
            }
            serde_json::to_vec(&normalized).map_err(|_| INVALID)
        }
        PLAN_CONNECT => {
            let input: ConnectInput = serde_json::from_slice(input).map_err(|_| INVALID)?;
            let mut address = [0; 16];
            let family = match input.proxy.ip() {
                IpAddr::V4(ip) => {
                    address[..4].copy_from_slice(&ip.octets());
                    2
                }
                IpAddr::V6(ip) => {
                    address.copy_from_slice(&ip.octets());
                    10
                }
            };
            let output = ConnectOutput {
                intercept: std::net::SocketAddr::new(input.ip, input.port) != input.proxy,
                family,
                address,
                port: input.proxy.port(),
                target: input
                    .hostname
                    .map(TargetAddress::Domain)
                    .unwrap_or(TargetAddress::Ip(input.ip)),
            };
            serde_json::to_vec(&output).map_err(|_| INVALID)
        }
        BUILD_HANDSHAKE => {
            let input: HandshakeInput = serde_json::from_slice(input).map_err(|_| INVALID)?;
            match input.phase {
                0 => Ok(vec![5, 1, 2]),
                1 => {
                    if input.username.len() > 255 || input.password.len() > 255 {
                        return Err(PROTOCOL);
                    }
                    let mut output =
                        Vec::with_capacity(input.username.len() + input.password.len() + 3);
                    output.extend_from_slice(&[1, input.username.len() as u8]);
                    output.extend_from_slice(input.username.as_bytes());
                    output.push(input.password.len() as u8);
                    output.extend_from_slice(&input.password);
                    Ok(output)
                }
                2 => {
                    let mut output = vec![5, 1, 0];
                    match input.target {
                        TargetAddress::Domain(name) => {
                            if name.len() > 255 {
                                return Err(PROTOCOL);
                            }
                            output.extend_from_slice(&[3, name.len() as u8]);
                            output.extend_from_slice(name.as_bytes());
                        }
                        TargetAddress::Ip(IpAddr::V4(ip)) => {
                            output.push(1);
                            output.extend_from_slice(&ip.octets());
                        }
                        TargetAddress::Ip(IpAddr::V6(ip)) => {
                            output.push(4);
                            output.extend_from_slice(&ip.octets());
                        }
                    }
                    output.extend_from_slice(&input.port.to_be_bytes());
                    Ok(output)
                }
                _ => Err(INVALID),
            }
        }
        VALIDATE_REPLY => {
            let input: ReplyInput = serde_json::from_slice(input).map_err(|_| INVALID)?;
            let bytes = &input.bytes;
            let valid = match input.phase {
                0 => bytes.as_slice() == [5, 2],
                1 => bytes.as_slice() == [1, 0],
                2 => {
                    bytes.len() >= if input.header_only { 4 } else { 5 }
                        && bytes[0] == 5
                        && bytes[1] == 0
                }
                _ => return Err(INVALID),
            };
            if valid {
                Ok(Vec::new())
            } else {
                Err(PROTOCOL)
            }
        }
        _ => Err(hyperhub_runtime::abi::UNSUPPORTED),
    }
}
