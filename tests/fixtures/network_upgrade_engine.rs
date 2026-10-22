//! Native upgrade fixture for the network Host suite. Controlled ASCII JSON
//! requests only; this independent decoder is not a production JSON parser.
//! New semantics: advertise two SOCKS methods, prefix CONNECT domains and
//! require a zero reserved reply byte. The server can select method 2 in both.
#![allow(dead_code)]
#[path = "../../crates/hyperhub-runtime/src/abi.rs"]
mod abi;
use std::net::{IpAddr, SocketAddr};

fn text<'a>(input: &'a str, key: &str) -> Option<&'a str> {
    let value = input.split_once(&format!("\"{key}\":"))?.1.strip_prefix('"')?;
    let end = value.find('"')?;
    let value = &value[..end];
    (!value.contains('\\')).then_some(value)
}
fn number(input: &str, key: &str) -> Option<u16> {
    let value = input.split_once(&format!("\"{key}\":"))?.1;
    value[..value.find(|c: char| !c.is_ascii_digit()).unwrap_or(value.len())].parse().ok()
}
fn array(input: &str, key: &str) -> Option<Vec<u8>> {
    let value = input.split_once(&format!("\"{key}\":["))?.1.split(']').next()?;
    if value.is_empty() { return Some(Vec::new()); }
    value.split(',').map(|x| x.trim().parse().ok()).collect()
}
fn run(operation: u32, input: &str) -> Option<Vec<u8>> {
    match operation {
        1 => {
            let name = input.strip_prefix('"')?.strip_suffix('"')?;
            if name.contains('\\') { return None; }
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            (!name.is_empty()).then(|| format!("\"normalized.{name}\"").into_bytes())
        }
        2 => {
            let proxy: SocketAddr = text(input, "proxy")?.parse().ok()?;
            let ip: IpAddr = text(input, "ip")?.parse().ok()?;
            let port = number(input, "port")?;
            let mut address = [0u8; 16];
            let family = match proxy.ip() {
                IpAddr::V4(ip) => { address[..4].copy_from_slice(&ip.octets()); 2 }
                IpAddr::V6(ip) => { address = ip.octets(); 10 }
            };
            let target = if let Some(name) = text(input, "hostname") {
                format!("{{\"Domain\":\"{name}\"}}")
            } else { format!("{{\"Ip\":\"{ip}\"}}") };
            let intercept = SocketAddr::new(ip, port) != proxy;
            Some(format!("{{\"intercept\":{intercept},\"family\":{family},\"address\":{address:?},\"port\":{},\"target\":{target}}}", proxy.port()).into_bytes())
        }
        3 => match number(input, "phase")? {
            0 => Some(vec![5, 2, 0, 2]),
            1 => {
                let username = text(input, "username")?.as_bytes();
                let password = array(input, "password")?;
                if username.len() > 255 || password.len() > 255 { return None; }
                let mut output = vec![1, username.len() as u8];
                output.extend_from_slice(username);
                output.push(password.len() as u8);
                output.extend_from_slice(&password);
                Some(output)
            }
            2 => {
                let mut output = vec![5, 1, 0];
                if let Some(name) = text(input, "Domain") {
                    let name = format!("upgraded.{name}");
                    if name.len() > 255 { return None; }
                    output.extend_from_slice(&[3, name.len() as u8]);
                    output.extend_from_slice(name.as_bytes());
                } else {
                    match text(input, "Ip")?.parse().ok()? {
                        IpAddr::V4(ip) => { output.push(1); output.extend_from_slice(&ip.octets()); }
                        IpAddr::V6(ip) => { output.push(4); output.extend_from_slice(&ip.octets()); }
                    }
                }
                output.extend_from_slice(&number(input, "port")?.to_be_bytes());
                Some(output)
            }
            _ => None,
        },
        4 => {
            let bytes = array(input, "bytes")?;
            let valid = match number(input, "phase")? {
                0 => bytes == [5, 2],
                1 => bytes == [1, 0],
                2 => bytes.len() >= 4 && bytes[0] == 5 && bytes[1] == 0 && bytes[2] == 0,
                _ => false,
            };
            valid.then(Vec::new)
        }
        _ => None,
    }
}
const fn version_hash() -> [u8; 32] {
    let bytes = env!("HH_FIXTURE_VERSION_HASH").as_bytes();
    const fn digit(b: u8) -> u8 { if b <= b'9' { b - b'0' } else { b - b'a' + 10 } }
    let mut hash = [0; 32]; let mut i = 0;
    while i < 32 { hash[i] = digit(bytes[i * 2]) * 16 + digit(bytes[i * 2 + 1]); i += 1; }
    hash
}
unsafe extern "C" fn health() -> i32 { abi::OK }
unsafe extern "C" fn invoke(
    _: *const abi::HostServices, operation: u32, input: *const u8, length: usize,
    output: *mut u8, capacity: usize, written: *mut usize,
) -> i32 {
    unsafe { written.write(0); }
    let input = unsafe { std::slice::from_raw_parts(input, length) };
    let result = std::str::from_utf8(input).ok().and_then(|input| run(operation, input));
    let Some(bytes) = result else { return -102; };
    if bytes.len() > capacity { return -103; }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()); written.write(bytes.len()); }
    abi::OK
}
static TABLE: abi::EngineApi = abi::EngineApi {
    struct_size: std::mem::size_of::<abi::EngineApi>() as u32,
    abi: abi::ABI_V1, state_schema: 1, reserved: 0, hooks: 0xf,
    version_hash: version_hash(), invoke: Some(invoke), health: Some(health),
};
#[no_mangle]
pub extern "C" fn hh_engine_v1() -> *const abi::EngineApi { &TABLE }
