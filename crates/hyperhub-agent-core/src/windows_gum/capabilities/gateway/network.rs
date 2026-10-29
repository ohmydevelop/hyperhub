use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKET};

use crate::{
    hh_agent_prepare_connect, hh_agent_record_dns, hh_agent_resolve_name, FirewallConnectTarget,
    HhConnectPlan, HH_OK,
};

pub(super) fn proxy_target(
    socket: SOCKET,
    source_family: Option<i32>,
    original: Option<&FirewallConnectTarget>,
) -> Result<Option<(i32, FirewallConnectTarget, Option<(u32, u32)>)>, i32> {
    let (Some(original), Some(family)) = (original, source_family) else {
        return Ok(None);
    };
    let address = match original.ip {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    let mut plan = HhConnectPlan::default();
    let status = unsafe {
        hh_agent_prepare_connect(
            socket as u64,
            family,
            address.as_ptr(),
            address.len(),
            original.port,
            &mut plan,
        )
    };
    if status == crate::HH_BYPASS {
        return Ok(None);
    }
    if status != HH_OK {
        return Err(status);
    }
    if plan.should_intercept == 0 {
        return Ok(None);
    }
    let (family, ip) = if plan.proxy_family == AF_INET as i32 {
        (
            AF_INET as i32,
            IpAddr::V4(std::net::Ipv4Addr::new(
                plan.proxy_address[0],
                plan.proxy_address[1],
                plan.proxy_address[2],
                plan.proxy_address[3],
            )),
        )
    } else {
        (
            AF_INET6 as i32,
            IpAddr::V6(std::net::Ipv6Addr::from(plan.proxy_address)),
        )
    };
    Ok(Some((
        family,
        FirewallConnectTarget {
            hostname: None,
            ip,
            port: plan.proxy_port,
            bypass: true,
        },
        (plan.reserved & crate::HH_CONNECT_NATIVE_COMPAT != 0)
            .then_some((plan.connection_id as u32, (plan.connection_id >> 32) as u32)),
    )))
}

pub(super) fn resolve_fake_hostname(
    hostname: &CStr,
    family: i32,
) -> Result<Option<(String, i32)>, i32> {
    let requested = if family == AF_INET6 as i32 { 6 } else { 4 };
    let mut output_family = 0;
    let mut output = [0_u8; 16];
    let mut written = 0;
    let status = unsafe {
        hh_agent_resolve_name(
            hostname.as_ptr(),
            requested,
            &mut output_family,
            output.as_mut_ptr(),
            output.len(),
            &mut written,
        )
    };
    decode_resolved_hostname(status, output_family, output, written)
}

fn decode_resolved_hostname(
    status: i32,
    output_family: u32,
    output: [u8; 16],
    written: usize,
) -> Result<Option<(String, i32)>, i32> {
    if status == crate::HH_BYPASS {
        return Ok(None);
    }
    if status != HH_OK {
        return Err(status);
    }
    let resolved = match (output_family, written) {
        (4, 4) => Some((
            Ipv4Addr::new(output[0], output[1], output[2], output[3]).to_string(),
            AF_INET as i32,
        )),
        (6, 16) => Some((Ipv6Addr::from(output).to_string(), AF_INET6 as i32)),
        _ => None,
    };
    resolved.map(Some).ok_or(crate::HH_ERR_PROTOCOL)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_bypass_permits_the_original_native_query() {
        assert_eq!(
            decode_resolved_hostname(crate::HH_BYPASS, 0, [0; 16], 0),
            Ok(None)
        );
        for status in [
            crate::HH_ERR_PROTOCOL,
            crate::HH_ERR_NATIVE_ALIAS_UNAVAILABLE,
            crate::HH_ERR_INVALID,
        ] {
            assert_eq!(decode_resolved_hostname(status, 0, [0; 16], 0), Err(status));
        }
        assert_eq!(
            decode_resolved_hostname(HH_OK, 4, [0; 16], 16),
            Err(crate::HH_ERR_PROTOCOL)
        );
        let mut output = [0; 16];
        output[..4].copy_from_slice(&[198, 18, 0, 1]);
        assert_eq!(
            decode_resolved_hostname(HH_OK, 4, output, 4),
            Ok(Some(("198.18.0.1".into(), AF_INET as i32)))
        );
    }
}
