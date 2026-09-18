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
) -> Option<(i32, FirewallConnectTarget)> {
    let original = original?;
    let family = source_family?;
    let address = match original.ip {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    let mut plan = HhConnectPlan::default();
    if unsafe {
        hh_agent_prepare_connect(
            socket as u64,
            family,
            address.as_ptr(),
            address.len(),
            original.port,
            &mut plan,
        )
    } != HH_OK
        || plan.should_intercept == 0
    {
        return None;
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
    Some((
        family,
        FirewallConnectTarget {
            hostname: None,
            ip,
            port: plan.proxy_port,
            bypass: true,
        },
    ))
}

pub(super) fn resolve_fake_hostname(hostname: &CStr, family: i32) -> Option<(String, i32)> {
    let requested = if family == AF_INET6 as i32 { 6 } else { 4 };
    let mut output_family = 0;
    let mut output = [0_u8; 16];
    let mut written = 0;
    if unsafe {
        hh_agent_resolve_name(
            hostname.as_ptr(),
            requested,
            &mut output_family,
            output.as_mut_ptr(),
            output.len(),
            &mut written,
        )
    } != HH_OK
    {
        return None;
    }
    let resolved = match (output_family, written) {
        (4, 4) => Some((
            Ipv4Addr::new(output[0], output[1], output[2], output[3]).to_string(),
            AF_INET as i32,
        )),
        (6, 16) => Some((Ipv6Addr::from(output).to_string(), AF_INET6 as i32)),
        _ => None,
    };
    if let Some((_, family)) = &resolved {
        let _ =
            unsafe { hh_agent_record_dns(hostname.as_ptr(), *family, output.as_ptr(), written) };
    }
    resolved
}
