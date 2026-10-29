//! Address identity is separate from the native socket representation.
use super::NativeAddress;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Immutable mode for native resolver adapters. Explicit SDK synthesis has its
/// own address-pool contract and is not enabled by preserving native answers.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeDnsMode {
    #[default]
    PreserveAnswers,
    SyntheticPool,
}

/// Canonicalize only IPv4-mapped IPv6 for origin and collision checks. Do not
/// apply this identity conversion to a sockaddr or a native resolver answer.
pub fn canonical_alias_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

pub fn is_synthetic_alias_address(address: IpAddr) -> bool {
    match canonical_alias_address(address) {
        IpAddr::V4(address) => {
            let bytes = address.octets();
            bytes[0] == 198 && matches!(bytes[1], 18 | 19)
        }
        IpAddr::V6(address) => {
            address.segments()[..6] == [0xfdfe, 0x6879, 0x7065, 0x7268, 0x7562, 0]
        }
    }
}

/// Keep the application's address family. A mapped alias supplied to an IPv6
/// socket must use a mapped IPv6 fallback, rather than sockaddr_in on that
/// socket. Other cross-family substitutions have no proved native meaning.
pub fn native_address_for_alias(alias: IpAddr, native: &NativeAddress) -> Option<NativeAddress> {
    if native.ip.is_ipv4() && (native.scope_id != 0 || native.flowinfo != 0) {
        return None;
    }
    match (alias, native.ip) {
        (IpAddr::V6(alias), IpAddr::V4(address)) if alias.to_ipv4_mapped().is_some() => {
            Some(NativeAddress {
                ip: IpAddr::V6(address.to_ipv6_mapped()),
                scope_id: 0,
                flowinfo: 0,
            })
        }
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => Some(native.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(address: &str) -> IpAddr {
        address.parse().unwrap()
    }

    #[test]
    fn only_mapped_ipv6_changes_alias_identity() {
        assert_eq!(
            canonical_alias_address(ip("::ffff:198.18.0.7")),
            ip("198.18.0.7")
        );
        for address in ["::198.18.0.7", "64:ff9b::c612:7", "2001:db8::c612:7"] {
            assert_eq!(canonical_alias_address(ip(address)), ip(address));
            assert!(!is_synthetic_alias_address(ip(address)));
        }
        for address in [
            "198.18.0.7",
            "::ffff:198.18.0.7",
            "::ffff:198.19.255.255",
            "fdfe:6879:7065:7268:7562::7",
        ] {
            assert!(is_synthetic_alias_address(ip(address)));
        }
    }

    #[test]
    fn mapped_alias_adapts_fallback_without_changing_socket_family() {
        let native = NativeAddress {
            ip: ip("127.0.0.1"),
            scope_id: 0,
            flowinfo: 0,
        };
        let mapped = native_address_for_alias(ip("::ffff:198.18.0.7"), &native).unwrap();
        assert_eq!(mapped.ip, ip("::ffff:127.0.0.1"));
        assert!(mapped.ip.is_ipv6());
        assert_eq!((mapped.scope_id, mapped.flowinfo), (0, 0));
        assert_eq!(
            native_address_for_alias(ip("198.18.0.7"), &native),
            Some(native.clone())
        );
        assert!(native_address_for_alias(ip("fdfe:6879:7065:7268:7562::7"), &native).is_none());
        let scoped = NativeAddress {
            ip: ip("fe80::7"),
            scope_id: 12,
            flowinfo: 99,
        };
        assert_eq!(
            native_address_for_alias(ip("fdfe:6879:7065:7268:7562::7"), &scoped),
            Some(scoped.clone())
        );
        assert!(native_address_for_alias(ip("198.18.0.7"), &scoped).is_none());
        let invalid = NativeAddress {
            scope_id: 1,
            ..native.clone()
        };
        assert!(native_address_for_alias(ip("::ffff:198.18.0.7"), &invalid).is_none());
        assert_eq!(native.ip, ip("127.0.0.1"));
    }

    #[test]
    fn native_mode_defaults_to_preserving_answers() {
        assert_eq!(NativeDnsMode::default(), NativeDnsMode::PreserveAnswers);
        assert_eq!(
            serde_json::to_string(&NativeDnsMode::PreserveAnswers).unwrap(),
            "\"preserve_answers\""
        );
        assert_eq!(
            serde_json::from_str::<NativeDnsMode>("\"synthetic_pool\"").unwrap(),
            NativeDnsMode::SyntheticPool
        );
    }
}
