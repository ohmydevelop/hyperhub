use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::HH_ERR_INVALID;

pub(crate) use hyperhub_engine::TargetAddress;

#[derive(Clone, Debug)]
pub(crate) struct SocketState {
    pub(crate) engine: hyperhub_runtime::Lease,
    pub(crate) connection_id: u64,
    pub(crate) target: TargetAddress,
    pub(crate) port: u16,
    pub(crate) last_io_result: i64,
    pub(crate) ready_mask: u32,
    pub(crate) nonblocking: bool,
    pub(crate) handshake_complete: bool,
}

/// An address returned by the target's own native resolver. IPv6 fields are
/// kept as raw native scalars so detached compatibility does not lose scope.
pub(crate) use hyperhub_runtime::attachment::NativeAddress as NativeDnsAddress;
#[derive(Clone, Debug)]
pub(crate) struct IssuedAlias {
    pub(crate) hostname: String,
    pub(crate) native_fallback: hyperhub_runtime::attachment::NativeFallback,
}

#[derive(Clone)]
pub(crate) struct GatewayState {
    pub(crate) root_image: Option<hyperhub_runtime::attachment::RootImageState>,
    pub(crate) root_image_signer: Option<[u8; 32]>,
    pub(crate) self_image: Option<hyperhub_runtime::attachment::RootImageIdentity>,
    pub(crate) root_image_challenged: bool,
    pub(crate) namespace: crate::alias_namespace::Namespace,
    pub(crate) proxy: Option<SocketAddr>,
    pub(crate) next_connection_id: u64,
    pub(crate) dns: HashMap<IpAddr, String>,
    pub(crate) issued_aliases: HashMap<IpAddr, IssuedAlias>,
    pub(crate) ambiguous_aliases: HashSet<IpAddr>,
    pub(crate) sockets: HashMap<u64, SocketState>,
    pub(crate) nonblocking_sockets: HashSet<u64>,
}

impl Default for GatewayState {
    fn default() -> Self {
        Self {
            root_image: None,
            root_image_signer: None,
            self_image: None,
            root_image_challenged: false,
            namespace: crate::alias_namespace::Namespace::default(),
            proxy: None,
            next_connection_id: 0,
            dns: HashMap::new(),
            issued_aliases: HashMap::new(),
            ambiguous_aliases: HashSet::new(),
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

impl GatewayState {
    fn reject_ambiguous(&mut self, ip: IpAddr) -> Result<(), i32> {
        let ip = hyperhub_runtime::attachment::canonical_alias_address(ip);
        self.ambiguous_aliases.insert(ip);
        crate::native_alias_snapshot::publish_conflict(ip)?;
        Err(crate::HH_ERR_ALIAS_CONFLICT)
    }
    pub(crate) fn observe_dns(
        &mut self,
        ip: IpAddr,
        hostname: String,
        retain: bool,
    ) -> Result<(), i32> {
        let ip = hyperhub_runtime::attachment::canonical_alias_address(ip);
        if self.issued_aliases.contains_key(&ip) {
            // A native lookup is not evidence for the original issuance, even
            // when its name matches. Refuse publication without changing the
            // identity of aliases already returned to the application.
            return Err(crate::HH_ERR_ALIAS_CONFLICT);
        }
        if retain {
            self.dns.insert(ip, hostname);
        }
        Ok(())
    }
    pub(crate) fn issue_alias(
        &mut self,
        ip: IpAddr,
        hostname: String,
        native_addresses: Vec<NativeDnsAddress>,
    ) -> Result<(), i32> {
        self.issue_native_alias(
            ip,
            hostname,
            hyperhub_runtime::attachment::NativeFallback {
                family: if ip.is_ipv4() { 4 } else { 6 },
                addresses: native_addresses,
                failure: None,
                unavailable: None,
            },
        )
    }
    pub(crate) fn issue_native_alias(
        &mut self,
        ip: IpAddr,
        hostname: String,
        native_fallback: hyperhub_runtime::attachment::NativeFallback,
    ) -> Result<(), i32> {
        let ip = hyperhub_runtime::attachment::canonical_alias_address(ip);
        native_fallback
            .validate()
            .map_err(|_| crate::HH_ERR_INVALID)?;
        if self.ambiguous_aliases.contains(&ip) {
            return Err(crate::HH_ERR_ALIAS_CONFLICT);
        }
        if let Some(old) = self.issued_aliases.get(&ip) {
            return if old.hostname == hostname && old.native_fallback == native_fallback {
                Ok(())
            } else {
                self.reject_ambiguous(ip)
            };
        }
        if self.dns.contains_key(&ip) {
            return self.reject_ambiguous(ip);
        }
        let alias = IssuedAlias {
            hostname: hostname.clone(),
            native_fallback,
        };
        crate::native_alias_snapshot::publish_issued(ip, alias.clone())?;
        self.dns.insert(ip, hostname);
        self.issued_aliases.insert(ip, alias);
        Ok(())
    }
    pub(crate) fn issued_snapshot(
        &self,
    ) -> Result<hyperhub_runtime::attachment::AliasSnapshot, i32> {
        use hyperhub_runtime::attachment::{AliasSnapshot, IssuedAliasSnapshot, MAX_FRAME};
        let bytes = self
            .issued_aliases
            .values()
            .try_fold(0usize, |total, alias| {
                total.checked_add(alias.hostname.len().saturating_add(128))
            });
        if bytes.is_none_or(|bytes| bytes > MAX_FRAME / 2) {
            return Err(crate::HH_ERR_BUFFER_TOO_SMALL);
        }
        let mut issued = self
            .issued_aliases
            .iter()
            .map(|(address, alias)| IssuedAliasSnapshot {
                address: *address,
                hostname: alias.hostname.clone(),
                ambiguous: self.ambiguous_aliases.contains(address),
            })
            .collect::<Vec<_>>();
        issued.sort_by_key(|alias| alias.address);
        Ok(AliasSnapshot {
            issued,
            complete: true,
            history_records: self.namespace.records.clone(),
        })
    }
    pub(crate) fn native_alias_plan(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<Option<crate::HhConnectPlan>, i32> {
        native_alias_plan(&self.issued_aliases, &self.ambiguous_aliases, ip, port)
    }
    pub(crate) fn issued_hostname(&self, ip: IpAddr) -> Option<String> {
        self.issued_aliases
            .get(&hyperhub_runtime::attachment::canonical_alias_address(ip))
            .map(|alias| alias.hostname.clone())
    }
}
pub(crate) fn native_alias_plan(
    issued: &HashMap<IpAddr, IssuedAlias>,
    ambiguous: &HashSet<IpAddr>,
    ip: IpAddr,
    port: u16,
) -> Result<Option<crate::HhConnectPlan>, i32> {
    let identity = hyperhub_runtime::attachment::canonical_alias_address(ip);
    let Some(alias) = issued.get(&identity) else {
        return Ok(None);
    };
    if ambiguous.contains(&identity) {
        return Err(crate::HH_ERR_ALIAS_CONFLICT);
    }
    let native = alias
        .native_fallback
        .addresses
        .iter()
        .find_map(|address| hyperhub_runtime::attachment::native_address_for_alias(ip, address))
        .ok_or(crate::HH_ERR_NATIVE_ALIAS_UNAVAILABLE)?;
    let mut plan = crate::HhConnectPlan {
        should_intercept: 1,
        reserved: crate::HH_CONNECT_NATIVE_COMPAT,
        proxy_port: port,
        connection_id: u64::from(native.scope_id) | (u64::from(native.flowinfo) << 32),
        ..Default::default()
    };
    match native.ip {
        IpAddr::V4(ip) => {
            plan.proxy_family = 2;
            plan.proxy_address[..4].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            plan.proxy_family = if cfg!(windows) { 23 } else { 10 };
            plan.proxy_address = ip.octets();
        }
    }
    Ok(Some(plan))
}
#[cfg(test)]
mod alias_tests {
    use super::*;
    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }
    fn native(value: &str) -> NativeDnsAddress {
        NativeDnsAddress {
            ip: ip(value),
            scope_id: 0,
            flowinfo: 0,
        }
    }
    #[test]
    fn observed_answers_do_not_create_detached_redirects() {
        let mut state = GatewayState::default();
        state
            .observe_dns(ip("198.18.0.7"), "observed.test".into(), true)
            .unwrap();
        assert!(state.issued_hostname(ip("198.18.0.7")).is_none());
        assert!(state
            .native_alias_plan(ip("198.18.0.7"), 80)
            .unwrap()
            .is_none());
        state
            .observe_dns(ip("127.0.0.1"), "later.test".into(), false)
            .unwrap();
        assert!(!state.dns.contains_key(&ip("127.0.0.1")));
    }
    #[test]
    fn issued_alias_cannot_be_reassigned_by_observation_or_publication() {
        let mut state = GatewayState::default();
        let alias = ip("198.18.0.8");
        state
            .issue_alias(alias, "first.test".into(), vec![native("127.0.0.1")])
            .unwrap();
        assert_eq!(
            state.observe_dns(alias, "first.test".into(), false),
            Err(crate::HH_ERR_ALIAS_CONFLICT)
        );
        assert_eq!(state.issued_aliases[&alias].hostname, "first.test");
        assert_eq!(
            state.observe_dns(alias, "other.test".into(), false),
            Err(crate::HH_ERR_ALIAS_CONFLICT)
        );
        let plan = state.native_alias_plan(alias, 80).unwrap().unwrap();
        assert_eq!(&plan.proxy_address[..4], &[127, 0, 0, 1]);
        assert!(state
            .issue_alias(alias, "first.test".into(), vec![])
            .is_err());
    }
    #[test]
    fn missing_native_cache_is_explicit_and_clone_preserves_native_scope() {
        let mut state = GatewayState::default();
        let alias = ip("fdfe:6879:7065:7268:7562::1");
        state
            .issue_alias(alias, "local.test".into(), vec![])
            .unwrap();
        assert!(matches!(
            state.native_alias_plan(alias, 8443),
            Err(crate::HH_ERR_NATIVE_ALIAS_UNAVAILABLE)
        ));
        let mut state = GatewayState::default();
        state
            .issue_alias(
                alias,
                "local.test".into(),
                vec![NativeDnsAddress {
                    ip: ip("fe80::1"),
                    scope_id: 7,
                    flowinfo: 0x12345678,
                }],
            )
            .unwrap();
        let copy = state.clone();
        let plan = copy.native_alias_plan(alias, 8443).unwrap().unwrap();
        assert_eq!(plan.reserved, crate::HH_CONNECT_NATIVE_COMPAT);
        assert_eq!(plan.connection_id as u32, 7);
        assert_eq!((plan.connection_id >> 32) as u32, 0x12345678);
        assert_eq!(plan.proxy_port, 8443);
        assert!(copy.sockets.is_empty());
    }
    #[test]
    fn recovery_snapshot_exports_only_actual_issued_aliases_and_never_a_partial_map() {
        let mut state = GatewayState::default();
        state
            .observe_dns(ip("198.18.0.1"), "external.test".into(), true)
            .unwrap();
        state
            .issue_alias(
                ip("198.18.0.2"),
                "issued.test".into(),
                vec![native("127.0.0.1")],
            )
            .unwrap();
        assert!(state
            .observe_dns(ip("198.18.0.2"), "collision.test".into(), false)
            .is_err());
        let snapshot = state.issued_snapshot().unwrap();
        assert!(snapshot.complete);
        assert_eq!(snapshot.issued.len(), 1);
        assert_eq!(snapshot.issued[0].hostname, "issued.test");
        assert_eq!(snapshot.issued[0].address, ip("198.18.0.2"));
        assert!(!snapshot.issued[0].ambiguous);
        state
            .issued_aliases
            .get_mut(&ip("198.18.0.2"))
            .unwrap()
            .hostname = "x".repeat(hyperhub_runtime::attachment::MAX_FRAME);
        assert!(state.issued_snapshot().is_err());
    }
    #[test]
    fn mapped_origin_is_shared_but_the_connect_family_is_preserved() {
        let mut state = GatewayState::default();
        let alias = ip("198.18.0.9");
        let mapped = ip("::ffff:198.18.0.9");
        state
            .issue_alias(alias, "issued.test".into(), vec![native("127.0.0.1")])
            .unwrap();
        let plan = state.native_alias_plan(mapped, 443).unwrap().unwrap();
        assert_eq!(plan.proxy_family, if cfg!(windows) { 23 } else { 10 });
        assert_eq!(
            plan.proxy_address,
            "::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(plan.connection_id, 0);
        for name in ["issued.test", "other.test"] {
            assert_eq!(
                state.observe_dns(mapped, name.into(), true),
                Err(crate::HH_ERR_ALIAS_CONFLICT)
            );
            assert!(state.native_alias_plan(alias, 443).unwrap().is_some());
            assert!(state.native_alias_plan(mapped, 443).unwrap().is_some());
        }
        let mut observed = GatewayState::default();
        observed
            .observe_dns(mapped, "foreign.test".into(), true)
            .unwrap();
        assert!(observed.dns.contains_key(&alias));
        assert!(observed.issued_hostname(mapped).is_none());
        assert!(observed.native_alias_plan(mapped, 443).unwrap().is_none());
        assert!(observed
            .issue_alias(alias, "foreign.test".into(), vec![native("127.0.0.1")])
            .is_err());
    }
}
