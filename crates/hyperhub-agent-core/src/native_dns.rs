//! Native answers are prefetched only at the original synchronous DNS boundary.
//! Detached connect never performs DNS, asks Core, or enters old routing policy.
use crate::{FirewallSnapshot, NativeDnsAddress, HH_ERR_PROTOCOL};
use hyperhub_runtime::attachment::{NativeFallback, NativeUnavailable};
#[cfg(test)]
use std::net::IpAddr;

pub(crate) fn prefetch(hostname: &str, family: u32) -> Result<NativeFallback, i32> {
    let (engine, snapshot) = {
        let core = crate::state().lock().map_err(|_| HH_ERR_PROTOCOL)?;
        (core.engine.clone(), core.sandbox.firewall.clone())
    };
    prefetch_using(hostname, family, &engine, snapshot.as_deref(), || {
        native(hostname, family)
    })
}
fn prefetch_using(
    hostname: &str,
    family: u32,
    engine: &std::sync::Arc<hyperhub_runtime::Runtime>,
    snapshot: Option<&FirewallSnapshot>,
    lookup: impl FnOnce() -> Result<Vec<NativeDnsAddress>, i32>,
) -> Result<NativeFallback, i32> {
    if !policy_allows_native(hostname, engine, snapshot)? {
        return Ok(unavailable(
            family,
            NativeUnavailable::SuppressedByActivePolicy,
        ));
    }
    // A native failure cannot turn a working Core-routed lookup into an active
    // failure. Its alias is retained with an explicit unavailable native cache.
    match lookup() {
        Err(error) => Ok(NativeFallback {
            family,
            addresses: Vec::new(),
            failure: Some(if error == 0 { HH_ERR_PROTOCOL } else { error }),
            unavailable: None,
        }),
        Ok(addresses) => {
            if addresses.iter().any(|address| {
                address.ip.is_ipv4() && (address.scope_id != 0 || address.flowinfo != 0)
            }) {
                return Ok(unavailable(family, NativeUnavailable::InvalidNativeAnswer));
            }
            let addresses: Vec<_> = addresses
                .into_iter()
                .filter(|address| address.ip.is_ipv4() == (family == 4))
                .collect();
            if addresses.is_empty() {
                return Ok(unavailable(family, NativeUnavailable::NoCompatibleAddress));
            }
            Ok(NativeFallback {
                family,
                addresses,
                failure: None,
                unavailable: None,
            })
        }
    }
}
/// A Host without a pinned alias authority may use native DNS only when the
/// current DNS policy permits that same native query. No query occurs here.
pub(crate) fn native_only_admission(hostname: &str) -> Result<(), i32> {
    let (engine, snapshot) = {
        let state = crate::state().lock().map_err(|_| HH_ERR_PROTOCOL)?;
        (state.engine.clone(), state.sandbox.firewall.clone())
    };
    if policy_allows_native(hostname, &engine, snapshot.as_deref())? {
        Ok(())
    } else {
        Err(crate::HH_ERR_NATIVE_ALIAS_UNAVAILABLE)
    }
}
fn policy_allows_native(
    hostname: &str,
    engine: &std::sync::Arc<hyperhub_runtime::Runtime>,
    snapshot: Option<&FirewallSnapshot>,
) -> Result<bool, i32> {
    if let Some(snapshot) = snapshot {
        let decision = (|| {
            let lease = crate::engine_call::calling(engine)?;
            hyperhub_engine::firewall(
                &lease,
                &hyperhub_engine::contract::FirewallInput {
                    snapshot: serde_json::to_value(snapshot).map_err(|_| HH_ERR_PROTOCOL)?,
                    hostname: Some(hostname.into()),
                    ip: std::net::Ipv4Addr::UNSPECIFIED.into(),
                    port: 0,
                    bypass: false,
                    dns: true,
                },
            )
        })();
        match decision {
            Ok(decision) if decision.action == "deny" => return Err(HH_ERR_PROTOCOL),
            Ok(decision) if decision.action != "pass" || decision.source == "error" => {
                return Ok(false)
            }
            Err(_) if snapshot.error_action == crate::FirewallAction::Deny => {
                return Err(HH_ERR_PROTOCOL)
            }
            Err(_) => return Ok(false),
            _ => (),
        }
    }
    Ok(true)
}

fn unavailable(family: u32, reason: NativeUnavailable) -> NativeFallback {
    NativeFallback {
        family,
        addresses: Vec::new(),
        failure: None,
        unavailable: Some(reason),
    }
}

fn native(hostname: &str, family: u32) -> Result<Vec<NativeDnsAddress>, i32> {
    #[cfg(all(windows, feature = "gum-agent"))]
    {
        return crate::windows_gum::resolve_native_addresses(hostname, family);
    }
    #[cfg(all(target_os = "linux", feature = "gum-agent"))]
    {
        return crate::unix_gum::resolve_native_addresses(hostname, family);
    }
    #[cfg(not(all(any(windows, target_os = "linux"), feature = "gum-agent")))]
    {
        use std::net::ToSocketAddrs;
        (hostname, 0)
            .to_socket_addrs()
            .map_err(|_| HH_ERR_PROTOCOL)
            .map(|values| {
                values
                    .filter_map(|value| {
                        let ip = value.ip();
                        if ip.is_ipv4() != (family != 6) {
                            return None;
                        }
                        let (scope_id, flowinfo) = match value {
                            std::net::SocketAddr::V4(_) => (0, 0),
                            std::net::SocketAddr::V6(value) => (value.scope_id(), value.flowinfo()),
                        };
                        Some(NativeDnsAddress {
                            ip,
                            scope_id,
                            flowinfo,
                        })
                    })
                    .collect()
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[test]
    fn dns_denial_does_not_issue_any_native_query() {
        let snapshot:FirewallSnapshot=serde_json::from_value(serde_json::json!({"version":1,"default_action":"deny","error_action":"deny","rules":[]})).unwrap();
        let calls = AtomicUsize::new(0);
        assert!(prefetch_using(
            "denied.fixture.test",
            4,
            &hyperhub_engine::resident(),
            Some(&snapshot),
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(vec![])
            }
        )
        .is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn allowed_lookup_preserves_native_address_order_and_original_failure_status() {
        let addresses = vec![NativeDnsAddress {
            ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            scope_id: 0,
            flowinfo: 0,
        }];
        assert_eq!(
            prefetch_using("localhost", 4, &hyperhub_engine::resident(), None, || Ok(
                addresses.clone()
            ))
            .unwrap()
            .addresses,
            addresses
        );
        assert!(
            prefetch_using(
                "unavailable.fixture.test",
                4,
                &hyperhub_engine::resident(),
                None,
                || Err(11001)
            )
            .unwrap()
            .failure
                == Some(11001)
        );
    }
}
