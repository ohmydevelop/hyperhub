//! Native-only compatibility state pinned before a fork. Child callbacks never
//! touch the copied publisher lock or the policy/Engine state.
use crate::{GatewayState, HhConnectPlan, IssuedAlias, HH_ERR_PROTOCOL};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicPtr, Ordering},
    Arc, RwLock, RwLockReadGuard,
};
#[derive(Clone, Default)]
pub(crate) struct NativeAliasSnapshot {
    issued: HashMap<IpAddr, IssuedAlias>,
    ambiguous: HashSet<IpAddr>,
    conflicts: HashMap<IpAddr, Arc<AtomicBool>>,
}
impl NativeAliasSnapshot {
    pub(crate) fn plan(&self, ip: IpAddr, port: u16) -> Result<Option<HhConnectPlan>, i32> {
        let identity = hyperhub_runtime::attachment::canonical_alias_address(ip);
        if self
            .conflicts
            .get(&identity)
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(crate::HH_ERR_ALIAS_CONFLICT);
        }
        crate::gateway::native_alias_plan(&self.issued, &self.ambiguous, ip, port)
    }
    pub(crate) fn check_observed(&self, ip: IpAddr, _hostname: &str) -> Result<(), i32> {
        let ip = hyperhub_runtime::attachment::canonical_alias_address(ip);
        if self.issued.contains_key(&ip) {
            return Err(crate::HH_ERR_ALIAS_CONFLICT);
        }
        Ok(())
    }
}
static PUBLISHER: AtomicPtr<RwLock<Arc<NativeAliasSnapshot>>> =
    AtomicPtr::new(std::ptr::null_mut());
fn publisher() -> &'static RwLock<Arc<NativeAliasSnapshot>> {
    let mut pointer = PUBLISHER.load(Ordering::Acquire);
    if pointer.is_null() {
        let fresh = Box::into_raw(Box::new(RwLock::new(Arc::new(
            NativeAliasSnapshot::default(),
        ))));
        match PUBLISHER.compare_exchange(
            std::ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => pointer = fresh,
            Err(old) => {
                unsafe {
                    drop(Box::from_raw(fresh));
                }
                pointer = old;
            }
        }
    }
    unsafe { &*pointer }
}
pub(crate) fn publish_issued(ip: IpAddr, alias: IssuedAlias) -> Result<(), i32> {
    let ip = hyperhub_runtime::attachment::canonical_alias_address(ip);
    let mut current = publisher().write().map_err(|_| HH_ERR_PROTOCOL)?;
    let state = Arc::make_mut(&mut current);
    state
        .conflicts
        .entry(ip)
        .or_insert_with(|| Arc::new(AtomicBool::new(false)));
    state.issued.insert(ip, alias);
    Ok(())
}
pub(crate) fn publish_conflict(ip: IpAddr) -> Result<(), i32> {
    let ip = hyperhub_runtime::attachment::canonical_alias_address(ip);
    let mut current = publisher().write().map_err(|_| HH_ERR_PROTOCOL)?;
    let state = Arc::make_mut(&mut current);
    state.ambiguous.insert(ip);
    if let Some(flag) = state.conflicts.get(&ip) {
        flag.store(true, Ordering::Release);
    }
    Ok(())
}
#[cfg(all(target_os = "linux", feature = "gum-agent"))]
pub(crate) fn pin_for_fork() -> Result<
    (
        Arc<NativeAliasSnapshot>,
        RwLockReadGuard<'static, Arc<NativeAliasSnapshot>>,
    ),
    i32,
> {
    let guard = publisher().read().map_err(|_| HH_ERR_PROTOCOL)?;
    let pin = Arc::clone(&guard);
    Ok((pin, guard))
}
/// Only the rebuilt child calls this. Never unlock or destroy the parent's
/// copied publisher: its lock and Arc ownership belong to the abandoned heap.
#[cfg(all(target_os = "linux", feature = "gum-agent"))]
pub(crate) fn rebuild(gateway: &GatewayState) {
    let snapshot = NativeAliasSnapshot {
        issued: gateway.issued_aliases.clone(),
        ambiguous: gateway.ambiguous_aliases.clone(),
        conflicts: gateway
            .issued_aliases
            .keys()
            .map(|ip| {
                (
                    *ip,
                    Arc::new(AtomicBool::new(gateway.ambiguous_aliases.contains(ip))),
                )
            })
            .collect(),
    };
    PUBLISHER.store(
        Box::into_raw(Box::new(RwLock::new(Arc::new(snapshot)))),
        Ordering::Release,
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeDnsAddress;
    #[test]
    fn a_pinned_fork_snapshot_has_stable_origin_and_scope_without_engine() {
        let alias = "fdfe:6879:7065:7268:7562::3".parse().unwrap();
        let mut snapshot = Arc::new(NativeAliasSnapshot::default());
        Arc::make_mut(&mut snapshot).issued.insert(
            alias,
            IssuedAlias {
                hostname: "first.test".into(),
                native_fallback: hyperhub_runtime::attachment::NativeFallback {
                    family: 6,
                    failure: None,
                    unavailable: None,
                    addresses: vec![NativeDnsAddress {
                        ip: "fe80::1".parse().unwrap(),
                        scope_id: 9,
                        flowinfo: 0x76543210,
                    }],
                },
            },
        );
        Arc::make_mut(&mut snapshot)
            .conflicts
            .insert(alias, Arc::new(AtomicBool::new(false)));
        let pinned = snapshot.clone();
        Arc::make_mut(&mut snapshot).ambiguous.insert(alias);
        let plan = pinned.plan(alias, 8443).unwrap().unwrap();
        assert_eq!(plan.connection_id as u32, 9);
        assert_eq!(plan.connection_id >> 32, 0x76543210);
        assert!(snapshot.plan(alias, 8443).is_err());
        assert!(pinned
            .plan("198.18.0.9".parse().unwrap(), 80)
            .unwrap()
            .is_none());
        assert!(pinned.check_observed(alias, "FIRST.TEST.").is_err());
        assert!(pinned.check_observed(alias, "different.test").is_err());
        assert!(pinned.plan(alias, 8443).unwrap().is_some());
    }
}

/// Windows loader calls only after all application/SDK references and native
/// entry points have passed their final external thread barrier.
#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) unsafe fn release_retired() {
    let pointer = PUBLISHER.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !pointer.is_null() {
        drop(Box::from_raw(pointer));
    }
}
