//! Pure policy processing. The cache belongs to this module generation; no Host
//! regex allocation or Rust object crosses the native boundary.
use crate::contract::*;
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

#[derive(Deserialize)]
struct Snapshot {
    default_action: String,
    #[serde(default)]
    rules: Vec<Rule>,
}
#[derive(Deserialize)]
struct Rule {
    id: String,
    action: String,
    patterns: Vec<serde_json::Value>,
    #[serde(default)]
    operations: Vec<String>,
    protection: Option<String>,
}
struct CompiledRule {
    id: String,
    action: String,
    patterns: Vec<(Option<Regex>, Option<Regex>)>,
    operations: Vec<String>,
    protection: Option<String>,
}
struct Compiled {
    default_action: String,
    rules: Vec<CompiledRule>,
}
type Entries = VecDeque<([u8; 32], Arc<Compiled>)>;
struct ForkCell<T>(std::cell::UnsafeCell<T>);
unsafe impl<T: Send> Sync for ForkCell<T> {}
static CACHE: ForkCell<Mutex<Entries>> =
    ForkCell(std::cell::UnsafeCell::new(Mutex::new(VecDeque::new())));
static OWNERS: ForkCell<Mutex<u64>> = ForkCell(std::cell::UnsafeCell::new(Mutex::new(0)));
static EPOCH: AtomicU64 = AtomicU64::new(1);
#[cfg(test)]
static LIVE_COMPILED: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static TEARDOWNS: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
impl Drop for Compiled {
    fn drop(&mut self) {
        LIVE_COMPILED.fetch_sub(1, Ordering::Relaxed);
    }
}
fn cache() -> &'static Mutex<Entries> {
    unsafe { &*CACHE.0.get() }
}
pub(crate) fn retain() -> Result<u64, i32> {
    let mut owners = unsafe { &*OWNERS.0.get() }.lock().map_err(|_| INVALID)?;
    *owners = owners.checked_add(1).ok_or(INVALID)?;
    Ok(EPOCH.load(Ordering::Acquire))
}
pub(crate) fn release(epoch: u64) -> Result<(), i32> {
    let detached = {
        let mut owners = unsafe { &*OWNERS.0.get() }.lock().map_err(|_| INVALID)?;
        if epoch != EPOCH.load(Ordering::Acquire) {
            return Ok(());
        }
        if *owners == 0 {
            return Err(INVALID);
        }
        *owners -= 1;
        if *owners == 0 {
            #[cfg(test)]
            TEARDOWNS.fetch_add(1, Ordering::Relaxed);
            Some(std::mem::take(&mut *cache().lock().map_err(|_| INVALID)?))
        } else {
            None
        }
    };
    // Regex allocator destruction must never execute under the lifecycle lock.
    drop(detached);
    Ok(())
}
/// Child-exclusive safe resume gate. Never unlock or destroy a parent's locks.
/// Each actual module receives this once before its logical owners are rebuilt.
pub(crate) fn reset_after_fork() {
    unsafe {
        std::ptr::write(CACHE.0.get(), Mutex::new(VecDeque::new()));
        std::ptr::write(OWNERS.0.get(), Mutex::new(0));
    }
    EPOCH.fetch_add(1, Ordering::AcqRel);
    #[cfg(test)]
    LIVE_COMPILED.store(0, Ordering::Relaxed);
}
#[cfg(test)]
pub(crate) fn lifecycle_stats() -> [u64; 4] {
    [
        *unsafe { &*OWNERS.0.get() }.lock().unwrap(),
        cache().lock().unwrap().len() as u64,
        LIVE_COMPILED.load(Ordering::Relaxed),
        TEARDOWNS.load(Ordering::Relaxed),
    ]
}
fn compiled(operation: u32, snapshot: &serde_json::Value) -> Result<Arc<Compiled>, i32> {
    let bytes = serde_json::to_vec(snapshot).map_err(|_| INVALID)?;
    let mut hash = Sha256::new();
    hash.update(operation.to_le_bytes());
    hash.update(&bytes);
    let digest: [u8; 32] = hash.finalize().into();
    let cache = cache();
    if let Some(value) = cache
        .lock()
        .map_err(|_| INVALID)?
        .iter()
        .find_map(|(key, value)| (*key == digest).then(|| value.clone()))
    {
        return Ok(value);
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
    let mut rules = Vec::with_capacity(snapshot.rules.len());
    for rule in snapshot.rules {
        if !matches!(rule.action.as_str(), "pass" | "deny") {
            return Err(INVALID);
        }
        let mut patterns = Vec::with_capacity(rule.patterns.len());
        for value in rule.patterns {
            let (target, cmd) = if operation == FILE_POLICY {
                (value.as_str().ok_or(INVALID)?, "")
            } else {
                (
                    value
                        .get("executable")
                        .and_then(|v| v.as_str())
                        .ok_or(INVALID)?,
                    value
                        .get("command_line")
                        .and_then(|v| v.as_str())
                        .ok_or(INVALID)?,
                )
            };
            let compile = |text: &str| -> Result<Option<Regex>, i32> {
                if text.is_empty() {
                    Ok(None)
                } else {
                    Regex::new(text).map(Some).map_err(|_| INVALID)
                }
            };
            // Empty file patterns are valid regular expressions; process empty
            // patterns have wildcard semantics in the established contract.
            let target = if operation == FILE_POLICY {
                Some(Regex::new(target).map_err(|_| INVALID)?)
            } else {
                compile(target)?
            };
            patterns.push((target, compile(cmd)?));
        }
        rules.push(CompiledRule {
            id: rule.id,
            action: rule.action,
            patterns,
            operations: rule.operations,
            protection: rule.protection,
        });
    }
    if !matches!(snapshot.default_action.as_str(), "pass" | "deny") {
        return Err(INVALID);
    }
    #[cfg(test)]
    LIVE_COMPILED.fetch_add(1, Ordering::Relaxed);
    let value = Arc::new(Compiled {
        default_action: snapshot.default_action,
        rules,
    });
    let mut cache = cache.lock().map_err(|_| INVALID)?;
    // Bound both the number and maximum request size. This state never escapes
    // the generation, and old leases retain it while their calls finish.
    if cache.len() == 32 {
        cache.pop_front();
    }
    cache.push_back((digest, value.clone()));
    Ok(value)
}
pub(crate) fn execute(operation: u32, bytes: &[u8]) -> Result<Vec<u8>, i32> {
    let input: PolicyInput = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    let snapshot = compiled(operation, &input.snapshot)?;
    let matches = |rule: &&CompiledRule| {
        (operation != FILE_POLICY || rule.operations.contains(&input.operation))
            && rule.patterns.iter().any(|(target, cmd)| {
                target.as_ref().is_none_or(|r| r.is_match(&input.target))
                    && cmd.as_ref().is_none_or(|r| r.is_match(&input.command_line))
            })
    };
    let first = snapshot.rules.iter().find(matches);
    // Protection can come from a later matching rule, as in the original Host
    // contract; do not silently collapse these two precedence rules.
    let protection = snapshot
        .rules
        .iter()
        .filter(|r| r.protection.is_some())
        .find(matches);
    serde_json::to_vec(&PolicyDecision {
        action: first.map_or_else(|| snapshot.default_action.clone(), |r| r.action.clone()),
        rule_id: first.map(|r| r.id.clone()),
        source: if first.is_some() { "rule" } else { "default" }.into(),
        protection: protection.and_then(|r| r.protection.clone()),
        protection_rule_id: protection.map(|r| r.id.clone()),
    })
    .map_err(|_| INVALID)
}
#[derive(Deserialize)]
struct Firewall {
    default_action: Option<String>,
    #[serde(default)]
    rules: Vec<FirewallRule>,
}
#[derive(Deserialize)]
struct FirewallRule {
    id: String,
    action: String,
    endpoints: Vec<Endpoint>,
    protection: Option<String>,
}
#[derive(Deserialize)]
struct Endpoint {
    target: FirewallTarget,
    port: Option<u16>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum FirewallTarget {
    Domain(Domain),
    Ip(std::net::IpAddr),
    Network(ipnet::IpNet),
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Domain {
    Legacy(String),
    Explicit {
        host: String,
        #[serde(default)]
        wildcard: bool,
        #[serde(default)]
        include_apex: bool,
    },
}
fn domain_matches(candidate: &str, domain: &Domain) -> bool {
    let (host, wildcard, apex) = match domain {
        Domain::Legacy(host) => (host, true, true),
        Domain::Explicit {
            host,
            wildcard,
            include_apex,
        } => (host, *wildcard, *include_apex),
    };
    let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if wildcard {
        (apex && candidate == host)
            || (candidate != host && candidate.ends_with(&format!(".{host}")))
    } else {
        candidate == host
    }
}
fn firewall_output(action: String, rule: Option<&FirewallRule>) -> Result<Vec<u8>, i32> {
    if !matches!(action.as_str(), "pass" | "deny") {
        return Err(INVALID);
    }
    serde_json::to_vec(&PolicyDecision {
        action,
        rule_id: rule.map(|r| r.id.clone()),
        source: if rule.is_some() { "rule" } else { "default" }.into(),
        protection: rule.and_then(|r| r.protection.clone()),
        protection_rule_id: rule
            .filter(|r| r.protection.is_some())
            .map(|r| r.id.clone()),
    })
    .map_err(|_| INVALID)
}
pub(crate) fn firewall(bytes: &[u8]) -> Result<Vec<u8>, i32> {
    let input: FirewallInput = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    let snapshot: Firewall = serde_json::from_value(input.snapshot).map_err(|_| INVALID)?;
    if input.bypass {
        return firewall_output("pass".into(), None);
    }
    if input.dns {
        let hostname = input.hostname.as_deref().ok_or(INVALID)?;
        if hostname.trim_end_matches('.').is_empty() {
            return Err(INVALID);
        }
        for rule in &snapshot.rules {
            let matched = rule.endpoints.iter().any(|e| match &e.target {
                FirewallTarget::Domain(d) => domain_matches(hostname, d),
                _ => false,
            });
            let needs_connect = rule
                .endpoints
                .iter()
                .any(|e| e.port.is_some() || !matches!(&e.target, FirewallTarget::Domain(_)));
            if !matched && !needs_connect {
                continue;
            }
            return if needs_connect {
                firewall_output("pass".into(), None)
            } else {
                firewall_output(rule.action.clone(), Some(rule))
            };
        }
        return firewall_output(
            snapshot.default_action.unwrap_or_else(|| "pass".into()),
            None,
        );
    }
    let rule = snapshot.rules.iter().find(|r| {
        r.endpoints.iter().any(|e| {
            e.port.is_none_or(|p| p == input.port)
                && match &e.target {
                    FirewallTarget::Domain(d) => input
                        .hostname
                        .as_ref()
                        .is_some_and(|h| domain_matches(h, d)),
                    FirewallTarget::Ip(ip) => input.hostname.is_none() && input.ip == *ip,
                    FirewallTarget::Network(net) => {
                        input.hostname.is_none() && net.contains(&input.ip)
                    }
                }
        })
    });
    firewall_output(
        rule.map_or_else(
            || snapshot.default_action.unwrap_or_else(|| "pass".into()),
            |r| r.action.clone(),
        ),
        rule,
    )
}

/// Source-based fork regression holds the actual module cache across fork.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn with_cache_lock_for_test(call: impl FnOnce()) {
    let _guard = cache().lock().unwrap();
    call();
}

#[cfg(test)]
#[test]
fn actual_compiled_cache_drops_only_after_last_module_owner() {
    assert_eq!(lifecycle_stats(), [0, 0, 0, 0]);
    let first = retain().unwrap();
    let second = retain().unwrap();
    execute(FILE_POLICY, br#"{"snapshot":{"default_action":"pass"},"target":"ordinary","operation":"read","command_line":""}"#).unwrap();
    assert_eq!(lifecycle_stats(), [2, 1, 1, 0]);
    release(first).unwrap();
    assert_eq!(lifecycle_stats(), [1, 1, 1, 0]);
    release(second).unwrap();
    assert_eq!(lifecycle_stats(), [0, 0, 0, 1]);
}
