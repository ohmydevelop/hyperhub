#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
use std::env;
use std::io::{Read, Write};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
use crate::SandboxAuditEvent;
use crate::{FirewallSnapshot, SandboxSnapshot, CONTROL_MAX_FRAME, HH_ERR_PROTOCOL};

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
use crate::FirewallAuditEvent;

#[cfg(all(windows, feature = "gum-agent"))]
use crate::windows_gum;

pub(crate) trait ControlStream: Read + Write {}
impl<T: Read + Write> ControlStream for T {}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AgentControlRequest<'a> {
    #[cfg(all(windows, feature = "gum-agent"))]
    BootstrapChild,
    ResolveName {
        session_id: &'a str,
        token: &'a str,
        hostname: &'a str,
        family: u8,
    },
    GetTrust {
        session_id: &'a str,
        token: &'a str,
    },
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    DecideProcessHook {
        session_id: &'a str,
        token: &'a str,
        executable: &'a str,
        root: bool,
    },
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    ReportFirewallAudit {
        session_id: &'a str,
        token: &'a str,
        event: &'a FirewallAuditEvent,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    RefreshFirewall {
        session_id: &'a str,
        token: &'a str,
        current_version: u64,
    },
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    SubscribeSandbox {
        session_id: &'a str,
        token: &'a str,
        current_version: u64,
    },
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    ReportSandboxAudit {
        session_id: &'a str,
        token: &'a str,
        event: &'a SandboxAuditEvent,
    },
    SmartProtectionCheck {
        session_id: &'a str,
        token: &'a str,
        protection_id: &'a str,
        rule_id: Option<&'a str>,
        stage: &'a str,
        executable: &'a str,
        argv: &'a [String],
        features: &'a [String],
        context: &'a serde_json::Value,
    },
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    RegisterChild {
        session_id: &'a str,
        token: &'a str,
        parent_pid: u32,
        child_pid: u32,
        executable: &'a str,
        process_policy_version: u64,
        process_rule_id: Option<&'a str>,
        process_decision_source: &'a str,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    BeginFork {
        session_id: &'a str,
        token: &'a str,
        parent_pid: u32,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    RegisterForkCandidate {
        session_id: &'a str,
        token: &'a str,
        lease_id: &'a str,
        parent_pid: u32,
        child_pid: u32,
        executable: &'a str,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    GetPendingForkLease {
        session_id: &'a str,
        token: &'a str,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    AttestForkChild {
        session_id: &'a str,
        token: &'a str,
        lease_id: &'a str,
        runtime_generation: u64,
        hook_manifest: &'a [String],
        policy_version: u64,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    GetForkStatus {
        session_id: &'a str,
        token: &'a str,
        lease_id: &'a str,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    FinishFork {
        session_id: &'a str,
        token: &'a str,
        lease_id: &'a str,
        require_attested: bool,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    ReportChildInjectionFailure {
        session_id: &'a str,
        token: &'a str,
        parent_pid: u32,
        child_pid: u32,
        executable: Option<&'a str>,
        stage: &'a str,
        error_code: u32,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AgentControlResponse {
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    Ok,
    SmartProtectionDecision {
        action: String,
        reason: String,
        #[serde(default)]
        risk_level: Option<String>,
        #[serde(default)]
        confidence: Option<f64>,
        #[serde(default)]
        cache_hit: bool,
    },
    ResolvedName {
        address: String,
        #[serde(rename = "ttl_secs")]
        _ttl_secs: u32,
    },
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    ProcessHookDecision {
        hook: bool,
        #[serde(default, rename = "rule_id")]
        _rule_id: Option<String>,
        #[serde(default, rename = "source")]
        _source: String,
        #[serde(default, rename = "version")]
        _version: u64,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    ForkLease { lease_id: String },
    #[cfg(all(windows, feature = "gum-agent"))]
    ForkStatus { attested: bool },
    TrustBootstrap {
        socks_address: String,
        agent_flags: AgentBootstrapFlags,
        environment: Vec<SessionEnvironmentVariable>,
        tls_ca_pem: String,
        #[serde(default, deserialize_with = "deserialize_optional_firewall")]
        firewall: Option<FirewallSnapshot>,
        #[serde(default, deserialize_with = "deserialize_optional_sandbox")]
        sandbox: Option<SandboxSnapshot>,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    FirewallRefresh {
        version: u64,
        changed: bool,
        #[serde(default, deserialize_with = "deserialize_optional_firewall")]
        firewall: Option<FirewallSnapshot>,
    },
    #[cfg(all(windows, feature = "gum-agent"))]
    AgentBootstrap {
        socks_address: String,
        control_endpoint: String,
        session_id: String,
        token: String,
        tls_ca_pem: String,
        agent_flags: AgentBootstrapFlags,
        #[serde(default)]
        environment: Vec<SessionEnvironmentVariable>,
        #[serde(default, deserialize_with = "deserialize_optional_firewall")]
        firewall: Option<FirewallSnapshot>,
        #[serde(default, deserialize_with = "deserialize_optional_sandbox")]
        sandbox: Option<SandboxSnapshot>,
    },
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    SandboxUpdate {
        #[serde(rename = "version")]
        _version: u64,
        #[serde(rename = "changed")]
        _changed: bool,
        #[serde(default, deserialize_with = "deserialize_optional_sandbox")]
        sandbox: Option<SandboxSnapshot>,
    },
    Error {
        #[serde(rename = "message")]
        _message: String,
    },
}

pub(crate) fn deserialize_optional_sandbox<'de, D>(
    deserializer: D,
) -> Result<Option<SandboxSnapshot>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|v| serde_json::from_value(v).ok()))
}

pub(crate) fn deserialize_optional_firewall<'de, D>(
    deserializer: D,
) -> Result<Option<FirewallSnapshot>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| serde_json::from_value(value).ok()))
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct SessionEnvironmentVariable {
    pub(crate) name: String,
    pub(crate) value: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct AgentBootstrapFlags {
    pub(crate) observe: bool,
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) struct InheritedBootstrap {
    pub(crate) socks_address: String,
    pub(crate) control_endpoint: String,
    pub(crate) session_id: String,
    pub(crate) token: String,
    pub(crate) tls_ca_pem: String,
    pub(crate) observe: bool,
    pub(crate) environment: Vec<SessionEnvironmentVariable>,
    pub(crate) firewall: Option<FirewallSnapshot>,
    pub(crate) sandbox: Option<SandboxSnapshot>,
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn bootstrap_child_control() -> Result<InheritedBootstrap, i32> {
    const DISCOVERY_ENDPOINT: &str = r"\\.\pipe\hyperhub-control";
    match exchange_control(DISCOVERY_ENDPOINT, &AgentControlRequest::BootstrapChild)? {
        AgentControlResponse::AgentBootstrap {
            socks_address,
            control_endpoint,
            session_id,
            token,
            tls_ca_pem,
            agent_flags,
            environment,
            firewall,
            sandbox,
        } => Ok(InheritedBootstrap {
            socks_address,
            control_endpoint,
            session_id,
            token,
            tls_ca_pem,
            observe: agent_flags.observe,
            environment,
            firewall,
            sandbox,
        }),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn install_inherited_environment(bootstrap: &InheritedBootstrap) -> Result<(), i32> {
    // SAFETY: this runs in the Agent initialization worker while the target main thread is
    // suspended. The values are installed before any application thread can read the environment.
    unsafe {
        env::set_var("HYPERHUB_SESSION_ID", &bootstrap.session_id);
        env::set_var("HYPERHUB_SESSION_TOKEN", &bootstrap.token);
        env::set_var("HYPERHUB_SOCKS_ADDR", &bootstrap.socks_address);
        env::set_var("HYPERHUB_CONTROL_ENDPOINT", &bootstrap.control_endpoint);
        install_managed_environment(
            &bootstrap.socks_address,
            bootstrap.observe,
            &bootstrap.environment,
        )?;
        if let Some(path) = windows_gum::agent_module_path() {
            env::set_var("HYPERHUB_AGENT_PATH", path);
        }
    }
    Ok(())
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) unsafe fn install_managed_environment(
    socks_address: &str,
    observe: bool,
    environment: &[SessionEnvironmentVariable],
) -> Result<(), i32> {
    if let Some(previous) = env::var_os("HYPERHUB_SESSION_ENV_KEYS") {
        let keys = serde_json::from_str::<Vec<String>>(&previous.to_string_lossy())
            .map_err(|_| HH_ERR_PROTOCOL)?;
        for key in keys {
            if !key.to_ascii_uppercase().starts_with("HYPERHUB_") {
                env::remove_var(key);
            }
        }
    }
    env::set_var("HYPERHUB_SOCKS_ADDR", socks_address);
    env::set_var(
        "HYPERHUB_ENFORCEMENT_MODE",
        if observe { "observe" } else { "enforce" },
    );
    for variable in environment {
        env::set_var(&variable.name, &variable.value);
    }
    let keys = serde_json::to_string(
        &environment
            .iter()
            .map(|variable| variable.name.as_str())
            .collect::<Vec<_>>(),
    )
    .map_err(|_| HH_ERR_PROTOCOL)?;
    env::set_var("HYPERHUB_SESSION_ENV_KEYS", keys);
    Ok(())
}

pub(crate) fn open_control(endpoint: &str) -> Result<Box<dyn ControlStream>, i32> {
    #[cfg(windows)]
    {
        for _ in 0..50 {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(endpoint)
            {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        Err(HH_ERR_PROTOCOL)
    }
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(endpoint)
            .map(|stream| Box::new(stream) as Box<dyn ControlStream>)
            .map_err(|_| HH_ERR_PROTOCOL)
    }
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) struct ProcessHookDecision {
    pub(crate) hook: bool,
    pub(crate) rule_id: Option<String>,
    pub(crate) source: String,
    pub(crate) version: u64,
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn decide_process_hook(
    endpoint: &str,
    session_id: &str,
    token: &str,
    executable: &str,
) -> ProcessHookDecision {
    let request = AgentControlRequest::DecideProcessHook {
        session_id,
        token,
        executable,
        root: false,
    };
    match exchange_control(endpoint, &request) {
        Ok(AgentControlResponse::ProcessHookDecision {
            hook,
            _rule_id: rule_id,
            _source: source,
            _version: version,
        }) => ProcessHookDecision {
            hook,
            rule_id,
            source,
            version,
        },
        _ => ProcessHookDecision {
            hook: true,
            rule_id: None,
            source: "fallback".into(),
            version: 0,
        },
    }
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn smart_protection_check(
    endpoint: &str,
    session_id: &str,
    token: &str,
    protection_id: &str,
    rule_id: Option<&str>,
    stage: &str,
    executable: &str,
    argv: &[String],
    features: &[String],
    context: &serde_json::Value,
) -> Result<bool, i32> {
    let request = AgentControlRequest::SmartProtectionCheck {
        session_id,
        token,
        protection_id,
        rule_id,
        stage,
        executable,
        argv,
        features,
        context,
    };
    match exchange_control(endpoint, &request)? {
        AgentControlResponse::SmartProtectionDecision { action, .. } => Ok(action == "deny"),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

pub(crate) fn resolve_fake_control(
    endpoint: &str,
    session_id: &str,
    token: &str,
    hostname: &str,
    family: u8,
) -> Result<IpAddr, i32> {
    let request = AgentControlRequest::ResolveName {
        session_id,
        token,
        hostname,
        family,
    };
    match exchange_control(endpoint, &request)? {
        AgentControlResponse::ResolvedName { address, .. } => {
            address.parse().map_err(|_| HH_ERR_PROTOCOL)
        }
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg_attr(
    not(all(any(windows, target_os = "linux"), feature = "gum-agent")),
    allow(dead_code)
)]
pub(crate) struct TrustBootstrapData {
    pub(crate) socks_address: String,
    pub(crate) agent_flags: AgentBootstrapFlags,
    pub(crate) environment: Vec<SessionEnvironmentVariable>,
    pub(crate) tls_ca_pem: String,
    pub(crate) firewall: Option<FirewallSnapshot>,
    pub(crate) sandbox: Option<SandboxSnapshot>,
}

pub(crate) fn fetch_trust_control(
    endpoint: &str,
    session_id: &str,
    token: &str,
) -> Result<TrustBootstrapData, i32> {
    let request = AgentControlRequest::GetTrust { session_id, token };
    let response = match exchange_control(endpoint, &request) {
        Ok(response) => response,
        Err(error) => {
            debug_bootstrap_failure(&format!(
                "GetTrust control exchange failed with status {error}"
            ));
            return Err(error);
        }
    };
    match response {
        AgentControlResponse::TrustBootstrap {
            socks_address,
            agent_flags,
            environment,
            tls_ca_pem,
            firewall,
            sandbox,
        } if tls_ca_pem.contains("-----BEGIN CERTIFICATE-----")
            && !tls_ca_pem.contains("PRIVATE KEY-----") =>
        {
            Ok(TrustBootstrapData {
                socks_address,
                agent_flags,
                environment,
                tls_ca_pem,
                firewall,
                sandbox,
            })
        }
        AgentControlResponse::Error { _message: message } => {
            debug_bootstrap_failure(&format!("GetTrust rejected by Serve: {message}"));
            Err(HH_ERR_PROTOCOL)
        }
        AgentControlResponse::TrustBootstrap { .. } => {
            debug_bootstrap_failure("GetTrust returned an invalid certificate bundle");
            Err(HH_ERR_PROTOCOL)
        }
        _ => {
            debug_bootstrap_failure("GetTrust returned an unexpected control response");
            Err(HH_ERR_PROTOCOL)
        }
    }
}

#[allow(dead_code)]
fn debug_bootstrap_failure(message: &str) {
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
        eprintln!("hyperhub-agent: {message}");
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn begin_fork_control(
    endpoint: &str,
    session_id: &str,
    token: &str,
    parent_pid: u32,
) -> Result<String, i32> {
    match exchange_control(
        endpoint,
        &AgentControlRequest::BeginFork {
            session_id,
            token,
            parent_pid,
        },
    )? {
        AgentControlResponse::ForkLease { lease_id } => Ok(lease_id),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn register_fork_candidate_control(
    endpoint: &str,
    session_id: &str,
    token: &str,
    lease_id: &str,
    parent_pid: u32,
    child_pid: u32,
    executable: &str,
) -> Result<(), i32> {
    match exchange_control(
        endpoint,
        &AgentControlRequest::RegisterForkCandidate {
            session_id,
            token,
            lease_id,
            parent_pid,
            child_pid,
            executable,
        },
    )? {
        AgentControlResponse::ForkStatus { attested: false } => Ok(()),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn attest_fork_child_control(
    endpoint: &str,
    session_id: &str,
    token: &str,
    lease_id: &str,
    runtime_generation: u64,
    hook_manifest: &[String],
    policy_version: u64,
) -> Result<TrustBootstrapData, i32> {
    match exchange_control(
        endpoint,
        &AgentControlRequest::AttestForkChild {
            session_id,
            token,
            lease_id,
            runtime_generation,
            hook_manifest,
            policy_version,
        },
    )? {
        AgentControlResponse::TrustBootstrap {
            socks_address,
            agent_flags,
            environment,
            tls_ca_pem,
            firewall,
            sandbox,
        } => Ok(TrustBootstrapData {
            socks_address,
            agent_flags,
            environment,
            tls_ca_pem,
            firewall,
            sandbox,
        }),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn pending_fork_lease_control(
    endpoint: &str,
    session_id: &str,
    token: &str,
) -> Result<String, i32> {
    match exchange_control(
        endpoint,
        &AgentControlRequest::GetPendingForkLease { session_id, token },
    )? {
        AgentControlResponse::ForkLease { lease_id } => Ok(lease_id),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn finish_fork_control(
    endpoint: &str,
    session_id: &str,
    token: &str,
    lease_id: &str,
    require_attested: bool,
) -> Result<bool, i32> {
    match exchange_control(
        endpoint,
        &AgentControlRequest::FinishFork {
            session_id,
            token,
            lease_id,
            require_attested,
        },
    )? {
        AgentControlResponse::ForkStatus { attested } => Ok(attested),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn fork_status_control(
    endpoint: &str,
    session_id: &str,
    token: &str,
    lease_id: &str,
) -> Result<bool, i32> {
    match exchange_control(
        endpoint,
        &AgentControlRequest::GetForkStatus {
            session_id,
            token,
            lease_id,
        },
    )? {
        AgentControlResponse::ForkStatus { attested } => Ok(attested),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(target_os = "linux", feature = "gum-agent"))]
pub(crate) fn register_unix_process(
    endpoint: &str,
    session_id: &str,
    token: &str,
) -> Result<(), i32> {
    let executable = std::env::current_exe()
        .map_err(|_| HH_ERR_PROTOCOL)?
        .display()
        .to_string();
    let request = AgentControlRequest::RegisterChild {
        session_id,
        token,
        parent_pid: unsafe { libc::getppid() as u32 },
        child_pid: unsafe { libc::getpid() as u32 },
        executable: &executable,
        process_policy_version: 0,
        process_rule_id: None,
        process_decision_source: "inherited",
    };
    match exchange_control(endpoint, &request)? {
        AgentControlResponse::Ok => Ok(()),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn subscribe_sandbox() {
    let _ = std::thread::Builder::new()
        .name("hyperhub-sandbox-subscription".into())
        .spawn(|| {
            let delays = [250u64, 1000, 2000, 5000, 10000, 30000];
            let mut attempt = 0usize;
            loop {
                let values = crate::state().lock().ok().map(|c| {
                    (
                        c.session.control_endpoint.clone(),
                        c.session.session_id.clone(),
                        c.session.token.clone(),
                    )
                });
                let Some((endpoint, session_id, token)) = values else {
                    return;
                };
                let request = AgentControlRequest::SubscribeSandbox {
                    session_id: &session_id,
                    token: &token,
                    current_version: crate::sandbox_version(),
                };
                let result = (|| -> Result<(), i32> {
                    let payload = serde_json::to_vec(&request).map_err(|_| HH_ERR_PROTOCOL)?;
                    let mut stream = open_control(&endpoint)?;
                    stream
                        .write_all(&(payload.len() as u32).to_be_bytes())
                        .and_then(|_| stream.write_all(&payload))
                        .and_then(|_| stream.flush())
                        .map_err(|_| HH_ERR_PROTOCOL)?;
                    loop {
                        let mut length = [0; 4];
                        stream
                            .read_exact(&mut length)
                            .map_err(|_| HH_ERR_PROTOCOL)?;
                        let len = u32::from_be_bytes(length) as usize;
                        if len > CONTROL_MAX_FRAME {
                            return Err(HH_ERR_PROTOCOL);
                        }
                        let mut payload = vec![0; len];
                        stream
                            .read_exact(&mut payload)
                            .map_err(|_| HH_ERR_PROTOCOL)?;
                        match serde_json::from_slice::<AgentControlResponse>(&payload)
                            .map_err(|_| HH_ERR_PROTOCOL)?
                        {
                            AgentControlResponse::SandboxUpdate {
                                sandbox: Some(snapshot),
                                ..
                            } => crate::apply_sandbox_snapshot(snapshot),
                            AgentControlResponse::SandboxUpdate { .. } => {}
                            _ => return Err(HH_ERR_PROTOCOL),
                        }
                    }
                })();
                if result.is_ok() {
                    attempt = 0
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(
                        delays[attempt.min(delays.len() - 1)],
                    ));
                    attempt = attempt.saturating_add(1);
                }
            }
        });
}
#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn report_sandbox_audit(event: &SandboxAuditEvent) -> Result<(), i32> {
    let (endpoint, session_id, token) = {
        let c = crate::state().lock().map_err(|_| HH_ERR_PROTOCOL)?;
        (
            c.session.control_endpoint.clone(),
            c.session.session_id.clone(),
            c.session.token.clone(),
        )
    };
    match exchange_control(
        &endpoint,
        &AgentControlRequest::ReportSandboxAudit {
            session_id: &session_id,
            token: &token,
            event,
        },
    )? {
        AgentControlResponse::Ok => Ok(()),
        _ => Err(HH_ERR_PROTOCOL),
    }
}

pub(crate) fn exchange_control(
    endpoint: &str,
    request: &AgentControlRequest<'_>,
) -> Result<AgentControlResponse, i32> {
    let payload = serde_json::to_vec(&request).map_err(|_| HH_ERR_PROTOCOL)?;
    if payload.len() > CONTROL_MAX_FRAME {
        return Err(HH_ERR_PROTOCOL);
    }
    let mut stream = open_control(endpoint)?;
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(&payload))
        .and_then(|_| stream.flush())
        .map_err(|_| HH_ERR_PROTOCOL)?;
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|_| HH_ERR_PROTOCOL)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > CONTROL_MAX_FRAME {
        return Err(HH_ERR_PROTOCOL);
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|_| HH_ERR_PROTOCOL)?;
    serde_json::from_slice::<AgentControlResponse>(&payload).map_err(|_| HH_ERR_PROTOCOL)
}

#[derive(Default)]
pub(crate) struct SessionState {
    pub(crate) initialized: bool,
    pub(crate) session_id: String,
    pub(crate) token: String,
    pub(crate) control_endpoint: String,
}

#[cfg(all(test, windows, feature = "gum-agent"))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::Mutex;

    static ENVIRONMENT_TEST: Mutex<()> = Mutex::new(());

    fn restore(name: &str, value: Option<OsString>) {
        unsafe {
            match value {
                Some(value) => env::set_var(name, value),
                None => env::remove_var(name),
            }
        }
    }

    #[test]
    fn managed_environment_removes_previous_keys_before_installing_snapshot() {
        let _guard = ENVIRONMENT_TEST.lock().unwrap();
        let names = [
            "HH_TEST_OLD_MANAGED",
            "HH_TEST_NEW_MANAGED",
            "HYPERHUB_SESSION_ENV_KEYS",
            "HYPERHUB_SOCKS_ADDR",
            "HYPERHUB_ENFORCEMENT_MODE",
        ];
        let previous = names.map(|name| (name, env::var_os(name)));
        unsafe {
            env::set_var("HH_TEST_OLD_MANAGED", "stale");
            env::set_var("HYPERHUB_SESSION_ENV_KEYS", r#"["HH_TEST_OLD_MANAGED"]"#);
            install_managed_environment(
                "127.0.0.1:19444",
                true,
                &[SessionEnvironmentVariable {
                    name: "HH_TEST_NEW_MANAGED".into(),
                    value: "latest".into(),
                }],
            )
            .unwrap();
        }
        assert!(env::var_os("HH_TEST_OLD_MANAGED").is_none());
        assert_eq!(env::var("HH_TEST_NEW_MANAGED").unwrap(), "latest");
        assert_eq!(env::var("HYPERHUB_SOCKS_ADDR").unwrap(), "127.0.0.1:19444");
        assert_eq!(env::var("HYPERHUB_ENFORCEMENT_MODE").unwrap(), "observe");
        for (name, value) in previous {
            restore(name, value);
        }
    }
}
