use std::env;
use std::net::{IpAddr, SocketAddr};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, Once};

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
use crate::control::install_managed_environment;
#[cfg(all(windows, feature = "gum-agent"))]
use crate::control::{bootstrap_child_control, install_inherited_environment};
use crate::control::{fetch_trust_control, SessionState};
use crate::{
    decode_first_pem_certificate, install_ca_environment, materialize_root_ca, parse_ip,
    GatewayState, HhConnectPlan, SandboxState, SocketState, TargetAddress, TrustState,
    HH_ERR_INVALID, HH_ERR_NOT_INITIALIZED, HH_ERR_PROTOCOL,
};

static RUNTIME_STATE: AtomicPtr<Mutex<AgentRuntime>> = AtomicPtr::new(null_mut());
static INITIALIZE_RUNTIME_STATE: Once = Once::new();

pub(crate) fn state() -> &'static Mutex<AgentRuntime> {
    INITIALIZE_RUNTIME_STATE.call_once(|| {
        RUNTIME_STATE.store(
            Box::into_raw(Box::new(Mutex::new(AgentRuntime::default()))),
            Ordering::Release,
        );
    });
    let pointer = RUNTIME_STATE.load(Ordering::Acquire);
    // SAFETY: the pointer is initialized once and runtime replacements intentionally leak the
    // copied pre-fork instance, so a concurrent callback never observes freed storage.
    unsafe { &*pointer }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn replace_state_after_fork(runtime: AgentRuntime) {
    let _ = state();
    let _ = RUNTIME_STATE.swap(
        Box::into_raw(Box::new(Mutex::new(runtime))),
        Ordering::AcqRel,
    );
}

pub(crate) struct AgentRuntime {
    pub(crate) session: SessionState,
    pub(crate) gateway: GatewayState,
    pub(crate) trust: TrustState,
    pub(crate) sandbox: SandboxState,
}

impl Default for AgentRuntime {
    fn default() -> Self {
        Self {
            session: SessionState::default(),
            gateway: GatewayState::default(),
            trust: TrustState::default(),
            sandbox: SandboxState::default(),
        }
    }
}

impl AgentRuntime {
    pub(crate) fn initialize_from_env(&mut self) -> Result<(), i32> {
        self.initialize_from_env_inner(true)
    }

    #[cfg(all(windows, feature = "gum-agent"))]
    pub(crate) fn initialize_after_fork(&mut self) -> Result<(), i32> {
        self.initialize_from_env_inner(false)
    }

    fn initialize_from_env_inner(&mut self, _subscribe: bool) -> Result<(), i32> {
        let inherited = (
            env::var("HYPERHUB_SESSION_ID"),
            env::var("HYPERHUB_SESSION_TOKEN"),
            env::var("HYPERHUB_SOCKS_ADDR"),
            env::var("HYPERHUB_CONTROL_ENDPOINT"),
        );
        let (session_id, token, proxy, control_endpoint, tls_ca_pem, firewall, sandbox) =
            match inherited {
                (Ok(session_id), Ok(token), Ok(_proxy), Ok(control_endpoint)) => {
                    #[cfg(all(target_os = "linux", feature = "gum-agent"))]
                    let _ = crate::register_unix_process(&control_endpoint, &session_id, &token);
                    let trust = fetch_trust_control(&control_endpoint, &session_id, &token)?;
                    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
                    // SAFETY: Agent initialization runs while the target main thread is
                    // suspended, before application code can observe the environment.
                    unsafe {
                        install_managed_environment(
                            &trust.socks_address,
                            trust.agent_flags.observe,
                            &trust.environment,
                        )?;
                    }
                    let proxy = trust
                        .socks_address
                        .parse::<SocketAddr>()
                        .map_err(|_| HH_ERR_INVALID)?;
                    (
                        session_id,
                        token,
                        proxy,
                        control_endpoint,
                        trust.tls_ca_pem,
                        trust.firewall,
                        trust.sandbox,
                    )
                }
                _ => {
                    #[cfg(all(windows, feature = "gum-agent"))]
                    {
                        let bootstrap = bootstrap_child_control()?;
                        install_inherited_environment(&bootstrap)?;
                        (
                            bootstrap.session_id,
                            bootstrap.token,
                            bootstrap
                                .socks_address
                                .parse::<SocketAddr>()
                                .map_err(|_| HH_ERR_PROTOCOL)?,
                            bootstrap.control_endpoint,
                            bootstrap.tls_ca_pem,
                            bootstrap.firewall,
                            bootstrap.sandbox,
                        )
                    }
                    #[cfg(not(all(windows, feature = "gum-agent")))]
                    {
                        return Err(HH_ERR_INVALID);
                    }
                }
            };

        let sandbox = sandbox
            .map(|snapshot| -> Result<_, i32> {
                Ok((
                    snapshot.version,
                    snapshot.network,
                    snapshot
                        .process
                        .map(crate::compile_process_snapshot)
                        .transpose()
                        .map_err(|_| HH_ERR_INVALID)?,
                    snapshot
                        .file
                        .map(crate::compile_file_snapshot)
                        .transpose()
                        .map_err(|_| HH_ERR_INVALID)?,
                ))
            })
            .transpose()?;

        self.session.initialized = true;
        self.session.session_id = session_id;
        self.session.token = token;
        self.gateway.proxy = Some(proxy);
        self.session.control_endpoint = control_endpoint;
        self.gateway.next_connection_id = 1;
        self.gateway.dns.clear();
        self.gateway.sockets.clear();
        self.gateway.nonblocking_sockets.clear();
        self.trust.tls_ca_der = decode_first_pem_certificate(&tls_ca_pem)?;
        self.trust.tls_ca_path = materialize_root_ca(&tls_ca_pem)?;
        install_ca_environment(&self.trust.tls_ca_path)?;
        self.trust.tls_ca_pem = tls_ca_pem.as_bytes().to_vec();
        self.trust.bundle_mappings.clear();
        self.sandbox.firewall = firewall.map(Arc::new);
        if let Some((version, network, process, file)) = sandbox {
            self.sandbox.firewall = network.map(Arc::new);
            self.sandbox.process.store(process.map(Arc::new));
            self.sandbox.file.store(file.map(Arc::new));
            self.sandbox
                .version
                .store(version, std::sync::atomic::Ordering::Release);
        }
        #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
        if _subscribe {
            crate::subscribe_sandbox();
        }
        Ok(())
    }

    pub(crate) fn prepare_connect(
        &mut self,
        socket: u64,
        family: i32,
        address: &[u8],
        port: u16,
    ) -> Result<HhConnectPlan, i32> {
        if !self.session.initialized {
            return Err(HH_ERR_NOT_INITIALIZED);
        }
        let proxy = self.gateway.proxy.ok_or(HH_ERR_NOT_INITIALIZED)?;
        let target_ip = parse_ip(address)?;
        if SocketAddr::new(target_ip, port) == proxy {
            return Ok(HhConnectPlan::default());
        }
        let target = self
            .gateway
            .dns
            .get(&(family, address.to_vec()))
            .cloned()
            .map(TargetAddress::Domain)
            .unwrap_or(TargetAddress::Ip(target_ip));
        let connection_id = self.gateway.next_connection_id;
        self.gateway.next_connection_id = self.gateway.next_connection_id.saturating_add(1);
        self.gateway.sockets.insert(
            socket,
            SocketState {
                connection_id,
                target,
                port,
                last_io_result: 0,
                ready_mask: 0,
                nonblocking: self.gateway.nonblocking_sockets.contains(&socket),
                handshake_complete: false,
            },
        );

        let mut plan = HhConnectPlan {
            should_intercept: 1,
            proxy_port: proxy.port(),
            connection_id,
            ..HhConnectPlan::default()
        };
        match proxy.ip() {
            IpAddr::V4(ip) => {
                plan.proxy_family = 2;
                plan.proxy_address[..4].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                // Keep the portable AF_INET6 value used by the Windows hook.
                plan.proxy_family = 10;
                plan.proxy_address.copy_from_slice(&ip.octets());
            }
        }
        Ok(plan)
    }

    pub(crate) fn handshake(&self, socket: u64, phase: u32) -> Result<Vec<u8>, i32> {
        let state = self.gateway.sockets.get(&socket).ok_or(HH_ERR_INVALID)?;
        match phase {
            0 => Ok(vec![5, 1, 2]),
            1 => {
                let username = format!(
                    "hh2:{}:{}:{}",
                    self.session.session_id,
                    std::process::id(),
                    state.connection_id
                );
                if username.len() > u8::MAX as usize || self.session.token.len() > u8::MAX as usize
                {
                    return Err(HH_ERR_PROTOCOL);
                }
                let mut out = Vec::with_capacity(username.len() + self.session.token.len() + 3);
                out.push(1);
                out.push(username.len() as u8);
                out.extend_from_slice(username.as_bytes());
                out.push(self.session.token.len() as u8);
                out.extend_from_slice(self.session.token.as_bytes());
                Ok(out)
            }
            2 => {
                let mut out = vec![5, 1, 0];
                match &state.target {
                    TargetAddress::Domain(host) => {
                        if host.len() > u8::MAX as usize {
                            return Err(HH_ERR_PROTOCOL);
                        }
                        out.push(3);
                        out.push(host.len() as u8);
                        out.extend_from_slice(host.as_bytes());
                    }
                    TargetAddress::Ip(IpAddr::V4(ip)) => {
                        out.push(1);
                        out.extend_from_slice(&ip.octets());
                    }
                    TargetAddress::Ip(IpAddr::V6(ip)) => {
                        out.push(4);
                        out.extend_from_slice(&ip.octets());
                    }
                }
                out.extend_from_slice(&state.port.to_be_bytes());
                Ok(out)
            }
            _ => Err(HH_ERR_INVALID),
        }
    }
}
