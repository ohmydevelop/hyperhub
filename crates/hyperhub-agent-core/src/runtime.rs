use rand::TryRng;
use std::env;
use std::net::SocketAddr;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
use crate::control::install_managed_environment;
#[cfg(all(windows, feature = "gum-agent"))]
use crate::control::{bootstrap_child_control, install_inherited_environment};
use crate::control::{fetch_trust_control, SessionState};
use crate::{
    decode_first_pem_certificate, install_ca_environment, materialize_root_ca, parse_ip,
    GatewayState, HhConnectPlan, SandboxState, SocketState, TrustState, HH_ERR_INVALID,
    HH_ERR_NOT_INITIALIZED, HH_ERR_PROTOCOL,
};

static RUNTIME_STATE: AtomicPtr<Mutex<AgentRuntime>> = AtomicPtr::new(null_mut());
static INITIALIZE_RUNTIME_STATE: Once = Once::new();
static SDK_ACCESS_CLOSED: AtomicBool = AtomicBool::new(false);
static STORAGE_ACCESS_CLOSED: AtomicBool = AtomicBool::new(false);
static SDK_USERS: AtomicUsize = AtomicUsize::new(0);
static HOST_USERS: AtomicUsize = AtomicUsize::new(0);
static ACCESS_EPOCH: AtomicU64 = AtomicU64::new(0);

pub(crate) struct RuntimeAccess {
    pid: u32,
    epoch: u64,
    sdk: bool,
}
fn access(sdk: bool) -> Option<RuntimeAccess> {
    let guard = RuntimeAccess {
        pid: std::process::id(),
        epoch: ACCESS_EPOCH.load(Ordering::SeqCst),
        sdk,
    };
    let users = if sdk { &SDK_USERS } else { &HOST_USERS };
    users.fetch_add(1, Ordering::SeqCst);
    if STORAGE_ACCESS_CLOSED.load(Ordering::SeqCst)
        || (sdk && SDK_ACCESS_CLOSED.load(Ordering::SeqCst))
    {
        drop(guard);
        None
    } else {
        Some(guard)
    }
}
pub(crate) fn sdk_access() -> Option<RuntimeAccess> {
    access(true)
}
pub(crate) fn host_access() -> Option<RuntimeAccess> {
    access(false)
}
pub(crate) fn close_sdk_access() -> bool {
    SDK_ACCESS_CLOSED.store(true, Ordering::SeqCst);
    SDK_USERS.load(Ordering::SeqCst) == 0
}
pub(crate) fn sdk_access_closed() -> bool {
    SDK_ACCESS_CLOSED.load(Ordering::SeqCst)
}
/// Only atomics in the copied child; a retired admission is never reopened.
pub(crate) fn after_fork_child() {
    ACCESS_EPOCH.fetch_add(1, Ordering::SeqCst);
    SDK_USERS.store(0, Ordering::SeqCst);
    HOST_USERS.store(0, Ordering::SeqCst);
}
#[cfg(test)]
pub(crate) fn access_user_counts() -> (usize, usize) {
    (
        SDK_USERS.load(Ordering::SeqCst),
        HOST_USERS.load(Ordering::SeqCst),
    )
}
#[cfg(test)]
pub(crate) fn storage_present() -> bool {
    !RUNTIME_STATE.load(Ordering::Acquire).is_null()
}
impl Drop for RuntimeAccess {
    fn drop(&mut self) {
        if self.pid == std::process::id() && self.epoch == ACCESS_EPOCH.load(Ordering::SeqCst) {
            (if self.sdk { &SDK_USERS } else { &HOST_USERS }).fetch_sub(1, Ordering::SeqCst);
        }
    }
}

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

#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn replace_state_after_fork(runtime: AgentRuntime) {
    after_fork_child();
    replace_fork_state_preserving_access(runtime);
}
/// The atfork child already abandoned copied access guards before a new Host
/// listener was created. Replacing copied Runtime storage must preserve those
/// real, process-local Host users and their access epoch.
#[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
pub(crate) fn replace_fork_state_preserving_access(runtime: AgentRuntime) {
    let _ = state();
    crate::engine_call::reset_after_fork();
    let _ = RUNTIME_STATE.swap(
        Box::into_raw(Box::new(Mutex::new(runtime))),
        Ordering::AcqRel,
    );
}

pub(crate) struct AgentRuntime {
    pub(crate) engine: Arc<hyperhub_runtime::Runtime>,
    pub(crate) session: SessionState,
    pub(crate) gateway: GatewayState,
    pub(crate) trust: TrustState,
    pub(crate) sandbox: SandboxState,
}

impl Default for AgentRuntime {
    fn default() -> Self {
        Self {
            engine: hyperhub_engine::resident(),
            session: SessionState::default(),
            gateway: GatewayState::default(),
            trust: TrustState::default(),
            sandbox: SandboxState::default(),
        }
    }
}

impl AgentRuntime {
    /// Initialize a live target from authenticated manager data. This path does
    /// not read or replace the application's environment or certificate stores.
    pub(crate) fn initialize_from_bootstrap(
        &mut self,
        bootstrap: &hyperhub_runtime::attachment::Bootstrap,
    ) -> Result<(), i32> {
        bootstrap.validate().map_err(|_| HH_ERR_INVALID)?;
        if self.session.initialized {
            return Err(HH_ERR_PROTOCOL);
        }
        let firewall = bootstrap
            .firewall
            .clone()
            .map(serde_json::from_value::<crate::FirewallSnapshot>)
            .transpose()
            .map_err(|_| HH_ERR_INVALID)?;
        let sandbox = bootstrap
            .sandbox
            .clone()
            .map(serde_json::from_value::<crate::SandboxSnapshot>)
            .transpose()
            .map_err(|_| HH_ERR_INVALID)?;
        let process = sandbox
            .as_ref()
            .and_then(|value| value.process.clone())
            .map(crate::compile_process_snapshot)
            .transpose()
            .map_err(|_| HH_ERR_INVALID)?;
        let file = sandbox
            .as_ref()
            .and_then(|value| value.file.clone())
            .map(crate::compile_file_snapshot)
            .transpose()
            .map_err(|_| HH_ERR_INVALID)?;
        let ca_der = decode_first_pem_certificate(&bootstrap.tls_ca_pem)?;
        let connection_id_seed = rand::rngs::SysRng
            .try_next_u64()
            .map_err(|_| HH_ERR_PROTOCOL)?;
        self.gateway.namespace = crate::alias_namespace::Namespace::from_bootstrap(bootstrap);
        self.session.session_id = bootstrap.session_id.clone();
        self.session.token = bootstrap.token.clone();
        self.session.control_endpoint = bootstrap.control_endpoint.clone();
        self.gateway.proxy = Some(
            bootstrap
                .socks_address
                .parse()
                .map_err(|_| HH_ERR_INVALID)?,
        );
        self.gateway.next_connection_id = 1 + (connection_id_seed & (u64::MAX >> 1));
        self.trust.tls_ca_der = ca_der;
        self.trust.tls_ca_pem = bootstrap.tls_ca_pem.as_bytes().to_vec();
        self.sandbox.firewall = firewall.map(Arc::new);
        if let Some(snapshot) = sandbox {
            self.sandbox.firewall = snapshot.network.map(Arc::new);
            self.sandbox.process.store(process.map(Arc::new));
            self.sandbox.file.store(file.map(Arc::new));
            self.sandbox
                .version
                .store(snapshot.version, Ordering::Release);
        }
        self.session.initialized = true;
        Ok(())
    }

    pub(crate) fn initialize_from_env(
        &mut self,
        deadline: &crate::control::StartupDeadline,
    ) -> Result<(), i32> {
        self.initialize_from_env_inner(true, deadline)
    }

    #[cfg(all(windows, feature = "gum-agent"))]
    pub(crate) fn initialize_after_fork(
        &mut self,
        deadline: &crate::control::StartupDeadline,
    ) -> Result<(), i32> {
        self.initialize_from_env_inner(false, deadline)
    }

    fn initialize_from_env_inner(
        &mut self,
        _subscribe: bool,
        deadline: &crate::control::StartupDeadline,
    ) -> Result<(), i32> {
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
                    crate::register_unix_process(&control_endpoint, &session_id, &token, deadline)?;
                    let trust =
                        fetch_trust_control(&control_endpoint, &session_id, &token, deadline)?;
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
                        let bootstrap = bootstrap_child_control(deadline)?;
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

        // Read directly from the OS before Hook installation, without a
        // destructible ThreadRng TLS slot or an infallible RNG panic path.
        let connection_id_seed = rand::rngs::SysRng
            .try_next_u64()
            .map_err(|_| HH_ERR_PROTOCOL)?;
        self.session.initialized = true;
        self.session.session_id = session_id;
        self.session.token = token;
        self.gateway.proxy = Some(proxy);
        self.session.control_endpoint = control_endpoint;
        // Initialization runs before Hook installation. A new exec image must
        // not reuse claims belonging to inherited, still-open TCP streams.
        // Leave at least half the u64 space available for monotonic allocation;
        // no RNG or new thread-local state is needed on the Hook path.
        self.gateway.next_connection_id = 1 + (connection_id_seed & (u64::MAX >> 1));
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
        Ok(())
    }

    pub(crate) fn record_dns(&mut self, hostname: String, address: &[u8]) -> Result<(), i32> {
        let ip = parse_ip(address)?;
        if !self.session.initialized {
            return Err(HH_ERR_NOT_INITIALIZED);
        }
        if !crate::attachment::enforcing() {
            return self.gateway.observe_dns(ip, hostname, false);
        }
        let hostname =
            hyperhub_engine::normalize(&crate::engine_call::calling(&self.engine)?, &hostname)
                .map_err(engine_error)?;
        self.gateway
            .observe_dns(ip, hostname, crate::attachment::enforcing())
    }

    pub(crate) fn prepare_connect(
        &mut self,
        socket: u64,
        _family: i32,
        address: &[u8],
        port: u16,
    ) -> Result<HhConnectPlan, i32> {
        if !self.session.initialized {
            return Err(HH_ERR_NOT_INITIALIZED);
        }
        let target_ip = parse_ip(address)?;
        let identity = hyperhub_runtime::attachment::canonical_alias_address(target_ip);
        if !crate::attachment::enforcing() {
            return self
                .gateway
                .native_alias_plan(target_ip, port)
                .map(|plan| plan.unwrap_or_default());
        }
        if self.gateway.issued_aliases.contains_key(&identity)
            && self.gateway.ambiguous_aliases.contains(&identity)
        {
            return Err(crate::HH_ERR_ALIAS_CONFLICT);
        }
        let proxy = self.gateway.proxy.ok_or(HH_ERR_NOT_INITIALIZED)?;
        let engine = crate::engine_call::calling(&self.engine)?;
        let decision = hyperhub_engine::connect(
            &engine,
            &hyperhub_engine::contract::ConnectInput {
                proxy,
                ip: target_ip,
                port,
                hostname: self.gateway.issued_hostname(target_ip),
            },
        )
        .map_err(engine_error)?;
        if !decision.intercept {
            return Ok(HhConnectPlan::default());
        }
        let target = decision.target;
        let connection_id = self.gateway.next_connection_id;
        if connection_id == 0 {
            return Err(HH_ERR_PROTOCOL);
        }
        self.gateway.next_connection_id = self
            .gateway
            .next_connection_id
            .checked_add(1)
            .ok_or(HH_ERR_PROTOCOL)?;
        self.gateway.sockets.insert(
            socket,
            SocketState {
                engine,
                connection_id,
                target,
                port,
                last_io_result: 0,
                ready_mask: 0,
                nonblocking: self.gateway.nonblocking_sockets.contains(&socket),
                handshake_complete: false,
            },
        );

        Ok(HhConnectPlan {
            should_intercept: 1,
            proxy_port: decision.port,
            connection_id,
            proxy_family: decision.family,
            proxy_address: decision.address,
            ..HhConnectPlan::default()
        })
    }

    pub(crate) fn handshake(&self, socket: u64, phase: u32) -> Result<Vec<u8>, i32> {
        let state = self.gateway.sockets.get(&socket).ok_or(HH_ERR_INVALID)?;
        hyperhub_engine::handshake(
            &state.engine,
            &hyperhub_engine::contract::HandshakeInput {
                phase,
                username: format!(
                    "hh2:{}:{}:{}",
                    self.session.session_id,
                    std::process::id(),
                    state.connection_id
                ),
                password: self.session.token.as_bytes().to_vec(),
                target: state.target.clone(),
                port: state.port,
            },
        )
        .map_err(engine_error)
    }
}

pub(crate) fn engine_error(error: i32) -> i32 {
    match error {
        hyperhub_engine::contract::INVALID => HH_ERR_INVALID,
        hyperhub_engine::contract::CAPACITY => crate::HH_ERR_BUFFER_TOO_SMALL,
        _ => HH_ERR_PROTOCOL,
    }
}

/// Requires restored native entrypoints, stopped workers and retired OS TLS.
/// No caller may access state() after this final native-base retirement.
pub(crate) unsafe fn retire_attachment_state() -> Result<(), i32> {
    SDK_ACCESS_CLOSED.store(true, Ordering::SeqCst);
    STORAGE_ACCESS_CLOSED.store(true, Ordering::SeqCst);
    if SDK_USERS.load(Ordering::SeqCst) != 0 || HOST_USERS.load(Ordering::SeqCst) != 0 {
        return Err(HH_ERR_PROTOCOL);
    }
    let pointer = RUNTIME_STATE.swap(null_mut(), Ordering::AcqRel);
    if !pointer.is_null() {
        drop(Box::from_raw(pointer));
    }
    Ok(())
}
