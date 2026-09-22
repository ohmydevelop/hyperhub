use crate::audit::AuditWriter;
use crate::client_proxy::{
    complete_socks5_connect, is_socks5_greeting, negotiate_socks5, resolve_socks5_target,
    write_socks5_reply,
};
use crate::config::{Config, EnforcementMode, Upstream, UpstreamKind};
use crate::connector::{connect_direct, connect_upstream, EnvironmentProxy};
use crate::duplex::PrefixedIo;
use crate::firewall::{compile_snapshot as compile_firewall_snapshot, decide as decide_firewall};
use crate::http::{proxy_http, proxy_https_via_tunneled_upstream, TlsMitm};
use crate::inspect;
use crate::policy::{ConnectionContext, Destination, ProcessInfo, Protocol};
use crate::protocol::{
    classify_ingress, run_stack, ConnectedUpstream, HandlerContext, IngressTransport,
    UpstreamTransport,
};
use crate::runtime::RuntimeState;
use crate::session::{
    unix_timestamp_ms, AuthenticatedSession, ClientProxySnapshot, ConnectionRegistry,
    ConnectionSnapshot, SessionRegistry,
};
use rustls::pki_types::CertificateDer;
use serde_json::json;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};

const SOCKS_VERSION: u8 = 5;
const AUTH_USERPASS: u8 = 2;
const LEARNED_PROXY_TIMEOUT_MS: u64 = 10_000;
const LEARNED_PROXY_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct ProxyAffinityKey {
    session_id: String,
    hostname: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct LearnedProxy {
    upstream: Upstream,
    snapshot: ClientProxySnapshot,
    observed_at: SystemTime,
}

#[derive(Clone, Default)]
struct SessionProxyAffinity(Arc<Mutex<std::collections::HashMap<ProxyAffinityKey, LearnedProxy>>>);

impl SessionProxyAffinity {
    fn remember(
        &self,
        session_id: &str,
        destination: &Destination,
        proxy_protocol: &str,
        proxy_address: String,
    ) {
        let kind = match proxy_protocol {
            "http" => UpstreamKind::HttpConnect,
            "socks5" => UpstreamKind::Socks5,
            _ => return,
        };
        let proxy = LearnedProxy {
            upstream: Upstream {
                uuid: crate::config::new_config_uuid(),
                id: "observed-client-proxy".into(),
                kind,
                address: proxy_address.clone(),
                timeout_ms: LEARNED_PROXY_TIMEOUT_MS,
                username: None,
                password: None,
                headers: Default::default(),
            },
            snapshot: ClientProxySnapshot {
                protocol: proxy_protocol.into(),
                address: proxy_address,
            },
            observed_at: SystemTime::now(),
        };
        let Ok(mut proxies) = self.0.lock() else {
            return;
        };
        proxies.retain(|_, value| {
            value
                .observed_at
                .elapsed()
                .is_ok_and(|age| age <= LEARNED_PROXY_MAX_AGE)
        });
        for hostname in &destination.hostnames {
            proxies.insert(
                ProxyAffinityKey {
                    session_id: session_id.into(),
                    hostname: normalize_hostname(hostname),
                    port: destination.port,
                },
                proxy.clone(),
            );
        }
    }

    fn lookup(&self, session_id: &str, destination: &Destination) -> Option<LearnedProxy> {
        let proxies = self.0.lock().ok()?;
        destination.hostnames.iter().find_map(|hostname| {
            proxies
                .get(&ProxyAffinityKey {
                    session_id: session_id.into(),
                    hostname: normalize_hostname(hostname),
                    port: destination.port,
                })
                .filter(|value| {
                    value
                        .observed_at
                        .elapsed()
                        .is_ok_and(|age| age <= LEARNED_PROXY_MAX_AGE)
                })
                .cloned()
        })
    }
}

struct ListenerCommand {
    address: SocketAddr,
    response: oneshot::Sender<io::Result<()>>,
}

/// Controls the SOCKS5 addresses accepted by a running [`SocksService`].
///
/// Newly added listeners are retained until the service stops so sessions that
/// were bootstrapped with an older address can continue to open connections.
#[derive(Clone)]
pub struct SocksListenerController {
    sender: mpsc::Sender<ListenerCommand>,
    address: Arc<RwLock<Option<SocketAddr>>>,
}

impl SocksListenerController {
    pub fn address(&self) -> Option<SocketAddr> {
        self.address.read().ok().and_then(|address| *address)
    }

    pub async fn ensure_listener(&self, address: &str) -> io::Result<()> {
        let address = address.parse::<SocketAddr>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid SOCKS5 listen address '{address}': {error}"),
            )
        })?;
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(ListenerCommand { address, response })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "SOCKS5 listener service is not running",
                )
            })?;
        receiver.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SOCKS5 listener service stopped before applying the update",
            )
        })?
    }
}

#[derive(Clone)]
pub struct SocksService {
    runtime: RuntimeState,
    sessions: SessionRegistry,
    audit: AuditWriter,
    tls_mitm: Arc<TlsMitm>,
    ssh_mitm_key: Arc<russh::keys::PrivateKey>,
    environment_proxy: EnvironmentProxy,
    proxy_affinity: SessionProxyAffinity,
    connections: ConnectionRegistry,
    listener_controller: SocksListenerController,
    listener_commands: Arc<Mutex<Option<mpsc::Receiver<ListenerCommand>>>>,
    initial_listener: Arc<Mutex<Option<TcpListener>>>,
    bound_address: Arc<RwLock<Option<SocketAddr>>>,
    trust: Option<Arc<crate::trust::TrustStore>>,
}

impl SocksService {
    pub fn new(config: Arc<Config>, sessions: SessionRegistry) -> io::Result<Self> {
        Self::new_with_debug(config, sessions, false)
    }

    pub fn new_with_debug(
        config: Arc<Config>,
        sessions: SessionRegistry,
        debug: bool,
    ) -> io::Result<Self> {
        let mut master = [0u8; 32];
        rand::fill(&mut master);
        Self::new_with_debug_output(config, sessions, Vec::new(), debug, None, &master)
    }

    pub fn new_with_debug_output(
        config: Arc<Config>,
        sessions: SessionRegistry,
        root_certificates: Vec<CertificateDer<'static>>,
        debug: bool,
        debug_output: Option<&Path>,
        ssh_mitm_master: &[u8],
    ) -> io::Result<Self> {
        let environment_proxy = EnvironmentProxy::from_env()?;
        Self::with_environment_debug(
            config,
            sessions,
            environment_proxy,
            root_certificates,
            debug,
            debug_output,
            ssh_mitm_master,
        )
    }

    pub fn audit_writer(&self) -> AuditWriter {
        self.audit.clone()
    }

    #[cfg(test)]
    fn with_environment(
        config: Arc<Config>,
        sessions: SessionRegistry,
        environment_proxy: EnvironmentProxy,
    ) -> io::Result<Self> {
        Self::with_environment_debug(
            config,
            sessions,
            environment_proxy,
            Vec::new(),
            false,
            None,
            b"test-ssh-mitm-master",
        )
    }

    fn with_environment_debug(
        config: Arc<Config>,
        sessions: SessionRegistry,
        environment_proxy: EnvironmentProxy,
        root_certificates: Vec<CertificateDer<'static>>,
        debug: bool,
        debug_output: Option<&Path>,
        ssh_mitm_master: &[u8],
    ) -> io::Result<Self> {
        let tls_mitm = TlsMitm::generate_with_root_certificates(root_certificates)?;
        let runtime = RuntimeState::new(config.clone()).map_err(io::Error::other)?;
        let (listener_sender, listener_commands) = mpsc::channel(8);
        let bound_address = Arc::new(RwLock::new(None));
        Ok(Self {
            audit: AuditWriter::open_with_retention(
                config.audit.log.as_deref(),
                config.audit.transcript_dir.as_deref(),
                config.audit.retention_days,
                debug,
                debug_output,
            )?,
            runtime,
            sessions,
            tls_mitm,
            ssh_mitm_key: Arc::new(crate::ssh_mitm::server_key_from_master(ssh_mitm_master)),
            environment_proxy,
            proxy_affinity: SessionProxyAffinity::default(),
            connections: ConnectionRegistry::default(),
            listener_controller: SocksListenerController {
                sender: listener_sender,
                address: bound_address.clone(),
            },
            listener_commands: Arc::new(Mutex::new(Some(listener_commands))),
            initial_listener: Arc::new(Mutex::new(None)),
            bound_address,
            trust: None,
        })
    }

    pub fn with_trust_store(mut self, trust: Arc<crate::trust::TrustStore>) -> Self {
        self.trust = Some(trust);
        self
    }

    pub fn tls_ca_pem(&self) -> &str {
        self.tls_mitm.ca_pem()
    }

    /// 共享运行时快照：CLI 热更新配置时经 `RuntimeState::apply` 替换。
    pub fn runtime(&self) -> RuntimeState {
        self.runtime.clone()
    }

    pub fn connections(&self) -> ConnectionRegistry {
        self.connections.clone()
    }

    pub fn listener_controller(&self) -> SocksListenerController {
        self.listener_controller.clone()
    }

    pub async fn prepare_listener(&self) -> io::Result<SocketAddr> {
        let requested = self.requested_listener_address()?;
        let listener = bind_listener(requested).await?;
        let address = listener.local_addr()?;
        let mut initial = self
            .initial_listener
            .lock()
            .map_err(|_| io::Error::other("initial SOCKS5 listener is poisoned"))?;
        if initial.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "initial SOCKS5 listener is already prepared",
            ));
        }
        *initial = Some(listener);
        drop(initial);
        self.set_bound_address(address)?;
        Ok(address)
    }

    pub async fn run(self) -> io::Result<()> {
        let mut commands = self
            .listener_commands
            .lock()
            .map_err(|_| io::Error::other("SOCKS5 listener controller is poisoned"))?
            .take()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "SOCKS5 service is already running",
                )
            })?;
        let initial_listener = self
            .initial_listener
            .lock()
            .map_err(|_| io::Error::other("initial SOCKS5 listener is poisoned"))?
            .take();
        let initial_listener = match initial_listener {
            Some(listener) => listener,
            None => {
                let requested = self.requested_listener_address()?;
                bind_listener(requested).await?
            }
        };
        let initial_address = initial_listener.local_addr()?;
        self.set_bound_address(initial_address)?;
        let mut active_addresses = HashSet::from([initial_address]);
        let mut listeners = JoinSet::new();
        self.spawn_listener(&mut listeners, initial_listener);

        loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "SOCKS5 listener controller stopped",
                        ));
                    };
                    let result = if active_addresses.contains(&command.address) {
                        Ok(())
                    } else {
                        match bind_listener(command.address).await {
                            Ok(listener) => match listener.local_addr() {
                                Ok(address) => {
                                    active_addresses.insert(address);
                                    self.spawn_listener(&mut listeners, listener);
                                    let _ = self.set_bound_address(address);
                                    Ok(())
                                }
                                Err(error) => Err(error),
                            },
                            Err(error) => Err(error),
                        }
                    };
                    let _ = command.response.send(result);
                }
                result = listeners.join_next() => {
                    return match result {
                        Some(Ok(Err(error))) => Err(error),
                        Some(Ok(Ok(()))) => Err(io::Error::other(
                            "SOCKS5 listener stopped unexpectedly",
                        )),
                        Some(Err(error)) => Err(io::Error::other(format!(
                            "SOCKS5 listener task failed: {error}",
                        ))),
                        None => Err(io::Error::other("SOCKS5 has no active listeners")),
                    };
                }
            }
        }
    }

    fn spawn_listener(&self, listeners: &mut JoinSet<io::Result<()>>, listener: TcpListener) {
        let service = self.clone();
        listeners.spawn(async move { service.run_listener(listener).await });
    }

    fn requested_listener_address(&self) -> io::Result<SocketAddr> {
        self.runtime
            .snapshot()
            .config
            .listener
            .socks_listen
            .parse::<SocketAddr>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    fn set_bound_address(&self, address: SocketAddr) -> io::Result<()> {
        *self
            .bound_address
            .write()
            .map_err(|_| io::Error::other("bound SOCKS5 address is poisoned"))? = Some(address);
        Ok(())
    }

    async fn run_listener(self, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            if !peer.ip().is_loopback() {
                drop(stream);
                continue;
            }
            let service = self.clone();
            let audit = service.audit.clone();
            tokio::spawn(async move {
                if let Err(error) = service.handle(stream).await {
                    audit.system_event(
                        "socks_connection_error",
                        json!({
                            "error_kind": format!("{:?}", error.kind()),
                            "message": error.to_string(),
                        }),
                    );
                }
            });
        }
    }

    async fn handle(self, mut client: TcpStream) -> io::Result<()> {
        let session = authenticate(&mut client, self.sessions.clone()).await?;
        let cancellation = session.cancellation.clone();
        tokio::select! {
            result = self.handle_authenticated(client, session) => result,
            _ = cancellation.cancelled() => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "session root process exited or the session was revoked",
            )),
        }
    }

    async fn handle_authenticated(
        self,
        mut client: TcpStream,
        session: AuthenticatedSession,
    ) -> io::Result<()> {
        let mut requested = match read_connect_request(&mut client).await {
            Ok(destination) => destination,
            Err(error) => {
                let _ = write_reply(&mut client, 8).await;
                return Err(error);
            }
        };
        if requested.hostnames.is_empty() {
            if let Some(hostname) = self
                .sessions
                .restore_fake(&session.session_id, requested.ip)
            {
                requested.ip = tokio::net::lookup_host((hostname.as_str(), requested.port))
                    .await?
                    .next()
                    .map(|address| address.ip())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "fake-IP hostname resolved to no addresses",
                        )
                    })?;
                requested.hostnames.push(hostname);
            } else if is_fake_ip(requested.ip) {
                write_reply(&mut client, 4).await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unknown or expired session Fake-IP",
                ));
            }
        }
        let mut context = ConnectionContext {
            session_id: session.session_id.clone(),
            connection_id: session.connection_id,
            process: ProcessInfo {
                pid: session.pid,
                tid: session.pid,
                executable: session.executable.clone(),
            },
            destination: requested.clone(),
            protocol: Protocol::Unknown,
        };
        let now = unix_timestamp_ms();
        let active = self.connections.track(ConnectionSnapshot {
            session_id: context.session_id.clone(),
            connection_id: context.connection_id,
            pid: context.process.pid,
            executable: context.process.executable.clone(),
            original_destination: requested.clone(),
            destination: context.destination.clone(),
            protocol: context.protocol,
            rule_id: None,
            action: "pending".into(),
            route_upstream: None,
            client_proxy: None,
            phase: "routing".into(),
            started_at_ms: now,
            updated_at_ms: now,
        });
        // 连接级快照：热更新只影响新连接，当前连接全程使用本次快照。
        let runtime = self.runtime.snapshot();
        let config = runtime.config;
        let policy = runtime.policy;
        let protection = runtime.protection;
        let firewall = compile_firewall_snapshot(&config, runtime.updated_at_ms)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if let Some(snapshot) = firewall.as_ref() {
            let firewall_decision =
                decide_firewall(snapshot, &requested.hostnames, requested.ip, requested.port);
            if firewall_decision.action == crate::config::FirewallAction::Deny {
                active.update(
                    &requested,
                    context.protocol,
                    firewall_decision.rule_id.as_deref(),
                    "deny",
                    None,
                    None,
                    "firewall-denied",
                );
                write_reply(&mut client, 2).await?;
                self.audit.session_event(
                    "firewall_denied",
                    &session.session_id,
                    Some(session.pid),
                    Some(&session.executable),
                    json!({
                        "decision": "deny",
                        "rule_id": firewall_decision.rule_id,
                        "decision_source": firewall_decision.source,
                        "stage": "connect",
                        "hostname": requested.hostnames.first(),
                        "ip": requested.ip,
                        "port": requested.port,
                        "process_tid": session.pid,
                        "snapshot_version": snapshot.version,
                    }),
                );
                return Ok(());
            }
            if firewall_decision.action != crate::config::FirewallAction::Deny {
                if let Some(profile_id) = firewall_decision.protection.as_deref() {
                    let destination = requested
                        .hostnames
                        .first()
                        .cloned()
                        .unwrap_or_else(|| requested.ip.to_string());
                    let outcome = protection
                        .evaluate_agent(
                            profile_id,
                            &session.session_id,
                            session.pid,
                            &session.executable,
                            "network_connect",
                            vec![format!("{destination}:{}", requested.port)],
                            vec!["network_egress".into()],
                            serde_json::json!({
                                "destination_authorized": false,
                                "hostname": requested.hostnames.first(),
                                "ip": requested.ip,
                                "port": requested.port,
                            }),
                        )
                        .await;
                    let provider = outcome
                        .provider
                        .as_ref()
                        .filter(|item| item.error.is_none());
                    let action = if outcome.deny { "deny" } else { "pass" };
                    self.audit.session_event(
                        "smart_protection_decision",
                        &session.session_id,
                        Some(session.pid),
                        Some(&session.executable),
                        json!({
                            "protection": profile_id,
                            "rule_id": firewall_decision.rule_id,
                            "stage": "network_connect",
                            "action": action,
                            "reason": outcome.reason,
                            "features": ["network_egress"],
                            "risk_level": provider.and_then(|item| item.risk_level.clone()),
                            "confidence": provider.and_then(|item| item.confidence),
                            "destructive_probability": provider.and_then(|item| item.destructive_probability),
                            "blast_radius": provider.and_then(|item| item.blast_radius),
                            "cache_hit": provider.is_some_and(|item| item.cache_hit),
                            "reporter": "gateway-firewall",
                        }),
                    );
                    if outcome.deny {
                        active.update(
                            &requested,
                            context.protocol,
                            firewall_decision.rule_id.as_deref(),
                            "deny",
                            None,
                            None,
                            "smart-firewall-denied",
                        );
                        write_reply(&mut client, 2).await?;
                        return Ok(());
                    }
                }
            }
        }
        let mut decision = policy.decide(&context);
        if decision.smart {
            if let Some(profile_id) = decision.protection.as_deref() {
                let destination = requested
                    .hostnames
                    .first()
                    .cloned()
                    .unwrap_or_else(|| requested.ip.to_string());
                let outcome = protection
                    .evaluate_agent(
                        profile_id,
                        &session.session_id,
                        session.pid,
                        &session.executable,
                        "route_connect",
                        vec![format!("{destination}:{}", requested.port)],
                        vec!["smart_route".into()],
                        json!({
                            "destination_authorized": false,
                            "hostname": requested.hostnames.first(),
                            "ip": requested.ip,
                            "port": requested.port,
                        }),
                    )
                    .await;
                self.audit.session_event(
                    "smart_protection_decision",
                    &session.session_id,
                    Some(session.pid),
                    Some(&session.executable),
                    json!({
                        "protection": profile_id,
                        "rule_id": decision.rule_id,
                        "stage": "route_connect",
                        "action": if outcome.deny { "deny" } else { "pass" },
                        "reason": outcome.reason,
                        "provider": outcome.provider,
                    }),
                );
                decision.deny = outcome.deny;
            }
        }
        active.update(
            &decision.destination,
            context.protocol,
            decision.rule_id.as_deref(),
            action_name(decision.deny, decision.upstream.is_some()),
            decision.upstream.as_deref(),
            None,
            "authorized",
        );
        if decision.deny {
            active.update(
                &decision.destination,
                context.protocol,
                decision.rule_id.as_deref(),
                "deny",
                decision.upstream.as_deref(),
                None,
                "denied",
            );
            write_reply(&mut client, 2).await?;
            self.audit.connection(
                "authorize",
                &context,
                decision.rule_id.as_deref(),
                "deny",
                "denied",
                None,
                None,
                None,
            );
            return Ok(());
        }

        let started = Instant::now();
        active.update(
            &decision.destination,
            context.protocol,
            decision.rule_id.as_deref(),
            action_name(decision.deny, decision.upstream.is_some()),
            decision.upstream.as_deref(),
            None,
            "connecting_upstream",
        );
        let upstream_result = self
            .connect_for(
                &config,
                &session.session_id,
                &decision.destination,
                decision.upstream.as_deref(),
            )
            .await;
        let (mut upstream, mut associated_client_proxy, mut upstream_transport) =
            match upstream_result {
                Ok(connected) => (
                    connected.stream,
                    connected.associated_client_proxy,
                    connected.transport,
                ),
                Err(error) if config.mode == EnforcementMode::Observe => {
                    self.audit.connection(
                        "fail_open",
                        &context,
                        decision.rule_id.as_deref(),
                        action_name(decision.deny, decision.upstream.is_some()),
                        "direct_fallback",
                        None,
                        Some(started.elapsed().as_millis()),
                        Some(json!({"message": error.to_string()})),
                    );
                    (
                        connect_direct(requested.clone()).await?,
                        None,
                        UpstreamTransport::Direct,
                    )
                }
                Err(error) => {
                    write_reply(&mut client, reply_code(&error)).await?;
                    self.audit.connection(
                        "connect",
                        &context,
                        decision.rule_id.as_deref(),
                        action_name(decision.deny, decision.upstream.is_some()),
                        "failed",
                        None,
                        Some(started.elapsed().as_millis()),
                        Some(json!({"message": error.to_string()})),
                    );
                    return Err(error);
                }
            };
        write_reply(&mut client, 0).await?;
        active.update(
            &decision.destination,
            context.protocol,
            decision.rule_id.as_deref(),
            action_name(decision.deny, decision.upstream.is_some()),
            decision.upstream.as_deref(),
            None,
            "inspecting_protocol",
        );

        let mut peek = vec![0u8; 16 * 1024];
        let mut count = timeout(Duration::from_millis(300), client.peek(&mut peek))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(0);
        let mut inspection = inspect::inspect(&peek[..count], requested.port);
        let mut client_proxy_protocol = None;
        let mut upstream_replaced = false;

        if is_socks5_greeting(&peek[..count]) {
            let target = negotiate_socks5(&mut client, &mut upstream).await?;
            context.destination =
                match resolve_socks5_target(target, &session.session_id, &self.sessions).await {
                    Ok(destination) => destination,
                    Err(error) => {
                        write_socks5_reply(&mut client, reply_code(&error)).await?;
                        return Err(error);
                    }
                };
            decision = policy.decide(&context);
            if decision.deny {
                write_socks5_reply(&mut client, 2).await?;
                self.audit.connection(
                    "authorize",
                    &context,
                    decision.rule_id.as_deref(),
                    "deny",
                    "denied",
                    None,
                    None,
                    Some(json!({
                        "client_proxy": format!("{}:{}", requested.ip, requested.port),
                        "client_proxy_protocol": "socks5",
                        "preserved": true,
                    })),
                );
                return Ok(());
            }
            if decision.upstream.is_some() {
                let connected = match self
                    .connect_for(
                        &config,
                        &session.session_id,
                        &decision.destination,
                        decision.upstream.as_deref(),
                    )
                    .await
                {
                    Ok(connected) => connected,
                    Err(error) if config.mode == EnforcementMode::Observe => {
                        self.audit.connection(
                            "fail_open",
                            &context,
                            decision.rule_id.as_deref(),
                            action_name(decision.deny, decision.upstream.is_some()),
                            "direct_fallback",
                            None,
                            Some(started.elapsed().as_millis()),
                            Some(json!({"message": error.to_string()})),
                        );
                        ConnectedUpstream {
                            stream: connect_direct(decision.destination.clone()).await?,
                            transport: UpstreamTransport::Direct,
                            associated_client_proxy: None,
                        }
                    }
                    Err(error) => {
                        self.audit.connection(
                            "connect",
                            &context,
                            decision.rule_id.as_deref(),
                            action_name(decision.deny, decision.upstream.is_some()),
                            "failed",
                            None,
                            Some(started.elapsed().as_millis()),
                            Some(json!({"message": error.to_string()})),
                        );
                        write_socks5_reply(&mut client, reply_code(&error)).await?;
                        return Err(error);
                    }
                };
                upstream = connected.stream;
                upstream_transport = connected.transport;
                associated_client_proxy = None;
                upstream_replaced = true;
                write_socks5_reply(&mut client, 0).await?;
            } else if !complete_socks5_connect(&mut client, &mut upstream, &decision.destination)
                .await?
            {
                self.audit.connection(
                    "connect",
                    &context,
                    decision.rule_id.as_deref(),
                    action_name(decision.deny, decision.upstream.is_some()),
                    "client_proxy_rejected",
                    None,
                    Some(started.elapsed().as_millis()),
                    Some(json!({
                        "client_proxy": format!("{}:{}", requested.ip, requested.port),
                        "client_proxy_protocol": "socks5",
                        "preserved": true,
                    })),
                );
                return Ok(());
            }
            client_proxy_protocol = Some("socks5");
            count = timeout(Duration::from_millis(300), client.peek(&mut peek))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0);
            inspection = inspect::inspect(&peek[..count], context.destination.port);
        }
        if let Some(host) = inspection.hostname.as_ref() {
            if !context
                .destination
                .hostnames
                .iter()
                .any(|value| value.eq_ignore_ascii_case(host))
            {
                context.destination.hostnames.push(host.clone());
            }
        }
        if inspection.protocol != Protocol::Unknown {
            context.protocol = inspection.protocol;
        }
        // IP-form SOCKS requests (the ptrace baseline) may only reveal the hostname in
        // the first TLS/HTTP bytes. Re-run connection policy before those bytes are
        // consumed so host routes can enable MITM, credentials, deny, rewrites, or an
        // upstream without depending on libc-level DNS hooks.
        let refined = policy.decide(&context);
        if refined.rule_id != decision.rule_id {
            if refined.deny {
                active.update(
                    &refined.destination,
                    context.protocol,
                    refined.rule_id.as_deref(),
                    "deny",
                    refined.upstream.as_deref(),
                    None,
                    "protocol-refined-denied",
                );
                self.audit.connection(
                    "authorize",
                    &context,
                    refined.rule_id.as_deref(),
                    "deny",
                    "denied",
                    None,
                    None,
                    inspection.detail.clone(),
                );
                return Ok(());
            }
            let reconnect = refined.upstream != decision.upstream
                || refined.destination.ip != context.destination.ip
                || refined.destination.port != context.destination.port
                || refined.destination.hostnames != context.destination.hostnames;
            if reconnect {
                let connected = match self
                    .connect_for(
                        &config,
                        &session.session_id,
                        &refined.destination,
                        refined.upstream.as_deref(),
                    )
                    .await
                {
                    Ok(connected) => connected,
                    Err(error) if config.mode == EnforcementMode::Observe => {
                        self.audit.connection(
                            "fail_open",
                            &context,
                            refined.rule_id.as_deref(),
                            action_name(refined.deny, refined.upstream.is_some()),
                            "direct_fallback",
                            None,
                            Some(started.elapsed().as_millis()),
                            Some(json!({"message": error.to_string(), "stage": "protocol_refine"})),
                        );
                        ConnectedUpstream {
                            stream: connect_direct(refined.destination.clone()).await?,
                            transport: UpstreamTransport::Direct,
                            associated_client_proxy: None,
                        }
                    }
                    Err(error) => {
                        self.audit.connection(
                            "connect",
                            &context,
                            refined.rule_id.as_deref(),
                            action_name(refined.deny, refined.upstream.is_some()),
                            "failed",
                            None,
                            Some(started.elapsed().as_millis()),
                            Some(json!({"message": error.to_string(), "stage": "protocol_refine"})),
                        );
                        return Err(error);
                    }
                };
                upstream = connected.stream;
                upstream_transport = connected.transport;
                associated_client_proxy = connected.associated_client_proxy;
                upstream_replaced = true;
            }
            decision = refined;
            active.update(
                &decision.destination,
                context.protocol,
                decision.rule_id.as_deref(),
                action_name(decision.deny, decision.upstream.is_some()),
                decision.upstream.as_deref(),
                None,
                "protocol-refined",
            );
        } else {
            decision = refined;
        }
        // 统一入站分类：客户端对原对端说了什么协议，serve 对原对端就说什么协议。
        // 外层代理协议（HTTP CONNECT、SOCKS5、absolute-form）在此保留，MITM 只替换最内层。
        let ingress = classify_ingress(&peek[..count], context.destination.port);
        if ingress == IngressTransport::HttpConnect
            || (ingress == IngressTransport::PlainHttp && inspection.proxy_form)
        {
            // HTTP 客户端代理：CONNECT 或 absolute-form 的目标才是审计对象，先解析目标再重新决策。
            client_proxy_protocol = Some("http");
            let host = inspection.hostname.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP proxy request has no target hostname",
                )
            })?;
            let port = inspection.port.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP proxy request has no target port",
                )
            })?;
            let ip = tokio::net::lookup_host((host.as_str(), port))
                .await?
                .next()
                .map(|address| address.ip())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "HTTP proxy target resolved to no addresses",
                    )
                })?;
            context.destination = Destination {
                ip,
                port,
                hostnames: vec![host],
            };
            context.protocol = if ingress == IngressTransport::HttpConnect {
                Protocol::Tls
            } else {
                inspection.protocol
            };
            decision = policy.decide(&context);
            if decision.deny {
                self.audit.connection(
                    "authorize",
                    &context,
                    decision.rule_id.as_deref(),
                    "deny",
                    "denied",
                    None,
                    None,
                    inspection.detail.clone(),
                );
                return Ok(());
            }
            if decision.upstream.is_some() {
                let connected = match self
                    .connect_for(
                        &config,
                        &session.session_id,
                        &decision.destination,
                        decision.upstream.as_deref(),
                    )
                    .await
                {
                    Ok(connected) => connected,
                    Err(error) if config.mode == EnforcementMode::Observe => {
                        self.audit.connection(
                            "fail_open",
                            &context,
                            decision.rule_id.as_deref(),
                            action_name(decision.deny, decision.upstream.is_some()),
                            "direct_fallback",
                            None,
                            Some(started.elapsed().as_millis()),
                            Some(json!({"message": error.to_string()})),
                        );
                        ConnectedUpstream {
                            stream: connect_direct(decision.destination.clone()).await?,
                            transport: UpstreamTransport::Direct,
                            associated_client_proxy: None,
                        }
                    }
                    Err(error) => {
                        self.audit.connection(
                            "connect",
                            &context,
                            decision.rule_id.as_deref(),
                            action_name(decision.deny, decision.upstream.is_some()),
                            "failed",
                            None,
                            Some(started.elapsed().as_millis()),
                            Some(json!({
                                "message": error.to_string(),
                                "configured_upstream": decision.upstream,
                            })),
                        );
                        client
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                            .await?;
                        return Err(error);
                    }
                };
                upstream = connected.stream;
                upstream_transport = connected.transport;
                associated_client_proxy = None;
                upstream_replaced = true;
            }
        } else {
            context.protocol = inspection.protocol;
        }
        let original_proxy_address = SocketAddr::new(requested.ip, requested.port).to_string();
        let upstream_tunneled = matches!(upstream_transport, UpstreamTransport::Tunneled);
        let upstream_transport = format!("{:?}", upstream_transport);
        let preserved = !upstream_replaced;
        let connection_detail = if let Some(proxy_protocol) = client_proxy_protocol {
            let mut detail = json!({
                "inspection": inspection.detail,
                "client_proxy": &original_proxy_address,
                "client_proxy_protocol": proxy_protocol,
                "upstream_transport": upstream_transport,
                "preserved": preserved,
            });
            if upstream_replaced {
                detail["configured_upstream"] = json!(decision.upstream);
            }
            Some(detail)
        } else if let Some(proxy) = associated_client_proxy.as_ref() {
            Some(json!({
                "inspection": inspection.detail,
                "client_proxy": proxy.address,
                "client_proxy_protocol": proxy.protocol,
                "associated": true,
                "upstream_transport": upstream_transport,
                "preserved": preserved,
            }))
        } else {
            inspection.detail.clone()
        };
        let detected_client_proxy = client_proxy_protocol.map(|protocol| ClientProxySnapshot {
            protocol: protocol.to_owned(),
            address: original_proxy_address,
        });
        if !upstream_replaced {
            if let Some(proxy) = detected_client_proxy.as_ref() {
                self.proxy_affinity.remember(
                    &session.session_id,
                    &context.destination,
                    &proxy.protocol,
                    proxy.address.clone(),
                );
            }
        }
        let client_proxy = detected_client_proxy.or(associated_client_proxy);
        active.update(
            &context.destination,
            context.protocol,
            decision.rule_id.as_deref(),
            action_name(decision.deny, decision.upstream.is_some()),
            decision.upstream.as_deref(),
            client_proxy.clone(),
            "connected",
        );
        self.audit.connection(
            "connect",
            &context,
            decision.rule_id.as_deref(),
            action_name(decision.deny, decision.upstream.is_some()),
            "connected",
            None,
            Some(started.elapsed().as_millis()),
            connection_detail,
        );

        // 递归协议栈分派：入站已探测字节作为已消费前缀入栈，逐层探测/还原后转发。
        // 加协议 = 新增 ProtocolHandler 模块并在 builtin_protocols() 注册。
        let phase = match ingress {
            IngressTransport::HttpConnect | IngressTransport::Tls => "tls_mitm",
            IngressTransport::PlainHttp => "http",
            IngressTransport::Socks5 | IngressTransport::Raw => "connected",
        };
        let host = context
            .destination
            .hostnames
            .first()
            .cloned()
            .unwrap_or_else(|| context.destination.ip.to_string());
        active.update(
            &context.destination,
            context.protocol,
            decision.rule_id.as_deref(),
            action_name(decision.deny, decision.upstream.is_some()),
            decision.upstream.as_deref(),
            client_proxy.clone(),
            phase,
        );
        let inner = HandlerContext {
            host,
            mitm: self.tls_mitm.clone(),
            ssh_mitm_key: self.ssh_mitm_key.clone(),
            config: config.clone(),
            policy: policy.clone(),
            protection: protection.clone(),
            audit: self.audit.clone(),
            context,
            decision,
            sessions: self.sessions.clone(),
            trust: self.trust.clone(),
            upstream_tunneled,
        };
        // 把 peek 过的字节从 client socket 消费掉，交给栈回放，避免与 socket 残留重复。
        let mut payload = vec![0u8; count];
        client.read_exact(&mut payload).await?;
        if upstream_replaced {
            match ingress {
                IngressTransport::HttpConnect => {
                    return proxy_https_via_tunneled_upstream(
                        Box::new(client),
                        Box::new(upstream),
                        payload,
                        inner,
                    )
                    .await;
                }
                IngressTransport::PlainHttp => {
                    return proxy_http(
                        PrefixedIo::new(Box::new(client), payload),
                        Box::new(upstream),
                        inner,
                    )
                    .await;
                }
                _ => {}
            }
        }
        run_stack(Box::new(client), Box::new(upstream), payload, 0, inner).await
    }

    async fn connect_for(
        &self,
        config: &Config,
        session_id: &str,
        destination: &Destination,
        upstream: Option<&str>,
    ) -> io::Result<ConnectedUpstream> {
        match upstream {
            Some(id) => {
                let item = config
                    .upstream(id)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "upstream not found"))?;
                Ok(ConnectedUpstream {
                    stream: connect_upstream(item.clone(), destination.clone()).await?,
                    transport: UpstreamTransport::Tunneled,
                    associated_client_proxy: None,
                })
            }
            None => match self.environment_proxy.upstream_for(destination) {
                Some(item) => Ok(ConnectedUpstream {
                    stream: connect_upstream(item, destination.clone()).await?,
                    transport: UpstreamTransport::Tunneled,
                    associated_client_proxy: None,
                }),
                None => match self.proxy_affinity.lookup(session_id, destination) {
                    Some(proxy) => Ok(ConnectedUpstream {
                        stream: connect_upstream(proxy.upstream, destination.clone()).await?,
                        transport: UpstreamTransport::Tunneled,
                        associated_client_proxy: Some(proxy.snapshot),
                    }),
                    None => Ok(ConnectedUpstream {
                        stream: connect_direct(destination.clone()).await?,
                        transport: UpstreamTransport::Direct,
                        associated_client_proxy: None,
                    }),
                },
            },
        }
    }
}

async fn bind_listener(address: SocketAddr) -> io::Result<TcpListener> {
    match TcpListener::bind(address).await {
        Ok(listener) => Ok(listener),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            let fallback = SocketAddr::new(address.ip(), 0);
            TcpListener::bind(fallback).await.map_err(|fallback_error| {
                io::Error::new(
                    fallback_error.kind(),
                    format!(
                        "configured SOCKS5 listener {address} is occupied and fallback listener {fallback} failed: {fallback_error}"
                    ),
                )
            })
        }
        Err(error) => Err(error),
    }
}

fn normalize_hostname(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

async fn authenticate(
    client: &mut TcpStream,
    sessions: SessionRegistry,
) -> io::Result<AuthenticatedSession> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION || head[1] == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid SOCKS5 greeting (first bytes 0x{:02x} 0x{:02x})",
                head[0], head[1]
            ),
        ));
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&AUTH_USERPASS) {
        client.write_all(&[SOCKS_VERSION, 0xff]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 username/password authentication required",
        ));
    }
    client.write_all(&[SOCKS_VERSION, AUTH_USERPASS]).await?;
    client.read_exact(&mut head).await?;
    if head[0] != 1 {
        return Err(invalid("invalid RFC1929 version"));
    }
    let mut username = vec![0u8; head[1] as usize];
    client.read_exact(&mut username).await?;
    let password_len = client.read_u8().await? as usize;
    let mut password = vec![0u8; password_len];
    client.read_exact(&mut password).await?;
    let username = std::str::from_utf8(&username).ok();
    let password = std::str::from_utf8(&password).ok();
    let authenticated = username
        .zip(password)
        .and_then(|(u, p)| sessions.authenticate(u, p));
    if let Some(session) = authenticated {
        client.write_all(&[1, 0]).await?;
        Ok(session)
    } else {
        client.write_all(&[1, 1]).await?;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid or expired HyperHub session",
        ))
    }
}

async fn read_connect_request(client: &mut TcpStream) -> io::Result<Destination> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION || head[1] != 1 || head[2] != 0 {
        return Err(invalid("only SOCKS5 CONNECT is supported"));
    }
    let (ip, hostnames) = match head[3] {
        1 => {
            let mut bytes = [0u8; 4];
            client.read_exact(&mut bytes).await?;
            (IpAddr::V4(bytes.into()), Vec::new())
        }
        4 => {
            let mut bytes = [0u8; 16];
            client.read_exact(&mut bytes).await?;
            (IpAddr::V6(bytes.into()), Vec::new())
        }
        3 => {
            let length = client.read_u8().await? as usize;
            if length == 0 {
                return Err(invalid("empty SOCKS5 hostname"));
            }
            let mut bytes = vec![0u8; length];
            client.read_exact(&mut bytes).await?;
            let host = std::str::from_utf8(&bytes)
                .map_err(|_| invalid("SOCKS5 hostname is not UTF-8"))?
                .to_ascii_lowercase();
            let ip = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .next()
                .map(|value| value.ip())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "destination hostname resolved to no addresses",
                    )
                })?;
            (ip, vec![host])
        }
        _ => return Err(invalid("unsupported SOCKS5 address type")),
    };
    let port = client.read_u16().await?;
    if port == 0 {
        return Err(invalid("destination port is zero"));
    }
    Ok(Destination {
        ip,
        port,
        hostnames,
    })
}

async fn write_reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    client
        .write_all(&[SOCKS_VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn is_fake_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            octets[0] == 198 && matches!(octets[1], 18 | 19)
        }
        IpAddr::V6(address) => address.segments()[..5] == [0xfdfe, 0x6879, 0x7065, 0x7268, 0x7562],
    }
}
fn reply_code(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::PermissionDenied => 2,
        io::ErrorKind::NetworkUnreachable => 3,
        io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => 4,
        io::ErrorKind::ConnectionRefused => 5,
        io::ErrorKind::TimedOut => 6,
        _ => 1,
    }
}
fn action_name(deny: bool, upstream: bool) -> &'static str {
    if deny {
        "deny"
    } else if upstream {
        "proxy"
    } else {
        "passthrough"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ListenerConfig;

    async fn unused_loopback_address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address
    }

    #[tokio::test]
    async fn listener_hot_update_keeps_old_address_available() {
        let initial_address = unused_loopback_address().await;
        let next_address = unused_loopback_address().await;
        let mut config = Config::default();
        config.listener.socks_listen = initial_address.to_string();
        let service = SocksService::with_environment(
            Arc::new(config),
            SessionRegistry::default(),
            EnvironmentProxy::default(),
        )
        .unwrap();
        let controller = service.listener_controller();
        let task = tokio::spawn(service.run());

        controller
            .ensure_listener(&initial_address.to_string())
            .await
            .unwrap();
        TcpStream::connect(initial_address).await.unwrap();

        controller
            .ensure_listener(&next_address.to_string())
            .await
            .unwrap();
        TcpStream::connect(next_address).await.unwrap();
        TcpStream::connect(initial_address).await.unwrap();

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn occupied_listener_falls_back_to_a_free_loopback_port() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_address = occupied.local_addr().unwrap();
        let mut config = Config::default();
        config.listener.socks_listen = occupied_address.to_string();
        let service = SocksService::with_environment(
            Arc::new(config),
            SessionRegistry::default(),
            EnvironmentProxy::default(),
        )
        .unwrap();
        let controller = service.listener_controller();
        let actual = service.prepare_listener().await.unwrap();
        assert_eq!(actual.ip(), occupied_address.ip());
        assert_ne!(actual.port(), occupied_address.port());
        assert_eq!(controller.address(), Some(actual));
        drop(occupied);

        let task = tokio::spawn(service.run());
        TcpStream::connect(actual).await.unwrap();
        task.abort();
        let _ = task.await;
    }

    #[test]
    fn associates_an_observed_proxy_only_with_the_same_session_and_target() {
        let affinity = SessionProxyAffinity::default();
        let destination = Destination {
            ip: "203.0.113.10".parse().unwrap(),
            port: 443,
            hostnames: vec!["Example.COM.".into()],
        };
        affinity.remember("session-a", &destination, "http", "127.0.0.1:7897".into());

        let matched = affinity
            .lookup(
                "session-a",
                &Destination {
                    ip: "203.0.113.11".parse().unwrap(),
                    port: 443,
                    hostnames: vec!["example.com".into()],
                },
            )
            .unwrap();
        assert_eq!(matched.upstream.kind, UpstreamKind::HttpConnect);
        assert_eq!(matched.upstream.address, "127.0.0.1:7897");
        assert!(affinity.lookup("session-b", &destination).is_none());
        assert!(affinity
            .lookup(
                "session-a",
                &Destination {
                    hostnames: vec!["other.example".into()],
                    ..destination
                },
            )
            .is_none());
    }

    #[tokio::test]
    async fn rejects_unauthenticated_client() {
        let registry = SessionRegistry::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            assert!(authenticate(&mut server, registry).await.is_err());
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0xff]);
        task.await.unwrap();
        let _ = ListenerConfig::default();
    }

    #[tokio::test]
    async fn ip_form_socks_refines_http_route_and_injects_credential() {
        use crate::config::{
            HttpAuthScheme, PluginConfig, PluginKind, PluginProtocol, RouteEndpoint, RouteRule,
            SecretValue,
        };

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.contains("authorization: bearer injected-token\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let registry = SessionRegistry::default();
        let challenge = registry
            .begin_auth("session-http".into(), "fixture".into(), [2; 32])
            .unwrap();
        let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
        let record = registry
            .finish_auth(
                &challenge.challenge_id,
                &proof,
                std::time::Duration::from_secs(30),
            )
            .unwrap();
        assert!(registry.activate("session-http", &record.token, 1));

        let mut config = Config::default();
        config.plugins.push(PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "credential".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Http],
            http_scheme: Some(HttpAuthScheme::Bearer),
            secret: Some(SecretValue::Inline {
                value: "injected-token".into(),
            }),
            ..PluginConfig::default()
        });
        config.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: "http-route".into(),
            enabled: true,
            priority: 100,
            endpoints: vec![RouteEndpoint {
                target: "http://localhost/probe".into(),
                port: Some(origin_address.port()),
            }],
            action: crate::config::RuleAction::Pass,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec!["credential".into()],
            legacy: Default::default(),
            protection: None,
            allow_sensitive_upload: false,
        });
        config.validate().unwrap();
        let service =
            SocksService::with_environment(Arc::new(config), registry, EnvironmentProxy::default())
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            service.handle(stream).await.unwrap();
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 2]);
        let username = b"hh2:session-http:1:42";
        let mut auth = vec![1, username.len() as u8];
        auth.extend(username);
        auth.push(record.token.len() as u8);
        auth.extend(record.token.as_bytes());
        client.write_all(&auth).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [1, 0]);
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend(origin_address.port().to_be_bytes());
        client.write_all(&connect).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        client
            .write_all(
                format!(
                    "GET /probe HTTP/1.1\r\nHost: localhost:{}\r\nAuthorization: Bearer placeholder\r\nConnection: close\r\n\r\n",
                    origin_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 200"));
        origin_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authenticated_connect_relays_bytes() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut data = [0u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });

        let registry = SessionRegistry::default();
        let challenge = registry
            .begin_auth("session".into(), "fixture".into(), [1; 32])
            .unwrap();
        let proof = crate::session::session_proof(&[0; 32], &challenge).unwrap();
        let record = registry
            .finish_auth(
                &challenge.challenge_id,
                &proof,
                std::time::Duration::from_secs(30),
            )
            .unwrap();
        assert!(registry.activate("session", &record.token, 1));
        let config = Config::default();
        let service =
            SocksService::with_environment(Arc::new(config), registry, EnvironmentProxy::default())
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            service.handle(stream).await.unwrap();
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 2]);
        let username = b"hh2:session:1:42";
        let mut auth = vec![1, username.len() as u8];
        auth.extend(username);
        auth.push(record.token.len() as u8);
        auth.extend(record.token.as_bytes());
        client.write_all(&auth).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [1, 0]);
        let mut request = vec![5, 1, 0, 1];
        request.extend([127, 0, 0, 1]);
        request.extend(echo_address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        drop(client);
        echo_task.await.unwrap();
        server.await.unwrap();
    }
}
