use super::*;
use crate::forward::authority::{Client, Request, Response, TlsAnchor};
use crate::forward::protocol::Bootstrap;
use crate::session::ActiveConnection;
use std::collections::HashMap;
use std::path::PathBuf;

pub use crate::forward::manager::{WorkerGroupStatus, WorkerManager, WorkerStatus};

pub(crate) struct ResidentAuthority {
    service: SocksService,
    grants: Mutex<HashMap<u64, Grant>>,
    claims: Arc<Mutex<HashSet<(String, u32, u64)>>>,
}
struct Grant {
    session: AuthenticatedSession,
    granted: bool,
    active: Option<ActiveConnection>,
}
impl ResidentAuthority {
    pub(crate) fn new(
        service: SocksService,
        claims: Arc<Mutex<HashSet<(String, u32, u64)>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            service,
            grants: Mutex::new(HashMap::new()),
            claims,
        })
    }
    pub(crate) fn bind(&self, id: u64, session: AuthenticatedSession) -> io::Result<()> {
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| io::Error::other("worker grant state poisoned"))?;
        if grants.len() >= 4096 || grants.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "worker connection capacity reached",
            ));
        }
        let key = (
            session.session_id.clone(),
            session.pid,
            session.connection_id,
        );
        if !self
            .claims
            .lock()
            .map_err(|_| io::Error::other("resident connection claims poisoned"))?
            .insert(key)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "connection identity already belongs to another socket offer",
            ));
        }
        grants.insert(
            id,
            Grant {
                session,
                granted: false,
                active: None,
            },
        );
        Ok(())
    }
    pub(crate) fn grant(&self, id: u64) -> io::Result<()> {
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| io::Error::other("worker grant state poisoned"))?;
        let grant = grants
            .get_mut(&id)
            .ok_or_else(|| io::Error::other("unknown worker socket offer"))?;
        if grant.session.cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "session was revoked before worker ownership grant",
            ));
        }
        grant.granted = true;
        Ok(())
    }
    pub(crate) fn finish(&self, id: u64) {
        let removed = self
            .grants
            .lock()
            .ok()
            .and_then(|mut grants| grants.remove(&id));
        if let Some(grant) = removed {
            if let Ok(mut claims) = self.claims.lock() {
                claims.remove(&(
                    grant.session.session_id.clone(),
                    grant.session.pid,
                    grant.session.connection_id,
                ));
            }
        }
    }
    pub(crate) fn clear(&self) {
        let removed = self
            .grants
            .lock()
            .map(|mut grants| grants.drain().map(|(_, grant)| grant).collect::<Vec<_>>())
            .unwrap_or_default();
        if let Ok(mut claims) = self.claims.lock() {
            for grant in removed {
                claims.remove(&(
                    grant.session.session_id.clone(),
                    grant.session.pid,
                    grant.session.connection_id,
                ));
            }
        }
    }
    pub(crate) fn count(&self) -> usize {
        self.grants
            .lock()
            .map(|grants| grants.len())
            .unwrap_or(4096)
    }
    fn identity(&self, id: u64) -> io::Result<AuthenticatedSession> {
        let grants = self
            .grants
            .lock()
            .map_err(|_| io::Error::other("worker grant state poisoned"))?;
        let grant = grants
            .get(&id)
            .filter(|grant| grant.granted)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "worker RPC has no ownership grant",
                )
            })?;
        Ok(grant.session.clone())
    }
    pub(crate) fn call(&self, id: u64, request: Request) -> io::Result<Response> {
        let identity = self.identity(id)?;
        let require_session = |session: &str| {
            if session == identity.session_id {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "worker session identity changed",
                ))
            }
        };
        match request {
            Request::FakeIp {
                session_id,
                address,
            } => {
                require_session(&session_id)?;
                Ok(Response::FakeIp {
                    hostname: self.service.sessions.restore_fake(&session_id, address),
                })
            }
            Request::DebugEnabled => Ok(Response::DebugEnabled {
                enabled: self.service.audit.debug_enabled(),
            }),
            Request::Audit {
                category,
                event,
                mut dimensions,
                attributes,
                debug_only,
            } => {
                for (key, expected) in [
                    ("session_id", json!(identity.session_id)),
                    ("connection_id", json!(identity.connection_id)),
                    ("process_pid", json!(identity.pid)),
                    ("process_executable", json!(identity.executable)),
                ] {
                    if dimensions
                        .get(key)
                        .is_some_and(|actual| actual != &expected)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "worker audit identity changed",
                        ));
                    }
                    dimensions.insert(key.into(), expected);
                }
                self.service
                    .audit
                    .record_from_worker(category, &event, dimensions, attributes, debug_only);
                Ok(Response::Ok)
            }
            Request::Connection { snapshot } => {
                if snapshot.session_id != identity.session_id
                    || snapshot.connection_id != identity.connection_id
                    || snapshot.pid != identity.pid
                    || snapshot.executable != identity.executable
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "worker connection identity changed",
                    ));
                }
                let mut grants = self
                    .grants
                    .lock()
                    .map_err(|_| io::Error::other("worker grant state poisoned"))?;
                let grant = grants
                    .get_mut(&id)
                    .ok_or_else(|| io::Error::other("worker offer already closed"))?;
                if let Some(active) = &grant.active {
                    active.replace_snapshot(snapshot)?;
                } else {
                    grant.active = Some(self.service.connections.try_track(snapshot)?);
                }
                Ok(Response::Ok)
            }
            Request::ConnectionClosed {
                session_id,
                pid,
                connection_id,
            } => {
                require_session(&session_id)?;
                if pid != identity.pid || connection_id != identity.connection_id {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "worker closed another connection",
                    ));
                }
                if let Some(grant) = self
                    .grants
                    .lock()
                    .map_err(|_| io::Error::other("worker grant state poisoned"))?
                    .get_mut(&id)
                {
                    grant.active.take();
                }
                Ok(Response::Ok)
            }
            Request::LookupProxy {
                session_id,
                destination,
            } => {
                require_session(&session_id)?;
                Ok(Response::Proxy {
                    proxy: self
                        .service
                        .proxy_affinity
                        .lookup(&session_id, &destination)?,
                })
            }
            Request::RememberProxy {
                session_id,
                destination,
                protocol,
                address,
            } => {
                require_session(&session_id)?;
                self.service.proxy_affinity.remember(
                    &session_id,
                    &destination,
                    &protocol,
                    address,
                )?;
                Ok(Response::Ok)
            }
            Request::TlsMaterial { host, port } => {
                let trust = self
                    .service
                    .trust
                    .as_ref()
                    .ok_or_else(|| io::Error::other("resident TLS trust is unavailable"))?;
                let material = trust.tls_material(&host, port)?;
                Ok(Response::TlsMaterial {
                    roots: material
                        .roots
                        .roots
                        .iter()
                        .map(|anchor| TlsAnchor {
                            subject: anchor.subject.as_ref().to_vec(),
                            subject_public_key_info: anchor
                                .subject_public_key_info
                                .as_ref()
                                .to_vec(),
                            name_constraints: anchor
                                .name_constraints
                                .as_ref()
                                .map(|value| value.as_ref().to_vec()),
                        })
                        .collect(),
                    host_certificate: material
                        .host_certificate
                        .map(|certificate| certificate.as_ref().to_vec()),
                })
            }
            Request::TrustTls {
                host,
                port,
                certificate,
            } => {
                self.service
                    .trust
                    .as_ref()
                    .ok_or_else(|| io::Error::other("resident TLS trust is unavailable"))?
                    .trust_tls_host(&host, port, &CertificateDer::from(certificate))?;
                Ok(Response::Ok)
            }
            Request::TrustSsh {
                host,
                port,
                key_type,
                key_blob,
            } => {
                self.service
                    .trust
                    .as_ref()
                    .ok_or_else(|| io::Error::other("resident SSH trust is unavailable"))?
                    .trust_ssh_host(&host, port, &key_type, &key_blob)?;
                Ok(Response::Ok)
            }
        }
    }
}

impl SocksService {
    pub fn forward_worker_protocol() -> u32 {
        crate::forward::protocol::VERSION
    }

    /// Override environment-derived upstreams before workers are enabled.
    pub fn with_environment_proxy(mut self, environment: EnvironmentProxy) -> io::Result<Self> {
        if self.forward_workers.is_some() {
            return Err(io::Error::other(
                "environment upstreams must be selected before worker startup",
            ));
        }
        self.environment_proxy = environment;
        Ok(self)
    }

    pub(crate) fn worker_bootstrap(&self) -> io::Result<Bootstrap> {
        let config = self.runtime.snapshot().config;
        Ok(Bootstrap {
            audit_log: config.audit.log.clone(),
            transcript_dir: config.audit.transcript_dir.clone(),
            config: (*config).clone(),
            tls: self.tls_mitm.export_authority(),
            roots: self.tls_mitm.export_root_certificates(),
            ssh_private_key: self
                .ssh_mitm_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .map_err(io::Error::other)?
                .to_string(),
            environment: self.environment_proxy.clone(),
            trust: self.trust.is_some(),
            engine: None,
        })
    }
    pub(crate) fn worker_template(material: &Bootstrap, client: Client) -> io::Result<Self> {
        let mut config = material.config.clone();
        config.audit.log = material.audit_log.clone();
        config.audit.transcript_dir = material.transcript_dir.clone();
        let runtime = RuntimeState::new(Arc::new(config)).map_err(io::Error::other)?;
        let tls_mitm = TlsMitm::restore_authority(
            &material.tls,
            material
                .roots
                .iter()
                .cloned()
                .map(CertificateDer::from)
                .collect(),
        )?;
        let ssh_mitm_key = Arc::new(
            russh::keys::PrivateKey::from_openssh(&material.ssh_private_key)
                .map_err(io::Error::other)?,
        );
        let (sender, receiver) = mpsc::channel(1);
        let bound_address = Arc::new(RwLock::new(None));
        Ok(Self {
            runtime,
            sessions: SessionRegistry::default(),
            names: crate::forward::authority::NameService::Remote(client.clone()),
            audit: AuditWriter::remote(client.clone())?,
            tls_mitm,
            ssh_mitm_key,
            environment_proxy: material.environment.clone(),
            proxy_affinity: SessionProxyAffinity(Default::default(), Some(client.clone())),
            connections: ConnectionRegistry::remote(client.clone()),
            listener_controller: SocksListenerController {
                sender,
                address: bound_address.clone(),
            },
            listener_commands: Arc::new(Mutex::new(Some(receiver))),
            initial_listener: Arc::new(Mutex::new(None)),
            bound_address,
            trust: material
                .trust
                .then(|| Arc::new(crate::trust::TrustStore::remote(client))),
            forward_workers: None,
        })
    }
    pub(crate) fn worker_connection(
        &self,
        client: Client,
        mut config: Config,
        audit_log: Option<PathBuf>,
        transcript_dir: Option<PathBuf>,
    ) -> io::Result<Self> {
        config.audit.log = audit_log;
        config.audit.transcript_dir = transcript_dir;
        let mut service = self.clone();
        service.runtime = RuntimeState::new(Arc::new(config)).map_err(io::Error::other)?;
        service.names = crate::forward::authority::NameService::Remote(client.clone());
        service.audit = AuditWriter::remote(client.clone())?;
        service.proxy_affinity = SessionProxyAffinity(Default::default(), Some(client.clone()));
        service.connections = ConnectionRegistry::remote(client.clone());
        service.trust = self
            .trust
            .as_ref()
            .map(|_| Arc::new(crate::trust::TrustStore::remote(client)));
        Ok(service)
    }
    pub async fn run_forward_worker() -> io::Result<()> {
        crate::forward::worker::run().await
    }
    pub fn run_forward_cache_cleanup(key: &[u8]) -> io::Result<()> {
        crate::forward::cleanup::run(key)
    }
    /// Blocking preparation: call from spawn_blocking when a runtime is serving.
    pub fn with_forward_workers(mut self, executable: impl AsRef<Path>) -> io::Result<Self> {
        let manager = WorkerManager::new(self.clone(), executable.as_ref())?;
        self.forward_workers = Some(manager);
        Ok(self)
    }
    pub fn with_authenticated_forward_workers(
        mut self,
        executable: impl AsRef<Path>,
        key: &[u8],
    ) -> io::Result<Self> {
        let manager =
            WorkerManager::new_authenticated(self.clone(), executable.as_ref(), Some(key))?;
        self.forward_workers = Some(manager);
        Ok(self)
    }
    pub fn forward_workers(&self) -> Option<WorkerManager> {
        self.forward_workers.clone()
    }
    pub(crate) async fn forward_authenticated(
        self,
        stream: TcpStream,
        session: AuthenticatedSession,
    ) -> io::Result<()> {
        self.handle_authenticated(stream, session).await
    }
}
