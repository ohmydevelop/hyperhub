use hyperhub_core::config::Config;
use hyperhub_core::connector::EnvironmentProxy;
use hyperhub_core::session::{session_proof, SessionRegistry};
use hyperhub_core::socks::{SocksService, WorkerManager};
use sha2::{Digest, Sha256};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub(super) fn executable() -> PathBuf {
    std::env::var_os("HH_FORWARD_WORKER_FIXTURE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("examples")
                .join(format!(
                    "forward_worker_probe{}",
                    std::env::consts::EXE_SUFFIX
                ))
        })
}
pub(super) fn digest(path: &Path) -> String {
    Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub(super) struct Fixture {
    pub(super) registry: SessionRegistry,
    pub(super) token: String,
    pub(super) address: SocketAddr,
    pub(super) manager: WorkerManager,
    pub(super) service: SocksService,
    task: tokio::task::JoinHandle<io::Result<()>>,
    pub(super) root: PathBuf,
}
impl Fixture {
    pub(super) async fn start() -> Self {
        Self::start_with(Config::default(), Vec::new()).await
    }
    pub(super) async fn start_with(
        mut config: Config,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Self {
        let root = std::env::temp_dir().join(format!(
            "hh-worker-fixture-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        config.audit.log = Some(root.join("audit.jsonl"));
        config.audit.transcript_dir = Some(root.join("transcripts"));
        let registry = SessionRegistry::default();
        let challenge = registry
            .begin_auth("worker-session".into(), "forward-fixture".into(), [1; 32])
            .unwrap();
        let proof = session_proof(&[0; 32], &challenge).unwrap();
        let record = registry
            .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(60))
            .unwrap();
        assert!(registry.activate("worker-session", &record.token, std::process::id()));

        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        config.listener.socks_listen = reservation.local_addr().unwrap().to_string();
        drop(reservation);
        let service = SocksService::new_with_debug_output(
            Arc::new(config),
            registry.clone(),
            roots,
            false,
            None,
            b"forward-worker-source-fixture-master",
        )
        .unwrap()
        .with_environment_proxy(EnvironmentProxy::default())
        .unwrap();
        let binary = executable();
        assert!(
            binary.is_file(),
            "build forward_worker_probe or set HH_FORWARD_WORKER_FIXTURE"
        );
        let service = tokio::task::spawn_blocking(move || service.with_forward_workers(binary))
            .await
            .unwrap()
            .unwrap();
        let address = service.prepare_listener().await.unwrap();
        let manager = service.forward_workers().unwrap();
        let task = tokio::spawn(service.clone().run());
        Self {
            registry,
            token: record.token,
            address,
            manager,
            service,
            task,
            root,
        }
    }
    pub(super) async fn connect(&self, id: u64, destination: SocketAddr) -> TcpStream {
        self.connect_session("worker-session", &self.token, id, destination)
            .await
    }
    pub(super) async fn connect_session(
        &self,
        session: &str,
        token: &str,
        id: u64,
        destination: SocketAddr,
    ) -> TcpStream {
        let mut client = authenticate(self.address, session, token, id).await;
        let mut request = vec![5, 1, 0];
        match destination.ip() {
            IpAddr::V4(ip) => {
                request.push(1);
                request.extend(ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(4);
                request.extend(ip.octets());
            }
        }
        request.extend(destination.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[1], 0, "SOCKS reply: {reply:?}");
        client
    }
    pub(super) async fn stop(mut self) {
        self.manager.shutdown();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if self
                .manager
                .status()
                .workers
                .iter()
                .all(|worker| worker.phase == "exited")
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "workers did not drain: {:?}",
                self.manager.status()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.manager.shutdown();
        self.task.abort();
        remove_private_tree(&self.root);
    }
}
pub(super) async fn echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut bytes = [0; 4096];
                loop {
                    let count = stream.read(&mut bytes).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    stream.write_all(&bytes[..count]).await.unwrap();
                }
            });
        }
    });
    (address, task)
}
pub(super) async fn exchange(stream: &mut TcpStream, value: &[u8]) {
    stream.write_all(value).await.unwrap();
    let mut result = vec![0; value.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut result))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, value);
}

pub(super) async fn authenticate(
    address: SocketAddr,
    session: &str,
    token: &str,
    id: u64,
) -> TcpStream {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let username = format!("hh2:{session}:{}:{id}", std::process::id());
    let mut auth = vec![1, username.len() as u8];
    auth.extend(username.as_bytes());
    auth.push(token.len() as u8);
    auth.extend(token.as_bytes());
    client.write_all(&auth).await.unwrap();
    let mut status = [0; 2];
    client.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 0]);
    client
}
pub(super) fn add_session(registry: &SessionRegistry, name: &str) -> String {
    let challenge = registry
        .begin_auth(name.into(), "forward-fixture".into(), [2; 32])
        .unwrap();
    let proof = session_proof(&[0; 32], &challenge).unwrap();
    let record = registry
        .finish_auth(&challenge.challenge_id, &proof, Duration::from_secs(60))
        .unwrap();
    assert!(registry.activate(name, &record.token, std::process::id()));
    record.token
}

pub(super) fn remove_private_tree(root: &Path) {
    #[cfg(windows)]
    fn writable(path: &Path) {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return;
        };
        if metadata.file_type().is_symlink() {
            return;
        }
        if metadata.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    writable(&entry.path());
                }
            }
        } else if metadata.is_file() {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }
    #[cfg(windows)]
    writable(root);
    let _ = std::fs::remove_dir_all(root);
}
