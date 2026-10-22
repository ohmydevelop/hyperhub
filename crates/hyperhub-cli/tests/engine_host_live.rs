//! Source-based native-target regression, shared by the unified backend suite.
//! The SOCKS peer independently observes a changed native packet after commit.
#![cfg(any(target_os = "linux", windows))]
use base64::Engine;
use hyperhub_core::{
    audit::AuditWriter,
    config::Config,
    control::{self, ControlService},
    engine_hosts::{DeliveryState, HostStatus, OwnerCommand},
    runtime::RuntimeState,
    session::{ConnectionRegistry, ControlRequest, ControlResponse, SessionRegistry},
};
use hyperhub_engine::management::{Command, Reply};
use hyperhub_runtime::Stage;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Stdio},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;

struct Target(Child);
impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "native Host fixture: {}\n{}",
                self.0.display(),
                fs::read_to_string(self.0.join("target.log")).unwrap_or_default()
            );
            return;
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn compile(source: &Path, output: &Path, library: bool, version: &str) {
    let mut command = std::process::Command::new("rustc");
    command
        .arg("--edition=2021")
        .arg(source)
        .arg("-o")
        .arg(output);
    if library {
        command.args(["--crate-type", "cdylib"]);
    }
    let result = command
        .env(
            "HH_FIXTURE_VERSION_HASH",
            hyperhub_runtime::artifact::hex(&Sha256::digest(version)),
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
async fn exchange(endpoint: &str, request: &ControlRequest) -> ControlResponse {
    tokio::time::timeout(
        Duration::from_secs(10),
        control::control_request(endpoint, request),
    )
    .await
    .unwrap()
    .unwrap()
}
async fn host(endpoint: &str) -> HostStatus {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let ControlResponse::EngineHosts { hosts, .. } = exchange(
                endpoint,
                &ControlRequest::GetEngineHosts {
                    request_id: None,
                    host_id: None,
                },
            )
            .await
            {
                if let Some(host) = hosts.into_iter().find(|h| h.online) {
                    return host;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("native Host did not enroll")
}
async fn dispatch(endpoint: &str, host_id: &str, id: &str, command: Command) -> Reply {
    let request = OwnerCommand {
        host_id: host_id.into(),
        request_id: id.into(),
        command,
        issued_at_ms: hyperhub_core::session::unix_timestamp_ms(),
    };
    let proof = request.proof(&[0; 32]).unwrap();
    let response = exchange(
        endpoint,
        &ControlRequest::EngineHostCommand { request, proof },
    )
    .await;
    assert!(
        matches!(response, ControlResponse::EngineHostCommand { .. }),
        "{response:?}"
    );
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let ControlResponse::EngineHosts { commands, .. } = exchange(
                endpoint,
                &ControlRequest::GetEngineHosts {
                    request_id: Some(id.into()),
                    host_id: None,
                },
            )
            .await
            {
                if let Some(status) = commands.into_iter().next() {
                    assert_ne!(
                        status.state,
                        DeliveryState::Unknown,
                        "Host lost before acknowledgement"
                    );
                    if status.state == DeliveryState::Acknowledged {
                        return status.reply.unwrap();
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
fn read_target_line(reader: &mut BufReader<std::process::ChildStdout>, prefix: &str) -> String {
    loop {
        let mut line = String::new();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "target exited before {prefix}"
        );
        if line.starts_with(prefix) {
            return line.trim().into();
        }
    }
}
async fn target_line(
    reader: &mut Arc<std::sync::Mutex<BufReader<std::process::ChildStdout>>>,
    prefix: &'static str,
) -> String {
    let reader = reader.clone();
    tokio::time::timeout(
        Duration::from_secs(15),
        tokio::task::spawn_blocking(move || read_target_line(&mut reader.lock().unwrap(), prefix)),
    )
    .await
    .expect("target output timed out")
    .unwrap()
}
fn mock_connection(
    mut stream: TcpStream,
    sessions: SessionRegistry,
    methods: std::sync::mpsc::Sender<u8>,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut head = [0; 2];
    stream.read_exact(&mut head).unwrap();
    assert_eq!(head[0], 5);
    let count = head[1];
    let mut values = vec![0; count as usize];
    stream.read_exact(&mut values).unwrap();
    assert!(values.contains(&2));
    stream.write_all(&[5, 2]).unwrap();
    stream.read_exact(&mut head).unwrap();
    assert_eq!(head[0], 1);
    let mut username = vec![0; head[1] as usize];
    stream.read_exact(&mut username).unwrap();
    let mut length = [0];
    stream.read_exact(&mut length).unwrap();
    let mut password = vec![0; length[0] as usize];
    stream.read_exact(&mut password).unwrap();
    assert!(sessions
        .authenticate(
            std::str::from_utf8(&username).unwrap(),
            std::str::from_utf8(&password).unwrap()
        )
        .is_some());
    stream.write_all(&[1, 0]).unwrap();
    let mut connect = [0; 10];
    stream.read_exact(&mut connect).unwrap();
    assert_eq!(connect, [5, 1, 0, 1, 127, 0, 0, 1, 0x7a, 0xb7]);
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
    methods.send(count).unwrap();
    let mut ping = [0; 4];
    while stream.read_exact(&mut ping).is_ok() {
        assert_eq!(&ping, b"ping");
        stream.write_all(&ping).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "native Gum fixture runs in test-windows-hooks.ps1 after building the Agent"
)]
async fn native_host_switch_keeps_target_pid_and_old_tcp_stream() {
    let version = "channel-fixture";
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = Root(std::env::temp_dir().join(format!(
        "hh-engine-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    )));
    fs::create_dir_all(root.0.join("runtime")).unwrap();
    let api_key = format!(
        "hhk_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7; 32])
    );
    hyperhub_core::config_store::save_private_bytes(
        &root.0.join("runtime/api-key"),
        api_key.as_bytes(),
    )
    .unwrap();
    let executable = root
        .0
        .join(format!("target{}", std::env::consts::EXE_SUFFIX));
    let module = root
        .0
        .join(format!("engine{}", std::env::consts::DLL_SUFFIX));
    compile(
        &repo.join("tests/fixtures/engine_host_target.rs"),
        &executable,
        false,
        version,
    );
    compile(
        &repo.join("tests/fixtures/network_upgrade_engine.rs"),
        &module,
        true,
        version,
    );
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = Config::default();
    config.listener.socks_listen = socks.local_addr().unwrap().to_string();
    let sessions =
        SessionRegistry::default().with_api_key(Zeroizing::new(api_key.as_bytes().to_vec()));
    let auth = sessions.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let mock = std::thread::spawn(move || {
        let mut handlers = Vec::new();
        for _ in 0..3 {
            let stream = socks.accept().unwrap().0;
            let auth = auth.clone();
            let sender = sender.clone();
            handlers.push(std::thread::spawn(move || {
                mock_connection(stream, auth, sender)
            }));
        }
        for handler in handlers {
            handler.join().unwrap();
        }
    });
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let service = ControlService::new(
        sessions,
        ConnectionRegistry::default(),
        cert.cert.pem(),
        AuditWriter::open(None).unwrap(),
        RuntimeState::new(Arc::new(config)).unwrap(),
        Zeroizing::new(vec![0; 32]),
    );
    let endpoint = control::instance_control_endpoint(&root.0);
    let server = tokio::spawn(control::run_control_server(endpoint.clone(), service));
    tokio::time::timeout(Duration::from_secs(10), async {
        while control::control_request(&endpoint, &ControlRequest::Ping)
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let binary = std::env::var_os("HYPERHUB_TEST_ENGINE_HYPERHUB")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_hyperhub").into());
    let mut command = std::process::Command::new(binary);
    command.arg("run");
    if let Ok(backend) = std::env::var("HYPERHUB_TEST_ENGINE_BACKEND") {
        command.args(["--backend", &backend]);
    }
    if let Ok(agent) = std::env::var("HYPERHUB_TEST_ENGINE_GUM_AGENT") {
        command.args(["--backend", "gum", "--runtime", &agent]);
    }
    let child = command
        .arg("--")
        .arg(&executable)
        .env("HYPERHUB_HOME", &root.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            fs::File::create(root.0.join("target.log")).unwrap(),
        ))
        .spawn()
        .unwrap();
    let mut target = Target(child);
    let mut input = target.0.stdin.take().unwrap();
    let mut output = Arc::new(std::sync::Mutex::new(BufReader::new(
        target.0.stdout.take().unwrap(),
    )));
    let pid_line = target_line(&mut output, "TARGET_PID ").await;
    let pid: u32 = pid_line.split_whitespace().nth(1).unwrap().parse().unwrap();
    #[cfg(target_os = "linux")]
    let original_start = fs::read_to_string(format!("/proc/{pid}/stat"))
        .unwrap()
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_string();
    let original = host(&endpoint).await;
    assert_eq!(original.root_pid, pid);
    input.write_all(b"open\n").unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} 1")
    );
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
    let request = OwnerCommand {
        host_id: original.host_id.clone(),
        request_id: "forged".into(),
        issued_at_ms: hyperhub_core::session::unix_timestamp_ms(),
        command: Command::Commit {
            id: "change".into(),
        },
    };
    assert!(matches!(
        exchange(
            &endpoint,
            &ControlRequest::EngineHostCommand {
                request,
                proof: vec![0; 32]
            }
        )
        .await,
        ControlResponse::Error { .. }
    ));
    let manifest = hyperhub_engine::manifest(&fs::read(&module).unwrap(), version);
    let mut incompatible = manifest.clone();
    incompatible.state_schema += 1;
    assert!(
        matches!(dispatch(&endpoint, &original.host_id, "incompatible", Command::Prepare {
        id: "incompatible".into(), manifest: incompatible, source: root.0.join("missing-module"), cache: root.0.join("cache"),
    }).await, Reply::Transaction { transaction } if transaction.stage == Stage::RequiresRestart)
    );
    let corrupt = root.0.join("corrupt-module");
    fs::write(&corrupt, b"invalid library").unwrap();
    assert!(matches!(
        dispatch(
            &endpoint,
            &original.host_id,
            "corrupt",
            Command::Prepare {
                id: "corrupt".into(),
                manifest: manifest.clone(),
                source: corrupt,
                cache: root.0.join("cache"),
            }
        )
        .await,
        Reply::Error { .. }
    ));
    assert_eq!(
        host(&endpoint).await.snapshot.active.version,
        original.snapshot.active.version
    );
    assert!(
        matches!(dispatch(&endpoint, &original.host_id, "prepare", Command::Prepare { id: "change".into(), manifest,
        source: module, cache: root.0.join("cache") }).await, Reply::Transaction { transaction } if transaction.stage == Stage::Prepared)
    );
    assert!(
        matches!(dispatch(&endpoint, &original.host_id, "commit", Command::CommitHeld { id: "change".into() }).await,
        Reply::Transaction { transaction } if matches!(transaction.stage, Stage::Draining | Stage::Complete))
    );
    input.write_all(b"ping\nopen\n").unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} 1")
    );
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} 2")
    );
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 2);
    let current = host(&endpoint).await;
    assert_eq!(current.host_id, original.host_id);
    assert_eq!(current.host_pid, original.host_pid);
    assert_eq!(current.root_start_time, original.root_start_time);
    assert!(current.root_start_time.is_some());
    #[cfg(target_os = "linux")]
    assert_eq!(
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .unwrap()
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap(),
        original_start
    );
    assert_eq!(current.snapshot.active.version, version);
    assert!(current
        .snapshot
        .retired
        .iter()
        .any(|g| g.generation == original.snapshot.active.generation && g.references > 0));
    assert!(
        matches!(dispatch(&endpoint, &original.host_id, "observe-start", Command::BeginObservation { id: "change".into() }).await,
        Reply::Transaction { transaction } if transaction.stage == Stage::Draining)
    );
    assert!(
        matches!(dispatch(&endpoint, &original.host_id, "rollback", Command::Rollback {
        id: "change".into(), reason: "fixture observation failure".into(),
    }).await, Reply::Transaction { transaction } if transaction.stage == Stage::RolledBack)
    );
    input.write_all(b"ping\nopen\n").unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} 2")
    );
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} 3")
    );
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
    assert_eq!(
        host(&endpoint).await.snapshot.active.generation,
        original.snapshot.active.generation
    );
    input.write_all(b"quit\n").unwrap();
    input.flush().unwrap();
    drop(input);
    let exit = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(exit) = target.0.try_wait().unwrap() {
                return exit;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        exit.success(),
        "{}",
        fs::read_to_string(root.0.join("target.log")).unwrap()
    );
    mock.join().unwrap();
    server.abort();
}
