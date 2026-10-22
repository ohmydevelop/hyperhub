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
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Stdio},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;
#[path = "../../../tests/fixtures/engine_fixture_build.rs"]
mod engine_fixture_build;
#[path = "support/engine_rollout.rs"]
mod rollout;
use hyperhub_core::upgrade::{Action, Phase};

struct Target(Child, PathBuf);
impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        #[cfg(target_os = "linux")]
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                    continue;
                };
                // A failed orphan fixture can outlive its launcher. Terminate
                // only executables from this exact private source-build root.
                let executable = entry.path().join("exe");
                if fs::read_link(&executable).is_ok_and(|path| path.starts_with(&self.1)) {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
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
        #[cfg(windows)]
        fn writable(path: &Path) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };
            if metadata.file_type().is_symlink() {
                return;
            }
            if metadata.is_dir() {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        writable(&entry.path());
                    }
                }
            } else if metadata.is_file() {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                let _ = fs::set_permissions(path, permissions);
            }
        }
        #[cfg(windows)]
        writable(&self.0);
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
        engine_fixture_build::configure(&mut command);
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
async fn policy_check(
    input: &mut std::process::ChildStdin,
    output: &mut Arc<std::sync::Mutex<BufReader<std::process::ChildStdout>>>,
    pid: u32,
    path: &Path,
    child: &Path,
    allow: bool,
) {
    writeln!(input, "file {}", path.display()).unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(output, "FILE_POLICY ").await,
        format!("FILE_POLICY {pid} {allow}")
    );
    writeln!(input, "process {}", child.display()).unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(output, "PROCESS_POLICY ").await,
        format!("PROCESS_POLICY {pid} {allow}")
    );
    writeln!(input, "child {}", path.display()).unwrap();
    input.flush().unwrap();
    let line = target_line(output, "CHILD_POLICY ").await;
    let fields: Vec<_> = line.split_whitespace().collect();
    assert_eq!(fields.len(), 3);
    assert_ne!(fields[1].parse::<u32>().unwrap(), pid);
    assert_eq!(fields[2], allow.to_string());
    // Consume the last command acknowledgement before the caller's next command.
    target_line(output, "TARGET_OK ").await;
}
#[cfg(target_os = "linux")]
async fn fork_check(
    input: &mut std::process::ChildStdin,
    output: &mut Arc<std::sync::Mutex<BufReader<std::process::ChildStdout>>>,
    path: Option<&Path>,
    expected: &[u32],
    allow: bool,
) -> Vec<u32> {
    if let Some(path) = path {
        writeln!(input, "fork {}", path.display()).unwrap();
    } else {
        writeln!(input, "fork-check").unwrap();
    }
    input.flush().unwrap();
    let count = if path.is_some() { 1 } else { expected.len() };
    let mut pids = Vec::new();
    for _ in 0..count {
        let line = target_line(output, "FORK_POLICY ").await;
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        pids.push(fields[1].parse().unwrap());
        assert_eq!(fields[2], allow.to_string());
    }
    if path.is_none() {
        assert_eq!(pids, expected);
    }
    target_line(output, "TARGET_OK ").await;
    pids
}
async fn online_hosts(endpoint: &str, persistent: &[u32]) -> Vec<String> {
    match exchange(
        endpoint,
        &ControlRequest::GetEngineHosts {
            request_id: None,
            host_id: None,
        },
    )
    .await
    {
        ControlResponse::EngineHosts { hosts, .. } => hosts
            .into_iter()
            .filter(|h| {
                h.online
                    && (h.backend == hyperhub_engine::host::Backend::LinuxPtrace
                        || persistent.contains(&h.root_pid))
            })
            .map(|h| h.host_id)
            .collect(),
        _ => panic!("missing Host inventory"),
    }
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
    host_for(endpoint, None).await
}
async fn host_for_process(endpoint: &str, pid: u32) -> HostStatus {
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
                if let Some(host) = hosts.into_iter().find(|h| h.online && h.root_pid == pid) {
                    return host;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the specific native process did not enroll")
}
async fn host_for(endpoint: &str, id: Option<&str>) -> HostStatus {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let ControlResponse::EngineHosts { hosts, .. } = exchange(
                endpoint,
                &ControlRequest::GetEngineHosts {
                    request_id: None,
                    host_id: id.map(str::to_owned),
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
    let proof = request.proof(rollout::api_key().as_bytes()).unwrap();
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
    claims: Arc<std::sync::Mutex<HashSet<(String, u32, u64)>>>,
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
    let authenticated = sessions
        .authenticate(
            std::str::from_utf8(&username).unwrap(),
            std::str::from_utf8(&password).unwrap(),
        )
        .unwrap();
    assert!(
        claims.lock().unwrap().insert((
            authenticated.session_id,
            authenticated.pid,
            authenticated.connection_id
        )),
        "a live socket claim must not be reused after exec"
    );
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
    native_host_scenario(false, false).await;
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ptrace_host_switch_survives_root_exit_with_live_descendants() {
    native_host_scenario(true, true).await;
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gum_host_switch_survives_root_exit_with_live_descendants() {
    if std::env::var_os("HYPERHUB_TEST_ENGINE_GUM_AGENT").is_none()
        && std::env::var_os("HYPERHUB_TEST_ENGINE_EMBEDDED_AGENT").is_none()
    {
        eprintln!("Gum orphan fixture requires an explicit or embedded Agent");
        return;
    }
    native_host_scenario(true, false).await;
}
async fn native_host_scenario(orphan: bool, force_ptrace: bool) {
    let version = "channel-fixture";
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = Root(std::env::temp_dir().join(format!(
        "hh-engine-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    )));
    fs::create_dir_all(root.0.join("runtime")).unwrap();
    let api_key = rollout::api_key();
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
    #[cfg(target_os = "linux")]
    let loader = {
        let library = root.0.join("native-tls-loader.so");
        let output = std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-pthread"])
            .arg(repo.join("tests/fixtures/native_tls_loader_probe.c"))
            .arg("-o")
            .arg(&library)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        library
    };
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = Config::default();
    config.listener.socks_listen = socks.local_addr().unwrap().to_string();
    config.sandbox.file.enabled = true;
    config.sandbox.process.enabled = true;
    #[cfg(target_os = "linux")]
    config.sandbox.file.rules.push(
        serde_json::from_value(serde_json::json!({
            "uuid":"d53c6f1d-2307-4577-b416-fd7fd7f6a39d", "id":"loader-control", "action":"pass", "patterns":[{"pattern":"^/dev/null$"}],
            "operations":["read"]
        }))
        .unwrap(),
    );
    let policy_path = root.0.join("engine-policy-deny");
    fs::write(&policy_path, b"policy fixture").unwrap();
    let policy_child = root.0.join(format!(
        "engine-policy-deny{}",
        std::env::consts::EXE_SUFFIX
    ));
    // On POSIX executable and data can have the same suffix, so keep them in
    // separate directories while preserving the generic final component.
    let child_dir = root.0.join("child");
    fs::create_dir_all(&child_dir).unwrap();
    let policy_child = child_dir.join(policy_child.file_name().unwrap());
    fs::copy(&executable, &policy_child).unwrap();
    let sessions =
        SessionRegistry::default().with_api_key(Zeroizing::new(api_key.as_bytes().to_vec()));
    let auth = sessions.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let mock = std::thread::spawn(move || {
        let mut handlers = Vec::new();
        let claims = Arc::new(std::sync::Mutex::new(HashSet::new()));
        for _ in 0..if cfg!(target_os = "linux") { 4 } else { 3 } {
            let stream = socks.accept().unwrap().0;
            let auth = auth.clone();
            let sender = sender.clone();
            let claims = claims.clone();
            handlers.push(std::thread::spawn(move || {
                mock_connection(stream, auth, sender, claims)
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
        AuditWriter::open(Some(&root.0.join("audit.jsonl"))).unwrap(),
        RuntimeState::new(Arc::new(config)).unwrap(),
        Zeroizing::new(vec![0; 32]),
    )
    .with_engine_upgrades(
        &root.0.join("upgrades"),
        Zeroizing::new(api_key.as_bytes().to_vec()),
    )
    .unwrap();
    let endpoint = control::instance_control_endpoint(&root.0);
    let (coordinator, runner) = rollout::start(&service);
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
    if force_ptrace {
        command.args(["--backend", "ptrace"]);
    }
    if !force_ptrace {
        if let Ok(backend) = std::env::var("HYPERHUB_TEST_ENGINE_BACKEND") {
            command.args(["--backend", &backend]);
        }
        let agent = std::env::var("HYPERHUB_TEST_ENGINE_GUM_AGENT").ok();
        let embedded = std::env::var_os("HYPERHUB_TEST_ENGINE_EMBEDDED_AGENT").is_some();
        if agent.is_some() || embedded {
            command.args(["--backend", "gum"]);
            if let Some(agent) = agent.filter(|_| !embedded) {
                command.args(["--runtime", &agent]);
            }
        }
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
    let mut target = Target(child, root.0.clone());
    let mut input = target.0.stdin.take().unwrap();
    let mut output = Arc::new(std::sync::Mutex::new(BufReader::new(
        target.0.stdout.take().unwrap(),
    )));
    let pid_line = target_line(&mut output, "TARGET_PID ").await;
    let mut pid: u32 = pid_line.split_whitespace().nth(1).unwrap().parse().unwrap();
    #[cfg(target_os = "linux")]
    let mut original_start = fs::read_to_string(format!("/proc/{pid}/stat"))
        .unwrap()
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_string();
    let mut original = host(&endpoint).await;
    rollout::reject_configuration_key(&endpoint).await;
    assert_eq!(original.root_pid, pid);
    policy_check(
        &mut input,
        &mut output,
        pid,
        &policy_path,
        &policy_child,
        true,
    )
    .await;
    #[cfg(target_os = "linux")]
    loader_check(&mut input, &mut output, pid, &loader).await;
    #[cfg(target_os = "linux")]
    fork_exec_check(&mut input, &mut output, pid, &policy_path, true).await;
    input.write_all(b"open\n").unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} 1")
    );
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
    #[cfg(target_os = "linux")]
    {
        input.write_all(b"exec-sockets\n").unwrap();
        input.flush().unwrap();
        assert_eq!(
            target_line(&mut output, "TARGET_PID ").await,
            format!("TARGET_PID {pid}")
        );
        assert_eq!(
            target_line(&mut output, "EXEC_SOCKETS ").await,
            format!("EXEC_SOCKETS {pid} 1")
        );
        input.write_all(b"open\n").unwrap();
        input.flush().unwrap();
        assert_eq!(
            target_line(&mut output, "TARGET_OK ").await,
            format!("TARGET_OK {pid} 2")
        );
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
        original = host_for_process(&endpoint, pid).await;
        assert_eq!(original.root_pid, pid);
    }
    let inherited_streams = if cfg!(target_os = "linux") { 2 } else { 1 };
    #[cfg(target_os = "linux")]
    if orphan {
        let root_pid = pid;
        input.write_all(b"orphan\n").unwrap();
        input.flush().unwrap();
        let line = target_line(&mut output, "ORPHAN_PID ").await;
        pid = line.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert_ne!(pid, root_pid);
        assert_eq!(
            target_line(&mut output, "TARGET_OK ").await,
            format!("TARGET_OK {pid} {inherited_streams}")
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while std::path::Path::new(&format!("/proc/{root_pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        original_start = fs::read_to_string(format!("/proc/{pid}/stat"))
            .unwrap()
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap()
            .to_owned();
        if force_ptrace {
            assert_eq!(
                host_for(&endpoint, Some(&original.host_id)).await.host_id,
                original.host_id,
                "the resident tracer must remain registered after root exit"
            );
        } else {
            original = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let ControlResponse::EngineHosts { hosts, .. } = exchange(
                        &endpoint,
                        &ControlRequest::GetEngineHosts {
                            request_id: None,
                            host_id: None,
                        },
                    )
                    .await
                    {
                        if let Some(child) = hosts
                            .into_iter()
                            .find(|host| host.online && host.root_pid == pid)
                        {
                            break child;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("surviving Gum child did not retain its enrolled Host");
        }
    }
    #[cfg(target_os = "linux")]
    let mut fork_pids = fork_check(&mut input, &mut output, Some(&policy_path), &[], true).await;
    #[cfg(target_os = "linux")]
    {
        writeln!(input, "fork-nested {}", policy_path.display()).unwrap();
        input.flush().unwrap();
        let line = target_line(&mut output, "FORK_POLICY ").await;
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields[2], "true");
        let nested: u32 = fields[1].parse().unwrap();
        assert!(!fork_pids.contains(&nested));
        fork_pids.push(nested);
        target_line(&mut output, "TARGET_OK ").await;
    }

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
        host_for(&endpoint, Some(&original.host_id))
            .await
            .snapshot
            .active
            .version,
        original.snapshot.active.version
    );
    let mut persistent = vec![pid];
    #[cfg(target_os = "linux")]
    persistent.extend(fork_pids.iter().copied());
    rollout::submit(
        &endpoint,
        Action::Prepare {
            manifest,
            source: module,
            cache: root.0.join("cache"),
            hosts: online_hosts(&endpoint, &persistent).await,
        },
    )
    .await;
    rollout::until(&endpoint, Phase::Prepared).await;
    rollout::submit(&endpoint, Action::Commit).await;
    rollout::interrupt_and_recover(&endpoint, runner).await;
    rollout::until(&endpoint, Phase::Committed).await;
    policy_check(
        &mut input,
        &mut output,
        pid,
        &policy_path,
        &policy_child,
        false,
    )
    .await;
    #[cfg(target_os = "linux")]
    if orphan && original.backend == hyperhub_engine::host::Backend::LinuxPtrace {
        let events: Vec<serde_json::Value> = fs::read_dir(&root.0)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("date="))
            .filter_map(|entry| fs::read_to_string(entry.path().join("audit.jsonl")).ok())
            .flat_map(|text| text.lines().map(str::to_owned).collect::<Vec<_>>())
            .map(|line| serde_json::from_str(&line).unwrap())
            .collect();
        for (kind, target) in [("file", &policy_path), ("process", &policy_child)] {
            assert!(
                events.iter().any(|event| {
                    event["event"] == "security_alert"
                        && event["attributes"]["kind"] == kind
                        && event["attributes"]["action"] == "deny"
                        && event["attributes"]["target"] == target.to_string_lossy().as_ref()
                }),
                "the retained tracer must publish {kind} decisions after root exit"
            );
        }
    }
    for code in [23, 127, 139, 255] {
        writeln!(input, "business-exit {code}").unwrap();
        input.flush().unwrap();
        assert_eq!(
            target_line(&mut output, "BUSINESS_EXIT ").await,
            format!("BUSINESS_EXIT {pid} {code}")
        );
        target_line(&mut output, "TARGET_OK ").await;
    }
    // A rejected launch must not turn its runtime's internal error stub into
    // an asynchronous Engine-health failure once the coordinator polls it.
    tokio::time::sleep(Duration::from_millis(250)).await;
    #[cfg(target_os = "linux")]
    loader_check(&mut input, &mut output, pid, &loader).await;
    #[cfg(target_os = "linux")]
    fork_exec_check(&mut input, &mut output, pid, &policy_path, false).await;
    #[cfg(target_os = "linux")]
    {
        fork_check(&mut input, &mut output, None, &fork_pids, false).await;
        let late = fork_check(&mut input, &mut output, Some(&policy_path), &[], false).await;
        fork_pids.extend(late);
    }
    input.write_all(b"ping\nopen\n").unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} {inherited_streams}")
    );
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} {}", inherited_streams + 1)
    );
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 2);
    let current = host_for(&endpoint, Some(&original.host_id)).await;
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
    rollout::submit(&endpoint, Action::Observe).await;
    #[cfg(target_os = "linux")]
    {
        input.write_all(b"signal-child\n").unwrap();
        input.flush().unwrap();
        assert_eq!(
            target_line(&mut output, "SIGNAL_EXIT ").await,
            format!("SIGNAL_EXIT {pid} 11")
        );
        target_line(&mut output, "TARGET_OK ").await;
        let expected = if original.backend == hyperhub_engine::host::Backend::LinuxPtrace {
            // The tracer remains alive and confirms compensation for its
            // entire tree; Gum has a separately exited participant to report.
            Phase::RolledBack
        } else {
            Phase::Failed
        };
        let record = rollout::until(&endpoint, expected).await;
        assert!(
            record.reason.is_some(),
            "the native fault must remain visible"
        );
        if original.backend == hyperhub_engine::host::Backend::LinuxPtrace {
            assert!(record.reason.as_ref().unwrap().contains("signal=Some(11)"));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        rollout::submit(
            &endpoint,
            Action::Rollback {
                reason: "fixture observation failure".into(),
            },
        )
        .await;
        rollout::until(&endpoint, Phase::RolledBack).await;
    }
    #[cfg(target_os = "linux")]
    fork_exec_check(&mut input, &mut output, pid, &policy_path, true).await;
    #[cfg(target_os = "linux")]
    fork_check(&mut input, &mut output, None, &fork_pids, true).await;
    policy_check(
        &mut input,
        &mut output,
        pid,
        &policy_path,
        &policy_child,
        true,
    )
    .await;
    #[cfg(target_os = "linux")]
    loader_check(&mut input, &mut output, pid, &loader).await;
    input.write_all(b"ping\nopen\n").unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} {}", inherited_streams + 1)
    );
    assert_eq!(
        target_line(&mut output, "TARGET_OK ").await,
        format!("TARGET_OK {pid} {}", inherited_streams + 2)
    );
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
    assert_eq!(
        host_for(&endpoint, Some(&original.host_id))
            .await
            .snapshot
            .active
            .generation,
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
    rollout::stop(coordinator).await;
    server.abort();
    let _ = server.await;
}

#[cfg(target_os = "linux")]
async fn fork_exec_check(
    input: &mut impl Write,
    output: &mut Arc<std::sync::Mutex<BufReader<std::process::ChildStdout>>>,
    pid: u32,
    path: &Path,
    allowed: bool,
) {
    writeln!(input, "fork-exec {allowed} {}", path.display()).unwrap();
    input.flush().unwrap();
    let line = target_line(output, "FORK_EXEC_STATUS ").await;
    let fields: Vec<_> = line.split_whitespace().collect();
    assert_eq!(fields[1], pid.to_string());
    assert_ne!(fields[2], fields[1]);
    assert_eq!(
        fields[3], "0",
        "fork followed immediately by exec must enroll and execute the expected policy: {line}"
    );
    target_line(output, "TARGET_OK ").await;
}

#[cfg(target_os = "linux")]
async fn loader_check(
    input: &mut impl Write,
    output: &mut Arc<std::sync::Mutex<BufReader<std::process::ChildStdout>>>,
    pid: u32,
    library: &Path,
) {
    writeln!(input, "loader {}", library.display()).unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(output, "LOADER_POLICY ").await,
        format!("LOADER_POLICY {pid} true")
    );
    target_line(output, "TARGET_OK ").await;
}
