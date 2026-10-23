//! Actual Serve restart, persistent target, descendants and post-restart policy.
#![cfg(any(target_os = "linux", windows))]
use hyperhub_core::{
    config::{Config, FileSandboxOperation, FileSandboxPattern, FileSandboxRule, SandboxAction},
    config_store::{self, ExportFormat},
};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
#[path = "support/literal_path_pattern.rs"]
mod literal_path_pattern;
#[path = "support/private_process.rs"]
mod private_process;

struct EchoServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl EchoServer {
    fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut connection = loop {
                if stopping.load(Ordering::Acquire) {
                    return;
                }
                match listener.accept() {
                    Ok((connection, _)) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("private echo accept failed: {error}"),
                }
            };
            connection.set_nonblocking(false).unwrap();
            connection
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            connection
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buffer = [0; 128];
            while !stopping.load(Ordering::Acquire) {
                match connection.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => connection.write_all(&buffer[..count]).unwrap(),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        break
                    }
                    Err(error) => panic!("private echo read failed: {error}"),
                }
            }
        });
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}

struct PersistentFlow {
    _echo: EchoServer,
    worker: private_process::PrivateProcess,
    worker_pid: u32,
    worker_birth: u64,
    cache: PathBuf,
    local: String,
}
impl PersistentFlow {
    fn open(
        fixture: &Fixture,
        input: &mut impl Write,
        receiver: &mpsc::Receiver<String>,
        pid: u32,
    ) -> Self {
        let echo = EchoServer::start();
        writeln!(input, "stream-open {}", echo.address).unwrap();
        input.flush().unwrap();
        let line = receive(receiver, "persistent stream open");
        let local = line
            .strip_prefix(&format!("STREAM_OPEN {pid} local="))
            .unwrap()
            .to_owned();
        writeln!(input, "stream-ping").unwrap();
        input.flush().unwrap();
        assert_eq!(
            receive(receiver, "persistent stream before restart"),
            format!("STREAM_OK {pid} local={local}")
        );
        let status = fixture.status();
        let workers: Vec<_> = status["forward_workers"]["workers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|worker| worker["live_connections"].as_u64().unwrap() > 0)
            .collect();
        assert_eq!(
            workers.len(),
            1,
            "expected one stream-owning worker: {status}"
        );
        let worker = workers[0];
        let worker_pid = worker["pid"].as_u64().unwrap() as u32;
        let worker_birth = worker["start_time"].as_u64().unwrap();
        assert_ne!(worker_birth, 0);
        let prefix = format!("hyperhub-forward-{}-", status["pid"].as_u64().unwrap());
        let caches: Vec<_> = fs::read_dir(fixture.root.join("tmp"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&prefix)
            })
            .collect();
        assert_eq!(
            caches.len(),
            1,
            "private old worker cache not unique: {caches:?}"
        );
        let cache = caches[0].clone();
        let executable = cache.join(format!(
            "{}{}",
            worker["sha256"].as_str().unwrap(),
            std::env::consts::EXE_SUFFIX
        ));
        let handle = private_process::PrivateProcess::capture(worker_pid, &executable).unwrap();
        assert!(!handle.exited());
        eprintln!("RESTART_FLOW_OPEN target={pid} worker={worker_pid} birth={worker_birth} local={local} cache={}", cache.display());
        Self {
            _echo: echo,
            worker: handle,
            worker_pid,
            worker_birth,
            cache,
            local,
        }
    }

    fn finish(&self, input: &mut impl Write, receiver: &mpsc::Receiver<String>, pid: u32) {
        writeln!(input, "stream-ping").unwrap();
        input.flush().unwrap();
        assert_eq!(
            receive(receiver, "same persistent stream after restart"),
            format!("STREAM_OK {pid} local={}", self.local)
        );
        assert!(!self.worker.exited(), "active old stream worker exited");
        assert!(self.cache.is_dir(), "active old stream cache was removed");
        eprintln!(
            "RESTART_FLOW_SURVIVED target={pid} worker={} birth={} local={} cache={}",
            self.worker_pid,
            self.worker_birth,
            self.local,
            self.cache.display()
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        writeln!(input, "stream-close").unwrap();
        input.flush().unwrap();
        assert_eq!(
            receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("persistent stream close exceeded the 10s drain deadline"),
            format!("STREAM_CLOSED {pid}")
        );
        while !self.worker.exited() || self.cache.exists() {
            assert!(Instant::now() < deadline, "old worker/cache did not drain within 10s before FixtureDrop: worker={} birth={} worker_exited={} cache_exists={} cache={}", self.worker_pid, self.worker_birth, self.worker.exited(), self.cache.exists(), self.cache.display());
            std::thread::sleep(Duration::from_millis(20));
        }
        eprintln!("RESTART_FLOW_DRAINED target={pid} worker={} cache_removed=true before_fixture_drop=true", self.worker_pid);
    }
}

struct Fixture {
    root: PathBuf,
    cli: PathBuf,
    children: Vec<Child>,
    target: Option<private_process::PrivateProcess>,
    backend: String,
}
impl Fixture {
    fn command(&self) -> Command {
        let mut command = Command::new(&self.cli);
        for name in [
            "HYPERHUB_SESSION_ID",
            "HYPERHUB_SESSION_TOKEN",
            "HYPERHUB_SOCKS_ADDR",
            "HYPERHUB_CONTROL_ENDPOINT",
            "HYPERHUB_SESSION_ENV_KEYS",
            "HYPERHUB_CONFIG_PASSWORD",
        ] {
            command.env_remove(name);
        }
        command
            .env("HYPERHUB_HOME", &self.root)
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("XDG_RUNTIME_DIR", self.root.join("runtime"))
            .env("TMPDIR", self.root.join("tmp"))
            .env("TMP", self.root.join("tmp"))
            .env("TEMP", self.root.join("tmp"))
            .stdin(Stdio::null());
        command
    }
    fn output(&self, mut command: Command) -> Vec<u8> {
        let out = self.root.join("command.stdout");
        let err = self.root.join("command.stderr");
        command
            .stdout(fs::File::create(&out).unwrap())
            .stderr(fs::File::create(&err).unwrap());
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("private CLI timed out: {:?}", command);
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            status.success(),
            "CLI failed {status}: {}",
            fs::read_to_string(err).unwrap()
        );
        fs::read(out).unwrap()
    }
    fn success(&self, args: &[&str]) {
        let mut command = self.command();
        command.args(args);
        self.output(command);
    }
    fn status(&self) -> serde_json::Value {
        let mut command = self.command();
        command.args(["status", "--json"]);
        serde_json::from_slice(&self.output(command)).unwrap()
    }
    fn import(&self, config: &Config) {
        let file = self.root.join("fixture.toml");
        config_store::export(&file, config, ExportFormat::Toml, None).unwrap();
        let mut command = self.command();
        command
            .arg("import")
            .arg(file)
            .arg("--admin-password-file")
            .arg(self.root.join("password"));
        self.output(command);
    }
    fn update(&self, config: &Config) {
        // This owner credential belongs only to the disposable test instance.
        // Exercise the same authenticated update protocol as configuration approval.
        let unlocked =
            config_store::load_encrypted(&self.root.join("config.bin"), b"private-restart-fixture")
                .unwrap();
        let config_json = serde_json::to_string(
            &hyperhub_core::config_document::ConfigDocument::from_config(config),
        )
        .unwrap();
        let proof =
            hyperhub_core::session::config_update_proof(&unlocked.session_auth_key, &config_json)
                .unwrap();
        // Approval persists the encrypted configuration before notifying Serve.
        // Preserve its descriptor so a second restart reads the same policy and
        // derives the same control/session keys as the live update.
        config_store::save_encrypted_with_descriptor(
            &self.root.join("config.bin"),
            config,
            b"private-restart-fixture",
            &unlocked.descriptor,
        )
        .unwrap();
        let endpoint = hyperhub_core::control::instance_control_endpoint(&self.root);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let response = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                hyperhub_core::control::control_request(
                    &endpoint,
                    &hyperhub_core::session::ControlRequest::UpdateConfig { proof, config_json },
                ),
            )
            .await
            .unwrap()
            .unwrap()
        });
        assert!(
            matches!(response, hyperhub_core::session::ControlResponse::Ok),
            "private policy update failed: {response:?}"
        );
    }
    #[cfg(target_os = "linux")]
    fn suspend_serve(&self) {
        use hyperhub_core::{
            control,
            session::{ControlRequest, ControlResponse},
        };
        let endpoint = control::instance_control_endpoint(&self.root);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let response = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                control::control_request(
                    &endpoint,
                    &ControlRequest::Shutdown {
                        preserve_sessions: true,
                    },
                ),
            )
            .await
            .unwrap()
            .unwrap()
        });
        assert!(matches!(response, ControlResponse::Ok));
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::os::unix::net::UnixStream::connect(&endpoint).is_ok() {
            assert!(
                Instant::now() < deadline,
                "private Serve did not close its endpoint"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        eprintln!("RESTART_OUTAGE_OBSERVED endpoint_is_unavailable=true");
    }
    fn wait_host(&self, pid: u32, historical_root: u64) {
        let deadline = Instant::now() + Duration::from_secs(35);
        loop {
            let status = self.status();
            let hosts = status["engine_hosts"].as_array().unwrap();
            let ptrace = self.backend == "ptrace";
            if hosts.iter().any(|host| {
                host["online"] == true
                    && if ptrace {
                        host["root_pid"].as_u64() == Some(historical_root)
                    } else {
                        host["host_pid"].as_u64() == Some(pid as u64)
                    }
            }) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "executor Engine Host did not reconnect: {status}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "RESTART_TARGET_BEFORE_CLEANUP exited={:?}",
                self.target.as_ref().map(|target| target.exited())
            );
            let _ = fs::copy(
                self.root.join("target.stderr"),
                self.root.join("target-before-cleanup.stderr"),
            );
        }
        // The protocol writer has already closed on unwind. Give the private
        // target's exact OS handle final ownership even if its launcher failed.
        drop(self.target.take());
        // Only terminate executables launched with this private instance.
        let mut stop = self.command();
        stop.arg("stop").stdout(Stdio::null()).stderr(Stdio::null());
        if let Ok(mut child) = stop.spawn() {
            let deadline = Instant::now() + Duration::from_secs(15);
            while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        if std::thread::panicking() {
            eprintln!("restart fixture retained: {}", self.root.display());
            for name in [
                "serve.log",
                "target-before-cleanup.stderr",
                "command.stderr",
            ] {
                eprintln!(
                    "RESTART_LOG {name}: {}",
                    fs::read_to_string(self.root.join(name)).unwrap_or_default()
                );
            }
        } else {
            private_process::remove_fixture(&self.root).unwrap();
        }
    }
}
fn rule(id: &str, path: &Path) -> FileSandboxRule {
    FileSandboxRule {
        uuid: String::new(),
        id: id.into(),
        enabled: true,
        priority: 0,
        action: SandboxAction::Deny,
        patterns: vec![FileSandboxPattern {
            enabled: true,
            pattern: literal_path_pattern::exact(path),
        }],
        operations: vec![FileSandboxOperation::Read],
        protection: None,
        legacy: Default::default(),
    }
}
fn receive(receiver: &mpsc::Receiver<String>, stage: &str) -> String {
    receiver
        .recv_timeout(Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("{stage}: executor made no progress: {error}"))
}
fn probe(input: &mut impl Write, receiver: &mpsc::Receiver<String>, pid: u32, changed: &str) {
    writeln!(input, "probe").unwrap();
    input.flush().unwrap();
    assert_eq!(
        receive(receiver, "probe"),
        format!("OK {pid} blocked=deny allowed=allow changed={changed} shell=ok")
    );
}
fn member(status: &serde_json::Value, pid: u32) -> bool {
    status["sessions"].as_array().unwrap().iter().any(|s| {
        s["processes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["pid"].as_u64() == Some(pid as u64))
    })
}
fn scenario(mode: &str, backend: Option<&str>) {
    let source = PathBuf::from(
        std::env::var_os("HYPERHUB_TEST_RESTART_HYPERHUB")
            .or_else(|| std::env::var_os("HH_FORWARD_WORKER_FIXTURE"))
            .expect("set HYPERHUB_TEST_RESTART_HYPERHUB"),
    );
    let root = std::env::temp_dir().join(format!(
        "hh-restart-{}-{:x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for directory in ["home", "runtime", "tmp"] {
        fs::create_dir(root.join(directory)).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cli = root.join(format!("hyperhub{}", std::env::consts::EXE_SUFFIX));
    fs::copy(source, &cli).unwrap();
    let mut fixture = Fixture {
        root,
        cli,
        children: Vec::new(),
        target: None,
        backend: backend.map(str::to_owned).unwrap_or_else(|| {
            if cfg!(windows) {
                "gum".into()
            } else {
                std::env::var("HYPERHUB_TEST_RESTART_BACKEND").unwrap_or_else(|_| "ptrace".into())
            }
        }),
    };
    fs::write(
        fixture.root.join("upgrade-check.json"),
        serde_json::to_vec(
            &serde_json::json!({"last_check_ms": hyperhub_core::session::unix_timestamp_ms()}),
        )
        .unwrap(),
    )
    .unwrap();
    config_store::save_private_bytes(&fixture.root.join("password"), b"private-restart-fixture")
        .unwrap();
    let blocked = fixture.root.join("blocked-secret.txt");
    let allowed = fixture.root.join("allowed.txt");
    let changed = fixture.root.join("changed.txt");
    fs::write(&blocked, b"dummy secret bytes").unwrap();
    fs::write(&allowed, b"allowed fixture bytes").unwrap();
    fs::write(&changed, b"changed fixture bytes").unwrap();
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut config = Config::default();
    config.listener.socks_listen = reservation.local_addr().unwrap().to_string();
    drop(reservation);
    config.sandbox.file.enabled = true;
    config.sandbox.file.error_action = SandboxAction::Deny;
    config
        .sandbox
        .file
        .rules
        .push(rule("restart-deny-dummy", &blocked));
    fixture.import(&config);
    fixture.success(&["start"]);
    let initial_serve = fixture.status()["pid"].as_u64().unwrap();
    let target = fixture
        .root
        .join(format!("restart-target{}", std::env::consts::EXE_SUFFIX));
    let mut compiler = Command::new("rustc");
    compiler
        .arg("--edition=2021")
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/restart_target.rs"),
        )
        .arg("-o")
        .arg(&target);
    fixture.output(compiler);
    let mut launcher = fixture.command();
    launcher.arg("run");
    let target_mode = if matches!(mode, "outage" | "denied-outage") {
        "child"
    } else {
        mode
    };
    #[cfg(target_os = "linux")]
    launcher.arg("--backend").arg(&fixture.backend);
    launcher
        .arg("--")
        .arg(&target)
        .arg(target_mode)
        .arg(&blocked)
        .arg(&allowed)
        .arg(&changed)
        .arg(fixture.root.join("child-ran.marker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(fs::File::create(fixture.root.join("target.stderr")).unwrap());
    let mut child = launcher.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    fixture.children.push(child);
    let (sender, receiver) = mpsc::channel();
    let mut transcript = fs::File::create(fixture.root.join("target.stdout")).unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let line = line.unwrap();
            writeln!(transcript, "{line}").unwrap();
            transcript.flush().unwrap();
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let ready = receive(&receiver, "ready");
    let pid: u32 = ready.strip_prefix("READY ").unwrap().parse().unwrap();
    fixture.target = Some(private_process::PrivateProcess::capture(pid, &target).unwrap());
    probe(&mut input, &receiver, pid, "allow");
    let mut initial = fixture.status();
    if mode == "orphan" {
        let deadline = Instant::now() + Duration::from_secs(15);
        while member(
            &initial,
            initial["sessions"][0]["root_pid"].as_u64().unwrap() as u32,
        ) {
            assert!(
                Instant::now() < deadline,
                "original fixture root did not exit before restart"
            );
            std::thread::sleep(Duration::from_millis(20));
            initial = fixture.status();
        }
        eprintln!(
            "RESTART_ROOT_EXIT_OBSERVED root_pid={} survivor_pid={pid}",
            initial["sessions"][0]["root_pid"]
        );
    }
    assert!(
        member(&initial, pid),
        "executor absent before restart: {initial}"
    );
    let session_ids: Vec<_> = initial["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["session_id"].clone())
        .collect();
    let historical_root = initial["sessions"][0]["root_pid"].as_u64().unwrap();
    fixture.wait_host(pid, historical_root);
    #[cfg(target_os = "linux")]
    if mode == "denied-outage" {
        let marker = fixture.root.join("child-ran.marker");
        for operation in ["allowed-marker", "blocked-spawn"] {
            if operation == "blocked-spawn" {
                fs::remove_file(&marker).unwrap();
                fixture.suspend_serve();
            }
            let deadline = Instant::now() + Duration::from_secs(45);
            writeln!(input, "{operation}").unwrap();
            input.flush().unwrap();
            let line = |stage: &str| {
                receiver
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(|e| panic!("{stage}: {e}"))
            };
            assert_eq!(line("marker start"), format!("SPAWN_STARTED {pid}"));
            let created = line("original spawn result");
            let child_pid: u32 = created
                .strip_prefix(&format!("SPAWN_CREATED {pid} "))
                .unwrap()
                .parse()
                .unwrap();
            assert_ne!(child_pid, pid);
            assert_ne!(child_pid, 0);
            if operation == "allowed-marker" {
                assert_eq!(
                    line("online marker result"),
                    format!("MARKER_ALLOWED {pid} child={child_pid}")
                );
                assert_eq!(fs::read(&marker).unwrap(), b"child-ran");
            } else {
                assert_eq!(
                    line("primary enforcement gate"),
                    format!("BLOCKED {pid} child={child_pid} signal=9")
                );
                assert!(
                    !marker.exists(),
                    "unenrolled child executed application code while Serve was unavailable"
                );
                eprintln!("RESTART_PRIMARY_GATE_VERIFIED parent={pid} child={child_pid} spawn=success signal=9 marker_absent=true");
            }
        }
        fixture.success(&["start"]);
        fixture.wait_host(pid, historical_root);
        assert!(member(&fixture.status(), pid));
        probe(&mut input, &receiver, pid, "allow");
    }
    #[cfg(target_os = "linux")]
    if mode == "outage" {
        fixture.suspend_serve();
        writeln!(input, "outage-probe").unwrap();
        input.flush().unwrap();
        assert_eq!(
            receive(&receiver, "outage execution"),
            format!("PROBE_STARTED {pid}")
        );
        fixture.success(&["start"]);
        assert_eq!(
            receive(&receiver, "outage recovery"),
            format!("OK {pid} blocked=deny allowed=allow changed=allow shell=ok")
        );
        assert!(member(&fixture.status(), pid));
        fixture.wait_host(pid, historical_root);
    }
    if mode == "orphan" {
        assert!(
            initial["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["root_pid"].as_u64() != Some(pid as u64)),
            "orphan trigger was not observed"
        );
    }
    let flow = (mode == "flow").then(|| PersistentFlow::open(&fixture, &mut input, &receiver, pid));
    fixture.success(&["restart"]);
    let restored = fixture.status();
    assert_ne!(restored["pid"].as_u64().unwrap(), initial_serve);
    assert_eq!(
        restored["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["session_id"].clone())
            .collect::<Vec<_>>(),
        session_ids,
        "session identities changed after restart: {restored}"
    );
    assert!(
        member(&restored, pid),
        "live executor missing after restart: {restored}"
    );
    fixture.wait_host(pid, historical_root);
    probe(&mut input, &receiver, pid, "allow");
    if let Some(flow) = &flow {
        flow.finish(&mut input, &receiver, pid);
    }
    // Existing executors must receive a new authenticated policy snapshot after
    // their original subscription was disconnected.
    config
        .sandbox
        .file
        .rules
        .push(rule("restart-deny-changed", &changed));
    fixture.update(&config);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        writeln!(input, "probe").unwrap();
        input.flush().unwrap();
        let line = receive(&receiver, "policy refresh");
        if line == format!("OK {pid} blocked=deny allowed=allow changed=deny shell=ok") {
            break;
        }
        assert_eq!(
            line,
            format!("OK {pid} blocked=deny allowed=allow changed=allow shell=ok")
        );
        assert!(
            Instant::now() < deadline,
            "restarted Serve never delivered policy update"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    fixture.success(&["restart"]);
    let twice = fixture.status();
    assert_ne!(twice["pid"], restored["pid"]);
    assert!(
        member(&twice, pid),
        "executor lost on second restart: {twice}"
    );
    fixture.wait_host(pid, historical_root);
    probe(&mut input, &receiver, pid, "deny");
    writeln!(input, "quit").unwrap();
    input.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = fixture.children[0].try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "launcher failed to terminate after executor quit"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!("RESTART_VERIFIED mode={mode} target_pid={pid} original_serve={initial_serve} restored_serve={}", restored["pid"]);
}
#[test]
#[ignore = "requires packaged CLI and native runtime; registered in platform Suites"]
fn restart_keeps_live_executor_and_command_progress() {
    scenario("child", None);
}
#[test]
#[ignore = "requires packaged CLI and native runtime; registered in platform Suites"]
fn restart_preserves_tcp_stream_then_reclaims_old_worker_cache() {
    scenario("flow", None);
}
#[test]
#[ignore = "requires packaged CLI and native runtime; registered in platform Suites"]
fn restart_preserves_child_after_original_root_exits() {
    scenario("orphan", None);
}
#[cfg(unix)]
#[test]
#[ignore = "requires packaged CLI and native runtime; registered in platform Suites"]
fn restart_preserves_root_after_exec_changes_its_executable() {
    scenario("exec", None);
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires packaged CLI and native runtime; registered in platform Suites"]
fn unavailable_control_socket_during_target_execution_recovers_without_panic() {
    scenario("outage", None);
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires packaged CLI and native runtime; registered in platform Suites"]
fn gum_unavailable_serve_never_resumes_an_unenrolled_child() {
    scenario("denied-outage", Some("gum"));
}
