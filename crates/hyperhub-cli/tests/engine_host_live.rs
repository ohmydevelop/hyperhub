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
        if let Some(destination) = std::env::var_os("HYPERHUB_TEST_ENGINE_DIAGNOSTICS") {
            let destination = PathBuf::from(destination).join(self.0.file_name().unwrap());
            if let Err(error) = fs::create_dir_all(&destination) {
                eprintln!("cannot retain native fixture diagnostics: {error}");
            } else {
                for name in [
                    "target.stdout",
                    "target-stages.log",
                    "target.log",
                    "timeout-proc.json",
                    "last-hosts.json",
                ] {
                    let source = self.0.join(name);
                    if source.is_file() {
                        if let Err(error) = fs::copy(source, destination.join(name)) {
                            eprintln!("cannot retain native fixture {name}: {error}");
                        }
                    }
                }
            }
        }
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
    output: &mut TargetOutput,
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
    output: &mut TargetOutput,
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
fn orphan_handshake_pid(
    first: &str,
    second: &str,
    root_pid: u32,
    inherited_streams: usize,
) -> Result<u32, String> {
    let (identity, acknowledgement) = match (
        first.starts_with("ORPHAN_PID "),
        second.starts_with("ORPHAN_PID "),
    ) {
        (true, false) => (first, second),
        (false, true) => (second, first),
        _ => {
            return Err(format!(
                "expected one orphan identity: {first:?}, {second:?}"
            ))
        }
    };
    let pid = identity
        .strip_prefix("ORPHAN_PID ")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid != 0 && *pid != root_pid)
        .ok_or_else(|| format!("invalid orphan identity: {identity:?}"))?;
    let expected = format!("TARGET_OK {pid} {inherited_streams}");
    if acknowledgement != expected {
        return Err(format!(
            "expected {expected:?}, received {acknowledgement:?}"
        ));
    }
    Ok(pid)
}
#[test]
fn orphan_handshake_accepts_parent_first_and_checks_child_identity() {
    assert_eq!(
        orphan_handshake_pid("ORPHAN_PID 23", "TARGET_OK 23 2", 17, 2),
        Ok(23)
    );
    assert!(orphan_handshake_pid("ORPHAN_PID 23", "TARGET_OK 24 2", 17, 2).is_err());
    assert!(orphan_handshake_pid("ORPHAN_PID 17", "TARGET_OK 17 2", 17, 2).is_err());
}
#[test]
fn orphan_handshake_accepts_child_first_and_checks_stream_count() {
    assert_eq!(
        orphan_handshake_pid("TARGET_OK 23 2", "ORPHAN_PID 23", 17, 2),
        Ok(23)
    );
    assert!(orphan_handshake_pid("TARGET_OK 23 1", "ORPHAN_PID 23", 17, 2).is_err());
    assert!(orphan_handshake_pid("ORPHAN_PID 23", "ORPHAN_PID 23", 17, 2).is_err());
}

#[cfg(target_os = "linux")]
fn orphan_monitor_barrier(root: &Path, launcher: u32, target: u32) {
    let Some(endpoint) = std::env::var_os("HYPERHUB_TEST_ENGINE_ORPHAN_BARRIER") else {
        return;
    };
    let mut channel = std::os::unix::net::UnixStream::connect(endpoint).unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    channel
        .set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    serde_json::to_writer(
        &mut channel,
        &serde_json::json!({
            "fixture_root": root,
            "launcher_pid": launcher,
            "target_pid": target,
        }),
    )
    .unwrap();
    channel.write_all(b"\n").unwrap();
    channel.flush().unwrap();
    let mut go = [0];
    channel.read_exact(&mut go).unwrap();
    assert_eq!(go, *b"G", "orphan monitor barrier rejected the driver");
}

#[derive(Clone)]
struct TargetOutput {
    reader: Arc<std::sync::Mutex<BufReader<std::process::ChildStdout>>>,
    diagnostics: Arc<std::sync::Mutex<TargetDiagnostics>>,
}
struct TargetDiagnostics {
    #[cfg(target_os = "linux")]
    root: PathBuf,
    #[cfg(target_os = "linux")]
    launcher_pid: u32,
    stdout: fs::File,
    stages: fs::File,
    recent: std::collections::VecDeque<String>,
}
#[cfg(target_os = "linux")]
fn capture_timeout_processes(root: &Path, launcher: u32, prefix: &str, caller: &str) {
    let read = |path: &Path| match fs::read_to_string(path) {
        Ok(contents) => serde_json::json!({"contents": contents}),
        Err(error) => serde_json::json!({"error": error.to_string()}),
    };
    let mut processes = std::collections::BTreeMap::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
                continue;
            };
            let parent = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .and_then(|value| value.trim().parse::<u32>().ok())
                .unwrap_or_default();
            let executable = fs::read_link(entry.path().join("exe")).ok();
            let private = pid == launcher
                || executable
                    .as_ref()
                    .is_some_and(|path| path.starts_with(root));
            processes.insert(pid, (parent, private));
        }
    }
    loop {
        let added: Vec<_> = processes
            .iter()
            .filter_map(|(pid, (parent, selected))| {
                (!selected && processes.get(parent).is_some_and(|(_, selected)| *selected))
                    .then_some(*pid)
            })
            .collect();
        if added.is_empty() {
            break;
        }
        for pid in added {
            processes.get_mut(&pid).unwrap().1 = true;
        }
    }
    let mut selected = Vec::new();
    for (pid, (_, private)) in processes {
        if !private {
            continue;
        }
        let process = PathBuf::from(format!("/proc/{pid}"));
        let mut tasks = Vec::new();
        if let Ok(entries) = fs::read_dir(process.join("task")) {
            for task in entries.flatten() {
                tasks.push(serde_json::json!({
                    "tid": task.file_name().to_string_lossy(),
                    "status": read(&task.path().join("status")),
                    "wchan": read(&task.path().join("wchan")),
                    "syscall": read(&task.path().join("syscall")),
                    "stack": read(&task.path().join("stack")),
                }));
            }
        }
        let mut descriptors = Vec::new();
        if let Ok(entries) = fs::read_dir(process.join("fd")) {
            for fd in entries.flatten().take(256) {
                descriptors.push(serde_json::json!({
                    "fd": fd.file_name().to_string_lossy(),
                    "target": fs::read_link(fd.path()).map(|path| path.to_string_lossy().into_owned()).map_err(|error| error.to_string()),
                }));
            }
        }
        selected.push(serde_json::json!({
            "pid": pid, "status": read(&process.join("status")),
            "stat": read(&process.join("stat")), "wchan": read(&process.join("wchan")),
            "syscall": read(&process.join("syscall")), "stack": read(&process.join("stack")),
            "tasks": tasks, "descriptors": descriptors,
        }));
    }
    let snapshot = serde_json::json!({
        "private_fixture": root, "launcher_pid": launcher, "waiting_prefix": prefix,
        "caller": caller, "captured_before_fixture_cleanup": true, "processes": selected,
    });
    if let Err(error) = fs::write(
        root.join("timeout-proc.json"),
        serde_json::to_vec_pretty(&snapshot).unwrap(),
    ) {
        eprintln!("cannot retain timeout process snapshot: {error}");
    }
}
fn read_target_line(
    reader: &mut BufReader<std::process::ChildStdout>,
    diagnostics: &std::sync::Mutex<TargetDiagnostics>,
    prefix: &str,
    caller: &str,
) -> String {
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).unwrap();
        let mut diagnostics = diagnostics.lock().unwrap();
        assert_ne!(
            read, 0,
            "target exited before {prefix:?} at {caller}; recent stdout: {:?}",
            diagnostics.recent
        );
        diagnostics.stdout.write_all(line.as_bytes()).unwrap();
        diagnostics.stdout.flush().unwrap();
        if diagnostics.recent.len() == 16 {
            diagnostics.recent.pop_front();
        }
        diagnostics.recent.push_back(line.trim().into());
        if line.starts_with(prefix) {
            writeln!(diagnostics.stages, "MATCH {prefix:?} at {caller}").unwrap();
            diagnostics.stages.flush().unwrap();
            return line.trim().into();
        }
    }
}
#[track_caller]
fn target_line(
    output: &mut TargetOutput,
    prefix: &'static str,
) -> impl std::future::Future<Output = String> {
    let caller = std::panic::Location::caller();
    let caller = format!("{}:{}", caller.file(), caller.line());
    let output = output.clone();
    async move {
        {
            let mut diagnostics = output.diagnostics.lock().unwrap();
            writeln!(diagnostics.stages, "WAIT {prefix:?} at {caller}").unwrap();
            diagnostics.stages.flush().unwrap();
        }
        let diagnostics = output.diagnostics.clone();
        let read_caller = caller.clone();
        match tokio::time::timeout(
            Duration::from_secs(15),
            tokio::task::spawn_blocking(move || {
                read_target_line(
                    &mut output.reader.lock().unwrap(),
                    &diagnostics,
                    prefix,
                    &read_caller,
                )
            }),
        )
        .await
        {
            Ok(result) => result.unwrap(),
            Err(error) => {
                let mut diagnostics = output.diagnostics.lock().unwrap();
                writeln!(diagnostics.stages, "TIMEOUT {prefix:?} at {caller}").unwrap();
                diagnostics.stages.flush().unwrap();
                #[cfg(target_os = "linux")]
                capture_timeout_processes(
                    &diagnostics.root,
                    diagnostics.launcher_pid,
                    prefix,
                    &caller,
                );
                let recent = diagnostics.recent.clone();
                drop(diagnostics);
                panic!(
                    "target output timed out waiting for {prefix:?} at {caller}: {error}; recent stdout: {recent:?}"
                );
            }
        }
    }
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
    native_host_scenario(false, false, false, false).await;
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ptrace_host_switch_survives_root_exit_with_live_descendants() {
    native_host_scenario(true, true, false, false).await;
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
    native_host_scenario(true, false, false, false).await;
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gum_fork_recovery_signal_does_not_bypass_policy() {
    if std::env::var_os("HYPERHUB_TEST_ENGINE_GUM_AGENT").is_none()
        && std::env::var_os("HYPERHUB_TEST_ENGINE_EMBEDDED_AGENT").is_none()
    {
        eprintln!("signal recovery regression requires an explicit or embedded Gum Agent");
        return;
    }
    native_host_scenario(false, false, true, false).await;
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gum_failed_fork_cancels_handoff_without_losing_policy() {
    if std::env::var_os("HYPERHUB_TEST_ENGINE_GUM_AGENT").is_none()
        && std::env::var_os("HYPERHUB_TEST_ENGINE_EMBEDDED_AGENT").is_none()
    {
        eprintln!("failed-fork regression requires an explicit or embedded Gum Agent");
        return;
    }
    native_host_scenario(false, false, false, true).await;
}
async fn native_host_scenario(
    orphan: bool,
    force_ptrace: bool,
    signal_case: bool,
    failed_fork_case: bool,
) {
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
    let failed_fork_fixture = failed_fork_case.then(|| {
        let executable = root.0.join("failed-fork-target");
        compile(
            &repo.join("tests/fixtures/failed_fork_target.rs"),
            &executable,
            false,
            version,
        );
        let allowed_file = root.0.join("failed-fork-readable-file");
        fs::write(&allowed_file, b"allowed fork regression").unwrap();
        (executable, allowed_file)
    });
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
    let signal_fixture = signal_case.then(|| {
        let executable = root.0.join("fork-signal-target");
        compile(&repo.join("tests/fixtures/linux_fork_signal_target.rs"), &executable, false, version);
        let denied_file = root.0.join("signal-denied-file");
        fs::write(&denied_file, b"permanent signal policy").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        config.sandbox.file.rules.push(serde_json::from_value(serde_json::json!({
            "uuid":"707d7285-66bf-4bd1-94ac-f7a4473197f9", "id":"signal-file-deny", "action":"deny",
            "patterns":[{"pattern":format!("^{}$", regex::escape(denied_file.to_str().unwrap()))}], "operations":["read"]
        })).unwrap());
        config.firewall.enabled = true;
        config.firewall.rules.push(serde_json::from_value(serde_json::json!({
            "uuid":"fb626906-757f-485d-916a-c85d4cf01891", "id":"signal-connect-deny", "action":"deny",
            "endpoints":[{"target":"127.0.0.1", "port":port}]
        })).unwrap());
        (executable, denied_file, listener)
    });
    #[cfg(windows)]
    assert!(!signal_case && !failed_fork_case);
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
    // Reversible run persists its bootstrap under the instance's runtime key.
    // Keep the mock Serve and the real CLI on the same disposable generation.
    let mut descriptor = hyperhub_core::config_store::new_descriptor();
    descriptor.memory_kib = 8192;
    descriptor.iterations = 1;
    descriptor.lanes = 1;
    let keyring = hyperhub_core::config_store::ConfigKeyring::from_runtime_master(
        descriptor,
        Zeroizing::new(vec![0; 32]),
    )
    .unwrap();
    hyperhub_core::config_store::save_encrypted_with_keyring(
        &root.0.join("config.bin"),
        &config,
        &keyring,
    )
    .unwrap();
    hyperhub_core::config_store::save_runtime_key(
        &root.0.join("runtime/config-key.bin"),
        &keyring,
        api_key.as_bytes(),
    )
    .unwrap();
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
    .with_attachment_directory(root.0.join("runtime/attachments"))
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
    #[cfg(target_os = "linux")]
    if let Some((_, path)) = &failed_fork_fixture {
        command.env("HH_FAILED_FORK_FILE", path);
    }
    #[cfg(target_os = "linux")]
    if let Some((_, path, listener)) = &signal_fixture {
        command.env("HH_SIGNAL_DENY_FILE", path).env(
            "HH_SIGNAL_DENY_PORT",
            listener.local_addr().unwrap().port().to_string(),
        );
    }
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
    let mut output = TargetOutput {
        reader: Arc::new(std::sync::Mutex::new(BufReader::new(
            target.0.stdout.take().unwrap(),
        ))),
        diagnostics: Arc::new(std::sync::Mutex::new(TargetDiagnostics {
            #[cfg(target_os = "linux")]
            root: root.0.clone(),
            #[cfg(target_os = "linux")]
            launcher_pid: target.0.id(),
            stdout: fs::File::create(root.0.join("target.stdout")).unwrap(),
            stages: fs::File::create(root.0.join("target-stages.log")).unwrap(),
            recent: std::collections::VecDeque::with_capacity(16),
        })),
    };
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
    #[cfg(target_os = "linux")]
    if let Some((executable, path)) = &failed_fork_fixture {
        writeln!(input, "process {}", executable.display()).unwrap();
        input.flush().unwrap();
        let first = target_line(&mut output, "").await;
        let fields: Vec<_> = first.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "{first}");
        assert_eq!(fields[0], "FILE_OK", "{first}");
        let child: u32 = fields[1].parse().unwrap();
        assert_ne!(child, pid);
        assert_eq!(
            fields[2].parse::<u64>().unwrap(),
            fs::metadata(path).unwrap().len()
        );
        for expected in [
            format!("FILTER_READY {child}"),
            format!("THREAD_OK {child}"),
            format!("FORK_EAGAIN {child} 11"),
            format!("FORK_EAGAIN {child} 11"),
            first,
            "FAILED_FORK_CASE_PASS".into(),
            format!("PROCESS_POLICY {pid} true"),
            format!("TARGET_OK {pid} 0"),
        ] {
            assert_eq!(target_line(&mut output, "").await, expected);
        }
        let ControlResponse::EngineHosts { hosts, .. } = exchange(
            &endpoint,
            &ControlRequest::GetEngineHosts {
                request_id: None,
                host_id: None,
            },
        )
        .await
        else {
            panic!("missing failed-fork helper Host inventory");
        };
        let helper = hosts
            .iter()
            .find(|host| host.root_pid == child && host.backend == original.backend)
            .unwrap_or_else(|| {
                panic!("failed-fork helper PID {child} was never registered as a managed Host")
            });
        // The short-lived target has already exited; its retained offline
        // registration proves that its two libc fork failures exercised hooks.
        eprintln!(
            "FAILED_FORK_MANAGED_HOST pid={child} online={}",
            helper.online
        );
    }
    #[cfg(target_os = "linux")]
    if let Some((executable, _, _)) = &signal_fixture {
        writeln!(input, "process {}", executable.display()).unwrap();
        input.flush().unwrap();
        assert_eq!(target_line(&mut output, "").await, "SIGNAL_CASE_PASS");
        assert_eq!(
            target_line(&mut output, "PROCESS_POLICY ").await,
            format!("PROCESS_POLICY {pid} true")
        );
        assert_eq!(
            target_line(&mut output, "TARGET_OK ").await,
            format!("TARGET_OK {pid} 0")
        );
    }
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
        orphan_monitor_barrier(&root.0, target.0.id(), root_pid);
        if force_ptrace {
            input.write_all(b"orphan\n").unwrap();
        } else {
            writeln!(input, "orphan-callbacks {}", policy_path.display()).unwrap();
        }
        input.flush().unwrap();
        // Parent identity and child acknowledgement come from independent
        // processes. Read this pair without discarding either possible order.
        let pair = tokio::time::timeout(Duration::from_secs(15), async {
            let first = target_line(&mut output, "").await;
            let second = target_line(&mut output, "").await;
            (first, second)
        })
        .await;
        let (first, second) = match pair {
            Ok(pair) => pair,
            Err(error) => {
                let diagnostics = output.diagnostics.lock().unwrap();
                capture_timeout_processes(
                    &diagnostics.root,
                    diagnostics.launcher_pid,
                    "orphan identity and acknowledgement pair",
                    "orphan handshake",
                );
                drop(diagnostics);
                panic!("orphan identity handshake timed out: {error}");
            }
        };
        pid = orphan_handshake_pid(&first, &second, root_pid, inherited_streams)
            .expect("invalid orphan identity handshake");
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
            let mut host_history = Vec::new();
            let enrolled = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    let response = exchange(
                        &endpoint,
                        &ControlRequest::GetEngineHosts {
                            request_id: None,
                            host_id: None,
                        },
                    )
                    .await;
                    let value = serde_json::to_value(&response).unwrap();
                    if host_history
                        .last()
                        .and_then(|entry: &serde_json::Value| entry.get("response"))
                        != Some(&value)
                    {
                        if host_history.len() == 32 {
                            host_history.remove(0);
                        }
                        host_history.push(serde_json::json!({
                            "at_ms": hyperhub_core::session::unix_timestamp_ms(),
                            "response": value,
                        }));
                    }
                    if let ControlResponse::EngineHosts { hosts, .. } = response {
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
            .await;
            original = match enrolled {
                Ok(host) => host,
                Err(error) => {
                    let diagnostics = output.diagnostics.lock().unwrap();
                    capture_timeout_processes(
                        &diagnostics.root,
                        diagnostics.launcher_pid,
                        "online surviving Gum child Host",
                        "Gum orphan enrollment",
                    );
                    fs::write(
                        root.0.join("last-hosts.json"),
                        serde_json::to_vec_pretty(&serde_json::json!({
                            "expected_pid": pid, "history": host_history,
                        }))
                        .unwrap(),
                    )
                    .unwrap();
                    drop(diagnostics);
                    panic!(
                        "surviving Gum child {pid} did not retain its enrolled Host: {error}; host history: {host_history:?}"
                    );
                }
            };
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
    .unwrap_or_else(|error| {
        #[cfg(target_os = "linux")]
        capture_timeout_processes(
            &root.0,
            target.0.id(),
            "launcher exit",
            "native Host final quit",
        );
        panic!("native launcher did not exit after quit within 15 seconds: {error}");
    });
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
    output: &mut TargetOutput,
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
async fn loader_check(input: &mut impl Write, output: &mut TargetOutput, pid: u32, library: &Path) {
    writeln!(input, "loader {}", library.display()).unwrap();
    input.flush().unwrap();
    assert_eq!(
        target_line(output, "LOADER_POLICY ").await,
        format!("LOADER_POLICY {pid} true")
    );
    target_line(output, "TARGET_OK ").await;
}
