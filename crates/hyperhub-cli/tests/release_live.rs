//! Real private-home CLI Serve + native Engine + forwarding worker + installer.
//! Every executable and installation destination is a copy inside this fixture.
#![cfg(any(target_os = "linux", windows))]
use hyperhub_core::{
    config::Config,
    config_store::{self, ExportFormat},
    control,
    release::{self, Action, Bundle, Phase, Plan, Request},
    session::{ControlRequest, ControlResponse},
};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("release fixture retained: {}", self.0.display());
            eprintln!(
                "{}",
                fs::read_to_string(self.0.join("serve.log")).unwrap_or_default()
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
                for entry in fs::read_dir(path).unwrap().flatten() {
                    writable(&entry.path());
                }
            } else {
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
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn cli(path: &Path, root: &Path) -> Command {
    let mut command = Command::new(path);
    command.env("HYPERHUB_HOME", root).stdin(Stdio::null());
    command
}
fn success(mut command: Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
async fn request(endpoint: &str, message: &ControlRequest) -> ControlResponse {
    tokio::time::timeout(
        Duration::from_secs(20),
        control::control_request(endpoint, message),
    )
    .await
    .unwrap()
    .unwrap()
}
async fn release_status(endpoint: &str, id: &str) -> release::RecordView {
    match request(
        endpoint,
        &ControlRequest::GetReleaseUpgrades {
            id: Some(id.into()),
        },
    )
    .await
    {
        ControlResponse::ReleaseUpgrades {
            status: Some(status),
        } => {
            assert!(status.error.is_none(), "{status:?}");
            assert_eq!(status.records.len(), 1);
            status.records.into_iter().next().unwrap()
        }
        other => panic!("release status missing: {other:?}"),
    }
}
async fn line(receiver: &mut mpsc::Receiver<String>) -> String {
    let started = tokio::time::Instant::now();
    loop {
        match receiver.try_recv() {
            Ok(line) => return line,
            Err(mpsc::TryRecvError::Empty) => {
                assert!(
                    started.elapsed() < Duration::from_secs(30),
                    "target output timed out"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("target stdout ended: {error}"),
        }
    }
}
async fn workload(
    target: &mut Process,
    output: &mut mpsc::Receiver<String>,
    command: &str,
    pid: u32,
    count: usize,
) {
    writeln!(target.0.stdin.as_mut().unwrap(), "{command}").unwrap();
    target.0.stdin.as_mut().unwrap().flush().unwrap();
    assert_eq!(line(output).await, format!("OK {pid} {count}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a final CLI with its verified embedded Engine; run through the platform Suite"]
async fn private_home_release_keeps_native_target_streams_and_installs_after_joint_finalize() {
    let source = std::env::var_os("HYPERHUB_TEST_RELEASE_HYPERHUB")
        .or_else(|| std::env::var_os("HH_FORWARD_WORKER_FIXTURE"))
        .map(PathBuf::from)
        .expect("set HYPERHUB_TEST_RELEASE_HYPERHUB to the built final CLI");
    let root = Root(std::env::temp_dir().join(format!(
        "hh-release-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    )));
    fs::create_dir(&root.0).unwrap();
    let installed = root
        .0
        .join(format!("installed{}", std::env::consts::EXE_SUFFIX));
    let candidate = root
        .0
        .join(format!("candidate{}", std::env::consts::EXE_SUFFIX));
    fs::copy(&source, &installed).unwrap();
    fs::copy(&source, &candidate).unwrap();
    // Acceptance binaries are immutable. Change only this private copy before
    // adding the valid executable overlay used to distinguish the candidate.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    {
        let mut permissions = fs::metadata(&candidate).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&candidate, permissions).unwrap();
    }
    fs::OpenOptions::new()
        .append(true)
        .open(&candidate)
        .unwrap()
        .write_all(b"\0hyperhub-private-release-candidate-overlay-v1\0")
        .unwrap();
    let old_digest = release::installer::digest(&installed).unwrap();
    assert_ne!(old_digest, release::installer::digest(&candidate).unwrap());
    fs::write(
        root.0.join("upgrade-check.json"),
        serde_json::to_vec(&serde_json::json!({
            "last_check_ms": hyperhub_core::session::unix_timestamp_ms(),
        }))
        .unwrap(),
    )
    .unwrap();
    let mut exporter = cli(&candidate, &root.0);
    exporter
        .arg("export-upgrade-bundle")
        .arg(root.0.join("bundle"));
    success(exporter);
    let bundle: Bundle =
        serde_json::from_slice(&fs::read(root.0.join("bundle/bundle.json")).unwrap()).unwrap();
    bundle.validate().unwrap();
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut config = Config::default();
    config.listener.socks_listen = reservation.local_addr().unwrap().to_string();
    config.audit.log = Some(root.0.join("audit.jsonl"));
    drop(reservation);
    let config_path = root.0.join("fixture.toml");
    config_store::export(&config_path, &config, ExportFormat::Toml, None).unwrap();
    let password = root.0.join("admin-password");
    config_store::save_private_bytes(&password, b"local-release-fixture-password").unwrap();
    let mut importer = cli(&installed, &root.0);
    importer
        .arg("import")
        .arg(&config_path)
        .arg("--admin-password-file")
        .arg(&password);
    success(importer);
    let log = fs::File::create(root.0.join("serve.log")).unwrap();
    let mut resident = cli(&installed, &root.0);
    resident
        .arg("serve")
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    let mut resident = Process(resident.spawn().unwrap());
    let serve_pid = resident.0.id();
    let endpoint = control::instance_control_endpoint(&root.0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if control::control_request(&endpoint, &ControlRequest::Ping)
            .await
            .is_ok()
        {
            break;
        }
        assert!(
            resident.0.try_wait().unwrap().is_none(),
            "private resident exited"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "private resident startup timed out"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let target_path = root
        .0
        .join(format!("stream-target{}", std::env::consts::EXE_SUFFIX));
    let mut compiler = Command::new("rustc");
    compiler
        .arg("--edition=2021")
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/release_tcp_target.rs"),
        )
        .arg("-o")
        .arg(&target_path);
    success(compiler);
    let mut launcher = cli(&installed, &root.0);
    launcher.arg("run");
    #[cfg(target_os = "linux")]
    launcher.args(["--backend", "ptrace"]);
    launcher
        .arg("--")
        .arg(&target_path)
        .arg(origin.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(fs::File::create(root.0.join("target.log")).unwrap());
    let mut target = Process(launcher.spawn().unwrap());
    let (sender, mut output) = mpsc::channel();
    let stdout = target.0.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let ready = line(&mut output).await;
    let target_pid: u32 = ready
        .strip_prefix("READY ")
        .expect("target ready")
        .parse()
        .unwrap();
    workload(&mut target, &mut output, "open", target_pid, 1).await;
    workload(&mut target, &mut output, "ping", target_pid, 1).await;
    let initial_generation = match request(&endpoint, &ControlRequest::GetStatus).await {
        ControlResponse::Status {
            pid,
            forward_workers: Some(workers),
            connections,
            engine_hosts,
            ..
        } => {
            assert_eq!(pid, serve_pid);
            assert_eq!(connections.len(), 1);
            assert!(engine_hosts
                .iter()
                .any(|h| h.online && h.root_pid == target_pid));
            workers.active_generation
        }
        other => panic!("initial release status: {other:?}"),
    };
    let key = fs::read_to_string(root.0.join("runtime/api-key")).unwrap();
    let id = "private-release-complete";
    let prepare = Request {
        id: id.into(),
        issued_at_ms: hyperhub_core::session::unix_timestamp_ms(),
        action: Action::Prepare {
            auto_commit: true,
            plan: Plan {
                engine: root.0.join("bundle").join(&bundle.engine_file),
                bundle: bundle.clone(),
                executable: candidate.clone(),
                cache: root.0.join("release-cache"),
                target: installed.clone(),
                expected_target_sha256: old_digest.0.clone(),
            },
        },
    };
    // The owner request uses a separate connection that closes immediately.
    // Further work must be carried by the resident durable coordinator.
    let proof = prepare.proof(key.trim().as_bytes()).unwrap();
    assert!(matches!(
        request(
            &endpoint,
            &ControlRequest::ReleaseUpgrade {
                request: prepare,
                proof
            }
        )
        .await,
        ControlResponse::ReleaseUpgrade { .. }
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut switched = false;
    loop {
        let status = release_status(&endpoint, id).await;
        assert!(
            !matches!(
                status.phase,
                Phase::RollingBack | Phase::RolledBack | Phase::RequiresRestart | Phase::Failed
            ),
            "{status:?}"
        );
        if status.phase == Phase::Observing && !switched {
            assert!(!status.finalize_decided && !status.installation_confirmed);
            assert_eq!(release::installer::digest(&installed).unwrap(), old_digest);
            workload(&mut target, &mut output, "open", target_pid, 2).await;
            workload(&mut target, &mut output, "ping", target_pid, 2).await;
            let ControlResponse::Status {
                pid,
                forward_workers: Some(workers),
                engine_hosts,
                connections,
                ..
            } = request(&endpoint, &ControlRequest::GetStatus).await
            else {
                panic!("missing active status")
            };
            assert_eq!(pid, serve_pid);
            assert_ne!(workers.active_generation, initial_generation);
            assert_eq!(connections.len(), 2);
            assert!(engine_hosts
                .iter()
                .any(|h| h.online && h.root_pid == target_pid && h.snapshot.active.generation > 0));
            switched = true;
        }
        if status.installation_confirmed {
            assert!(status.finalize_decided);
            assert_eq!(
                release::installer::digest(&installed).unwrap(),
                (bundle.worker_sha256.clone(), bundle.worker_size)
            );
            break;
        }
        assert!(
            resident.0.try_wait().unwrap().is_none(),
            "resident exited during upgrade"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "release did not install: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(switched, "joint committed observation was never witnessed");
    workload(&mut target, &mut output, "ping", target_pid, 2).await;
    let abort = Request {
        id: id.into(),
        issued_at_ms: hyperhub_core::session::unix_timestamp_ms(),
        action: Action::Abort,
    };
    let proof = abort.proof(key.trim().as_bytes()).unwrap();
    assert!(matches!(
        request(
            &endpoint,
            &ControlRequest::ReleaseUpgrade {
                request: abort,
                proof
            }
        )
        .await,
        ControlResponse::Error { .. }
    ));
    workload(&mut target, &mut output, "close", target_pid, 0).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = release_status(&endpoint, id).await;
        if status.phase == Phase::Complete {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "release did not drain: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let ControlResponse::Status { pid, .. } = request(&endpoint, &ControlRequest::GetStatus).await
    else {
        panic!("missing final status")
    };
    assert_eq!(pid, serve_pid);
    writeln!(target.0.stdin.as_mut().unwrap(), "quit").unwrap();
    assert!(target.0.wait().unwrap().success());
    echo.abort();
    eprintln!(
        "RELEASE_NATIVE_OK serve_pid={serve_pid} target_pid={target_pid} installed_sha256={}",
        bundle.worker_sha256
    );
}
