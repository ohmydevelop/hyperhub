//! CLI output regressions with private installation files and a local control stub.
#![cfg(any(unix, windows))]

use base64::Engine;
use hyperhub_core::{
    config_store,
    framing::{read_frame, write_frame},
    release::{
        installer::{self, Job, SignedAcknowledgement, SignedJob},
        Phase, RecordView, Status,
    },
    session::{ControlRequest, ControlResponse},
};
use std::{fs, path::PathBuf, process::Output, time::Duration};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("hh-notify-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(root.join("runtime")).unwrap();
        Self(root)
    }

    fn command(&self, args: &[&str]) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_hyperhub"));
        command
            .args(args)
            .env("HYPERHUB_HOME", &self.0)
            .env("HOME", self.0.join("home"))
            .env("USERPROFILE", self.0.join("home"))
            .env_remove("HYPERHUB_CONFIG_PASSWORD")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
struct Server(tokio::net::UnixListener);

#[cfg(unix)]
impl Server {
    fn bind(fixture: &Fixture) -> Self {
        Self(tokio::net::UnixListener::bind(config_store_endpoint(fixture)).unwrap())
    }

    async fn accept(&mut self) -> tokio::net::UnixStream {
        self.0.accept().await.unwrap().0
    }
}

#[cfg(windows)]
struct Server {
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    endpoint: String,
}

#[cfg(windows)]
impl Server {
    fn bind(fixture: &Fixture) -> Self {
        let endpoint = config_store_endpoint(fixture);
        let pipe = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&endpoint)
            .unwrap();
        Self { pipe, endpoint }
    }

    async fn accept(&mut self) -> tokio::net::windows::named_pipe::NamedPipeServer {
        self.pipe.connect().await.unwrap();
        let next = tokio::net::windows::named_pipe::ServerOptions::new()
            .create(&self.endpoint)
            .unwrap();
        std::mem::replace(&mut self.pipe, next)
    }
}

fn config_store_endpoint(fixture: &Fixture) -> String {
    hyperhub_core::control::instance_control_endpoint(&fixture.0)
}

fn record(phase: Phase, confirmed: bool) -> RecordView {
    RecordView {
        id: "celebration-test".into(),
        version: "1.2.3".into(),
        phase,
        reason: None,
        created_at_ms: 0,
        updated_at_ms: 0,
        finalize_decided: confirmed,
        installation_confirmed: confirmed,
        engine_hosts: 0,
        worker_generation: None,
        worker_pid: None,
        helper_pid: None,
        requires_restart_processes: vec![],
    }
}

async fn status_output(args: &[&str], records: Vec<RecordView>) -> Output {
    let fixture = Fixture::new();
    let mut server = Server::bind(&fixture);
    let serve = async {
        for record in records {
            let mut stream = server.accept().await;
            let request: ControlRequest = read_frame(&mut stream).await.unwrap();
            assert!(
                matches!(request, ControlRequest::GetReleaseUpgrades { id: Some(id) } if id == record.id)
            );
            write_frame(
                &mut stream,
                &ControlResponse::ReleaseUpgrades {
                    status: Some(Status {
                        records: vec![record],
                        records_omitted: 0,
                        error: None,
                    }),
                },
            )
            .await
            .unwrap();
        }
    };
    tokio::time::timeout(Duration::from_secs(15), async {
        let (_, output) = tokio::join!(serve, fixture.command(args).output());
        output.unwrap()
    })
    .await
    .expect("notification must consume every expected phase and exit")
}

#[tokio::test]
async fn watcher_waits_for_installation_and_celebrates_before_old_connections_finish() {
    let output = status_output(
        &["upgrade-watch-helper", "celebration-test"],
        vec![
            record(Phase::Preparing, false),
            record(Phase::Installing, false),
            record(Phase::Draining, false),
            record(Phase::Draining, true),
        ],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.starts_with("\n🎉 HyperHub 1.2.3 updated successfully!"));
    assert_eq!(text.matches('🎉').count(), 1);
    assert!(!text.contains('\x1b'));
    assert!(output.stderr.is_empty());
}

#[tokio::test]
async fn watcher_reports_uncertain_or_failed_updates_without_celebrating() {
    for phase in [
        Phase::InstallationPending,
        Phase::RequiresRestart,
        Phase::RolledBack,
        Phase::Failed,
    ] {
        let mut record = record(phase, false);
        record.reason = Some("fixture update needs attention".into());
        let output =
            status_output(&["upgrade-watch-helper", "celebration-test"], vec![record]).await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("fixture update needs attention"));
        assert!(error.contains("hyperhub upgrade status celebration-test"));
    }
}

#[tokio::test]
async fn upgrade_status_keeps_completed_results_as_json() {
    let output = status_output(
        &["upgrade", "status", "celebration-test"],
        vec![record(Phase::Complete, true)],
    )
    .await;
    assert!(output.status.success());
    let response: ControlResponse = serde_json::from_slice(&output.stdout).unwrap();
    assert!(matches!(
        response,
        ControlResponse::ReleaseUpgrades { status: Some(_) }
    ));
    assert!(output.stderr.is_empty());
}

async fn install_output(changed_target: bool, start_after_install: bool, notify: bool) -> Output {
    let fixture = Fixture::new();
    let mut server = Server::bind(&fixture);
    let key = format!(
        "hhk_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32])
    );
    config_store::save_private_bytes(&fixture.0.join("runtime/api-key"), key.as_bytes()).unwrap();
    let source = fixture.0.join("candidate");
    let target = fixture
        .0
        .join(format!("installed{}", std::env::consts::EXE_SUFFIX));
    fs::write(&source, b"private installation fixture, not an executable").unwrap();
    fs::write(&target, b"old private installation").unwrap();
    let (sha256, size) = installer::digest(&source).unwrap();
    let job = Job {
        id: "celebration-test".into(),
        attempt: 1,
        issued_at_ms: hyperhub_core::session::unix_timestamp_ms(),
        source,
        expected_target_sha256: installer::digest(&target).unwrap().0,
        target: target.clone(),
        sha256: sha256.clone(),
        size,
        start_after_install,
    };
    let path = fixture.0.join("install.json");
    SignedJob::sign(job, key.as_bytes())
        .unwrap()
        .write(&path)
        .unwrap();
    if changed_target {
        fs::write(&target, b"changed private installation").unwrap();
    }
    let mut command = fixture.command(&["upgrade-install-helper"]);
    command.arg(&path);
    if notify {
        command.args(["--notify-version", "1.2.3"]);
    }
    let serve = async {
        let mut stream = server.accept().await;
        let request: ControlRequest = read_frame(&mut stream).await.unwrap();
        let ControlRequest::ReleaseHelperAck { ack, .. } = request else {
            panic!("unexpected request")
        };
        assert_eq!(ack.installed, !changed_target);
        write_frame(&mut stream, &ControlResponse::Ok)
            .await
            .unwrap();
    };
    let output = tokio::time::timeout(Duration::from_secs(15), async {
        let (_, output) = tokio::join!(serve, command.output());
        output.unwrap()
    })
    .await
    .expect("installation helper must exit");
    let receipt =
        SignedAcknowledgement::read(&path.with_extension("ack.json"), key.as_bytes()).unwrap();
    assert_eq!(receipt.ack.installed, !changed_target);
    if !changed_target {
        assert_eq!(installer::digest(&target).unwrap(), (sha256, size));
    }
    output
}

#[tokio::test]
async fn installer_celebrates_only_after_verified_installation() {
    let output = install_output(false, false, true).await;
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("🎉 HyperHub 1.2.3 updated successfully!"));
    assert!(output.stderr.is_empty());

    let output = install_output(false, false, false).await;
    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "resident helpers must remain quiet"
    );
}

#[tokio::test]
async fn installer_does_not_celebrate_failed_installation_or_requested_start() {
    for (changed_target, start_after_install) in [(true, false), (false, true)] {
        let output = install_output(changed_target, start_after_install, true).await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}
