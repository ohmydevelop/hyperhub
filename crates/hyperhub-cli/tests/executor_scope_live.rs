//! A local IPC request does not enroll its existing external executor.
#![cfg(any(target_os = "linux", windows))]
use base64::Engine;
use hyperhub_core::{
    config::Config,
    control::{self, ControlService},
    session::{ControlRequest, ControlResponse, SessionRegistry},
    socks::SocksService,
};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc},
    time::Duration,
};
use zeroize::Zeroizing;

#[allow(dead_code)]
#[path = "../../../tests/fixtures/executor_scope_target.rs"]
mod fixture;

struct PrivateRoot(PathBuf);
impl Drop for PrivateRoot {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "executor scope diagnostics retained at {}",
                self.0.display()
            );
        } else {
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
                } else if metadata.permissions().readonly() {
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
}

struct Process(Child, mpsc::Receiver<String>);
impl Process {
    fn spawn(mut command: Command, root: &Path, role: &str) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(
                fs::File::create(root.join(format!("{role}.log"))).unwrap(),
            ))
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        let mut transcript = fs::File::create(root.join(format!("{role}.stdout"))).unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                writeln!(transcript, "{line}").unwrap();
                transcript.flush().unwrap();
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        Self(child, receive)
    }

    async fn line(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match self.1.try_recv() {
                    Ok(line) => return line,
                    Err(mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("fixture stdout ended: {error}"),
                }
            }
        })
        .await
        .expect("executor scope output timed out")
    }

    async fn quit(&mut self) {
        writeln!(self.0.stdin.as_mut().unwrap(), "quit").unwrap();
        self.0.stdin.as_mut().unwrap().flush().unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    assert!(status.success(), "fixture exited {status}");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            #[cfg(unix)]
            unsafe {
                // Each fixture command creates its own private process group.
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn isolate(command: &mut Command, root: &Path) {
    for name in [
        "HYPERHUB_SESSION_ID",
        "HYPERHUB_SESSION_TOKEN",
        "HYPERHUB_SOCKS_ADDR",
        "HYPERHUB_CONTROL_ENDPOINT",
        "HYPERHUB_SESSION_ENV_KEYS",
    ] {
        command.env_remove(name);
    }
    command
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("HYPERHUB_HOME", root)
        .env("XDG_RUNTIME_DIR", root.join("xdg"))
        .env("TMPDIR", root.join("tmp"))
        .env("TMP", root.join("tmp"))
        .env("TEMP", root.join("tmp"));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run with the built CLI through the Linux backend Suite"]
async fn ptrace_existing_ipc_executor_is_outside_the_managed_tree() {
    scenario("ptrace").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run with the built embedded CLI through the platform Suite"]
async fn gum_existing_ipc_executor_is_outside_the_managed_tree() {
    scenario("gum").await;
}

async fn scenario(backend: &str) {
    #[cfg(target_os = "linux")]
    let temporary = PathBuf::from("/var/tmp");
    #[cfg(windows)]
    let temporary = std::env::temp_dir();
    let root = PrivateRoot(temporary.join(format!("hh-scope-{:08x}", rand::random::<u32>())));
    fs::create_dir(&root.0).unwrap();
    for path in [
        root.0.clone(),
        root.0.join("home"),
        root.0.join("runtime"),
        root.0.join("xdg"),
        root.0.join("tmp"),
    ] {
        fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let executable = root
        .0
        .join(format!("scope-target{}", std::env::consts::EXE_SUFFIX));
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/executor_scope_target.rs");
    // Compile before isolating HOME, so rustup can locate the test toolchain.
    let compiled = Command::new("rustc")
        .args(["--edition=2021"])
        .arg(source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let secret = root.0.join("executor-scope-dummy-secret");
    fs::write(&secret, fixture::DUMMY_DATA).unwrap();
    let mut external = Command::new(&executable);
    external.arg("server").arg(&secret);
    isolate(&mut external, &root.0);
    let mut executor = Process::spawn(external, &root.0, "external-executor");
    let ready = executor.line().await;
    let fields: Vec<_> = ready.split_whitespace().collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0], "SERVER_READY");
    let executor_pid = fields[1].parse::<u32>().unwrap();
    let birth = fields[2].parse::<u64>().unwrap();
    assert_eq!(executor_pid, executor.0.id());
    assert_eq!(fixture::process_birth(executor_pid), birth);
    let address = fields[3].to_string();

    let api_key = format!(
        "hhk_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([19; 32])
    );
    hyperhub_core::config_store::save_private_bytes(
        &root.0.join("runtime/api-key"),
        api_key.as_bytes(),
    )
    .unwrap();
    let sessions =
        SessionRegistry::default().with_api_key(Zeroizing::new(api_key.as_bytes().to_vec()));
    let mut config = Config::default();
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    config.listener.socks_listen = reserved.local_addr().unwrap().to_string();
    config.audit.log = Some(root.0.join("audit.jsonl"));
    config.sandbox.file.enabled = true;
    config.sandbox.file.rules.push(serde_json::from_value(serde_json::json!({
        "uuid":"11574a8c-8ed4-46f8-9f23-d4c0db7d2afb", "id":"dummy-secret-deny", "action":"deny",
        "patterns":[{"pattern":"executor-scope-dummy-secret$"}], "operations":["read"]
    })).unwrap());
    let socks = SocksService::new_with_debug_output(
        Arc::new(config),
        sessions.clone(),
        Vec::new(),
        false,
        None,
        b"executor-scope-dummy-master",
    )
    .unwrap();
    drop(reserved);
    socks.prepare_listener().await.unwrap();
    let service = ControlService::new(
        sessions.clone(),
        socks.connections(),
        socks.tls_ca_pem().into(),
        socks.audit_writer(),
        socks.runtime(),
        Zeroizing::new(vec![19; 32]),
    )
    .with_socks_listener(socks.listener_controller())
    .with_engine_upgrades(
        &root.0.join("upgrades"),
        Zeroizing::new(api_key.as_bytes().to_vec()),
    )
    .unwrap();
    let endpoint = control::instance_control_endpoint(&root.0);
    let control_task = tokio::spawn(control::run_control_server(endpoint.clone(), service));
    let socks_task = tokio::spawn(socks.run());
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
    assert!(sessions.snapshot().is_empty());

    let cli = std::env::var_os("HYPERHUB_TEST_ENGINE_HYPERHUB")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_hyperhub").into());
    let mut launch = Command::new(cli);
    launch
        .args(["run", "--backend", backend, "--"])
        .arg(&executable)
        .arg("client")
        .arg(&address)
        .arg(&secret);
    isolate(&mut launch, &root.0);
    let mut client = Process::spawn(launch, &root.0, "managed-client");
    let launcher_pid = client.0.id();
    let launcher_birth = fixture::process_birth(launcher_pid);
    let denied = client.line().await;
    let client_pid = denied
        .strip_prefix("DIRECT_READ_DENIED ")
        .expect("managed file read was not denied")
        .parse::<u32>()
        .unwrap();
    let client_birth = fixture::process_birth(client_pid);
    assert_ne!(client_pid, executor_pid);
    assert_eq!(
        client.line().await,
        format!("DELEGATED_READ {client_pid} {executor_pid} {birth}")
    );
    assert_eq!(
        executor.line().await,
        format!("SERVER_READ {executor_pid} {birth}")
    );
    let response = control::control_request(&endpoint, &ControlRequest::GetStatus)
        .await
        .unwrap();
    let ControlResponse::Status {
        sessions: snapshot, ..
    } = response
    else {
        panic!("missing status")
    };
    let members: Vec<_> = snapshot
        .iter()
        .flat_map(|s| s.processes.iter().map(|p| p.pid))
        .collect();
    assert!(
        members.contains(&client_pid),
        "actual managed client must be present in the full member list"
    );
    assert!(
        !members.contains(&executor_pid),
        "an unrelated IPC executor must not be enrolled by the client request"
    );
    assert_eq!(fixture::process_birth(executor_pid), birth);
    assert_eq!(fixture::process_birth(client_pid), client_birth);
    eprintln!("EXECUTOR_SCOPE_OK backend={backend} launcher_pid={launcher_pid} launcher_birth={launcher_birth} managed_pid={client_pid} managed_birth={client_birth} external_pid={executor_pid} external_birth={birth} members={members:?} direct=denied delegated=external-read private_root={}", root.0.display());
    client.quit().await;
    executor.quit().await;
    control_task.abort();
    socks_task.abort();
    let _ = control_task.await;
    let _ = socks_task.await;
}
