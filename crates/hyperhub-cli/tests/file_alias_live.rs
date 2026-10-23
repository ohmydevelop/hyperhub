//! Actual packaged CLI regressions for denied content and namespace aliases.
#![cfg(any(target_os = "linux", windows))]
use hyperhub_core::{
    config::{Config, FileSandboxOperation, FileSandboxPattern, FileSandboxRule, SandboxAction},
    config_store::{self, ExportFormat},
};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
#[path = "support/literal_path_pattern.rs"]
mod literal_path_pattern;
#[path = "support/private_process.rs"]
mod private_process;

const DUMMY: &[u8] = b"private-file-alias-fixture\n";

struct Fixture {
    root: PathBuf,
    cli: PathBuf,
    target: Option<private_process::PrivateProcess>,
    launcher: Option<Child>,
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
                panic!("private file-alias CLI timed out: {command:?}");
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
    #[cfg(windows)]
    fn update(&self, config: &Config) {
        let unlocked = config_store::load_encrypted(
            &self.root.join("config.bin"),
            b"private-file-alias-fixture",
        )
        .unwrap();
        let config_json = serde_json::to_string(
            &hyperhub_core::config_document::ConfigDocument::from_config(config),
        )
        .unwrap();
        let proof =
            hyperhub_core::session::config_update_proof(&unlocked.session_auth_key, &config_json)
                .unwrap();
        config_store::save_encrypted_with_descriptor(
            &self.root.join("config.bin"),
            config,
            b"private-file-alias-fixture",
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
            "private map policy update failed: {response:?}"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.target.take());
        if let Some(mut child) = self.launcher.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let mut command = self.command();
        command
            .arg("stop")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Ok(mut child) = command.spawn() {
            let deadline = Instant::now() + Duration::from_secs(15);
            while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        if std::thread::panicking() {
            eprintln!("file alias diagnostics retained: {}", self.root.display());
            for name in ["target.stderr", "serve.log", "command.stderr"] {
                eprintln!(
                    "FILE_ALIAS_LOG {name}: {}",
                    fs::read_to_string(self.root.join(name)).unwrap_or_default()
                );
            }
        } else {
            private_process::remove_fixture(&self.root).unwrap();
        }
    }
}

fn line(receiver: &mpsc::Receiver<String>) -> String {
    receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("private file-alias target made no progress")
}

#[cfg(target_os = "linux")]
fn inherited_path(root: &std::path::Path) -> (std::os::fd::OwnedFd, bool) {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::ffi::OsStrExt,
        },
    };
    let source = CString::new(root.join("auth.key").as_os_str().as_bytes()).unwrap();
    let descriptor = unsafe { libc::open(source.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    assert!(
        descriptor >= 0,
        "cannot prepare inherited O_PATH fixture descriptor"
    );
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let destination = root.join("empty-preflight.alias");
    let destination_c = CString::new(destination.as_os_str().as_bytes()).unwrap();
    let result = unsafe {
        libc::linkat(
            descriptor.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            destination_c.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    let supported = result == 0;
    if supported {
        fs::remove_file(destination).unwrap();
    } else {
        let error = std::io::Error::last_os_error();
        assert!(
            matches!(error.raw_os_error(), Some(libc::EPERM | libc::ENOENT)),
            "unexpected unmanaged empty-path preflight error: {error}"
        );
        eprintln!("FILE_ALIAS_PREFLIGHT linkat-empty=unsupported error={error}");
    }
    (descriptor, supported)
}

fn scenario(backend: &str) {
    let cli = PathBuf::from(
        std::env::var_os("HYPERHUB_TEST_ALIAS_HYPERHUB")
            .or_else(|| std::env::var_os("HYPERHUB_TEST_ENGINE_HYPERHUB"))
            .expect("set HYPERHUB_TEST_ALIAS_HYPERHUB"),
    );
    #[cfg(target_os = "linux")]
    let temporary = PathBuf::from("/var/tmp");
    #[cfg(windows)]
    let temporary = std::env::temp_dir();
    let root = temporary.join(format!("hh-alias-{:08x}", rand::random::<u32>()));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for name in ["home", "runtime", "tmp"] {
        fs::create_dir(root.join(name)).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut fixture = Fixture {
        root,
        cli,
        target: None,
        launcher: None,
    };
    fs::write(
        fixture.root.join("upgrade-check.json"),
        serde_json::to_vec(&serde_json::json!({
            "last_check_ms": hyperhub_core::session::unix_timestamp_ms()
        }))
        .unwrap(),
    )
    .unwrap();
    config_store::save_private_bytes(
        &fixture.root.join("password"),
        b"private-file-alias-fixture",
    )
    .unwrap();
    for name in [
        "auth.key",
        "rename.key",
        "ordinary.txt",
        "ordinary-rename.txt",
        "exchange-ordinary.txt",
        "exchange.key",
        "write-link.data",
        "write-rename.data",
    ] {
        fs::write(fixture.root.join(name), DUMMY).unwrap();
    }
    #[cfg(windows)]
    for name in [
        "mapping-read.data",
        "mapping-write.data",
        "delete-close.data",
        "delete-allowed.data",
        "supersede.data",
        "supersede-allowed.data",
    ] {
        fs::write(fixture.root.join(name), DUMMY).unwrap();
    }
    fs::hard_link(
        fixture.root.join("auth.key"),
        fixture.root.join("existing.alias"),
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("auth.key", fixture.root.join("source.symlink")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("ordinary.txt", fixture.root.join("lexical.key")).unwrap();
    #[cfg(target_os = "linux")]
    {
        fs::create_dir(fixture.root.join("subdirectory")).unwrap();
        std::os::unix::fs::symlink("subdirectory", fixture.root.join("directory.symlink")).unwrap();
        fs::create_dir(fixture.root.join("exact-directory")).unwrap();
        fs::write(fixture.root.join("exact-directory/protected.data"), DUMMY).unwrap();
        std::os::unix::fs::symlink(
            "exact-directory",
            fixture.root.join("exact-directory.symlink"),
        )
        .unwrap();
    }

    let mut config = Config::default();
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    config.listener.socks_listen = reservation.local_addr().unwrap().to_string();
    drop(reservation);
    config.sandbox.file.enabled = true;
    config.sandbox.file.error_action = SandboxAction::Deny;
    config.sandbox.file.rules.push(FileSandboxRule {
        uuid: String::new(),
        id: "deny-dummy-file-alias-read".into(),
        enabled: true,
        priority: 0,
        action: SandboxAction::Deny,
        patterns: vec![FileSandboxPattern {
            enabled: true,
            pattern: r"(?:^|[/\\])(?:auth|rename|lexical|exchange)\.key$".into(),
        }],
        operations: vec![FileSandboxOperation::Read],
        protection: None,
        legacy: Default::default(),
    });
    let mut write_only = config.sandbox.file.rules[0].clone();
    write_only.id = "deny-dummy-file-alias-write".into();
    write_only.patterns[0].pattern = r"(?:^|[/\\])write-(?:link|rename)\.data$".into();
    write_only.operations = vec![FileSandboxOperation::Write];
    config.sandbox.file.rules.push(write_only);
    #[cfg(windows)]
    {
        let mut deletion = config.sandbox.file.rules[0].clone();
        deletion.id = "deny-implicit-file-deletion".into();
        deletion.patterns[0].pattern = r"(?:^|[/\\])(?:delete-close|supersede)\.data$".into();
        deletion.operations = vec![FileSandboxOperation::Delete];
        config.sandbox.file.rules.push(deletion);
    }
    #[cfg(target_os = "linux")]
    {
        let mut exact = config.sandbox.file.rules[0].clone();
        exact.id = "deny-exact-dummy-file-alias-read".into();
        exact.patterns[0].pattern =
            literal_path_pattern::exact(&fixture.root.join("exact-directory/protected.data"));
        config.sandbox.file.rules.push(exact);
    }
    let file = fixture.root.join("fixture.toml");
    config_store::export(&file, &config, ExportFormat::Toml, None).unwrap();
    let mut import = fixture.command();
    import
        .arg("import")
        .arg(file)
        .arg("--admin-password-file")
        .arg(fixture.root.join("password"));
    fixture.output(import);
    fixture.success(&["start"]);

    let target = fixture
        .root
        .join(format!("file-alias-target{}", std::env::consts::EXE_SUFFIX));
    let mut compiler = Command::new("rustc");
    compiler
        .arg("--edition=2021")
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/file_alias_target.rs"),
        )
        .arg("-o")
        .arg(&target);
    fixture.output(compiler);
    let mut launch = fixture.command();
    launch.arg("run");
    #[cfg(target_os = "linux")]
    launch.args(["--backend", backend]);
    launch
        .arg("--")
        .arg(&target)
        .arg(&fixture.root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(fs::File::create(fixture.root.join("target.stderr")).unwrap());
    #[cfg(target_os = "linux")]
    let (inherited, empty_supported) = inherited_path(&fixture.root);
    #[cfg(target_os = "linux")]
    {
        use std::os::{fd::AsRawFd, unix::process::CommandExt};
        let descriptor = inherited.as_raw_fd();
        launch
            .env("HH_ALIAS_INHERITED_FD", descriptor.to_string())
            .env("HH_ALIAS_EMPTY_SUPPORTED", empty_supported.to_string());
        unsafe {
            launch.pre_exec(move || {
                if libc::fcntl(descriptor, libc::F_SETFD, 0) == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
    }
    let mut child = launch.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    fixture.launcher = Some(child);
    let (send, receive) = mpsc::channel();
    let mut transcript = fs::File::create(fixture.root.join("target.stdout")).unwrap();
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
    let ready = line(&receive);
    let pid = ready
        .strip_prefix("READY ")
        .expect("target did not initialize")
        .parse()
        .unwrap();
    fixture.target = Some(private_process::PrivateProcess::capture(pid, &target).unwrap());
    #[cfg(windows)]
    {
        let mut read = config.sandbox.file.rules[0].clone();
        read.id = "deny-warmed-map-read".into();
        read.patterns[0].pattern = r"(?:^|[/\\])mapping-read\.data$".into();
        config.sandbox.file.rules.push(read);
        let mut write = config.sandbox.file.rules[1].clone();
        write.id = "deny-warmed-map-write".into();
        write.patterns[0].pattern = r"(?:^|[/\\])mapping-write\.data$".into();
        config.sandbox.file.rules.push(write);
        fixture.update(&config);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            writeln!(input, "policy-check").unwrap();
            input.flush().unwrap();
            let response = line(&receive);
            if response == format!("POLICY_READY {pid}") {
                break;
            }
            assert_eq!(response, format!("POLICY_PENDING {pid}"));
            assert!(
                Instant::now() < deadline,
                "map policy did not reach actual target {pid}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        eprintln!(
            "FILE_ALIAS_MAP_POLICY_READY pid={pid} read=deny write=deny warmed_sections=true"
        );
    }
    writeln!(input, "go").unwrap();
    input.flush().unwrap();
    let mut outcomes = BTreeMap::new();
    loop {
        let reply = line(&receive);
        if reply == "DONE" {
            break;
        }
        let fields: Vec<_> = reply.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "invalid fixture reply: {reply}");
        assert_eq!(fields[0], "CASE");
        assert!(outcomes
            .insert(fields[1].to_owned(), fields[2].to_owned())
            .is_none());
    }
    // Record the gap explicitly: arbitrary filename regex rules do not imply
    // that all hard links created outside the managed tree have an identity rule.
    match outcomes["preexisting-hardlink-first"].as_str() {
        "readable" => eprintln!("FILE_ALIAS_SCOPE_GAP backend={backend} preexisting-hardlink-first=unprotected property=filename-regex private_root={}", fixture.root.display()),
        "denied" => eprintln!("FILE_ALIAS_SCOPE_PROTECTED backend={backend} preexisting-hardlink-first=denied private_root={}", fixture.root.display()),
        other => panic!("invalid preexisting alias diagnostic: {other}"),
    }
    let mut expected = vec![
        "direct-read",
        "copy",
        "rename",
        "hardlink",
        "write-only-direct-write",
        "write-only-hardlink",
        "write-only-rename",
        "combined-rw-open",
        "create-read-open",
    ];
    #[cfg(windows)]
    expected.extend([
        "create-rw-read-deny",
        "map-rw-read-deny",
        "map-copy-read-deny",
        "map-rw-write-deny",
        "delete-on-close",
        "supersede",
    ]);
    assert_eq!(outcomes["write-only-direct-read"], "readable");
    #[cfg(target_os = "linux")]
    {
        expected.extend([
            "exact-directory-alias-hardlink",
            "exact-directory-alias-rename",
            "rename-exchange",
            "linkat-dirfd",
            "linkat-follow",
            "directory-symlink-read",
            "directory-symlink-hardlink",
            "inherited-proc-fd-read",
        ]);
        if empty_supported {
            expected.push("linkat-empty");
        } else {
            assert_eq!(
                outcomes["linkat-empty"],
                "unsupported-by-unmanaged-preflight"
            );
        }
        assert!(
            matches!(
                outcomes["linkat-nofollow"].as_str(),
                "denied" | "created:denied"
            ),
            "nofollow hard-linked symlink exposed content: {}",
            outcomes["linkat-nofollow"]
        );
    }
    #[cfg(unix)]
    expected.extend(["symlink-read", "lexical-symlink-read"]);
    assert_eq!(
        outcomes.len(),
        if cfg!(target_os = "linux") { 28 } else { 25 }
    );
    let failures: Vec<_> = expected
        .iter()
        .filter(|name| outcomes[**name] != "denied")
        .map(|name| format!("{name}={}", outcomes[*name]))
        .collect();
    assert_eq!(outcomes["allowed-hardlink"], "created:readable");
    assert_eq!(outcomes["allowed-combined-rw-open"], "opened:readable");
    assert_eq!(outcomes["allowed-create-read-open"], "opened:readable");
    #[cfg(windows)]
    {
        assert_eq!(outcomes["ordinary-map-rw"], "read_write");
        assert_eq!(outcomes["ordinary-map-copy"], "read_write");
        assert_eq!(outcomes["allowed-delete-on-close"], "opened:deleted");
        assert_eq!(outcomes["allowed-supersede"], "opened:replaced");
        eprintln!("FILE_ALIAS_MAPPING_VERIFIED backend={backend} readonly-deny=rw+copy write-deny=rw ordinary=rw+copy");
    }
    assert_eq!(outcomes["allowed-rename"], "created:readable");
    #[cfg(target_os = "linux")]
    assert_eq!(outcomes["allowed-linkat"], "created:readable");
    eprintln!("FILE_ALIAS_OUTCOMES backend={backend} {outcomes:?}");
    if failures.is_empty() {
        #[cfg(windows)]
        for name in ["delete-close.data", "supersede.data"] {
            assert_eq!(
                fs::read(fixture.root.join(name)).unwrap(),
                DUMMY,
                "protected implicit delete changed dummy file"
            );
        }
        for name in ["write-link.data", "write-rename.data"] {
            assert_eq!(
                fs::read(fixture.root.join(name)).unwrap(),
                DUMMY,
                "write-only protected content changed through an alias"
            );
        }
    }
    writeln!(input, "quit").unwrap();
    input.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = fixture.launcher.as_mut().unwrap().try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "alias target did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        fixture.target.as_ref().unwrap().exited(),
        "managed fixture process remains alive after launcher exit"
    );
    assert!(
        failures.is_empty(),
        "protected namespace/content alias bypasses: {}",
        failures.join(", ")
    );
    eprintln!("FILE_ALIAS_VERIFIED backend={backend} managed-mutations=denied content-symlink=denied ordinary-hardlinks=allowed");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires packaged CLI; registered in the Linux backend Suite"]
fn ptrace_denied_content_cannot_mint_or_follow_managed_aliases() {
    scenario("ptrace");
}

#[test]
#[ignore = "requires packaged embedded CLI; registered in platform Suites"]
fn gum_denied_content_cannot_mint_or_follow_managed_aliases() {
    scenario("gum");
}
