use hyperhub_core::config::{Config, EnvironmentVariable, SecretValue};
use hyperhub_core::config_store::{
    self, default_config_path, derive_session_auth_key, load_encrypted, ExportFormat,
};
use hyperhub_core::control::{
    control_request, discovery_control_endpoint, run_control_server, ControlService,
};
use hyperhub_core::session::{session_proof, ControlRequest, ControlResponse, SessionRegistry};
use hyperhub_core::socks::SocksService;
use std::cell::Cell;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(feature = "embedded-agent", feature = "external-runtime"))]
compile_error!("embedded-agent and external-runtime are mutually exclusive");

mod agent_runtime;
mod chat;
mod clipboard;
mod config_cli;
mod config_semantics;
mod config_tui;
mod lifecycle;
mod password;
mod platform;
mod skill_installer;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunConfig {
    runtime: Option<PathBuf>,
    backend: Option<String>,
    password_file: Option<PathBuf>,
    dry_run: bool,
    target: OsString,
    target_args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServeConfig {
    output: Option<PathBuf>,
    debug: bool,
    action: ServeAction,
    password_file: Option<PathBuf>,
    password_stdin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ServeAction {
    Run,
    Config,
    Import {
        path: PathBuf,
        input_password_file: Option<PathBuf>,
    },
    Export {
        path: PathBuf,
        plain: bool,
        export_password_file: Option<PathBuf>,
    },
}

struct ServeOutput(Option<File>);

impl ServeOutput {
    fn open(path: Option<&Path>) -> Result<Self, String> {
        let Some(path) = path else {
            return Ok(Self(None));
        };
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "cannot create output directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("cannot open terminal output {}: {error}", path.display()))?;
        Ok(Self(Some(file)))
    }

    fn line(&mut self, message: impl AsRef<str>) -> Result<(), String> {
        if let Some(file) = self.0.as_mut() {
            writeln!(file, "{}", message.as_ref()).map_err(|error| error.to_string())?;
            file.flush().map_err(|error| error.to_string())
        } else {
            println!("{}", message.as_ref());
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Run(RunConfig),
    Serve(ServeConfig),
    Start(lifecycle::StartConfig),
    Stop,
    Restart(lifecycle::StartConfig),
    Status { json: bool },
    Logs(lifecycle::LogsConfig),
    AuthClear,
    Chat(chat::ChatConfig),
    ConfigCli(config_cli::Command),
    Skill,
    Validate(Option<PathBuf>),
    Doctor(Option<PathBuf>),
    Help,
}

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(result) = platform::run_internal(&args) {
        match result {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("hyperhub: {error}");
                std::process::exit(2);
            }
        }
    }
    let command = match parse_args(args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("hyperhub: {error}\n\n{}", usage());
            std::process::exit(2);
        }
    };
    match execute(command) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("hyperhub: {error}");
            std::process::exit(2);
        }
    }
}

fn execute(command: Command) -> Result<i32, String> {
    match command {
        Command::Help => {
            print_usage();
            Ok(0)
        }
        Command::Doctor(target) => print_doctor(target.as_deref()),
        Command::Validate(password_file) => {
            let path = default_config_path().map_err(|error| error.to_string())?;
            let password = password::acquire(password_file.as_deref(), false)?;
            let unlocked = load_encrypted(&path, password.as_bytes()).map_err(|e| e.to_string())?;
            config_store::save_redacted_json(&path, &unlocked.config)
                .map_err(|error| error.to_string())?;
            println!("configuration is valid: {}", path.display());
            Ok(0)
        }
        Command::Serve(config) => serve(config),
        Command::Start(config) => lifecycle::start(config),
        Command::Stop => lifecycle::stop(),
        Command::Restart(config) => lifecycle::restart(config),
        Command::Status { json } => lifecycle::status(json),
        Command::Logs(config) => lifecycle::logs(config),
        Command::AuthClear => clear_password_authorization(),
        Command::Chat(config) => chat::run(config),
        Command::ConfigCli(command) => config_cli::run(command),
        Command::Skill => skill_installer::print_embedded_skill(),
        Command::Run(run) => run_target(run),
    }
}

fn serve(run: ServeConfig) -> Result<i32, String> {
    let path = default_config_path().map_err(|error| error.to_string())?;
    if matches!(run.action, ServeAction::Import { .. }) && serve_is_running() {
        return Err("Serve 正在运行；请停止 Serve 后再导入配置".into());
    }
    if let ServeAction::Import {
        path: source,
        input_password_file,
    } = &run.action
    {
        return import_config(
            &path,
            source,
            run.password_file.as_deref(),
            input_password_file.as_deref(),
        );
    }
    if let ServeAction::Export {
        path: destination,
        plain,
        export_password_file,
    } = &run.action
    {
        return export_config(
            &path,
            destination,
            *plain,
            run.password_file.as_deref(),
            export_password_file.as_deref(),
        );
    }
    let configure = matches!(run.action, ServeAction::Config);
    let live = configure && serve_is_running();
    let first_run = !path.is_file();
    if (first_run || configure)
        && (!std::io::stdin().is_terminal() || !std::io::stdout().is_terminal())
    {
        return Err(
            "an interactive terminal is required for initial configuration; run `hyperhub config` in a terminal first"
                .into(),
        );
    }
    if first_run && live {
        return Err("Serve is running but the local encrypted configuration is missing".into());
    }
    let password = if run.password_stdin {
        password::acquire_stdin()?
    } else {
        password::acquire(run.password_file.as_deref(), first_run)?
    };
    let initial = if first_run {
        initialize_config(&path, password.as_bytes())?
    } else {
        load_encrypted(&path, password.as_bytes())
            .map_err(|error| error.to_string())?
            .config
    };
    let password = if configure || first_run {
        let result = config_tui::run(&path, password, initial, live, first_run)?;
        if configure {
            if !path.is_file() {
                return Err("configuration was not saved".into());
            }
            return Ok(0);
        }
        result.password
    } else {
        password
    };
    let unlocked = load_encrypted(&path, password.as_bytes()).map_err(|error| error.to_string())?;
    config_store::save_redacted_json(&path, &unlocked.config).map_err(|error| error.to_string())?;
    let debug = run.debug || unlocked.config.debug;
    let config = Arc::new(unlocked.config);
    let mut output = ServeOutput::open(run.output.as_deref())?;
    let session_auth_key = unlocked.session_auth_key.clone();
    let descriptor = unlocked.descriptor.clone();
    let sessions = SessionRegistry::new(unlocked.session_auth_key, unlocked.descriptor);
    let root_certificates = config_store::load_root_certificates(
        &path,
        password.as_bytes(),
        config
            .root_certificates
            .iter()
            .filter(|certificate| certificate.enabled && certificate.host.is_none())
            .map(|certificate| certificate.fingerprint.as_str()),
    )
    .map_err(|error| error.to_string())?;
    let socks = SocksService::new_with_debug_output(
        config.clone(),
        sessions.clone(),
        root_certificates,
        debug,
        run.output.as_deref(),
        session_auth_key.as_slice(),
    )
    .map_err(|e| e.to_string())?;
    let trust = Arc::new(hyperhub_core::trust::TrustStore::new(
        path.clone(),
        password.as_bytes().to_vec(),
        descriptor,
        socks.runtime(),
        socks.audit_writer(),
    ));
    let socks = socks.with_trust_store(trust);
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let socks_address = runtime
        .block_on(socks.prepare_listener())
        .map_err(|error| format!("cannot bind SOCKS5 listener: {error}"))?;
    let audit = socks.audit_writer();
    let (shutdown, mut shutdown_signal) = tokio::sync::watch::channel(false);
    let control = ControlService::new(
        sessions,
        socks.connections(),
        socks.tls_ca_pem().to_owned(),
        audit.clone(),
        socks.runtime(),
        session_auth_key,
    )
    .with_socks_listener(socks.listener_controller())
    .with_forced_debug(run.debug)
    .with_shutdown(shutdown);
    output.line(format!("HyperHub SOCKS5 listening on {}", socks_address))?;
    output.line(format!(
        "HyperHub control endpoint {}",
        discovery_control_endpoint()
    ))?;
    if let Some(path) = audit.current_log_path() {
        output.line(format!("HyperHub audit log {}", path.display()))?;
    }
    if let Some(path) = run.output.as_deref() {
        output.line(format!("HyperHub terminal output {}", path.display()))?;
    }
    if debug {
        output.line("HyperHub debug event stream enabled")?;
    }
    runtime
        .block_on(async {
            tokio::select! {
                result = async {
                    tokio::try_join!(
                        socks.run(),
                        run_control_server(discovery_control_endpoint(), control)
                    )
                    .map(|_| ())
                } => result,
                _ = shutdown_signal.changed() => Ok(()),
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(0)
}

fn initialize_config(path: &Path, password: &[u8]) -> Result<Config, String> {
    let mut config = Config::default();
    config.apply_managed_audit_paths(path);
    config.environment = default_environment();
    config.validate().map_err(|error| error.to_string())?;
    config_store::save_encrypted(path, &config, password).map_err(|error| error.to_string())?;
    Ok(config)
}

fn default_environment() -> Vec<EnvironmentVariable> {
    ["GITLAB_HOST", "GITLAB_TOKEN", "GH_TOKEN"]
        .into_iter()
        .map(|name| EnvironmentVariable {
            uuid: hyperhub_core::config::new_config_uuid(),
            name: name.into(),
            value: SecretValue::Inline {
                value: String::new(),
            },
        })
        .collect()
}

fn import_config(
    active_path: &Path,
    source: &Path,
    password_file: Option<&Path>,
    input_password_file: Option<&Path>,
) -> Result<i32, String> {
    let first_run = !active_path.is_file();
    let local_password = password::acquire(password_file, first_run)?;
    let input_password = if let Some(path) = input_password_file {
        password::acquire(Some(path), false)?
    } else {
        local_password.clone()
    };
    let config =
        config_store::import(source, Some(input_password.as_bytes())).map_err(|error| {
            if matches!(error, config_store::StoreError::Authentication)
                && input_password_file.is_none()
            {
                "无法解密导入文件；如果它使用不同密码，请指定 --input-password-file".into()
            } else {
                error.to_string()
            }
        })?;
    config.validate().map_err(|error| error.to_string())?;
    config_store::save_encrypted(active_path, &config, local_password.as_bytes())
        .map_err(|error| error.to_string())?;
    println!(
        "configuration imported from {} and encrypted at {}",
        source.display(),
        active_path.display()
    );
    Ok(0)
}

fn export_config(
    active_path: &Path,
    destination: &Path,
    plain: bool,
    password_file: Option<&Path>,
    export_password_file: Option<&Path>,
) -> Result<i32, String> {
    if !active_path.is_file() {
        return Err(format!(
            "encrypted configuration does not exist: {}",
            active_path.display()
        ));
    }
    let local_password = password::acquire(password_file, false)?;
    let unlocked = load_encrypted(active_path, local_password.as_bytes())
        .map_err(|error| error.to_string())?;
    let toml = destination
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"));
    let format = if toml {
        ExportFormat::Toml
    } else if plain {
        ExportFormat::PlainBin
    } else {
        ExportFormat::EncryptedBin
    };
    if matches!(format, ExportFormat::PlainBin | ExportFormat::Toml) {
        confirm_plain_export()?;
        config_store::export(destination, &unlocked.config, format, None)
            .map_err(|error| error.to_string())?;
    } else {
        let export_password = if let Some(path) = export_password_file {
            password::acquire(Some(path), false)?
        } else {
            local_password
        };
        config_store::export(
            destination,
            &unlocked.config,
            ExportFormat::EncryptedBin,
            Some(export_password.as_bytes()),
        )
        .map_err(|error| error.to_string())?;
    }
    println!("configuration exported to {}", destination.display());
    Ok(0)
}

fn confirm_plain_export() -> Result<(), String> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err("明文导出需要交互终端确认".into());
    }
    eprint!("导出文件将包含明文 Secret。输入 EXPORT 继续: ");
    std::io::stderr()
        .flush()
        .map_err(|error| error.to_string())?;
    let mut confirmation = String::new();
    std::io::stdin()
        .read_line(&mut confirmation)
        .map_err(|error| error.to_string())?;
    if confirmation.trim_end() != "EXPORT" {
        return Err("已取消明文导出".into());
    }
    Ok(())
}

fn serve_is_running() -> bool {
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return false;
    };
    runtime
        .block_on(control_request(
            &discovery_control_endpoint(),
            &ControlRequest::Ping,
        ))
        .is_ok()
}

fn run_target(run: RunConfig) -> Result<i32, String> {
    let console_guard = password::ConsoleModeGuard::capture();
    let environment_password = password::take_environment();
    let control_endpoint = discovery_control_endpoint();
    let target = resolve_target(&run.target)?;
    let backend = platform::target_backend(Path::new(&target), run.backend.as_deref())?;
    if !backend.requires_agent_runtime() && run.runtime.is_some() {
        eprintln!(
            "hyperhub: warning: {} does not use an Agent runtime; ignoring --runtime",
            backend.name()
        );
    }
    let agent_runtime = resolve_backend_agent_runtime(backend, run.runtime.as_deref())?;
    if let Some(agent_runtime) = &agent_runtime {
        platform::validate_target_runtime(Path::new(&target), agent_runtime.display_path())?;
        agent_runtime.verify()?;
    }
    let session_id = new_session_id();
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let mut client_nonce = [0u8; 32];
    rand::fill(&mut client_nonce);
    let auth_response = runtime
        .block_on(control_request(
            &control_endpoint,
            &ControlRequest::BeginSessionAuth {
                session_id: session_id.clone(),
                executable: target.to_string_lossy().into_owned(),
                client_nonce,
            },
        ))
        .map_err(|e| format!("cannot authenticate with HyperHub serve: {e}"))?;
    let bootstrap = match auth_response {
        bootstrap @ ControlResponse::SessionBootstrap { .. } => bootstrap,
        ControlResponse::SessionChallenge { challenge } => {
            let password = password::acquire_with_environment(
                run.password_file.as_deref(),
                false,
                environment_password,
            )?;
            let auth_key = derive_session_auth_key(password.as_bytes(), &challenge.descriptor)
                .map_err(|error| error.to_string())?;
            let proof = session_proof(&auth_key, &challenge)?;
            runtime
                .block_on(control_request(
                    &control_endpoint,
                    &ControlRequest::FinishSessionAuth {
                        challenge_id: challenge.challenge_id,
                        proof,
                    },
                ))
                .map_err(|e| format!("cannot finish HyperHub authentication: {e}"))?
        }
        ControlResponse::Error { message } => return Err(message),
        _ => return Err("HyperHub serve rejected the session authentication request".into()),
    };
    let ControlResponse::SessionBootstrap {
        socks_address,
        token,
        agent_flags,
        tls_ca_pem,
        environment,
        sandbox,
        ..
    } = bootstrap
    else {
        return Err("HyperHub serve rejected session registration".into());
    };
    let session_token = token.clone();
    let environment_keys = environment
        .iter()
        .map(|variable| variable.name.clone())
        .collect::<Vec<_>>();
    let mut env = vec![
        ("HYPERHUB_SESSION_ID".into(), session_id.clone().into()),
        ("HYPERHUB_SESSION_TOKEN".into(), token.into()),
        ("HYPERHUB_SOCKS_ADDR".into(), socks_address.into()),
        (
            "HYPERHUB_CONTROL_ENDPOINT".into(),
            control_endpoint.clone().into(),
        ),
        (
            "HYPERHUB_ENFORCEMENT_MODE".into(),
            (if agent_flags.observe {
                "observe"
            } else {
                "enforce"
            })
            .into(),
        ),
    ];
    for variable in environment {
        env.push((variable.name.into(), variable.value.into()));
    }
    env.push((
        "HYPERHUB_SESSION_ENV_KEYS".into(),
        serde_json::to_string(&environment_keys)
            .map_err(|error| format!("cannot encode session environment: {error}"))?
            .into(),
    ));
    if let Some(agent_runtime) = &agent_runtime {
        env.extend(agent_runtime.integrity_environment());
    }
    if run.dry_run {
        let runtime_description = agent_runtime
            .as_ref()
            .map(|runtime| runtime.display_path().display().to_string())
            .unwrap_or_else(|| "not used (standard Gum injection unavailable)".into());
        println!(
            "mode: run\ntarget: {}\nbackend: {}\nruntime: {}\ninjector: {}\nsocks: {}\ncontrol: {}",
            target.to_string_lossy(),
            backend.name(),
            runtime_description,
            platform::INJECTOR_NAME,
            "provided by serve",
            control_endpoint
        );
        let _ = runtime.block_on(control_request(
            &control_endpoint,
            &ControlRequest::RevokeSession { session_id },
        ));
        return Ok(0);
    }
    env.extend(platform::backend_trust_environment(backend, &tls_ca_pem)?);
    let executable = target.to_string_lossy().into_owned();
    // 密码提示在 Windows Terminal/ConPTY 下可能遗留残缺控制台模式；
    // 在创建子进程前用提示前保存的模式强制恢复，确保目标继承正常输入状态。
    if !console_guard.restore() {
        eprintln!("hyperhub: warning: failed to restore console mode before launching the target");
    }
    let session_activated = Cell::new(false);
    let result = platform::run_injected(
        &target,
        &run.target,
        &run.target_args,
        backend,
        agent_runtime.as_ref().map(|runtime| runtime.load_path()),
        &env,
        sandbox.as_ref(),
        |root_pid, root_executable| {
            let root_executable = root_executable.to_string_lossy().into_owned();
            let root_executable = (!platform::same_executable_path(
                Path::new(&root_executable),
                Path::new(&executable),
            ))
            .then_some(root_executable);
            let response = runtime
                .block_on(control_request(
                    &control_endpoint,
                    &ControlRequest::ActivateSession {
                        session_id: session_id.clone(),
                        token: session_token.clone(),
                        root_pid,
                        executable: executable.clone(),
                        root_executable,
                        process_policy_version: 0,
                        process_rule_id: None,
                        process_decision_source: "default".into(),
                    },
                ))
                .map_err(|error| format!("cannot activate HyperHub session: {error}"))?;
            if matches!(response, ControlResponse::Ok) {
                session_activated.set(true);
                Ok(true)
            } else {
                Err("HyperHub serve rejected root process activation".into())
            }
        },
    );
    // 交互目标（例如 ssh/cmd）也可能修改共享控制台模式。必须在目标退出后
    // 再恢复一次，避免外层 PowerShell 把退格或控制键解析为续行输入并显示 More?。
    if !console_guard.restore() {
        eprintln!("hyperhub: warning: failed to restore console mode after target exit");
    }
    drop(console_guard);
    if !session_activated.get() {
        let _ = runtime.block_on(control_request(
            &control_endpoint,
            &ControlRequest::RevokeSession { session_id },
        ));
    }
    result
}

fn clear_password_authorization() -> Result<i32, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    match runtime
        .block_on(control_request(
            &discovery_control_endpoint(),
            &ControlRequest::ClearPasswordAuthorization,
        ))
        .map_err(|error| error.to_string())?
    {
        ControlResponse::Ok => {
            println!("HyperHub authorization cache cleared");
            Ok(0)
        }
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected response while clearing authorization cache".into()),
    }
}

fn parse_auth(args: &[OsString]) -> Result<Command, String> {
    match args {
        [action] if action == "clear" => Ok(Command::AuthClear),
        _ => Err("auth accepts only `clear`".into()),
    }
}

fn parse_args(args: Vec<OsString>) -> Result<Command, String> {
    if args.is_empty() {
        return Ok(Command::Help);
    }
    match args[0].to_string_lossy().as_ref() {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "serve" => parse_serve(&args[1..]).map(Command::Serve),
        "start" => parse_start(&args[1..]).map(Command::Start),
        "stop" => {
            require_no_args("stop", &args[1..])?;
            Ok(Command::Stop)
        }
        "restart" => parse_start(&args[1..]).map(Command::Restart),
        "status" => parse_status(&args[1..]),
        "logs" => parse_logs(&args[1..]).map(Command::Logs),
        "auth" => parse_auth(&args[1..]),
        "config" => parse_config_command(&args[1..]),
        "chat" => chat::parse(&args[1..]).map(Command::Chat),
        "skill" => parse_skill(&args[1..]),
        "show" => config_cli::parse_show(&args[1..]).map(Command::ConfigCli),
        "approve" => config_cli::parse_approve(&args[1..]).map(Command::ConfigCli),
        "import" => parse_import(&args[1..]).map(Command::Serve),
        "export" => parse_export(&args[1..]).map(Command::Serve),
        "validate" => match &args[1..] {
            [] => Ok(Command::Validate(None)),
            [option, path] if option == "--password-file" => {
                Ok(Command::Validate(Some(path.clone().into())))
            }
            _ => Err("validate accepts only --password-file <file>".into()),
        },
        "doctor" => match &args[1..] {
            [] => Ok(Command::Doctor(None)),
            [option, path] if option == "--target" => {
                Ok(Command::Doctor(Some(path.clone().into())))
            }
            _ => Err("doctor accepts only --target <exe>".into()),
        },
        "run" => parse_run(&args[1..]).map(Command::Run),
        value => Err(format!(
            "unknown command '{value}'; use `hyperhub run -- {value}` to run a target with this name"
        )),
    }
}

fn parse_skill(args: &[OsString]) -> Result<Command, String> {
    if args.is_empty() {
        Ok(Command::Skill)
    } else {
        Err("skill accepts no options; run `hyperhub skill` to print the Agent Skill".into())
    }
}

fn require_no_args(command: &str, args: &[OsString]) -> Result<(), String> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(format!("{command} accepts no options"))
    }
}

fn parse_start(args: &[OsString]) -> Result<lifecycle::StartConfig, String> {
    let mut debug = false;
    let mut password_file = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_string_lossy().as_ref() {
            "--debug" => debug = true,
            "--password-file" => {
                index += 1;
                password_file = Some(
                    args.get(index)
                        .ok_or("--password-file requires a value")?
                        .clone()
                        .into(),
                );
            }
            value => return Err(format!("unknown start option '{value}'")),
        }
        index += 1;
    }
    Ok(lifecycle::StartConfig {
        debug,
        password_file,
    })
}

fn parse_status(args: &[OsString]) -> Result<Command, String> {
    match args {
        [] => Ok(Command::Status { json: false }),
        [option] if option == "--json" => Ok(Command::Status { json: true }),
        _ => Err("status accepts only --json".into()),
    }
}

fn parse_logs(args: &[OsString]) -> Result<lifecycle::LogsConfig, String> {
    let mut lines = 100usize;
    let mut follow = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_string_lossy().as_ref() {
            "-f" | "--follow" => follow = true,
            "-n" | "--lines" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or("--lines requires a value")?
                    .to_string_lossy();
                lines = value
                    .parse()
                    .map_err(|_| format!("invalid log line count '{value}'"))?;
            }
            value => return Err(format!("unknown logs option '{value}'")),
        }
        index += 1;
    }
    Ok(lifecycle::LogsConfig { lines, follow })
}

fn parse_serve(args: &[OsString]) -> Result<ServeConfig, String> {
    let mut output = None;
    let mut debug = false;
    let mut password_file = None;
    let mut password_stdin = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_string_lossy().as_ref() {
            "--debug" => debug = true,
            "--output" => {
                index += 1;
                output = Some(
                    args.get(index)
                        .ok_or("--output requires a value")?
                        .clone()
                        .into(),
                );
            }
            "--password-file" => {
                index += 1;
                password_file = Some(
                    args.get(index)
                        .ok_or("--password-file requires a value")?
                        .clone()
                        .into(),
                );
            }
            "--password-stdin" => password_stdin = true,
            value => return Err(format!("unknown serve option '{value}'")),
        }
        index += 1;
    }
    if password_stdin && password_file.is_some() {
        return Err("--password-stdin conflicts with --password-file".into());
    }
    Ok(ServeConfig {
        output,
        debug,
        action: ServeAction::Run,
        password_file,
        password_stdin,
    })
}

fn parse_config_command(args: &[OsString]) -> Result<Command, String> {
    if args
        .first()
        .is_some_and(|value| value.to_string_lossy() == "patch")
    {
        return config_cli::parse(args).map(Command::ConfigCli);
    }
    if args
        .first()
        .is_some_and(|value| value.to_string_lossy() == "show")
    {
        return Err("`config show` was removed; use `hyperhub show`".into());
    }
    let password_file = parse_single_password_file("config", args)?;
    Ok(Command::Serve(ServeConfig {
        output: None,
        debug: false,
        action: ServeAction::Config,
        password_file,
        password_stdin: false,
    }))
}

fn parse_import(args: &[OsString]) -> Result<ServeConfig, String> {
    let path = args.first().ok_or("import requires a file")?.clone().into();
    let mut password_file = None;
    let mut input_password_file = None;
    let mut index = 1;
    while index < args.len() {
        let destination = match args[index].to_string_lossy().as_ref() {
            "--password-file" => &mut password_file,
            "--input-password-file" => &mut input_password_file,
            value => return Err(format!("unknown import option '{value}'")),
        };
        index += 1;
        *destination = Some(
            args.get(index)
                .ok_or("password file option requires a value")?
                .clone()
                .into(),
        );
        index += 1;
    }
    Ok(ServeConfig {
        output: None,
        debug: false,
        action: ServeAction::Import {
            path,
            input_password_file,
        },
        password_file,
        password_stdin: false,
    })
}

fn parse_export(args: &[OsString]) -> Result<ServeConfig, String> {
    let path = args.first().ok_or("export requires a file")?.clone().into();
    let mut plain = false;
    let mut password_file = None;
    let mut export_password_file = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].to_string_lossy().as_ref() {
            "--plain" => {
                plain = true;
                index += 1;
            }
            "--password-file" | "--export-password-file" => {
                let export = args[index] == "--export-password-file";
                index += 1;
                let path = args
                    .get(index)
                    .ok_or("password file option requires a value")?
                    .clone()
                    .into();
                if export {
                    export_password_file = Some(path);
                } else {
                    password_file = Some(path);
                }
                index += 1;
            }
            value => return Err(format!("unknown export option '{value}'")),
        }
    }
    Ok(ServeConfig {
        output: None,
        debug: false,
        action: ServeAction::Export {
            path,
            plain,
            export_password_file,
        },
        password_file,
        password_stdin: false,
    })
}

fn parse_single_password_file(command: &str, args: &[OsString]) -> Result<Option<PathBuf>, String> {
    match args {
        [] => Ok(None),
        [option, path] if option == "--password-file" => Ok(Some(path.clone().into())),
        _ => Err(format!("{command} accepts only --password-file <file>")),
    }
}

fn parse_run(args: &[OsString]) -> Result<RunConfig, String> {
    let mut runtime = None;
    let mut backend = None;
    let mut password_file = None;
    let mut dry_run = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_string_lossy().as_ref() {
            "--runtime" | "--backend" | "--password-file" => {
                let option = args[index].to_string_lossy();
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| format!("{option} requires a value"))?
                    .clone();
                if option == "--runtime" {
                    if !cfg!(feature = "external-runtime") {
                        return Err("--runtime is disabled in this release build".into());
                    }
                    runtime = Some(value.into());
                } else if option == "--backend" {
                    let value = value
                        .into_string()
                        .map_err(|_| "--backend must be UTF-8".to_string())?;
                    if !matches!(value.as_str(), "ptrace" | "gum") {
                        return Err("--backend must be ptrace or gum".into());
                    }
                    backend = Some(value);
                } else {
                    password_file = Some(value.into());
                }
                index += 1;
            }
            "--dry-run" => {
                dry_run = true;
                index += 1;
            }
            "--" => {
                index += 1;
                break;
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown run option '{value}'"));
            }
            _ => break,
        }
    }
    if index >= args.len() {
        return Err("run requires a target command".into());
    }
    Ok(RunConfig {
        runtime,
        backend,
        password_file,
        dry_run,
        target: args[index].clone(),
        target_args: args[index + 1..].to_vec(),
    })
}

fn resolve_backend_agent_runtime(
    backend: platform::TargetBackend,
    explicit: Option<&Path>,
) -> Result<Option<agent_runtime::AgentRuntime>, String> {
    if !backend.requires_agent_runtime() {
        return Ok(None);
    }
    resolve_agent_runtime(explicit).map(Some)
}

fn resolve_agent_runtime(explicit: Option<&Path>) -> Result<agent_runtime::AgentRuntime, String> {
    if let Some(path) = explicit {
        #[cfg(feature = "external-runtime")]
        {
            if !path.is_file() {
                return Err(format!("runtime does not exist: {}", path.display()));
            }
            return agent_runtime::AgentRuntime::external(path);
        }
        #[cfg(not(feature = "external-runtime"))]
        {
            let _ = path;
            return Err("external Agent runtimes are disabled in this release build".into());
        }
    }

    #[cfg(feature = "embedded-agent")]
    {
        return agent_runtime::AgentRuntime::embedded();
    }

    #[cfg(all(not(feature = "embedded-agent"), feature = "external-runtime"))]
    {
        let directory = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .parent()
            .ok_or("cannot resolve executable directory")?
            .to_owned();
        let names: &[&str] = if cfg!(windows) {
            &["hyperhub_gum_agent.dll"]
        } else if cfg!(target_os = "linux") {
            &["libhyperhub_gum_agent.so"]
        } else {
            &[]
        };
        let current = std::env::current_dir().map_err(|e| e.to_string())?;
        for name in names {
            for candidate in [
                directory.join(name),
                current.join(name),
                current.join("target").join("release").join(name),
            ] {
                if candidate.is_file() {
                    return agent_runtime::AgentRuntime::external(&candidate);
                }
            }
        }
        Err("agent runtime was not found; build an embedded release or use --runtime".into())
    }

    #[cfg(not(any(feature = "embedded-agent", feature = "external-runtime")))]
    {
        Err("this build contains no Agent runtime provider".into())
    }
}

fn resolve_target(target: &OsString) -> Result<OsString, String> {
    let direct = PathBuf::from(target);
    if direct.is_file() {
        return reject_self_target(direct);
    }
    if direct.components().count() > 1 {
        return Err(format!("target does not exist: {}", direct.display()));
    }
    let path = std::env::var_os("PATH").ok_or("PATH is not set")?;
    #[cfg(windows)]
    let mut names = vec![target.clone()];
    #[cfg(not(windows))]
    let names = vec![target.clone()];
    #[cfg(windows)]
    if Path::new(target).extension().is_none() {
        for extension in std::env::var_os("PATHEXT")
            .unwrap_or_else(|| ".EXE;.COM;.BAT;.CMD".into())
            .to_string_lossy()
            .split(';')
            .filter(|value| !value.is_empty())
        {
            let mut name = target.clone();
            name.push(extension.to_ascii_lowercase());
            names.push(name);
        }
    }
    for directory in std::env::split_paths(&path) {
        for name in &names {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return reject_self_target(candidate);
            }
        }
    }
    Err(format!(
        "target '{}' was not found on PATH",
        target.to_string_lossy()
    ))
}

fn reject_self_target(target: PathBuf) -> Result<OsString, String> {
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    let target_absolute = std::fs::canonicalize(&target)
        .map(strip_windows_verbatim_prefix)
        .unwrap_or(target);
    let current_absolute = std::fs::canonicalize(&current)
        .map(strip_windows_verbatim_prefix)
        .unwrap_or(current);
    if target_absolute == current_absolute {
        return Err("refusing to attach HyperHub to itself".into());
    }
    Ok(target_absolute.into_os_string())
}

fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(stripped) = text.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

fn new_session_id() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

fn print_doctor(target: Option<&Path>) -> Result<i32, String> {
    println!("HyperHub capability report");
    println!(
        "platform={} arch={} injector={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        platform::INJECTOR_NAME
    );
    println!("agent_runtime={}", agent_runtime::provider_name());
    println!("network=tcp; ingress=socks5-rfc1929; ipv4=true; ipv6=true; udp=false; http3=false");
    println!(
        "dns=fake-ip-per-session; windows=getaddrinfo,GetAddrInfoW; routing=server-side-domain"
    );
    println!("tcp=all-destinations; self-ingress=exact-bypass; client-proxy=http,socks5");
    println!(
        "descendants=createprocess,createprocessinternal,ntcreateuserprocess; recursive=true; brokered=false; protected=false"
    );
    println!(
        "trust=server-root,schannel,rustls-ca-environment; file-bundle=bootstrap; sectrust=false; pinning=false"
    );
    if let Some(path) = target {
        let report = platform::doctor_target(path)?;
        println!("target={} {report}", path.display());
    }
    Ok(0)
}

fn usage() -> &'static str {
    "HyperHub process network control and Agent configuration gateway

usage:
  hyperhub <command> [options]

configuration and Agent guidance:
  hyperhub skill                         print the complete Agent Skill and config reference
  hyperhub chat [--password-file file]  edit configuration with the local chat assistant
  hyperhub config [--password-file file] open the interactive configuration editor
  hyperhub show                         show the redacted JSON configuration
  hyperhub config patch <file|-> ...    queue a JSON Patch for human approval
  hyperhub approve ...                  review, edit, approve, or reject queued changes
  hyperhub import <file> ...            import and encrypt a configuration
  hyperhub export <file> ...            export configuration (redacted by default)
  hyperhub validate ...                 validate and refresh the redacted view

server management:
  hyperhub start ...                    start the local gateway
  hyperhub stop                         stop the local gateway
  hyperhub restart ...                  restart the local gateway
  hyperhub status [--json]              show gateway and managed-process status
  hyperhub logs ...                     view gateway logs
  hyperhub auth clear                   clear cached local authorization
  hyperhub serve ...                    run the gateway service directly

target execution:
  hyperhub run ... -- target [args...]  run a target inside HyperHub controls

diagnostics:
  hyperhub doctor [--target exe]        show backend and target diagnostics

Use `hyperhub skill` when an Agent cannot discover the installed agents/skills directory."
}

fn print_usage() {
    println!("{}", usage());
}

#[cfg(test)]
mod tests {
    use super::*;
    fn os(value: &str) -> OsString {
        value.into()
    }

    #[test]
    fn help_lists_only_canonical_user_commands() {
        let help = usage();
        assert!(help.contains("configuration and Agent guidance:"));
        assert!(help.contains("server management:"));
        assert!(help.contains("target execution:"));
        assert!(help.contains("diagnostics:"));
        assert!(help.contains("hyperhub skill"));
        assert!(help.contains("hyperhub show"));
        let configuration = help.find("configuration and Agent guidance:").unwrap();
        let server = help.find("server management:").unwrap();
        let execution = help.find("target execution:").unwrap();
        let diagnostics = help.find("diagnostics:").unwrap();
        assert!(configuration < server && server < execution && execution < diagnostics);
        for command in [
            "skill",
            "chat",
            "config",
            "show",
            "config patch",
            "approve",
            "import",
            "export",
            "validate",
        ] {
            let line = format!("  hyperhub {command}");
            let position = help.find(&line).unwrap();
            assert!(position > configuration && position < server);
        }
        for command in [
            "start",
            "stop",
            "restart",
            "status",
            "logs",
            "auth clear",
            "serve",
        ] {
            let line = format!("  hyperhub {command}");
            let position = help.find(&line).unwrap();
            assert!(position > server && position < execution);
        }
        assert!(!help.contains("hyperhub config show"));
        assert!(!help.contains("--runtime"));
        assert!(!help.contains("--password-stdin"));
        assert!(!help.contains("--token"));
    }
    #[test]
    fn parses_commands() {
        assert!(matches!(
            parse_args(vec![os("serve")]).unwrap(),
            Command::Serve(ServeConfig {
                output: None,
                debug: false,
                action: ServeAction::Run,
                password_stdin: false,
                ..
            })
        ));
        assert!(matches!(
            parse_args(vec![os("start"), os("--debug")]).unwrap(),
            Command::Start(lifecycle::StartConfig { debug: true, .. })
        ));
        assert!(matches!(
            parse_args(vec![os("stop")]).unwrap(),
            Command::Stop
        ));
        assert!(matches!(
            parse_args(vec![os("restart")]).unwrap(),
            Command::Restart(_)
        ));
        assert!(matches!(
            parse_args(vec![os("status"), os("--json")]).unwrap(),
            Command::Status { json: true }
        ));
        assert!(matches!(
            parse_args(vec![os("auth"), os("clear")]).unwrap(),
            Command::AuthClear
        ));
        assert!(parse_args(vec![os("auth")]).is_err());
        assert_eq!(
            parse_logs(&[os("--follow"), os("--lines"), os("25")]).unwrap(),
            lifecycle::LogsConfig {
                lines: 25,
                follow: true,
            }
        );

        let Command::Chat(chat) =
            parse_args(vec![os("chat"), os("--password-file"), os("password.txt")]).unwrap()
        else {
            panic!()
        };
        assert_eq!(chat.password_file, Some("password.txt".into()));

        let Command::Serve(configure) = parse_args(vec![
            os("config"),
            os("--password-file"),
            os("password.txt"),
        ])
        .unwrap() else {
            panic!()
        };
        assert_eq!(configure.action, ServeAction::Config);
        assert_eq!(configure.password_file, Some("password.txt".into()));

        assert!(matches!(
            parse_args(vec![os("skill")]).unwrap(),
            Command::Skill
        ));
        assert!(parse_args(vec![os("skill"), os("--help")]).is_err());
        assert!(matches!(
            parse_args(vec![os("show")]).unwrap(),
            Command::ConfigCli(config_cli::Command::Show)
        ));
        let removed_alias = parse_args(vec![os("config"), os("show")]).unwrap_err();
        assert!(removed_alias.contains("use `hyperhub show`"));
        assert!(parse_args(vec![os("show"), os("--password-file"), os("password.txt")]).is_err());

        let Command::ConfigCli(config_cli::Command::Patch {
            patch,
            password_file,
        }) = parse_args(vec![
            os("config"),
            os("patch"),
            os("patch.json"),
            os("--password-file"),
            os("password.txt"),
        ])
        .unwrap()
        else {
            panic!()
        };
        assert_eq!(patch, PathBuf::from("patch.json"));
        assert_eq!(password_file, Some("password.txt".into()));

        let Command::ConfigCli(config_cli::Command::Approve {
            password_file,
            editor,
        }) = parse_args(vec![
            os("approve"),
            os("--password-file"),
            os("password.txt"),
            os("--editor"),
            os("review-editor"),
        ])
        .unwrap()
        else {
            panic!()
        };
        assert_eq!(password_file, Some("password.txt".into()));
        assert_eq!(editor, Some(PathBuf::from("review-editor")));
        assert!(parse_args(vec![os("approve"), os("patch.json")]).is_err());

        let Command::Serve(import) = parse_args(vec![
            os("import"),
            os("config.toml"),
            os("--input-password-file"),
            os("source-password.txt"),
        ])
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            import.action,
            ServeAction::Import {
                path: "config.toml".into(),
                input_password_file: Some("source-password.txt".into())
            }
        );

        let Command::Serve(export) =
            parse_args(vec![os("export"), os("backup.bin"), os("--plain")]).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            export.action,
            ServeAction::Export {
                path: "backup.bin".into(),
                plain: true,
                export_password_file: None
            }
        );

        let Command::Run(run) =
            parse_args(vec![os("run"), os("curl"), os("https://baidu.com")]).unwrap()
        else {
            panic!()
        };
        assert_eq!(run.backend, None);
        assert_eq!(run.target, os("curl"));
        assert_eq!(run.target_args, vec![os("https://baidu.com")]);

        let Command::Run(run) =
            parse_args(vec![os("run"), os("--backend"), os("gum"), os("curl")]).unwrap()
        else {
            panic!()
        };
        assert_eq!(run.backend.as_deref(), Some("gum"));
        assert!(parse_args(vec![os("run"), os("--backend"), os("invalid"), os("curl")]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn static_backend_does_not_resolve_or_validate_an_agent_runtime() {
        let runtime = resolve_backend_agent_runtime(
            platform::TargetBackend::PtraceSyscall,
            Some(Path::new("/definitely/missing/libhyperhub_gum_agent.so")),
        )
        .unwrap();
        assert!(runtime.is_none());
    }

    #[cfg(all(feature = "embedded-agent", not(feature = "external-runtime")))]
    #[test]
    fn embedded_release_rejects_external_runtime_override() {
        let error = parse_args(vec![
            os("run"),
            os("--runtime"),
            os("agent.dll"),
            os("target"),
        ])
        .unwrap_err();
        assert!(error.contains("--runtime is disabled"));
    }

    #[test]
    fn initialization_persists_a_runnable_base_config() {
        let directory = std::env::temp_dir().join(format!(
            "hyperhub-init-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = directory.join("config.bin");
        let password = b"test-password";
        let config = initialize_config(&path, password).unwrap();
        assert_eq!(config.listener.socks_listen, "127.0.0.1:18444");
        assert_eq!(config.listener.pending_session_ttl_secs, 60);
        assert_eq!(
            config.audit.log.as_deref(),
            Some(directory.join("audit").join("hyperhub.jsonl").as_path())
        );
        assert_eq!(
            config.audit.transcript_dir.as_deref(),
            Some(directory.join("audit").join("transcripts").as_path())
        );
        let unlocked = load_encrypted(&path, password).unwrap();
        assert_eq!(unlocked.config.listener.socks_listen, "127.0.0.1:18444");
        assert!(config.rules.is_empty());
        assert_eq!(
            config
                .environment
                .iter()
                .map(|variable| variable.name.as_str())
                .collect::<Vec<_>>(),
            ["GITLAB_HOST", "GITLAB_TOKEN", "GH_TOKEN"]
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(config_store::redacted_config_path(&path)).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn target_execution_requires_run_subcommand() {
        assert!(parse_args(vec![os("powershell.exe")]).is_err());
        let Command::Run(run) = parse_args(vec![os("run"), os("--dry-run"), os("doctor")]).unwrap()
        else {
            panic!()
        };
        assert_eq!(run.target, os("doctor"));
        assert!(run.dry_run);
    }

    #[test]
    fn nested_management_namespace_is_rejected() {
        assert!(parse_args(vec![os("hyperhub"), os("serve")]).is_err());
        assert!(parse_args(vec![os("serve"), os("config")]).is_err());
    }

    #[test]
    fn refuses_to_attach_current_executable() {
        let current = std::env::current_exe().unwrap();
        let error = reject_self_target(current).unwrap_err();
        assert!(error.contains("refusing to attach HyperHub to itself"));
    }

    #[test]
    fn strips_windows_verbatim_prefix_from_resolved_target() {
        let path = PathBuf::from(r"\\?\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        let stripped = strip_windows_verbatim_prefix(path);
        assert_eq!(
            stripped,
            PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );
    }
}
