use crate::password;
use hyperhub_core::config_store::{default_config_path, load_encrypted, ConfigKeyring};
use hyperhub_core::control::{control_request, discovery_control_endpoint};
use hyperhub_core::session::{ControlRequest, ControlResponse};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartConfig {
    pub debug: bool,
    pub admin_password_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogsConfig {
    pub lines: usize,
    pub follow: bool,
}

pub fn start(config: StartConfig) -> Result<i32, String> {
    let skill = crate::skill_installer::install_user_skill()?;
    match skill.status {
        crate::skill_installer::SkillInstallStatus::Installed => println!(
            "HyperHub Agent Skill installed ({})\nskill: {}",
            skill.bundle_version,
            skill.path.display()
        ),
        crate::skill_installer::SkillInstallStatus::Upgraded => println!(
            "HyperHub Agent Skill upgraded ({})\nskill: {}",
            skill.bundle_version,
            skill.path.display()
        ),
        crate::skill_installer::SkillInstallStatus::Current => {}
    }
    if let Some(status) = query_status()? {
        println!("HyperHub serve is already running (pid {})", status.pid);
        return Ok(0);
    }

    let config_path = default_config_path().map_err(|error| error.to_string())?;
    let first_run = !config_path.is_file();
    let api_key_path = if first_run {
        let password = password::acquire(config.admin_password_file.as_deref(), true)?;
        crate::initialize_config_for_start(&config_path, password.as_bytes())?;
        let descriptor = hyperhub_core::config_store::read_descriptor(&config_path)
            .map_err(|error| error.to_string())?;
        let keyring = ConfigKeyring::derive(password.as_bytes(), descriptor)
            .map_err(|error| error.to_string())?;
        let api_key_path = password::save_runtime_keyring(&keyring)?;
        println!(
            "HyperHub configuration initialized: {}",
            config_path.display()
        );
        api_key_path
    } else if password::runtime_key_exists()? && config.admin_password_file.is_none() {
        password::load_runtime_keyring()?;
        password::default_api_key_path()?
    } else {
        let password = password::acquire(config.admin_password_file.as_deref(), false)?;
        let unlocked =
            load_encrypted(&config_path, password.as_bytes()).map_err(|error| error.to_string())?;
        let keyring = ConfigKeyring::derive(password.as_bytes(), unlocked.descriptor)
            .map_err(|error| error.to_string())?;
        let api_key_path = password::save_runtime_keyring(&keyring)?;
        println!(
            "HyperHub runtime key initialized: {}",
            password::default_runtime_key_path()?.display()
        );
        api_key_path
    };
    // The detached installer can start the new executable only after this Home
    // has a usable runtime envelope. Preserve first-run/password-file setup.
    if crate::upgrade::check_on_start()? {
        return Ok(0);
    }
    let log_path = default_log_path()?;
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!("cannot create log directory {}: {error}", parent.display())
        })?;
    }
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("cannot open serve log {}: {error}", log_path.display()))?;
    writeln!(
        log,
        "\n--- HyperHub serve start {} ---",
        unix_timestamp_ms()
    )
    .map_err(|error| error.to_string())?;
    log.flush().map_err(|error| error.to_string())?;
    let attempt_offset = log
        .metadata()
        .map_err(|error| format!("cannot inspect serve log {}: {error}", log_path.display()))?
        .len();

    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve HyperHub executable: {error}"))?;
    let mut command = Command::new(executable);
    command.arg("serve");
    if config.debug {
        command.arg("--debug");
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            log.try_clone().map_err(|error| error.to_string())?,
        ))
        .stderr(Stdio::from(log));
    configure_background_process(&mut command);

    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start HyperHub serve: {error}"))?;
    let pid = child.id();
    for _ in 0..100 {
        let running = match query_status() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        if let Some(status) = running {
            if status.pid == pid {
                println!(
                    "HyperHub serve started (pid {pid})\nhome: {}\napi-key: {}\ncontrol: {}\nsocks: {}\nlog: {}",
                    hyperhub_core::config_store::hyperhub_home()
                        .map_err(|error| error.to_string())?
                        .display(),
                    api_key_path.display(),
                    discovery_control_endpoint(),
                    status.socks_address,
                    log_path.display()
                );
                return Ok(0);
            }
            let _ = child.kill();
            let _ = child.wait();
            println!("HyperHub serve is already running (pid {})", status.pid);
            return Ok(0);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot inspect HyperHub serve: {error}"))?
        {
            let tail = read_tail_from(&log_path, attempt_offset, 20)
                .unwrap_or_default()
                .join("\n");
            return Err(format!(
                "HyperHub serve exited during startup ({status}){}\nlog: {}",
                if tail.is_empty() {
                    String::new()
                } else {
                    format!("\n{tail}")
                },
                log_path.display()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(format!(
        "timed out waiting for HyperHub serve; inspect {}",
        log_path.display()
    ))
}

pub(crate) fn serve_running() -> Result<bool, String> {
    Ok(query_status()?.is_some())
}

pub fn stop() -> Result<i32, String> {
    stop_with_persistence(false)
}

fn stop_with_persistence(preserve_sessions: bool) -> Result<i32, String> {
    let Some(status) = query_status()? else {
        println!("HyperHub serve is stopped");
        return Ok(0);
    };
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    match runtime.block_on(control_request(
        &discovery_control_endpoint(),
        &ControlRequest::Shutdown { preserve_sessions },
    )) {
        Ok(ControlResponse::Ok) => {}
        Ok(ControlResponse::Error { message }) => return Err(message),
        Ok(_) => return Err("HyperHub serve returned an unexpected shutdown response".into()),
        Err(error) => return Err(format!("cannot stop HyperHub serve: {error}")),
    }
    for _ in 0..100 {
        if query_status()?.is_none() {
            println!("HyperHub serve stopped (pid {})", status.pid);
            return Ok(0);
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "timed out waiting for HyperHub serve process {} to stop",
        status.pid
    ))
}

pub fn restart(config: StartConfig) -> Result<i32, String> {
    if !hyperhub_core::attachments::process_attachment_identity_available() {
        stop_with_persistence(true)?;
        return start(config);
    }
    if query_status()?.is_none() {
        return start(config);
    }
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let response = runtime
        .block_on(control_request(
            &discovery_control_endpoint(),
            &ControlRequest::RestartServe {
                debug: config.debug,
            },
        ))
        .map_err(|e| {
            format!(
                "cannot prepare Core successor; original Core was not intentionally stopped: {e}"
            )
        })?;
    let process = match response {
        ControlResponse::ServeSuccessor { process } => process,
        ControlResponse::Error { message } => return Err(message),
        _ => return Err("Core returned an unexpected successor response".into()),
    };
    for _ in 0..300 {
        if hyperhub_core::attachments::process_birth(process.pid) != Some(process.birth) {
            return Err(format!("Core successor {} exited before readiness; inspect {}. Existing target processes were not restarted",process.pid,default_log_path()?.display()));
        }
        if let Ok(Some(status)) = query_status() {
            if status.pid == process.pid {
                hyperhub_core::attachments::verify_process(&process)?;
                println!("HyperHub serve replaced by successor (pid {})", process.pid);
                return Ok(0);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "Core successor {} did not become ready within 30 seconds; inspect {}",
        process.pid,
        default_log_path()?.display()
    ))
}

pub(crate) const PROCESS_SCOPE: &str = "registered process trees; not system-wide";
pub(crate) const EXECUTOR_SCOPE: &str =
    "existing executors reached through IPC require separate management";

fn protection_scope(registered_processes: Option<usize>) -> serde_json::Value {
    serde_json::json!({
        "kind": "registered_process_trees",
        "system_wide": false,
        "external_executor_delegation": "not_automatically_managed",
        "registration_evidence": if registered_processes.is_some() {
            "current_serve_snapshot"
        } else {
            "unavailable"
        },
        "registered_processes": registered_processes,
        "specific_executor_protection": "not_assessed",
    })
}

fn print_scope_notice() {
    println!("scope: {PROCESS_SCOPE}");
    println!("scope: {EXECUTOR_SCOPE}");
    println!("registration is not a verdict on a specific executor; check all session members and process identity");
}

pub fn status(json: bool) -> Result<i32, String> {
    let Some(status) = query_status()? else {
        let home =
            hyperhub_core::config_store::hyperhub_home().map_err(|error| error.to_string())?;
        let control_endpoint = discovery_control_endpoint();
        let (attachments, attachment_state_error) = match hyperhub_core::attachments::directory()
            .and_then(|directory| hyperhub_core::attachments::records(&directory))
        {
            Ok(records) => (records, None),
            Err(error) => (Vec::new(), Some(error)),
        };
        if json {
            let output = serde_json::json!({
                "state": "stopped",
                "hyperhub_home": home,
                "control_endpoint": control_endpoint,
                "protection_scope": protection_scope(None),
                "attachments": attachments,
                "attachment_state_error": attachment_state_error,
                "attachment_status_source": "durable_record",
                "approval_trust": null,
                "approval_trust_source": "unavailable",
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?
            );
        } else {
            println!("HyperHub serve is stopped");
            println!("home: {}", home.display());
            println!("control: {control_endpoint}");
            println!("runtime approval authority: unavailable (Serve is offline)");
            println!(
                "attachments: {} (durable records; Serve is offline)",
                attachments.len()
            );
            for attachment in &attachments {
                println!(
                    "  attachment={} pid={} phase={:?}",
                    attachment.spec.id, attachment.spec.target.pid, attachment.phase
                );
            }
            if let Some(error) = &attachment_state_error {
                eprintln!("attachment state: {error}");
            }
            print_scope_notice();
        }
        return Ok(3);
    };
    let managed = status
        .sessions
        .iter()
        .map(|session| session.processes.len())
        .sum::<usize>();
    if json {
        let output = serde_json::json!({
            "state": "running",
            "pid": status.pid,
            "socks_address": status.socks_address,
            "hyperhub_home": hyperhub_core::config_store::hyperhub_home().map_err(|error| error.to_string())?,
            "control_endpoint": discovery_control_endpoint(),
            "started_at_ms": status.started_at_ms,
            "generated_at_ms": status.generated_at_ms,
            "sessions": status.sessions,
            "connections": status.connections,
            "engine_hosts": status.engine_hosts,
            "engine_upgrades": status.engine_upgrades,
            "release_upgrades": status.release_upgrades,
            "forward_workers": status.forward_workers,
            "attachments": status.attachments,
            "attachment_state_error": status.attachment_state_error,
            "attachment_status_source": "serve_snapshot",
            "approval_trust": status.approval_trust,
            "approval_trust_source": if status.approval_trust.is_some() { "serve_memory" } else { "unavailable" },
            "protection_scope": protection_scope(Some(managed)),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?
        );
    } else {
        println!("HyperHub serve is running");
        println!("pid: {}", status.pid);
        println!(
            "home: {}",
            hyperhub_core::config_store::hyperhub_home()
                .map_err(|error| error.to_string())?
                .display()
        );
        println!("control: {}", discovery_control_endpoint());
        println!("socks: {}", status.socks_address);
        if let Some(trust) = &status.approval_trust {
            println!(
                "runtime approval authority: {} (expected root: {})",
                trust.state, trust.expected_root
            );
        } else {
            println!("runtime approval authority: unavailable");
        }
        println!("sessions: {}", status.sessions.len());
        println!("managed processes: {managed}");
        print_scope_notice();
        for session in &status.sessions {
            for process in &session.processes {
                println!(
                    "  pid={} {} firewall_version={} session={} executable={}",
                    process.pid,
                    if process.root { "root" } else { "child" },
                    process.firewall_version,
                    session.session_id,
                    process.executable
                );
            }
        }
        println!("attachments: {}", status.attachments.len());
        for attachment in &status.attachments {
            println!(
                "  attachment={} pid={} phase={:?}",
                attachment.spec.id, attachment.spec.target.pid, attachment.phase
            );
        }
        if let Some(error) = &status.attachment_state_error {
            eprintln!("attachment state: {error}");
        }
        println!("connections: {}", status.connections.len());
        println!("log: {}", default_log_path()?.display());
    }
    Ok(0)
}

pub fn logs(config: LogsConfig) -> Result<i32, String> {
    let path = default_log_path()?;
    if !path.is_file() {
        return Err(format!("serve log does not exist: {}", path.display()));
    }
    for line in read_tail(&path, config.lines)? {
        println!("{line}");
    }
    if !config.follow {
        return Ok(0);
    }

    let mut position = std::fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len();
    loop {
        let length = std::fs::metadata(&path)
            .map_err(|error| format!("cannot inspect serve log {}: {error}", path.display()))?
            .len();
        if length < position {
            position = 0;
        }
        if length > position {
            let mut file = File::open(&path)
                .map_err(|error| format!("cannot open serve log {}: {error}", path.display()))?;
            file.seek(SeekFrom::Start(position))
                .map_err(|error| error.to_string())?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            print!("{}", String::from_utf8_lossy(&bytes));
            std::io::stdout()
                .flush()
                .map_err(|error| error.to_string())?;
            position = length;
        }
        thread::sleep(Duration::from_millis(250));
    }
}

struct ServeStatus {
    pid: u32,
    socks_address: String,
    started_at_ms: u64,
    generated_at_ms: u64,
    sessions: Vec<hyperhub_core::session::SessionSnapshot>,
    connections: Vec<hyperhub_core::session::ConnectionSnapshot>,
    engine_hosts: Vec<hyperhub_core::engine_hosts::HostStatus>,
    engine_upgrades: Option<hyperhub_core::upgrade::Status>,
    release_upgrades: Option<hyperhub_core::release::Status>,
    forward_workers: Option<hyperhub_core::socks::WorkerGroupStatus>,
    attachments: Vec<hyperhub_core::attachments::Record>,
    attachment_state_error: Option<String>,
    approval_trust: Option<hyperhub_core::attachments::ApprovalStatus>,
}

fn query_status() -> Result<Option<ServeStatus>, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let response = match runtime.block_on(control_request(
        &discovery_control_endpoint(),
        &ControlRequest::GetStatus,
    )) {
        Ok(response) => response,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(format!("cannot query HyperHub serve: {error}")),
    };
    match response {
        ControlResponse::Status {
            pid,
            socks_address,
            started_at_ms,
            generated_at_ms,
            sessions,
            connections,
            engine_hosts,
            engine_upgrades,
            release_upgrades,
            forward_workers,
            attachments,
            attachment_state_error,
            approval_trust,
        } => Ok(Some(ServeStatus {
            pid,
            socks_address,
            started_at_ms,
            generated_at_ms,
            sessions,
            connections,
            engine_hosts,
            engine_upgrades,
            release_upgrades,
            forward_workers,
            attachments,
            attachment_state_error,
            approval_trust,
        })),
        _ => Err("HyperHub serve returned an unexpected status response".into()),
    }
}

fn default_log_path() -> Result<PathBuf, String> {
    let config = default_config_path().map_err(|error| error.to_string())?;
    let parent = config
        .parent()
        .ok_or("cannot resolve the HyperHub state directory")?;
    Ok(parent.join("serve.log"))
}

fn read_tail(path: &PathBuf, lines: usize) -> Result<Vec<String>, String> {
    if lines == 0 {
        return Ok(Vec::new());
    }
    let file = File::open(path)
        .map_err(|error| format!("cannot open serve log {}: {error}", path.display()))?;
    let mut tail = VecDeque::with_capacity(lines);
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| error.to_string())?;
        if tail.len() == lines {
            tail.pop_front();
        }
        tail.push_back(line);
    }
    Ok(tail.into_iter().collect())
}

fn read_tail_from(path: &PathBuf, offset: u64, lines: usize) -> Result<Vec<String>, String> {
    if lines == 0 {
        return Ok(Vec::new());
    }
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open serve log {}: {error}", path.display()))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| error.to_string())?;
    let mut tail = VecDeque::with_capacity(lines);
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| error.to_string())?;
        if tail.len() == lines {
            tail.pop_front();
        }
        tail.push_back(line);
    }
    Ok(tail.into_iter().collect())
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(windows)]
fn configure_background_process(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

#[cfg(unix)]
fn configure_background_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(any(windows, unix)))]
fn configure_background_process(_command: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_does_not_infer_executor_protection_from_registry_availability() {
        for count in [None, Some(0), Some(3)] {
            let scope = protection_scope(count);
            assert_eq!(scope["kind"], "registered_process_trees");
            assert_eq!(scope["system_wide"], false);
            assert_eq!(
                scope["external_executor_delegation"],
                "not_automatically_managed"
            );
            assert_eq!(scope["specific_executor_protection"], "not_assessed");
            assert_eq!(scope["registered_processes"], serde_json::json!(count));
            assert_eq!(
                scope["registration_evidence"],
                if count.is_some() {
                    "current_serve_snapshot"
                } else {
                    "unavailable"
                }
            );
        }
    }

    #[test]
    fn default_log_is_next_to_the_encrypted_config() {
        let config = default_config_path().unwrap();
        assert_eq!(
            default_log_path().unwrap(),
            config.parent().unwrap().join("serve.log")
        );
    }

    #[test]
    fn tail_returns_only_requested_lines() {
        let path = std::env::temp_dir().join(format!(
            "hyperhub-log-tail-{}-{}",
            std::process::id(),
            unix_timestamp_ms()
        ));
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        assert_eq!(read_tail(&path, 2).unwrap(), ["two", "three"]);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn tail_from_excludes_previous_startup_output() {
        let path = std::env::temp_dir().join(format!(
            "hyperhub-log-attempt-{}-{}",
            std::process::id(),
            unix_timestamp_ms()
        ));
        std::fs::write(&path, "old error\nold usage\nnew error\nnew detail\n").unwrap();
        let offset = "old error\nold usage\n".len() as u64;
        assert_eq!(
            read_tail_from(&path, offset, 20).unwrap(),
            ["new error", "new detail"]
        );
        std::fs::remove_file(path).unwrap();
    }
}
