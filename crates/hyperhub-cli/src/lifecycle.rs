use crate::password;
use hyperhub_core::config_store::default_config_path;
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
    pub password_file: Option<PathBuf>,
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

    if crate::upgrade::check_on_start()? {
        return Ok(0);
    }

    let config_path = default_config_path().map_err(|error| error.to_string())?;
    let first_run = !config_path.is_file();
    let password = password::acquire(config.password_file.as_deref(), first_run)?;
    if first_run {
        crate::initialize_config_for_start(&config_path, password.as_bytes())?;
        println!(
            "HyperHub configuration initialized: {}",
            config_path.display()
        );
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
    command.arg("serve").arg("--password-stdin");
    if config.debug {
        command.arg("--debug");
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::from(
            log.try_clone().map_err(|error| error.to_string())?,
        ))
        .stderr(Stdio::from(log));
    configure_background_process(&mut command);

    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start HyperHub serve: {error}"))?;
    let pid = child.id();
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("cannot open the serve password channel".into());
    };
    if let Err(error) = stdin.write_all(password.as_bytes()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("cannot send password to HyperHub serve: {error}"));
    }
    drop(stdin);

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
                    "HyperHub serve started (pid {pid})\nhome: {}\ncontrol: {}\nsocks: {}\nlog: {}",
                    hyperhub_core::config_store::hyperhub_home()
                        .map_err(|error| error.to_string())?
                        .display(),
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
    let Some(status) = query_status()? else {
        println!("HyperHub serve is stopped");
        return Ok(0);
    };
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    match runtime.block_on(control_request(
        &discovery_control_endpoint(),
        &ControlRequest::Shutdown,
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
    stop()?;
    start(config)
}

pub fn status(json: bool) -> Result<i32, String> {
    let Some(status) = query_status()? else {
        let home =
            hyperhub_core::config_store::hyperhub_home().map_err(|error| error.to_string())?;
        let control_endpoint = discovery_control_endpoint();
        if json {
            let output = serde_json::json!({
                "state": "stopped",
                "hyperhub_home": home,
                "control_endpoint": control_endpoint,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?
            );
        } else {
            println!("HyperHub serve is stopped");
            println!("home: {}", home.display());
            println!("control: {control_endpoint}");
        }
        return Ok(3);
    };
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
        println!("sessions: {}", status.sessions.len());
        let managed = status
            .sessions
            .iter()
            .map(|session| session.processes.len())
            .sum::<usize>();
        println!("managed processes: {managed}");
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
        } => Ok(Some(ServeStatus {
            pid,
            socks_address,
            started_at_ms,
            generated_at_ms,
            sessions,
            connections,
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
