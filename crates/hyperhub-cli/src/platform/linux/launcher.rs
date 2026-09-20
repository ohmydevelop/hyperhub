use super::frida_core::{ChildOrigin, FridaCore, PendingChild, Process, Stdio};
use super::pty::PtyClient;
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hyperhub_core::control::{control_request, discovery_control_endpoint};

use crate::platform::TargetBackend;
use hyperhub_core::session::{ControlRequest, ControlResponse};
use sha2::{Digest, Sha256};

const ELF_MACHINE_X86_64: u16 = 62;
const ELF_MACHINE_AARCH64: u16 = 183;
const ELF_PROGRAM_INTERPRETER: u32 = 3;

pub fn backend_trust_environment(
    backend: TargetBackend,
    tls_ca_pem: &str,
) -> Result<Vec<(OsString, OsString)>, String> {
    if backend != TargetBackend::PtraceSyscall {
        return Ok(Vec::new());
    }
    if !tls_ca_pem.contains("-----BEGIN CERTIFICATE-----")
        || tls_ca_pem.contains("PRIVATE KEY-----")
    {
        return Err("Serve returned an invalid TLS root certificate".into());
    }
    let bundle = build_ptrace_trust_bundle(tls_ca_pem)?;
    let digest = Sha256::digest(&bundle);
    let name = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let endpoint = PathBuf::from(discovery_control_endpoint());
    let directory = endpoint
        .parent()
        .ok_or("HyperHub control endpoint has no parent directory")?;
    std::fs::create_dir_all(directory).map_err(|error| {
        format!(
            "cannot create HyperHub runtime directory {}: {error}",
            directory.display()
        )
    })?;
    let path = directory.join(format!("ptrace-ca-{name}.pem"));
    let current = std::fs::read(&path).ok();
    if current.as_deref() != Some(bundle.as_slice()) {
        let temporary = directory.join(format!(
            ".ptrace-ca-{name}-{}-{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&temporary, &bundle).map_err(|error| {
            format!(
                "cannot write ptrace trust bundle {}: {error}",
                temporary.display()
            )
        })?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot protect ptrace trust bundle: {error}"))?;
        std::fs::rename(&temporary, &path).map_err(|error| {
            format!(
                "cannot install ptrace trust bundle {}: {error}",
                path.display()
            )
        })?;
    }
    let value = path.into_os_string();
    Ok([
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "AWS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    ]
    .into_iter()
    .map(|name| (OsString::from(name), value.clone()))
    .collect())
}

fn build_ptrace_trust_bundle(tls_ca_pem: &str) -> Result<Vec<u8>, String> {
    let configured = ["SSL_CERT_FILE", "CURL_CA_BUNDLE"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from);
    let system = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
    ]
    .into_iter()
    .map(PathBuf::from);
    let mut bundle = configured
        .chain(system)
        .find_map(|path| std::fs::read(path).ok())
        .unwrap_or_default();
    let root = tls_ca_pem.as_bytes();
    if !bundle.windows(root.len()).any(|window| window == root) {
        if !bundle.is_empty() && !bundle.ends_with(b"\n") {
            bundle.push(b'\n');
        }
        bundle.extend_from_slice(root);
        if !bundle.ends_with(b"\n") {
            bundle.push(b'\n');
        }
    }
    if bundle.is_empty() {
        return Err("cannot construct ptrace TLS trust bundle".into());
    }
    Ok(bundle)
}

pub fn validate_target_runtime(target: &Path, runtime: &Path) -> Result<(), String> {
    let target = read_elf(target)?;
    if !target.has_interpreter {
        return Err(
            "static ELF does not support standard Frida Gum injection; use the ptrace syscall backend"
                .into(),
        );
    }
    if !runtime.is_file() {
        return Err(format!(
            "agent runtime does not exist: {}",
            runtime.display()
        ));
    }
    if runtime.extension().and_then(|x| x.to_str()) != Some("so") {
        return Err("Linux Agent runtime must be a .so file".into());
    }
    let runtime = read_elf(runtime)?;
    if target.machine != runtime.machine {
        return Err(format!(
            "target architecture {} does not match Agent architecture {}",
            machine_name(target.machine),
            machine_name(runtime.machine)
        ));
    }
    let native_machine = match std::env::consts::ARCH {
        "x86_64" => ELF_MACHINE_X86_64,
        "aarch64" => ELF_MACHINE_AARCH64,
        other => return Err(format!("unsupported Linux architecture: {other}")),
    };
    if target.machine != native_machine {
        return Err(format!(
            "target architecture {} does not match this HyperHub build ({})",
            machine_name(target.machine),
            std::env::consts::ARCH
        ));
    }
    Ok(())
}

pub fn target_backend(target: &Path, requested: Option<&str>) -> Result<TargetBackend, String> {
    let elf = read_elf(target)?;
    match requested {
        None | Some("ptrace") => Ok(TargetBackend::PtraceSyscall),
        Some("gum") if elf.has_interpreter => Ok(TargetBackend::GumInterceptor),
        Some("gum") => Err(
            "static ELF does not support standard Frida Gum injection; use --backend ptrace".into(),
        ),
        Some(value) => Err(format!("unknown backend '{value}'; use ptrace or gum")),
    }
}

pub fn doctor_target(target: &Path) -> Result<String, String> {
    let elf = read_elf(target)?;
    let backend = TargetBackend::PtraceSyscall;
    Ok(format!(
        "ELF64 little-endian {} {}; default-backend={}; gum={}; agent-runtime={}",
        machine_name(elf.machine),
        if elf.has_interpreter {
            "dynamically linked"
        } else {
            "static/no interpreter"
        },
        backend.name(),
        if elf.has_interpreter {
            "available"
        } else {
            "unavailable"
        },
        "not-used-by-default"
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ElfInfo {
    machine: u16,
    has_interpreter: bool,
}

fn read_elf(path: &Path) -> Result<ElfInfo, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read ELF {}: {error}", path.display()))?;
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        return Err(format!("{} is not an ELF executable", path.display()));
    }
    if bytes[4] != 2 {
        return Err(format!("{} is not a 64-bit ELF", path.display()));
    }
    if bytes[5] != 1 {
        return Err(format!("{} is not little-endian ELF", path.display()));
    }
    let machine = u16::from_le_bytes(bytes[18..20].try_into().unwrap());
    if !matches!(machine, ELF_MACHINE_X86_64 | ELF_MACHINE_AARCH64) {
        return Err(format!(
            "unsupported ELF architecture: {}",
            machine_name(machine)
        ));
    }
    let program_offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let entry_size = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let entry_count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    if entry_size < 4 {
        return Err(format!(
            "{} has an invalid ELF program table",
            path.display()
        ));
    }
    let table_size = entry_size
        .checked_mul(entry_count)
        .and_then(|size| program_offset.checked_add(size))
        .ok_or_else(|| format!("{} has an invalid ELF program table", path.display()))?;
    if table_size > bytes.len() {
        return Err(format!(
            "{} has a truncated ELF program table",
            path.display()
        ));
    }
    let has_interpreter = (0..entry_count).any(|index| {
        let offset = program_offset + index * entry_size;
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) == ELF_PROGRAM_INTERPRETER
    });
    Ok(ElfInfo {
        machine,
        has_interpreter,
    })
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        ELF_MACHINE_X86_64 => "x86_64",
        ELF_MACHINE_AARCH64 => "aarch64",
        _ => "unknown",
    }
}
pub fn run_injected<F>(
    target: &OsString,
    argv0: &OsString,
    args: &[OsString],
    backend: TargetBackend,
    runtime: Option<&Path>,
    env: &[(OsString, OsString)],
    sandbox: Option<&hyperhub_core::sandbox::SandboxSnapshot>,
    activate: F,
) -> Result<i32, String>
where
    F: FnOnce(u32, &std::ffi::OsStr) -> Result<bool, String>,
{
    let environment = merged_environment(env);
    if backend == TargetBackend::PtraceSyscall {
        return super::syscall_supervisor::run(
            target,
            argv0,
            args,
            &environment,
            sandbox.cloned(),
            activate,
        );
    }

    let runtime = runtime
        .ok_or("Linux requires libhyperhub_gum_agent.so")?
        .to_owned();
    let integrity = RuntimeIntegrity::from_environment(env)?;
    integrity.verify(&runtime)?;
    let frida = FridaCore::new().map_err(|error| format!("Frida Core init failed: {error}"))?;
    let cwd = std::env::current_dir()
        .map_err(|error| format!("cannot resolve current directory: {error}"))?;
    let mut pty = PtyClient::for_terminal(target, argv0, args)?;
    let (spawn_target, spawn_args) = pty
        .as_ref()
        .map(PtyClient::launch_command)
        .unwrap_or_else(|| (target.clone(), args.to_vec()));
    let process = frida
        .spawn(
            &spawn_target,
            &spawn_args,
            &environment,
            &cwd,
            Stdio::Inherit,
        )
        .map_err(|error| format!("Frida Core spawn failed: {error}"))?;
    let pid = process.pid() as u32;
    let process_start_time = process_start_time(pid);
    if pty.is_some() && process_start_time.is_none() {
        terminate_process(pid);
        return Err("cannot identify the Linux PTY launcher process".into());
    }
    let activated = activate(pid, &spawn_target).inspect_err(|_| terminate_process(pid))?;
    if !activated {
        terminate_process(pid);
        return Err("serve rejected Linux root process activation".into());
    }
    let ready = AgentReady::new(pid).map_err(|error| {
        terminate_process(pid);
        error
    })?;
    let ready_data = ready.data().map_err(|error| {
        terminate_process(pid);
        error
    })?;
    let _injected = frida
        .inject(process, &runtime, "frida_agent_main", &ready_data)
        .map_err(|error| {
            terminate_process(pid);
            format!("Frida Core injection failed: {error}")
        })?;
    if let Err(error) = ready.wait() {
        terminate_process(pid);
        return Err(error);
    }
    frida.enable_child_gating(process).map_err(|error| {
        terminate_process(pid);
        format!("Frida Core child gating failed: {error}")
    })?;
    let credentials = SessionCredentials::from_environment(env)?;
    let enforce = environment_value(env, "HYPERHUB_ENFORCEMENT_MODE").as_deref() != Some("observe");
    let monitor = ChildMonitor::start(frida.clone(), runtime, enforce, credentials, integrity)?;
    frida.resume(process).map_err(|error| {
        terminate_process(pid);
        format!("Frida Core resume failed: {error}")
    })?;
    let result = match pty.as_mut() {
        Some(pty) => pty.relay(pid, process_start_time.unwrap()),
        None => wait_for_process(pid, process_start_time),
    };
    monitor.stop();
    result
}

#[derive(Clone)]
struct RuntimeIntegrity {
    expected_hash: Option<[u8; 32]>,
    expected_size: Option<u64>,
}

impl RuntimeIntegrity {
    fn from_environment(env: &[(OsString, OsString)]) -> Result<Self, String> {
        let hash = environment_value(env, "HYPERHUB_AGENT_SHA256");
        let size = environment_value(env, "HYPERHUB_AGENT_SIZE");
        match (hash, size) {
            (None, None) => Ok(Self {
                expected_hash: None,
                expected_size: None,
            }),
            (Some(hash), Some(size)) => Ok(Self {
                expected_hash: Some(parse_sha256(&hash).ok_or("invalid Agent SHA-256")?),
                expected_size: Some(
                    size.parse()
                        .map_err(|_| "invalid Agent size metadata".to_string())?,
                ),
            }),
            _ => Err("incomplete Agent integrity metadata".into()),
        }
    }

    fn verify(&self, path: &Path) -> Result<(), String> {
        let Some(expected_hash) = self.expected_hash else {
            return Ok(());
        };
        let expected_size = self.expected_size.expect("hash metadata includes size");
        let mut file = std::fs::File::open(path)
            .map_err(|error| format!("cannot open Agent runtime {}: {error}", path.display()))?;
        let actual_size = file
            .metadata()
            .map_err(|error| format!("cannot inspect Agent runtime: {error}"))?
            .len();
        if actual_size != expected_size {
            return Err(format!(
                "Agent runtime size mismatch: expected {expected_size}, got {actual_size}"
            ));
        }
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)
            .map_err(|error| format!("cannot hash Agent runtime: {error}"))?;
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected_hash {
            return Err("Agent runtime SHA-256 verification failed".into());
        }
        Ok(())
    }
}

fn parse_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(result)
}

#[derive(Clone)]
struct SessionCredentials {
    endpoint: String,
    session_id: String,
    token: String,
}

impl SessionCredentials {
    fn from_environment(env: &[(OsString, OsString)]) -> Result<Self, String> {
        Ok(Self {
            endpoint: environment_value(env, "HYPERHUB_CONTROL_ENDPOINT")
                .ok_or("Linux child monitor is missing the control endpoint")?,
            session_id: environment_value(env, "HYPERHUB_SESSION_ID")
                .ok_or("Linux child monitor is missing the session ID")?,
            token: environment_value(env, "HYPERHUB_SESSION_TOKEN")
                .ok_or("Linux child monitor is missing the session token")?,
        })
    }
}

fn environment_value(env: &[(OsString, OsString)], key: &str) -> Option<String> {
    env.iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.to_string_lossy().into_owned())
}

struct ChildMonitor {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ChildMonitor {
    fn start(
        frida: FridaCore,
        runtime: PathBuf,
        enforce: bool,
        credentials: SessionCredentials,
        integrity: RuntimeIntegrity,
    ) -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("hyperhub-frida-children".into())
            .spawn(move || {
                monitor_children(
                    &frida,
                    &runtime,
                    enforce,
                    &credentials,
                    &integrity,
                    &worker_stop,
                )
            })
            .map_err(|error| format!("cannot start Frida child monitor: {error}"))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ChildMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn monitor_children(
    frida: &FridaCore,
    runtime: &Path,
    enforce: bool,
    credentials: &SessionCredentials,
    integrity: &RuntimeIntegrity,
    stop: &AtomicBool,
) {
    while !stop.load(Ordering::Acquire) {
        match frida.pending_children() {
            Ok(children) => {
                for child in children {
                    if child.skip_agent {
                        let _ = frida.resume(child.process);
                        continue;
                    }
                    if child.origin == ChildOrigin::Fork {
                        let result = register_fork_child(
                            credentials,
                            child.parent_pid as u32,
                            child.process,
                        )
                        .and_then(|_| {
                            frida
                                .resume(child.process)
                                .map_err(|error| format!("Frida Core fork resume failed: {error}"))
                        });
                        if let Err(error) = result {
                            handle_child_failure(frida, child, enforce, error);
                        } else {
                            debug_child_success(child, "resumed");
                        }
                        continue;
                    }
                    if let Err(error) = inject_child(frida, child.process, runtime, integrity) {
                        handle_child_failure(frida, child, enforce, error);
                    } else {
                        debug_child_success(child, "injected");
                    }
                }
            }
            Err(error) => {
                if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
                    eprintln!("hyperhub: cannot enumerate Frida pending children: {error}");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn debug_child_success(child: PendingChild, action: &str) {
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
        eprintln!(
            "hyperhub: Frida child {action} pid={} parent={} origin={:?}",
            child.process.pid(),
            child.parent_pid,
            child.origin
        );
    }
}

fn handle_child_failure(frida: &FridaCore, child: PendingChild, enforce: bool, error: String) {
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
        eprintln!(
            "hyperhub: Frida child injection failed pid={} parent={} origin={:?}: {error}",
            child.process.pid(),
            child.parent_pid,
            child.origin
        );
    }
    match child_failure_action(enforce) {
        ChildFailureAction::Terminate => terminate_process(child.process.pid() as u32),
        ChildFailureAction::Resume => {
            let _ = frida.resume(child.process);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChildFailureAction {
    Terminate,
    Resume,
}

fn child_failure_action(enforce: bool) -> ChildFailureAction {
    if enforce {
        ChildFailureAction::Terminate
    } else {
        ChildFailureAction::Resume
    }
}

fn register_fork_child(
    credentials: &SessionCredentials,
    parent_pid: u32,
    process: Process,
) -> Result<(), String> {
    let executable = std::fs::read_link(format!("/proc/{}/exe", process.pid()))
        .map_err(|error| format!("cannot resolve fork child executable: {error}"))?
        .to_string_lossy()
        .into_owned();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|error| format!("cannot create child registration runtime: {error}"))?;
    let response = runtime
        .block_on(control_request(
            &credentials.endpoint,
            &ControlRequest::RegisterChild {
                session_id: credentials.session_id.clone(),
                token: credentials.token.clone(),
                parent_pid,
                child_pid: process.pid() as u32,
                executable,
                process_policy_version: 0,
                process_rule_id: None,
                process_decision_source: "fork".into(),
            },
        ))
        .map_err(|error| format!("cannot register fork child: {error}"))?;
    if matches!(response, ControlResponse::Ok) {
        Ok(())
    } else {
        Err("serve rejected fork child registration".into())
    }
}

fn inject_child(
    frida: &FridaCore,
    process: Process,
    runtime: &Path,
    integrity: &RuntimeIntegrity,
) -> Result<(), String> {
    inject_child_entrypoint(frida, process, runtime, integrity, "frida_agent_main")
}

fn inject_child_entrypoint(
    frida: &FridaCore,
    process: Process,
    runtime: &Path,
    integrity: &RuntimeIntegrity,
    entrypoint: &str,
) -> Result<(), String> {
    integrity.verify(runtime)?;
    let pid = process.pid() as u32;
    let ready = AgentReady::new(pid)?;
    let data = ready.data()?;
    let _injected = frida
        .inject(process, runtime, entrypoint, &data)
        .map_err(|error| format!("Frida Core injection failed: {error}"))?;
    ready.wait()?;
    frida
        .enable_child_gating(process)
        .map_err(|error| format!("Frida Core child gating failed: {error}"))?;
    frida
        .resume(process)
        .map_err(|error| format!("Frida Core resume failed: {error}"))
}

struct AgentReady {
    path: PathBuf,
}

impl AgentReady {
    fn new(pid: u32) -> Result<Self, String> {
        for _ in 0..8 {
            let path = std::env::temp_dir().join(format!(
                "hyperhub-agent-ready-{pid}-{:016x}",
                rand::random::<u64>()
            ));
            if !path.exists() {
                return Ok(Self { path });
            }
        }
        Err("cannot allocate a unique Linux Agent ready signal".into())
    }

    fn data(&self) -> Result<CString, String> {
        CString::new(self.path.as_os_str().as_bytes())
            .map_err(|_| "Linux Agent ready path contains NUL".to_string())
    }

    fn wait(&self) -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::fs::read(&self.path) {
                Ok(value) => match parse_ready_status(&value) {
                    Some(Ok(())) => return Ok(()),
                    Some(Err(error)) => return Err(error),
                    None => {}
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!("cannot read Linux Agent ready signal: {error}"));
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("Linux Agent initialization timed out".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

fn parse_ready_status(value: &[u8]) -> Option<Result<(), String>> {
    if value == b"ok" {
        Some(Ok(()))
    } else if let Some(detail) = value.strip_prefix(b"error:") {
        Some(Err(format!(
            "Linux Agent initialization failed: {}",
            String::from_utf8_lossy(detail)
        )))
    } else {
        None
    }
}

impl Drop for AgentReady {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn merged_environment(overrides: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    let mut values = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for (key, value) in overrides {
        values.insert(key.clone(), value.clone());
    }
    values.into_iter().collect()
}

fn terminate_process(pid: u32) {
    let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let mut status = 0;
    let _ = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
}

fn wait_for_process(pid: u32, expected_start_time: Option<u64>) -> Result<i32, String> {
    loop {
        // A blocking waitpid consumes ptrace stops used by Frida child gating.
        // Reap only once the root process is a zombie; otherwise let Frida's
        // event loop observe and resume fork/exec transitions.
        if process_state(pid).is_some_and(|state| !matches!(state, 'Z' | 'X')) {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                while process_exists(pid, expected_start_time) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                return Ok(0);
            }
            return Err(error.to_string());
        }
        if waited == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(128 + libc::WTERMSIG(status));
        }
    }
}

pub(super) fn process_exists(pid: u32, expected_start_time: Option<u64>) -> bool {
    if let Some(expected) = expected_start_time {
        return process_start_time(pid) == Some(expected);
    }
    if unsafe { libc::kill(pid as i32, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn process_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?.1.chars().next()
}

fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = stat.rsplit_once(") ")?.1;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    if fields.first().is_some_and(|state| *state == "Z") {
        return None;
    }
    fields.get(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_elf(has_interpreter: bool) -> std::path::PathBuf {
        let mut bytes = vec![0u8; 64 + 56];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[18..20].copy_from_slice(&ELF_MACHINE_X86_64.to_le_bytes());
        bytes[32..40].copy_from_slice(&(64u64).to_le_bytes());
        bytes[54..56].copy_from_slice(&(56u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(1u16).to_le_bytes());
        if has_interpreter {
            bytes[64..68].copy_from_slice(&ELF_PROGRAM_INTERPRETER.to_le_bytes());
        }
        let path = std::env::temp_dir().join(format!(
            "hyperhub-elf-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn ptrace_trust_bundle_contains_the_hyperhub_root_once() {
        let root = "-----BEGIN CERTIFICATE-----\ntest-root\n-----END CERTIFICATE-----\n";
        let bundle = build_ptrace_trust_bundle(root).unwrap();
        assert_eq!(
            bundle
                .windows(root.len())
                .filter(|window| *window == root.as_bytes())
                .count(),
            1
        );
    }

    #[test]
    fn process_state_reads_the_current_process_without_reaping_it() {
        let state = process_state(std::process::id()).unwrap();
        assert!(!matches!(state, 'Z' | 'X'));
    }

    #[test]
    fn backend_selection_defaults_to_ptrace_and_allows_dynamic_gum() {
        let dynamic = write_test_elf(true);
        let static_target = write_test_elf(false);
        assert_eq!(
            target_backend(&dynamic, None).unwrap(),
            TargetBackend::PtraceSyscall
        );
        assert_eq!(
            target_backend(&static_target, None).unwrap(),
            TargetBackend::PtraceSyscall
        );
        assert_eq!(
            target_backend(&dynamic, Some("gum")).unwrap(),
            TargetBackend::GumInterceptor
        );
        assert!(target_backend(&static_target, Some("gum")).is_err());
        let _ = std::fs::remove_file(dynamic);
        let _ = std::fs::remove_file(static_target);
    }

    #[test]
    fn static_target_rejects_standard_gum_runtime_validation() {
        let target = write_test_elf(false);
        let error = validate_target_runtime(&target, Path::new("/missing-agent.so")).unwrap_err();
        let _ = std::fs::remove_file(target);
        assert!(error.contains("does not support standard Frida Gum injection"));
    }

    #[test]
    fn elf_parser_reports_machine_and_interpreter() {
        let path = write_test_elf(true);
        let info = read_elf(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(info.machine, ELF_MACHINE_X86_64);
        assert!(info.has_interpreter);
    }

    #[test]
    fn ready_status_distinguishes_success_failure_and_partial_data() {
        assert_eq!(parse_ready_status(b"ok"), Some(Ok(())));
        assert!(matches!(
            parse_ready_status(b"error:hook install failed"),
            Some(Err(error)) if error.contains("hook install failed")
        ));
        assert_eq!(parse_ready_status(b"o"), None);
    }

    #[test]
    fn child_failure_policy_matches_enforcement_mode() {
        assert_eq!(child_failure_action(true), ChildFailureAction::Terminate);
        assert_eq!(child_failure_action(false), ChildFailureAction::Resume);
    }

    #[test]
    fn parses_runtime_integrity_metadata() {
        let hash = "00".repeat(32);
        assert_eq!(parse_sha256(&hash), Some([0; 32]));
        assert!(parse_sha256("00").is_none());
    }
}
