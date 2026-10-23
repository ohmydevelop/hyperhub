use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, CString, OsString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

use hyperhub_core::config::{FileSandboxOperation, SandboxAction};
use hyperhub_core::control::control_request;
use hyperhub_core::sandbox::{
    compile_runtime_snapshot, file_error_decision, process_error_decision, CompiledSandboxSnapshot,
    FileProtectionBinding, ProcessProtectionBinding, ProtectionContext, SandboxAuditEvent,
    SandboxAuditKind, SandboxDecision,
};
use hyperhub_core::session::{ControlRequest, ControlResponse};

#[cfg(test)]
use super::dns_tracking::parse_dns_query;
use super::dns_tracking::{parse_dns_addresses, DnsTransactions};
use super::hook_manifest::{self, syscall};

const PTRACE_TRACEME: libc::c_uint = 0;
const PTRACE_PEEKDATA: libc::c_uint = 2;
const PTRACE_POKEDATA: libc::c_uint = 5;
const PTRACE_SYSCALL: libc::c_uint = 24;
const PTRACE_SETOPTIONS: libc::c_uint = 0x4200;
const PTRACE_GETEVENTMSG: libc::c_uint = 0x4201;
const PTRACE_GETREGSET: libc::c_uint = 0x4204;
const PTRACE_SETREGSET: libc::c_uint = 0x4205;
const PTRACE_O_TRACESYSGOOD: libc::c_ulong = 0x0000_0001;
const PTRACE_O_TRACEFORK: libc::c_ulong = 0x0000_0002;
const PTRACE_O_TRACEVFORK: libc::c_ulong = 0x0000_0004;
const PTRACE_O_TRACECLONE: libc::c_ulong = 0x0000_0008;
const PTRACE_O_TRACEEXEC: libc::c_ulong = 0x0000_0010;
const PTRACE_O_TRACEEXIT: libc::c_ulong = 0x0000_0040;
const PTRACE_O_EXITKILL: libc::c_ulong = 0x0010_0000;
const PTRACE_EVENT_FORK: u32 = 1;
const PTRACE_EVENT_VFORK: u32 = 2;
const PTRACE_EVENT_CLONE: u32 = 3;
const PTRACE_EVENT_EXEC: u32 = 4;
const NT_PRSTATUS: usize = 1;
const SYSCALL_STOP: i32 = libc::SIGTRAP | 0x80;
const SCRATCH_SIZE: usize = 4096;
const SANDBOX_REFRESH_INTERVAL: Duration = Duration::from_millis(250);
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;

#[derive(Debug)]
struct DnsReceivePacket {
    buffers: Vec<(usize, usize)>,
    header: Option<usize>,
    source: Option<(usize, usize)>,
}

#[derive(Clone, Debug)]
struct TargetAddress {
    ip: IpAddr,
    port: u16,
    hostname: Option<String>,
}

struct FileIntent {
    targets: Vec<String>,
    operations: Vec<(FileSandboxOperation, &'static str)>,
}

struct ProcessIntent {
    executable: String,
    argv: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketDescriptor {
    id: u64,
    domain: i32,
    socket_type: i32,
    handshake_complete: bool,
}

impl SocketDescriptor {
    fn requires_blocking_handshake(self) -> bool {
        matches!(self.domain, libc::AF_INET | libc::AF_INET6)
            && self.socket_type == libc::SOCK_STREAM
            && !self.handshake_complete
    }
}

impl ProcessIntent {
    fn command_line(&self) -> String {
        self.argv.join(" ")
    }
}

#[derive(Debug)]
enum PendingSyscall {
    OverrideResult {
        result: i64,
    },
    Close {
        fd: i32,
    },
    CloseRange {
        first: u32,
        last: u32,
        flags: u32,
    },
    UnshareFiles,
    Dup {
        old_fd: i32,
    },
    Socket {
        descriptor: SocketDescriptor,
        logical_nonblocking: bool,
    },
    UdpConnect {
        fd: i32,
        target: TargetAddress,
    },
    DnsSend {
        socket_id: u64,
        packets: Vec<Option<(SocketAddr, Vec<u8>)>>,
        batched: bool,
    },
    DnsReceive {
        socket_id: u64,
        packets: Vec<DnsReceivePacket>,
        batched: bool,
        peer: Option<SocketAddr>,
    },
    FcntlSetfl {
        socket_id: u64,
        logical_nonblocking: bool,
    },
    FcntlGetfl {
        logical_nonblocking: bool,
    },
    IoctlNonblocking {
        socket_id: u64,
        value_address: usize,
        original: [u8; 4],
        logical_nonblocking: bool,
    },
    Connect {
        fd: i32,
        address: usize,
        original: Vec<u8>,
        target: TargetAddress,
    },
}

#[derive(Debug)]
struct ThreadState {
    entering: bool,
    pending: Option<PendingSyscall>,
    engine: Option<hyperhub_runtime::Lease>,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self {
            entering: true,
            pending: None,
            engine: None,
        }
    }
}

struct Supervisor {
    engine: std::sync::Arc<hyperhub_runtime::Runtime>,
    socket_engines: HashMap<u64, hyperhub_runtime::Lease>,
    root_pid: libc::pid_t,
    proxy: SocketAddr,
    endpoint: String,
    session_id: String,
    password: Vec<u8>,
    next_connection_id: u64,
    next_socket_id: u64,
    control: tokio::runtime::Runtime,
    sandbox: Option<CompiledSandboxSnapshot>,
    sandbox_raw: Option<hyperhub_core::sandbox::SandboxSnapshot>,
    next_sandbox_refresh: Instant,
    last_sandbox_refresh_error: Option<String>,
    hook_counts: HashMap<&'static str, u64>,
    hook_report: Option<std::path::PathBuf>,
    require_all_hooks: bool,
    enforce: bool,
    threads: HashMap<libc::pid_t, ThreadState>,
    thread_groups: HashMap<libc::pid_t, libc::pid_t>,
    parents: HashMap<libc::pid_t, libc::pid_t>,
    members: HashSet<libc::pid_t>,
    logical_nonblocking: HashSet<u64>,
    file_tables: HashMap<libc::pid_t, u64>,
    pending_child_stops: HashSet<libc::pid_t>,
    next_file_table: u64,
    clone_flags: HashMap<libc::pid_t, u64>,
    sockets: HashMap<(u64, i32), SocketDescriptor>,
    udp_peers: HashMap<(u64, i32), TargetAddress>,
    dns_queries: DnsTransactions,
    dns_addresses: HashMap<(u64, IpAddr), (String, Instant)>,
    dns_ports: HashSet<u16>,
    root_status: Option<i32>,
    process_starts: HashMap<libc::pid_t, u64>,
    tree_failure: Option<(Option<i32>, Option<i32>)>,
    last_exit: Option<(u32, u64)>,
}

pub fn run<F>(
    target: &OsString,
    argv0: &OsString,
    args: &[OsString],
    environment: &[(OsString, OsString)],
    sandbox: Option<hyperhub_core::sandbox::SandboxSnapshot>,
    activate: F,
) -> Result<i32, String>
where
    F: FnOnce(u32, &std::ffi::OsStr) -> Result<bool, String>,
{
    let sandbox_raw = sandbox.clone();
    let sandbox = sandbox
        .map(compile_runtime_snapshot)
        .transpose()
        .map_err(|error| format!("cannot compile static sandbox snapshot: {error}"))?;
    let hook_report =
        environment_value(environment, "HYPERHUB_STATIC_HOOK_REPORT").map(std::path::PathBuf::from);
    let require_all_hooks =
        environment_value(environment, "HYPERHUB_STATIC_REQUIRE_ALL_HOOKS").as_deref() == Some("1");
    let enforce =
        environment_value(environment, "HYPERHUB_ENFORCEMENT_MODE").as_deref() != Some("observe");
    let mut dns_ports = HashSet::from([53u16]);
    if let Some(configured) = environment_value(environment, "HYPERHUB_DNS_PORTS") {
        for value in configured.split(',') {
            let port = value
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid HYPERHUB_DNS_PORTS value: {value}"))?;
            dns_ports.insert(port);
        }
    }
    let proxy = environment_value(environment, "HYPERHUB_SOCKS_ADDR")
        .ok_or("static syscall supervisor is missing HYPERHUB_SOCKS_ADDR")?
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid HyperHub SOCKS address: {error}"))?;
    let session_id = environment_value(environment, "HYPERHUB_SESSION_ID")
        .ok_or("static syscall supervisor is missing HYPERHUB_SESSION_ID")?;
    let password = environment_value(environment, "HYPERHUB_SESSION_TOKEN")
        .ok_or("static syscall supervisor is missing HYPERHUB_SESSION_TOKEN")?
        .into_bytes();
    let endpoint = environment_value(environment, "HYPERHUB_CONTROL_ENDPOINT")
        .ok_or("static syscall supervisor is missing HYPERHUB_CONTROL_ENDPOINT")?;
    if password.len() > u8::MAX as usize {
        return Err("HyperHub SOCKS password exceeds RFC 1929 limits".into());
    }

    let control = super::engine_control::control_runtime()?;
    let child = spawn_traced(target, argv0, args, environment)?;
    let initial_status = wait_for(child)?;
    if !libc::WIFSTOPPED(initial_status) || libc::WSTOPSIG(initial_status) != libc::SIGTRAP {
        terminate(child);
        return Err(format!(
            "static target did not stop after exec: status={initial_status:#x}"
        ));
    }
    if !activate(child as u32, target.as_os_str()).inspect_err(|_| terminate(child))? {
        terminate(child);
        return Err("serve rejected Linux static root process activation".into());
    }
    set_options(child).inspect_err(|_| terminate(child))?;

    let mut supervisor = Supervisor {
        engine: hyperhub_engine::resident(),
        socket_engines: HashMap::new(),
        root_pid: child,
        proxy,
        endpoint,
        session_id,
        password,
        next_connection_id: 1,
        next_socket_id: 1,
        control,
        sandbox,
        sandbox_raw,
        next_sandbox_refresh: Instant::now() + SANDBOX_REFRESH_INTERVAL,
        last_sandbox_refresh_error: None,
        hook_counts: HashMap::new(),
        hook_report,
        require_all_hooks,
        enforce,
        threads: HashMap::from([(child, ThreadState::default())]),
        thread_groups: HashMap::from([(child, child)]),
        parents: HashMap::new(),
        members: HashSet::from([child]),
        logical_nonblocking: HashSet::new(),
        file_tables: HashMap::from([(child, 1)]),
        pending_child_stops: HashSet::new(),
        next_file_table: 2,
        clone_flags: HashMap::new(),
        sockets: HashMap::new(),
        udp_peers: HashMap::new(),
        dns_queries: DnsTransactions::default(),
        dns_addresses: HashMap::new(),
        dns_ports,
        root_status: None,
        process_starts: process_birth(child)
            .map(|start| HashMap::from([(child, start)]))
            .unwrap_or_default(),
        tree_failure: None,
        last_exit: None,
    };
    super::engine_control::bootstrap(
        &supervisor.engine,
        &supervisor.endpoint,
        &supervisor.session_id,
        &String::from_utf8(supervisor.password.clone()).map_err(|_| "invalid session token")?,
        child as u32,
    )
    .inspect_err(|_| terminate(child))?;
    let _engine_control = super::engine_control::start(
        supervisor.engine.clone(),
        supervisor.endpoint.clone(),
        supervisor.session_id.clone(),
        String::from_utf8(supervisor.password.clone()).map_err(|_| "invalid session token")?,
        child as u32,
    )
    .inspect_err(|_| terminate(child))?;
    resume_syscall(child, 0).inspect_err(|_| terminate(child))?;
    let result = supervisor.event_loop();
    if result.is_err() {
        supervisor.terminate_all();
        return result;
    }
    supervisor.write_hook_report()?;
    result
}

fn engine_policy(
    engine: &hyperhub_runtime::Lease,
    operation: u32,
    snapshot: serde_json::Value,
    target: &str,
    file_op: &str,
    command_line: &str,
) -> Result<hyperhub_engine::contract::PolicyDecision, i32> {
    hyperhub_engine::policy(
        engine,
        operation,
        &hyperhub_engine::contract::PolicyInput {
            snapshot,
            target: target.into(),
            operation: file_op.into(),
            command_line: command_line.into(),
        },
    )
}
fn policy_decision(result: &hyperhub_engine::contract::PolicyDecision) -> SandboxDecision {
    SandboxDecision {
        action: if result.action == "pass" {
            SandboxAction::Pass
        } else {
            SandboxAction::Deny
        },
        rule_id: result.rule_id.clone(),
        source: match result.source.as_str() {
            "rule" => "rule",
            "default" => "default",
            _ => "error",
        },
    }
}
#[derive(serde::Deserialize)]
struct EngineSanitizedAction {
    local_deny: bool,
    features: Vec<String>,
    redacted_argv: Vec<String>,
}
fn engine_sanitize(
    engine: &hyperhub_runtime::Lease,
    executable: &str,
    argv: &[String],
    context: &ProtectionContext,
) -> EngineSanitizedAction {
    hyperhub_engine::call(
        engine,
        hyperhub_engine::contract::SANITIZE_ACTION,
        &serde_json::json!({"executable":executable,"argv":argv,"context":context}),
    )
    .ok()
    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    .unwrap_or_else(|| EngineSanitizedAction {
        local_deny: true,
        features: vec!["engine_error".into()],
        redacted_argv: vec!["<redacted>".into(); argv.len()],
    })
}

impl Supervisor {
    fn copy_descriptor(&mut self, process_pid: u64, old_fd: i32, new_fd: i32) {
        if old_fd == new_fd {
            return;
        }
        let old_key = (process_pid, old_fd);
        let new_key = (process_pid, new_fd);
        self.remove_descriptor(new_key);
        self.udp_peers.remove(&new_key);

        if let Some(descriptor) = self.sockets.get(&old_key).copied() {
            self.sockets.insert(new_key, descriptor);
        }
        if let Some(peer) = self.udp_peers.get(&old_key).cloned() {
            self.udp_peers.insert(new_key, peer);
        }
    }

    fn inherit_descriptors(&mut self, parent_pid: u64, child_pid: u64) {
        let sockets = self
            .sockets
            .iter()
            .filter_map(|(&(pid, fd), &descriptor)| {
                (pid == parent_pid).then_some(((child_pid, fd), descriptor))
            })
            .collect::<Vec<_>>();
        let udp_peers = self
            .udp_peers
            .iter()
            .filter_map(|(&(pid, fd), target)| {
                (pid == parent_pid).then_some(((child_pid, fd), target.clone()))
            })
            .collect::<Vec<_>>();
        self.sockets.extend(sockets);
        self.udp_peers.extend(udp_peers);
        let addresses = self
            .dns_addresses
            .iter()
            .filter_map(|(&(table, ip), value)| {
                (table == parent_pid).then_some(((child_pid, ip), value.clone()))
            })
            .collect::<Vec<_>>();
        self.dns_addresses.extend(addresses);
    }

    fn remove_descriptor(&mut self, key: (u64, i32)) {
        let Some(descriptor) = self.sockets.remove(&key) else {
            return;
        };
        if !self
            .sockets
            .values()
            .any(|candidate| candidate.id == descriptor.id)
        {
            self.socket_engines.remove(&descriptor.id);
            self.logical_nonblocking.remove(&descriptor.id);
            self.dns_queries.forget(descriptor.id);
        }
    }

    fn remove_descriptor_range(&mut self, process_pid: u64, first: u32, last: u32) {
        let keys = self
            .sockets
            .keys()
            .chain(self.udp_peers.keys())
            .filter_map(|&(pid, fd)| {
                let fd = u32::try_from(fd).ok()?;
                (pid == process_pid && fd >= first && fd <= last).then_some((pid, fd as i32))
            })
            .collect::<HashSet<_>>();
        for key in keys {
            self.remove_descriptor(key);
            self.udp_peers.remove(&key);
        }
    }

    fn reconcile_descriptors(&mut self, tid: libc::pid_t, process_pid: u64) {
        let keys = self
            .sockets
            .keys()
            .chain(self.udp_peers.keys())
            .filter_map(|&(pid, fd)| (pid == process_pid).then_some((pid, fd)))
            .collect::<HashSet<_>>();
        for key in keys {
            if !std::path::Path::new(&format!("/proc/{tid}/fd/{}", key.1)).exists() {
                self.remove_descriptor(key);
                self.udp_peers.remove(&key);
            }
        }
    }

    fn mark_handshake_complete(&mut self, socket_id: u64) {
        for descriptor in self.sockets.values_mut() {
            if descriptor.id == socket_id {
                descriptor.handshake_complete = true;
            }
        }
    }

    fn descriptor_table(&self, tid: libc::pid_t) -> u64 {
        *self
            .file_tables
            .get(&tid)
            .expect("traced thread has an fd table")
    }

    fn detach_file_table(&mut self, tid: libc::pid_t) {
        let old = self.descriptor_table(tid);
        if self
            .file_tables
            .values()
            .filter(|&&table| table == old)
            .count()
            <= 1
        {
            return;
        }
        let new = self.next_file_table;
        self.next_file_table += 1;
        self.inherit_descriptors(old, new);
        self.file_tables.insert(tid, new);
    }

    fn report_exit(
        &self,
        pid: u32,
        start: u64,
        code: Option<i32>,
        signal: Option<i32>,
        source: &str,
    ) {
        if let Err(error) = super::engine_control::report_exit(
            &self.endpoint,
            &self.session_id,
            pid,
            start,
            code,
            signal,
            source,
        ) {
            if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
                eprintln!("hyperhub: {error}");
            }
        }
    }
    fn observe_exit(&mut self, tid: libc::pid_t, code: Option<i32>, signal: Option<i32>) {
        let group = self.thread_groups.get(&tid).copied().unwrap_or(tid);
        if !super::engine_control::completed_normally(code, signal) {
            self.tree_failure = Some((code, signal));
        }
        if self
            .thread_groups
            .iter()
            .any(|(&other, &owner)| other != tid && owner == group)
        {
            return;
        }
        if let Some(start) = self.process_starts.remove(&group) {
            self.last_exit = Some((group as u32, start));
            self.report_exit(group as u32, start, code, signal, "ptrace_process");
        }
    }

    fn cleanup_exited_thread(&mut self, tid: libc::pid_t) {
        self.thread_groups.remove(&tid);
        self.clone_flags.remove(&tid);
        if let Some(table) = self.file_tables.remove(&tid) {
            if !self.file_tables.values().any(|&other| other == table) {
                self.remove_descriptor_range(table, 0, u32::MAX);
                self.dns_addresses.retain(|(owner, _), _| *owner != table);
            }
        }
    }

    fn event_loop(&mut self) -> Result<i32, String> {
        while !self.threads.is_empty() {
            let mut status = 0;
            let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
            if tid < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if error.raw_os_error() == Some(libc::ECHILD) {
                    break;
                }
                return Err(format!("waitpid failed in static supervisor: {error}"));
            }
            if libc::WIFEXITED(status) {
                if tid == self.root_pid {
                    self.root_status = Some(libc::WEXITSTATUS(status));
                }
                self.observe_exit(tid, Some(libc::WEXITSTATUS(status)), None);
                self.threads.remove(&tid);
                self.cleanup_exited_thread(tid);
                continue;
            }
            if libc::WIFSIGNALED(status) {
                if tid == self.root_pid {
                    self.root_status = Some(128 + libc::WTERMSIG(status));
                }
                self.observe_exit(tid, None, Some(libc::WTERMSIG(status)));
                self.threads.remove(&tid);
                self.cleanup_exited_thread(tid);
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }

            let signal = libc::WSTOPSIG(status);
            let event = (status as u32) >> 16;
            if signal == SYSCALL_STOP {
                self.handle_syscall(tid)?;
                resume_syscall(tid, 0)?;
                continue;
            }
            if signal == libc::SIGTRAP && event != 0 {
                self.handle_event(tid, event)?;
                resume_syscall(tid, 0)?;
                continue;
            }
            if !self.file_tables.contains_key(&tid) {
                self.pending_child_stops.insert(tid);
                continue;
            }
            self.threads.entry(tid).or_default();
            self.thread_groups
                .entry(tid)
                .or_insert_with(|| thread_group(tid));
            let deliver = if signal == libc::SIGSTOP || signal == libc::SIGTRAP {
                0
            } else {
                signal
            };
            resume_syscall(tid, deliver)?;
        }
        if let Some((pid, start)) = self.last_exit {
            let (code, signal) = self.tree_failure.unwrap_or((Some(0), None));
            self.report_exit(pid, start, code, signal, "ptrace_tree");
        }
        Ok(self.root_status.unwrap_or_default())
    }

    fn handle_event(&mut self, tid: libc::pid_t, event: u32) -> Result<(), String> {
        match event {
            PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE => {
                let mut child = 0usize;
                ptrace(
                    PTRACE_GETEVENTMSG,
                    tid,
                    std::ptr::null_mut(),
                    (&mut child as *mut usize).cast(),
                )?;
                if child != 0 {
                    let child = child as libc::pid_t;
                    self.threads.entry(child).or_default();
                    let parent_group = thread_group(tid);
                    let child_group = thread_group(child);
                    self.thread_groups.insert(child, child_group);
                    if let Some(start) = process_birth(child_group) {
                        self.process_starts.entry(child_group).or_insert(start);
                    }
                    let parent_table = self.descriptor_table(tid);
                    let table = if self.clone_flags.get(&tid).copied().unwrap_or(0)
                        & libc::CLONE_FILES as u64
                        != 0
                    {
                        parent_table
                    } else {
                        let table = self.next_file_table;
                        self.next_file_table += 1;
                        self.inherit_descriptors(parent_table, table);
                        table
                    };
                    self.file_tables.insert(child, table);
                    if child_group != parent_group {
                        self.parents.entry(child_group).or_insert(parent_group);
                        // Register every new process before either task resumes.
                        // Even a child that only exits or faults must have a
                        // registered birth for authenticated health reporting.
                        self.ensure_member(child)?;
                    }
                    if self.pending_child_stops.remove(&child) {
                        resume_syscall(child, 0)?;
                    }
                }
            }
            PTRACE_EVENT_EXEC => {
                let mut former = 0usize;
                ptrace(
                    PTRACE_GETEVENTMSG,
                    tid,
                    std::ptr::null_mut(),
                    (&mut former as *mut usize).cast(),
                )?;
                if former != 0 && former as libc::pid_t != tid {
                    let former = former as libc::pid_t;
                    let table = self.file_tables.remove(&former);
                    if let Some(state) = self.threads.remove(&former) {
                        self.threads.insert(tid, state);
                    }
                    self.thread_groups.remove(&former);
                    if let Some(table) = table {
                        self.file_tables.insert(tid, table);
                    }
                }
                self.threads.entry(tid).or_default().pending = None;
                self.threads.entry(tid).or_default().engine = None;
                let process_pid = thread_group(tid);
                self.thread_groups.insert(tid, process_pid);
                self.detach_file_table(tid);
                self.reconcile_descriptors(tid, self.descriptor_table(tid));
                self.refresh_exec_member(process_pid)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn refresh_sandbox_if_due(&mut self) {
        let now = Instant::now();
        if now < self.next_sandbox_refresh {
            return;
        }
        self.next_sandbox_refresh = now + SANDBOX_REFRESH_INTERVAL;
        let current_version = self.sandbox.as_ref().map_or(0, |snapshot| snapshot.version);
        let request = ControlRequest::RefreshSandbox {
            session_id: self.session_id.clone(),
            token: String::from_utf8_lossy(&self.password).into_owned(),
            root_pid: self.root_pid as u32,
            current_version,
        };
        let response = self
            .control
            .block_on(control_request(&self.endpoint, &request));
        let result = (|| -> Result<(), String> {
            match response {
                Ok(ControlResponse::SandboxRefresh {
                    version,
                    changed,
                    enforce,
                    sandbox,
                }) => {
                    self.enforce = enforce;
                    if !changed {
                        return Ok(());
                    }
                    let snapshot = sandbox.ok_or_else(|| {
                        "sandbox refresh reported a change without a snapshot".to_string()
                    })?;
                    if snapshot.version != version {
                        return Err(format!(
                            "sandbox refresh version mismatch: response={version} snapshot={}",
                            snapshot.version
                        ));
                    }
                    let compiled = compile_runtime_snapshot(snapshot.clone())
                        .map_err(|error| format!("cannot compile refreshed sandbox: {error}"))?;
                    self.sandbox = Some(compiled);
                    self.sandbox_raw = Some(snapshot);
                    Ok(())
                }
                Ok(ControlResponse::Error { message }) => Err(message),
                Ok(_) => Err("Serve returned an unexpected sandbox refresh response".into()),
                Err(error) => Err(format!("cannot refresh ptrace sandbox: {error}")),
            }
        })();
        match result {
            Ok(()) => self.last_sandbox_refresh_error = None,
            Err(error) => self.log_sandbox_refresh_error(error),
        }
    }

    fn log_sandbox_refresh_error(&mut self, error: String) {
        if self.last_sandbox_refresh_error.as_deref() == Some(error.as_str()) {
            return;
        }
        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
            eprintln!("hyperhub: ptrace sandbox refresh kept the previous snapshot: {error}");
        }
        self.last_sandbox_refresh_error = Some(error);
    }

    fn handle_syscall(&mut self, tid: libc::pid_t) -> Result<(), String> {
        let entering = self.threads.entry(tid).or_default().entering;
        if entering {
            self.refresh_sandbox_if_due();
        }
        let mut registers = Registers::get(tid)?;
        if entering {
            let engine = self.engine.acquire();
            let pending = self.syscall_enter(tid, &mut registers, &engine)?;
            if pending.is_some() {
                registers.set(tid)?;
            }
            let state = self.threads.entry(tid).or_default();
            state.pending = pending;
            state.engine = Some(engine);
            state.entering = false;
        } else {
            let pending = self.threads.entry(tid).or_default().pending.take();
            let modified = pending.is_some();
            let engine = self
                .threads
                .entry(tid)
                .or_default()
                .engine
                .take()
                .unwrap_or_else(|| self.engine.acquire());
            self.syscall_exit(tid, &mut registers, pending, &engine)?;
            if modified {
                registers.set(tid)?;
            }
            self.threads.entry(tid).or_default().entering = true;
        }
        Ok(())
    }

    fn syscall_enter(
        &mut self,
        tid: libc::pid_t,
        registers: &mut Registers,
        engine: &hyperhub_runtime::Lease,
    ) -> Result<Option<PendingSyscall>, String> {
        let number = registers.syscall_number();
        self.clone_flags.insert(
            tid,
            if number == syscall::CLONE {
                registers.argument(0)
            } else if number == syscall::CLONE3 {
                read_memory(tid, registers.argument(0) as usize, 8)
                    .ok()
                    .map(|bytes| u64::from_ne_bytes(bytes.try_into().unwrap()))
                    .unwrap_or(0)
            } else {
                0
            },
        );
        self.record_hooks(number);
        // Fast Open combines connect and first payload. Until the supervisor can
        // mediate both atomically, refuse it before any kernel network side effect.
        let flags = if number == syscall::SENDTO {
            registers.argument(3)
        } else if number == syscall::SENDMSG || number == syscall::SENDMMSG {
            registers.argument(2)
        } else {
            0
        };
        if flags & libc::MSG_FASTOPEN as u64 != 0 {
            return Ok(Some(deny_syscall(registers, libc::EOPNOTSUPP)));
        }
        if let Some(pending) = self.intent_enter(tid, number, registers, engine)? {
            return Ok(Some(pending));
        }
        // Observation must not turn a native EFAULT/partial batch into supervisor failure.
        if let Ok(Some(pending)) = self.dns_enter(tid, number, registers) {
            return Ok(Some(pending));
        }
        if number == syscall::SOCKET {
            let domain = registers.argument(0) as i32;
            let socket_type = registers.argument(1) as i32;
            let descriptor = SocketDescriptor {
                id: self.next_socket_id,
                domain,
                socket_type: socket_type & 0xf,
                handshake_complete: false,
            };
            self.next_socket_id = self.next_socket_id.saturating_add(1);
            let logical_nonblocking =
                descriptor.requires_blocking_handshake() && socket_type & libc::SOCK_NONBLOCK != 0;
            if logical_nonblocking {
                registers.set_argument(1, (socket_type & !libc::SOCK_NONBLOCK) as u64);
            }
            return Ok(Some(PendingSyscall::Socket {
                descriptor,
                logical_nonblocking,
            }));
        }
        if number == syscall::FCNTL {
            let fd = registers.argument(0) as i32;
            let command = registers.argument(1) as i32;
            let flags = registers.argument(2) as i32;
            if command == libc::F_DUPFD || command == libc::F_DUPFD_CLOEXEC {
                return Ok(Some(PendingSyscall::Dup { old_fd: fd }));
            }
            let key = (self.descriptor_table(tid), fd);
            let Some(descriptor) = self.sockets.get(&key).copied() else {
                return Ok(None);
            };
            if command == libc::F_GETFL && descriptor.requires_blocking_handshake() {
                return Ok(Some(PendingSyscall::FcntlGetfl {
                    logical_nonblocking: self.logical_nonblocking.contains(&descriptor.id),
                }));
            }
            if command == libc::F_SETFL {
                if !descriptor.requires_blocking_handshake() {
                    return Ok(None);
                }
                let logical_nonblocking = flags & libc::O_NONBLOCK != 0;
                if logical_nonblocking {
                    registers.set_argument(2, (flags & !libc::O_NONBLOCK) as u64);
                }
                return Ok(Some(PendingSyscall::FcntlSetfl {
                    socket_id: descriptor.id,
                    logical_nonblocking,
                }));
            }
            return Ok(None);
        }
        if number == syscall::IOCTL {
            let fd = registers.argument(0) as i32;
            let request = registers.argument(1) as libc::c_ulong;
            let value_address = registers.argument(2) as usize;
            if request == libc::FIONBIO as libc::c_ulong && value_address != 0 {
                let key = (self.descriptor_table(tid), fd);
                let Some(descriptor) = self.sockets.get(&key).copied() else {
                    return Ok(None);
                };
                if !descriptor.requires_blocking_handshake() {
                    return Ok(None);
                }
                let value = read_memory(tid, value_address, 4)?;
                let original: [u8; 4] = value.try_into().unwrap();
                let logical_nonblocking = i32::from_ne_bytes(original) != 0;
                if logical_nonblocking {
                    write_memory(tid, value_address, &0i32.to_ne_bytes())?;
                }
                return Ok(Some(PendingSyscall::IoctlNonblocking {
                    socket_id: descriptor.id,
                    value_address,
                    original,
                    logical_nonblocking,
                }));
            }
            return Ok(None);
        }
        if number != syscall::CONNECT {
            return Ok(None);
        }

        let fd = registers.argument(0) as i32;
        let address = registers.argument(1) as usize;
        let length = registers.argument(2) as usize;
        let original = read_memory(tid, address, length.min(128))?;
        let Some(mut target) = parse_sockaddr(&original) else {
            return Ok(None);
        };
        let socket_type = self
            .sockets
            .get(&(self.descriptor_table(tid), fd))
            .map(|descriptor| descriptor.socket_type);
        if socket_type == Some(libc::SOCK_DGRAM) {
            return Ok(Some(PendingSyscall::UdpConnect { fd, target }));
        }
        if socket_type.is_some_and(|kind| kind != libc::SOCK_STREAM) {
            return Ok(None);
        }
        target.hostname = self
            .dns_addresses
            .get(&(self.descriptor_table(tid), target.ip))
            .filter(|(_, expires)| *expires > Instant::now())
            .map(|(name, _)| name.clone());
        let decision = match hyperhub_engine::connect(
            engine,
            &hyperhub_engine::contract::ConnectInput {
                proxy: self.proxy,
                ip: target.ip,
                port: target.port,
                hostname: target.hostname.clone(),
            },
        ) {
            Ok(decision) => decision,
            Err(_) => return Ok(Some(deny_syscall(registers, libc::EPROTO))),
        };
        if !decision.intercept {
            return Ok(None);
        }
        match decision.target {
            hyperhub_engine::TargetAddress::Domain(name) => target.hostname = Some(name),
            hyperhub_engine::TargetAddress::Ip(ip) => {
                target.ip = ip;
                target.hostname = None;
            }
        }
        let proxy_ip = match decision.family {
            2 => IpAddr::V4(Ipv4Addr::new(
                decision.address[0],
                decision.address[1],
                decision.address[2],
                decision.address[3],
            )),
            10 => IpAddr::V6(Ipv6Addr::from(decision.address)),
            _ => return Ok(Some(deny_syscall(registers, libc::EPROTO))),
        };
        if let Some(socket) = self.sockets.get(&(self.descriptor_table(tid), fd)) {
            self.socket_engines.insert(socket.id, engine.clone());
        }
        let proxy = encode_proxy_sockaddr(
            SocketAddr::new(proxy_ip, decision.port),
            target.ip,
            original.len(),
        )?;
        write_memory(tid, address, &proxy)?;
        registers.set_argument(2, proxy.len() as u64);
        Ok(Some(PendingSyscall::Connect {
            fd,
            address,
            original,
            target,
        }))
    }

    fn syscall_exit(
        &mut self,
        tid: libc::pid_t,
        registers: &mut Registers,
        pending: Option<PendingSyscall>,
        engine: &hyperhub_runtime::Lease,
    ) -> Result<(), String> {
        match pending {
            Some(PendingSyscall::OverrideResult { result }) => {
                registers.set_result(result);
            }
            Some(PendingSyscall::Close { fd }) => {
                if registers.result() >= 0 {
                    let key = (self.descriptor_table(tid), fd);
                    self.remove_descriptor(key);
                    self.udp_peers.remove(&key);
                }
            }
            Some(PendingSyscall::CloseRange { first, last, flags }) => {
                if registers.result() >= 0 {
                    if flags & CLOSE_RANGE_UNSHARE != 0 {
                        self.detach_file_table(tid);
                    }
                    if flags & CLOSE_RANGE_CLOEXEC == 0 {
                        self.remove_descriptor_range(self.descriptor_table(tid), first, last);
                    }
                }
            }
            Some(PendingSyscall::UnshareFiles) => {
                if registers.result() >= 0 {
                    self.detach_file_table(tid);
                }
            }
            Some(PendingSyscall::Dup { old_fd }) => {
                let new_fd = registers.result();
                if new_fd >= 0 {
                    self.copy_descriptor(self.descriptor_table(tid), old_fd, new_fd as i32);
                }
            }
            Some(PendingSyscall::Socket {
                descriptor,
                logical_nonblocking,
            }) => {
                let fd = registers.result();
                if fd >= 0 {
                    let key = (self.descriptor_table(tid), fd as i32);
                    self.remove_descriptor(key);
                    self.udp_peers.remove(&key);
                    self.sockets.insert(key, descriptor);
                    if logical_nonblocking {
                        self.logical_nonblocking.insert(descriptor.id);
                    }
                }
            }
            Some(PendingSyscall::UdpConnect { fd, target }) => {
                if registers.result() >= 0 {
                    self.udp_peers
                        .insert((self.descriptor_table(tid), fd), target);
                }
            }
            Some(PendingSyscall::FcntlSetfl {
                socket_id,
                logical_nonblocking,
            }) => {
                if registers.result() >= 0 {
                    if logical_nonblocking {
                        self.logical_nonblocking.insert(socket_id);
                    } else {
                        self.logical_nonblocking.remove(&socket_id);
                    }
                }
            }
            Some(PendingSyscall::FcntlGetfl {
                logical_nonblocking,
            }) => {
                if logical_nonblocking && registers.result() >= 0 {
                    registers.set_result(registers.result() | i64::from(libc::O_NONBLOCK));
                }
            }
            Some(PendingSyscall::IoctlNonblocking {
                socket_id,
                value_address,
                original,
                logical_nonblocking,
            }) => {
                write_memory(tid, value_address, &original)?;
                if registers.result() >= 0 {
                    if logical_nonblocking {
                        self.logical_nonblocking.insert(socket_id);
                    } else {
                        self.logical_nonblocking.remove(&socket_id);
                    }
                }
            }
            Some(PendingSyscall::DnsSend {
                socket_id,
                packets,
                batched,
            }) => {
                let result = registers.result();
                if result >= 0 {
                    let count = if batched { result as usize } else { 1 };
                    for packet in packets.into_iter().take(count).flatten() {
                        if batched || result as usize == packet.1.len() {
                            self.dns_queries.sent(socket_id, packet.0, &packet.1);
                        }
                    }
                }
            }
            Some(PendingSyscall::DnsReceive {
                socket_id,
                packets,
                batched,
                peer,
            }) => {
                let result = registers.result();
                if result > 0 {
                    let count = if batched { result as usize } else { 1 };
                    for packet in packets.into_iter().take(count) {
                        let length = if batched {
                            u32::from_ne_bytes(
                                read_memory(tid, packet.header.unwrap() + 56, 4)?
                                    .try_into()
                                    .unwrap(),
                            ) as usize
                        } else {
                            result as usize
                        };
                        let response = read_buffers(tid, &packet.buffers, length.min(65535))?;
                        let source = if let Some(header) = packet.header {
                            read_msghdr(tid, header)?
                                .name
                                .as_deref()
                                .and_then(parse_sockaddr)
                        } else if let Some((address, length)) = packet.source {
                            let length = u32::from_ne_bytes(
                                read_memory(tid, length, 4)?.try_into().unwrap(),
                            ) as usize;
                            parse_sockaddr(&read_memory(tid, address, length.min(128))?)
                        } else {
                            None
                        };
                        let source = source
                            .map(|target| SocketAddr::new(target.ip, target.port))
                            .or(peer);
                        if let Some(hostname) =
                            self.dns_queries.received(socket_id, source, &response)
                        {
                            let hostname = match hyperhub_engine::normalize(engine, &hostname) {
                                Ok(hostname) => hostname,
                                Err(_) => {
                                    registers.set_result(-(libc::EPROTO as i64));
                                    return Ok(());
                                }
                            };
                            let table = self.descriptor_table(tid);
                            for address in parse_dns_addresses(&response) {
                                self.dns_addresses.insert(
                                    (table, address),
                                    (hostname.clone(), Instant::now() + Duration::from_secs(60)),
                                );
                            }
                        }
                    }
                }
            }
            Some(PendingSyscall::Connect {
                fd,
                address,
                original,
                target,
            }) => {
                write_memory(tid, address, &original)?;
                if registers.result() >= 0 {
                    let socket_id = self
                        .sockets
                        .get(&(self.descriptor_table(tid), fd))
                        .map(|descriptor| descriptor.id);
                    let handshake = self.socks_handshake(tid, registers, fd, target, engine);
                    if let Err(error) = handshake {
                        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
                            eprintln!("hyperhub: static SOCKS handshake failed: {error}");
                        }
                        registers.set_result(-(libc::EACCES as i64));
                    } else {
                        if let Some(socket_id) = socket_id {
                            self.mark_handshake_complete(socket_id);
                        }
                        registers.set_result(0);
                    }
                }
            }
            None => {}
        }
        Ok(())
    }

    fn dns_enter(
        &mut self,
        tid: libc::pid_t,
        number: i64,
        registers: &Registers,
    ) -> Result<Option<PendingSyscall>, String> {
        let fd = registers.argument(0) as i32;
        let key = (self.descriptor_table(tid), fd);
        let Some(descriptor) = self
            .sockets
            .get(&key)
            .copied()
            .filter(|socket| socket.socket_type == libc::SOCK_DGRAM)
        else {
            return Ok(None);
        };
        let peer = self.udp_peers.get(&key).cloned();
        let peer_address = peer
            .as_ref()
            .map(|target| SocketAddr::new(target.ip, target.port));
        let is_send = is_one_of(
            number,
            &[
                syscall::SENDTO,
                syscall::SENDMSG,
                syscall::SENDMMSG,
                syscall::WRITE,
                syscall::WRITEV,
            ],
        );
        if is_send {
            let batched = number == syscall::SENDMMSG;
            let mut packets = Vec::new();
            if number == syscall::SENDMSG || batched {
                let count = if batched {
                    (registers.argument(2) as usize).min(1024)
                } else {
                    1
                };
                for index in 0..count {
                    let Some(header) = (registers.argument(1) as usize).checked_add(index * 64)
                    else {
                        break;
                    };
                    let Ok(message) = read_msghdr(tid, header) else {
                        break;
                    };
                    let target = message
                        .name
                        .as_deref()
                        .and_then(parse_sockaddr)
                        .or_else(|| peer.clone());
                    let Ok(payload) = read_buffers(tid, &message.buffers, 65535) else {
                        break;
                    };
                    packets.push(
                        target
                            .filter(|target| self.dns_ports.contains(&target.port))
                            .map(|target| (SocketAddr::new(target.ip, target.port), payload)),
                    );
                }
            } else {
                let payload = if number == syscall::WRITEV {
                    let buffers = read_iovecs(
                        tid,
                        registers.argument(1) as usize,
                        registers.argument(2) as usize,
                    )?;
                    read_buffers(tid, &buffers, 65535)?
                } else {
                    read_memory(
                        tid,
                        registers.argument(1) as usize,
                        (registers.argument(2) as usize).min(65535),
                    )?
                };
                let target = if number == syscall::SENDTO && registers.argument(4) != 0 {
                    parse_sockaddr(&read_memory(
                        tid,
                        registers.argument(4) as usize,
                        (registers.argument(5) as usize).min(128),
                    )?)
                } else {
                    peer
                };
                packets.push(
                    target
                        .filter(|target| self.dns_ports.contains(&target.port))
                        .map(|target| (SocketAddr::new(target.ip, target.port), payload)),
                );
            }
            if packets.iter().any(Option::is_some) {
                self.record_named_hook(if number == syscall::SENDTO {
                    "dns.sendto"
                } else if number == syscall::SENDMSG {
                    "dns.sendmsg"
                } else if batched {
                    "dns.sendmmsg"
                } else if number == syscall::WRITEV {
                    "dns.writev"
                } else {
                    "dns.write"
                });
                return Ok(Some(PendingSyscall::DnsSend {
                    socket_id: descriptor.id,
                    packets,
                    batched,
                }));
            }
            return Ok(None);
        }
        if !self.dns_queries.has_queries(descriptor.id) {
            return Ok(None);
        }
        let batched = number == syscall::RECVMMSG;
        let mut packets = Vec::new();
        if number == syscall::RECVMSG || batched {
            let count = if batched {
                (registers.argument(2) as usize).min(1024)
            } else {
                1
            };
            for index in 0..count {
                let Some(header) = (registers.argument(1) as usize).checked_add(index * 64) else {
                    break;
                };
                let Ok(message) = read_msghdr(tid, header) else {
                    break;
                };
                packets.push(DnsReceivePacket {
                    buffers: message.buffers,
                    header: Some(header),
                    source: None,
                });
            }
        } else if number == syscall::RECVFROM || number == syscall::READ || number == syscall::READV
        {
            let buffers = if number == syscall::READV {
                read_iovecs(
                    tid,
                    registers.argument(1) as usize,
                    registers.argument(2) as usize,
                )?
            } else {
                vec![(
                    registers.argument(1) as usize,
                    registers.argument(2) as usize,
                )]
            };
            let source = (number == syscall::RECVFROM
                && registers.argument(4) != 0
                && registers.argument(5) != 0)
                .then_some((
                    registers.argument(4) as usize,
                    registers.argument(5) as usize,
                ));
            packets.push(DnsReceivePacket {
                buffers,
                header: None,
                source,
            });
        } else {
            return Ok(None);
        }
        self.record_named_hook(if batched {
            "dns.recvmmsg"
        } else if number == syscall::RECVMSG {
            "dns.recvmsg"
        } else if number == syscall::RECVFROM {
            "dns.recvfrom"
        } else if number == syscall::READV {
            "dns.readv"
        } else {
            "dns.read"
        });
        Ok(Some(PendingSyscall::DnsReceive {
            socket_id: descriptor.id,
            packets,
            batched,
            peer: peer_address,
        }))
    }

    fn intent_enter(
        &mut self,
        tid: libc::pid_t,
        number: i64,
        registers: &mut Registers,
        engine: &hyperhub_runtime::Lease,
    ) -> Result<Option<PendingSyscall>, String> {
        if number == syscall::UNSHARE && registers.argument(0) & libc::CLONE_FILES as u64 != 0 {
            return Ok(Some(PendingSyscall::UnshareFiles));
        }
        if number == syscall::CLOSE {
            return Ok(Some(PendingSyscall::Close {
                fd: registers.argument(0) as i32,
            }));
        }
        if number == syscall::CLOSE_RANGE {
            return Ok(Some(PendingSyscall::CloseRange {
                first: registers.argument(0) as u32,
                last: registers.argument(1) as u32,
                flags: registers.argument(2) as u32,
            }));
        }
        if is_one_of(number, &[syscall::DUP, syscall::DUP2, syscall::DUP3]) {
            return Ok(Some(PendingSyscall::Dup {
                old_fd: registers.argument(0) as i32,
            }));
        }

        match self.file_intent(tid, number, registers) {
            Ok(Some(intent)) if self.file_denied(tid, &intent, engine)? => {
                return Ok(Some(deny_syscall(registers, libc::EACCES)));
            }
            Err(error) if self.file_error_denied(tid, &error) => {
                return Ok(Some(deny_syscall(registers, libc::EACCES)));
            }
            _ => {}
        }

        match self.process_intent(tid, number, registers) {
            Ok(Some(intent)) if self.process_denied(tid, &intent, engine)? => {
                return Ok(Some(deny_syscall(registers, libc::EACCES)));
            }
            Err(error) if self.process_error_denied(tid, &error) => {
                return Ok(Some(deny_syscall(registers, libc::EACCES)));
            }
            _ => {}
        }
        Ok(None)
    }

    fn file_intent(
        &self,
        tid: libc::pid_t,
        number: i64,
        registers: &Registers,
    ) -> Result<Option<FileIntent>, String> {
        if self
            .sandbox
            .as_ref()
            .and_then(|snapshot| snapshot.file.as_ref())
            .is_none()
        {
            return Ok(None);
        }
        if number == syscall::OPEN && syscall::OPEN >= 0 {
            let path = read_path(tid, libc::AT_FDCWD, registers.argument(0) as usize)?;
            let flags = registers.argument(1) as i32;
            return Ok(Some(file_open_intent(path, flags)));
        }
        if number == syscall::CREAT && syscall::CREAT >= 0 {
            let path = read_path(tid, libc::AT_FDCWD, registers.argument(0) as usize)?;
            return Ok(Some(file_open_intent(path, libc::O_CREAT | libc::O_WRONLY)));
        }
        if number == syscall::OPENAT || number == syscall::OPENAT2 {
            let dirfd = registers.argument(0) as i32;
            let path = read_path(tid, dirfd, registers.argument(1) as usize)?;
            let flags = if number == syscall::OPENAT {
                registers.argument(2) as i32
            } else {
                let address = registers.argument(2) as usize;
                let bytes = read_memory(tid, address, 8)?;
                u64::from_ne_bytes(bytes.try_into().unwrap()) as i32
            };
            return Ok(Some(file_open_intent(path, flags)));
        }
        if is_one_of(
            number,
            &[
                syscall::READ,
                syscall::PREAD64,
                syscall::READV,
                syscall::PREADV,
                syscall::PREADV2,
            ],
        ) {
            if let Some(path) = fd_path(tid, registers.argument(0) as i32) {
                return Ok(Some(file_intent(path, FileSandboxOperation::Read, "read")));
            }
            return Ok(None);
        }
        if is_one_of(
            number,
            &[
                syscall::WRITE,
                syscall::PWRITE64,
                syscall::WRITEV,
                syscall::PWRITEV,
                syscall::PWRITEV2,
            ],
        ) {
            if let Some(path) = fd_path(tid, registers.argument(0) as i32) {
                return Ok(Some(file_intent(
                    path,
                    FileSandboxOperation::Write,
                    "write",
                )));
            }
            return Ok(None);
        }
        if number == syscall::UNLINK && syscall::UNLINK >= 0 {
            let path = read_path(tid, libc::AT_FDCWD, registers.argument(0) as usize)?;
            return Ok(Some(file_intent(
                path,
                FileSandboxOperation::Delete,
                "delete",
            )));
        }
        if number == syscall::UNLINKAT {
            let path = read_path(
                tid,
                registers.argument(0) as i32,
                registers.argument(1) as usize,
            )?;
            return Ok(Some(file_intent(
                path,
                FileSandboxOperation::Delete,
                "delete",
            )));
        }
        if number == syscall::RENAME && syscall::RENAME >= 0 {
            let old = read_path(tid, libc::AT_FDCWD, registers.argument(0) as usize)?;
            let new = read_path(tid, libc::AT_FDCWD, registers.argument(1) as usize)?;
            return Ok(Some(FileIntent {
                targets: vec![old, new],
                operations: vec![(FileSandboxOperation::Rename, "rename")],
            }));
        }
        if number == syscall::RENAMEAT || number == syscall::RENAMEAT2 {
            let old = read_path(
                tid,
                registers.argument(0) as i32,
                registers.argument(1) as usize,
            )?;
            let new = read_path(
                tid,
                registers.argument(2) as i32,
                registers.argument(3) as usize,
            )?;
            return Ok(Some(FileIntent {
                targets: vec![old, new],
                operations: vec![(FileSandboxOperation::Rename, "rename")],
            }));
        }
        if number == syscall::MMAP || number == syscall::MPROTECT {
            let protection = registers.argument(2) as i32;
            let mut operations = Vec::new();
            if protection & (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0 {
                operations.push((FileSandboxOperation::Read, "map_read"));
            }
            if protection & libc::PROT_WRITE != 0 {
                operations.push((FileSandboxOperation::Write, "map_write"));
            }
            if !operations.is_empty() {
                let targets = if number == syscall::MMAP {
                    if registers.argument(3) as i32 & libc::MAP_ANONYMOUS != 0 {
                        return Ok(None);
                    }
                    fd_path(tid, registers.argument(4) as i32)
                        .into_iter()
                        .collect()
                } else {
                    mapped_file_paths(
                        tid,
                        registers.argument(0) as usize,
                        registers.argument(1) as usize,
                    )?
                };
                if !targets.is_empty() {
                    return Ok(Some(FileIntent {
                        targets,
                        operations,
                    }));
                }
            }
        }
        Ok(None)
    }

    fn process_intent(
        &self,
        tid: libc::pid_t,
        number: i64,
        registers: &Registers,
    ) -> Result<Option<ProcessIntent>, String> {
        if self
            .sandbox
            .as_ref()
            .and_then(|snapshot| snapshot.process.as_ref())
            .is_none()
        {
            return Ok(None);
        }
        if is_one_of(
            number,
            &[
                syscall::CLONE,
                syscall::CLONE3,
                syscall::FORK,
                syscall::VFORK,
            ],
        ) {
            let process_pid = thread_group(tid);
            let executable = std::fs::read_link(format!("/proc/{process_pid}/exe"))
                .map_err(|error| format!("cannot resolve process executable: {error}"))?
                .to_string_lossy()
                .into_owned();
            let argv = std::fs::read(format!("/proc/{process_pid}/cmdline"))
                .map_err(|error| format!("cannot read process command line: {error}"))?
                .split(|byte| *byte == 0)
                .filter(|argument| !argument.is_empty())
                .map(|argument| String::from_utf8_lossy(argument).into_owned())
                .collect::<Vec<_>>();
            return Ok(Some(ProcessIntent { executable, argv }));
        }
        let (dirfd, path_address, argv_address, flags) = if number == syscall::EXECVE {
            (
                libc::AT_FDCWD,
                registers.argument(0) as usize,
                registers.argument(1) as usize,
                0,
            )
        } else if number == syscall::EXECVEAT {
            (
                registers.argument(0) as i32,
                registers.argument(1) as usize,
                registers.argument(2) as usize,
                registers.argument(4) as i32,
            )
        } else {
            return Ok(None);
        };
        let raw = read_c_string(tid, path_address, 4096)?;
        let executable = if raw.is_empty() && flags & libc::AT_EMPTY_PATH != 0 {
            fd_path(tid, dirfd).ok_or_else(|| format!("cannot resolve exec fd {dirfd}"))?
        } else {
            resolve_path(tid, dirfd, &raw)?
        };
        let argv = read_command_arguments(tid, argv_address)?;
        Ok(Some(ProcessIntent { executable, argv }))
    }

    fn file_denied(
        &mut self,
        tid: libc::pid_t,
        intent: &FileIntent,
        engine: &hyperhub_runtime::Lease,
    ) -> Result<bool, String> {
        for target in &intent.targets {
            for (operation, operation_name) in &intent.operations {
                let context = ProtectionContext::default();
                let sanitized = engine_sanitize(engine, target, &[target.clone()], &context);
                let (decision, binding) = {
                    let Some(snapshot) = self
                        .sandbox
                        .as_ref()
                        .and_then(|snapshot| snapshot.file.as_ref())
                    else {
                        return Ok(false);
                    };
                    let wire = self
                        .sandbox_raw
                        .as_ref()
                        .and_then(|s| s.file.as_ref())
                        .ok_or("missing file policy wire snapshot")?;
                    match engine_policy(
                        engine,
                        hyperhub_engine::contract::FILE_POLICY,
                        serde_json::to_value(wire).map_err(|e| e.to_string())?,
                        target,
                        serde_json::to_value(operation)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_owned))
                            .as_deref()
                            .unwrap_or(""),
                        "",
                    ) {
                        Ok(result) => {
                            let binding = result
                                .protection_rule_id
                                .clone()
                                .zip(result.protection.clone())
                                .map(|(rule_id, protection_id)| FileProtectionBinding {
                                    rule_id,
                                    protection_id,
                                });
                            (policy_decision(&result), binding)
                        }
                        Err(_) => (file_error_decision(snapshot), None),
                    }
                };
                if decision.action == SandboxAction::Deny {
                    self.report_sandbox(
                        tid,
                        SandboxAuditKind::File,
                        operation_name,
                        target,
                        &decision,
                        Some(sanitized.redacted_argv.clone()),
                        None,
                    );
                    return Ok(self.enforce);
                }
                let Some(binding) = binding else {
                    continue;
                };
                let process_pid = self.ensure_member(tid)? as u32;
                let executable = std::fs::read_link(format!("/proc/{process_pid}/exe"))
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "unknown".into());
                let response = self.control.block_on(control_request(
                    &self.endpoint,
                    &ControlRequest::StaticSmartProtectionCheck {
                        session_id: self.session_id.clone(),
                        token: String::from_utf8_lossy(&self.password).into_owned(),
                        root_pid: self.root_pid as u32,
                        process_pid,
                        protection_id: binding.protection_id,
                        rule_id: Some(binding.rule_id.clone()),
                        stage: format!("file_{}", operation_name),
                        executable,
                        argv: sanitized.redacted_argv.clone(),
                        features: sanitized.features,
                        context: serde_json::json!({
                            "local_deny": sanitized.local_deny,
                        }),
                    },
                ));
                let (action, reason) = match response {
                    Ok(ControlResponse::SmartProtectionDecision { action, reason, .. }) => {
                        (action, Some(reason))
                    }
                    Ok(ControlResponse::Error { message }) => {
                        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
                            eprintln!("hyperhub: file smart protection failed: {message}");
                        }
                        let action = self
                            .sandbox
                            .as_ref()
                            .and_then(|snapshot| snapshot.file.as_ref())
                            .map(file_error_decision)
                            .map_or(SandboxAction::Pass, |decision| decision.action);
                        (action, Some(format!("smart_protection_error: {message}")))
                    }
                    _ => {
                        let action = self
                            .sandbox
                            .as_ref()
                            .and_then(|snapshot| snapshot.file.as_ref())
                            .map(file_error_decision)
                            .map_or(SandboxAction::Pass, |decision| decision.action);
                        (action, Some("smart_protection_error".into()))
                    }
                };
                let denied = action == SandboxAction::Deny;
                let decision = SandboxDecision {
                    action,
                    rule_id: Some(binding.rule_id),
                    source: if denied {
                        "smart_protection"
                    } else {
                        "smart_protection_pass"
                    },
                };
                self.report_sandbox(
                    tid,
                    SandboxAuditKind::File,
                    operation_name,
                    target,
                    &decision,
                    Some(sanitized.redacted_argv),
                    reason,
                );
                if denied {
                    return Ok(self.enforce);
                }
            }
        }
        Ok(false)
    }

    fn file_error_denied(&mut self, tid: libc::pid_t, error: &str) -> bool {
        let Some(snapshot) = self
            .sandbox
            .as_ref()
            .and_then(|snapshot| snapshot.file.as_ref())
        else {
            return false;
        };
        let decision = file_error_decision(snapshot);
        if decision.action != SandboxAction::Deny {
            return false;
        }
        self.report_sandbox(
            tid,
            SandboxAuditKind::File,
            "inspect",
            &format!("<unresolved: {error}>"),
            &decision,
            None,
            Some("sandbox_inspection_error".into()),
        );
        self.enforce
    }

    fn process_error_denied(&mut self, tid: libc::pid_t, error: &str) -> bool {
        let Some(snapshot) = self
            .sandbox
            .as_ref()
            .and_then(|snapshot| snapshot.process.as_ref())
        else {
            return false;
        };
        let decision = process_error_decision(snapshot);
        if decision.action != SandboxAction::Deny {
            return false;
        }
        self.report_sandbox(
            tid,
            SandboxAuditKind::Process,
            "inspect",
            &format!("<unresolved: {error}>"),
            &decision,
            None,
            Some("sandbox_inspection_error".into()),
        );
        self.enforce
    }

    fn process_denied(
        &mut self,
        tid: libc::pid_t,
        intent: &ProcessIntent,
        engine: &hyperhub_runtime::Lease,
    ) -> Result<bool, String> {
        let Some(snapshot) = self
            .sandbox
            .as_ref()
            .and_then(|snapshot| snapshot.process.as_ref())
        else {
            return Ok(false);
        };
        let command_line = intent.command_line();
        let context = ProtectionContext::default();
        let sanitized = engine_sanitize(engine, &intent.executable, &intent.argv, &context);
        let wire = self
            .sandbox_raw
            .as_ref()
            .and_then(|s| s.process.as_ref())
            .ok_or("missing process policy wire snapshot")?;
        let result = engine_policy(
            engine,
            hyperhub_engine::contract::PROCESS_POLICY,
            serde_json::to_value(wire).map_err(|e| e.to_string())?,
            &intent.executable,
            "",
            &command_line,
        );
        let decision = result
            .as_ref()
            .map(policy_decision)
            .unwrap_or_else(|_| process_error_decision(snapshot));
        if decision.action == SandboxAction::Deny {
            self.report_sandbox(
                tid,
                SandboxAuditKind::Process,
                "create",
                &intent.executable,
                &decision,
                Some(sanitized.redacted_argv.clone()),
                None,
            );
            return Ok(self.enforce);
        }
        let binding = result
            .ok()
            .and_then(|r| r.protection_rule_id.zip(r.protection))
            .map(|(rule_id, protection_id)| ProcessProtectionBinding {
                rule_id,
                protection_id,
            });
        let Some(binding) = binding else {
            return Ok(false);
        };
        let process_pid = self.ensure_member(tid)? as u32;
        let response = self.control.block_on(control_request(
            &self.endpoint,
            &ControlRequest::StaticSmartProtectionCheck {
                session_id: self.session_id.clone(),
                token: String::from_utf8_lossy(&self.password).into_owned(),
                root_pid: self.root_pid as u32,
                process_pid,
                protection_id: binding.protection_id,
                rule_id: Some(binding.rule_id.clone()),
                stage: "process_create".into(),
                executable: intent.executable.clone(),
                argv: sanitized.redacted_argv.clone(),
                features: sanitized.features,
                context: serde_json::json!({
                    "local_deny": sanitized.local_deny,
                }),
            },
        ));
        match response {
            Ok(ControlResponse::SmartProtectionDecision { action, reason, .. }) => {
                let denied = action == SandboxAction::Deny;
                let decision = SandboxDecision {
                    action,
                    rule_id: Some(binding.rule_id),
                    source: if denied {
                        "smart_protection"
                    } else {
                        "smart_protection_pass"
                    },
                };
                self.report_sandbox(
                    tid,
                    SandboxAuditKind::Process,
                    "create",
                    &intent.executable,
                    &decision,
                    Some(sanitized.redacted_argv),
                    Some(reason),
                );
                Ok(denied && self.enforce)
            }
            Ok(ControlResponse::Error { message }) => {
                self.process_protection_error(tid, &intent.executable, &binding.rule_id, &message)
            }
            Ok(_) => self.process_protection_error(
                tid,
                &intent.executable,
                &binding.rule_id,
                "unexpected smart protection response",
            ),
            Err(error) => self.process_protection_error(
                tid,
                &intent.executable,
                &binding.rule_id,
                &error.to_string(),
            ),
        }
    }

    fn process_protection_error(
        &mut self,
        tid: libc::pid_t,
        executable: &str,
        rule_id: &str,
        error: &str,
    ) -> Result<bool, String> {
        let Some(snapshot) = self
            .sandbox
            .as_ref()
            .and_then(|snapshot| snapshot.process.as_ref())
        else {
            return Ok(false);
        };
        let error_action = process_error_decision(snapshot).action;
        let decision = SandboxDecision {
            action: error_action,
            rule_id: Some(rule_id.to_owned()),
            source: "smart_protection_error",
        };
        self.report_sandbox(
            tid,
            SandboxAuditKind::Process,
            "create",
            executable,
            &decision,
            None,
            Some(format!("smart_protection_error: {error}")),
        );
        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
            eprintln!("hyperhub: smart protection check failed: {error}");
        }
        Ok(error_action == SandboxAction::Deny && self.enforce)
    }

    fn report_sandbox(
        &mut self,
        tid: libc::pid_t,
        kind: SandboxAuditKind,
        operation: &str,
        target: &str,
        decision: &SandboxDecision,
        target_argv_redacted: Option<Vec<String>>,
        reason: Option<String>,
    ) {
        let process_pid = match self.ensure_member(tid) {
            Ok(pid) => pid,
            Err(error) => {
                if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
                    eprintln!("hyperhub: cannot register static sandbox reporter: {error}");
                }
                return;
            }
        };
        let process_executable = std::fs::read_link(format!("/proc/{process_pid}/exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| target.to_owned());
        let process_argv_redacted = read_process_argv(process_pid as libc::pid_t).map(|argv| {
            engine_sanitize(
                &self.engine.acquire(),
                &process_executable,
                &argv,
                &ProtectionContext::default(),
            )
            .redacted_argv
        });
        let event = SandboxAuditEvent {
            kind,
            decision: decision.action,
            rule_id: decision.rule_id.clone(),
            source: decision.source.into(),
            operation: operation.into(),
            target: target.into(),
            process_argv_redacted,
            target_argv_redacted,
            reason,
            process_pid: process_pid as u32,
            process_tid: tid as u32,
            snapshot_version: self.sandbox.as_ref().map_or(0, |snapshot| snapshot.version),
        };
        let response = self.control.block_on(control_request(
            &self.endpoint,
            &ControlRequest::ReportStaticSandboxAudit {
                session_id: self.session_id.clone(),
                token: String::from_utf8_lossy(&self.password).into_owned(),
                root_pid: self.root_pid as u32,
                event,
            },
        ));
        if let Err(error) = response {
            if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
                eprintln!("hyperhub: cannot report static sandbox decision: {error}");
            }
        }
    }

    fn socks_handshake(
        &mut self,
        tid: libc::pid_t,
        registers: &Registers,
        fd: i32,
        target: TargetAddress,
        engine: &hyperhub_runtime::Lease,
    ) -> Result<(), String> {
        let saved = *registers;
        let scratch = saved.stack_pointer().saturating_sub(SCRATCH_SIZE) & !15usize;
        let original = read_memory(tid, scratch, SCRATCH_SIZE)?;
        let socket_id = self
            .sockets
            .get(&(self.descriptor_table(tid), fd))
            .map(|descriptor| descriptor.id);
        let was_logical_nonblocking =
            socket_id.is_some_and(|socket_id| self.logical_nonblocking.contains(&socket_id));
        let result = (|| {
            let mut input = hyperhub_engine::contract::HandshakeInput {
                phase: 0,
                username: String::new(),
                password: Vec::new(),
                target: target
                    .hostname
                    .clone()
                    .map(hyperhub_engine::TargetAddress::Domain)
                    .unwrap_or(hyperhub_engine::TargetAddress::Ip(target.ip)),
                port: target.port,
            };
            let greeting_request = hyperhub_engine::handshake(engine, &input)
                .map_err(|e| format!("network Engine greeting failed: {e}"))?;
            self.remote_send_all(tid, &saved, fd, scratch, &greeting_request)?;
            let greeting = self.remote_recv_exact(tid, &saved, fd, scratch, 2)?;
            if hyperhub_engine::validate_reply(engine, 0, &greeting, false).is_err() {
                return Err(format!("SOCKS method negotiation returned {greeting:?}"));
            }

            let process_pid = self.ensure_member(tid)?;
            let connection_id = self.next_connection_id;
            self.next_connection_id = self
                .next_connection_id
                .checked_add(1)
                .ok_or("connection identity space is exhausted")?;
            input.phase = 1;
            input.username = format!("hh2:{}:{}:{}", self.session_id, process_pid, connection_id);
            input.password.clone_from(&self.password);
            let authentication = hyperhub_engine::handshake(engine, &input)
                .map_err(|e| format!("network Engine authentication failed: {e}"))?;
            self.remote_send_all(tid, &saved, fd, scratch, &authentication)?;
            let authentication_reply = self.remote_recv_exact(tid, &saved, fd, scratch, 2)?;
            if hyperhub_engine::validate_reply(engine, 1, &authentication_reply, false).is_err() {
                return Err(format!(
                    "SOCKS authentication returned {authentication_reply:?}"
                ));
            }

            input.phase = 2;
            let request = hyperhub_engine::handshake(engine, &input)
                .map_err(|e| format!("network Engine CONNECT failed: {e}"))?;
            self.remote_send_all(tid, &saved, fd, scratch, &request)?;
            let reply = self.remote_recv_exact(tid, &saved, fd, scratch, 4)?;
            if hyperhub_engine::validate_reply(engine, 2, &reply, true).is_err() {
                return Err(format!("SOCKS CONNECT returned {reply:?}"));
            }
            match reply[3] {
                1 => {
                    self.remote_recv_exact(tid, &saved, fd, scratch, 6)?;
                }
                4 => {
                    self.remote_recv_exact(tid, &saved, fd, scratch, 18)?;
                }
                3 => {
                    let length = self.remote_recv_exact(tid, &saved, fd, scratch, 1)?[0] as usize;
                    self.remote_recv_exact(tid, &saved, fd, scratch, length + 2)?;
                }
                value => {
                    return Err(format!(
                        "SOCKS CONNECT returned invalid address type {value}"
                    ))
                }
            }

            Ok(())
        })();
        let restore_nonblocking = if was_logical_nonblocking {
            (|| {
                let flags = remote_syscall(
                    tid,
                    &saved,
                    libc::SYS_fcntl,
                    [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
                )?;
                if flags < 0 {
                    return Err(format!("cannot read socket flags after handshake: {flags}"));
                }
                let restored = remote_syscall(
                    tid,
                    &saved,
                    libc::SYS_fcntl,
                    [
                        fd as u64,
                        libc::F_SETFL as u64,
                        (flags as i32 | libc::O_NONBLOCK) as u64,
                        0,
                        0,
                        0,
                    ],
                )?;
                if restored < 0 {
                    return Err(format!(
                        "cannot restore nonblocking socket after handshake: {restored}"
                    ));
                }
                if let Some(socket_id) = socket_id {
                    self.logical_nonblocking.remove(&socket_id);
                }
                Ok(())
            })()
        } else {
            Ok(())
        };
        let restore = write_memory(tid, scratch, &original);
        result.and(restore_nonblocking).and(restore)
    }

    fn ensure_member(&mut self, tid: libc::pid_t) -> Result<libc::pid_t, String> {
        let process_pid = thread_group(tid);
        if self.members.contains(&process_pid) {
            return Ok(process_pid);
        }

        let mut chain = Vec::new();
        let mut current = process_pid;
        while !self.members.contains(&current) {
            let parent = self
                .parents
                .get(&current)
                .copied()
                .or_else(|| process_parent(current))
                .ok_or_else(|| format!("cannot identify parent of static child {current}"))?;
            if parent == current || parent <= 0 {
                return Err(format!(
                    "invalid parent {parent} for static child {current}"
                ));
            }
            chain.push((parent, current));
            current = parent;
            if chain.len() > 64 {
                return Err("static child ancestry exceeds 64 processes".into());
            }
        }

        for (parent, child) in chain.into_iter().rev() {
            self.register_member(parent, child, "static-supervisor", Duration::from_secs(30))
                .map_err(|error| format!("cannot register static child {child}: {error}"))?;
            self.members.insert(child);
        }
        Ok(process_pid)
    }

    fn register_member(
        &self,
        parent: libc::pid_t,
        child: libc::pid_t,
        source: &str,
        timeout: Duration,
    ) -> std::io::Result<()> {
        let executable = std::fs::read_link(format!("/proc/{child}/exe"))?
            .to_string_lossy()
            .into_owned();
        let response = self.control.block_on(async {
            tokio::time::timeout(
                timeout,
                control_request(
                    &self.endpoint,
                    &ControlRequest::RegisterChild {
                        session_id: self.session_id.clone(),
                        token: String::from_utf8_lossy(&self.password).into_owned(),
                        parent_pid: parent as u32,
                        child_pid: child as u32,
                        executable,
                        process_policy_version: 0,
                        process_rule_id: None,
                        process_decision_source: source.into(),
                    },
                ),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "static process registration timed out",
                )
            })?
        })?;
        if matches!(response, ControlResponse::Ok) {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Serve rejected static process registration",
            ))
        }
    }

    fn refresh_exec_member(&self, process: libc::pid_t) -> Result<(), String> {
        // Successful exec keeps PID and birth, but changes the executable used
        // for authenticated restart recovery. Refresh before this image runs.
        if !self
            .process_starts
            .get(&process)
            .is_some_and(|birth| *birth != 0 && process_birth(process) == Some(*birth))
        {
            return Err(format!(
                "static exec process identity changed for {process}"
            ));
        }
        let parent = self
            .parents
            .get(&process)
            .copied()
            .or_else(|| process_parent(process))
            .ok_or_else(|| format!("cannot identify exec parent for {process}"))?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.register_member(
                parent,
                process,
                "static-supervisor-exec",
                deadline.saturating_duration_since(Instant::now()),
            ) {
                Ok(()) => return Ok(()),
                Err(error)
                    if Instant::now() < deadline
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound
                                | std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                        ) =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => {
                    return Err(format!("cannot refresh static exec {process}: {error}"));
                }
            }
        }
    }

    fn record_hooks(&mut self, number: i64) {
        for point in hook_manifest::for_syscall(number) {
            if point.intent != super::hook_manifest::Intent::DnsResolution {
                *self.hook_counts.entry(point.name).or_default() += 1;
            }
        }
    }

    fn record_named_hook(&mut self, name: &'static str) {
        *self.hook_counts.entry(name).or_default() += 1;
    }

    fn write_hook_report(&self) -> Result<(), String> {
        let missing = hook_manifest::HOOK_POINTS
            .iter()
            .filter(|point| point.fixture_required && point.syscall >= 0)
            .filter(|point| !self.hook_counts.contains_key(point.name))
            .map(|point| point.name)
            .collect::<Vec<_>>();
        if let Some(path) = &self.hook_report {
            let report = serde_json::json!({
                "architecture": std::env::consts::ARCH,
                "counts": self.hook_counts,
                "missing_required": missing,
            });
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "cannot create static hook report directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            std::fs::write(
                path,
                serde_json::to_vec_pretty(&report)
                    .map_err(|error| format!("cannot encode static hook report: {error}"))?,
            )
            .map_err(|error| {
                format!(
                    "cannot write static hook report {}: {error}",
                    path.display()
                )
            })?;
        }
        if self.require_all_hooks && !missing.is_empty() {
            return Err(format!(
                "static hook fixture missed required points: {}",
                missing.join(", ")
            ));
        }
        Ok(())
    }

    fn terminate_all(&mut self) {
        let process_ids = self
            .threads
            .keys()
            .map(|tid| thread_group(*tid))
            .collect::<HashSet<_>>();
        for pid in process_ids {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        self.threads.clear();
    }

    fn remote_send_all(
        &self,
        tid: libc::pid_t,
        saved: &Registers,
        fd: i32,
        scratch: usize,
        data: &[u8],
    ) -> Result<(), String> {
        write_memory(tid, scratch, data)?;
        let mut written = 0usize;
        while written < data.len() {
            let result = remote_syscall(
                tid,
                saved,
                libc::SYS_sendto,
                [
                    fd as u64,
                    (scratch + written) as u64,
                    (data.len() - written) as u64,
                    libc::MSG_NOSIGNAL as u64,
                    0,
                    0,
                ],
            )?;
            if result <= 0 {
                return Err(format!("remote send failed with {result}"));
            }
            written += result as usize;
        }
        Ok(())
    }

    fn remote_recv_exact(
        &self,
        tid: libc::pid_t,
        saved: &Registers,
        fd: i32,
        scratch: usize,
        length: usize,
    ) -> Result<Vec<u8>, String> {
        if length > SCRATCH_SIZE {
            return Err("SOCKS response exceeds supervisor scratch space".into());
        }
        let mut received = 0usize;
        while received < length {
            let result = remote_syscall(
                tid,
                saved,
                libc::SYS_recvfrom,
                [
                    fd as u64,
                    (scratch + received) as u64,
                    (length - received) as u64,
                    0,
                    0,
                    0,
                ],
            )?;
            if result <= 0 {
                return Err(format!("remote receive failed with {result}"));
            }
            received += result as usize;
        }
        read_memory(tid, scratch, length)
    }
}

struct RemoteMessage {
    name: Option<Vec<u8>>,
    buffers: Vec<(usize, usize)>,
}

fn read_msghdr(tid: libc::pid_t, address: usize) -> Result<RemoteMessage, String> {
    let header = read_memory(tid, address, 56)?;
    let name_address = u64::from_ne_bytes(header[0..8].try_into().unwrap()) as usize;
    let name_length = u32::from_ne_bytes(header[8..12].try_into().unwrap()) as usize;
    let iov_address = u64::from_ne_bytes(header[16..24].try_into().unwrap()) as usize;
    let iov_count = (u64::from_ne_bytes(header[24..32].try_into().unwrap()) as usize).min(1024);
    let name = if name_address != 0 && name_length != 0 {
        Some(read_memory(tid, name_address, name_length.min(128))?)
    } else {
        None
    };
    let buffers = read_iovecs(tid, iov_address, iov_count)?;
    Ok(RemoteMessage { name, buffers })
}

fn read_iovecs(
    tid: libc::pid_t,
    iov_address: usize,
    count: usize,
) -> Result<Vec<(usize, usize)>, String> {
    let mut buffers = Vec::with_capacity(count.min(1024));
    for index in 0..count.min(1024) {
        let address = iov_address
            .checked_add(index * 16)
            .ok_or("iovec address overflow")?;
        let iovec = read_memory(tid, address, 16)?;
        let base = u64::from_ne_bytes(iovec[0..8].try_into().unwrap()) as usize;
        let length = u64::from_ne_bytes(iovec[8..16].try_into().unwrap()) as usize;
        if base != 0 && length != 0 {
            buffers.push((base, length));
        }
    }
    Ok(buffers)
}

fn read_buffers(
    tid: libc::pid_t,
    buffers: &[(usize, usize)],
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    for (address, length) in buffers {
        if output.len() >= maximum {
            break;
        }
        let count = (*length).min(maximum - output.len());
        output.extend_from_slice(&read_memory(tid, *address, count)?);
    }
    Ok(output)
}

fn deny_syscall(registers: &mut Registers, error: i32) -> PendingSyscall {
    registers.set_syscall_number(syscall::GETPID);
    PendingSyscall::OverrideResult {
        result: -(error as i64),
    }
}

fn is_one_of(number: i64, candidates: &[i64]) -> bool {
    candidates
        .iter()
        .any(|candidate| *candidate >= 0 && *candidate == number)
}

fn file_intent(
    target: String,
    operation: FileSandboxOperation,
    operation_name: &'static str,
) -> FileIntent {
    FileIntent {
        targets: vec![target],
        operations: vec![(operation, operation_name)],
    }
}

fn file_open_intent(target: String, flags: i32) -> FileIntent {
    let mut operations = Vec::new();
    if flags & libc::O_CREAT != 0 {
        operations.push((FileSandboxOperation::Create, "create"));
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_TRUNC != 0 {
        operations.push((FileSandboxOperation::Write, "write"));
    }
    if operations.is_empty() {
        operations.push((FileSandboxOperation::Read, "read"));
    }
    FileIntent {
        targets: vec![target],
        operations,
    }
}

fn read_c_string(tid: libc::pid_t, address: usize, limit: usize) -> Result<String, String> {
    if address == 0 {
        return Err("target string pointer is null".into());
    }
    let word = std::mem::size_of::<libc::c_long>();
    let mut output = Vec::new();
    while output.len() < limit {
        let bytes = ptrace(
            PTRACE_PEEKDATA,
            tid,
            (address + output.len()) as *mut c_void,
            std::ptr::null_mut(),
        )?
        .to_ne_bytes();
        for byte in bytes {
            if byte == 0 {
                return String::from_utf8(output)
                    .map_err(|_| "target string is not UTF-8".to_string());
            }
            output.push(byte);
            if output.len() == limit {
                break;
            }
        }
        if word == 0 {
            break;
        }
    }
    Err(format!("target string exceeds {limit} bytes"))
}

fn read_command_arguments(tid: libc::pid_t, address: usize) -> Result<Vec<String>, String> {
    if address == 0 {
        return Ok(Vec::new());
    }
    let mut arguments = Vec::new();
    for index in 0..128usize {
        let bytes = read_memory(
            tid,
            address + index * std::mem::size_of::<usize>(),
            std::mem::size_of::<usize>(),
        )?;
        let pointer = usize::from_ne_bytes(bytes.try_into().unwrap());
        if pointer == 0 {
            return Ok(arguments);
        }
        arguments.push(read_c_string(tid, pointer, 4096)?);
    }
    Err("target command line exceeds 128 arguments".into())
}

fn read_process_argv(pid: libc::pid_t) -> Option<Vec<String>> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv = bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument).into_owned())
        .collect::<Vec<_>>();
    (!argv.is_empty()).then_some(argv)
}

fn read_path(tid: libc::pid_t, dirfd: i32, address: usize) -> Result<String, String> {
    let raw = read_c_string(tid, address, 4096)?;
    resolve_path(tid, dirfd, &raw)
}

fn resolve_path(tid: libc::pid_t, dirfd: i32, raw: &str) -> Result<String, String> {
    let path = std::path::Path::new(raw);
    if path.is_absolute() {
        return Ok(normalize_path(path));
    }
    let process_pid = tid;
    let root = if dirfd == libc::AT_FDCWD {
        std::fs::read_link(format!("/proc/{process_pid}/cwd"))
            .map_err(|error| format!("cannot resolve cwd for {process_pid}: {error}"))?
    } else {
        std::fs::read_link(format!("/proc/{process_pid}/fd/{dirfd}"))
            .map_err(|error| format!("cannot resolve fd {dirfd} for {process_pid}: {error}"))?
    };
    Ok(normalize_path(&root.join(path)))
}

fn normalize_path(path: &std::path::Path) -> String {
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized.to_string_lossy().into_owned()
}

fn fd_path(tid: libc::pid_t, fd: i32) -> Option<String> {
    if fd < 0 {
        return None;
    }
    let process_pid = tid;
    let path = std::fs::read_link(format!("/proc/{process_pid}/fd/{fd}")).ok()?;
    path.is_absolute().then(|| normalize_path(&path))
}

fn mapped_file_paths(
    process_pid: libc::pid_t,
    address: usize,
    length: usize,
) -> Result<Vec<String>, String> {
    let maps = std::fs::read_to_string(format!("/proc/{process_pid}/maps"))
        .map_err(|error| format!("cannot read mappings for {process_pid}: {error}"))?;
    Ok(parse_mapped_file_paths(&maps, address, length))
}

fn parse_mapped_file_paths(maps: &str, address: usize, length: usize) -> Vec<String> {
    let requested_end = address.saturating_add(length);
    let mut paths = HashSet::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some((start, end)) = range.split_once('-').and_then(|(start, end)| {
            Some((
                usize::from_str_radix(start, 16).ok()?,
                usize::from_str_radix(end, 16).ok()?,
            ))
        }) else {
            continue;
        };
        if start >= requested_end || end <= address {
            continue;
        }
        let Some(path) = fields.nth(4) else {
            continue;
        };
        if path.starts_with('/') {
            paths.insert(normalize_path(std::path::Path::new(
                path.strip_suffix(" (deleted)").unwrap_or(path),
            )));
        }
    }
    let mut paths = paths.into_iter().collect::<Vec<_>>();
    paths.sort();
    paths
}

fn environment_value(environment: &[(OsString, OsString)], key: &str) -> Option<String> {
    environment
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.to_string_lossy().into_owned())
}

fn spawn_traced(
    target: &OsString,
    argv0: &OsString,
    args: &[OsString],
    environment: &[(OsString, OsString)],
) -> Result<libc::pid_t, String> {
    let program = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| "target contains NUL".to_string())?;
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(
        CString::new(argv0.as_os_str().as_bytes())
            .map_err(|_| "argv[0] contains NUL".to_string())?,
    );
    for argument in args {
        argv.push(
            CString::new(argument.as_os_str().as_bytes())
                .map_err(|_| "argument contains NUL".to_string())?,
        );
    }
    let mut argv_pointers = argv.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    argv_pointers.push(std::ptr::null());

    let mut env = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let mut item = name.as_os_str().as_bytes().to_vec();
        item.push(b'=');
        item.extend_from_slice(value.as_os_str().as_bytes());
        env.push(CString::new(item).map_err(|_| "environment contains NUL".to_string())?);
    }
    let mut env_pointers = env.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    env_pointers.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "cannot fork static target: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        unsafe {
            if libc::ptrace(
                PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<c_void>(),
                std::ptr::null_mut::<c_void>(),
            ) != 0
            {
                libc::_exit(126);
            }
            libc::execve(
                program.as_ptr(),
                argv_pointers.as_ptr(),
                env_pointers.as_ptr(),
            );
            libc::_exit(127);
        }
    }
    Ok(pid)
}

fn wait_for(pid: libc::pid_t) -> Result<i32, String> {
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return Ok(status);
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("cannot wait for static target: {error}"));
        }
    }
}

fn set_options(tid: libc::pid_t) -> Result<(), String> {
    let options = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC
        | PTRACE_O_TRACEEXIT
        | PTRACE_O_EXITKILL;
    ptrace(
        PTRACE_SETOPTIONS,
        tid,
        std::ptr::null_mut(),
        options as usize as *mut c_void,
    )
    .map(|_| ())
}

fn resume_syscall(tid: libc::pid_t, signal: i32) -> Result<(), String> {
    unsafe {
        *libc::__errno_location() = 0;
        let result = libc::ptrace(
            PTRACE_SYSCALL,
            tid,
            std::ptr::null_mut::<c_void>(),
            signal as usize as *mut c_void,
        );
        if result == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(format!(
                "ptrace request {PTRACE_SYSCALL:#x} for {tid} failed: {error}"
            ));
        }
    }
    Ok(())
}

fn terminate(pid: libc::pid_t) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
}

fn ptrace(
    request: libc::c_uint,
    pid: libc::pid_t,
    address: *mut c_void,
    data: *mut c_void,
) -> Result<libc::c_long, String> {
    unsafe {
        *libc::__errno_location() = 0;
        let result = libc::ptrace(request, pid, address, data);
        if result == -1 && *libc::__errno_location() != 0 {
            Err(format!(
                "ptrace request {request:#x} for {pid} failed: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(result)
        }
    }
}

fn read_memory(tid: libc::pid_t, address: usize, length: usize) -> Result<Vec<u8>, String> {
    address
        .checked_add(length)
        .ok_or("remote memory address overflow")?;
    let word = std::mem::size_of::<libc::c_long>();
    let mut output = vec![0u8; length];
    let mut offset = 0usize;
    while offset < length {
        let value = ptrace(
            PTRACE_PEEKDATA,
            tid,
            (address + offset) as *mut c_void,
            std::ptr::null_mut(),
        )? as libc::c_long;
        let bytes = value.to_ne_bytes();
        let count = (length - offset).min(word);
        output[offset..offset + count].copy_from_slice(&bytes[..count]);
        offset += count;
    }
    Ok(output)
}

fn write_memory(tid: libc::pid_t, address: usize, data: &[u8]) -> Result<(), String> {
    address
        .checked_add(data.len())
        .ok_or("remote memory address overflow")?;
    let word = std::mem::size_of::<libc::c_long>();
    let mut offset = 0usize;
    while offset < data.len() {
        let count = (data.len() - offset).min(word);
        let mut bytes = if count == word {
            [0u8; std::mem::size_of::<libc::c_long>()]
        } else {
            ptrace(
                PTRACE_PEEKDATA,
                tid,
                (address + offset) as *mut c_void,
                std::ptr::null_mut(),
            )?
            .to_ne_bytes()
        };
        bytes[..count].copy_from_slice(&data[offset..offset + count]);
        let value = libc::c_long::from_ne_bytes(bytes);
        ptrace(
            PTRACE_POKEDATA,
            tid,
            (address + offset) as *mut c_void,
            value as usize as *mut c_void,
        )?;
        offset += count;
    }
    Ok(())
}

fn parse_sockaddr(bytes: &[u8]) -> Option<TargetAddress> {
    if bytes.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes(bytes[..2].try_into().ok()?);
    match family as i32 {
        libc::AF_INET if bytes.len() >= 16 => Some(TargetAddress {
            ip: IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
            port: u16::from_be_bytes([bytes[2], bytes[3]]),
            hostname: None,
        }),
        libc::AF_INET6 if bytes.len() >= 28 => Some(TargetAddress {
            ip: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
            port: u16::from_be_bytes([bytes[2], bytes[3]]),
            hostname: None,
        }),
        _ => None,
    }
}

fn encode_proxy_sockaddr(
    proxy: SocketAddr,
    target_ip: IpAddr,
    original_length: usize,
) -> Result<Vec<u8>, String> {
    match (target_ip, proxy) {
        (IpAddr::V4(_), SocketAddr::V4(proxy)) if original_length >= 16 => {
            let mut bytes = vec![0u8; 16];
            bytes[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            bytes[2..4].copy_from_slice(&proxy.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&proxy.ip().octets());
            Ok(bytes)
        }
        (IpAddr::V6(_), SocketAddr::V6(proxy)) if original_length >= 28 => {
            let mut bytes = vec![0u8; 28];
            bytes[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            bytes[2..4].copy_from_slice(&proxy.port().to_be_bytes());
            bytes[8..24].copy_from_slice(&proxy.ip().octets());
            bytes[24..28].copy_from_slice(&proxy.scope_id().to_ne_bytes());
            Ok(bytes)
        }
        (IpAddr::V6(_), SocketAddr::V4(proxy)) if original_length >= 28 => {
            let mut bytes = vec![0u8; 28];
            bytes[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            bytes[2..4].copy_from_slice(&proxy.port().to_be_bytes());
            bytes[18] = 0xff;
            bytes[19] = 0xff;
            bytes[20..24].copy_from_slice(&proxy.ip().octets());
            Ok(bytes)
        }
        _ => Err("SOCKS listener address family does not match target socket".into()),
    }
}

fn thread_group(tid: libc::pid_t) -> libc::pid_t {
    let path = format!("/proc/{tid}/status");
    let Ok(status) = std::fs::read_to_string(path) else {
        return tid;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:\t")?.trim().parse().ok())
        .unwrap_or(tid)
}

fn process_parent(pid: libc::pid_t) -> Option<libc::pid_t> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:\t")?.trim().parse().ok())
}

fn remote_syscall(
    tid: libc::pid_t,
    saved: &Registers,
    number: libc::c_long,
    arguments: [u64; 6],
) -> Result<i64, String> {
    let mut call = *saved;
    call.prepare_remote_syscall(number, arguments);
    call.set(tid)?;
    resume_syscall(tid, 0)?;
    expect_syscall_stop(tid, "entry")?;
    resume_syscall(tid, 0)?;
    expect_syscall_stop(tid, "exit")?;
    let result = Registers::get(tid)?.result();
    saved.set(tid)?;
    Ok(result)
}

fn expect_syscall_stop(tid: libc::pid_t, phase: &str) -> Result<(), String> {
    let status = wait_for(tid)?;
    if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == SYSCALL_STOP {
        Ok(())
    } else {
        Err(format!(
            "remote syscall {phase} for {tid} stopped unexpectedly: {status:#x}"
        ))
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Registers {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Registers {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

impl Registers {
    fn get(tid: libc::pid_t) -> Result<Self, String> {
        let mut registers = Self::default();
        let mut io = libc::iovec {
            iov_base: (&mut registers as *mut Self).cast(),
            iov_len: std::mem::size_of::<Self>(),
        };
        ptrace(
            PTRACE_GETREGSET,
            tid,
            NT_PRSTATUS as *mut c_void,
            (&mut io as *mut libc::iovec).cast(),
        )?;
        Ok(registers)
    }

    fn set(&self, tid: libc::pid_t) -> Result<(), String> {
        let mut registers = *self;
        let mut io = libc::iovec {
            iov_base: (&mut registers as *mut Self).cast(),
            iov_len: std::mem::size_of::<Self>(),
        };
        ptrace(
            PTRACE_SETREGSET,
            tid,
            NT_PRSTATUS as *mut c_void,
            (&mut io as *mut libc::iovec).cast(),
        )?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn syscall_number(&self) -> libc::c_long {
        self.orig_rax as libc::c_long
    }

    #[cfg(target_arch = "aarch64")]
    fn syscall_number(&self) -> libc::c_long {
        self.regs[8] as libc::c_long
    }

    #[cfg(target_arch = "x86_64")]
    fn argument(&self, index: usize) -> u64 {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9][index]
    }

    #[cfg(target_arch = "aarch64")]
    fn argument(&self, index: usize) -> u64 {
        self.regs[index]
    }

    #[cfg(target_arch = "x86_64")]
    fn set_argument(&mut self, index: usize, value: u64) {
        match index {
            0 => self.rdi = value,
            1 => self.rsi = value,
            2 => self.rdx = value,
            3 => self.r10 = value,
            4 => self.r8 = value,
            5 => self.r9 = value,
            _ => unreachable!(),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn set_argument(&mut self, index: usize, value: u64) {
        self.regs[index] = value;
    }

    #[cfg(target_arch = "x86_64")]
    fn set_syscall_number(&mut self, number: i64) {
        self.orig_rax = number as u64;
        self.rax = number as u64;
    }

    #[cfg(target_arch = "aarch64")]
    fn set_syscall_number(&mut self, number: i64) {
        self.regs[8] = number as u64;
    }

    #[cfg(target_arch = "x86_64")]
    fn result(&self) -> i64 {
        self.rax as i64
    }

    #[cfg(target_arch = "aarch64")]
    fn result(&self) -> i64 {
        self.regs[0] as i64
    }

    #[cfg(target_arch = "x86_64")]
    fn set_result(&mut self, result: i64) {
        self.rax = result as u64;
    }

    #[cfg(target_arch = "aarch64")]
    fn set_result(&mut self, result: i64) {
        self.regs[0] = result as u64;
    }

    #[cfg(target_arch = "x86_64")]
    fn stack_pointer(&self) -> usize {
        self.rsp as usize
    }

    #[cfg(target_arch = "aarch64")]
    fn stack_pointer(&self) -> usize {
        self.sp as usize
    }

    #[cfg(target_arch = "x86_64")]
    fn prepare_remote_syscall(&mut self, number: libc::c_long, arguments: [u64; 6]) {
        self.rip = self.rip.saturating_sub(2);
        self.rax = number as u64;
        self.orig_rax = number as u64;
        self.rdi = arguments[0];
        self.rsi = arguments[1];
        self.rdx = arguments[2];
        self.r10 = arguments[3];
        self.r8 = arguments[4];
        self.r9 = arguments[5];
    }

    #[cfg(target_arch = "aarch64")]
    fn prepare_remote_syscall(&mut self, number: libc::c_long, arguments: [u64; 6]) {
        self.pc = self.pc.saturating_sub(4);
        self.regs[8] = number as u64;
        self.regs[..6].copy_from_slice(&arguments);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_sockaddr() {
        let bytes = [2, 0, 0x01, 0xbb, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_sockaddr(&bytes).map(|target| (target.ip, target.port)),
            Some((IpAddr::V4(Ipv4Addr::LOCALHOST), 443))
        );
    }

    #[test]
    fn encodes_ipv4_proxy() {
        let proxy = SocketAddr::from(([127, 0, 0, 1], 18444));
        let bytes = encode_proxy_sockaddr(proxy, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 16).unwrap();
        assert_eq!(&bytes[2..4], &18444u16.to_be_bytes());
        assert_eq!(&bytes[4..8], &[127, 0, 0, 1]);
    }

    #[test]
    fn only_inet_stream_sockets_require_blocking_handshakes() {
        for domain in [libc::AF_INET, libc::AF_INET6] {
            assert!(SocketDescriptor {
                id: 1,
                domain,
                socket_type: libc::SOCK_STREAM,
                handshake_complete: false,
            }
            .requires_blocking_handshake());
        }
        assert!(!SocketDescriptor {
            id: 1,
            domain: libc::AF_UNIX,
            socket_type: libc::SOCK_STREAM,
            handshake_complete: false,
        }
        .requires_blocking_handshake());
        assert!(!SocketDescriptor {
            id: 1,
            domain: libc::AF_INET,
            socket_type: libc::SOCK_DGRAM,
            handshake_complete: false,
        }
        .requires_blocking_handshake());
        assert!(!SocketDescriptor {
            id: 1,
            domain: libc::AF_INET,
            socket_type: libc::SOCK_STREAM,
            handshake_complete: true,
        }
        .requires_blocking_handshake());
    }

    #[test]
    fn finds_file_mappings_overlapping_the_requested_range() {
        let maps = concat!(
            "1000-2000 r--p 00000000 00:00 0 /tmp/first\n",
            "2000-3000 rw-p 00000000 00:00 0 [heap]\n",
            "3000-4000 r--p 00000000 00:00 0 /tmp/second (deleted)\n",
        );
        assert_eq!(
            parse_mapped_file_paths(maps, 0x1800, 0x2000),
            vec!["/tmp/first".to_string(), "/tmp/second".to_string()]
        );
    }

    #[test]
    fn parses_dns_query_and_addresses() {
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 9, b'l', b'o',
            b'c', b'a', b'l', b'h', b'o', b's', b't', 0, 0, 1, 0, 1,
        ];
        assert_eq!(parse_dns_query(&query).as_deref(), Some("localhost"));
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
        assert_eq!(
            parse_dns_addresses(&response),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }
}

fn process_birth(pid: libc::pid_t) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
