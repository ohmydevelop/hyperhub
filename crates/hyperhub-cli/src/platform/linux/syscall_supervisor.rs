use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, CString, OsString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

use hyperhub_core::config::{FileSandboxOperation, SandboxAction};
use hyperhub_core::control::control_request;
use hyperhub_core::sandbox::{
    compile_runtime_snapshot, decide_file, decide_process, evaluate_process_prefilter,
    file_error_decision, process_error_decision, process_protection_binding,
    CompiledSandboxSnapshot, ProcessPrefilterContext, SandboxAuditEvent, SandboxAuditKind,
    SandboxDecision,
};
use hyperhub_core::session::{ControlRequest, ControlResponse};

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

#[derive(Clone, Debug)]
struct TargetAddress {
    ip: IpAddr,
    port: u16,
    hostname: Option<String>,
}

struct FileIntent {
    targets: Vec<String>,
    operation: FileSandboxOperation,
    operation_name: &'static str,
}

struct ProcessIntent {
    executable: String,
    argv: Vec<String>,
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
    Dup {
        old_fd: i32,
    },
    Socket {
        socket_type: i32,
        logical_nonblocking: bool,
    },
    UdpConnect {
        fd: i32,
        target: TargetAddress,
    },
    DnsReceive {
        fd: i32,
        buffers: Vec<(usize, usize)>,
    },
    FcntlSetfl {
        fd: i32,
        logical_nonblocking: bool,
    },
    IoctlNonblocking {
        fd: i32,
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
}

impl Default for ThreadState {
    fn default() -> Self {
        Self {
            entering: true,
            pending: None,
        }
    }
}

struct Supervisor {
    root_pid: libc::pid_t,
    proxy: SocketAddr,
    endpoint: String,
    session_id: String,
    password: Vec<u8>,
    next_connection_id: u64,
    control: tokio::runtime::Runtime,
    sandbox: Option<CompiledSandboxSnapshot>,
    next_sandbox_refresh: Instant,
    last_sandbox_refresh_error: Option<String>,
    hook_counts: HashMap<&'static str, u64>,
    hook_report: Option<std::path::PathBuf>,
    require_all_hooks: bool,
    enforce: bool,
    threads: HashMap<libc::pid_t, ThreadState>,
    parents: HashMap<libc::pid_t, libc::pid_t>,
    members: HashSet<libc::pid_t>,
    nonblocking: HashMap<(libc::pid_t, i32), bool>,
    socket_types: HashMap<(libc::pid_t, i32), i32>,
    udp_peers: HashMap<(libc::pid_t, i32), TargetAddress>,
    dns_queries: HashMap<(libc::pid_t, i32), String>,
    dns_addresses: HashMap<IpAddr, String>,
    dns_ports: HashSet<u16>,
    root_status: Option<i32>,
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

    let control = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|error| format!("cannot start static supervisor control runtime: {error}"))?;
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
        root_pid: child,
        proxy,
        endpoint,
        session_id,
        password,
        next_connection_id: 1,
        control,
        sandbox,
        next_sandbox_refresh: Instant::now() + SANDBOX_REFRESH_INTERVAL,
        last_sandbox_refresh_error: None,
        hook_counts: HashMap::new(),
        hook_report,
        require_all_hooks,
        enforce,
        threads: HashMap::from([(child, ThreadState::default())]),
        parents: HashMap::new(),
        members: HashSet::from([child]),
        nonblocking: HashMap::new(),
        socket_types: HashMap::new(),
        udp_peers: HashMap::new(),
        dns_queries: HashMap::new(),
        dns_addresses: HashMap::new(),
        dns_ports,
        root_status: None,
    };
    resume_syscall(child, 0).inspect_err(|_| terminate(child))?;
    let result = supervisor.event_loop();
    if result.is_err() {
        supervisor.terminate_all();
        return result;
    }
    supervisor.write_hook_report()?;
    result
}

impl Supervisor {
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
                self.threads.remove(&tid);
                continue;
            }
            if libc::WIFSIGNALED(status) {
                if tid == self.root_pid {
                    self.root_status = Some(128 + libc::WTERMSIG(status));
                }
                self.threads.remove(&tid);
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
            self.threads.entry(tid).or_default();
            let deliver = if signal == libc::SIGSTOP || signal == libc::SIGTRAP {
                0
            } else {
                signal
            };
            resume_syscall(tid, deliver)?;
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
                    if child_group != parent_group {
                        self.parents.entry(child_group).or_insert(parent_group);
                    }
                }
            }
            PTRACE_EVENT_EXEC => {
                self.threads.entry(tid).or_default().pending = None;
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
                    let compiled = compile_runtime_snapshot(snapshot)
                        .map_err(|error| format!("cannot compile refreshed sandbox: {error}"))?;
                    self.sandbox = Some(compiled);
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
            let pending = self.syscall_enter(tid, &mut registers)?;
            if pending.is_some() {
                registers.set(tid)?;
            }
            let state = self.threads.entry(tid).or_default();
            state.pending = pending;
            state.entering = false;
        } else {
            let pending = self.threads.entry(tid).or_default().pending.take();
            let modified = pending.is_some();
            self.syscall_exit(tid, &mut registers, pending)?;
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
    ) -> Result<Option<PendingSyscall>, String> {
        let number = registers.syscall_number();
        self.record_hooks(number);
        if let Some(pending) = self.intent_enter(tid, number, registers)? {
            return Ok(Some(pending));
        }
        if let Some(pending) = self.dns_enter(tid, number, registers)? {
            return Ok(Some(pending));
        }
        if number == syscall::SOCKET {
            let socket_type = registers.argument(1) as i32;
            let logical_nonblocking = socket_type & libc::SOCK_NONBLOCK != 0;
            if logical_nonblocking {
                registers.set_argument(1, (socket_type & !libc::SOCK_NONBLOCK) as u64);
            }
            return Ok(Some(PendingSyscall::Socket {
                socket_type: socket_type & 0xf,
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
            if command == libc::F_SETFL {
                let logical_nonblocking = flags & libc::O_NONBLOCK != 0;
                if logical_nonblocking {
                    registers.set_argument(2, (flags & !libc::O_NONBLOCK) as u64);
                }
                return Ok(Some(PendingSyscall::FcntlSetfl {
                    fd,
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
                let value = read_memory(tid, value_address, 4)?;
                let original: [u8; 4] = value.try_into().unwrap();
                let logical_nonblocking = i32::from_ne_bytes(original) != 0;
                if logical_nonblocking {
                    write_memory(tid, value_address, &0i32.to_ne_bytes())?;
                }
                return Ok(Some(PendingSyscall::IoctlNonblocking {
                    fd,
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
        let process_pid = thread_group(tid);
        let socket_type = self.socket_types.get(&(process_pid, fd)).copied();
        if socket_type == Some(libc::SOCK_DGRAM) {
            return Ok(Some(PendingSyscall::UdpConnect { fd, target }));
        }
        if socket_type.is_some_and(|kind| kind != libc::SOCK_STREAM) {
            return Ok(None);
        }
        target.hostname = self.dns_addresses.get(&target.ip).cloned();
        if SocketAddr::new(target.ip, target.port) == self.proxy {
            return Ok(None);
        }
        let proxy = encode_proxy_sockaddr(self.proxy, target.ip, original.len())?;
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
    ) -> Result<(), String> {
        match pending {
            Some(PendingSyscall::OverrideResult { result }) => {
                registers.set_result(result);
            }
            Some(PendingSyscall::Close { fd }) => {
                if registers.result() >= 0 {
                    let key = (thread_group(tid), fd);
                    self.nonblocking.remove(&key);
                    self.socket_types.remove(&key);
                    self.udp_peers.remove(&key);
                    self.dns_queries.remove(&key);
                }
            }
            Some(PendingSyscall::Dup { old_fd }) => {
                let new_fd = registers.result();
                if new_fd >= 0 && self.nonblocking.contains_key(&(thread_group(tid), old_fd)) {
                    self.nonblocking
                        .insert((thread_group(tid), new_fd as i32), true);
                }
            }
            Some(PendingSyscall::Socket {
                socket_type,
                logical_nonblocking,
            }) => {
                let fd = registers.result();
                if fd >= 0 {
                    let key = (thread_group(tid), fd as i32);
                    self.socket_types.insert(key, socket_type);
                    if logical_nonblocking {
                        self.nonblocking.insert(key, true);
                    }
                }
            }
            Some(PendingSyscall::UdpConnect { fd, target }) => {
                if registers.result() >= 0 {
                    self.udp_peers.insert((thread_group(tid), fd), target);
                }
            }
            Some(PendingSyscall::FcntlSetfl {
                fd,
                logical_nonblocking,
            }) => {
                if registers.result() >= 0 {
                    let key = (thread_group(tid), fd);
                    if logical_nonblocking {
                        self.nonblocking.insert(key, true);
                    } else {
                        self.nonblocking.remove(&key);
                    }
                }
            }
            Some(PendingSyscall::IoctlNonblocking {
                fd,
                value_address,
                original,
                logical_nonblocking,
            }) => {
                write_memory(tid, value_address, &original)?;
                if registers.result() >= 0 {
                    let key = (thread_group(tid), fd);
                    if logical_nonblocking {
                        self.nonblocking.insert(key, true);
                    } else {
                        self.nonblocking.remove(&key);
                    }
                }
            }
            Some(PendingSyscall::DnsReceive { fd, buffers }) => {
                let length = registers.result();
                if length > 0 {
                    let response = read_buffers(tid, &buffers, length as usize)?;
                    if let Some(hostname) = self.dns_queries.get(&(thread_group(tid), fd)).cloned()
                    {
                        for address in parse_dns_addresses(&response) {
                            self.dns_addresses.insert(address, hostname.clone());
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
                    let handshake = self.socks_handshake(tid, registers, fd, target);
                    if let Err(error) = handshake {
                        if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
                            eprintln!("hyperhub: static SOCKS handshake failed: {error}");
                        }
                        registers.set_result(-(libc::EACCES as i64));
                    } else {
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
        let process_pid = thread_group(tid);
        let fd = registers.argument(0) as i32;
        let key = (process_pid, fd);
        if self.socket_types.get(&key).copied() != Some(libc::SOCK_DGRAM) {
            return Ok(None);
        }

        let (payload, target, hook_name) = if number == syscall::SENDTO {
            let length = (registers.argument(2) as usize).min(4096);
            let payload = read_memory(tid, registers.argument(1) as usize, length)?;
            let target = if registers.argument(4) != 0 {
                let address_length = (registers.argument(5) as usize).min(128);
                parse_sockaddr(&read_memory(
                    tid,
                    registers.argument(4) as usize,
                    address_length,
                )?)
            } else {
                self.udp_peers.get(&key).cloned()
            };
            (Some(payload), target, Some("dns.sendto"))
        } else if number == syscall::SENDMSG {
            let message = read_msghdr(tid, registers.argument(1) as usize)?;
            let target = message
                .name
                .as_ref()
                .and_then(|bytes| parse_sockaddr(bytes))
                .or_else(|| self.udp_peers.get(&key).cloned());
            (
                Some(read_buffers(tid, &message.buffers, 4096)?),
                target,
                Some("dns.sendmsg"),
            )
        } else if number == syscall::WRITE {
            let length = (registers.argument(2) as usize).min(4096);
            (
                Some(read_memory(tid, registers.argument(1) as usize, length)?),
                self.udp_peers.get(&key).cloned(),
                Some("dns.write"),
            )
        } else {
            (None, None, None)
        };
        if let (Some(payload), Some(target), Some(hook_name)) = (payload, target, hook_name) {
            if self.dns_ports.contains(&target.port) {
                if let Some(hostname) = parse_dns_query(&payload) {
                    self.dns_queries.insert(key, hostname);
                    self.record_named_hook(hook_name);
                }
            }
            return Ok(None);
        }

        if !self.dns_queries.contains_key(&key) {
            return Ok(None);
        }
        if number == syscall::RECVFROM {
            self.record_named_hook("dns.recvfrom");
            return Ok(Some(PendingSyscall::DnsReceive {
                fd,
                buffers: vec![(
                    registers.argument(1) as usize,
                    registers.argument(2) as usize,
                )],
            }));
        }
        if number == syscall::RECVMSG {
            let message = read_msghdr(tid, registers.argument(1) as usize)?;
            self.record_named_hook("dns.recvmsg");
            return Ok(Some(PendingSyscall::DnsReceive {
                fd,
                buffers: message.buffers,
            }));
        }
        if number == syscall::READ {
            self.record_named_hook("dns.read");
            return Ok(Some(PendingSyscall::DnsReceive {
                fd,
                buffers: vec![(
                    registers.argument(1) as usize,
                    registers.argument(2) as usize,
                )],
            }));
        }
        Ok(None)
    }

    fn intent_enter(
        &mut self,
        tid: libc::pid_t,
        number: i64,
        registers: &mut Registers,
    ) -> Result<Option<PendingSyscall>, String> {
        if number == syscall::CLOSE {
            return Ok(Some(PendingSyscall::Close {
                fd: registers.argument(0) as i32,
            }));
        }
        if is_one_of(number, &[syscall::DUP, syscall::DUP2, syscall::DUP3]) {
            return Ok(Some(PendingSyscall::Dup {
                old_fd: registers.argument(0) as i32,
            }));
        }

        match self.file_intent(tid, number, registers) {
            Ok(Some(intent)) if self.file_denied(tid, &intent)? => {
                return Ok(Some(deny_syscall(registers, libc::EACCES)));
            }
            Err(error) if self.file_error_denied(tid, &error) => {
                return Ok(Some(deny_syscall(registers, libc::EACCES)));
            }
            _ => {}
        }

        match self.process_intent(tid, number, registers) {
            Ok(Some(intent)) if self.process_denied(tid, &intent)? => {
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
            return Ok(Some(file_intent(path, file_operation(flags), "open")));
        }
        if number == syscall::CREAT && syscall::CREAT >= 0 {
            let path = read_path(tid, libc::AT_FDCWD, registers.argument(0) as usize)?;
            return Ok(Some(file_intent(
                path,
                FileSandboxOperation::Create,
                "open",
            )));
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
            return Ok(Some(file_intent(path, file_operation(flags), "open")));
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
                operation: FileSandboxOperation::Rename,
                operation_name: "rename",
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
                operation: FileSandboxOperation::Rename,
                operation_name: "rename",
            }));
        }
        if number == syscall::MMAP {
            let protection = registers.argument(2) as i32;
            let fd = registers.argument(4) as i32;
            if fd >= 0 && protection & libc::PROT_WRITE != 0 {
                if let Some(path) = fd_path(tid, fd) {
                    return Ok(Some(file_intent(path, FileSandboxOperation::Write, "map")));
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

    fn file_denied(&mut self, tid: libc::pid_t, intent: &FileIntent) -> Result<bool, String> {
        let Some(snapshot) = self
            .sandbox
            .as_ref()
            .and_then(|snapshot| snapshot.file.as_ref())
        else {
            return Ok(false);
        };
        let denied = intent.targets.iter().find_map(|target| {
            let decision = decide_file(snapshot, target, intent.operation);
            (decision.action == SandboxAction::Deny).then(|| (target.clone(), decision))
        });
        let Some((target, decision)) = denied else {
            return Ok(false);
        };
        self.report_sandbox(
            tid,
            SandboxAuditKind::File,
            intent.operation_name,
            &target,
            &decision,
        );
        Ok(self.enforce)
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
        );
        self.enforce
    }

    fn process_denied(&mut self, tid: libc::pid_t, intent: &ProcessIntent) -> Result<bool, String> {
        let Some(snapshot) = self
            .sandbox
            .as_ref()
            .and_then(|snapshot| snapshot.process.as_ref())
        else {
            return Ok(false);
        };
        let command_line = intent.command_line();
        let decision = decide_process(snapshot, &intent.executable, &command_line);
        if decision.action == SandboxAction::Deny {
            self.report_sandbox(
                tid,
                SandboxAuditKind::Process,
                "create",
                &intent.executable,
                &decision,
            );
            return Ok(self.enforce);
        }
        let Some(binding) = process_protection_binding(snapshot, &intent.executable, &command_line)
        else {
            return Ok(false);
        };
        let context = ProcessPrefilterContext::default();
        let prefilter = evaluate_process_prefilter(
            binding.prefilter_policy,
            &intent.executable,
            &intent.argv,
            &context,
        );
        if prefilter.hard_deny {
            let decision = SandboxDecision {
                action: SandboxAction::Deny,
                rule_id: Some(binding.rule_id),
                source: "prefilter_hard_deny",
            };
            self.report_sandbox(
                tid,
                SandboxAuditKind::Process,
                "create",
                &intent.executable,
                &decision,
            );
            return Ok(self.enforce);
        }
        if !prefilter.should_query_gateway {
            return Ok(false);
        }
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
                argv: prefilter.redacted_argv,
                features: prefilter.features,
                context: serde_json::to_value(&context)
                    .map_err(|error| format!("cannot encode smart protection context: {error}"))?,
            },
        ));
        match response {
            Ok(ControlResponse::SmartProtectionDecision { action, .. }) => {
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
        let event = SandboxAuditEvent {
            kind,
            decision: decision.action,
            rule_id: decision.rule_id.clone(),
            source: decision.source.into(),
            operation: operation.into(),
            target: target.into(),
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
    ) -> Result<(), String> {
        let saved = *registers;
        let scratch = saved.stack_pointer().saturating_sub(SCRATCH_SIZE) & !15usize;
        let original = read_memory(tid, scratch, SCRATCH_SIZE)?;
        let result = (|| {
            self.remote_send_all(tid, &saved, fd, scratch, &[5, 1, 2])?;
            let greeting = self.remote_recv_exact(tid, &saved, fd, scratch, 2)?;
            if greeting != [5, 2] {
                return Err(format!("SOCKS method negotiation returned {greeting:?}"));
            }

            let process_pid = self.ensure_member(tid)?;
            let connection_id = self.next_connection_id;
            self.next_connection_id = self.next_connection_id.saturating_add(1);
            let username = format!("hh2:{}:{}:{}", self.session_id, process_pid, connection_id);
            if username.len() > u8::MAX as usize {
                return Err("HyperHub SOCKS username exceeds RFC 1929 limits".into());
            }
            let mut authentication = Vec::with_capacity(username.len() + self.password.len() + 3);
            authentication.extend_from_slice(&[1, username.len() as u8]);
            authentication.extend_from_slice(username.as_bytes());
            authentication.push(self.password.len() as u8);
            authentication.extend_from_slice(&self.password);
            self.remote_send_all(tid, &saved, fd, scratch, &authentication)?;
            let authentication_reply = self.remote_recv_exact(tid, &saved, fd, scratch, 2)?;
            if authentication_reply != [1, 0] {
                return Err(format!(
                    "SOCKS authentication returned {authentication_reply:?}"
                ));
            }

            let mut request = vec![5, 1, 0];
            if let Some(hostname) = target.hostname.as_deref() {
                if hostname.len() > u8::MAX as usize {
                    return Err("SOCKS target hostname exceeds 255 bytes".into());
                }
                request.push(3);
                request.push(hostname.len() as u8);
                request.extend_from_slice(hostname.as_bytes());
            } else {
                match target.ip {
                    IpAddr::V4(address) => {
                        request.push(1);
                        request.extend_from_slice(&address.octets());
                    }
                    IpAddr::V6(address) => {
                        request.push(4);
                        request.extend_from_slice(&address.octets());
                    }
                }
            }
            request.extend_from_slice(&target.port.to_be_bytes());
            self.remote_send_all(tid, &saved, fd, scratch, &request)?;
            let reply = self.remote_recv_exact(tid, &saved, fd, scratch, 4)?;
            if reply[0] != 5 || reply[1] != 0 {
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

            if self
                .nonblocking
                .remove(&(thread_group(tid), fd))
                .unwrap_or(false)
            {
                let flags = remote_syscall(
                    tid,
                    &saved,
                    libc::SYS_fcntl,
                    [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
                )?;
                if flags >= 0 {
                    let _ = remote_syscall(
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
                }
            }
            Ok(())
        })();
        let restore = write_memory(tid, scratch, &original);
        result.and(restore)
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
            let executable = std::fs::read_link(format!("/proc/{child}/exe"))
                .map_err(|error| format!("cannot resolve static child {child}: {error}"))?
                .to_string_lossy()
                .into_owned();
            let response = self
                .control
                .block_on(control_request(
                    &self.endpoint,
                    &ControlRequest::RegisterChild {
                        session_id: self.session_id.clone(),
                        token: String::from_utf8_lossy(&self.password).into_owned(),
                        parent_pid: parent as u32,
                        child_pid: child as u32,
                        executable,
                        process_policy_version: 0,
                        process_rule_id: None,
                        process_decision_source: "static-supervisor".into(),
                    },
                ))
                .map_err(|error| format!("cannot register static child {child}: {error}"))?;
            if !matches!(response, ControlResponse::Ok) {
                return Err(format!("serve rejected static child {child}"));
            }
            self.members.insert(child);
        }
        Ok(process_pid)
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
    let iov_count = (u64::from_ne_bytes(header[24..32].try_into().unwrap()) as usize).min(64);
    let name = if name_address != 0 && name_length != 0 {
        Some(read_memory(tid, name_address, name_length.min(128))?)
    } else {
        None
    };
    let mut buffers = Vec::with_capacity(iov_count);
    for index in 0..iov_count {
        let iovec = read_memory(tid, iov_address + index * 16, 16)?;
        let base = u64::from_ne_bytes(iovec[0..8].try_into().unwrap()) as usize;
        let length = u64::from_ne_bytes(iovec[8..16].try_into().unwrap()) as usize;
        if base != 0 && length != 0 {
            buffers.push((base, length));
        }
    }
    Ok(RemoteMessage { name, buffers })
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

fn parse_dns_query(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 || packet[2] & 0x80 != 0 || u16::from_be_bytes([packet[4], packet[5]]) == 0
    {
        return None;
    }
    let (hostname, _) = parse_dns_name(packet, 12)?;
    (!hostname.is_empty()).then_some(hostname)
}

fn parse_dns_addresses(packet: &[u8]) -> Vec<IpAddr> {
    if packet.len() < 12 || packet[2] & 0x80 == 0 {
        return Vec::new();
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..questions {
        let Some((_, next)) = parse_dns_name(packet, offset) else {
            return Vec::new();
        };
        offset = next.saturating_add(4);
        if offset > packet.len() {
            return Vec::new();
        }
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        let Some((_, next)) = parse_dns_name(packet, offset) else {
            break;
        };
        if next + 10 > packet.len() {
            break;
        }
        let record_type = u16::from_be_bytes([packet[next], packet[next + 1]]);
        let data_length = u16::from_be_bytes([packet[next + 8], packet[next + 9]]) as usize;
        let data = next + 10;
        if data + data_length > packet.len() {
            break;
        }
        match (record_type, data_length) {
            (1, 4) => addresses.push(IpAddr::V4(Ipv4Addr::new(
                packet[data],
                packet[data + 1],
                packet[data + 2],
                packet[data + 3],
            ))),
            (28, 16) => {
                if let Ok(bytes) = <[u8; 16]>::try_from(&packet[data..data + 16]) {
                    addresses.push(IpAddr::V6(Ipv6Addr::from(bytes)));
                }
            }
            _ => {}
        }
        offset = data + data_length;
    }
    addresses
}

fn parse_dns_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;
    loop {
        let length = *packet.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let second = *packet.get(offset + 1)?;
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        offset += 1;
        if length == 0 {
            return Some((labels.join("."), next.unwrap_or(offset)));
        }
        if length > 63 {
            return None;
        }
        let end = offset.checked_add(length as usize)?;
        let label = std::str::from_utf8(packet.get(offset..end)?).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }
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
        operation,
        operation_name,
    }
}

fn file_operation(flags: i32) -> FileSandboxOperation {
    if flags & libc::O_CREAT != 0 {
        FileSandboxOperation::Create
    } else if flags & libc::O_ACCMODE == libc::O_RDONLY {
        FileSandboxOperation::Read
    } else {
        FileSandboxOperation::Write
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

fn read_path(tid: libc::pid_t, dirfd: i32, address: usize) -> Result<String, String> {
    let raw = read_c_string(tid, address, 4096)?;
    resolve_path(tid, dirfd, &raw)
}

fn resolve_path(tid: libc::pid_t, dirfd: i32, raw: &str) -> Result<String, String> {
    let path = std::path::Path::new(raw);
    if path.is_absolute() {
        return Ok(normalize_path(path));
    }
    let process_pid = thread_group(tid);
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
    let process_pid = thread_group(tid);
    let path = std::fs::read_link(format!("/proc/{process_pid}/fd/{fd}")).ok()?;
    path.is_absolute().then(|| normalize_path(&path))
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
