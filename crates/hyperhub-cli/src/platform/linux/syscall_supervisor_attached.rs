//! Non-owning tracing of an already running process. Unlike `run`, errors here
//! never grant ownership of the target and never install PTRACE_O_EXITKILL.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc};

const SEIZE: libc::c_uint = 0x4206;
const INTERRUPT: libc::c_uint = 0x4207;
const LISTEN: libc::c_uint = 0x4208;
const DETACH: libc::c_uint = 17;
const GET_SYSCALL_INFO: libc::c_uint = 0x420e;
pub(super) const EVENT_STOP: u32 = 128;

pub(crate) struct Configuration {
    pub root_pid: u32,
    pub tree: bool,
    pub environment: Vec<(OsString, OsString)>,
    pub sandbox: Option<hyperhub_core::sandbox::SandboxSnapshot>,
    pub detach: Arc<AtomicBool>,
    pub events: Sender<Event>,
    pub initial_members: Vec<hyperhub_core::attachments::ProcessIdentity>,
    pub execution: Option<hyperhub_core::attachments::Execution>,
    pub authorization: Arc<std::sync::Mutex<hyperhub_core::attachments::Authorization>>,
}

#[derive(Debug)]
pub(crate) enum Event {
    Active(Vec<u32>),
    CleanupPending(String),
    Draining { sockets: usize },
    Detached,
    Exited,
    Degraded(String),
}

pub(super) struct State {
    pub(super) recovery: Option<hyperhub_core::attachments::Execution>,
    authorization: Arc<std::sync::Mutex<hyperhub_core::attachments::Authorization>>,
    pub(super) current_root: Option<hyperhub_core::attachments::ProcessIdentity>,
    pub(super) manager_identity: Option<hyperhub_core::attachments::ProcessIdentity>,
    recovery_safe: bool,
    detach_prepared: bool,
    detach_finished: bool,
    tree: bool,
    pub(super) detaching: bool,
    detach: Arc<AtomicBool>,
    pub(super) events: Sender<Event>,
    pub(super) unscoped_children: HashSet<libc::pid_t>,
    last_sockets: Option<usize>,
    pub(super) stopped: HashMap<libc::pid_t, i32>,
    pub(super) new_children: HashSet<libc::pid_t>,
}

struct InheritedSocket {
    pid: libc::pid_t,
    fd: i32,
    inode: u64,
    domain: i32,
    socket_type: i32,
    nonblocking: bool,
    connected: bool,
    peer: Option<TargetAddress>,
}
fn socket_option(fd: i32, name: i32) -> Result<i32, String> {
    let mut value = 0i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<i32>()
    {
        return Err(format!(
            "cannot inspect an inherited socket option: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(value)
}
fn snapshot_socket_descriptors(
    tids: &HashSet<libc::pid_t>,
) -> Result<Vec<InheritedSocket>, String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let groups = tids
        .iter()
        .map(|tid| thread_group(*tid))
        .collect::<HashSet<_>>();
    let mut sockets = Vec::new();
    for pid in groups {
        let handle = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if handle < 0 {
            return Err(format!(
                "cannot pin existing process descriptor table: {}",
                std::io::Error::last_os_error()
            ));
        }
        let handle = unsafe { OwnedFd::from_raw_fd(handle) };
        for entry in
            std::fs::read_dir(format!("/proc/{pid}/fd")).map_err(|error| error.to_string())?
        {
            let entry = entry.map_err(|error| error.to_string())?;
            let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            let link = std::fs::read_link(entry.path()).map_err(|error| error.to_string())?;
            let link = link.to_string_lossy();
            let Some(inode) = link
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            // Duplicating the open description is read-only inspection. No
            // target fd/flags/environment are changed before approval commits.
            let duplicate =
                unsafe { libc::syscall(libc::SYS_pidfd_getfd, handle.as_raw_fd(), fd, 0) } as i32;
            if duplicate < 0 {
                return Err(format!(
                    "kernel cannot inspect an existing socket safely: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
            let domain = socket_option(duplicate.as_raw_fd(), libc::SO_DOMAIN)?;
            let socket_type = socket_option(duplicate.as_raw_fd(), libc::SO_TYPE)?;
            let flags = unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(format!(
                    "cannot inspect inherited socket flags: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
            let connected = unsafe {
                libc::getpeername(
                    duplicate.as_raw_fd(),
                    (&mut peer as *mut libc::sockaddr_storage).cast(),
                    &mut size,
                )
            } == 0;
            let peer = if connected && socket_type == libc::SOCK_DGRAM {
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        (&peer as *const libc::sockaddr_storage).cast::<u8>(),
                        (size as usize).min(std::mem::size_of_val(&peer)),
                    )
                };
                parse_sockaddr(bytes)
            } else {
                None
            };
            let listening = socket_option(duplicate.as_raw_fd(), libc::SO_ACCEPTCONN)? != 0;
            sockets.push(InheritedSocket {
                pid,
                fd,
                inode,
                domain,
                socket_type,
                nonblocking: flags & libc::O_NONBLOCK != 0,
                connected: connected || listening,
                peer,
            });
        }
    }
    Ok(sockets)
}

fn options(tree: bool) -> libc::c_ulong {
    PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC
        | PTRACE_O_TRACEEXIT
        | if tree {
            PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
        } else {
            0
        }
}

pub(super) fn listen(tid: libc::pid_t) -> Result<(), String> {
    ptrace(LISTEN, tid, std::ptr::null_mut(), std::ptr::null_mut()).map(|_| ())
}

pub(super) fn syscall_is_entry(tid: libc::pid_t) -> Result<bool, String> {
    // PTRACE_SEIZE can first report the exit of a syscall that started before
    // attachment. Never infer its direction by alternating from an assumed entry.
    let mut information = [0u64; 16];
    let count = ptrace(
        GET_SYSCALL_INFO,
        tid,
        (std::mem::size_of_val(&information)) as *mut c_void,
        information.as_mut_ptr().cast(),
    )?;
    if count < 1 {
        return Err("kernel returned no syscall direction".into());
    }
    match information[0] as u8 {
        1 | 3 => Ok(true),
        2 => Ok(false),
        _ => Err("kernel did not identify an attached syscall stop".into()),
    }
}

fn tracer_pid(tid: libc::pid_t) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{tid}/status"))
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("TracerPid:")
                .and_then(|value| value.trim().parse().ok())
        })
}

fn thread_ids(pid: libc::pid_t) -> Result<Vec<libc::pid_t>, String> {
    let entries = std::fs::read_dir(format!("/proc/{pid}/task")).map_err(|e| e.to_string())?;
    let mut tids = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<libc::pid_t>().ok())
        .collect::<Vec<_>>();
    tids.sort_unstable();
    Ok(tids)
}

pub(crate) fn process_tree(root: u32, tree: bool) -> Result<Vec<u32>, String> {
    if process_birth(root as i32).is_none() {
        return Err("attachment target exited".into());
    }
    let mut pids = HashSet::from([root]);
    if tree {
        let all = std::fs::read_dir("/proc")
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .filter_map(|pid| process_parent(pid as i32).map(|parent| (pid, parent as u32)))
            .collect::<Vec<_>>();
        loop {
            let before = pids.len();
            for &(pid, parent) in &all {
                if pids.contains(&parent) {
                    pids.insert(pid);
                }
            }
            if before == pids.len() {
                break;
            }
        }
    }
    let mut pids = pids.into_iter().collect::<Vec<_>>();
    pids.sort_unstable();
    Ok(pids)
}

/// Tracks each seized thread until it is handed to the event loop. A rejected
/// attachment detaches the threads it actually acquired, never SIGKILLs them.
struct Seized {
    tids: HashSet<libc::pid_t>,
    stopped: HashMap<libc::pid_t, i32>,
    armed: bool,
    synthetic_children: HashSet<libc::pid_t>,
}
impl Seized {
    fn new() -> Self {
        Self {
            tids: HashSet::new(),
            stopped: HashMap::new(),
            armed: true,
            synthetic_children: HashSet::new(),
        }
    }
    fn acquire(&mut self, tid: libc::pid_t, tree: bool) -> Result<(), String> {
        if self.tids.contains(&tid) {
            return Ok(());
        }
        match ptrace(
            SEIZE,
            tid,
            std::ptr::null_mut(),
            options(tree) as usize as *mut c_void,
        ) {
            Ok(_) => {
                self.tids.insert(tid);
                Ok(())
            }
            Err(_)
                if std::fs::read_to_string(format!("/proc/{tid}/status"))
                    .ok()
                    .and_then(|s| {
                        s.lines().find_map(|line| {
                            line.strip_prefix("TracerPid:")
                                .and_then(|v| v.trim().parse::<u32>().ok())
                        })
                    })
                    == Some(std::process::id()) =>
            {
                self.tids.insert(tid);
                Ok(())
            }
            Err(error) if process_birth(thread_group(tid)).is_none() => {
                let _ = error;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    fn interrupt(&self) -> Result<(), String> {
        for &tid in &self.tids {
            if !self.stopped.contains_key(&tid) {
                if let Err(error) =
                    ptrace(INTERRUPT, tid, std::ptr::null_mut(), std::ptr::null_mut())
                {
                    if tracer_pid(tid) == Some(std::process::id()) {
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }
    fn wait_stopped(&mut self, deadline: Instant) -> Result<(), String> {
        while self.stopped.len() < self.tids.len() {
            if Instant::now() >= deadline {
                return Err("timed out quiescing attachment threads".into());
            }
            let mut progress = false;
            for tid in self.tids.iter().copied().collect::<Vec<_>>() {
                if self.stopped.contains_key(&tid) {
                    continue;
                }
                let mut status = 0;
                let result =
                    unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
                if result == tid {
                    progress = true;
                    if libc::WIFSTOPPED(status) {
                        self.stopped.insert(tid, status);
                        if matches!(
                            (status as u32) >> 16,
                            PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE
                        ) {
                            let mut child = 0usize;
                            ptrace(
                                PTRACE_GETEVENTMSG,
                                tid,
                                std::ptr::null_mut(),
                                (&mut child as *mut usize).cast(),
                            )?;
                            if child != 0 {
                                self.tids.insert(child as i32);
                                self.synthetic_children.insert(child as i32);
                            }
                        }
                    } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        self.tids.remove(&tid);
                    }
                } else if result < 0 {
                    let error = std::io::Error::last_os_error();
                    if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ECHILD)) {
                        self.tids.remove(&tid);
                    } else if error.raw_os_error() != Some(libc::EINTR) {
                        return Err(error.to_string());
                    }
                }
            }
            if !progress {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
}
impl Drop for Seized {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.interrupt();
        let _ = self.wait_stopped(Instant::now() + Duration::from_secs(2));
        for (&tid, &status) in &self.stopped {
            let signal = libc::WSTOPSIG(status);
            let event = (status as u32) >> 16;
            let deliver = if signal == SYSCALL_STOP
                || (event != 0
                    && (event != EVENT_STOP
                        || signal == libc::SIGTRAP
                        || self.synthetic_children.contains(&tid)))
            {
                0
            } else {
                signal
            };
            let _ = ptrace(
                DETACH,
                tid,
                std::ptr::null_mut(),
                deliver as usize as *mut c_void,
            );
        }
    }
}

pub(crate) fn run<F>(configuration: Configuration, activate: F) -> Result<(), String>
where
    F: FnOnce(u32, &std::ffi::OsStr) -> Result<bool, String>,
{
    let root = configuration.root_pid as libc::pid_t;
    let recovering = !configuration.initial_members.is_empty();
    let root_birth = process_birth(root);
    if root_birth.is_none() && !recovering {
        return Err("attachment target exited".into());
    }
    let anchors = if recovering {
        configuration
            .initial_members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>()
    } else {
        vec![configuration.root_pid]
    };
    for member in &configuration.initial_members {
        if super::super::attachment::inspect_attachment_target(member.pid)? != *member {
            return Err("approved recovery member changed identity".into());
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut acquired = Seized::new();
    // Install fork/clone tracing before enumerating a second time. Once all
    // original members are stopped, the fixed-point snapshot cannot lose a
    // concurrently created thread or descendant.
    loop {
        let before = acquired.tids.len();
        for anchor in &anchors {
            for pid in process_tree(*anchor, configuration.tree)? {
                for tid in thread_ids(pid as i32)? {
                    acquired.acquire(tid, configuration.tree)?;
                }
            }
        }
        acquired.interrupt()?;
        acquired.wait_stopped(deadline)?;
        if acquired.tids.len() == before {
            break;
        }
    }
    if !configuration.tree {
        for tid in acquired.tids.iter().copied().collect::<Vec<_>>() {
            if thread_group(tid) != root {
                ptrace(DETACH, tid, std::ptr::null_mut(), std::ptr::null_mut())?;
                acquired.tids.remove(&tid);
                acquired.stopped.remove(&tid);
                acquired.synthetic_children.remove(&tid);
            }
        }
    }
    if process_birth(root) != root_birth {
        return Err("attachment target identity changed".into());
    }
    let inherited = snapshot_socket_descriptors(&acquired.tids)?;
    let executable = std::fs::read_link(format!(
        "/proc/{}/exe",
        if root_birth.is_some() {
            root as u32
        } else {
            anchors[0]
        }
    ))
    .map_err(|e| e.to_string())?;
    if !activate(configuration.root_pid, executable.as_os_str())? {
        return Err("Serve rejected attachment activation".into());
    }
    let env = &configuration.environment;
    let endpoint = environment_value(env, "HYPERHUB_CONTROL_ENDPOINT")
        .ok_or("missing attachment control endpoint")?;
    let session_id =
        environment_value(env, "HYPERHUB_SESSION_ID").ok_or("missing attachment session id")?;
    let token =
        environment_value(env, "HYPERHUB_SESSION_TOKEN").ok_or("missing attachment token")?;
    let proxy = environment_value(env, "HYPERHUB_SOCKS_ADDR")
        .ok_or("missing attachment proxy")?
        .parse::<SocketAddr>()
        .map_err(|e| e.to_string())?;
    let sandbox_raw = configuration.sandbox.clone();
    let sandbox = configuration
        .sandbox
        .map(compile_runtime_snapshot)
        .transpose()
        .map_err(|e| e.to_string())?;
    let mut supervisor = Supervisor {
        engine: hyperhub_engine::resident(),
        socket_engines: HashMap::new(),
        root_pid: root,
        proxy,
        endpoint,
        session_id,
        password: token.as_bytes().to_vec(),
        next_connection_id: 1,
        next_socket_id: 1,
        control: super::super::engine_control::control_runtime()?,
        sandbox,
        sandbox_raw,
        next_sandbox_refresh: Instant::now() + SANDBOX_REFRESH_INTERVAL,
        last_sandbox_refresh_error: None,
        hook_counts: HashMap::new(),
        hook_report: None,
        require_all_hooks: false,
        enforce: environment_value(env, "HYPERHUB_ENFORCEMENT_MODE").as_deref() != Some("observe"),
        threads: acquired
            .tids
            .iter()
            .map(|&tid| (tid, ThreadState::default()))
            .collect(),
        thread_groups: HashMap::new(),
        parents: HashMap::new(),
        members: anchors
            .iter()
            .map(|pid| *pid as i32)
            .chain(std::iter::once(root))
            .collect(),
        logical_nonblocking: HashSet::new(),
        inherited_nonblocking: HashSet::new(),
        file_tables: HashMap::new(),
        pending_child_stops: HashSet::new(),
        next_file_table: 1,
        clone_flags: HashMap::new(),
        sockets: HashMap::new(),
        udp_peers: HashMap::new(),
        dns_queries: DnsTransactions::default(),
        dns_addresses: HashMap::new(),
        dns_ports: HashSet::from([53]),
        root_status: None,
        process_starts: HashMap::new(),
        tree_failure: None,
        last_exit: None,
        attachment: Some(State {
            current_root: configuration
                .execution
                .as_ref()
                .map(|value| value.spec.effective_target().clone()),
            manager_identity: hyperhub_core::attachments::inspect_process(std::process::id()).ok(),
            recovery: configuration.execution,
            authorization: configuration.authorization,
            recovery_safe: true,
            detach_prepared: false,
            detach_finished: false,
            tree: configuration.tree,
            detaching: configuration.detach.load(Ordering::Acquire),
            detach: configuration.detach,
            events: configuration.events,
            unscoped_children: HashSet::new(),
            last_sockets: None,
            stopped: HashMap::new(),
            new_children: HashSet::new(),
        }),
    };
    let mut tables = HashMap::new();
    for &tid in &acquired.tids {
        let group = thread_group(tid);
        supervisor.thread_groups.insert(tid, group);
        supervisor
            .process_starts
            .entry(group)
            .or_insert_with(|| process_birth(group).unwrap_or(0));
        let table = *tables.entry(group).or_insert_with(|| {
            let value = supervisor.next_file_table;
            supervisor.next_file_table += 1;
            value
        });
        supervisor.file_tables.insert(tid, table);
        if group != root {
            supervisor
                .parents
                .insert(group, process_parent(group).unwrap_or(root));
        }
    }
    let mut sockets_by_inode = HashMap::new();
    for inherited in inherited {
        let table = *tables
            .get(&inherited.pid)
            .ok_or("inherited socket has no descriptor table")?;
        let descriptor = *sockets_by_inode.entry(inherited.inode).or_insert_with(|| {
            let id = supervisor.next_socket_id;
            supervisor.next_socket_id += 1;
            SocketDescriptor {
                id,
                domain: inherited.domain,
                socket_type: inherited.socket_type,
                handshake_complete: inherited.connected,
            }
        });
        if inherited.nonblocking && descriptor.requires_blocking_handshake() {
            supervisor.logical_nonblocking.insert(descriptor.id);
            supervisor.inherited_nonblocking.insert(descriptor.id);
        }
        supervisor.sockets.insert((table, inherited.fd), descriptor);
        if let Some(peer) = inherited.peer {
            supervisor.udp_peers.insert((table, inherited.fd), peer);
        }
    }
    for &pid in tables.keys() {
        supervisor.ensure_member(pid)?;
    }
    super::super::engine_control::bootstrap(
        &supervisor.engine,
        &supervisor.endpoint,
        &supervisor.session_id,
        &token,
        configuration.root_pid,
    )?;
    let _engine = super::super::engine_control::start(
        supervisor.engine.clone(),
        supervisor.endpoint.clone(),
        supervisor.session_id.clone(),
        token,
        configuration.root_pid,
    )?;
    for (&tid, &status) in &acquired.stopped {
        let signal = libc::WSTOPSIG(status);
        let event = (status as u32) >> 16;
        if event == EVENT_STOP && signal != libc::SIGTRAP {
            listen(tid)?;
        } else {
            resume_syscall(
                tid,
                if event != 0 || signal == SYSCALL_STOP {
                    0
                } else {
                    signal
                },
            )?;
        }
    }
    acquired.armed = false;
    let pids = tables.keys().map(|&pid| pid as u32).collect();
    let state = supervisor.attachment.as_ref().unwrap();
    let _ = state.events.send(if state.detaching {
        Event::Draining {
            sockets: supervisor.socket_engines.len(),
        }
    } else {
        Event::Active(pids)
    });
    let result = supervisor.event_loop();
    match result {
        Ok(_) => {
            let state = supervisor.attachment.as_ref().unwrap();
            let _ = state.events.send(if state.detaching {
                Event::Detached
            } else {
                Event::Exited
            });
            Ok(())
        }
        Err(error) => {
            let _ = supervisor
                .attachment
                .as_ref()
                .unwrap()
                .events
                .send(Event::Degraded(error.clone()));
            // Non-owning recovery deliberately does not call terminate_all.
            let cleanup = supervisor.detach_external();
            cleanup.and(Err(error))
        }
    }
}

impl Supervisor {
    pub(super) fn checkpoint_ptrace_safety(&mut self, mutating: bool) -> Result<(), String> {
        let Some(state) = self.attachment.as_ref() else {
            return Ok(());
        };
        let Some(execution) = state.recovery.as_ref() else {
            return Ok(());
        };
        let virtual_flags = self
            .logical_nonblocking
            .iter()
            .any(|id| !self.inherited_nonblocking.contains(id));
        let in_flight = self
            .threads
            .values()
            .filter_map(|thread| thread.pending.as_ref())
            .any(PendingSyscall::has_recovery_dependency);
        let dns = self
            .dns_addresses
            .values()
            .any(|(_, expires)| *expires > Instant::now());
        let leased_connections = !self.socket_engines.is_empty();
        let safe = !(mutating || virtual_flags || in_flight || dns || leased_connections);
        if safe != state.recovery_safe {
            // Durable dirty-before-mutation / clean-after-restore ordering.
            // A crash in a dirty interval cannot be approved as transparent
            // recovery from the kernel's incomplete view of application flags.
            crate::attachment::save_backend_recovery(
                execution,
                &serde_json::json!({"schema":1,"backend":"ptrace","safe":safe,"virtual_descriptor_flags":virtual_flags,"in_flight_syscall":mutating||in_flight,"cached_dns":dns,"leased_connections":leased_connections}),
            )?;
            self.attachment
                .as_mut()
                .expect("attached state")
                .recovery_safe = safe;
        }
        Ok(())
    }
    pub(super) fn restore_detached_socket_flags(
        &mut self,
        tid: libc::pid_t,
        registers: &Registers,
    ) -> Result<(), String> {
        if !self
            .attachment
            .as_ref()
            .is_some_and(|state| state.detaching)
        {
            return Ok(());
        }
        if self.threads.values().any(|thread| thread.pending.is_some()) {
            return Ok(());
        }
        let table = self.descriptor_table(tid);
        let restore = self
            .sockets
            .iter()
            .filter(|((owner, _), socket)| {
                *owner == table && self.logical_nonblocking.contains(&socket.id)
            })
            .map(|((_, fd), socket)| (*fd, socket.id))
            .collect::<Vec<_>>();
        for (fd, id) in restore {
            let flags = remote_syscall(
                tid,
                registers,
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
            )?;
            if flags < 0 {
                return Err(format!(
                    "cannot read virtual socket flags during detach: {flags}"
                ));
            }
            let result = remote_syscall(
                tid,
                registers,
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
            if result < 0 {
                return Err(format!(
                    "cannot restore virtual socket flags during detach: {result}"
                ));
            }
            self.logical_nonblocking.remove(&id);
            self.inherited_nonblocking.remove(&id);
            self.mark_handshake_complete(id);
        }
        Ok(())
    }
    pub(super) fn resume_tracee(&mut self, tid: libc::pid_t, signal: i32) -> Result<(), String> {
        resume_syscall(tid, signal)?;
        if let Some(state) = self.attachment.as_mut() {
            state.stopped.remove(&tid);
            state.new_children.remove(&tid);
        }
        Ok(())
    }
    pub(super) fn attachment_tracks_children(&self) -> bool {
        self.attachment
            .as_ref()
            .is_none_or(|state| state.tree && !state.detaching)
    }
    pub(super) fn detach_unscoped_child(&mut self, tid: libc::pid_t) -> Result<bool, String> {
        if !self
            .attachment
            .as_mut()
            .is_some_and(|state| state.unscoped_children.remove(&tid))
        {
            return Ok(false);
        }
        ptrace(DETACH, tid, std::ptr::null_mut(), std::ptr::null_mut())?;
        self.threads.remove(&tid);
        self.cleanup_exited_thread(tid);
        if let Some(state) = self.attachment.as_mut() {
            state.stopped.remove(&tid);
            state.new_children.remove(&tid);
        }
        Ok(true)
    }
    pub(super) fn poll_attachment(&mut self) -> Result<bool, String> {
        let Some(state) = self.attachment.as_mut() else {
            return Ok(false);
        };
        if !state.detach.load(Ordering::Acquire) && state.detaching {
            let grant = state
                .authorization
                .lock()
                .map_err(|_| "attachment authorization poisoned")?
                .clone();
            let execution = state
                .recovery
                .as_ref()
                .ok_or("reactivation has no sealed attachment context")?;
            let image = hyperhub_core::attachments::manager_root_image(&execution.spec.id)?;
            let current = state
                .current_root
                .as_ref()
                .ok_or("reactivation has no private root identity")?;
            if !matches!(
                &grant.request.action,
                hyperhub_core::attachments::Action::Attach { .. }
            ) || grant.request.action.exec_epoch() != image.exec_epoch
                || grant.request.action.target().root_image_identity() != image.identity
                || current.root_image_identity() != image.identity
            {
                state.detach.store(true, Ordering::Release);
                return Err("attachment reactivation grant became stale after root exec".into());
            }
            state.detaching = false;
            state.detach_prepared = false;
            state.detach_finished = false;
            state.last_sockets = None;
            self.next_sandbox_refresh = Instant::now();
            self.refresh_sandbox_if_due();
            if let Some(error) = &self.last_sandbox_refresh_error {
                return Err(format!(
                    "cannot reactivate attachment with stale policy: {error}"
                ));
            }
            let pids = self.process_starts.keys().map(|pid| *pid as u32).collect();
            let _ = self
                .attachment
                .as_ref()
                .expect("attached state")
                .events
                .send(Event::Active(pids));
            return Ok(false);
        }
        if state.detach.load(Ordering::Acquire) {
            state.detaching = true;
        }
        if !state.detaching {
            return Ok(false);
        }
        if !state.detach_prepared {
            let grant = state
                .authorization
                .lock()
                .map_err(|_| "attachment authorization poisoned")?
                .clone();
            let execution = state
                .recovery
                .as_ref()
                .ok_or("detach has no sealed attachment context")?;
            let manager = state
                .manager_identity
                .as_ref()
                .ok_or("detach manager identity is unavailable")?;
            match self
                .control
                .block_on(hyperhub_core::attachments::prepare_detach_session(
                    execution, &grant, manager,
                )) {
                Ok(()) => state.detach_prepared = true,
                Err(error) => {
                    let _ = state.events.send(Event::CleanupPending(format!(
                        "detach_session_fence_pending:{error}"
                    )));
                    return Ok(false);
                }
            }
        }
        if !state.detach_finished {
            let grant = state
                .authorization
                .lock()
                .map_err(|_| "attachment authorization poisoned")?
                .clone();
            let execution = state
                .recovery
                .as_ref()
                .ok_or("detach has no sealed attachment context")?;
            let manager = state
                .manager_identity
                .as_ref()
                .ok_or("detach manager identity is unavailable")?;
            // Ptrace has no injected alias Hosts or native fork reservations;
            // Core still validates this signed continuation before completion.
            state.detach_finished =
                match self
                    .control
                    .block_on(hyperhub_core::attachments::finish_detach_session(
                        execution, &grant, manager,
                    )) {
                    Ok(finished) => finished,
                    Err(error) => {
                        let _ = state.events.send(Event::CleanupPending(format!(
                            "detach_session_completion_pending:{error}"
                        )));
                        return Ok(false);
                    }
                };
            if !state.detach_finished {
                return Ok(false);
            }
        }
        // Inherited native-nonblocking descriptions have not been altered and
        // require no remote restoration. Do not keep an idle target traced
        // merely because no new application syscall has completed yet.
        let already_native = self.inherited_nonblocking.drain().collect::<Vec<_>>();
        for id in already_native {
            self.logical_nonblocking.remove(&id);
            self.mark_handshake_complete(id);
        }
        let state = self.attachment.as_mut().expect("attached state");
        let sockets = self.socket_engines.len() + self.logical_nonblocking.len();
        if state.last_sockets != Some(sockets) {
            state.last_sockets = Some(sockets);
            let _ = state.events.send(Event::Draining { sockets });
        }
        if sockets != 0 || self.threads.values().any(|state| state.pending.is_some()) {
            return Ok(false);
        }
        self.detach_external()?;
        Ok(true)
    }
    pub(super) fn detach_external(&mut self) -> Result<(), String> {
        let mut acquired = Seized::new();
        acquired.tids = self
            .threads
            .keys()
            .copied()
            .filter(|tid| tracer_pid(*tid) == Some(std::process::id()))
            .collect();
        if let Some(state) = self.attachment.as_ref() {
            acquired.stopped = state
                .stopped
                .iter()
                .filter(|(tid, _)| tracer_pid(**tid) == Some(std::process::id()))
                .map(|(&tid, &status)| (tid, status))
                .collect();
            acquired.synthetic_children = state.new_children.clone();
            acquired.tids.extend(acquired.stopped.keys().copied());
        }
        acquired.interrupt()?;
        acquired.wait_stopped(Instant::now() + Duration::from_secs(5))?;
        // Drop performs PTRACE_DETACH and preserves real pending signals.
        let tids = acquired.tids.clone();
        drop(acquired);
        let remaining = tids
            .into_iter()
            .filter(|tid| tracer_pid(*tid) == Some(std::process::id()))
            .collect::<Vec<_>>();
        if !remaining.is_empty() {
            return Err(format!(
                "attachment tracing cleanup is incomplete for {} threads",
                remaining.len()
            ));
        }
        self.threads.clear();
        self.file_tables.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_options_never_own_target_lifetime() {
        assert_eq!(options(true) & PTRACE_O_EXITKILL, 0);
        assert_eq!(
            options(false) & (PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK),
            0
        );
        assert_ne!(options(false) & PTRACE_O_TRACECLONE, 0);
    }
}

/// A reversible `run` keeps its original foreground launcher after tracing has
/// detached. This bridge owns management resources, never the target process.
pub(super) struct OwnedBridge {
    _listener: super::super::attachment::ManagerListener,
    execution: hyperhub_core::attachments::Execution,
    detach: Arc<AtomicBool>,
    events: Option<Sender<Event>>,
    reporter: Option<std::thread::JoinHandle<()>>,
}
impl OwnedBridge {
    pub(super) fn new(execution: &hyperhub_core::attachments::Execution) -> Result<Self, String> {
        let manager = super::super::attachment::inspect_attachment_target(std::process::id())?;
        super::super::attachment::persist_ptrace_context(execution)?;
        let detach = Arc::new(AtomicBool::new(false));
        let listener = super::super::attachment::ManagerListener::start(execution, detach.clone())?;
        let (events, reporter) = super::super::attachment::start_reporter(
            execution,
            &manager,
            &listener.endpoint,
            listener.authorization.clone(),
        )?;
        Ok(Self {
            _listener: listener,
            execution: execution.clone(),
            detach,
            events: Some(events),
            reporter: Some(reporter),
        })
    }
    pub(super) fn state(&self) -> State {
        State {
            recovery: Some(self.execution.clone()),
            authorization: self._listener.authorization.clone(),
            current_root: Some(self.execution.spec.effective_target().clone()),
            manager_identity: hyperhub_core::attachments::inspect_process(std::process::id()).ok(),
            recovery_safe: true,
            detach_prepared: false,
            detach_finished: false,
            tree: true,
            detaching: false,
            detach: self.detach.clone(),
            events: self
                .events
                .as_ref()
                .expect("owned bridge sender exists")
                .clone(),
            unscoped_children: HashSet::new(),
            last_sockets: None,
            stopped: HashMap::new(),
            new_children: HashSet::new(),
        }
    }
    pub(super) fn report(&self, event: Event) {
        if let Some(send) = &self.events {
            let _ = send.send(event);
        }
    }
}
impl Drop for OwnedBridge {
    fn drop(&mut self) {
        self.events.take();
        if let Some(reporter) = self.reporter.take() {
            let _ = reporter.join();
        }
    }
}

/// The child has not exec'ed application code yet. Convert its private startup
/// SIGSTOP into SEIZE tracing so later detach can use INTERRUPT without sending
/// an application-visible SIGSTOP/SIGCONT pair to a running target.
pub(super) fn resume_owned_startup(child: libc::pid_t) -> Result<i32, String> {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(child, &mut status, libc::WUNTRACED | libc::__WALL) };
        if result == child {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error.to_string());
        }
    }
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP {
        return Err("reversible run did not reach its pre-exec stop".into());
    }
    ptrace(
        SEIZE,
        child,
        std::ptr::null_mut(),
        (options(true) | PTRACE_O_EXITKILL) as usize as *mut c_void,
    )?;
    if unsafe { libc::kill(child, libc::SIGCONT) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    loop {
        status = wait_for(child)?;
        if !libc::WIFSTOPPED(status) {
            return Ok(status);
        }
        let event = (status as u32) >> 16;
        if event == PTRACE_EVENT_EXEC {
            return Ok(status);
        }
        let signal = libc::WSTOPSIG(status);
        let deliver = if event == EVENT_STOP { 0 } else { signal };
        ptrace(
            7,
            child,
            std::ptr::null_mut(),
            deliver as usize as *mut c_void,
        )?;
    }
}

pub(super) fn activate_owned(child: libc::pid_t) -> Result<(), String> {
    ptrace(
        PTRACE_SETOPTIONS,
        child,
        std::ptr::null_mut(),
        options(true) as usize as *mut c_void,
    )
    .map(|_| ())
}
