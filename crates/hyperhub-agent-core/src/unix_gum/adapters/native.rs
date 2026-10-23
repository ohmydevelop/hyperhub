#![allow(dead_code)]
#![cfg(all(target_os = "linux", feature = "gum-agent"))]

use crate::unix_gum::gum;
use libc::{
    addrinfo, c_int, c_void, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t,
    AF_INET, AF_INET6,
};
use std::cell::Cell;
use std::ffi::{CStr, CString, OsStr};
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Once, OnceLock};

thread_local! { static INSIDE_HOOK: Cell<bool> = const { Cell::new(false) }; }

static HOOK_HITS: [AtomicU64; 42] = [const { AtomicU64::new(0) }; 42];
static HOOK_REPORT_ENABLED: AtomicBool = AtomicBool::new(false);
static INSTALL_HOOK_REPORT: Once = Once::new();

const HOOK_REPORT_NAMES: &[(usize, &str)] = &[
    (1, "dns.resolve"),
    (2, "dns.release"),
    (3, "socket.connect"),
    (4, "socket.send"),
    (5, "socket.recv"),
    (6, "handle.close"),
    (7, "socket.nonblocking"),
    (8, "socket.ioctl"),
    (9, "file.open"),
    (11, "file.openat"),
    (13, "file.creat"),
    (14, "file.read"),
    (15, "file.write"),
    (16, "file.unlink"),
    (17, "file.unlinkat"),
    (18, "file.rename"),
    (19, "file.renameat"),
    (20, "process.execve"),
    (21, "process.posix_spawn"),
    (22, "process.posix_spawnp"),
    (23, "file.mmap"),
    (24, "file.mprotect"),
    (25, "file.munmap"),
    (26, "handle.dup"),
    (27, "handle.dup2"),
    (28, "handle.dup3"),
    (29, "socket.sendto"),
    (30, "socket.recvfrom"),
    (31, "socket.sendmsg"),
    (32, "socket.recvmsg"),
    (33, "file.readv"),
    (34, "file.writev"),
    (35, "file.pread"),
    (36, "file.pwrite"),
    (40, "file.link"),
    (41, "file.linkat"),
];

fn hook_hit(id: usize) {
    if HOOK_REPORT_ENABLED.load(Ordering::Relaxed) && id < HOOK_HITS.len() {
        HOOK_HITS[id].fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn install_hook_report() {
    install_exit_status();
    if std::env::var_os("HYPERHUB_DYNAMIC_HOOK_REPORT").is_none() {
        return;
    }
    INSTALL_HOOK_REPORT.call_once(|| unsafe {
        HOOK_REPORT_ENABLED.store(true, Ordering::Release);
        libc::atexit(write_hook_report);
    });
}

static EXIT_STATUS_DIRECTORY: OnceLock<std::path::PathBuf> = OnceLock::new();
static EXIT_STATUS_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn install_exit_status() {
    let Some(directory) = std::env::var_os("HYPERHUB_GUM_EXIT_DIRECTORY") else {
        return;
    };
    if EXIT_STATUS_DIRECTORY.set(directory.into()).is_ok() {
        unsafe extern "C" {
            fn on_exit(
                callback: unsafe extern "C" fn(c_int, *mut c_void),
                argument: *mut c_void,
            ) -> c_int;
        }
        unsafe {
            on_exit(record_exit_status, std::ptr::null_mut());
        }
    }
}

unsafe extern "C" fn record_exit_status(status: c_int, _: *mut c_void) {
    let Some(directory) = EXIT_STATUS_DIRECTORY.get() else {
        return;
    };
    let pid = libc::getpid();
    let sequence = EXIT_STATUS_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let Ok(path) = CString::new(directory.join(format!("{pid}.exit")).as_os_str().as_bytes())
    else {
        return;
    };
    let Ok(temporary) = CString::new(
        directory
            .join(format!("{pid}.{sequence}.tmp"))
            .as_os_str()
            .as_bytes(),
    ) else {
        return;
    };
    // Exit can run after fork or while another Agent thread owns runtime locks.
    // Use the same raw-syscall approach as signal_ready: no Hook reentry or
    // socket-state locks, and never follow a target-created symlink.
    let fd = libc::syscall(
        libc::SYS_openat,
        libc::AT_FDCWD,
        temporary.as_ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    ) as c_int;
    if fd < 0 {
        return;
    }
    let stat_fd = libc::syscall(
        libc::SYS_openat,
        libc::AT_FDCWD,
        c"/proc/self/stat".as_ptr(),
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    ) as c_int;
    if stat_fd < 0 {
        libc::syscall(libc::SYS_close, fd);
        return;
    }
    let mut stat = [0u8; 4096];
    let count = libc::syscall(libc::SYS_read, stat_fd, stat.as_mut_ptr(), stat.len());
    libc::syscall(libc::SYS_close, stat_fd);
    let birth = (count > 0)
        .then(|| std::str::from_utf8(&stat[..count as usize]).ok())
        .flatten()
        .and_then(|text| text.rsplit_once(") "))
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok());
    let Some(birth) = birth else {
        libc::syscall(libc::SYS_close, fd);
        return;
    };
    let status = format!("{} {birth}", status & 255);
    let mut written = 0;
    while written < status.len() {
        let result = libc::syscall(
            libc::SYS_write,
            fd,
            status.as_ptr().add(written),
            status.len() - written,
        );
        if result < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        if result <= 0 {
            break;
        }
        written += result as usize;
    }
    libc::syscall(libc::SYS_close, fd);
    if written == status.len() {
        libc::syscall(
            libc::SYS_renameat,
            libc::AT_FDCWD,
            temporary.as_ptr(),
            libc::AT_FDCWD,
            path.as_ptr(),
        );
    }
    libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, temporary.as_ptr(), 0);
}

extern "C" fn write_hook_report() {
    let Some(path) = std::env::var_os("HYPERHUB_DYNAMIC_HOOK_REPORT") else {
        return;
    };
    let counts = HOOK_REPORT_NAMES
        .iter()
        .map(|(id, name)| ((*name).to_owned(), HOOK_HITS[*id].load(Ordering::Relaxed)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let missing_required = counts
        .iter()
        .filter_map(|(name, count)| (*count == 0).then_some(name.clone()))
        .collect::<Vec<_>>();
    let report = serde_json::json!({
        "counts": counts,
        "missing_required": missing_required,
        "aliases": {
            "file.open": ["open", "open64"],
            "file.openat": ["openat", "openat64"]
        }
    });
    if let Ok(bytes) = serde_json::to_vec_pretty(&report) {
        let _ = std::fs::write(path, bytes);
    }
}
// A libc child callback runs before Frida restores its copied runtime. New
// policy decisions fail without entering copied locks; existing raw FD IO stays
// available. The early native fork listener opens only Frida's recovery scope.
unsafe fn child_policy_denied() -> bool {
    if super::super::fork::new_policy_blocked() {
        *libc::__errno_location() = libc::EACCES;
        true
    } else {
        false
    }
}

pub(in crate::unix_gum) struct HookGuard {
    _engine: Option<crate::engine_call::EngineCallGuard>,
}
impl HookGuard {
    pub(in crate::unix_gum) fn enter() -> Option<Self> {
        if super::super::fork::awaiting_rebuild() || crate::engine_call::host_background() {
            return None;
        }
        INSIDE_HOOK.with(|inside| {
            if inside.replace(true) {
                None
            } else {
                if !crate::engine_call::EngineCallGuard::available() {
                    inside.set(false);
                    None
                } else {
                    Some(Self {
                        _engine: crate::engine_call::EngineCallGuard::enter(),
                    })
                }
            }
        })
    }
}
impl Drop for HookGuard {
    fn drop(&mut self) {
        INSIDE_HOOK.with(|inside| inside.set(false));
    }
}

/// Resolve lazy native trampolines before any application fork. A copied
/// OnceLock in its initializing state cannot be completed by a vanished thread.
pub(crate) fn warm_originals() {
    let _ = connect_fn();
    let _ = send_fn();
    let _ = recv_fn();
    let _ = sendto_fn();
    let _ = recvfrom_fn();
    let _ = sendmsg_fn();
    let _ = recvmsg_fn();
    let _ = gai_fn();
    let _ = free_fn();
    let _ = read_fn();
    let _ = write_fn();
    let _ = unlink_fn();
    let _ = rename_fn();
    let _ = execve_fn();
    let _ = mmap_fn();
    let _ = readv_fn();
    let _ = writev_fn();
    let _ = pread_fn();
    let _ = pwrite_fn();
    if gum::original("renameat2").is_some() {
        let _ = renameat2_fn();
    }
}
type ConnectFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
type SendFn = unsafe extern "C" fn(c_int, *const c_void, usize, c_int) -> isize;
type RecvFn = unsafe extern "C" fn(c_int, *mut c_void, usize, c_int) -> isize;
type SendToFn =
    unsafe extern "C" fn(c_int, *const c_void, usize, c_int, *const sockaddr, socklen_t) -> isize;
type RecvFromFn =
    unsafe extern "C" fn(c_int, *mut c_void, usize, c_int, *mut sockaddr, *mut socklen_t) -> isize;
type SendMsgFn = unsafe extern "C" fn(c_int, *const libc::msghdr, c_int) -> isize;
type RecvMsgFn = unsafe extern "C" fn(c_int, *mut libc::msghdr, c_int) -> isize;
type ReadvFn = unsafe extern "C" fn(c_int, *const libc::iovec, c_int) -> isize;
type WritevFn = unsafe extern "C" fn(c_int, *const libc::iovec, c_int) -> isize;
type PreadFn = unsafe extern "C" fn(c_int, *mut c_void, usize, libc::off_t) -> isize;
type PwriteFn = unsafe extern "C" fn(c_int, *const c_void, usize, libc::off_t) -> isize;
type GetAddrInfoFn = unsafe extern "C" fn(
    *const libc::c_char,
    *const libc::c_char,
    *const addrinfo,
    *mut *mut addrinfo,
) -> c_int;
type FreeAddrInfoFn = unsafe extern "C" fn(*mut addrinfo);
fn symbol<T>(name: &CStr) -> T {
    unsafe {
        let symbol = name.to_str().expect("symbol is UTF-8");
        let p =
            gum::original(symbol).unwrap_or_else(|| libc::dlsym(libc::RTLD_NEXT, name.as_ptr()));
        assert!(!p.is_null(), "missing libc symbol {:?}", name);
        std::mem::transmute_copy(&p)
    }
}
fn connect_fn() -> ConnectFn {
    static F: OnceLock<ConnectFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"connect"))
}
fn send_fn() -> SendFn {
    static F: OnceLock<SendFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"send"))
}
fn recv_fn() -> RecvFn {
    static F: OnceLock<RecvFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"recv"))
}
fn sendto_fn() -> SendToFn {
    static F: OnceLock<SendToFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"sendto"))
}
fn recvfrom_fn() -> RecvFromFn {
    static F: OnceLock<RecvFromFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"recvfrom"))
}
fn sendmsg_fn() -> SendMsgFn {
    static F: OnceLock<SendMsgFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"sendmsg"))
}
fn recvmsg_fn() -> RecvMsgFn {
    static F: OnceLock<RecvMsgFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"recvmsg"))
}
fn gai_fn() -> GetAddrInfoFn {
    static F: OnceLock<GetAddrInfoFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"getaddrinfo"))
}
fn free_fn() -> FreeAddrInfoFn {
    static F: OnceLock<FreeAddrInfoFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"freeaddrinfo"))
}

pub unsafe extern "C" fn connect(fd: c_int, address: *const sockaddr, length: socklen_t) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(3);
    let original = connect_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, address, length);
    };
    if address.is_null() {
        return original(fd, address, length);
    }
    let (family, ip, port) = match (*address).sa_family as c_int {
        AF_INET => {
            let a = &*(address as *const sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            (4, ip.to_string(), u16::from_be(a.sin_port))
        }
        AF_INET6 => {
            let a = &*(address as *const sockaddr_in6);
            let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
            (6, ip.to_string(), u16::from_be(a.sin6_port))
        }
        _ => return original(fd, address, length),
    };
    let mut plan = crate::HhConnectPlan::default();
    let bytes = if family == 4 {
        ip.parse::<Ipv4Addr>().unwrap().octets().to_vec()
    } else {
        ip.parse::<Ipv6Addr>().unwrap().octets().to_vec()
    };
    if let Some(snapshot) = crate::firewall_snapshot() {
        let (action, rule_id, source, target) =
            match crate::firewall_connect_target(family, &bytes, port) {
                Some(target) => {
                    let (action, rule_id, source) = crate::firewall_decision(&snapshot, &target);
                    (action, rule_id, source, Some(target))
                }
                None => (
                    snapshot.error_action,
                    None,
                    crate::FirewallDecisionSource::Error,
                    None,
                ),
            };
        if action == crate::FirewallAction::Deny || source == crate::FirewallDecisionSource::Error {
            let event = crate::FirewallAuditEvent {
                decision: action,
                rule_id,
                source,
                stage: crate::FirewallAuditStage::Connect,
                hostname: target.as_ref().and_then(|target| target.hostname.clone()),
                ip: target.as_ref().map(|target| target.ip),
                port: target.as_ref().map(|target| target.port),
                process_pid: libc::getpid() as u32,
                process_tid: libc::syscall(libc::SYS_gettid) as u32,
                snapshot_version: snapshot.version,
            };
            let _ = crate::report_firewall_audit(&event);
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    if crate::hh_agent_prepare_connect(
        fd as u64,
        family,
        bytes.as_ptr(),
        bytes.len(),
        port,
        &mut plan,
    ) != crate::HH_OK
        || plan.should_intercept == 0
    {
        return original(fd, address, length);
    }
    let mut proxy: sockaddr_storage = std::mem::zeroed();
    let result = if plan.proxy_family == 2 {
        let p = &mut *(&mut proxy as *mut _ as *mut sockaddr_in);
        p.sin_family = AF_INET as u16;
        p.sin_port = plan.proxy_port.to_be();
        p.sin_addr.s_addr = u32::from_ne_bytes(plan.proxy_address[..4].try_into().unwrap());
        original(
            fd,
            &proxy as *const _ as *const sockaddr,
            size_of::<sockaddr_in>() as socklen_t,
        )
    } else {
        let p = &mut *(&mut proxy as *mut _ as *mut sockaddr_in6);
        p.sin6_family = AF_INET6 as u16;
        p.sin6_port = plan.proxy_port.to_be();
        p.sin6_addr.s6_addr = plan.proxy_address;
        original(
            fd,
            &proxy as *const _ as *const sockaddr,
            size_of::<sockaddr_in6>() as socklen_t,
        )
    };
    if result < 0 {
        let error = *libc::__errno_location();
        if matches!(
            error,
            libc::EINPROGRESS | libc::EWOULDBLOCK | libc::EALREADY
        ) {
            return -1;
        }
        let _ = crate::hh_agent_close_socket(fd as u64);
        *libc::__errno_location() = error;
        return -1;
    }
    if ensure_handshake_blocking(fd) {
        0
    } else {
        let _ = crate::hh_agent_close_socket(fd as u64);
        *libc::__errno_location() = libc::ECONNRESET;
        -1
    }
}

unsafe fn ensure_handshake(fd: c_int) -> bool {
    let state = crate::hh_agent_handshake_complete(fd as u64);
    if state == 1 || state < 0 {
        return true;
    }
    let flags = libc::fcntl(fd, libc::F_GETFL);
    if flags < 0 {
        return false;
    }
    let was_nonblocking = flags & libc::O_NONBLOCK != 0;
    if was_nonblocking && libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
        return false;
    }
    let ok = exchange_handshake(fd);
    let restored = !was_nonblocking || libc::fcntl(fd, libc::F_SETFL, flags) == 0;
    ok && restored && crate::hh_agent_set_handshake_complete(fd as u64) == crate::HH_OK
}

unsafe fn ensure_handshake_blocking(fd: c_int) -> bool {
    let state = crate::hh_agent_handshake_complete(fd as u64);
    if state == 1 || state < 0 {
        return true;
    }
    exchange_handshake(fd) && crate::hh_agent_set_handshake_complete(fd as u64) == crate::HH_OK
}

unsafe fn exchange_handshake(fd: c_int) -> bool {
    for phase in 0..3 {
        let mut request = [0u8; 512];
        let mut request_length = 0usize;
        if crate::hh_agent_build_handshake(
            fd as u64,
            phase,
            request.as_mut_ptr(),
            request.len(),
            &mut request_length,
        ) != crate::HH_OK
            || !send_all(fd, &request[..request_length])
        {
            return false;
        }
        if phase < 2 {
            let mut reply = [0u8; 2];
            if !recv_all(fd, &mut reply)
                || crate::hh_agent_validate_socket_handshake_reply(
                    fd as u64,
                    phase,
                    reply.as_ptr(),
                    reply.len(),
                ) != crate::HH_OK
            {
                return false;
            }
            continue;
        }
        let mut head = [0u8; 4];
        if !recv_all(fd, &mut head) || head[0] != 5 || head[1] != 0 {
            return false;
        }
        let tail_length = match head[3] {
            1 => 6,
            4 => 18,
            3 => {
                let mut domain_length = [0u8; 1];
                if !recv_all(fd, &mut domain_length) {
                    return false;
                }
                domain_length[0] as usize + 2
            }
            _ => return false,
        };
        let mut tail = [0u8; 258];
        if tail_length > tail.len() || !recv_all(fd, &mut tail[..tail_length]) {
            return false;
        }
        let validation = [head[0], head[1], head[2], head[3], 0];
        if crate::hh_agent_validate_socket_handshake_reply(
            fd as u64,
            phase,
            validation.as_ptr(),
            validation.len(),
        ) != crate::HH_OK
        {
            return false;
        }
    }
    true
}

unsafe fn send_all(fd: c_int, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let sent = send_fn()(fd, data.as_ptr() as *const c_void, data.len(), 0);
        if sent > 0 {
            data = &data[sent as usize..];
        } else if sent < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        } else {
            return false;
        }
    }
    true
}

unsafe fn file_allowed_for_io(fd: c_int, operation: crate::FileSandboxOperation) -> bool {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .map(|path| crate::file_allows(&path.to_string_lossy(), operation))
        .unwrap_or(true)
}

unsafe fn audit_io_denial(fd: c_int, operation: &str) {
    if let Ok(path) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
        audit(
            crate::SandboxAuditKind::File,
            operation,
            &path.to_string_lossy(),
        );
    }
}

unsafe fn recv_all(fd: c_int, mut data: &mut [u8]) -> bool {
    while !data.is_empty() {
        let received = recv_fn()(fd, data.as_mut_ptr() as *mut c_void, data.len(), 0);
        if received > 0 {
            let (_, remaining) = data.split_at_mut(received as usize);
            data = remaining;
        } else if received < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        } else {
            return false;
        }
    }
    true
}

pub unsafe extern "C" fn send(
    fd: c_int,
    buffer: *const c_void,
    length: usize,
    flags: c_int,
) -> isize {
    hook_hit(4);
    let original = send_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, buffer, length, flags);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    let result = original(fd, buffer, length, flags);
    let _ = crate::hh_agent_note_io(fd as u64, result as i64);
    result
}
pub unsafe extern "C" fn recv(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    flags: c_int,
) -> isize {
    hook_hit(5);
    let original = recv_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, buffer, length, flags);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    let result = original(fd, buffer, length, flags);
    let _ = crate::hh_agent_note_io(fd as u64, result as i64);
    result
}

pub unsafe extern "C" fn sendto(
    fd: c_int,
    buffer: *const c_void,
    length: usize,
    flags: c_int,
    address: *const sockaddr,
    address_length: socklen_t,
) -> isize {
    if !address.is_null() && child_policy_denied() {
        return -1;
    }
    if flags & libc::MSG_FASTOPEN != 0 {
        *libc::__errno_location() = libc::EOPNOTSUPP;
        return -1;
    }
    hook_hit(29);
    let original = sendto_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, buffer, length, flags, address, address_length);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    let result = original(fd, buffer, length, flags, address, address_length);
    let _ = crate::hh_agent_note_io(fd as u64, result as i64);
    result
}

pub unsafe extern "C" fn recvfrom(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    flags: c_int,
    address: *mut sockaddr,
    address_length: *mut socklen_t,
) -> isize {
    hook_hit(30);
    let original = recvfrom_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, buffer, length, flags, address, address_length);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    let result = original(fd, buffer, length, flags, address, address_length);
    let _ = crate::hh_agent_note_io(fd as u64, result as i64);
    result
}

pub unsafe extern "C" fn sendmsg(fd: c_int, message: *const libc::msghdr, flags: c_int) -> isize {
    if !message.is_null() && !(*message).msg_name.is_null() && child_policy_denied() {
        return -1;
    }
    if flags & libc::MSG_FASTOPEN != 0 {
        *libc::__errno_location() = libc::EOPNOTSUPP;
        return -1;
    }
    hook_hit(31);
    let original = sendmsg_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, message, flags);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    let result = original(fd, message, flags);
    let _ = crate::hh_agent_note_io(fd as u64, result as i64);
    result
}

pub unsafe extern "C" fn recvmsg(fd: c_int, message: *mut libc::msghdr, flags: c_int) -> isize {
    hook_hit(32);
    let original = recvmsg_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, message, flags);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    let result = original(fd, message, flags);
    let _ = crate::hh_agent_note_io(fd as u64, result as i64);
    result
}

pub unsafe extern "C" fn readv(fd: c_int, iov: *const libc::iovec, count: c_int) -> isize {
    hook_hit(33);
    let original = readv_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, iov, count);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    if !file_allowed_for_io(fd, crate::FileSandboxOperation::Read) {
        audit_io_denial(fd, "read");
        *libc::__errno_location() = libc::EACCES;
        return -1;
    }
    original(fd, iov, count)
}

pub unsafe extern "C" fn writev(fd: c_int, iov: *const libc::iovec, count: c_int) -> isize {
    hook_hit(34);
    let original = writev_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, iov, count);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    if !file_allowed_for_io(fd, crate::FileSandboxOperation::Write) {
        audit_io_denial(fd, "write");
        *libc::__errno_location() = libc::EACCES;
        return -1;
    }
    original(fd, iov, count)
}

pub unsafe extern "C" fn pread(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    offset: libc::off_t,
) -> isize {
    hook_hit(35);
    let original = pread_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, buffer, length, offset);
    };
    if !file_allowed_for_io(fd, crate::FileSandboxOperation::Read) {
        audit_io_denial(fd, "read");
        *libc::__errno_location() = libc::EACCES;
        return -1;
    }
    original(fd, buffer, length, offset)
}

pub unsafe extern "C" fn pwrite(
    fd: c_int,
    buffer: *const c_void,
    length: usize,
    offset: libc::off_t,
) -> isize {
    hook_hit(36);
    let original = pwrite_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, buffer, length, offset);
    };
    if !file_allowed_for_io(fd, crate::FileSandboxOperation::Write) {
        audit_io_denial(fd, "write");
        *libc::__errno_location() = libc::EACCES;
        return -1;
    }
    original(fd, buffer, length, offset)
}
pub unsafe extern "C" fn getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const addrinfo,
    result: *mut *mut addrinfo,
) -> c_int {
    if child_policy_denied() {
        if !result.is_null() {
            result.write(std::ptr::null_mut());
        }
        return libc::EAI_SYSTEM;
    }
    hook_hit(1);
    let original = gai_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(node, service, hints, result);
    };
    let out = original(node, service, hints, result);
    if out == 0 && !node.is_null() && !result.is_null() {
        let host = CStr::from_ptr(node).to_bytes();
        if let Ok(host) = std::str::from_utf8(host) {
            let mut cur = *result;
            while !cur.is_null() {
                let ai = &*cur;
                if ai.ai_family == AF_INET {
                    let a = &*(ai.ai_addr as *const sockaddr_in);
                    let b = u32::from_be(a.sin_addr.s_addr).to_be_bytes();
                    let c = CString::new(host).unwrap();
                    let _ = crate::hh_agent_record_dns(c.as_ptr(), 4, b.as_ptr(), 4);
                } else if ai.ai_family == AF_INET6 {
                    let a = &*(ai.ai_addr as *const sockaddr_in6);
                    let c = CString::new(host).unwrap();
                    let _ =
                        crate::hh_agent_record_dns(c.as_ptr(), 6, a.sin6_addr.s6_addr.as_ptr(), 16);
                }
                cur = ai.ai_next;
            }
        }
    }
    out
}

type ReadFn = unsafe extern "C" fn(c_int, *mut c_void, usize) -> isize;
type WriteFn = unsafe extern "C" fn(c_int, *const c_void, usize) -> isize;
type UnlinkFn = unsafe extern "C" fn(*const libc::c_char) -> c_int;
type RenameFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> c_int;
type RenameAt2Fn = unsafe extern "C" fn(
    c_int,
    *const libc::c_char,
    c_int,
    *const libc::c_char,
    libc::c_uint,
) -> c_int;
type ExecveFn = unsafe extern "C" fn(
    *const libc::c_char,
    *const *const libc::c_char,
    *const *const libc::c_char,
) -> c_int;
type MmapFn =
    unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int, libc::off_t) -> *mut c_void;
fn read_fn() -> ReadFn {
    static F: OnceLock<ReadFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"read"))
}
fn write_fn() -> WriteFn {
    static F: OnceLock<WriteFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"write"))
}
fn unlink_fn() -> UnlinkFn {
    static F: OnceLock<UnlinkFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"unlink"))
}
fn rename_fn() -> RenameFn {
    static F: OnceLock<RenameFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"rename"))
}
fn renameat2_fn() -> RenameAt2Fn {
    static F: OnceLock<RenameAt2Fn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"renameat2"))
}
fn execve_fn() -> ExecveFn {
    static F: OnceLock<ExecveFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"execve"))
}
fn mmap_fn() -> MmapFn {
    static F: OnceLock<MmapFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"mmap"))
}
fn readv_fn() -> ReadvFn {
    static F: OnceLock<ReadvFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"readv"))
}
fn writev_fn() -> WritevFn {
    static F: OnceLock<WritevFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"writev"))
}
fn pread_fn() -> PreadFn {
    static F: OnceLock<PreadFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"pread"))
}
fn pwrite_fn() -> PwriteFn {
    static F: OnceLock<PwriteFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"pwrite"))
}
fn audit(kind: crate::SandboxAuditKind, operation: &str, target: &str) {
    let event = crate::SandboxAuditEvent {
        kind,
        decision: crate::SandboxAction::Deny,
        rule_id: None,
        source: "rule".into(),
        operation: operation.into(),
        target: target.into(),
        process_argv_redacted: None,
        target_argv_redacted: None,
        reason: None,
        process_pid: unsafe { libc::getpid() as u32 },
        process_tid: unsafe { libc::syscall(libc::SYS_gettid) as u32 },
        snapshot_version: crate::sandbox_version(),
    };
    let _ = crate::report_sandbox_audit(&event);
}

unsafe fn cpath(p: *const libc::c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        CStr::from_ptr(p).to_str().ok().map(|x| {
            if x.starts_with('/') {
                x.to_owned()
            } else {
                std::env::current_dir()
                    .ok()
                    .map(|d| d.join(x).to_string_lossy().into_owned())
                    .unwrap_or_else(|| x.to_owned())
            }
        })
    }
}
fn file_operations_for_flags(flags: c_int) -> Vec<crate::FileSandboxOperation> {
    let mut operations = Vec::new();
    if flags & libc::O_CREAT != 0 {
        operations.push(crate::FileSandboxOperation::Create);
    }
    if matches!(flags & libc::O_ACCMODE, libc::O_RDONLY | libc::O_RDWR) {
        operations.push(crate::FileSandboxOperation::Read);
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_TRUNC != 0 {
        operations.push(crate::FileSandboxOperation::Write);
    }
    if operations.is_empty() {
        operations.push(crate::FileSandboxOperation::Read);
    }
    operations
}
fn relative_path(dirfd: c_int, path: &str) -> String {
    if path.starts_with('/') || dirfd == libc::AT_FDCWD {
        return cpath_string(path);
    }
    std::fs::read_link(format!("/proc/self/fd/{dirfd}"))
        .map(|root| format!("{}/{}", root.to_string_lossy().trim_end_matches('/'), path))
        .unwrap_or_else(|_| cpath_string(path))
}
fn cpath_string(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map(|d| d.join(path).to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_owned())
    }
}
pub(crate) const LISTENER_OPEN: usize = 1;
pub(crate) const LISTENER_OPENAT: usize = 2;
pub(crate) const LISTENER_FCNTL: usize = 3;
pub(crate) const LISTENER_IOCTL: usize = 4;
pub(crate) const LISTENER_EXIT: usize = 5;

#[repr(C)]
#[derive(Clone, Copy)]
struct ListenerState {
    active: u8,
    denied: u8,
    fd: c_int,
    nonblocking: u8,
    duplicate: u8,
    guard: *mut HookGuard,
}

impl Default for ListenerState {
    fn default() -> Self {
        Self {
            active: 0,
            denied: 0,
            fd: -1,
            nonblocking: 0,
            duplicate: 0,
            guard: std::ptr::null_mut(),
        }
    }
}

pub(crate) unsafe extern "C" fn variadic_on_enter(
    context: *mut gum::GumInvocationContext,
    data: *mut c_void,
) {
    let state = gum::invocation_data::<ListenerState>(context);
    if state.is_null() {
        return;
    }
    state.write(ListenerState::default());
    if data as usize == LISTENER_EXIT {
        record_exit_status(
            gum::argument(context, 0) as usize as c_int,
            std::ptr::null_mut(),
        );
        return;
    }
    let kind = data as usize;
    if matches!(kind, LISTENER_OPEN | LISTENER_OPENAT) && child_policy_denied() {
        (*state).active = 1;
        (*state).denied = 1;
        gum::replace_argument(
            context,
            u32::from(kind == LISTENER_OPENAT),
            c"".as_ptr() as *mut c_void,
        );
        return;
    }
    let Some(guard) = HookGuard::enter() else {
        return;
    };
    (*state).guard = Box::into_raw(Box::new(guard));
    (*state).active = 1;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let kind = data as usize;
        hook_hit(match kind {
            LISTENER_OPEN => 9,
            LISTENER_OPENAT => 11,
            LISTENER_FCNTL => 7,
            LISTENER_IOCTL => 8,
            _ => 0,
        });
        match kind {
            LISTENER_OPEN => inspect_open(context, state, false),
            LISTENER_OPENAT => inspect_open(context, state, true),
            LISTENER_FCNTL => inspect_fcntl(context, state),
            LISTENER_IOCTL => inspect_ioctl(context, state),
            _ => {}
        }
    }));
    if result.is_err() {
        (*state).active = 0;
        drop(Box::from_raw(std::mem::replace(
            &mut (*state).guard,
            std::ptr::null_mut(),
        )));
    }
}

pub(crate) unsafe extern "C" fn variadic_on_leave(
    context: *mut gum::GumInvocationContext,
    _data: *mut c_void,
) {
    let state = gum::invocation_data::<ListenerState>(context);
    if state.is_null() || (*state).active == 0 {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if (*state).denied != 0 {
            *libc::__errno_location() = libc::EACCES;
            gum::replace_system_error(context, libc::EACCES);
            gum::replace_return_value(context, usize::MAX as *mut c_void);
        } else if gum::return_value(context) as isize >= 0 && (*state).duplicate != 0 {
            let _ = crate::hh_agent_dup_socket(
                (*state).fd as u64,
                gum::return_value(context) as usize as u64,
            );
        } else if gum::return_value(context) as isize >= 0 && (*state).fd >= 0 {
            let _ = crate::hh_agent_note_nonblocking(
                (*state).fd as u64,
                u32::from((*state).nonblocking != 0),
            );
        }
    }));
    (*state).active = 0;
    let guard = std::mem::replace(&mut (*state).guard, std::ptr::null_mut());
    if !guard.is_null() {
        drop(Box::from_raw(guard));
    }
}

unsafe fn inspect_open(
    context: *mut gum::GumInvocationContext,
    state: *mut ListenerState,
    at: bool,
) {
    let path_index = u32::from(at);
    let flags_index = path_index + 1;
    let path = gum::argument(context, path_index).cast::<libc::c_char>();
    let flags = gum::argument(context, flags_index) as usize as c_int;
    if path.is_null() {
        return;
    }
    let Ok(raw) = CStr::from_ptr(path).to_str() else {
        return;
    };
    let path = if at {
        let dirfd = gum::argument(context, 0) as usize as c_int;
        relative_path(dirfd, raw)
    } else {
        cpath_string(raw)
    };
    for operation in file_operations_for_flags(flags) {
        if !crate::file_allows(&path, operation) {
            audit(crate::SandboxAuditKind::File, "open", &path);
            (*state).denied = 1;
            gum::replace_argument(
                context,
                path_index,
                c"/proc/self/fd/-1/hyperhub-denied".as_ptr() as *mut c_void,
            );
            break;
        }
    }
}

unsafe fn inspect_fcntl(context: *mut gum::GumInvocationContext, state: *mut ListenerState) {
    let command = gum::argument(context, 1) as usize as c_int;
    if command == libc::F_DUPFD || command == libc::F_DUPFD_CLOEXEC {
        (*state).fd = gum::argument(context, 0) as usize as c_int;
        (*state).duplicate = 1;
    } else if command == libc::F_SETFL {
        let flags = gum::argument(context, 2) as usize as c_int;
        (*state).fd = gum::argument(context, 0) as usize as c_int;
        (*state).nonblocking = u8::from(flags & libc::O_NONBLOCK != 0);
    }
}

unsafe fn inspect_ioctl(context: *mut gum::GumInvocationContext, state: *mut ListenerState) {
    let request = gum::argument(context, 1) as usize as libc::c_ulong;
    if request == libc::FIONBIO as libc::c_ulong {
        let value = gum::argument(context, 2).cast::<c_int>();
        if !value.is_null() {
            (*state).fd = gum::argument(context, 0) as usize as c_int;
            (*state).nonblocking = u8::from(value.read_unaligned() != 0);
        }
    }
}

pub unsafe extern "C" fn creat(path: *const libc::c_char, mode: libc::mode_t) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(13);
    let original: unsafe extern "C" fn(*const libc::c_char, libc::mode_t) -> c_int =
        symbol(c"creat");
    let Some(_guard) = HookGuard::enter() else {
        return original(path, mode);
    };
    if let Some(path) = cpath(path) {
        for operation in [
            crate::FileSandboxOperation::Create,
            crate::FileSandboxOperation::Write,
        ] {
            if !crate::file_allows(&path, operation) {
                audit(crate::SandboxAuditKind::File, "open", &path);
                *libc::__errno_location() = libc::EACCES;
                return -1;
            }
        }
    }
    original(path, mode)
}

pub unsafe extern "C" fn read(fd: c_int, b: *mut c_void, n: usize) -> isize {
    hook_hit(14);
    let original = read_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, b, n);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    if let Ok(p) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
        if !crate::file_allows(&p.to_string_lossy(), crate::FileSandboxOperation::Read) {
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    original(fd, b, n)
}
pub unsafe extern "C" fn write(fd: c_int, b: *const c_void, n: usize) -> isize {
    hook_hit(15);
    let original = write_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(fd, b, n);
    };
    if !ensure_handshake(fd) {
        *libc::__errno_location() = libc::ECONNRESET;
        return -1;
    }
    if let Ok(p) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
        if !crate::file_allows(&p.to_string_lossy(), crate::FileSandboxOperation::Write) {
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    original(fd, b, n)
}
pub unsafe extern "C" fn unlink(path: *const libc::c_char) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(16);
    let original = unlink_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(path);
    };
    if let Some(p) = cpath(path) {
        if !crate::file_allows(&p, crate::FileSandboxOperation::Delete) {
            audit(crate::SandboxAuditKind::File, "delete", &p);
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    original(path)
}
// A new hardlink grants another name for the same data. Authorize the source
// as both content disclosure and namespace mutation, and the new name as create.
fn hardlink_allowed(source: &str, destination: &str, follow: bool) -> bool {
    crate::file_link_source_allows(source, follow)
        && crate::file_allows(destination, crate::FileSandboxOperation::Create)
}
pub unsafe extern "C" fn link(old: *const libc::c_char, new: *const libc::c_char) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(40);
    let original: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> c_int =
        symbol(c"link");
    let Some(_guard) = HookGuard::enter() else {
        return original(old, new);
    };
    let saved_errno = *libc::__errno_location();
    if let (Some(source), Some(destination)) = (cpath(old), cpath(new)) {
        if !hardlink_allowed(&source, &destination, false) {
            audit(crate::SandboxAuditKind::File, "link", &source);
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    *libc::__errno_location() = saved_errno;
    original(old, new)
}
pub unsafe extern "C" fn linkat(
    od: c_int,
    old: *const libc::c_char,
    nd: c_int,
    new: *const libc::c_char,
    flags: c_int,
) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(41);
    let original: unsafe extern "C" fn(
        c_int,
        *const libc::c_char,
        c_int,
        *const libc::c_char,
        c_int,
    ) -> c_int = symbol(c"linkat");
    let Some(_guard) = HookGuard::enter() else {
        return original(od, old, nd, new, flags);
    };
    let saved_errno = *libc::__errno_location();
    // Read raw names before resolving dirfds. cpath() would incorrectly turn a
    // relative name into an absolute cwd path before applying its dirfd.
    let old_raw = if old.is_null() {
        None
    } else {
        CStr::from_ptr(old).to_str().ok()
    };
    let new_raw = if new.is_null() {
        None
    } else {
        CStr::from_ptr(new).to_str().ok()
    };
    if let (Some(raw), Some(destination)) = (old_raw, new_raw) {
        let source = if raw.is_empty() && flags & libc::AT_EMPTY_PATH != 0 {
            std::fs::read_link(format!("/proc/self/fd/{od}"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        } else {
            Some(relative_path(od, raw))
        };
        if let Some(source) = source {
            let destination = relative_path(nd, destination);
            if !hardlink_allowed(
                &source,
                &destination,
                !raw.is_empty() && flags & libc::AT_SYMLINK_FOLLOW != 0,
            ) {
                audit(crate::SandboxAuditKind::File, "linkat", &source);
                *libc::__errno_location() = libc::EACCES;
                return -1;
            }
        }
    }
    *libc::__errno_location() = saved_errno;
    original(od, old, nd, new, flags)
}
fn rename_allowed(source: &str, destination: &str) -> bool {
    crate::file_link_source_allows(source, false)
        && crate::file_allows(destination, crate::FileSandboxOperation::Create)
        && crate::file_allows(destination, crate::FileSandboxOperation::Rename)
}
pub unsafe extern "C" fn rename(old: *const libc::c_char, new: *const libc::c_char) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(18);
    let original = rename_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(old, new);
    };
    let saved_errno = *libc::__errno_location();
    if let (Some(source), Some(destination)) = (cpath(old), cpath(new)) {
        if !rename_allowed(&source, &destination) {
            audit(crate::SandboxAuditKind::File, "rename", &source);
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    *libc::__errno_location() = saved_errno;
    original(old, new)
}
pub unsafe extern "C" fn unlinkat(dirfd: c_int, path: *const libc::c_char, flags: c_int) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(17);
    let f: unsafe extern "C" fn(c_int, *const libc::c_char, c_int) -> c_int = symbol(c"unlinkat");
    let Some(_guard) = HookGuard::enter() else {
        return f(dirfd, path, flags);
    };
    if let Some(raw) = cpath(path) {
        let p = relative_path(dirfd, &raw);
        if !crate::file_allows(&p, crate::FileSandboxOperation::Delete) {
            audit(crate::SandboxAuditKind::File, "delete", &p);
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    f(dirfd, path, flags)
}
pub unsafe extern "C" fn renameat(
    od: c_int,
    old: *const libc::c_char,
    nd: c_int,
    new: *const libc::c_char,
) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(19);
    let f: unsafe extern "C" fn(c_int, *const libc::c_char, c_int, *const libc::c_char) -> c_int =
        symbol(c"renameat");
    let Some(_guard) = HookGuard::enter() else {
        return f(od, old, nd, new);
    };
    let saved_errno = *libc::__errno_location();
    if !old.is_null() && !new.is_null() {
        if let (Ok(source), Ok(destination)) =
            (CStr::from_ptr(old).to_str(), CStr::from_ptr(new).to_str())
        {
            let source = relative_path(od, source);
            let destination = relative_path(nd, destination);
            if !rename_allowed(&source, &destination) {
                audit(crate::SandboxAuditKind::File, "rename", &source);
                *libc::__errno_location() = libc::EACCES;
                return -1;
            }
        }
    }
    *libc::__errno_location() = saved_errno;
    f(od, old, nd, new)
}

pub unsafe extern "C" fn renameat2(
    od: c_int,
    old: *const libc::c_char,
    nd: c_int,
    new: *const libc::c_char,
    flags: libc::c_uint,
) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(37);
    let original = renameat2_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(od, old, nd, new, flags);
    };
    let saved_errno = *libc::__errno_location();
    if !old.is_null() && !new.is_null() {
        if let (Ok(source), Ok(destination)) =
            (CStr::from_ptr(old).to_str(), CStr::from_ptr(new).to_str())
        {
            let source = relative_path(od, source);
            let destination = relative_path(nd, destination);
            if !rename_allowed(&source, &destination)
                || (flags & libc::RENAME_EXCHANGE != 0
                    && !crate::file_link_source_allows(&destination, false))
            {
                audit(crate::SandboxAuditKind::File, "rename", &source);
                *libc::__errno_location() = libc::EACCES;
                return -1;
            }
        }
    }
    *libc::__errno_location() = saved_errno;
    original(od, old, nd, new, flags)
}
fn housekeeping_allowed() -> bool {
    !super::super::fork::awaiting_rebuild()
        && !crate::engine_call::host_background()
        && INSIDE_HOOK.with(|inside| !inside.get())
}
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    hook_hit(6);
    if housekeeping_allowed() {
        let _ = crate::hh_agent_close_socket(fd as u64);
    }
    let f: unsafe extern "C" fn(c_int) -> c_int = symbol(c"close");
    f(fd)
}

pub unsafe extern "C" fn dup(fd: c_int) -> c_int {
    hook_hit(26);
    let f: unsafe extern "C" fn(c_int) -> c_int = symbol(c"dup");
    let result = f(fd);
    if result >= 0 && housekeeping_allowed() {
        let _ = crate::hh_agent_dup_socket(fd as u64, result as u64);
    }
    result
}

pub unsafe extern "C" fn dup2(fd: c_int, destination: c_int) -> c_int {
    hook_hit(27);
    let f: unsafe extern "C" fn(c_int, c_int) -> c_int = symbol(c"dup2");
    let result = f(fd, destination);
    if result >= 0 && housekeeping_allowed() {
        let _ = crate::hh_agent_dup_socket(fd as u64, result as u64);
    }
    result
}

pub unsafe extern "C" fn dup3(fd: c_int, destination: c_int, flags: c_int) -> c_int {
    hook_hit(28);
    let f: unsafe extern "C" fn(c_int, c_int, c_int) -> c_int = symbol(c"dup3");
    let result = f(fd, destination, flags);
    if result >= 0 && housekeeping_allowed() {
        let _ = crate::hh_agent_dup_socket(fd as u64, result as u64);
    }
    result
}
fn mapping_operations(prot: c_int) -> Vec<crate::FileSandboxOperation> {
    let mut operations = Vec::new();
    if prot & (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0 {
        operations.push(crate::FileSandboxOperation::Read);
    }
    if prot & libc::PROT_WRITE != 0 {
        operations.push(crate::FileSandboxOperation::Write);
    }
    operations
}

pub unsafe extern "C" fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int {
    if prot != libc::PROT_NONE && child_policy_denied() {
        return -1;
    }
    hook_hit(24);
    let f: unsafe extern "C" fn(*mut c_void, usize, c_int) -> c_int = symbol(c"mprotect");
    if prot & (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
        return f(addr, len, prot);
    }
    let Some(_guard) = HookGuard::enter() else {
        return f(addr, len, prot);
    };
    for path in mapped_file_paths(addr as usize, len) {
        for operation in mapping_operations(prot) {
            if !crate::file_allows(&path, operation) {
                audit(crate::SandboxAuditKind::File, "protect", &path);
                *libc::__errno_location() = libc::EACCES;
                return -1;
            }
        }
    }
    f(addr, len, prot)
}
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: usize) -> c_int {
    hook_hit(25);
    let f: unsafe extern "C" fn(*mut c_void, usize) -> c_int = symbol(c"munmap");
    f(addr, len)
}

unsafe fn inherited_environment(
    envp: *const *const libc::c_char,
    should_hook: bool,
) -> (Vec<CString>, Vec<*const libc::c_char>) {
    let mut values = Vec::<CString>::new();
    let mut keys = std::collections::HashSet::<Vec<u8>>::new();
    if !envp.is_null() {
        let mut index = 0;
        while !(*envp.add(index)).is_null() {
            let bytes = CStr::from_ptr(*envp.add(index)).to_bytes().to_vec();
            let key = bytes
                .split(|b| *b == b'=')
                .next()
                .unwrap_or_default()
                .to_vec();
            keys.insert(key);
            if let Ok(value) = CString::new(bytes) {
                values.push(value)
            }
            index += 1
        }
    }
    for (key, value) in std::env::vars_os() {
        let key_bytes = OsStr::new(&key).as_bytes();
        let inherit = key_bytes.starts_with(b"HYPERHUB_")
            || matches!(
                key_bytes,
                b"SSL_CERT_FILE" | b"SSL_CERT_DIR" | b"CURL_CA_BUNDLE"
            );
        if !inherit {
            continue;
        }
        let mut bytes = key_bytes.to_vec();
        bytes.push(b'=');
        bytes.extend_from_slice(OsStr::new(&value).as_bytes());
        let key_vec = key_bytes.to_vec();
        if let Some(position) = values
            .iter()
            .position(|item| item.to_bytes().starts_with(&[key_bytes, b"="].concat()))
        {
            values.remove(position);
        }
        if let Ok(item) = CString::new(bytes) {
            values.push(item)
        }
        keys.insert(key_vec);
    }
    values.retain(|value| !value.to_bytes().starts_with(b"HYPERHUB_SKIP_AGENT="));
    if !should_hook {
        values.push(CString::new("HYPERHUB_SKIP_AGENT=1").expect("static environment"));
    }
    let mut pointers = values
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    pointers.push(std::ptr::null());
    (values, pointers)
}
unsafe fn command_line(argv: *const *const libc::c_char) -> String {
    let mut result = String::new();
    if argv.is_null() {
        return result;
    }
    let mut i = 0;
    while !(*argv.add(i)).is_null() {
        if let Ok(value) = CStr::from_ptr(*argv.add(i)).to_str() {
            if !result.is_empty() {
                result.push(' ')
            }
            result.push_str(value)
        }
        i += 1
    }
    result
}
fn normalize_executable(path: &str) -> String {
    let path = std::path::PathBuf::from(path);
    let resolved = if path.is_absolute() {
        std::fs::canonicalize(&path).unwrap_or(path)
    } else if path.components().count() > 1 {
        std::env::current_dir()
            .map(|current| current.join(&path))
            .ok()
            .and_then(|candidate| std::fs::canonicalize(&candidate).ok().or(Some(candidate)))
            .unwrap_or(path)
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join(&path))
            .find(|candidate| candidate.is_file())
            .and_then(|candidate| std::fs::canonicalize(&candidate).ok().or(Some(candidate)))
            .unwrap_or(path)
    };
    resolved.to_string_lossy().into_owned()
}

unsafe fn process_target(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
) -> Option<(String, String)> {
    let path = CStr::from_ptr(path).to_str().ok()?;
    Some((normalize_executable(path), command_line(argv)))
}

fn process_hook_enabled(executable: &str) -> bool {
    let endpoint = std::env::var("HYPERHUB_CONTROL_ENDPOINT").ok();
    let session_id = std::env::var("HYPERHUB_SESSION_ID").ok();
    let token = std::env::var("HYPERHUB_SESSION_TOKEN").ok();
    match (endpoint, session_id, token) {
        (Some(endpoint), Some(session_id), Some(token)) => {
            crate::control::decide_process_hook(&endpoint, &session_id, &token, executable).hook
        }
        _ => true,
    }
}

pub unsafe extern "C" fn execve(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> c_int {
    if child_policy_denied() {
        return -1;
    }
    hook_hit(20);
    let original = execve_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(path, argv, envp);
    };
    let target = process_target(path, argv);
    if target
        .as_ref()
        .is_some_and(|(executable, command)| !crate::process_allows(executable, command))
    {
        audit(
            crate::SandboxAuditKind::Process,
            "create",
            &target.as_ref().unwrap().0,
        );
        *libc::__errno_location() = libc::EACCES;
        return -1;
    }
    let should_hook = target
        .as_ref()
        .is_none_or(|(executable, _)| process_hook_enabled(executable));
    let (_values, pointers) = inherited_environment(envp, should_hook);
    original(path, argv, pointers.as_ptr())
}
type SpawnFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const libc::c_char,
    *const libc::posix_spawn_file_actions_t,
    *const libc::posix_spawnattr_t,
    *const *mut libc::c_char,
    *const *mut libc::c_char,
) -> c_int;
unsafe fn spawn_impl(
    symbol_name: &CStr,
    report_id: usize,
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    actions: *const libc::posix_spawn_file_actions_t,
    attributes: *const libc::posix_spawnattr_t,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> c_int {
    if child_policy_denied() {
        return libc::EACCES;
    }
    hook_hit(report_id);
    let original: SpawnFn = symbol(symbol_name);
    let Some(_guard) = HookGuard::enter() else {
        return original(pid, path, actions, attributes, argv, envp);
    };
    let target = process_target(path, argv as *const *const libc::c_char);
    if target
        .as_ref()
        .is_some_and(|(executable, command)| !crate::process_allows(executable, command))
    {
        audit(
            crate::SandboxAuditKind::Process,
            "create",
            &target.as_ref().unwrap().0,
        );
        return libc::EACCES;
    }
    let should_hook = target
        .as_ref()
        .is_none_or(|(executable, _)| process_hook_enabled(executable));
    let (_values, pointers) =
        inherited_environment(envp as *const *const libc::c_char, should_hook);
    let mut child_pid = 0;
    // Linux also accepts a null PID output. Obtain a private output in that
    // case without changing what the caller supplied or receives.
    let output_pid = if should_hook && pid.is_null() {
        &mut child_pid
    } else {
        pid
    };
    let result = original(
        output_pid,
        path,
        actions,
        attributes,
        argv,
        pointers.as_ptr() as *const *mut libc::c_char,
    );
    let saved_errno = *libc::__errno_location();
    if result == 0 && should_hook {
        let child_pid = *output_pid;
        if super::spawn_admission::await_registration(child_pid).is_err()
            && std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some()
        {
            eprintln!("hyperhub-gum: posix_spawn registration was not acknowledged pid={child_pid}; retaining the original spawn result");
        }
    }
    drop(pointers);
    drop(_values);
    drop(_guard);
    *libc::__errno_location() = saved_errno;
    result
}
pub unsafe extern "C" fn posix_spawn(
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    actions: *const libc::posix_spawn_file_actions_t,
    attributes: *const libc::posix_spawnattr_t,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> c_int {
    spawn_impl(
        c"posix_spawn",
        21,
        pid,
        path,
        actions,
        attributes,
        argv,
        envp,
    )
}
pub unsafe extern "C" fn posix_spawnp(
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    actions: *const libc::posix_spawn_file_actions_t,
    attributes: *const libc::posix_spawnattr_t,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> c_int {
    spawn_impl(
        c"posix_spawnp",
        22,
        pid,
        path,
        actions,
        attributes,
        argv,
        envp,
    )
}

pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    off: libc::off_t,
) -> *mut c_void {
    if fd >= 0 && flags & libc::MAP_ANONYMOUS == 0 && child_policy_denied() {
        return libc::MAP_FAILED;
    }
    hook_hit(23);
    let original = mmap_fn();
    // Anonymous allocator mappings carry no file-policy work. In particular,
    // do not register generation TLS destructors while a loader-created thread
    // allocates its first heap under the dynamic loader's rendezvous lock.
    if fd < 0 || flags & libc::MAP_ANONYMOUS != 0 {
        return original(addr, len, prot, flags, fd, off);
    }
    let Some(_guard) = HookGuard::enter() else {
        return original(addr, len, prot, flags, fd, off);
    };
    if fd >= 0 && flags & libc::MAP_ANONYMOUS == 0 {
        if let Ok(path) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
            for operation in mapping_operations(prot) {
                if !crate::file_allows(&path.to_string_lossy(), operation) {
                    audit(
                        crate::SandboxAuditKind::File,
                        "map",
                        &path.to_string_lossy(),
                    );
                    *libc::__errno_location() = libc::EACCES;
                    return libc::MAP_FAILED;
                }
            }
        }
    }
    original(addr, len, prot, flags, fd, off)
}

pub unsafe extern "C" fn freeaddrinfo(result: *mut addrinfo) {
    hook_hit(2);
    free_fn()(result)
}

fn mapped_file_paths(address: usize, length: usize) -> Vec<String> {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return Vec::new();
    };
    let requested_end = address.saturating_add(length);
    let mut paths = std::collections::BTreeSet::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some((start, end)) = fields
            .next()
            .and_then(|range| range.split_once('-'))
            .and_then(|(start, end)| {
                Some((
                    usize::from_str_radix(start, 16).ok()?,
                    usize::from_str_radix(end, 16).ok()?,
                ))
            })
        else {
            continue;
        };
        if start >= requested_end || end <= address {
            continue;
        }
        let Some(path) = fields.nth(4) else {
            continue;
        };
        if path.starts_with('/') {
            paths.insert(path.strip_suffix(" (deleted)").unwrap_or(path).to_owned());
        }
    }
    paths.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_access_modes_preserve_all_requested_content_permissions() {
        use crate::FileSandboxOperation::{Create, Read, Write};
        for (flags, expected) in [
            (libc::O_RDONLY, vec![Read]),
            (libc::O_WRONLY, vec![Write]),
            (libc::O_RDWR, vec![Read, Write]),
            (libc::O_CREAT | libc::O_RDONLY, vec![Create, Read]),
            (libc::O_CREAT | libc::O_WRONLY, vec![Create, Write]),
            (libc::O_CREAT | libc::O_RDWR, vec![Create, Read, Write]),
            (libc::O_TRUNC | libc::O_RDONLY, vec![Read, Write]),
            (
                libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR,
                vec![Create, Read, Write],
            ),
        ] {
            assert_eq!(
                file_operations_for_flags(flags),
                expected,
                "open flags {flags}"
            );
        }
    }
}
