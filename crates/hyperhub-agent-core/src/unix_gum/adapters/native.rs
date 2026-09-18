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

static HOOK_HITS: [AtomicU64; 26] = [const { AtomicU64::new(0) }; 26];
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
];

fn hook_hit(id: usize) {
    if HOOK_REPORT_ENABLED.load(Ordering::Relaxed) && id < HOOK_HITS.len() {
        HOOK_HITS[id].fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn install_hook_report() {
    if std::env::var_os("HYPERHUB_DYNAMIC_HOOK_REPORT").is_none() {
        return;
    }
    INSTALL_HOOK_REPORT.call_once(|| unsafe {
        HOOK_REPORT_ENABLED.store(true, Ordering::Release);
        libc::atexit(write_hook_report);
    });
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
struct HookGuard;
impl HookGuard {
    fn enter() -> Option<Self> {
        INSIDE_HOOK.with(|inside| {
            if inside.replace(true) {
                None
            } else {
                Some(Self)
            }
        })
    }
}
impl Drop for HookGuard {
    fn drop(&mut self) {
        INSIDE_HOOK.with(|inside| inside.set(false));
    }
}

type ConnectFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
type SendFn = unsafe extern "C" fn(c_int, *const c_void, usize, c_int) -> isize;
type RecvFn = unsafe extern "C" fn(c_int, *mut c_void, usize, c_int) -> isize;
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
fn gai_fn() -> GetAddrInfoFn {
    static F: OnceLock<GetAddrInfoFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"getaddrinfo"))
}
fn free_fn() -> FreeAddrInfoFn {
    static F: OnceLock<FreeAddrInfoFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"freeaddrinfo"))
}

pub unsafe extern "C" fn connect(fd: c_int, address: *const sockaddr, length: socklen_t) -> c_int {
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
    if plan.proxy_family == 2 {
        let p = &mut *(&mut proxy as *mut _ as *mut sockaddr_in);
        p.sin_family = AF_INET as u16;
        p.sin_port = plan.proxy_port.to_be();
        p.sin_addr.s_addr = u32::from_ne_bytes(plan.proxy_address[..4].try_into().unwrap());
        if original(
            fd,
            &proxy as *const _ as *const sockaddr,
            size_of::<sockaddr_in>() as socklen_t,
        ) < 0
        {
            return -1;
        }
    } else {
        let p = &mut *(&mut proxy as *mut _ as *mut sockaddr_in6);
        p.sin6_family = AF_INET6 as u16;
        p.sin6_port = plan.proxy_port.to_be();
        p.sin6_addr.s6_addr = plan.proxy_address;
        if original(
            fd,
            &proxy as *const _ as *const sockaddr,
            size_of::<sockaddr_in6>() as socklen_t,
        ) < 0
        {
            return -1;
        }
    }
    for phase in 0..3 {
        let mut out = [0u8; 512];
        let mut written = 0usize;
        if crate::hh_agent_build_handshake(
            fd as u64,
            phase,
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        ) != crate::HH_OK
        {
            return -1;
        }
        if send_fn()(fd, out.as_ptr() as *const c_void, written, 0) < 0 {
            return -1;
        }
        let mut input = [0u8; 512];
        let n = recv_fn()(fd, input.as_mut_ptr() as *mut c_void, input.len(), 0);
        if n < 0 {
            return -1;
        }
        if crate::hh_agent_validate_handshake_reply(phase, input.as_ptr(), n as usize)
            != crate::HH_OK
        {
            return -1;
        }
    }
    crate::hh_agent_set_handshake_complete(fd as u64);
    0
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
    let result = original(fd, buffer, length, flags);
    let _ = crate::hh_agent_note_io(fd as u64, result as i64);
    result
}
pub unsafe extern "C" fn getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const addrinfo,
    result: *mut *mut addrinfo,
) -> c_int {
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
fn execve_fn() -> ExecveFn {
    static F: OnceLock<ExecveFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"execve"))
}
fn mmap_fn() -> MmapFn {
    static F: OnceLock<MmapFn> = OnceLock::new();
    *F.get_or_init(|| symbol(c"mmap"))
}
fn audit(kind: crate::SandboxAuditKind, operation: &str, target: &str) {
    let event = crate::SandboxAuditEvent {
        kind,
        decision: crate::SandboxAction::Deny,
        rule_id: None,
        source: "rule".into(),
        operation: operation.into(),
        target: target.into(),
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
fn file_operation_for_flags(flags: c_int) -> crate::FileSandboxOperation {
    if flags & libc::O_CREAT != 0 {
        return crate::FileSandboxOperation::Create;
    }
    if flags & libc::O_ACCMODE == libc::O_RDONLY {
        crate::FileSandboxOperation::Read
    } else {
        crate::FileSandboxOperation::Write
    }
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

#[repr(C)]
#[derive(Clone, Copy)]
struct ListenerState {
    active: u8,
    denied: u8,
    fd: c_int,
    nonblocking: u8,
}

impl Default for ListenerState {
    fn default() -> Self {
        Self {
            active: 0,
            denied: 0,
            fd: -1,
            nonblocking: 0,
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
    let active = INSIDE_HOOK.with(|inside| !inside.replace(true));
    if !active {
        return;
    }
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
        INSIDE_HOOK.with(|inside| inside.set(false));
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
            gum::replace_return_value(context, usize::MAX as *mut c_void);
        } else if gum::return_value(context) as isize >= 0 && (*state).fd >= 0 {
            let _ = crate::hh_agent_note_nonblocking(
                (*state).fd as u64,
                u32::from((*state).nonblocking != 0),
            );
        }
    }));
    INSIDE_HOOK.with(|inside| inside.set(false));
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
    if !crate::file_allows(&path, file_operation_for_flags(flags)) {
        audit(crate::SandboxAuditKind::File, "open", &path);
        (*state).denied = 1;
        gum::replace_argument(
            context,
            path_index,
            c"/proc/self/fd/-1/hyperhub-denied".as_ptr() as *mut c_void,
        );
    }
}

unsafe fn inspect_fcntl(context: *mut gum::GumInvocationContext, state: *mut ListenerState) {
    let command = gum::argument(context, 1) as usize as c_int;
    if command == libc::F_SETFL {
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
    hook_hit(13);
    let original: unsafe extern "C" fn(*const libc::c_char, libc::mode_t) -> c_int =
        symbol(c"creat");
    let Some(_guard) = HookGuard::enter() else {
        return original(path, mode);
    };
    if let Some(path) = cpath(path) {
        if !crate::file_allows(&path, crate::FileSandboxOperation::Create) {
            audit(crate::SandboxAuditKind::File, "open", &path);
            *libc::__errno_location() = libc::EACCES;
            return -1;
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
    if let Ok(p) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
        if !crate::file_allows(&p.to_string_lossy(), crate::FileSandboxOperation::Write) {
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    original(fd, b, n)
}
pub unsafe extern "C" fn unlink(path: *const libc::c_char) -> c_int {
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
pub unsafe extern "C" fn rename(old: *const libc::c_char, new: *const libc::c_char) -> c_int {
    hook_hit(18);
    let original = rename_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(old, new);
    };
    if let Some(p) = cpath(old) {
        if !crate::file_allows(&p, crate::FileSandboxOperation::Rename) {
            audit(crate::SandboxAuditKind::File, "rename", &p);
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    original(old, new)
}
pub unsafe extern "C" fn unlinkat(dirfd: c_int, path: *const libc::c_char, flags: c_int) -> c_int {
    hook_hit(17);
    if let Some(raw) = cpath(path) {
        let p = relative_path(dirfd, &raw);
        if !crate::file_allows(&p, crate::FileSandboxOperation::Delete) {
            audit(crate::SandboxAuditKind::File, "delete", &p);
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    let f: unsafe extern "C" fn(c_int, *const libc::c_char, c_int) -> c_int = symbol(c"unlinkat");
    f(dirfd, path, flags)
}
pub unsafe extern "C" fn renameat(
    od: c_int,
    old: *const libc::c_char,
    nd: c_int,
    new: *const libc::c_char,
) -> c_int {
    hook_hit(19);
    if let Some(raw) = cpath(old) {
        let p = relative_path(od, &raw);
        if !crate::file_allows(&p, crate::FileSandboxOperation::Rename) {
            audit(crate::SandboxAuditKind::File, "rename", &p);
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    let f: unsafe extern "C" fn(c_int, *const libc::c_char, c_int, *const libc::c_char) -> c_int =
        symbol(c"renameat");
    f(od, old, nd, new)
}
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    hook_hit(6);
    let _ = crate::hh_agent_close_socket(fd as u64);
    let f: unsafe extern "C" fn(c_int) -> c_int = symbol(c"close");
    f(fd)
}
pub unsafe extern "C" fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int {
    hook_hit(24);
    let f: unsafe extern "C" fn(*mut c_void, usize, c_int) -> c_int = symbol(c"mprotect");
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
    original(
        pid,
        path,
        actions,
        attributes,
        argv,
        pointers.as_ptr() as *const *mut libc::c_char,
    )
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
    hook_hit(23);
    let original = mmap_fn();
    let Some(_guard) = HookGuard::enter() else {
        return original(addr, len, prot, flags, fd, off);
    };
    if fd >= 0 && prot & libc::PROT_WRITE != 0 {
        if let Ok(p) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
            if !crate::file_allows(&p.to_string_lossy(), crate::FileSandboxOperation::Write) {
                audit(crate::SandboxAuditKind::File, "write", &p.to_string_lossy());
                *libc::__errno_location() = libc::EACCES;
                return libc::MAP_FAILED;
            }
        }
    }
    original(addr, len, prot, flags, fd, off)
}

pub unsafe extern "C" fn freeaddrinfo(result: *mut addrinfo) {
    hook_hit(2);
    free_fn()(result)
}
