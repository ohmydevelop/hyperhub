//! Exact ownership of HyperHub's Unix control sockets across ordinary fork.
//!
//! Only constructors in this module enroll descriptors. Application sockets are
//! never inspected. The fork fence covers socket creation/registration and close,
//! never connect, protocol I/O, allocation, or an application/Engine lock.
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};

const CAPACITY: usize = 4096;
struct Slot {
    fd: AtomicI32,
    generation: AtomicU64,
}
static SLOTS: [Slot; CAPACITY] = [const {
    Slot {
        fd: AtomicI32::new(-1),
        generation: AtomicU64::new(0),
    }
}; CAPACITY];
static NEXT: AtomicU64 = AtomicU64::new(1);
static OWNER: AtomicUsize = AtomicUsize::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);

fn thread_id() -> usize {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::syscall(libc::SYS_gettid) as usize
    }
    #[cfg(not(target_os = "linux"))]
    unsafe {
        libc::pthread_self() as usize
    }
}
fn acquire() {
    let owner = thread_id();
    loop {
        if OWNER.load(Ordering::Acquire) == owner {
            DEPTH.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if OWNER
            .compare_exchange_weak(0, owner, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            DEPTH.store(1, Ordering::Relaxed);
            return;
        }
        std::hint::spin_loop();
    }
}
fn release() {
    if DEPTH.fetch_sub(1, Ordering::Relaxed) == 1 {
        OWNER.store(0, Ordering::Release);
    }
}
struct Fence {
    pid: libc::pid_t,
}
impl Fence {
    fn enter() -> Self {
        acquire();
        Self {
            pid: unsafe { libc::getpid() },
        }
    }
}
impl Drop for Fence {
    fn drop(&mut self) {
        if self.pid == unsafe { libc::getpid() } {
            release();
        }
    }
}
unsafe fn close_raw(fd: RawFd) {
    // Bypass Gum's close hook: it may acquire Engine state while a prepare
    // callback owns that state, and no hook/TLS machinery may run in the child.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::syscall(libc::SYS_close, fd);
    }
    #[cfg(not(target_os = "linux"))]
    unsafe {
        libc::close(fd);
    }
}
struct Ownership {
    fd: RawFd,
    pid: libc::pid_t,
    slot: usize,
    generation: u64,
}
impl Ownership {
    // Called with the fence held, immediately after an unhooked creation call.
    fn register(fd: RawFd) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(not(target_os = "linux"))]
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            let error = io::Error::last_os_error();
            unsafe { close_raw(fd) };
            return Err(error);
        }
        for (index, slot) in SLOTS.iter().enumerate() {
            if slot.fd.load(Ordering::Relaxed) == -1 {
                let generation = NEXT.fetch_add(1, Ordering::Relaxed);
                slot.generation.store(generation, Ordering::Relaxed);
                slot.fd.store(fd, Ordering::Release);
                return Ok(Self {
                    fd,
                    pid: unsafe { libc::getpid() },
                    slot: index,
                    generation,
                });
            }
        }
        unsafe { close_raw(fd) };
        Err(io::Error::from_raw_os_error(libc::EMFILE))
    }
    fn current(&self) -> bool {
        self.pid == unsafe { libc::getpid() }
            && SLOTS[self.slot].generation.load(Ordering::Acquire) == self.generation
            && SLOTS[self.slot].fd.load(Ordering::Acquire) == self.fd
    }
    fn check(&self) -> io::Result<()> {
        if self.current() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "control socket belongs to a previous process generation",
            ))
        }
    }
}
impl Drop for Ownership {
    fn drop(&mut self) {
        // A copied object must neither acquire a vanished parent's lock nor close
        // a newly reused descriptor in the child.
        if self.pid != unsafe { libc::getpid() } {
            return;
        }
        let _fence = Fence::enter();
        if self.current() {
            unsafe { close_raw(self.fd) };
            SLOTS[self.slot].fd.store(-1, Ordering::Release);
        }
    }
}
fn socket(nonblocking: bool) -> io::Result<Ownership> {
    let _fence = Fence::enter();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let kind =
        libc::SOCK_STREAM | libc::SOCK_CLOEXEC | if nonblocking { libc::SOCK_NONBLOCK } else { 0 };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let kind = libc::SOCK_STREAM;
    #[cfg(target_os = "linux")]
    let fd = unsafe { libc::syscall(libc::SYS_socket, libc::AF_UNIX, kind, 0) as i32 };
    #[cfg(not(target_os = "linux"))]
    let fd = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
    let ownership = Ownership::register(fd)?;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    if nonblocking && unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ownership)
}

/// Fixed-storage control descriptor for async-signal-safe fork handoff code.
/// The successful Linux construction and Drop paths use only raw syscalls and
/// atomics; connect, protocol I/O and all waiting remain outside the fork fence.
pub struct IpcFd(Ownership);
impl IpcFd {
    pub fn socket(nonblocking: bool) -> io::Result<Self> {
        socket(nonblocking).map(Self)
    }
    pub fn raw_fd(&self) -> io::Result<RawFd> {
        self.0.check()?;
        Ok(self.0.fd)
    }
}

/// A control socket whose copied Rust value is inert after fork.
pub struct IpcStream {
    // UnixStream contains only its descriptor. Ownership closes it using the
    // unhooked syscall; ManuallyDrop prevents a second, stale close after fork.
    stream: ManuallyDrop<UnixStream>,
    ownership: Ownership,
}
impl IpcStream {
    pub fn socket() -> io::Result<Self> {
        let ownership = socket(false)?;
        let stream = ManuallyDrop::new(unsafe { UnixStream::from_raw_fd(ownership.fd) });
        Ok(Self { stream, ownership })
    }
    pub fn get(&self) -> io::Result<&UnixStream> {
        self.ownership.check()?;
        Ok(&self.stream)
    }
    pub fn is_current(&self) -> bool {
        self.ownership.current()
    }
    pub fn connect(endpoint: &str) -> io::Result<Self> {
        let (address, length) = address(Path::new(endpoint))?;
        let value = Self::socket()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        value.get()?.set_nonblocking(true)?;
        let fd = value.get()?.as_raw_fd();
        if unsafe { libc::connect(fd, (&address as *const libc::sockaddr_un).cast(), length) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error);
            }
            loop {
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .filter(|time| !time.is_zero())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::TimedOut, "control connect timed out")
                    })?;
                let mut poll = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let timeout = remaining
                    .as_millis()
                    .saturating_add(1)
                    .min(i32::MAX as u128) as i32;
                match unsafe { libc::poll(&mut poll, 1, timeout) } {
                    count if count > 0 => {
                        if let Some(error) = value.get()?.take_error()? {
                            return Err(error);
                        }
                        break;
                    }
                    0 => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "control connect timed out",
                        ))
                    }
                    _ => {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
            }
        }
        value.get()?.set_nonblocking(false)?;
        Ok(value)
    }
}
impl Read for IpcStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.get()?.read(bytes)
    }
}
impl Write for IpcStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.get()?.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.get()?.flush()
    }
}

/// Host listener; accepted control endpoints are registered before exposure.
pub struct IpcListener {
    listener: ManuallyDrop<UnixListener>,
    ownership: Ownership,
}
impl IpcListener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        let (address, length) = address(path)?;
        let ownership = socket(false)?;
        if unsafe {
            libc::bind(
                ownership.fd,
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::listen(ownership.fd, 128) } < 0 {
            let error = io::Error::last_os_error();
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        let listener = ManuallyDrop::new(unsafe { UnixListener::from_raw_fd(ownership.fd) });
        let value = Self {
            listener,
            ownership,
        };
        if let Err(error) = value.get()?.set_nonblocking(true) {
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        Ok(value)
    }
    pub(crate) fn get(&self) -> io::Result<&UnixListener> {
        self.ownership.check()?;
        Ok(&self.listener)
    }
    pub fn is_current(&self) -> bool {
        self.ownership.current()
    }
    /// The listener must be nonblocking so this syscall cannot stall fork.
    pub fn accept(&self) -> io::Result<IpcStream> {
        self.ownership.check()?;
        let _fence = Fence::enter();
        #[cfg(target_os = "linux")]
        let fd = unsafe {
            libc::syscall(
                libc::SYS_accept4,
                self.ownership.fd,
                std::ptr::null_mut::<libc::sockaddr>(),
                std::ptr::null_mut::<libc::socklen_t>(),
                libc::SOCK_CLOEXEC,
            ) as i32
        };
        #[cfg(not(target_os = "linux"))]
        let fd = unsafe {
            libc::accept(
                self.ownership.fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let ownership = Ownership::register(fd)?;
        let stream = ManuallyDrop::new(unsafe { UnixStream::from_raw_fd(fd) });
        Ok(IpcStream { stream, ownership })
    }
}
fn address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid control socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as _;
    for (output, input) in address.sun_path.iter_mut().zip(bytes) {
        *output = *input as _;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        address.sun_len = length as _;
    }
    Ok((address, length as _))
}

/// Must be last in SDK's prepare callback, after all Engine/Frida work.
/// Pair exactly once with `fork_parent` or `fork_child`.
///
/// # Safety
/// The caller must execute this only as part of serialized atfork callbacks.
pub unsafe fn fork_prepare() {
    acquire();
}
/// # Safety
/// Must match this thread's preceding `fork_prepare` in the fork parent.
pub unsafe fn fork_parent() {
    release();
}
/// Close only registered control descriptors. No allocation, locks, TLS, or Drop.
///
/// # Safety
/// Must run in the fork child after `fork_prepare` fenced descriptor mutations.
pub unsafe fn fork_child() {
    for slot in &SLOTS {
        let fd = slot.fd.swap(-1, Ordering::Relaxed);
        if fd >= 0 {
            unsafe { close_raw(fd) };
        }
    }
    // Preserve NEXT: copied objects are additionally invalidated by PID. Fresh
    // child registrations use a new token even if an old descriptor is reused.
    DEPTH.store(0, Ordering::Relaxed);
    OWNER.store(0, Ordering::Release);
}

#[cfg(test)]
mod tests;
