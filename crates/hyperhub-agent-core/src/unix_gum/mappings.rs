//! Allocation-free map provenance at allocator-sensitive mprotect boundaries.
use crate::{snapshot::Snapshot, CompiledFileSandboxSnapshot, SandboxAction};
use std::sync::{
    atomic::{AtomicI32, AtomicPtr, AtomicU32, AtomicU64, Ordering},
    Arc,
};

static CURSOR: AtomicU32 = AtomicU32::new(0);
static OWNER: AtomicU32 = AtomicU32::new(0);
static BIRTH: AtomicU64 = AtomicU64::new(0);
static FD: AtomicI32 = AtomicI32::new(-1);
static DEVICE: AtomicU64 = AtomicU64::new(0);
static INODE: AtomicU64 = AtomicU64::new(0);
static POLICY: AtomicPtr<Snapshot<CompiledFileSandboxSnapshot>> =
    AtomicPtr::new(std::ptr::null_mut());

/// The proc seq_file owns one VMA traversal cursor. Never interleave byte
/// seeks from different scans. This guard performs raw syscalls only: a caller
/// may already hold libc's allocator lock, including on a different thread.
struct CursorGuard;
impl CursorGuard {
    fn acquire() -> Result<Self, &'static str> {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
        loop {
            match CURSOR.compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return Ok(Self),
                Err(owner) if owner == tid => {
                    return Err("process mapping traversal was reentered")
                }
                Err(owner) => unsafe {
                    libc::syscall(
                        libc::SYS_futex,
                        &CURSOR as *const AtomicU32,
                        libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                        owner,
                        std::ptr::null::<libc::timespec>(),
                    );
                },
            }
        }
    }
}
impl Drop for CursorGuard {
    fn drop(&mut self) {
        CURSOR.store(0, Ordering::Release);
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &CURSOR as *const AtomicU32,
                libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                i32::MAX,
            );
        }
    }
}

/// Scalar provenance scratch cannot use the application allocator while the
/// cursor is locked. Anonymous scans keep it empty; file spans use raw mappings
/// which are released before the original application mprotect call.
pub(crate) struct Regions {
    pointer: *mut Region,
    length: usize,
    bytes: usize,
}
impl Regions {
    fn new() -> Self {
        Self {
            pointer: std::ptr::NonNull::<Region>::dangling().as_ptr(),
            length: 0,
            bytes: 0,
        }
    }
    fn push(&mut self, region: Region) -> Result<(), &'static str> {
        if self.length == self.bytes / std::mem::size_of::<Region>() {
            let bytes = if self.bytes == 0 {
                4096
            } else {
                self.bytes
                    .checked_mul(2)
                    .ok_or("mapping provenance scratch overflows")?
            };
            let fresh = unsafe {
                libc::syscall(
                    libc::SYS_mmap,
                    std::ptr::null_mut::<libc::c_void>(),
                    bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                ) as *mut Region
            };
            if fresh.cast::<libc::c_void>() == libc::MAP_FAILED {
                return Err("mapping provenance scratch is unavailable");
            }
            unsafe {
                if self.length != 0 {
                    std::ptr::copy_nonoverlapping(self.pointer, fresh, self.length);
                }
                if self.bytes != 0 {
                    libc::syscall(libc::SYS_munmap, self.pointer, self.bytes);
                }
            }
            self.pointer = fresh;
            self.bytes = bytes;
        }
        unsafe {
            self.pointer.add(self.length).write(region);
        }
        self.length += 1;
        Ok(())
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub(crate) fn iter(&self) -> std::slice::Iter<'_, Region> {
        unsafe { std::slice::from_raw_parts(self.pointer, self.length) }.iter()
    }
}
impl Drop for Regions {
    fn drop(&mut self) {
        if self.bytes != 0 {
            unsafe {
                libc::syscall(libc::SYS_munmap, self.pointer, self.bytes);
            }
        }
    }
}

struct Errno(i32);
impl Errno {
    unsafe fn preserve() -> Self {
        Self(*libc::__errno_location())
    }
}
impl Drop for Errno {
    fn drop(&mut self) {
        unsafe {
            *libc::__errno_location() = self.0;
        }
    }
}

unsafe fn identity(fd: i32) -> Result<(u64, u64), &'static str> {
    let mut value: libc::stat = std::mem::zeroed();
    if libc::syscall(libc::SYS_fstat, fd, &mut value) != 0 {
        return Err("mapping probe descriptor is unavailable");
    }
    Ok((value.st_dev as u64, value.st_ino as u64))
}
unsafe fn valid(fd: i32) -> bool {
    OWNER.load(Ordering::Acquire) == libc::syscall(libc::SYS_getpid) as u32
        && BIRTH.load(Ordering::Acquire) != 0
        && identity(fd)
            == Ok((
                DEVICE.load(Ordering::Acquire),
                INODE.load(Ordering::Acquire),
            ))
}

/// Called before hook publication, or by the trusted rebuilt child worker.
/// A parent's open proc file refers to the parent's mm, so it is never reused.
pub(crate) fn initialize(policy: Arc<Snapshot<CompiledFileSandboxSnapshot>>) -> Result<(), String> {
    let pid = std::process::id();
    let owner = OWNER.load(Ordering::Acquire);
    let pointer = Arc::as_ptr(&policy).cast_mut();
    if owner == pid {
        if POLICY.load(Ordering::Acquire) != pointer {
            return Err("mapping policy snapshot changed native ownership".into());
        }
        if unsafe { valid(FD.load(Ordering::Acquire)) } {
            return Ok(());
        }
        return Err("mapping probe descriptor was closed or reused".into());
    }
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|e| e.to_string())?;
    let birth = stat
        .rsplit_once(") ")
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or("mapping probe process birth is unavailable")?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            c"/proc/self/maps".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        ) as i32
    };
    if fd < 0 {
        return Err("cannot reserve the process mapping descriptor".into());
    }
    let (device, inode) = match unsafe { identity(fd) } {
        Ok(value) => value,
        Err(error) => {
            unsafe {
                libc::syscall(libc::SYS_close, fd);
            };
            return Err(error.into());
        }
    };
    if owner != 0 {
        // The old pin and its locks belong to the vanished parent's threads.
        // Abandon that copied Arc; never run its destructor in the child.
        let old = FD.load(Ordering::Acquire);
        if old >= 0
            && old != fd
            && unsafe { identity(old) }
                == Ok((
                    DEVICE.load(Ordering::Acquire),
                    INODE.load(Ordering::Acquire),
                ))
        {
            unsafe {
                libc::syscall(libc::SYS_close, old);
            };
        }
    }
    CURSOR.store(0, Ordering::Release);
    POLICY.store(Arc::into_raw(policy).cast_mut(), Ordering::Release);
    DEVICE.store(device, Ordering::Release);
    INODE.store(inode, Ordering::Release);
    FD.store(fd, Ordering::Release);
    BIRTH.store(birth, Ordering::Release);
    OWNER.store(pid, Ordering::Release);
    Ok(())
}

pub(crate) fn error_action() -> Option<SandboxAction> {
    let pointer = POLICY.load(Ordering::Acquire);
    if pointer.is_null() || OWNER.load(Ordering::Acquire) != std::process::id() {
        return Some(SandboxAction::Deny);
    }
    // The owning snapshot pin is never replaced or freed in this process.
    unsafe { &*pointer }.inspect(|snapshot| snapshot.map(|value| value.error_action))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Region {
    pub start: usize,
    pub end: usize,
    pub device: u64,
    pub inode: u64,
}

fn field<'a>(line: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    while line.get(*position).is_some_and(u8::is_ascii_whitespace) {
        *position += 1;
    }
    let start = *position;
    while line
        .get(*position)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        *position += 1;
    }
    (*position > start).then_some(&line[start..*position])
}
fn number(value: &[u8], radix: u32) -> Option<u64> {
    u64::from_str_radix(std::str::from_utf8(value).ok()?, radix).ok()
}
fn region(line: &[u8], start: usize, end: usize) -> Result<Option<Region>, &'static str> {
    let mut position = 0;
    let range = field(line, &mut position).ok_or("mapping record has no range")?;
    let separator = range
        .iter()
        .position(|byte| *byte == b'-')
        .ok_or("mapping range is malformed")?;
    let low = number(&range[..separator], 16)
        .and_then(|v| usize::try_from(v).ok())
        .ok_or("mapping start is malformed")?;
    let high = number(&range[separator + 1..], 16)
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > low)
        .ok_or("mapping end is malformed")?;
    if low >= end || high <= start {
        return Ok(None);
    }
    field(line, &mut position).ok_or("mapping permissions are missing")?;
    field(line, &mut position).ok_or("mapping offset is missing")?;
    let device = field(line, &mut position).ok_or("mapping device is missing")?;
    let colon = device
        .iter()
        .position(|byte| *byte == b':')
        .ok_or("mapping device is malformed")?;
    let major = number(&device[..colon], 16)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("mapping major is malformed")?;
    let minor = number(&device[colon + 1..], 16)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("mapping minor is malformed")?;
    let inode = number(
        field(line, &mut position).ok_or("mapping inode is missing")?,
        10,
    )
    .ok_or("mapping inode is malformed")?;
    if inode == 0 {
        return Ok(None);
    }
    while line.get(position).is_some_and(u8::is_ascii_whitespace) {
        position += 1;
    }
    if line.get(position) != Some(&b'/') {
        return Err("file mapping has no provable pathname");
    }
    Ok(Some(Region {
        start: low,
        end: high,
        device: libc::makedev(major, minor) as u64,
        inode,
    }))
}

/// Sequential read retains the kernel's VMA cursor across changes. Concurrent
/// pread byte offsets on one seq_file can otherwise splice different traversals.
/// No heap, SDK TLS, path resolution, or policy calls run under CursorGuard.
pub(crate) fn file_regions(start: usize, length: usize) -> Result<Regions, &'static str> {
    let end = start.checked_add(length).ok_or("mapping range overflows")?;
    let mut regions = Regions::new();
    let _errno = unsafe { Errno::preserve() };
    let fd = FD.load(Ordering::Acquire);
    if !unsafe { valid(fd) } {
        return Err("mapping probe descriptor identity changed");
    }
    let _cursor = CursorGuard::acquire()?;
    if !unsafe { valid(fd) } {
        return Err("mapping probe descriptor identity changed");
    }
    if unsafe { libc::syscall(libc::SYS_lseek, fd, 0, libc::SEEK_SET) } != 0 {
        return Err("cannot rewind process mapping provenance");
    }
    // Keep only the numeric header and first pathname byte. Full paths are
    // resolved separately through map_files; long paths never enlarge this
    // allocator-sensitive frame (including legal small pthread stacks).
    let mut buffer = [0u8; 1024];
    let mut header = [0u8; 256];
    let mut used = 0;
    loop {
        let count = unsafe { libc::syscall(libc::SYS_read, fd, buffer.as_mut_ptr(), buffer.len()) };
        if count < 0 {
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return Err("cannot read process mapping provenance");
        }
        if count == 0 {
            if used != 0 {
                return Err("incomplete mapping record");
            }
            break;
        }
        for &byte in &buffer[..count as usize] {
            if byte == b'\n' {
                if let Some(value) = region(&header[..used], start, end)? {
                    regions.push(value)?;
                }
                used = 0;
            } else if used < header.len() {
                header[used] = byte;
                used += 1;
            }
        }
    }
    if !unsafe { valid(fd) } {
        return Err("mapping probe descriptor changed during read");
    }
    Ok(regions)
}

pub(crate) fn paths(region: Region) -> Result<Vec<String>, &'static str> {
    use std::os::unix::fs::MetadataExt;
    let path = std::fs::read_link(format!(
        "/proc/self/map_files/{:x}-{:x}",
        region.start, region.end
    ))
    .map_err(|_| "mapped object changed or its pathname is unavailable")?;
    let text = path.to_str().ok_or("mapped object pathname is not UTF-8")?;
    let same = std::fs::metadata(&path)
        .ok()
        .is_some_and(|value| value.dev() == region.device && value.ino() == region.inode);
    if same {
        return Ok(vec![text.into()]);
    }
    if let Some(original) = text.strip_suffix(" (deleted)") {
        // A live literal suffix was verified above. When deletion/lookup is
        // ambiguous, check both representations; never discard a possible deny.
        return Ok(vec![text.into(), original.into()]);
    }
    Err("mapped pathname no longer identifies the original object")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scalar_region_scratch_grows_without_a_fixed_mapping_limit() {
        let mut regions = Regions::new();
        assert!(regions.is_empty());
        assert_eq!(regions.bytes, 0);
        for index in 0..1024 {
            regions
                .push(Region {
                    start: index * 4096,
                    end: (index + 1) * 4096,
                    device: 1,
                    inode: index as u64 + 1,
                })
                .unwrap();
        }
        assert_eq!(regions.iter().len(), 1024);
        for (index, region) in regions.iter().enumerate() {
            assert_eq!(region.inode, index as u64 + 1);
        }
    }

    #[test]
    fn parser_does_not_tokenize_pathnames_or_confuse_anonymous_ranges() {
        assert_eq!(
            region(
                b"1000-2000 rw-p 00000000 00:00 0 [anon:arena]",
                0x1000,
                0x2000
            ),
            Ok(None)
        );
        let value = region(
            b"1000-2000 ---p 00000000 08:01 42 /a path/with\\012newline (deleted)",
            0x1000,
            0x2000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(value.inode, 42);
        assert_eq!(value.device, libc::makedev(8, 1) as u64);
        assert!(region(b"1000-2000 rw-p 0 08:01 nope /path", 0x1000, 0x2000).is_err());
        assert!(region(b"not-a-range", 0x1000, 0x2000).is_err());
    }
}
