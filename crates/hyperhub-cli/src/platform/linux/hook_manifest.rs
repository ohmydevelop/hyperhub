#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Intent {
    DnsResolution,
    NetworkRequest,
    DescriptorState,
    FileOpen,
    FileRead,
    FileWrite,
    FileDelete,
    FileRename,
    FileMap,
    ProcessCreate,
    ProcessExec,
    ProcessWait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HookPoint {
    pub name: &'static str,
    pub intent: Intent,
    pub syscall: i64,
    pub fixture_required: bool,
}

#[cfg(target_arch = "x86_64")]
pub mod syscall {
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const OPEN: i64 = 2;
    pub const CLOSE: i64 = 3;
    pub const MMAP: i64 = 9;
    pub const MPROTECT: i64 = 10;
    pub const MUNMAP: i64 = 11;
    pub const IOCTL: i64 = 16;
    pub const PREAD64: i64 = 17;
    pub const PWRITE64: i64 = 18;
    pub const READV: i64 = 19;
    pub const WRITEV: i64 = 20;
    pub const DUP: i64 = 32;
    pub const DUP2: i64 = 33;
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const SENDMSG: i64 = 46;
    pub const RECVMSG: i64 = 47;
    pub const GETSOCKOPT: i64 = 55;
    pub const CLONE: i64 = 56;
    pub const FORK: i64 = 57;
    pub const VFORK: i64 = 58;
    pub const EXECVE: i64 = 59;
    pub const WAIT4: i64 = 61;
    pub const FCNTL: i64 = 72;
    pub const RENAME: i64 = 82;
    pub const CREAT: i64 = 85;
    pub const UNLINK: i64 = 87;
    pub const OPENAT: i64 = 257;
    pub const UNLINKAT: i64 = 263;
    pub const RENAMEAT: i64 = 264;
    pub const DUP3: i64 = 292;
    pub const PREADV: i64 = 295;
    pub const PWRITEV: i64 = 296;
    pub const RENAMEAT2: i64 = 316;
    pub const EXECVEAT: i64 = 322;
    pub const PREADV2: i64 = 327;
    pub const PWRITEV2: i64 = 328;
    pub const CLONE3: i64 = 435;
    pub const OPENAT2: i64 = 437;
    pub const GETPID: i64 = 39;
}

#[cfg(target_arch = "aarch64")]
pub mod syscall {
    pub const IOCTL: i64 = 29;
    pub const DUP: i64 = 23;
    pub const DUP2: i64 = -1;
    pub const DUP3: i64 = 24;
    pub const FCNTL: i64 = 25;
    pub const UNLINKAT: i64 = 35;
    pub const RENAMEAT: i64 = 38;
    pub const OPENAT: i64 = 56;
    pub const CLOSE: i64 = 57;
    pub const READ: i64 = 63;
    pub const WRITE: i64 = 64;
    pub const READV: i64 = 65;
    pub const WRITEV: i64 = 66;
    pub const PREAD64: i64 = 67;
    pub const PWRITE64: i64 = 68;
    pub const PREADV: i64 = 69;
    pub const PWRITEV: i64 = 70;
    pub const SOCKET: i64 = 198;
    pub const CONNECT: i64 = 203;
    pub const SENDTO: i64 = 206;
    pub const RECVFROM: i64 = 207;
    pub const GETSOCKOPT: i64 = 209;
    pub const SENDMSG: i64 = 211;
    pub const RECVMSG: i64 = 212;
    pub const MUNMAP: i64 = 215;
    pub const CLONE: i64 = 220;
    pub const EXECVE: i64 = 221;
    pub const MMAP: i64 = 222;
    pub const MPROTECT: i64 = 226;
    pub const WAIT4: i64 = 260;
    pub const RENAMEAT2: i64 = 276;
    pub const EXECVEAT: i64 = 281;
    pub const PREADV2: i64 = 286;
    pub const PWRITEV2: i64 = 287;
    pub const CLONE3: i64 = 435;
    pub const OPENAT2: i64 = 437;
    pub const OPEN: i64 = -1;
    pub const CREAT: i64 = -1;
    pub const UNLINK: i64 = -1;
    pub const RENAME: i64 = -1;
    pub const FORK: i64 = -1;
    pub const VFORK: i64 = -1;
    pub const GETPID: i64 = 172;
}

use syscall::*;

pub static HOOK_POINTS: &[HookPoint] = &[
    hook("network.socket", Intent::NetworkRequest, SOCKET, true),
    hook("network.write", Intent::NetworkRequest, WRITE, true),
    hook("network.read", Intent::NetworkRequest, READ, true),
    hook("network.connect", Intent::NetworkRequest, CONNECT, true),
    hook("network.sendto", Intent::NetworkRequest, SENDTO, true),
    hook("network.recvfrom", Intent::NetworkRequest, RECVFROM, true),
    hook("network.sendmsg", Intent::NetworkRequest, SENDMSG, true),
    hook("network.recvmsg", Intent::NetworkRequest, RECVMSG, true),
    hook(
        "network.getsockopt",
        Intent::NetworkRequest,
        GETSOCKOPT,
        true,
    ),
    hook("dns.write", Intent::DnsResolution, WRITE, true),
    hook("dns.read", Intent::DnsResolution, READ, true),
    hook("dns.sendto", Intent::DnsResolution, SENDTO, true),
    hook("dns.recvfrom", Intent::DnsResolution, RECVFROM, true),
    hook("dns.sendmsg", Intent::DnsResolution, SENDMSG, true),
    hook("dns.recvmsg", Intent::DnsResolution, RECVMSG, true),
    hook("descriptor.fcntl", Intent::DescriptorState, FCNTL, true),
    hook("descriptor.ioctl", Intent::DescriptorState, IOCTL, true),
    hook("descriptor.close", Intent::DescriptorState, CLOSE, true),
    hook("descriptor.dup", Intent::DescriptorState, DUP, true),
    hook(
        "descriptor.dup2",
        Intent::DescriptorState,
        DUP2,
        cfg!(target_arch = "x86_64"),
    ),
    hook("descriptor.dup3", Intent::DescriptorState, DUP3, true),
    hook(
        "file.open",
        Intent::FileOpen,
        OPEN,
        cfg!(target_arch = "x86_64"),
    ),
    hook("file.openat", Intent::FileOpen, OPENAT, true),
    hook("file.openat2", Intent::FileOpen, OPENAT2, true),
    hook(
        "file.creat",
        Intent::FileOpen,
        CREAT,
        cfg!(target_arch = "x86_64"),
    ),
    hook("file.read", Intent::FileRead, READ, true),
    hook("file.pread64", Intent::FileRead, PREAD64, true),
    hook("file.readv", Intent::FileRead, READV, true),
    hook("file.preadv", Intent::FileRead, PREADV, true),
    hook("file.preadv2", Intent::FileRead, PREADV2, true),
    hook("file.write", Intent::FileWrite, WRITE, true),
    hook("file.pwrite64", Intent::FileWrite, PWRITE64, true),
    hook("file.writev", Intent::FileWrite, WRITEV, true),
    hook("file.pwritev", Intent::FileWrite, PWRITEV, true),
    hook("file.pwritev2", Intent::FileWrite, PWRITEV2, true),
    hook(
        "file.unlink",
        Intent::FileDelete,
        UNLINK,
        cfg!(target_arch = "x86_64"),
    ),
    hook("file.unlinkat", Intent::FileDelete, UNLINKAT, true),
    hook(
        "file.rename",
        Intent::FileRename,
        RENAME,
        cfg!(target_arch = "x86_64"),
    ),
    hook("file.renameat", Intent::FileRename, RENAMEAT, true),
    hook("file.renameat2", Intent::FileRename, RENAMEAT2, true),
    hook("file.mmap", Intent::FileMap, MMAP, true),
    hook("file.mprotect", Intent::FileMap, MPROTECT, true),
    hook("file.munmap", Intent::FileMap, MUNMAP, true),
    hook("process.clone", Intent::ProcessCreate, CLONE, true),
    hook("process.clone3", Intent::ProcessCreate, CLONE3, true),
    hook(
        "process.fork",
        Intent::ProcessCreate,
        FORK,
        cfg!(target_arch = "x86_64"),
    ),
    hook(
        "process.vfork",
        Intent::ProcessCreate,
        VFORK,
        cfg!(target_arch = "x86_64"),
    ),
    hook("process.execve", Intent::ProcessExec, EXECVE, true),
    hook("process.execveat", Intent::ProcessExec, EXECVEAT, true),
    hook("process.wait4", Intent::ProcessWait, WAIT4, true),
];

const fn hook(
    name: &'static str,
    intent: Intent,
    syscall: i64,
    fixture_required: bool,
) -> HookPoint {
    HookPoint {
        name,
        intent,
        syscall,
        fixture_required,
    }
}

pub fn for_syscall(number: i64) -> impl Iterator<Item = &'static HookPoint> {
    HOOK_POINTS
        .iter()
        .filter(move |point| point.syscall >= 0 && point.syscall == number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn manifest_names_are_unique_and_supported_points_have_syscalls() {
        let mut names = HashSet::new();
        for point in HOOK_POINTS {
            assert!(
                names.insert(point.name),
                "duplicate hook point {}",
                point.name
            );
            if point.fixture_required {
                assert!(point.syscall >= 0, "{} has no syscall", point.name);
            }
        }
    }

    #[test]
    fn every_intent_has_multiple_or_explicit_hook_points() {
        let intents = [
            Intent::DnsResolution,
            Intent::NetworkRequest,
            Intent::DescriptorState,
            Intent::FileOpen,
            Intent::FileRead,
            Intent::FileWrite,
            Intent::FileDelete,
            Intent::FileRename,
            Intent::FileMap,
            Intent::ProcessCreate,
            Intent::ProcessExec,
            Intent::ProcessWait,
        ];
        for intent in intents {
            assert!(
                HOOK_POINTS.iter().any(|point| point.intent == intent),
                "missing hook points for {intent:?}"
            );
        }
    }
}
