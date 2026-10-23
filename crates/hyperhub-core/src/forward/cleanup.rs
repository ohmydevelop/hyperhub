//! Authenticated, instance-scoped cache retirement after Serve exits.
//!
//! Workers can retain granted streams after their control channel disappears.
//! The helper therefore waits for OS process objects; it never kills workers.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
#[path = "cleanup/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "cleanup/windows.rs"]
mod platform;

const MAX_JOB: u64 = 64 * 1024;
const PURPOSE: &[u8] = b"hyperhub-forward-cache-cleanup-v1\0";
const OWNER_PURPOSE: &[u8] = b"hyperhub-forward-cache-owner-v1\0";
pub(crate) const ADMISSION: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    volume: u64,
    index: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Leaf {
    name: String,
    identity: FileIdentity,
    size: u64,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    pub(crate) pid: u32,
    pub(crate) birth: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Job {
    issued_at_ms: u64,
    owner: ProcessIdentity,
    root: PathBuf,
    root_identity: FileIdentity,
    leaves: Vec<Leaf>,
    workers: Vec<ProcessIdentity>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedJob {
    job: Job,
    proof: Vec<u8>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    owner: ProcessIdentity,
    root: PathBuf,
    root_identity: FileIdentity,
    nonce_salt: [u8; 32],
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerReceipt {
    owner: Owner,
    proof: Vec<u8>,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn leaf_hash(name: &str) -> Option<&str> {
    let hash = name.strip_suffix(std::env::consts::EXE_SUFFIX)?;
    valid_hash(hash).then_some(hash)
}
fn authentication(value: &impl Serialize, key: &[u8], purpose: &[u8]) -> io::Result<Hmac<Sha256>> {
    if key.is_empty() {
        return Err(invalid("cache cleanup authentication key is missing"));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(io::Error::other)?;
    mac.update(purpose);
    mac.update(&serde_json::to_vec(value).map_err(io::Error::other)?);
    Ok(mac)
}
fn mac(job: &Job, key: &[u8]) -> io::Result<Hmac<Sha256>> {
    authentication(job, key, PURPOSE)
}

/// Create once, before any worker exists. A job signed with another profile's
/// valid key cannot replace this original ownership authority.
pub(crate) fn root_nonce(key: &[u8], pid: u32, birth: u64, salt: &[u8; 32]) -> io::Result<String> {
    if pid == 0 || birth == 0 {
        return Err(invalid("cache root owner identity unavailable"));
    }
    let bytes = authentication(
        &(pid, birth, salt),
        key,
        b"hyperhub-forward-cache-root-name-v1\0",
    )?
    .finalize()
    .into_bytes();
    Ok(hyperhub_runtime::artifact::hex(&bytes[..16]))
}
pub(crate) fn bind_owner(root: &Path, key: &[u8], nonce_salt: [u8; 32]) -> io::Result<()> {
    let directory = platform::Directory::open(root)?;
    let owner = Owner {
        owner: ProcessIdentity {
            pid: std::process::id(),
            birth: crate::session::process_start_time(std::process::id())
                .filter(|birth| *birth != 0)
                .ok_or_else(|| invalid("cache owner birth unavailable"))?,
        },
        root: root.into(),
        root_identity: directory.identity()?,
        nonce_salt,
    };
    let proof = authentication(&owner, key, OWNER_PURPOSE)?
        .finalize()
        .into_bytes()
        .to_vec();
    let bytes = serde_json::to_vec(&OwnerReceipt { owner, proof }).map_err(io::Error::other)?;
    let path = root.join(".owner");
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    #[cfg(windows)]
    {
        crate::config_store::restrict_file_to_current_user(&path)?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)?;
    }
    Ok(())
}
fn verify_owner(directory: &platform::Directory, job: &Job, key: &[u8]) -> io::Result<()> {
    let receipt: OwnerReceipt =
        serde_json::from_slice(&directory.read_owner()?).map_err(io::Error::other)?;
    let owner = &receipt.owner;
    if owner.root != job.root
        || owner.root_identity != job.root_identity
        || owner.owner.pid != job.owner.pid
        || owner.owner.birth != job.owner.birth
    {
        return Err(invalid(
            "cache cleanup job differs from original root ownership",
        ));
    }
    let nonce = root_nonce(key, owner.owner.pid, owner.owner.birth, &owner.nonce_salt)?;
    let expected_name = format!("hyperhub-forward-{}-{nonce}", owner.owner.pid);
    if job.root.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err(invalid(
            "cache cleanup root name is not bound to this authentication profile",
        ));
    }
    authentication(owner, key, OWNER_PURPOSE)?
        .verify_slice(&receipt.proof)
        .map_err(|_| invalid("cache cleanup root belongs to another authentication profile"))
}
impl Job {
    pub(crate) fn capture(root: &Path, workers: Vec<ProcessIdentity>) -> io::Result<Self> {
        let directory = platform::Directory::open(root)?;
        let owner = ProcessIdentity {
            pid: std::process::id(),
            birth: crate::session::process_start_time(std::process::id())
                .filter(|birth| *birth != 0)
                .ok_or_else(|| invalid("cache cleanup owner birth is unavailable"))?,
        };
        let job = Self {
            issued_at_ms: crate::session::unix_timestamp_ms(),
            owner,
            root: root.to_owned(),
            root_identity: directory.identity()?,
            leaves: directory.snapshot()?,
            workers,
        };
        job.validate()?;
        Ok(job)
    }
    fn validate(&self) -> io::Result<()> {
        let prefix = format!("hyperhub-forward-{}-", self.owner.pid);
        let nonce = self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(&prefix));
        if !self.root.is_absolute()
            || self.owner.pid == 0
            || self.owner.birth == 0
            || nonce.is_none_or(|nonce| {
                nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            || self
                .issued_at_ms
                .abs_diff(crate::session::unix_timestamp_ms())
                > 30_000
            || self.leaves.len() > 64
            || self.workers.len() > 64
            || self.leaves.iter().any(|leaf| {
                (if leaf.name == ".owner" {
                    !valid_hash(&leaf.sha256) || leaf.size > 4096
                } else {
                    leaf_hash(&leaf.name) != Some(leaf.sha256.as_str())
                }) || leaf.size == 0
                    || leaf.size > 1024 * 1024 * 1024
            })
            || self
                .leaves
                .iter()
                .filter(|leaf| leaf.name == ".owner")
                .count()
                != 1
            || self
                .workers
                .iter()
                .any(|worker| worker.pid == 0 || worker.birth == 0 || worker.pid == self.owner.pid)
        {
            return Err(invalid("cache cleanup job identity or scope is invalid"));
        }
        let mut names = std::collections::HashSet::new();
        let mut pids = std::collections::HashSet::new();
        if self.leaves.iter().any(|leaf| !names.insert(&leaf.name))
            || self.workers.iter().any(|worker| !pids.insert(worker.pid))
        {
            return Err(invalid("cache cleanup job contains duplicate objects"));
        }
        Ok(())
    }
}
impl SignedJob {
    fn new(job: Job, key: &[u8]) -> io::Result<Self> {
        job.validate()?;
        let proof = mac(&job, key)?.finalize().into_bytes().to_vec();
        Ok(Self { job, proof })
    }
    fn verify(&self, key: &[u8]) -> io::Result<()> {
        self.job.validate()?;
        mac(&self.job, key)?
            .verify_slice(&self.proof)
            .map_err(|_| invalid("cache cleanup job authentication failed"))
    }
}

/// Admit one helper before Serve exits. The helper is launched from the stable
/// resident executable, never from the cache that it will eventually remove.
pub(crate) fn start(
    job: Job,
    executable: &Path,
    expected_sha256: &str,
    key: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(&SignedJob::new(job, key)?).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_JOB {
        return Err(invalid("cache cleanup job exceeds the size limit"));
    }
    let (_source_guard, executable) = helper_source(executable, expected_sha256)?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "cache cleanup admission deadline expired during validation",
        ));
    }
    let child = Command::new(executable)
        .arg("forward-cache-cleanup")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    transfer(child, bytes, deadline)
}
fn transfer(mut child: std::process::Child, bytes: Vec<u8>, deadline: Instant) -> io::Result<()> {
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("cleanup helper input missing"))?;
    let mut output = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("cleanup helper output missing"))?;
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let exchange = std::thread::Builder::new()
        .name("hh-cache-admission".into())
        .spawn(move || {
            let result = (|| {
                input.write_all(&bytes)?;
                drop(input);
                let mut ready = [0; 6];
                output.read_exact(&mut ready)?;
                if &ready != b"READY\n" {
                    return Err(invalid("cleanup helper rejected admission"));
                }
                Ok(())
            })();
            let _ = send.send(result);
        });
    let result = match exchange {
        Ok(thread) => {
            let result = receive
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "cache cleanup helper admission deadline expired",
                    )
                })
                .and_then(|result| result);
            if thread.is_finished() {
                let _ = thread.join();
            }
            result
        }
        Err(error) => Err(error),
    };
    if result.is_err() {
        // Only the newly created helper belongs to this failed admission.
        // Active forwarding workers are never killed by cache cleanup.
        let _ = child.kill();
        // Reap only our failed helper without extending the caller's deadline.
        // This thread owns an exact Child object and never handles workers.
        let _ = std::thread::Builder::new()
            .name("hh-cache-reap".into())
            .spawn(move || {
                let _ = child.wait();
            });
    }
    result
}

fn helper_source(path: &Path, expected: &str) -> io::Result<(std::fs::File, PathBuf)> {
    use sha2::Digest;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(target_os = "linux")]
    let _ = path;
    #[cfg(target_os = "linux")]
    let path = Path::new("/proc/self/exe");
    // /proc/self/exe is the kernel's resident image link, including an old
    // unlinked image after installation. Open that link deliberately on Linux.
    #[cfg(target_os = "linux")]
    let mut file = std::fs::File::open(path)?;
    #[cfg(not(target_os = "linux"))]
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 1024 * 1024 * 1024 {
        return Err(invalid("cache cleanup helper source is invalid"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if hyperhub_runtime::artifact::hex(&hasher.finalize()) != expected {
        return Err(invalid(
            "cache cleanup helper differs from the original resident executable",
        ));
    }
    #[cfg(target_os = "linux")]
    let executable = {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
    };
    #[cfg(not(target_os = "linux"))]
    let executable = path.to_path_buf();
    Ok((file, executable))
}

/// Private CLI entry. The key comes from the normal protected API-key store,
/// not from arguments, a caller-supplied environment value, or the job itself.
pub(crate) fn run(key: &[u8]) -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().take(MAX_JOB + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JOB {
        return Err(invalid("cache cleanup job exceeds the size limit"));
    }
    let signed: SignedJob = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let admission = admit(signed, key)?;
    io::stdout().write_all(b"READY\n")?;
    io::stdout().flush()?;
    admission.owner.wait()?;
    for worker in admission.workers.into_iter().flatten() {
        worker.wait()?;
    }
    admission.directory.remove(&admission.leaves)
}
struct Admission {
    directory: platform::Directory,
    owner: platform::Process,
    workers: Vec<Option<platform::Process>>,
    leaves: Vec<Leaf>,
}
fn admit(signed: SignedJob, key: &[u8]) -> io::Result<Admission> {
    signed.verify(key)?;
    let job = signed.job;
    let directory = platform::Directory::open(&job.root)?;
    if directory.identity()? != job.root_identity {
        return Err(invalid("cache cleanup root identity changed"));
    }
    verify_owner(&directory, &job, key)?;
    // Resolve every process object while the authenticated owner is still
    // alive. No PID is reopened after owner death, and PID reuse is rejected.
    let owner = platform::Process::open(job.owner.pid, job.owner.birth)?
        .ok_or_else(|| invalid("cache cleanup owner has already exited"))?;
    let workers = job
        .workers
        .iter()
        .map(|worker| platform::Process::open(worker.pid, worker.birth))
        .collect::<io::Result<Vec<_>>>()?;
    // Validate the precise whitelist before acknowledging responsibility.
    // Missing leaves are safe: an idle generation may already have retired.
    let current = directory.leaves()?;
    if current.iter().any(|leaf| !job.leaves.contains(leaf)) {
        return Err(invalid("cache cleanup artifacts changed before admission"));
    }
    Ok(Admission {
        directory,
        owner,
        workers,
        leaves: job.leaves,
    })
}

#[cfg(test)]
mod tests;
