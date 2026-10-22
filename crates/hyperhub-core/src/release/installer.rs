use super::{mac, valid_id};
use hmac::Mac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MAX_EXECUTABLE: u64 = 1024 * 1024 * 1024;
pub(crate) fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn digest(path: &Path) -> io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("executable size overflow"))?;
        if size > MAX_EXECUTABLE {
            return Err(io::Error::other("executable exceeds size limit"));
        }
        hash.update(&buffer[..read]);
    }
    Ok((hyperhub_runtime::artifact::hex(&hash.finalize()), size))
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub id: String,
    pub attempt: u32,
    pub issued_at_ms: u64,
    pub source: PathBuf,
    pub target: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub expected_target_sha256: String,
    pub start_after_install: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedJob {
    pub job: Job,
    pub proof: Vec<u8>,
}
impl SignedJob {
    pub fn write(&self, path: &Path) -> io::Result<()> {
        crate::config_store::save_durable_private_bytes(
            path,
            &serde_json::to_vec(self).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)
    }
    pub fn sign(job: Job, key: &[u8]) -> io::Result<Self> {
        let proof = mac(key, b"hyperhub-release-installer-job-v1\0", &job)?
            .finalize()
            .into_bytes()
            .to_vec();
        Ok(Self { job, proof })
    }
    pub fn verify(&self, key: &[u8]) -> bool {
        let job = &self.job;
        valid_id(&job.id)
            && job.source.is_absolute()
            && job.target.is_absolute()
            && valid_hash(&job.sha256)
            && valid_hash(&job.expected_target_sha256)
            && job.size > 0
            && job.size <= MAX_EXECUTABLE
            && job
                .issued_at_ms
                .abs_diff(crate::session::unix_timestamp_ms())
                <= 30_000
            && mac(key, b"hyperhub-release-installer-job-v1\0", job)
                .is_ok_and(|mac| mac.verify_slice(&self.proof).is_ok())
    }
    pub fn read(path: &Path, key: &[u8]) -> io::Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::other("installation job exceeds size limit"));
        }
        let job: Self = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if !job.verify(key) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installation job is invalid or expired",
            ));
        }
        Ok(job)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub id: String,
    pub attempt: u32,
    pub issued_at_ms: u64,
    pub sha256: String,
    pub installed: bool,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAcknowledgement {
    pub ack: Acknowledgement,
    pub proof: Vec<u8>,
}
impl SignedAcknowledgement {
    pub fn write(&self, path: &Path) -> io::Result<()> {
        crate::config_store::save_durable_private_bytes(
            path,
            &serde_json::to_vec(self).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)
    }
    pub fn read(path: &Path, key: &[u8]) -> io::Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::other(
                "installation acknowledgement exceeds limit",
            ));
        }
        let signed: Self = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        // An on-disk acknowledgement is bound to the journaled attempt. It can
        // be recovered after downtime; the network endpoint also checks age.
        mac(key, b"hyperhub-release-installer-ack-v1\0", &signed.ack)?
            .verify_slice(&signed.proof)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid installation acknowledgement",
                )
            })?;
        Ok(signed)
    }
}
impl Acknowledgement {
    pub fn proof(&self, key: &[u8]) -> io::Result<Vec<u8>> {
        Ok(mac(key, b"hyperhub-release-installer-ack-v1\0", self)?
            .finalize()
            .into_bytes()
            .to_vec())
    }
    pub fn authenticate(&self, key: &[u8], proof: &[u8]) -> bool {
        valid_id(&self.id)
            && valid_hash(&self.sha256)
            && self.error.as_ref().is_none_or(|e| e.len() <= 4096)
            && self
                .issued_at_ms
                .abs_diff(crate::session::unix_timestamp_ms())
                <= 30_000
            && mac(key, b"hyperhub-release-installer-ack-v1\0", self)
                .is_ok_and(|mac| mac.verify_slice(proof).is_ok())
    }
}

/// Retries a Windows sharing violation while the initiating CLI exits. Each
/// attempt checks the source and destination identity; no process is stopped.
pub fn install(job: &Job) -> io::Result<()> {
    if !valid_id(&job.id)
        || !job.target.is_absolute()
        || !job.source.is_absolute()
        || !valid_hash(&job.sha256)
        || !valid_hash(&job.expected_target_sha256)
    {
        return Err(io::Error::other("invalid installation identity"));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match install_once(job) {
            Ok(()) => return Ok(()),
            Err(error)
                if cfg!(windows)
                    && Instant::now() < deadline
                    && matches!(
                        error.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::WouldBlock
                    ) =>
            {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(error) => return Err(error),
        }
    }
}
fn install_once(job: &Job) -> io::Result<()> {
    let parent = job
        .target
        .parent()
        .ok_or_else(|| io::Error::other("missing installation directory"))?;
    let name = job
        .target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("invalid executable name"))?;
    if digest(&job.source)? != (job.sha256.clone(), job.size) {
        return Err(io::Error::other(
            "installation source digest or size mismatch",
        ));
    }
    // A cancelled copy can leave a partial file. Recovery starts a new durable
    // attempt without overwriting either that file or another helper's staging.
    let staging = parent.join(format!(".{name}.hh-stage-{}-{}", job.id, job.attempt));
    let backup = parent.join(format!(".{name}.hh-backup-{}", job.id));
    match fs::symlink_metadata(&job.target) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let hash = digest(&job.target)?.0;
            if hash == job.sha256 {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                    let target = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&job.target)?;
                    target.set_permissions(fs::Permissions::from_mode(0o755))?;
                    target.sync_all()?;
                }
                return Ok(());
            }
            if hash != job.expected_target_sha256 {
                return Err(io::Error::other(
                    "installed executable changed after upgrade preparation",
                ));
            }
        }
        Ok(_) => {
            return Err(io::Error::other(
                "installation target must be a regular file",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if digest(&backup)?.0 != job.expected_target_sha256 {
                return Err(io::Error::other("installation recovery backup mismatch"));
            }
        }
        Err(error) => return Err(error),
    }
    match fs::symlink_metadata(&staging) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && digest(&staging)? == (job.sha256.clone(), job.size) => {}
        Ok(_) => {
            return Err(io::Error::other(
                "installation staging file conflicts with this job",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o700);
            }
            let mut output = options.open(&staging)?;
            io::copy(&mut File::open(&job.source)?, &mut output)?;
            output.flush()?;
            output.sync_all()?;
            if digest(&staging)? != (job.sha256.clone(), job.size) {
                return Err(io::Error::other("staged executable changed while copying"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                output.set_permissions(fs::Permissions::from_mode(0o755))?;
            }
        }
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let staging_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staging)?;
        staging_file.set_permissions(fs::Permissions::from_mode(0o755))?;
        staging_file.sync_all()?;
        // Keep an exact recovery identity without creating a missing-target
        // interval. Renaming the staged inode atomically replaces the name.
        if !backup.try_exists()? {
            fs::hard_link(&job.target, &backup)?;
        }
        if digest(&backup)?.0 != job.expected_target_sha256 {
            return Err(io::Error::other(
                "installation backup conflicts with this job",
            ));
        }
        fs::rename(&staging, &job.target)?;
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        if job.target.try_exists()? {
            if backup.try_exists()? {
                return Err(io::Error::other("installation backup already exists"));
            }
            fs::rename(&job.target, &backup)?;
        }
        if let Err(error) = fs::rename(&staging, &job.target) {
            let _ = fs::rename(&backup, &job.target);
            return Err(error);
        }
    }
    if digest(&job.target)? != (job.sha256.clone(), job.size) {
        return Err(io::Error::other("installed executable verification failed"));
    }
    // A resident Windows base can retain the old image. Its backup remains
    // until the operating system permits removal; this does not block success.
    let _ = fs::remove_file(backup);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installation_is_verified_idempotent_and_preserves_a_changed_target() {
        let root = std::env::temp_dir().join(format!(
            "hh-install-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("payload");
        let target = root.join("installed");
        fs::write(&source, b"new executable").unwrap();
        fs::write(&target, b"original executable").unwrap();
        let (sha256, size) = digest(&source).unwrap();
        let expected = digest(&target).unwrap().0;
        let job = Job {
            id: "fixture".into(),
            attempt: 1,
            issued_at_ms: crate::session::unix_timestamp_ms(),
            source,
            target,
            sha256,
            size,
            expected_target_sha256: expected,
            start_after_install: false,
        };
        let signed = SignedJob::sign(job.clone(), b"local fixture key").unwrap();
        assert!(signed.verify(b"local fixture key"));
        assert!(!signed.verify(b"other fixture key"));
        install(&job).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&job.target, fs::Permissions::from_mode(0o600)).unwrap();
        }
        install(&job).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&job.target).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert_eq!(digest(&job.target).unwrap(), (job.sha256.clone(), job.size));
        fs::write(&job.target, b"user replacement").unwrap();
        assert!(install(&job).is_err());
        assert_eq!(fs::read(&job.target).unwrap(), b"user replacement");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn acknowledgement_cannot_be_reused_as_an_owner_request_or_job() {
        let ack = Acknowledgement {
            id: "fixture".into(),
            attempt: 2,
            issued_at_ms: crate::session::unix_timestamp_ms(),
            sha256: "0".repeat(64),
            installed: true,
            error: None,
        };
        let proof = ack.proof(b"local fixture key").unwrap();
        assert!(ack.authenticate(b"local fixture key", &proof));
        assert!(
            mac(b"local fixture key", b"hyperhub-release-owner-v1\0", &ack)
                .unwrap()
                .verify_slice(&proof)
                .is_err()
        );
        let mut changed = ack.clone();
        changed.attempt += 1;
        assert!(!changed.authenticate(b"local fixture key", &proof));
    }

    #[test]
    fn interrupted_replacement_recovers_from_exact_backup_and_staging_identity() {
        let root = std::env::temp_dir().join(format!(
            "hh-install-recovery-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("payload");
        let target = root.join("installed");
        fs::write(&source, b"new executable").unwrap();
        fs::write(&target, b"previous executable").unwrap();
        let (sha256, size) = digest(&source).unwrap();
        let expected_target_sha256 = digest(&target).unwrap().0;
        let job = Job {
            id: "interrupted".into(),
            attempt: 1,
            issued_at_ms: crate::session::unix_timestamp_ms(),
            source,
            target,
            sha256,
            size,
            expected_target_sha256,
            start_after_install: false,
        };
        let backup = root.join(".installed.hh-backup-interrupted");
        let staging = root.join(".installed.hh-stage-interrupted-1");
        fs::rename(&job.target, &backup).unwrap();
        fs::write(&staging, b"new executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o600)).unwrap();
        }
        install(&job).unwrap();
        assert_eq!(digest(&job.target).unwrap(), (job.sha256, job.size));
        assert!(!staging.exists());
        assert!(!backup.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&job.target).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn damaged_source_or_conflicting_stage_never_moves_the_installed_executable() {
        let root = std::env::temp_dir().join(format!(
            "hh-install-reject-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("payload");
        let target = root.join("installed");
        fs::write(&source, b"new executable").unwrap();
        fs::write(&target, b"previous executable").unwrap();
        let (sha256, size) = digest(&source).unwrap();
        let expected_target_sha256 = digest(&target).unwrap().0;
        let job = Job {
            id: "rejected".into(),
            attempt: 1,
            issued_at_ms: crate::session::unix_timestamp_ms(),
            source,
            target,
            sha256,
            size,
            expected_target_sha256: expected_target_sha256.clone(),
            start_after_install: false,
        };
        fs::write(&job.source, b"damaged download").unwrap();
        assert!(install(&job).is_err());
        assert_eq!(digest(&job.target).unwrap().0, expected_target_sha256);
        fs::write(&job.source, b"new executable").unwrap();
        let staging = root.join(".installed.hh-stage-rejected-1");
        fs::write(&staging, b"unrelated staging contents").unwrap();
        assert!(install(&job).is_err());
        assert_eq!(fs::read(&staging).unwrap(), b"unrelated staging contents");
        assert_eq!(digest(&job.target).unwrap().0, expected_target_sha256);
        assert!(!root.join(".installed.hh-backup-rejected").exists());
        let mut retry = job.clone();
        retry.attempt += 1;
        install(&retry).unwrap();
        assert_eq!(digest(&retry.target).unwrap(), (retry.sha256, retry.size));
        assert_eq!(fs::read(&staging).unwrap(), b"unrelated staging contents");
        fs::remove_dir_all(root).unwrap();
    }
}
