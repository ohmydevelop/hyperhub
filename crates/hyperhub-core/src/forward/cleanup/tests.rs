use super::*;
use sha2::Digest;

const KEY: &[u8] = b"private cleanup source fixture key";
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let pid = std::process::id();
        let birth = crate::session::process_start_time(pid).unwrap();
        let mut salt = [0; 32];
        rand::fill(&mut salt);
        let nonce = root_nonce(KEY, pid, birth, &salt).unwrap();
        let root = std::env::temp_dir().join(format!("hyperhub-forward-{pid}-{nonce}"));
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).unwrap();
        #[cfg(windows)]
        crate::config_store::restrict_file_to_current_user(&root).unwrap();
        bind_owner(&root, KEY, salt).unwrap();
        Self { root }
    }
    fn job(&self) -> Job {
        Job::capture(&self.root, vec![]).unwrap()
    }
    fn executable(&self, bytes: &[u8]) -> PathBuf {
        let hash = hyperhub_runtime::artifact::hex(&Sha256::digest(bytes));
        let path = self
            .root
            .join(format!("{hash}{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&path, bytes).unwrap();
        #[cfg(windows)]
        crate::config_store::restrict_file_to_current_user(&path).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                if let Ok(metadata) = std::fs::symlink_metadata(entry.path()) {
                    if metadata.is_file() && metadata.permissions().readonly() {
                        let mut permissions = metadata.permissions();
                        permissions.set_readonly(false);
                        let _ = std::fs::set_permissions(entry.path(), permissions);
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn cleanup_job_authentication_rejects_wrong_key_purpose_and_tampering() {
    let fixture = Fixture::new();
    let mut signed = SignedJob::new(fixture.job(), KEY).unwrap();
    assert!(signed.verify(KEY).is_ok());
    assert!(signed.verify(b"another private profile").is_err());
    signed.proof = authentication(&signed.job, KEY, b"hyperhub-release-installer-job-v1\0")
        .unwrap()
        .finalize()
        .into_bytes()
        .to_vec();
    assert!(signed.verify(KEY).is_err());
    signed = SignedJob::new(fixture.job(), KEY).unwrap();
    signed.job.owner.birth += 1;
    assert!(signed.verify(KEY).is_err());
    assert!(SignedJob::new(fixture.job(), b"").is_err());
}

#[test]
fn another_profiles_valid_job_cannot_claim_the_original_root() {
    let fixture = Fixture::new();
    let signed = SignedJob::new(fixture.job(), b"another profile key").unwrap();
    assert!(signed.verify(b"another profile key").is_ok());
    assert!(admit(signed, b"another profile key").is_err());
    // Even replacing the receipt using a key selected by the caller cannot
    // reproduce the original key-bound random directory name.
    let directory = platform::Directory::open(&fixture.root).unwrap();
    let bytes = directory.read_owner().unwrap();
    drop(directory);
    let mut receipt: OwnerReceipt = serde_json::from_slice(&bytes).unwrap();
    receipt.proof = authentication(&receipt.owner, b"another profile key", OWNER_PURPOSE)
        .unwrap()
        .finalize()
        .into_bytes()
        .to_vec();
    let path = fixture.root.join(".owner");
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions).unwrap();
    std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let signed = SignedJob::new(fixture.job(), b"another profile key").unwrap();
    assert!(admit(signed, b"another profile key").is_err());
}

#[test]
fn invalid_scope_stale_jobs_and_missing_births_are_rejected() {
    let fixture = Fixture::new();
    let mut job = fixture.job();
    job.issued_at_ms = job.issued_at_ms.saturating_sub(31_000);
    assert!(SignedJob::new(job, KEY).is_err());
    let mut job = fixture.job();
    job.owner.birth = 0;
    assert!(SignedJob::new(job, KEY).is_err());
    let mut job = fixture.job();
    job.workers.push(ProcessIdentity {
        pid: std::process::id() + 1,
        birth: 0,
    });
    assert!(SignedJob::new(job, KEY).is_err());
    let mut job = fixture.job();
    job.leaves.push(job.leaves[0].clone());
    assert!(SignedJob::new(job, KEY).is_err());
    let mut job = fixture.job();
    job.root = PathBuf::from("../another-instance");
    assert!(SignedJob::new(job, KEY).is_err());
}

#[test]
fn exact_objects_are_validated_before_admission_and_retirement() {
    let fixture = Fixture::new();
    let path = fixture.executable(b"private executable source bytes");
    let job = fixture.job();
    assert!(admit(SignedJob::new(job.clone(), KEY).unwrap(), KEY).is_ok());
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"changed bytes").unwrap();
    assert!(admit(SignedJob::new(job.clone(), KEY).unwrap(), KEY).is_err());
    assert!(platform::Directory::open(&fixture.root)
        .unwrap()
        .remove(&job.leaves)
        .is_err());
    assert!(path.exists());
}

#[cfg(unix)]
#[test]
fn roots_symlinks_hardlinks_and_unapproved_files_fail_closed() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let path = fixture.executable(b"owned single link bytes");
    let job = fixture.job();
    let link = fixture.root.join("unexpected");
    symlink(&path, &link).unwrap();
    assert!(admit(SignedJob::new(job.clone(), KEY).unwrap(), KEY).is_err());
    std::fs::remove_file(&link).unwrap();
    let other = fixture.root.join("another-link");
    std::fs::hard_link(&path, &other).unwrap();
    assert!(fixture.job_capture().is_err());
    std::fs::remove_file(&other).unwrap();
    assert!(platform::Directory::open(&link).is_err());
    let renamed = fixture.root.with_extension("moved");
    std::fs::rename(&fixture.root, &renamed).unwrap();
    symlink(&renamed, &fixture.root).unwrap();
    assert!(admit(SignedJob::new(job, KEY).unwrap(), KEY).is_err());
    std::fs::remove_file(&fixture.root).unwrap();
    std::fs::rename(&renamed, &fixture.root).unwrap();
}
#[cfg(unix)]
impl Fixture {
    fn job_capture(&self) -> io::Result<Job> {
        Job::capture(&self.root, vec![])
    }
}

#[test]
fn cleanup_removes_only_the_validated_instance_and_accepts_missing_idle_files() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let path = fixture.executable(b"drained worker bytes");
    let job = fixture.job();
    std::fs::remove_file(path).unwrap();
    let directory = platform::Directory::open(&fixture.root).unwrap();
    directory.remove(&job.leaves).unwrap();
    drop(directory);
    assert!(!fixture.root.exists());
    assert!(other.root.exists());
}

#[cfg(unix)]
#[test]
fn valid_hash_unknown_leaf_is_rejected_before_any_approved_leaf_is_removed() {
    let fixture = Fixture::new();
    // SHA(b) sorts before SHA(a); the extra valid leaf used to be discovered
    // only after approved objects had already been unlinked.
    let approved = fixture.executable(b"b");
    let job = fixture.job();
    let unknown = fixture.executable(b"a");
    let directory = platform::Directory::open(&fixture.root).unwrap();
    assert!(directory.remove(&job.leaves).is_err());
    assert!(approved.exists());
    assert!(unknown.exists());
    assert!(fixture.root.join(".owner").exists());
}

#[cfg(unix)]
#[test]
fn already_removed_pinned_empty_root_is_idempotent_but_renamed_root_is_rejected() {
    let fixture = Fixture::new();
    let job = fixture.job();
    let directory = platform::Directory::open(&fixture.root).unwrap();
    let moved = fixture.root.with_extension("moved");
    std::fs::rename(&fixture.root, &moved).unwrap();
    assert!(directory.remove(&job.leaves).is_err());
    std::fs::rename(&moved, &fixture.root).unwrap();
    std::fs::remove_file(fixture.root.join(".owner")).unwrap();
    std::fs::remove_dir(&fixture.root).unwrap();
    directory.remove(&job.leaves).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn exact_process_handles_reject_birth_reuse_and_wait_for_actual_exit() {
    let pid = std::process::id();
    let birth = crate::session::process_start_time(pid).unwrap();
    assert!(platform::Process::open(pid, birth + 1).is_err());
    assert!(platform::Process::open(pid, 0).is_err());
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let process = platform::Process::open(
        child.id(),
        crate::session::process_start_time(child.id()).unwrap(),
    )
    .unwrap()
    .unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || send.send(process.wait()).unwrap());
    assert!(receive.recv_timeout(Duration::from_millis(30)).is_err());
    child.kill().unwrap();
    child.wait().unwrap();
    receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    thread.join().unwrap();
}

#[test]
fn helper_source_must_match_original_resident_bytes() {
    assert!(helper_source(&std::env::current_exe().unwrap(), &"0".repeat(64)).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn helper_admission_bounds_both_silent_ack_and_backpressured_stdin() {
    for bytes in [b"{}".to_vec(), vec![b' '; MAX_JOB as usize]] {
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let started = Instant::now();
        let error = transfer(child, bytes, started + Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "admission extended its deadline"
        );
        let cleanup_deadline = Instant::now() + Duration::from_secs(2);
        while crate::session::process_start_time(pid).is_some() && Instant::now() < cleanup_deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            crate::session::process_start_time(pid).is_none(),
            "failed helper was not reaped"
        );
    }
}
