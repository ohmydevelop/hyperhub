use hyperhub_runtime::artifact::{hex, Artifact};
use hyperhub_runtime::native::{Host, NativeEngine};
use hyperhub_runtime::{abi, Engine, Error, Manifest, Runtime, Settings, Stage};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "modules-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn cache(&self) -> PathBuf {
        self.0.join("cache")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        // Only these test-owned artifacts are removed. Windows requires clearing
        // read-only flags after all module and verification handles are closed.
        #[cfg(windows)]
        fn writable(path: &Path) {
            if path.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    writable(&entry.unwrap().path());
                }
            } else {
                let mut permissions = fs::metadata(path).unwrap().permissions();
                permissions.set_readonly(false);
                fs::set_permissions(path, permissions).unwrap();
            }
        }
        #[cfg(windows)]
        writable(&self.0);
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn manifest(version: &str, bytes: &[u8]) -> Manifest {
    Manifest {
        version: version.into(),
        target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        abi: abi::ABI_V1,
        state_schema: 1,
        hooks: 3,
        sha256: hex(&Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}
fn build(root: &Root, version: &str, cfg: Option<&str>) -> (Manifest, Vec<u8>) {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/upgrade_engine.rs");
    let output = root
        .0
        .join(format!("engine-{version}{}", std::env::consts::DLL_SUFFIX));
    let mut cmd = Command::new("rustc");
    cmd.arg("--edition=2021")
        .arg("--crate-type=cdylib")
        .arg(&fixture)
        .arg("-o")
        .arg(&output)
        .env(
            "HH_FIXTURE_VERSION_HASH",
            hex(&Sha256::digest(version.as_bytes())),
        );
    if let Some(cfg) = cfg {
        cmd.arg("--cfg").arg(cfg);
    }
    let result = cmd.output().unwrap();
    assert!(
        result.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = fs::read(output).unwrap();
    (manifest(version, &bytes), bytes)
}
struct Echo;
impl Host for Echo {
    fn call(
        &self,
        _: &hyperhub_runtime::Lease,
        operation: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, i32> {
        assert_eq!(operation, 7);
        if output.len() < input.len() {
            return Err(abi::BUFFER_TOO_SMALL);
        }
        output[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }
}
fn load(root: &Root, manifest: &Manifest, bytes: &[u8]) -> Arc<dyn Engine> {
    let artifact = Artifact::install(&root.cache(), manifest, bytes).unwrap();
    Arc::new(unsafe { NativeEngine::load(artifact, Some(Arc::new(Echo))).unwrap() })
}
fn answer(lease: &hyperhub_runtime::Lease) -> u64 {
    let mut output = [0; 8];
    assert_eq!(lease.invoke(0, &[1, 2, 3], &mut output), Ok(8));
    u64::from_le_bytes(output)
}

#[test]
fn real_native_code_switches_while_old_leases_keep_their_implementation() {
    let root = Root::new();
    let (v1, one) = build(&root, "1.0.0", None);
    let (v2, two) = build(&root, "2.0.0", Some("engine_v2"));
    let runtime = Runtime::new(
        load(&root, &v1, &one),
        Settings {
            health_window: Duration::ZERO,
            ..Settings::default()
        },
    )
    .unwrap();
    let pending = runtime.acquire();
    let foreign = load(&root, &v2, &two);
    assert_eq!(
        foreign.invoke(&pending, 0, &[], &mut [0; 8]),
        Err(abi::INVALID)
    );
    drop(foreign);
    assert_eq!(answer(&pending), 106);
    runtime
        .prepare("real-swap", &v2, || Ok(load(&root, &v2, &two)))
        .unwrap();
    runtime.commit("real-swap").unwrap();
    runtime.observe().unwrap();
    assert_eq!(answer(&runtime.acquire()), 206);
    assert_eq!(answer(&pending), 106);
    assert_eq!(
        runtime.snapshot().unwrap().transactions[0].stage,
        Stage::Draining
    );
    let mut echo = [0; 5];
    assert_eq!(runtime.acquire().invoke(1, b"hello", &mut echo), Ok(5));
    assert_eq!(&echo, b"hello");
    assert_eq!(
        runtime.acquire().invoke(3, &[], &mut echo),
        Err(abi::FAILED)
    );
    drop(pending);
    assert_eq!(
        runtime.snapshot().unwrap().transactions[0].stage,
        Stage::Complete
    );
}

#[test]
fn real_module_failure_rolls_back_new_calls_without_unloading_pending_code() {
    let root = Root::new();
    let (v1, one) = build(&root, "1.1.0", None);
    let (v2, two) = build(&root, "2.1.0", Some("engine_v2"));
    let runtime = Runtime::new(load(&root, &v1, &one), Settings::default()).unwrap();
    runtime
        .prepare("real-rollback", &v2, || Ok(load(&root, &v2, &two)))
        .unwrap();
    runtime.commit("real-rollback").unwrap();
    let pending = runtime.acquire();
    assert_eq!(pending.invoke(2, &[], &mut []), Ok(0));
    runtime.observe().unwrap();
    assert_eq!(answer(&runtime.acquire()), 106);
    assert_eq!(answer(&pending), 206);
    assert_eq!(
        runtime.snapshot().unwrap().transactions[0].stage,
        Stage::RolledBack
    );
}

#[test]
fn native_table_abi_mismatch_is_rejected_even_with_valid_file_hash() {
    let root = Root::new();
    let (manifest, bytes) = build(&root, "broken", Some("incompatible_abi"));
    let artifact = Artifact::install(&root.cache(), &manifest, &bytes[..]).unwrap();
    assert!(matches!(
        unsafe { NativeEngine::load(artifact, None) },
        Err(Error::RequiresRestart)
    ));
}

#[test]
fn size_and_digest_failures_leave_no_loadable_cache_object() {
    let root = Root::new();
    let bytes = b"module bytes";
    let valid = manifest("1", bytes);
    for bad in [
        &b"short"[..],
        &b"longer than module bytes"[..],
        &b"module bytex"[..],
    ] {
        assert!(Artifact::install(&root.cache(), &valid, bad).is_err());
        assert_eq!(fs::read_dir(root.cache()).unwrap().count(), 0);
    }
    let mut invalid = valid.clone();
    invalid.sha256 = "../escape".into();
    assert!(matches!(
        Artifact::install(&root.cache(), &invalid, &bytes[..]),
        Err(Error::InvalidManifest)
    ));
    let mut oversized = valid.clone();
    oversized.size = 513 * 1024 * 1024;
    assert!(Artifact::install(&root.cache(), &oversized, &bytes[..]).is_err());
}

#[test]
fn concurrent_cache_installs_validate_existing_objects_without_overwriting() {
    let root = Root::new();
    let bytes = b"same module";
    let manifest = manifest("1", bytes);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let cache = root.cache();
            let manifest = manifest.clone();
            std::thread::spawn(move || Artifact::install(&cache, &manifest, &bytes[..]).unwrap())
        })
        .collect();
    let objects: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for artifact in &objects {
        assert_eq!(fs::read(artifact.path()).unwrap(), bytes);
    }
    assert_eq!(fs::read_dir(root.cache()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn symlink_or_writable_cache_is_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = Root::new();
    let bytes = b"valid";
    let manifest = manifest("1", bytes);
    let artifact = Artifact::install(&root.cache(), &manifest, &bytes[..]).unwrap();
    let path = artifact.path().to_owned();
    drop(artifact);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Artifact::install(&root.cache(), &manifest, &bytes[..]).is_err());
    fs::remove_file(&path).unwrap();
    symlink(root.0.join("elsewhere"), &path).unwrap();
    assert!(Artifact::install(&root.cache(), &manifest, &bytes[..]).is_err());
    fs::set_permissions(root.cache(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Artifact::install(&root.cache(), &manifest, &bytes[..]).is_err());
}

#[derive(Default)]
struct AsyncHost {
    pending: std::sync::Mutex<Vec<hyperhub_runtime::Lease>>,
}
impl Host for AsyncHost {
    fn call(
        &self,
        calling: &hyperhub_runtime::Lease,
        operation: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, i32> {
        assert_eq!(operation, 7);
        if output.len() < input.len() {
            return Err(abi::BUFFER_TOO_SMALL);
        }
        self.pending.lock().unwrap().push(calling.clone());
        output[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }
}
#[test]
fn host_async_work_pins_the_calling_generation_after_a_concurrent_switch() {
    let root = Root::new();
    let (v1, one) = build(&root, "async-1", None);
    let (v2, two) = build(&root, "async-2", Some("engine_v2"));
    let host = Arc::new(AsyncHost::default());
    let first = Artifact::install(&root.cache(), &v1, &one[..]).unwrap();
    let runtime = Runtime::new(
        Arc::new(unsafe { NativeEngine::load(first, Some(host.clone())).unwrap() }),
        Settings {
            health_window: Duration::ZERO,
            ..Settings::default()
        },
    )
    .unwrap();
    let entered = runtime.acquire();
    runtime
        .prepare("async-swap", &v2, || {
            let artifact = Artifact::install(&root.cache(), &v2, &two[..]).unwrap();
            Ok(Arc::new(unsafe {
                NativeEngine::load(artifact, Some(host.clone())).unwrap()
            }))
        })
        .unwrap();
    runtime.commit("async-swap").unwrap();
    runtime.observe().unwrap();
    // The old invocation enters Host services AFTER the active pointer changed.
    // Capturing active here would pin the wrong library for its completion.
    assert_eq!(entered.invoke(1, b"old", &mut [0; 3]), Ok(3));
    drop(entered);
    assert_eq!(runtime.acquire().invoke(1, b"new", &mut [0; 3]), Ok(3));
    let status = runtime.snapshot().unwrap();
    assert_eq!(status.retired[0].references, 1);
    let pending = std::mem::take(&mut *host.pending.lock().unwrap());
    assert_eq!(pending[0].generation(), 0);
    assert_eq!(pending[1].generation(), 1);
    assert_eq!(answer(&pending[0]), 106);
    assert_eq!(answer(&pending[1]), 206);
    drop(pending);
    assert!(runtime.snapshot().unwrap().retired.is_empty());
}
