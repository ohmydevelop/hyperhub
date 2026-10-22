use super::support::*;
use hyperhub_core::connector::EnvironmentProxy;
use hyperhub_core::engine_hosts::EngineHosts;
use hyperhub_core::session::{unix_timestamp_ms, SessionRegistry};
use hyperhub_core::socks::SocksService;
use hyperhub_core::{release, upgrade};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

fn engine_manifest(bytes: &[u8]) -> hyperhub_runtime::Manifest {
    hyperhub_engine::manifest(bytes, hyperhub_engine::VERSION)
}
fn production_engine() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!(
            "{}hyperhub_engine{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ))
}
fn wrong_abi(root: &Path) -> PathBuf {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/upgrade_engine.rs");
    let output = root.join(format!("wrong-abi{}", std::env::consts::DLL_SUFFIX));
    let version_hash =
        hyperhub_runtime::artifact::hex(&Sha256::digest(hyperhub_engine::VERSION.as_bytes()));
    let result = std::process::Command::new("rustc")
        .args([
            "--edition=2021",
            "--crate-type=cdylib",
            "--cfg",
            "incompatible_abi",
        ])
        .arg(source)
        .arg("-o")
        .arg(&output)
        .env("HH_FIXTURE_VERSION_HASH", version_hash)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn isolated_candidate_checks_native_engine_without_any_target_hosts() {
    let fixture = Fixture::start().await;
    let initial = fixture.manager.status().active_generation;
    let corrupt = fixture.root.join("corrupt-engine");
    std::fs::write(&corrupt, b"not a native Engine").unwrap();
    let incompatible = wrong_abi(&fixture.root);
    for (id, source, unsupported) in [
        ("corrupt-native", corrupt, false),
        ("wrong-native-abi", incompatible, true),
    ] {
        let manager = fixture.manager.clone();
        let binary = executable();
        let hash = digest(&binary);
        let bytes = std::fs::read(&source).unwrap();
        let manifest = engine_manifest(&bytes);
        let cache = fixture.root.join(id);
        let error = tokio::task::spawn_blocking(move || {
            manager.prepare_bundle(id, &binary, &hash, &manifest, &source, &cache)
        })
        .await
        .unwrap()
        .unwrap_err();
        if unsupported {
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        }
        assert_eq!(fixture.manager.status().active_generation, initial);
        assert_eq!(fixture.manager.status().retained_generations, 0);
    }
    let source = production_engine();
    assert!(source.is_file(), "current Cargo Engine cdylib is missing");
    let bytes = std::fs::read(&source).unwrap();
    let manifest = engine_manifest(&bytes);
    let manager = fixture.manager.clone();
    let binary = executable();
    let hash = digest(&binary);
    let cache = fixture.root.join("valid-native");
    tokio::task::spawn_blocking(move || {
        manager.prepare_bundle("valid-native", &binary, &hash, &manifest, &source, &cache)
    })
    .await
    .unwrap()
    .unwrap();
    fixture.manager.abort("valid-native").unwrap();
    fixture.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn zero_host_release_rejects_native_abi_before_publishing_global_stable_generation() {
    let root = std::env::temp_dir().join(format!(
        "hh-worker-zero-host-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    let sessions = SessionRegistry::default();
    let service = SocksService::new(Arc::new(hyperhub_core::Config::default()), sessions.clone())
        .unwrap()
        .with_environment_proxy(EnvironmentProxy::default())
        .unwrap();
    let executable = executable();
    let binary = executable.clone();
    let service = tokio::task::spawn_blocking(move || service.with_forward_workers(binary))
        .await
        .unwrap()
        .unwrap();
    let manager = service.forward_workers().unwrap();
    let hosts = EngineHosts::default();
    assert!(hosts.host(None).is_empty());
    assert!(sessions.snapshot().is_empty());
    let key = Zeroizing::new(vec![17u8; 32]);
    let engine =
        upgrade::Coordinator::open(&root.join("engine-journal"), key.clone(), hosts.clone())
            .unwrap();
    let target = root.join(format!("installed-fixture{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(&executable, &target).unwrap();
    let expected = digest(&target);
    let coordinator = release::Coordinator::open(
        &root.join("release-journal"),
        key,
        engine.clone(),
        hosts,
        manager.clone(),
        &target,
        sessions,
    )
    .unwrap();
    let source = wrong_abi(&root);
    let bytes = std::fs::read(&source).unwrap();
    let manifest = engine_manifest(&bytes);
    let worker_bytes = std::fs::metadata(&executable).unwrap().len();
    let bundle = release::Bundle {
        format: 1,
        version: hyperhub_engine::VERSION.into(),
        target: hyperhub_engine::TARGET.into(),
        base: release::Base::resident(),
        engine: manifest,
        engine_file: release::engine_name().into(),
        worker_sha256: digest(&executable),
        worker_size: worker_bytes,
    };
    let plan = release::Plan {
        bundle,
        executable,
        engine: source,
        cache: root.join("native-cache"),
        target: target.clone(),
        expected_target_sha256: expected.clone(),
    };
    coordinator
        .submit(release::Request {
            id: "no-host-bad-abi".into(),
            issued_at_ms: unix_timestamp_ms(),
            action: release::Action::Prepare {
                plan,
                auto_commit: true,
            },
        })
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = coordinator.status(Some("no-host-bad-abi"));
        let record = &status.records[0];
        if record.phase.terminal() {
            assert!(!record.finalize_decided);
            assert!(!record.installation_confirmed);
            assert!(matches!(
                record.phase,
                release::Phase::Failed
                    | release::Phase::RequiresRestart
                    | release::Phase::RolledBack
            ));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "release did not reject: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(digest(&target), expected);
    assert_eq!(manager.status().active_generation, 1);
    assert!(
        engine.status(None).records.is_empty(),
        "native Engine coordination must not start after candidate preflight rejection"
    );
    coordinator.stop_runner();
    engine.stop_runner();
    manager.shutdown();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while manager
        .status()
        .workers
        .iter()
        .any(|worker| worker.phase != "exited")
    {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop((coordinator, engine, manager, service));
    remove_private_tree(&root);
}
