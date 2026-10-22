//! Controlled component benchmark: real native decisions and direct switch calls.
use hyperhub_engine::{
    contract::*,
    management::{self, Command, Reply},
    runtime::{artifact::Artifact, native::NativeEngine, Runtime, Settings},
};
use serde_json::json;
use sha2::Digest;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};
#[path = "../../../tests/fixtures/engine_fixture_build.rs"]
mod fixture_build;
fn compile(root: &Path, baseline: bool) -> (PathBuf, String) {
    let version = if baseline { "bench-base" } else { "bench-next" };
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/network_upgrade_engine.rs");
    let output = root.join(format!("{}{}", version, std::env::consts::DLL_SUFFIX));
    let mut command = std::process::Command::new("rustc");
    fixture_build::configure(&mut command);
    command
        .arg("--edition=2021")
        .arg("--crate-type=cdylib")
        .arg("-O")
        .arg(source)
        .arg("-o")
        .arg(&output)
        .env(
            "HH_FIXTURE_VERSION_HASH",
            hyperhub_engine::runtime::artifact::hex(&sha2::Sha256::digest(version.as_bytes())),
        );
    if baseline {
        command.env("HH_FIXTURE_BASELINE", "1");
    }
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    (output, version.into())
}
fn initial(module: &Path, version: &str, cache: &Path) -> Arc<Runtime> {
    let bytes = std::fs::read(module).unwrap();
    let manifest = hyperhub_engine::manifest(&bytes, version);
    let artifact = Artifact::install(cache, &manifest, bytes.as_slice()).unwrap();
    Arc::new(
        Runtime::new(
            Arc::new(unsafe { NativeEngine::load(artifact, None) }.unwrap()),
            Settings::default(),
        )
        .unwrap(),
    )
}
fn decision(lease: &hyperhub_engine::runtime::Lease, operation: u32, request: &PolicyInput) {
    let result = hyperhub_engine::policy(lease, operation, request).unwrap();
    assert_eq!(result.action, "pass");
    assert_eq!(result.rule_id.as_deref(), Some("rule-31"));
    assert_eq!(result.protection.as_deref(), Some("review"));
}
fn apply(runtime: &Runtime, command: Command) {
    assert!(!matches!(
        unsafe { management::execute(runtime, command) },
        Reply::Error { .. }
    ));
}
fn trial(
    root: &Path,
    baseline: &(PathBuf, String),
    candidate: &(PathBuf, String),
    update: bool,
    index: usize,
) -> serde_json::Value {
    let cache = root.join(format!("trial-{update}-{index}"));
    let runtime = initial(&baseline.0, &baseline.1, &cache);
    let pinned = runtime.acquire();
    let request = Arc::new(PolicyInput {
        snapshot: json!({"default_action":"deny", "rules": (0..32).map(|i| json!({"id":format!("rule-{i}"),"action":"pass","patterns":[format!("^fixture-target-{i}$")],"operations":["read"],"protection":"review"})).collect::<Vec<_>>() }),
        target: "fixture-target-31".into(),
        operation: "read".into(),
        command_line: "tool --safe".into(),
    });
    let process_request = Arc::new(PolicyInput {
        snapshot: json!({"default_action":"deny", "rules": (0..32).map(|i| json!({"id":format!("rule-{i}"),"action":"pass","patterns":[{"executable":format!("^fixture-target-{i}$"),"command_line":"--safe"}],"protection":"review"})).collect::<Vec<_>>() }),
        target: "fixture-target-31".into(),
        operation: "execute".into(),
        command_line: "tool --safe".into(),
    });
    for _ in 0..128 {
        decision(&pinned, FILE_POLICY, &request);
        decision(&pinned, PROCESS_POLICY, &process_request);
    }
    let sentinel = PolicyInput {
        snapshot: json!({"default_action":"pass"}),
        target: "engine-policy-deny".into(),
        operation: "read".into(),
        command_line: String::new(),
    };
    assert_eq!(
        hyperhub_engine::policy(&pinned, FILE_POLICY, &sentinel)
            .unwrap()
            .action,
        "pass"
    );
    let gate = Arc::new(Barrier::new(5));
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let runtime = runtime.clone();
        let old = pinned.clone();
        let gate = gate.clone();
        let request = request.clone();
        let process_request = process_request.clone();
        let active = active.clone();
        workers.push(std::thread::spawn(move || {
            active.fetch_add(1, std::sync::atomic::Ordering::Release);
            gate.wait();
            let start = Instant::now();
            let mut completed = 0u64;
            let mut latency = Vec::new();
            while start.elapsed() < Duration::from_millis(250) {
                let clock = Instant::now();
                let calling = runtime.acquire();
                decision(&calling, FILE_POLICY, &request);
                decision(&calling, PROCESS_POLICY, &process_request);
                decision(&old, FILE_POLICY, &request);
                completed += 1;
                if completed.is_multiple_of(64) {
                    latency.push(clock.elapsed().as_nanos() as u64);
                }
            }
            active.fetch_sub(1, std::sync::atomic::Ordering::Release);
            (completed, latency)
        }));
    }
    let wall = Instant::now();
    gate.wait();
    assert_eq!(active.load(std::sync::atomic::Ordering::Acquire), 4);
    let (mut prepare_ns, mut commit_ns) = (0, 0);
    if update {
        let bytes = std::fs::read(&candidate.0).unwrap();
        let manifest = hyperhub_engine::manifest(&bytes, &candidate.1);
        let clock = Instant::now();
        apply(
            &runtime,
            Command::Prepare {
                id: "measured".into(),
                manifest,
                source: candidate.0.clone(),
                cache: cache.clone(),
            },
        );
        prepare_ns = clock.elapsed().as_nanos() as u64;
        assert_eq!(
            active.load(std::sync::atomic::Ordering::Acquire),
            4,
            "preparation outlasted the offered concurrent workload"
        );
        let clock = Instant::now();
        apply(
            &runtime,
            Command::CommitHeld {
                id: "measured".into(),
            },
        );
        commit_ns = clock.elapsed().as_nanos() as u64;
        assert_eq!(
            active.load(std::sync::atomic::Ordering::Acquire),
            4,
            "commit did not overlap all decision workers"
        );
        assert_eq!(
            hyperhub_engine::policy(&runtime.acquire(), FILE_POLICY, &sentinel)
                .unwrap()
                .action,
            "deny"
        );
        assert_eq!(
            hyperhub_engine::policy(&pinned, FILE_POLICY, &sentinel)
                .unwrap()
                .action,
            "pass"
        );
        assert_ne!(runtime.acquire().generation(), pinned.generation());
    }
    let mut completed = 0;
    let mut latencies = Vec::new();
    for worker in workers {
        let (count, samples) = worker.join().unwrap();
        completed += count;
        latencies.extend(samples);
    }
    let elapsed = wall.elapsed().as_nanos() as u64;
    assert!(completed > 0 && !latencies.is_empty());
    latencies.sort_unstable();
    if update {
        runtime.rollback("measured", "benchmark cleanup").unwrap();
    }
    json!({"mode":if update {"upgrade"}else{"baseline"},"trial":index,"prepare_ns":prepare_ns,"commit_ns":commit_ns,
        "completed_units":completed,"native_calls":completed*3,"elapsed_ns":elapsed,"units_per_second":completed as f64*1e9/elapsed as f64,
        "unit_latency_ns_p50":latencies[latencies.len()/2],"unit_latency_ns_p99":latencies[(latencies.len()-1)*99/100],
        "latency_samples_ns":latencies,"correctness":"passed","old_lease_pinned":true,"concurrent_workers_observed":4})
}
fn main() {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("output directory argument");
    std::fs::create_dir_all(&output).unwrap();
    let baseline = compile(&output, true);
    let candidate = compile(&output, false);
    let mut trials = Vec::new();
    for index in 0..5 {
        for upgrade in [false, true] {
            trials.push(trial(&output, &baseline, &candidate, upgrade, index));
        }
    }
    let result = json!({"schema":"native-engine-component-bench-v1","profile":if cfg!(debug_assertions){"debug"}else{"release"},
        "threads":4,"rules":32,"trial_duration_ms":250,"work_unit":"file+process+old-file decisions", "trials":trials});
    std::fs::write(
        output.join("raw.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!(
        "NATIVE_ENGINE_BENCHMARK_OK {}",
        output.join("raw.json").display()
    );
}
