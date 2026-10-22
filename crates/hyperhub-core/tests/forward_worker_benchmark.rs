//! Component benchmark. The wrapper executes functional preflight first and
//! saves raw observations; this target never runs in the ordinary worker suite.
#[path = "forward_worker_benchmark/resources.rs"]
mod resources;
#[allow(dead_code)]
#[path = "forward_workers/support.rs"]
mod support;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn prepare(fixture: &Fixture, id: String) -> (hyperhub_core::socks::WorkerStatus, f64) {
    let manager = fixture.manager.clone();
    let binary = executable();
    let hash = digest(&binary);
    // The executable is already immutable in this manager's cache. Timing
    // includes source verification, cache verification, child boot and health.
    tokio::task::spawn_blocking(move || {
        let started = Instant::now();
        let result = manager.prepare(&id, &binary, &hash).unwrap();
        (result, started.elapsed().as_secs_f64() * 1000.)
    })
    .await
    .unwrap()
}

async fn scenario(state: &str, trial: usize) -> Value {
    let fixture = Fixture::start().await;
    let (origin, server) = echo().await;
    let stop = Arc::new(AtomicBool::new(false));
    let samples = Arc::new(Mutex::new(Vec::<Value>::new()));
    let sampling_stop = stop.clone();
    let sampling_data = samples.clone();
    let manager = fixture.manager.clone();
    let sampling = std::thread::spawn(move || {
        let start = Instant::now();
        while !sampling_stop.load(Ordering::Acquire) {
            let mut processes = vec![resources::sample(std::process::id()).unwrap()];
            for worker in manager
                .status()
                .workers
                .iter()
                .filter(|w| w.phase != "exited")
            {
                if let Ok(sample) = resources::sample(worker.pid) {
                    processes.push(sample);
                }
            }
            sampling_data.lock().unwrap().push(
                json!({"elapsed_ms":start.elapsed().as_secs_f64()*1000.,"processes":processes}),
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let old: usize = state
        .strip_prefix("upgrade-")
        .unwrap_or("0")
        .parse()
        .unwrap();
    let mut held = vec![fixture.connect(1, origin).await];
    exchange(&mut held[0], b"independent-preflight").await;
    for n in 0..old.saturating_sub(1) {
        let id = format!("setup-{n}");
        prepare(&fixture, id.clone()).await;
        fixture.manager.commit(&id).unwrap();
        fixture.manager.finalize(&id).unwrap();
        let mut connection = fixture.connect(2 + n as u64, origin).await;
        exchange(&mut connection, b"retained-generation-preflight").await;
        held.push(connection);
    }
    let mut control = Value::Null;
    if state != "baseline" {
        if old == 0 {
            drop(held.pop());
        }
        let (candidate, prepare_ms) = prepare(&fixture, "measured".into()).await;
        let start = Instant::now();
        fixture.manager.commit("measured").unwrap();
        let commit_ms = start.elapsed().as_secs_f64() * 1000.;
        assert_eq!(
            fixture.manager.status().active_generation,
            candidate.generation
        );
        fixture.manager.finalize("measured").unwrap();
        // Wait for the zero-flow prior worker to exit in the upgrade-0 case.
        if old == 0 {
            let deadline = Instant::now() + Duration::from_secs(10);
            while fixture.manager.status().retained_generations != 0 {
                assert!(Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        assert_eq!(fixture.manager.status().retained_generations, old);
        control = json!({"prepare_ms":prepare_ms,"commit_ms":commit_ms,"old_generations":old});
    }
    for connection in &mut held {
        exchange(connection, b"held-flow-survived-switch").await;
    }
    // Admission burst exercises offer/watchdog thread creation. All clients
    // authenticate concurrently, complete CONNECT, then check a unique token.
    let barrier = Arc::new(tokio::sync::Barrier::new(33));
    let mut burst = Vec::new();
    let mut admission = Vec::new();
    for n in 0..32u64 {
        let address = fixture.address;
        let token = fixture.token.clone();
        let barrier = barrier.clone();
        burst.push(tokio::spawn(async move {
            barrier.wait().await;
            let start = Instant::now();
            let mut stream = authenticate(address, "worker-session", &token, 100 + n).await;
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend(origin.port().to_be_bytes());
            stream.write_all(&request).await.unwrap();
            let mut reply = [0; 10];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply[1], 0);
            let payload = format!("admission-{n:04}");
            exchange(&mut stream, payload.as_bytes()).await;
            start.elapsed().as_secs_f64() * 1000.
        }));
    }
    barrier.wait().await;
    for task in burst {
        admission.push(task.await.unwrap());
    }
    // Closed loop, eight established clients, 128 independently validated
    // 256-byte echoes per client; no request retries or scheduled open arrivals.
    let barrier = Arc::new(tokio::sync::Barrier::new(9));
    let mut tasks = Vec::new();
    for client in 0..8u64 {
        let mut stream = fixture.connect(1000 + client, origin).await;
        for _ in 0..32 {
            exchange(&mut stream, b"warmup-does-not-enter-samples").await;
        }
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let mut latency = Vec::new();
            barrier.wait().await;
            for sequence in 0..128u64 {
                let mut payload = [0u8; 256];
                payload[..8].copy_from_slice(&client.to_be_bytes());
                payload[8..16].copy_from_slice(&sequence.to_be_bytes());
                for (offset, byte) in payload[16..].iter_mut().enumerate() {
                    *byte = (offset as u64 ^ client ^ sequence) as u8;
                }
                let start = Instant::now();
                stream.write_all(&payload).await.unwrap();
                let mut received = [0u8; 256];
                tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut received))
                    .await
                    .unwrap()
                    .unwrap();
                let elapsed = start.elapsed().as_secs_f64() * 1_000_000.;
                assert_eq!(received, payload, "independent payload oracle failed");
                latency.push(elapsed);
            }
            latency
        }));
    }
    let started = Instant::now();
    barrier.wait().await;
    let mut latency = Vec::new();
    for task in tasks {
        latency.extend(task.await.unwrap());
    }
    let duration = started.elapsed().as_secs_f64();
    assert_eq!(latency.len(), 1024);
    for connection in &mut held {
        exchange(connection, b"held-flow-survived-measurement").await;
    }
    stop.store(true, Ordering::Release);
    sampling.join().unwrap();
    let resource_samples = samples.lock().unwrap().clone();
    assert!(!resource_samples.is_empty());
    drop(held);
    fixture.stop().await;
    server.abort();
    json!({"state":state,"trial":trial,"control":control,"admission_ms":admission,"echo_us":latency,"echo_seconds":duration,"echo_per_second":1024./duration,"resource_samples":resource_samples,"accounting":{"offered":1024,"accepted":1024,"succeeded":1024,"failed":0,"rejected":0,"cancelled":0,"unfinished":0,"retries":0}})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit component benchmark; run scripts/benchmark-forward-workers.py"]
async fn measure_worker_switch_and_echo() {
    let output =
        std::env::var_os("HH_FORWARD_BENCHMARK_OUTPUT").expect("set benchmark output path");
    let mut results = Vec::new();
    // Alternate order across independently constructed groups to reduce drift.
    for trial in 0..5 {
        let states = if trial % 2 == 0 {
            vec!["baseline", "upgrade-0", "upgrade-1", "upgrade-4"]
        } else {
            vec!["upgrade-4", "upgrade-1", "upgrade-0", "baseline"]
        };
        for state in states {
            results.push(scenario(state, trial).await);
            std::fs::write(
                &output,
                serde_json::to_vec_pretty(&json!({"schema":1,"trials":results})).unwrap(),
            )
            .unwrap();
        }
    }
}
