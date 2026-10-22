use super::support::*;
use std::time::Duration;

async fn prepare(fixture: &Fixture, id: String) {
    let worker = fixture.manager.clone();
    let binary = executable();
    let sha = digest(&binary);
    tokio::task::spawn_blocking(move || worker.prepare(&id, &binary, &sha))
        .await
        .unwrap()
        .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn retained_worker_limit_rejects_without_closing_any_old_stream() {
    let fixture = Fixture::start().await;
    let (origin, server) = echo().await;
    let mut streams = vec![fixture.connect(1, origin).await];
    exchange(&mut streams[0], b"generation-one").await;
    for generation in 2..=5 {
        let id = format!("generation-{generation}");
        prepare(&fixture, id.clone()).await;
        fixture.manager.commit(&id).unwrap();
        fixture.manager.finalize(&id).unwrap();
        let mut stream = fixture.connect(generation, origin).await;
        exchange(&mut stream, b"generation-next").await;
        streams.push(stream);
    }
    assert_eq!(fixture.manager.status().retained_generations, 4);
    let manager = fixture.manager.clone();
    let binary = executable();
    let sha = digest(&binary);
    let denied = tokio::task::spawn_blocking(move || manager.prepare("over-limit", &binary, &sha))
        .await
        .unwrap();
    assert_eq!(denied.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    for stream in &mut streams {
        exchange(stream, b"still-alive-at-capacity").await;
    }
    drop(streams.remove(0));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fixture.manager.status().retained_generations == 4 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        fixture.manager.query("generation-2").unwrap().phase,
        "complete"
    );
    fixture.manager.finalize("generation-2").unwrap();
    assert_eq!(
        fixture.manager.query("generation-2").unwrap().phase,
        "complete"
    );
    prepare(&fixture, "after-drain".into()).await;
    fixture.manager.abort("after-drain").unwrap();
    for stream in &mut streams {
        exchange(stream, b"abort-keeps-old-streams").await;
    }
    drop(streams);
    fixture.stop().await;
    server.abort();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn rejected_hash_conflicting_id_and_prepared_abort_preserve_active_worker() {
    let fixture = Fixture::start().await;
    let (origin, server) = echo().await;
    let initial = fixture.manager.status().active_generation;
    let mut stream = fixture.connect(1, origin).await;
    exchange(&mut stream, b"before-invalid").await;
    let manager = fixture.manager.clone();
    let binary = executable();
    assert!(tokio::task::spawn_blocking(move || manager.prepare(
        "bad-hash",
        &binary,
        &"0".repeat(64)
    ))
    .await
    .unwrap()
    .is_err());
    assert_eq!(fixture.manager.status().active_generation, initial);
    prepare(&fixture, "prepared-abort".into()).await;
    let manager = fixture.manager.clone();
    let binary = executable();
    assert!(tokio::task::spawn_blocking(move || manager.prepare(
        "prepared-abort",
        &binary,
        &"0".repeat(64)
    ))
    .await
    .unwrap()
    .is_err());
    fixture.manager.abort("prepared-abort").unwrap();
    fixture.manager.abort("prepared-abort").unwrap();
    assert!(fixture.manager.commit("prepared-abort").is_err());
    exchange(&mut stream, b"after-invalid-and-abort").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fixture.manager.status().retained_generations != 0 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(stream);
    fixture.stop().await;
    server.abort();
}

#[cfg(target_os = "linux")]
fn stop_owned_worker(worker: &hyperhub_core::socks::WorkerStatus) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, worker.pid, 0) as i32 };
    assert!(raw >= 0);
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", worker.pid)).unwrap();
    let start: u64 = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(worker.start_time, Some(start));
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                descriptor.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
}
#[cfg(windows)]
fn stop_owned_worker(worker: &hyperhub_core::socks::WorkerStatus) {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{
            GetProcessTimes, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_TERMINATE,
        },
    };
    let raw = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            worker.pid,
        )
    };
    assert!(!raw.is_null());
    let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    let mut created: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit = created;
    let mut kernel = created;
    let mut user = created;
    assert_ne!(
        unsafe {
            GetProcessTimes(
                handle.as_raw_handle().cast(),
                &mut created,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        },
        0
    );
    assert_eq!(
        worker.start_time,
        Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    );
    assert_ne!(
        unsafe { TerminateProcess(handle.as_raw_handle().cast(), 73) },
        0
    );
}
#[cfg(any(target_os = "linux", windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn candidate_process_failure_rolls_back_future_dispatch_without_touching_old_streams() {
    let fixture = Fixture::start().await;
    let (origin, server) = echo().await;
    let initial = fixture.manager.status().active_generation;
    let mut old = fixture.connect(1, origin).await;
    exchange(&mut old, b"old-before-worker-fault").await;
    prepare(&fixture, "worker-crash".into()).await;
    let candidate = fixture.manager.commit("worker-crash").unwrap();
    stop_owned_worker(&candidate);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fixture
        .manager
        .status()
        .workers
        .iter()
        .find(|worker| worker.pid == candidate.pid)
        .unwrap()
        .phase
        != "exited"
    {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(fixture.manager.finalize("worker-crash").is_err());
    fixture.manager.rollback("worker-crash").unwrap();
    fixture.manager.rollback("worker-crash").unwrap();
    assert_eq!(fixture.manager.status().active_generation, initial);
    let mut restored = fixture.connect(2, origin).await;
    exchange(&mut restored, b"new-after-worker-fault").await;
    exchange(&mut old, b"old-after-worker-fault").await;
    drop((old, restored));
    fixture.stop().await;
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn concurrent_handoff_and_session_cancel_preserve_other_sessions() {
    use tokio::io::AsyncReadExt;
    let fixture = Fixture::start().await;
    let (origin, server) = echo().await;
    let mut survivor = fixture.connect(1, origin).await;
    exchange(&mut survivor, b"survivor-before-race").await;
    let token = add_session(&fixture.registry, "revoked-session");
    let address = fixture.address;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(33));
    let mut clients = Vec::new();
    for id in 100..132 {
        let token = token.clone();
        let barrier = barrier.clone();
        clients.push(tokio::spawn(async move {
            let mut client = authenticate(address, "revoked-session", &token, id).await;
            barrier.wait().await;
            let mut byte = [0];
            let closed = tokio::time::timeout(Duration::from_secs(10), client.read(&mut byte))
                .await
                .unwrap();
            assert!(matches!(closed, Ok(0) | Err(_)));
        }));
    }
    barrier.wait().await;
    assert!(fixture.registry.revoke("revoked-session"));
    for client in clients {
        client.await.unwrap();
    }
    for _ in 0..16 {
        exchange(&mut survivor, b"survivor-after-race").await;
    }
    assert!(fixture
        .manager
        .status()
        .workers
        .iter()
        .all(|worker| worker.healthy));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fixture
        .manager
        .status()
        .workers
        .iter()
        .map(|worker| worker.live_connections)
        .sum::<usize>()
        != 1
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "cancelled offers were not released: {:?}",
            fixture.manager.status()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let snapshots = fixture.service.connections().snapshot();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].session_id, "worker-session");
    drop(survivor);
    fixture.stop().await;
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn disconnected_control_drains_granted_streams_and_preserves_central_revocation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn stage<T>(name: &str, operation: impl std::future::Future<Output = T>) -> T {
        eprintln!("DISCONNECTED_CONTROL_STAGE begin={name}");
        let result = tokio::time::timeout(Duration::from_secs(10), operation)
            .await
            .unwrap_or_else(|_| panic!("disconnected control stage {name} exceeded 10s"));
        eprintln!("DISCONNECTED_CONTROL_STAGE complete={name}");
        result
    }
    eprintln!("DISCONNECTED_CONTROL_STAGE begin=fixture-startup");
    let fixture = Fixture::start().await;
    eprintln!("DISCONNECTED_CONTROL_STAGE complete=fixture-startup");
    let (origin, server) = echo().await;
    let stalled = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let stalled_address = stalled.local_addr().unwrap();
    let stalled_server = tokio::spawn(async move {
        let (mut stream, _) = stalled.accept().await.unwrap();
        let mut bytes = [0; 4096];
        loop {
            match stream.read(&mut bytes).await {
                Ok(0) | Err(_) => {
                    // An origin can ignore a peer half-close. Central revoke
                    // must still close the whole child flow without this peer
                    // helping its cleanup.
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    drop(stream);
                    break;
                }
                Ok(count) => stream.write_all(&bytes[..count]).await.unwrap(),
            }
        }
    });
    let legitimate_origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let legitimate_address = legitimate_origin.local_addr().unwrap();
    let (started, observed_start) = tokio::sync::oneshot::channel();
    let (half_closed, observed_half_close) = tokio::sync::oneshot::channel();
    let response_allowed = std::sync::Arc::new(tokio::sync::Notify::new());
    let response_waiter = response_allowed.clone();
    let legitimate_server = tokio::spawn(async move {
        let (mut stream, _) = legitimate_origin.accept().await.unwrap();
        let mut request = vec![0; b"half-close-request".len()];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, b"half-close-request");
        started.send(()).unwrap();
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
        half_closed.send(()).unwrap();
        response_waiter.notified().await;
        stream.write_all(b"half-close-response").await.unwrap();
    });
    let other_token = add_session(&fixture.registry, "other-control-session");
    let initial = fixture.manager.status().active_generation;
    eprintln!("DISCONNECTED_CONTROL_STAGE begin=candidate-prepare");
    prepare(&fixture, "control-failure".into()).await;
    eprintln!("DISCONNECTED_CONTROL_STAGE complete=candidate-prepare");
    let candidate = fixture.manager.commit("control-failure").unwrap();
    let mut closed = fixture.connect(901, origin).await;
    let mut survivor = fixture.connect(902, stalled_address).await;
    exchange(&mut closed, b"before-control-loss").await;
    exchange(&mut survivor, b"before-control-loss").await;
    let mut other = fixture
        .connect_session("other-control-session", &other_token, 904, origin)
        .await;
    exchange(&mut other, b"other-session-before-loss").await;
    let mut legitimate = fixture
        .connect_session(
            "other-control-session",
            &other_token,
            905,
            legitimate_address,
        )
        .await;
    legitimate.write_all(b"half-close-request").await.unwrap();
    stage("origin-observed-request", observed_start)
        .await
        .unwrap();
    let manager = fixture.manager.clone();
    stage(
        "quarantine-control",
        tokio::task::spawn_blocking(move || {
            manager.quarantine(candidate.generation, "fixture control channel failure")
        }),
    )
    .await
    .unwrap()
    .unwrap();
    fixture.manager.rollback("control-failure").unwrap();
    assert_eq!(fixture.manager.status().active_generation, initial);
    exchange(&mut survivor, b"granted-flow-survives-control-loss").await;
    legitimate.shutdown().await.unwrap();
    stage("origin-observed-half-close", observed_half_close)
        .await
        .unwrap();
    closed.shutdown().await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), closed.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    exchange(&mut survivor, b"another-flow-survives-completion").await;
    let mut future = fixture.connect(903, origin).await;
    exchange(&mut future, b"rollback-only-changes-future-dispatch").await;
    assert!(fixture.registry.revoke("worker-session"));
    for stream in [&mut survivor, &mut future] {
        let result = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fixture
        .service
        .connections()
        .snapshot()
        .iter()
        .any(|snapshot| snapshot.session_id == "worker-session")
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "cancelled session leases were not released while another session remained live"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    exchange(&mut other, b"other-session-after-central-revoke").await;
    // Hold a valid remote half-close across more than two fallback intervals.
    // The native probe unit test independently verifies the exact distinction.
    tokio::time::sleep(Duration::from_millis(600)).await;
    response_allowed.notify_one();
    let mut response = vec![0; b"half-close-response".len()];
    tokio::time::timeout(
        Duration::from_secs(10),
        legitimate.read_exact(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response, b"half-close-response");
    exchange(&mut other, b"other-session-still-live-after-half-close").await;
    drop((closed, survivor, future, other, legitimate));
    stage("legitimate-origin-completion", legitimate_server)
        .await
        .unwrap();
    stage("fixture-drain", fixture.stop()).await;
    server.abort();
    stalled_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn whole_prepare_deadline_covers_a_child_that_never_reads_bootstrap() {
    let fixture = Fixture::start().await;
    let initial = fixture.manager.status().active_generation;
    let binary = fixture
        .root
        .join(format!("silent-worker{}", std::env::consts::EXE_SUFFIX));
    let marker = fixture.root.join("silent-entered");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/forward_worker_silent.rs");
    let output = std::process::Command::new("rustc")
        .args(["--edition=2021", "--crate-name", "forward_worker_silent"])
        .arg(source)
        .arg("-o")
        .arg(&binary)
        .env("HH_SILENT_WORKER_MARKER", &marker)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Exceeds both the Windows anonymous pipe and Unix datagram queue capacity.
    // Each entry remains a valid HTTP header name, so configuration validation
    // cannot short circuit the blocked transport send being tested.
    let runtime = fixture.service.runtime();
    let mut config = (*runtime.snapshot().config).clone();
    config.audit.header_allowlist = (0..8192)
        .map(|id| format!("x-silent-{id:05}-{}", "a".repeat(80)))
        .collect();
    runtime.apply(std::sync::Arc::new(config)).unwrap();
    let hash = digest(&binary);
    let manager = fixture.manager.clone();
    let start = std::time::Instant::now();
    let error =
        tokio::task::spawn_blocking(move || manager.prepare("silent-bootstrap", &binary, &hash))
            .await
            .unwrap()
            .unwrap_err();
    let elapsed = start.elapsed();
    assert!(
        marker.is_file(),
        "fixture did not enter its no-read phase: {error}"
    );
    assert!(
        elapsed >= Duration::from_secs(29),
        "failure preceded the absolute deadline: {elapsed:?}: {error}"
    );
    assert!(
        elapsed < Duration::from_secs(34),
        "blocked bootstrap escaped the 30s phase budget: {elapsed:?}: {error}"
    );
    assert_eq!(fixture.manager.status().active_generation, initial);
    assert_eq!(fixture.manager.status().retained_generations, 0);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn health_deadline_closes_control_when_booted_child_stops_consuming_messages() {
    let fixture = Fixture::start().await;
    let initial = fixture.manager.status().active_generation;
    let binary = fixture.root.join(format!(
        "unresponsive-worker{}",
        std::env::consts::EXE_SUFFIX
    ));
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/forward_worker_unresponsive.rs");
    let output = std::process::Command::new("rustc")
        .args([
            "--edition=2021",
            "--crate-name",
            "forward_worker_unresponsive",
        ])
        .arg(source)
        .arg("-o")
        .arg(&binary)
        .env("HH_TEST_WORKER_VERSION", env!("CARGO_PKG_VERSION"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hash = digest(&binary);
    let manager = fixture.manager.clone();
    let candidate = tokio::task::spawn_blocking(move || {
        manager.prepare("unresponsive-control", &binary, &hash)
    })
    .await
    .unwrap()
    .unwrap();
    let start = std::time::Instant::now();
    loop {
        let worker = fixture
            .manager
            .status()
            .workers
            .into_iter()
            .find(|worker| worker.generation == candidate.generation)
            .unwrap();
        if !worker.healthy && worker.reason.is_some() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(34),
            "monitor did not close an unhealthy channel: {worker:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(start.elapsed() >= Duration::from_secs(29));
    assert_eq!(fixture.manager.status().active_generation, initial);
    fixture.manager.abort("unresponsive-control").unwrap();
    fixture.stop().await;
}
