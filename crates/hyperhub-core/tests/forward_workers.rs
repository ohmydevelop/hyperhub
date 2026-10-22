#[path = "forward_workers/faults.rs"]
mod faults;
#[path = "forward_workers/preflight.rs"]
mod preflight;
#[path = "forward_workers/protocols.rs"]
mod protocols;
#[path = "forward_workers/ssh.rs"]
mod ssh;
#[path = "forward_workers/support.rs"]
mod support;
use std::net::SocketAddr;
use std::time::Duration;
use support::*;
use tokio::io::AsyncReadExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn real_worker_generations_preserve_streams_fake_ip_authority_and_cancellation() {
    let fixture = Fixture::start().await;
    let resident_pid = std::process::id();
    let (origin, server) = echo().await;
    let initial = fixture.manager.status().workers[0].clone();
    assert_ne!(initial.pid, resident_pid);
    let mut old = fixture.connect(1, origin).await;
    exchange(&mut old, b"old-generation").await;
    let binary = executable();
    let sha = digest(&binary);
    let manager = fixture.manager.clone();
    let artifact = binary.clone();
    let hash = sha.clone();
    let prepared =
        tokio::task::spawn_blocking(move || manager.prepare("upgrade-one", &artifact, &hash))
            .await
            .unwrap()
            .unwrap();
    assert_ne!(prepared.pid, initial.pid);
    fixture.manager.commit("upgrade-one").unwrap();
    let mut current = fixture.connect(2, origin).await;
    // A live identity belongs to its original socket across worker generations.
    // A second authenticated socket must close before reading CONNECT; allowing
    // it to wait for payload would hide an Agent image's connection-ID reuse.
    let mut duplicate = authenticate(fixture.address, "worker-session", &fixture.token, 1).await;
    let rejected = tokio::time::timeout(Duration::from_secs(10), duplicate.read(&mut [0]))
        .await
        .expect("duplicate live identity was allowed to wait for CONNECT");
    assert!(matches!(rejected, Ok(0) | Err(_)));
    assert_eq!(fixture.service.connections().snapshot().len(), 2);
    drop(duplicate);
    for index in 0..32 {
        let bytes = format!("echo-{index:04}");
        exchange(&mut old, bytes.as_bytes()).await;
        exchange(&mut current, bytes.as_bytes()).await;
    }
    let fake = fixture
        .registry
        .resolve_fake("worker-session", &fixture.token, "localhost", 4)
        .unwrap();
    let mut by_fake = fixture
        .connect(3, SocketAddr::new(fake, origin.port()))
        .await;
    exchange(&mut by_fake, b"fake-IP-survives").await;
    let snapshots = fixture.service.connections().snapshot();
    assert_eq!(snapshots.len(), 3);
    assert!(snapshots
        .iter()
        .all(|snapshot| snapshot.pid == resident_pid && snapshot.session_id == "worker-session"));
    assert!(snapshots.iter().any(|snapshot| snapshot.connection_id == 3
        && snapshot.original_destination.hostnames == vec!["localhost"]));
    fixture.manager.rollback("upgrade-one").unwrap();
    let mut restored = fixture.connect(4, origin).await;
    exchange(&mut restored, b"future-rollback").await;
    exchange(&mut current, b"candidate-still-drains").await;
    assert_eq!(
        fixture.manager.status().active_generation,
        initial.generation
    );
    assert!(fixture.registry.revoke("worker-session"));
    for stream in [&mut old, &mut current, &mut by_fake, &mut restored] {
        let mut byte = [0];
        let result = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !fixture.service.connections().snapshot().is_empty() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(std::process::id(), resident_pid);
    drop((old, current, by_fake, restored));
    fixture.stop().await;
    server.abort();
}
