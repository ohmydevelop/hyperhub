//! Real Windows named-pipe tests. These execute in the native workspace Suite.
use super::*;
use std::sync::{atomic::AtomicU64, Arc};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn endpoint() -> String {
    format!(
        r"\\.\pipe\hh-attachment-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}
struct Server {
    endpoint: String,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<io::Result<()>>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn echo_server() -> Server {
    let endpoint = endpoint();
    let listener = Listener::bind(&endpoint).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let worker = std::thread::spawn(move || {
        listener.run(&done, |value| serde_json::json!({"id":value["id"].clone()}))
    });
    Server {
        endpoint,
        stop,
        worker: Some(worker),
    }
}
#[test]
fn busy_instance_retries_and_two_clients_receive_their_own_response() {
    let server = echo_server();
    let mut first = connect(&server.endpoint).unwrap();
    // The first accepted connection holds the sole instance without a frame.
    let endpoint = server.endpoint.clone();
    let (started, ready) = std::sync::mpsc::sync_channel(1);
    let second = std::thread::spawn(move || {
        started.send(()).unwrap();
        super::super::exchange_raw_for_process(
            &endpoint,
            &serde_json::json!({"id":2}),
            std::process::id(),
        )
    });
    ready.recv().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !second.is_finished(),
        "a busy instance failed instead of waiting for the first client"
    );
    super::super::write_frame(&mut first, br#"{"id":1}"#).unwrap();
    let reply: serde_json::Value =
        serde_json::from_slice(&super::super::read_frame(&mut first).unwrap()).unwrap();
    assert_eq!(reply["id"], 1);
    drop(first);
    let reply = second.join().unwrap().unwrap();
    assert_eq!(reply["id"], 2);
}
#[test]
fn wrong_server_pid_sends_no_credentials_or_approval_bytes() {
    let endpoint = endpoint();
    let listener = Listener::bind(&endpoint).unwrap();
    let worker = std::thread::spawn(move || -> io::Result<usize> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let connected =
                unsafe { ConnectNamedPipe(listener.handle.as_raw_handle(), std::ptr::null_mut()) };
            let error = if connected == 0 {
                unsafe { GetLastError() }
            } else {
                ERROR_PIPE_LISTENING
            };
            if error == ERROR_PIPE_CONNECTED || error == ERROR_NO_DATA {
                break;
            }
            if error != ERROR_PIPE_LISTENING {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "test client did not connect",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut stream = PipeStream {
            handle: &listener.handle,
            deadline,
        };
        let mut byte = [0];
        stream.read(&mut byte)
    });
    let command = AuthenticatedCommand {
        attachment_id: "fixture".into(),
        token: "never-send-this-runtime-token".into(),
        command: HostCommand::Detach,
        proof: Some(ApprovalProof {
            payload: b"never-send-this-approval".to_vec(),
            signature: vec![7; 64],
        }),
        enrollment: None,
        aliases: None,
        root_image: None,
    };
    let error =
        super::super::exchange_for_process(&endpoint, &command, std::process::id().wrapping_add(1))
            .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        worker.join().unwrap().unwrap(),
        0,
        "credentials or approval bytes crossed an unverified server connection"
    );
}
#[test]
fn queued_replies_survive_delayed_reads_and_rearmed_instances_wait_for_clients() {
    let endpoint = endpoint();
    let listener = Listener::bind(&endpoint).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let (handled, observed) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        listener.run_with_peer(&done, |value, peer| {
            assert_eq!(peer, std::process::id());
            handled.send(()).unwrap();
            serde_json::json!({"id": value["id"].clone()})
        })
    });
    let _server = Server {
        endpoint: endpoint.clone(),
        stop,
        worker: Some(worker),
    };
    for id in 0..4 {
        // Also leave the rearmed instance idle between real client arrivals.
        std::thread::sleep(Duration::from_millis(30));
        let mut client = connect(&endpoint).unwrap();
        verify_peer(&client, std::process::id()).unwrap();
        super::super::write_frame(
            &mut client,
            &serde_json::to_vec(&serde_json::json!({"id": id})).unwrap(),
        )
        .unwrap();
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        // Let the server finish its small buffered response before we read.
        // The old immediate DisconnectNamedPipe discarded this response.
        std::thread::sleep(Duration::from_millis(100));
        let reply: serde_json::Value =
            serde_json::from_slice(&super::super::read_frame(&mut client).unwrap()).unwrap();
        assert_eq!(reply["id"], id);
    }
}

#[test]
fn waiting_for_client_close_keeps_the_existing_absolute_deadline() {
    let endpoint = endpoint();
    let listener = Listener::bind(&endpoint).unwrap();
    let _client = connect(&endpoint).unwrap();
    // The client connects before ConnectNamedPipe, so ERROR_PIPE_CONNECTED
    // must be observed before querying or using its connection.
    assert_eq!(
        unsafe { ConnectNamedPipe(listener.handle.as_raw_handle(), std::ptr::null_mut()) },
        0
    );
    assert_eq!(unsafe { GetLastError() }, ERROR_PIPE_CONNECTED);
    let begin = Instant::now();
    let mut stream = PipeStream {
        handle: &listener.handle,
        deadline: begin + Duration::from_millis(50),
    };
    let error = stream.wait_for_client_close().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(begin.elapsed() >= Duration::from_millis(40));
    assert!(begin.elapsed() < Duration::from_secs(1));
}
#[test]
fn busy_connection_deadline_is_total_and_missing_endpoint_is_immediate() {
    let server = echo_server();
    let _first = connect(&server.endpoint).unwrap();
    let begin = Instant::now();
    let error = match connect_until(&server.endpoint, begin + Duration::from_millis(50)) {
        Ok(_) => panic!("occupied pipe unexpectedly accepted another client"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(begin.elapsed() >= Duration::from_millis(40));
    assert!(begin.elapsed() < Duration::from_secs(1));
    let begin = Instant::now();
    let missing = endpoint();
    let error = match connect(&missing) {
        Ok(_) => panic!("missing pipe connected"),
        Err(error) => error,
    };
    assert_eq!(
        error.raw_os_error(),
        Some(windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND as i32)
    );
    assert!(begin.elapsed() < Duration::from_secs(1));
}
