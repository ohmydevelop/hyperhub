use super::*;

#[test]
fn transport_errors_retry_but_protocol_and_authorization_errors_do_not() {
    let deadline = StartupDeadline(Instant::now() + Duration::from_secs(2));
    let mut calls = 0;
    assert_eq!(
        deadline
            .retry(|| {
                calls += 1;
                if calls < 3 {
                    Err(io::Error::from(io::ErrorKind::ConnectionReset))
                } else {
                    Ok(7)
                }
            })
            .unwrap(),
        7
    );
    assert_eq!(calls, 3);
    for kind in [
        io::ErrorKind::InvalidData,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::InvalidInput,
    ] {
        let mut calls = 0;
        assert_eq!(
            deadline
                .retry::<()>(|| {
                    calls += 1;
                    Err(io::Error::from(kind))
                })
                .unwrap_err()
                .kind(),
            kind
        );
        assert_eq!(calls, 1);
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::{fs::DirBuilderExt, net::UnixListener};
    use std::sync::mpsc;

    const TRUST_RESPONSE: &[u8] = br#"{"type":"trust_bootstrap","socks_address":"127.0.0.1:12345","agent_flags":{"observe":false},"environment":[],"tls_ca_pem":"-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----"}"#;

    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "hh-startup-{}-{:x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            Self(root)
        }
        fn endpoint(&self) -> String {
            self.0.join("socket").to_string_lossy().into_owned()
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn request() -> AgentControlRequest<'static> {
        AgentControlRequest::GetTrust {
            session_id: "dummy-session",
            token: "dummy-token",
        }
    }
    fn read_request(stream: &mut std::os::unix::net::UnixStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let mut payload = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut payload).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(value["type"], "get_trust");
    }

    fn accept(listener: &UnixListener) -> std::os::unix::net::UnixStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "test client never connected");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("test listener failed: {error}"),
            }
        }
    }

    #[test]
    fn missing_control_socket_retries_until_a_new_listener_is_ready() {
        let root = Root::new();
        let endpoint = root.endpoint();
        let server_endpoint = endpoint.clone();
        let (failed, first_failure) = mpsc::channel();
        let server = std::thread::spawn(move || {
            first_failure.recv_timeout(Duration::from_secs(2)).unwrap();
            let listener = UnixListener::bind(server_endpoint).unwrap();
            let mut stream = accept(&listener);
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            assert_eq!(byte, [7]);
        });
        let deadline = StartupDeadline(Instant::now() + Duration::from_secs(2));
        let mut missing_was_observed = false;
        let mut stream = deadline
            .retry(|| {
                let result = deadline.connect(&endpoint);
                if result
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
                    && !missing_was_observed
                {
                    missing_was_observed = true;
                    failed.send(()).unwrap();
                }
                result
            })
            .unwrap();
        assert!(missing_was_observed);
        stream.write_all(&[7]).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn retries_connection_loss_before_receiving_a_complete_frame() {
        let root = Root::new();
        let listener = UnixListener::bind(root.endpoint()).unwrap();
        let server = std::thread::spawn(move || {
            let mut first = accept(&listener);
            read_request(&mut first);
            first.write_all(&[0, 0]).unwrap();
            drop(first);
            let mut second = accept(&listener);
            read_request(&mut second);
            let response = TRUST_RESPONSE;
            second
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            second.write_all(response).unwrap();
        });
        let deadline = StartupDeadline(Instant::now() + Duration::from_secs(2));
        assert!(matches!(
            deadline.exchange(&root.endpoint(), &request()),
            Ok(AgentControlResponse::TrustBootstrap { .. })
        ));
        server.join().unwrap();
    }

    #[test]
    fn malformed_json_and_explicit_rejection_are_not_retried() {
        for response in [
            br#"{"type":"error","message":"invalid dummy session"}"#.as_slice(),
            b"invalid-json".as_slice(),
        ] {
            let root = Root::new();
            let listener = UnixListener::bind(root.endpoint()).unwrap();
            let response = response.to_vec();
            let valid_json = serde_json::from_slice::<serde_json::Value>(&response).is_ok();
            let server = std::thread::spawn(move || {
                let mut stream = accept(&listener);
                read_request(&mut stream);
                stream
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
            });
            let deadline = StartupDeadline(Instant::now() + Duration::from_secs(2));
            let result = deadline.exchange(&root.endpoint(), &request());
            if valid_json {
                assert!(matches!(result, Ok(AgentControlResponse::Error { .. })));
            } else {
                assert!(result.is_err());
            }
            assert!(
                deadline.remaining().is_ok(),
                "failure was retried until the budget expired"
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn an_accepted_but_silent_peer_cannot_exceed_the_bootstrap_deadline() {
        let root = Root::new();
        let listener = UnixListener::bind(root.endpoint()).unwrap();
        let (release, released) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            read_request(&mut stream);
            let _ = released.recv_timeout(Duration::from_secs(2));
        });
        let began = Instant::now();
        let deadline = StartupDeadline(began + Duration::from_millis(100));
        assert!(deadline.exchange(&root.endpoint(), &request()).is_err());
        let elapsed = began.elapsed();
        let _ = release.send(());
        server.join().unwrap();
        assert!(
            elapsed < Duration::from_secs(1),
            "unbounded control read: {elapsed:?}"
        );
        assert!(deadline.remaining().is_err());
    }

    #[test]
    fn a_peer_that_does_not_read_cannot_block_bootstrap_writes() {
        let root = Root::new();
        let listener = UnixListener::bind(root.endpoint()).unwrap();
        let (release, released) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let _stream = accept(&listener);
            let _ = released.recv_timeout(Duration::from_secs(2));
        });
        let began = Instant::now();
        let deadline = StartupDeadline(began + Duration::from_millis(100));
        let mut stream = deadline.connect(&root.endpoint()).unwrap();
        let error = stream.write_all(&vec![0; 8 * 1024 * 1024]).unwrap_err();
        let elapsed = began.elapsed();
        let _ = release.send(());
        server.join().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_secs(1),
            "unbounded control write: {elapsed:?}"
        );
    }

    #[test]
    fn startup_phases_share_the_original_deadline() {
        let root = Root::new();
        let listener = UnixListener::bind(root.endpoint()).unwrap();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            read_request(&mut stream);
            let response = TRUST_RESPONSE;
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(response).unwrap();
        });
        let deadline = StartupDeadline(Instant::now() + Duration::from_millis(150));
        assert!(deadline.exchange(&root.endpoint(), &request()).is_ok());
        server.join().unwrap();
        std::thread::sleep(deadline.remaining().unwrap() + Duration::from_millis(1));
        assert!(deadline.exchange(&root.endpoint(), &request()).is_err());
    }
}
