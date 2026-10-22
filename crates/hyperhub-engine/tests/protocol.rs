use hyperhub_engine::{contract::*, *};

fn input(phase: u32, target: TargetAddress) -> HandshakeInput {
    HandshakeInput {
        phase,
        username: "user".into(),
        password: b"pass".to_vec(),
        target,
        port: 443,
    }
}
#[test]
fn wire_packets_keep_authentication_domain_and_ip_identity() {
    let runtime = resident();
    let lease = runtime.acquire();
    let target = TargetAddress::Domain("example.test".into());
    assert_eq!(
        handshake(&lease, &input(0, target.clone())).unwrap(),
        [5, 1, 2]
    );
    assert_eq!(
        handshake(&lease, &input(1, target.clone())).unwrap(),
        b"\x01\x04user\x04pass"
    );
    assert_eq!(
        handshake(&lease, &input(2, target)).unwrap(),
        b"\x05\x01\x00\x03\x0cexample.test\x01\xbb"
    );
    assert_eq!(
        handshake(
            &lease,
            &input(2, TargetAddress::Ip("192.0.2.5".parse().unwrap()))
        )
        .unwrap(),
        [5, 1, 0, 1, 192, 0, 2, 5, 1, 187]
    );
    let ipv6 = handshake(
        &lease,
        &input(2, TargetAddress::Ip("2001:db8::1".parse().unwrap())),
    )
    .unwrap();
    assert_eq!(ipv6.len(), 22);
    assert_eq!(&ipv6[..8], &[5, 1, 0, 4, 0x20, 1, 0xd, 0xb8]);
}
#[test]
fn rfc_length_edges_and_invalid_phases_are_rejected() {
    let runtime = resident();
    let lease = runtime.acquire();
    for size in [255, 256] {
        let mut request = input(1, TargetAddress::Domain("test".into()));
        request.username = "x".repeat(size);
        assert_eq!(handshake(&lease, &request).is_ok(), size == 255);
        request.username = "user".into();
        request.password = vec![1; size];
        assert_eq!(handshake(&lease, &request).is_ok(), size == 255);
        request.phase = 2;
        request.target = TargetAddress::Domain("x".repeat(size));
        assert_eq!(handshake(&lease, &request).is_ok(), size == 255);
    }
    assert_eq!(
        handshake(&lease, &input(3, TargetAddress::Ip("::1".parse().unwrap()))),
        Err(INVALID)
    );
    assert_eq!(normalize(&lease, "..."), Err(INVALID));
    assert_eq!(
        normalize(&lease, "Name.Example..."),
        Ok("name.example".into())
    );
}
#[test]
fn connection_plan_bypasses_only_the_exact_proxy_endpoint() {
    let runtime = resident();
    let lease = runtime.acquire();
    for proxy in ["127.0.0.1:9000", "[::1]:9000"] {
        let proxy: std::net::SocketAddr = proxy.parse().unwrap();
        let mut request = ConnectInput {
            proxy,
            ip: proxy.ip(),
            port: proxy.port(),
            hostname: Some("name.test".into()),
        };
        assert!(!connect(&lease, &request).unwrap().intercept);
        request.port += 1;
        let plan = connect(&lease, &request).unwrap();
        assert!(plan.intercept);
        assert_eq!(plan.port, 9000);
        assert_eq!(plan.target, TargetAddress::Domain("name.test".into()));
    }
}
#[test]
fn reply_validation_covers_greeting_authentication_and_split_connect_headers() {
    let runtime = resident();
    let lease = runtime.acquire();
    for (phase, bytes) in [(0, &[5, 2][..]), (1, &[1, 0]), (2, &[5, 0, 0, 1, 0])] {
        assert!(validate_reply(&lease, phase, bytes, false).is_ok());
        for length in 0..bytes.len() {
            assert!(validate_reply(&lease, phase, &bytes[..length], false).is_err());
        }
    }
    assert!(validate_reply(&lease, 2, &[5, 0, 0, 1], true).is_ok());
    assert!(validate_reply(&lease, 0, &[5, 0], false).is_err());
    assert!(validate_reply(&lease, 1, &[1, 1], false).is_err());
    assert!(validate_reply(&lease, 2, &[5, 1, 0, 1, 0], false).is_err());
}

#[test]
fn exported_native_table_obeys_buffer_and_error_output_contracts() {
    let api = unsafe { &*hh_engine_v1() };
    assert_eq!(api.abi, hyperhub_runtime::abi::ABI_V1);
    assert_eq!(api.hooks, REQUIRED_OPERATIONS);
    assert_eq!(unsafe { api.health.unwrap()() }, 0);
    let request =
        serde_json::to_vec(&input(0, TargetAddress::Ip("127.0.0.1".parse().unwrap()))).unwrap();
    let invoke = api.invoke.unwrap();
    let mut output = [99; 3];
    let mut written = usize::MAX;
    assert_eq!(
        unsafe {
            invoke(
                std::ptr::null(),
                BUILD_HANDSHAKE,
                request.as_ptr(),
                request.len(),
                output.as_mut_ptr(),
                2,
                &mut written,
            )
        },
        CAPACITY
    );
    assert_eq!(written, 0);
    assert_eq!(output, [99; 3]);
    assert_eq!(
        unsafe {
            invoke(
                std::ptr::null(),
                BUILD_HANDSHAKE,
                request.as_ptr(),
                request.len(),
                output.as_mut_ptr(),
                3,
                &mut written,
            )
        },
        0
    );
    assert_eq!(written, 3);
    assert_eq!(output, [5, 1, 2]);
    assert_eq!(
        unsafe {
            invoke(
                std::ptr::null(),
                BUILD_HANDSHAKE,
                std::ptr::null(),
                1,
                output.as_mut_ptr(),
                3,
                &mut written,
            )
        },
        INVALID
    );
    assert_eq!(written, 0);
}

#[test]
fn capacity_retry_is_bounded_to_one_pure_policy_call_and_preserves_input_limits() {
    use hyperhub_runtime::{Engine, Lease, Manifest, Runtime};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Capacity {
        manifest: Manifest,
        calls: Arc<AtomicUsize>,
    }
    impl Engine for Capacity {
        fn manifest(&self) -> &Manifest {
            &self.manifest
        }
        fn health(&self) -> bool {
            true
        }
        fn invoke(&self, lease: &Lease, _: u32, _: &[u8], output: &mut [u8]) -> Result<usize, i32> {
            assert_eq!(lease.generation(), 0);
            assert!(output.len() <= MAX_POLICY_REQUEST * 2 + MAX_RESPONSE);
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(CAPACITY)
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = Runtime::new(
        Arc::new(Capacity {
            manifest: manifest(b"retry-contract", "retry-contract"),
            calls: calls.clone(),
        }),
        Default::default(),
    )
    .unwrap();
    let lease = runtime.acquire();
    for operation in [FILE_POLICY, PROCESS_POLICY, FIREWALL_POLICY] {
        calls.store(0, Ordering::Relaxed);
        assert_eq!(
            call(&lease, operation, &"controlled request"),
            Err(CAPACITY)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2, "at most one pure retry");
    }
    for operation in [
        NORMALIZE_DNS,
        PLAN_CONNECT,
        BUILD_HANDSHAKE,
        VALIDATE_REPLY,
        TRUST_BUNDLE,
        CHILD_PLAN,
        SANITIZE_ACTION,
        FORK_RESET,
        MODULE_RETAIN,
        MODULE_RELEASE,
    ] {
        calls.store(0, Ordering::Relaxed);
        assert_eq!(
            call(&lease, operation, &"controlled request"),
            Err(CAPACITY)
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "no other operation may repeat"
        );
    }
    calls.store(0, Ordering::Relaxed);
    assert_eq!(
        call(&lease, FILE_POLICY, &"x".repeat(MAX_POLICY_REQUEST)),
        Err(INVALID)
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        0,
        "oversized input must not reach a module"
    );
}
