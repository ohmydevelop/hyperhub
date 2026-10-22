use super::*;

/// Run a real descriptor-exhaustion failure in a separate process so unrelated
/// tests and runtime threads retain their original process resource limits.
#[cfg(unix)]
#[test]
fn failed_cancellation_probe_marks_the_shared_socket_complete() {
    const CHILD: &str = "HH_FORWARD_PROBE_LIMIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "forward::worker::tests::failed_cancellation_probe_marks_the_shared_socket_complete",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "descriptor-exhaustion child failed: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().unwrap();
    super::super::cancellation::initialize(&stream).unwrap();
    let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original.as_mut_ptr()) },
        0
    );
    let original = unsafe { original.assume_init() };
    let limited = libc::rlimit {
        rlim_cur: original.rlim_cur.min(64),
        rlim_max: original.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);
    let mut held = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => held.push(file),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                break;
            }
        }
    }
    let failure = cancellation_probe(&stream).unwrap_err();
    let marked = super::super::cancellation::locally_closed(&stream);
    drop(held);
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) },
        0
    );
    assert_eq!(failure.raw_os_error(), Some(libc::EMFILE));
    assert!(
        marked,
        "failed granted socket was not marked complete for its resident duplicate"
    );
}
