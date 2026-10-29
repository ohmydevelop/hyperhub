//! Cancellation must fail before runtime credentials or Execution are opened.
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn rejected(frame: Option<Vec<u8>>, expected: &str) {
    let root = std::env::temp_dir().join(format!(
        "hh-manager-cancel-{}",
        hyperhub_core::attachments::new_id()
    ));
    hyperhub_core::attachments::private_directory(&root).unwrap();
    let state = root.join("no-execution-directory");
    let mut command = Command::new(env!("CARGO_BIN_EXE_hyperhub"));
    command.env_clear();
    // Keep only OS executable/temporary-directory dependencies. In particular,
    // do not inherit credentials, discovery endpoints or injection settings.
    for name in [
        "PATH",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command
        .arg("attachment-manager")
        .arg(&state)
        .env("HYPERHUB_HOME", &root)
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env("XDG_RUNTIME_DIR", root.join("xdg-runtime"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    if let Some(frame) = frame {
        input.write_all(&frame).unwrap();
    }
    drop(input);
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cancelled private manager did not exit");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut error = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();
    assert!(!status.success(), "unapproved manager started");
    assert!(
        error.contains(expected),
        "unexpected manager error: {error}"
    );
    assert!(
        !state.exists(),
        "uncommitted helper created execution state"
    );
    assert!(
        !root.join("config.bin").exists(),
        "uncommitted helper initialized credentials"
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn manager_creator_eof_exits_before_loading_execution() {
    rejected(None, "missing private manager bootstrap frame");
}
#[test]
fn manager_oversized_creator_frame_exits_before_loading_execution() {
    rejected(
        Some(u32::MAX.to_be_bytes().to_vec()),
        "invalid private manager bootstrap frame length",
    );
}
