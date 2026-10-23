//! Persistent executor used by the Serve restart Suite. No real credentials.
use std::{
    fs,
    io::{self, BufRead, Write},
    process::{Command, Stdio},
};

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let mode = args[1].to_str().unwrap();
    if mode == "orphan" {
        let mut child = Command::new(&args[0]);
        child.arg("child").args(&args[2..]);
        child
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        child.spawn().unwrap();
        return;
    }
    #[cfg(unix)]
    if mode == "exec" {
        use std::os::unix::process::CommandExt;
        // The original root lives on as a different executable. Its shell then
        // starts the protocol executor, so both root and child must be restored.
        let error = Command::new("/bin/sh")
            .args([
                "-c",
                "\"$1\" child \"$2\" \"$3\" \"$4\"; exit $?",
                "restart-shell",
            ])
            .arg(&args[0])
            .args(&args[2..])
            .exec();
        panic!("root exec failed: {error}");
    }
    println!("READY {}", std::process::id());
    io::stdout().flush().unwrap();
    for line in io::stdin().lock().lines() {
        match line.unwrap().as_str() {
            "quit" => return,
            #[cfg(target_os = "linux")]
            operation @ ("allowed-marker" | "blocked-spawn") => {
                use std::os::unix::process::ExitStatusExt;
                println!("SPAWN_STARTED {}", std::process::id());
                io::stdout().flush().unwrap();
                let mut child = Command::new("/bin/sh")
                    .args(["-c", "printf child-ran > \"$1\"", "marker-shell"])
                    .arg(&args[5])
                    .spawn()
                    .expect("original posix_spawn must report creation success");
                let child_pid = child.id();
                println!("SPAWN_CREATED {} {child_pid}", std::process::id());
                io::stdout().flush().unwrap();
                let status = child.wait().unwrap();
                if operation == "allowed-marker" {
                    assert!(status.success(), "online marker child failed: {status}");
                    println!("MARKER_ALLOWED {} child={child_pid}", std::process::id());
                } else {
                    assert_eq!(
                        status.signal(),
                        Some(9),
                        "unenrolled child must be terminated by the enforcement gate"
                    );
                    println!("BLOCKED {} child={child_pid} signal=9", std::process::id());
                }
                io::stdout().flush().unwrap();
            }
            operation @ ("probe" | "outage-probe") => {
                if operation == "outage-probe" {
                    println!("PROBE_STARTED {}", std::process::id());
                    io::stdout().flush().unwrap();
                }
                let blocked = fs::read(&args[2]).unwrap_err();
                assert_eq!(blocked.kind(), io::ErrorKind::PermissionDenied);
                assert_eq!(fs::read(&args[3]).unwrap(), b"allowed fixture bytes");
                let changed = match fs::read(&args[4]) {
                    Ok(bytes) => {
                        assert_eq!(bytes, b"changed fixture bytes");
                        "allow"
                    }
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                        "deny"
                    }
                };
                #[cfg(unix)]
                let output = Command::new("/bin/sh")
                    .args(["-c", "printf shell-ok"])
                    .output()
                    .unwrap();
                #[cfg(windows)]
                let output = Command::new("cmd.exe")
                    .args(["/D", "/C", "echo shell-ok"])
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "child status {:?}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(
                    String::from_utf8(output.stdout).unwrap().trim_end(),
                    "shell-ok"
                );
                println!(
                    "OK {} blocked=deny allowed=allow changed={changed} shell=ok",
                    std::process::id()
                );
                io::stdout().flush().unwrap();
            }
            other => panic!("unknown restart operation {other}"),
        }
    }
}
