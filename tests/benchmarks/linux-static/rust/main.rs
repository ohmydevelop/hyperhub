use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{self, Command};
use std::time::Duration;

const PAYLOAD: &[u8] = b"hyperhub-static-rust-probe";

fn main() {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.get(1).map(String::as_str) == Some("--child") {
        let result = arguments
            .get(2)
            .zip(arguments.get(3))
            .ok_or_else(|| "child requires host and port".to_string())
            .and_then(|(host, port)| {
                let port = port
                    .parse::<u16>()
                    .map_err(|error| format!("invalid child port: {error}"))?;
                run_network_probe(host, port)
            });
        if let Err(error) = result {
            eprintln!("child network probe failed: {error}");
            process::exit(1);
        }
        println!("static-rust-child-ok");
        return;
    }
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
    println!("static-rust-probe-ok");
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let host = arguments
        .next()
        .ok_or_else(|| "usage: linux_static_rust host port".to_string())?;
    let port = arguments
        .next()
        .ok_or_else(|| "usage: linux_static_rust host port".to_string())?
        .parse::<u16>()
        .map_err(|error| format!("invalid port: {error}"))?;
    if arguments.next().is_some() {
        return Err("usage: linux_static_rust host port".into());
    }

    run_raw_syscall_probe()?;
    run_file_probe()?;
    run_network_probe(&host, port)?;
    run_process_probe(&host, port)?;
    Ok(())
}

fn run_raw_syscall_probe() -> Result<(), String> {
    let pid = raw_getpid();
    if pid == process::id() as i64 {
        Ok(())
    } else {
        Err(format!(
            "getpid mismatch: raw={pid} runtime={}",
            process::id()
        ))
    }
}

#[cfg(target_arch = "x86_64")]
fn raw_getpid() -> i64 {
    let mut result = 39_i64;
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    result
}

#[cfg(target_arch = "aarch64")]
fn raw_getpid() -> i64 {
    let result: i64;
    unsafe {
        std::arch::asm!(
            "svc 0",
            in("x8") 172_i64,
            lateout("x0") result,
            options(nostack)
        );
    }
    result
}

fn run_file_probe() -> Result<(), String> {
    let path = temporary_path("hyperhub-static-rust");
    let renamed = path.with_extension("renamed");
    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        file.write_all(PAYLOAD)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| format!("seek {}: {error}", path.display()))?;
        let mut readback = vec![0; PAYLOAD.len()];
        file.read_exact(&mut readback)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        drop(file);
        if readback != PAYLOAD {
            return Err("file readback mismatch".into());
        }
        fs::rename(&path, &renamed).map_err(|error| {
            format!(
                "rename {} to {}: {error}",
                path.display(),
                renamed.display()
            )
        })?;
        fs::remove_file(&renamed).map_err(|error| format!("remove {}: {error}", renamed.display()))
    })();
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&renamed);
    result
}

fn run_network_probe(host: &str, port: u16) -> Result<(), String> {
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("resolve {host}:{port}: {error}"))?
        .next()
        .ok_or_else(|| format!("{host}:{port} resolved to no addresses"))?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|error| format!("connect {address}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("set write timeout: {error}"))?;
    stream
        .write_all(PAYLOAD)
        .map_err(|error| format!("write socket: {error}"))?;
    let mut readback = vec![0; PAYLOAD.len()];
    stream
        .read_exact(&mut readback)
        .map_err(|error| format!("read socket: {error}"))?;
    if readback != PAYLOAD {
        return Err("network echo mismatch".into());
    }
    Ok(())
}

fn run_process_probe(host: &str, port: u16) -> Result<(), String> {
    let executable = env::current_exe().map_err(|error| format!("resolve executable: {error}"))?;
    let output = Command::new(executable)
        .arg("--child")
        .arg(host)
        .arg(port.to_string())
        .output()
        .map_err(|error| format!("spawn child: {error}"))?;
    if !output.status.success() {
        return Err(format!("child exited with {}", output.status));
    }
    if output.stdout != b"static-rust-child-ok\n" {
        return Err(format!(
            "unexpected child output: {:?}",
            String::from_utf8_lossy(&output.stdout)
        ));
    }
    Ok(())
}

fn temporary_path(prefix: &str) -> PathBuf {
    env::temp_dir().join(format!("{prefix}-{}", process::id()))
}
