//! An existing local executor and a managed client with different file policies.
use std::{
    fs,
    io::{BufRead, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
};

pub const DUMMY_DATA: &[u8] = b"dummy-executor-scope-data\n";

pub fn process_birth(pid: u32) -> u64 {
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        return stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap()
            .parse()
            .unwrap();
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        #[derive(Default)]
        struct FileTime {
            low: u32,
            high: u32,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
            fn GetProcessTimes(
                process: *mut std::ffi::c_void,
                creation: *mut FileTime,
                exit: *mut FileTime,
                kernel: *mut FileTime,
                user: *mut FileTime,
            ) -> i32;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }
        unsafe {
            let handle = OpenProcess(0x1000, 0, pid);
            assert!(!handle.is_null(), "cannot query fixture process identity");
            let mut creation = FileTime::default();
            let mut exit = FileTime::default();
            let mut kernel = FileTime::default();
            let mut user = FileTime::default();
            let ok = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
            CloseHandle(handle);
            assert_ne!(ok, 0);
            return (u64::from(creation.high) << 32) | u64::from(creation.low);
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    panic!("executor scope fixture requires Linux or Windows: {pid}");
}

fn wait_for_parent() {
    let mut input = String::new();
    std::io::stdin().lock().read_line(&mut input).unwrap();
    assert!(input.is_empty() || input.trim() == "quit");
}

fn server(secret: &Path) {
    let pid = std::process::id();
    let birth = process_birth(pid);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    println!(
        "SERVER_READY {pid} {birth} {}",
        listener.local_addr().unwrap()
    );
    std::io::stdout().flush().unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .unwrap();
    let mut request = [0; 11];
    peer.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"READ-SCOPE\n");
    let bytes = fs::read(secret).expect("the existing external executor can read its dummy file");
    assert_eq!(bytes, DUMMY_DATA);
    peer.write_all(&pid.to_be_bytes()).unwrap();
    peer.write_all(&birth.to_be_bytes()).unwrap();
    peer.write_all(&bytes).unwrap();
    peer.flush().unwrap();
    println!("SERVER_READ {pid} {birth}");
    std::io::stdout().flush().unwrap();
    wait_for_parent();
}

fn client(address: &str, secret: &Path) {
    let pid = std::process::id();
    let error = fs::read(secret).expect_err("managed direct file read must be denied");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    println!("DIRECT_READ_DENIED {pid}");
    std::io::stdout().flush().unwrap();
    let mut peer = TcpStream::connect(address).unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .unwrap();
    peer.write_all(b"READ-SCOPE\n").unwrap();
    let mut server_pid = [0; 4];
    let mut server_birth = [0; 8];
    peer.read_exact(&mut server_pid).unwrap();
    peer.read_exact(&mut server_birth).unwrap();
    let mut reply = vec![0; DUMMY_DATA.len()];
    peer.read_exact(&mut reply).unwrap();
    assert_eq!(reply, DUMMY_DATA);
    println!(
        "DELEGATED_READ {pid} {} {}",
        u32::from_be_bytes(server_pid),
        u64::from_be_bytes(server_birth)
    );
    std::io::stdout().flush().unwrap();
    wait_for_parent();
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    match args.get(1).and_then(|value| value.to_str()) {
        Some("server") if args.len() == 3 => server(Path::new(&args[2])),
        Some("client") if args.len() == 4 => client(args[2].to_str().unwrap(), Path::new(&args[3])),
        _ => panic!("expected server <dummy-file> or client <loopback-address> <dummy-file>"),
    }
}
