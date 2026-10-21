//! Shared network Host regression. Compiles a native module from source and
//! exercises the same exported C ABI used by the Gum socket adapters.
use crate::*;
use hyperhub_engine::management::{Command, Reply, MIN_REPLY};
use hyperhub_runtime::{Settings, Stage};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("diagnostics")
            .join(format!("network-host-upgrade-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        #[cfg(windows)]
        fn writable(path: &std::path::Path) {
            if path.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    writable(&entry.unwrap().path());
                }
            } else {
                let mut permissions = fs::metadata(path).unwrap().permissions();
                permissions.set_readonly(false);
                fs::set_permissions(path, permissions).unwrap();
            }
        }
        #[cfg(windows)]
        writable(&self.0);
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Restore(Option<AgentRuntime>);
impl Drop for Restore {
    fn drop(&mut self) {
        let current = {
            let mut core = state().lock().unwrap();
            std::mem::replace(&mut *core, self.0.take().unwrap())
        };
        drop(current);
    }
}
fn control(command: Command) -> Reply {
    let input = serde_json::to_vec(&command).unwrap();
    let mut output = vec![0; MIN_REPLY];
    let mut written = 0;
    assert_eq!(
        unsafe {
            hh_agent_engine_control(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        },
        HH_OK
    );
    serde_json::from_slice(&output[..written]).unwrap()
}
fn snapshot() -> hyperhub_runtime::Snapshot {
    match control(Command::Query) {
        Reply::Snapshot { snapshot } => snapshot,
        _ => panic!("missing snapshot"),
    }
}
fn connect(socket: u64, address: &[u8], port: u16) -> HhConnectPlan {
    let mut plan = HhConnectPlan::default();
    assert_eq!(
        unsafe {
            hh_agent_prepare_connect(socket, 2, address.as_ptr(), address.len(), port, &mut plan)
        },
        HH_OK
    );
    plan
}
fn packet(socket: u64, phase: u32) -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    let mut written = 0;
    assert_eq!(
        unsafe {
            hh_agent_build_handshake(socket, phase, bytes.as_mut_ptr(), bytes.len(), &mut written)
        },
        HH_OK
    );
    bytes.truncate(written);
    bytes
}

#[test]
fn native_upgrade_preserves_host_state_and_pins_all_socket_handshake_phases() {
    let root = Root::new();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("network_upgrade_engine.rs");
    let module = root
        .0
        .join(format!("network-upgrade{}", std::env::consts::DLL_SUFFIX));
    let version = "fixture-upgraded";
    let output = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg("--crate-type=cdylib")
        .arg(&fixture)
        .arg("-o")
        .arg(&module)
        .env(
            "HH_FIXTURE_VERSION_HASH",
            hyperhub_runtime::artifact::hex(&Sha256::digest(version.as_bytes())),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(&module).unwrap();
    let manifest = hyperhub_engine::manifest(&bytes, version);
    let mut core = crate::tests::configured_core();
    core.engine = hyperhub_engine::resident_with(Settings {
        health_window: Duration::ZERO,
        ..Settings::default()
    });
    let _restore = Restore(Some(std::mem::replace(&mut *state().lock().unwrap(), core)));
    let host_pointer = state() as *const _;
    let pid = std::process::id();
    let name = std::ffi::CString::new("Original.Example.").unwrap();
    let ip = [198, 18, 0, 9];
    assert_eq!(
        unsafe { hh_agent_record_dns(name.as_ptr(), 2, ip.as_ptr(), ip.len()) },
        HH_OK
    );
    assert_eq!(hh_agent_note_nonblocking(42, 1), HH_OK);
    assert_eq!(connect(42, &ip, 443).connection_id, 7);
    assert_eq!(hh_agent_note_io(42, 88), HH_OK);
    assert_eq!(packet(42, 0), [5, 1, 2]);
    let delayed = crate::engine_call::EngineCallGuard::enter().unwrap();
    let prepare = Command::Prepare {
        id: "host-update".into(),
        manifest: manifest.clone(),
        source: module.clone(),
        cache: root.0.join("cache"),
    };
    // A size probe must not prepare or load any code.
    let input = serde_json::to_vec(&prepare).unwrap();
    let mut small = [0; 4];
    let mut written = 0;
    assert_eq!(
        unsafe {
            hh_agent_engine_control(
                input.as_ptr(),
                input.len(),
                small.as_mut_ptr(),
                small.len(),
                &mut written,
            )
        },
        HH_ERR_BUFFER_TOO_SMALL
    );
    assert!(snapshot().transactions.is_empty());
    assert!(
        matches!(control(prepare), Reply::Transaction { transaction } if transaction.stage == Stage::Prepared)
    );
    assert!(
        matches!(control(Command::Commit { id: "host-update".into() }), Reply::Transaction { transaction } if transaction.stage == Stage::Draining)
    );
    assert!(matches!(control(Command::Observe), Reply::Ok));
    assert_eq!(snapshot().active.version, version);
    assert_eq!(
        {
            let core = state().lock().unwrap();
            crate::engine_call::calling(&core.engine)
                .unwrap()
                .generation()
        },
        0
    );
    let delayed_name = std::ffi::CString::new("Delayed.Example.").unwrap();
    let delayed_ip = [198, 18, 0, 10];
    assert_eq!(
        unsafe { hh_agent_record_dns(delayed_name.as_ptr(), 2, delayed_ip.as_ptr(), 4) },
        HH_OK
    );
    drop(delayed);
    let current_name = std::ffi::CString::new("Current.Example.").unwrap();
    let current_ip = [198, 18, 0, 11];
    assert_eq!(
        unsafe { hh_agent_record_dns(current_name.as_ptr(), 2, current_ip.as_ptr(), 4) },
        HH_OK
    );
    {
        let core = state().lock().unwrap();
        assert_eq!(
            core.gateway.dns[&"198.18.0.10".parse::<std::net::IpAddr>().unwrap()],
            "delayed.example"
        );
        assert_eq!(
            core.gateway.dns[&"198.18.0.11".parse::<std::net::IpAddr>().unwrap()],
            "normalized.current.example"
        );
    }
    assert_eq!(state() as *const _, host_pointer);
    assert_eq!(std::process::id(), pid);
    {
        let core = state().lock().unwrap();
        assert_eq!(core.session.session_id, "session");
        assert_eq!(core.session.token, "token");
        assert_eq!(core.gateway.next_connection_id, 8);
        assert_eq!(
            core.gateway.dns[&"198.18.0.9".parse::<std::net::IpAddr>().unwrap()],
            "original.example"
        );
        assert_eq!(core.gateway.sockets[&42].last_io_result, 88);
        assert!(core.gateway.sockets[&42].nonblocking);
    }
    let old = packet(42, 2);
    assert_eq!(&old[5..old.len() - 2], b"original.example");
    assert_eq!(connect(44, &ip, 443).connection_id, 8);
    let new = packet(44, 2);
    assert_eq!(&new[5..new.len() - 2], b"upgraded.original.example");
    // The native module tightens reply validation. Old sockets must retain the
    // original behavior even for a phase that starts after the switch.
    let reply = [5, 0, 7, 1, 0];
    assert_eq!(
        unsafe { hh_agent_validate_socket_handshake_reply(42, 2, reply.as_ptr(), reply.len()) },
        HH_OK
    );
    assert_eq!(
        unsafe { hh_agent_validate_socket_handshake_reply(44, 2, reply.as_ptr(), reply.len()) },
        HH_ERR_PROTOCOL
    );
    assert_eq!(hh_agent_dup_socket(42, 43), HH_OK);
    assert_eq!(hh_agent_close_socket(42), HH_OK);
    assert_eq!(snapshot().retired[0].references, 1);
    assert_eq!(packet(43, 2), old);
    assert_eq!(hh_agent_close_socket(43), HH_OK);
    assert!(snapshot().retired.is_empty());
    assert_eq!(snapshot().transactions[0].stage, Stage::Complete);
    let mut incompatible = manifest;
    incompatible.state_schema += 1;
    assert!(
        matches!(control(Command::Prepare { id: "incompatible".into(), manifest: incompatible, source: root.0.join("must-not-open"), cache: root.0.join("cache") }), Reply::Transaction { transaction } if transaction.stage == Stage::RequiresRestart)
    );
    assert_eq!(snapshot().active.version, version);
    assert_eq!(hh_agent_close_socket(44), HH_OK);
}
