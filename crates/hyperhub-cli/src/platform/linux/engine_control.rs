//! Management IO runs separately from the resident ptrace event loop. The
//! original tracer remains attached and keeps all tracee/syscall/FD state.
use hyperhub_engine::host::{self, Backend, Enrollment};
use hyperhub_runtime::Runtime;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

pub(super) struct EngineControl {
    stop: Arc<AtomicBool>,
    stream: Arc<Mutex<Option<UnixStream>>>,
}
impl Drop for EngineControl {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(stream) = self.stream.lock() {
            if let Some(stream) = stream.as_ref() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }
}
pub(super) fn bootstrap(
    runtime: &Runtime,
    endpoint: &str,
    session_id: &str,
    token: &str,
    root_pid: u32,
) -> Result<(), String> {
    let mut stream = UnixStream::connect(endpoint).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let host = runtime.snapshot().map_err(|e| e.to_string())?.host;
    let pid = std::process::id();
    let nonce: [u8; 32] = rand::random();
    host::write_frame(&mut stream,&serde_json::json!({"type":"get_engine_bootstrap","session_id":session_id,"token":token,"pid":pid,"root_pid":root_pid,"nonce":nonce,"host":host,"native_base_sha256":hyperhub_engine::NATIVE_BASE_SHA256})).map_err(|e|e.to_string())?;
    let value: serde_json::Value = host::read_frame(&mut stream).map_err(|e| e.to_string())?;
    if value.get("type").and_then(|v| v.as_str()) != Some("engine_bootstrap") {
        return Err(format!(
            "Engine bootstrap rejected: {}",
            value
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unexpected response")
        ));
    }
    let bootstrap: hyperhub_engine::bootstrap::Bootstrap = serde_json::from_value(
        value
            .get("bootstrap")
            .cloned()
            .ok_or("missing Engine bootstrap")?,
    )
    .map_err(|e| e.to_string())?;
    if !bootstrap.verify(
        token,
        &nonce,
        pid,
        root_pid,
        &host,
        hyperhub_engine::NATIVE_BASE_SHA256,
    ) {
        return Err("invalid Engine bootstrap proof".into());
    }
    unsafe { hyperhub_engine::bootstrap::install(runtime, &bootstrap.selection) }
}

pub(super) fn start(
    runtime: Arc<Runtime>,
    endpoint: String,
    session_id: String,
    token: String,
    root_pid: u32,
) -> Result<EngineControl, String> {
    let control = EngineControl {
        stop: Arc::new(AtomicBool::new(false)),
        stream: Arc::new(Mutex::new(None)),
    };
    let (ready_send, ready_recv) = std::sync::mpsc::sync_channel(1);
    let stop = control.stop.clone();
    let connection = control.stream.clone();
    std::thread::Builder::new()
        .name("hyperhub-ptrace-engine".into())
        .spawn(move || {
            let mut ready_send = Some(ready_send);
            while !stop.load(Ordering::Acquire) {
                let result = (|| -> std::io::Result<()> {
                    let mut stream = UnixStream::connect(&endpoint)?;
                    stream.set_read_timeout(Some(Duration::from_secs(40)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                    {
                        let mut slot = connection
                            .lock()
                            .map_err(|_| std::io::Error::other("engine channel poisoned"))?;
                        if stop.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        *slot = Some(stream.try_clone()?);
                    }
                    let nonce = rand::random();
                    host::write_frame(
                        &mut stream,
                        &Enrollment {
                            kind: "subscribe_engine_host",
                            session_id: &session_id,
                            token: &token,
                            root_pid,
                            backend: Backend::LinuxPtrace,
                            native_base_sha256: hyperhub_engine::NATIVE_BASE_SHA256,
                            snapshot: host::report(&runtime).map_err(std::io::Error::other)?,
                            nonce,
                        },
                    )?;
                    unsafe {
                        host::await_enrollment(&mut stream, &runtime, &token, &nonce)?;
                    }
                    if let Some(sender) = ready_send.take() {
                        let _ = sender.send(Ok(()));
                    }
                    unsafe { host::serve(&mut stream, &runtime, &token, &nonce) }
                })();
                if let Some(sender) = ready_send.take() {
                    let _ = sender.send(result.map_err(|e| e.to_string()));
                    return;
                }
                if let Ok(mut slot) = connection.lock() {
                    slot.take();
                }
                if !stop.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        })
        .map_err(|error| error.to_string())?;
    ready_recv
        .recv_timeout(Duration::from_secs(30))
        .map_err(|e| e.to_string())??;
    Ok(control)
}

/// Ordinary Unix application exit values do not establish an Engine failure.
pub(super) fn completed_normally(exit_code: Option<i32>, signal: Option<i32>) -> bool {
    matches!(exit_code, Some(0..=255)) && signal.is_none()
}

/// Only the resident CLI observer holds the instance key. Injected Agents never
/// receive it. Core also verifies this OS peer and the exited incarnation.
pub(super) fn report_exit(
    endpoint: &str,
    session_id: &str,
    pid: u32,
    start_time: u64,
    exit_code: Option<i32>,
    signal: Option<i32>,
    source: &str,
) -> Result<(), String> {
    let key = crate::password::acquire_api_key()?;
    let event = hyperhub_core::engine_hosts::ProcessExit {
        session_id: session_id.into(),
        pid,
        start_time,
        exit_code,
        signal,
        source: source.into(),
        issued_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis() as u64,
    };
    let proof = event.proof(key.as_bytes()).map_err(|e| e.to_string())?;
    let mut stream = UnixStream::connect(endpoint).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    host::write_frame(
        &mut stream,
        &serde_json::json!({"type":"report_engine_process_exit","event":event,"proof":proof}),
    )
    .map_err(|e| e.to_string())?;
    let response: serde_json::Value = host::read_frame(&mut stream).map_err(|e| e.to_string())?;
    if response.get("type").and_then(|v| v.as_str()) == Some("ok") {
        Ok(())
    } else {
        Err(format!("Engine exit evidence rejected: {response}"))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn business_exit_codes_do_not_hide_signal_or_unknown_termination() {
        for code in 0..=255 {
            assert!(super::completed_normally(Some(code), None));
            assert!(!super::completed_normally(Some(code), Some(libc::SIGSEGV)));
        }
        for code in [-1, 256, i32::MAX] {
            assert!(!super::completed_normally(Some(code), None));
        }
        assert!(!super::completed_normally(None, None));
        assert!(!super::completed_normally(None, Some(libc::SIGSEGV)));
    }
}

pub(super) fn retain_tree(
    endpoint: &str,
    session_id: &str,
    token: &str,
    root_pid: u32,
) -> Result<(), String> {
    let mut stream = UnixStream::connect(endpoint).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    host::write_frame(&mut stream, &serde_json::json!({"type":"retain_engine_tree","session_id":session_id,"token":token,"root_pid":root_pid})).map_err(|e| e.to_string())?;
    let response: serde_json::Value = host::read_frame(&mut stream).map_err(|e| e.to_string())?;
    if response.get("type").and_then(|v| v.as_str()) == Some("ok") {
        Ok(())
    } else {
        Err(format!("Engine tree observer rejected: {response}"))
    }
}
