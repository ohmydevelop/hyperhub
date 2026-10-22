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
    let stop = control.stop.clone();
    let connection = control.stream.clone();
    std::thread::Builder::new()
        .name("hyperhub-ptrace-engine".into())
        .spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let _ = (|| -> std::io::Result<()> {
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
                            snapshot: host::report(&runtime).map_err(std::io::Error::other)?,
                            nonce,
                        },
                    )?;
                    unsafe { host::serve(&mut stream, &runtime, &token, &nonce) }
                })();
                if let Ok(mut slot) = connection.lock() {
                    slot.take();
                }
                if !stop.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        })
        .map_err(|error| error.to_string())?;
    Ok(control)
}
