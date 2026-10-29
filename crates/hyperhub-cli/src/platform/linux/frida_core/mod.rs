mod child_gating;
mod context;
mod fork_listener;
mod injector;

pub(super) const FRIDA_CORE_VERSION: &str = "17.17.0";

use hyperhub_core::attachments::ProcessIdentity;
use std::ffi::CStr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

pub use context::{Process, Stdio};

#[derive(Clone)]
pub struct FridaCore {
    inner: Arc<Inner>,
}

struct Inner {
    sender: Sender<QueuedCommand>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    poisoned: Arc<AtomicBool>,
    cleanup: Mutex<Option<CleanupFlight>>,
}

enum Command {
    Spawn {
        program: std::ffi::OsString,
        args: Vec<std::ffi::OsString>,
        env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        cwd: PathBuf,
        stdio: Stdio,
        reply: Reply<Process>,
    },
    Inject {
        process: Process,
        library: PathBuf,
        entrypoint: String,
        data: Vec<u8>,
        cancellation: Option<Arc<Cancellable>>,
        reply: Reply<u32>,
    },
    EnableChildGating {
        process: Process,
        cancellation: Option<Arc<Cancellable>>,
        reply: Reply<()>,
    },
    DisableChildGating {
        process: Process,
        cancellation: Option<Arc<Cancellable>>,
        reply: Reply<()>,
    },
    ForkListener {
        exec_action: Option<ExecMonitorAction>,
        process: Process,
        runtime: PathBuf,
        prepare: bool,
        deadline_millis: Option<u64>,
        cancellation: Option<Arc<Cancellable>>,
        reply: Reply<()>,
    },
    AbortForkListener {
        process: Process,
        runtime: PathBuf,
        reply: Reply<()>,
    },
    CleanupDisableChildGating {
        process: Process,
        reply: Reply<()>,
    },
    CleanupPendingChildren {
        reply: Reply<Vec<PendingChild>>,
    },
    CleanupResume {
        process: Process,
        reply: Reply<()>,
    },
    CleanupRecoverTransport {
        process: Process,
        identity: ProcessIdentity,
        runtime: PathBuf,
        reply: Reply<()>,
    },
    PendingChildren {
        cancellation: Option<Arc<Cancellable>>,
        reply: Reply<Vec<PendingChild>>,
    },
    Resume {
        process: Process,
        cancellation: Option<Arc<Cancellable>>,
        reply: Reply<()>,
    },
    Shutdown,
}

struct QueuedCommand {
    id: u64,
    command: Command,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CleanupKey {
    AbortForkListener(i32, PathBuf),
    DisableChildGating(i32),
    PendingChildren,
    Resume(i32),
    RecoverTransport(ProcessIdentity, PathBuf),
}

impl CleanupKey {
    fn diagnostic_identity(&self) -> (&'static str, Option<i32>) {
        match self {
            Self::AbortForkListener(pid, _) => ("fork_abort", Some(*pid)),
            Self::DisableChildGating(pid) => ("cleanup_disable_child_gating", Some(*pid)),
            Self::PendingChildren => ("cleanup_pending_children", None),
            Self::Resume(pid) => ("cleanup_resume", Some(*pid)),
            Self::RecoverTransport(identity, _) => (
                "cleanup_recover_attachment_transport",
                i32::try_from(identity.pid).ok(),
            ),
        }
    }
}

struct CleanupFlight {
    key: CleanupKey,
    completion: Arc<CleanupCompletion>,
}

struct CleanupCompletion {
    result: Mutex<Option<CleanupResult>>,
    ready: Condvar,
}

#[derive(Clone)]
enum CleanupResult {
    Unit(Result<(), String>),
    PendingChildren(Result<Vec<PendingChild>, String>),
}

impl CleanupResult {
    fn summary(&self) -> String {
        match self {
            Self::Unit(Ok(())) | Self::PendingChildren(Ok(_)) => "succeeded".into(),
            Self::Unit(Err(error)) | Self::PendingChildren(Err(error)) => {
                format!("failed: {error}")
            }
        }
    }
}

trait CleanupValue: Sized + Send + 'static {
    fn pack(result: Result<Self, String>) -> CleanupResult;
    fn unpack(result: &CleanupResult) -> Option<Result<Self, String>>;
}

impl CleanupValue for () {
    fn pack(result: Result<Self, String>) -> CleanupResult {
        CleanupResult::Unit(result)
    }

    fn unpack(result: &CleanupResult) -> Option<Result<Self, String>> {
        match result {
            CleanupResult::Unit(result) => Some(result.clone()),
            CleanupResult::PendingChildren(_) => None,
        }
    }
}

impl CleanupValue for Vec<PendingChild> {
    fn pack(result: Result<Self, String>) -> CleanupResult {
        CleanupResult::PendingChildren(result)
    }

    fn unpack(result: &CleanupResult) -> Option<Result<Self, String>> {
        match result {
            CleanupResult::Unit(_) => None,
            CleanupResult::PendingChildren(result) => Some(result.clone()),
        }
    }
}

impl CleanupCompletion {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn complete(&self, result: CleanupResult) {
        if let Ok(mut slot) = self.result.lock() {
            *slot = Some(result);
            self.ready.notify_all();
        }
    }

    fn wait(&self, timeout: Duration) -> Option<CleanupResult> {
        let slot = self.result.lock().ok()?;
        let (slot, _) = self
            .ready
            .wait_timeout_while(slot, timeout, |result| result.is_none())
            .ok()?;
        slot.clone()
    }
}

impl Command {
    fn diagnostic_identity(&self) -> (&'static str, Option<i32>) {
        match self {
            Self::Spawn { .. } => ("spawn", None),
            Self::Inject { process, .. } => ("inject", Some(process.pid())),
            Self::EnableChildGating { process, .. } => ("enable_child_gating", Some(process.pid())),
            Self::DisableChildGating { process, .. } => {
                ("disable_child_gating", Some(process.pid()))
            }
            Self::ForkListener {
                process,
                exec_action,
                prepare,
                ..
            } => (
                match exec_action {
                    Some(ExecMonitorAction::Prepare) => "exec_prepare",
                    Some(ExecMonitorAction::RemoveFresh) => "exec_remove_fresh",
                    Some(ExecMonitorAction::ReinstallFresh) => "exec_reinstall_fresh",
                    Some(ExecMonitorAction::Confirm) => "exec_confirm",
                    Some(ExecMonitorAction::RecoverTransport) => "recover_attachment_transport",
                    None if *prepare => "fork_prepare",
                    None => "fork_arm",
                },
                Some(process.pid()),
            ),
            Self::AbortForkListener { process, .. } => ("fork_abort", Some(process.pid())),
            Self::CleanupDisableChildGating { process, .. } => {
                ("cleanup_disable_child_gating", Some(process.pid()))
            }
            Self::CleanupPendingChildren { .. } => ("cleanup_pending_children", None),
            Self::CleanupResume { process, .. } => ("cleanup_resume", Some(process.pid())),
            Self::CleanupRecoverTransport { process, .. } => {
                ("cleanup_recover_attachment_transport", Some(process.pid()))
            }
            Self::PendingChildren { .. } => ("pending_children", None),
            Self::Resume { process, .. } => ("resume", Some(process.pid())),
            Self::Shutdown => ("shutdown", None),
        }
    }

    fn allowed_when_poisoned(&self) -> bool {
        matches!(
            self,
            Self::AbortForkListener { .. }
                | Self::CleanupDisableChildGating { .. }
                | Self::CleanupPendingChildren { .. }
                | Self::CleanupResume { .. }
                | Self::CleanupRecoverTransport { .. }
                | Self::Shutdown
        )
    }

    fn reject(self, error: String) {
        match self {
            Self::Spawn { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Inject { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::EnableChildGating { reply, .. }
            | Self::DisableChildGating { reply, .. }
            | Self::ForkListener { reply, .. }
            | Self::AbortForkListener { reply, .. }
            | Self::CleanupDisableChildGating { reply, .. }
            | Self::CleanupResume { reply, .. }
            | Self::CleanupRecoverTransport { reply, .. }
            | Self::Resume { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::PendingChildren { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::CleanupPendingChildren { reply } => {
                let _ = reply.send(Err(error));
            }
            Self::Shutdown => {}
        }
    }
}

const POISONED_OWNER: &str =
    "Frida Core owner is poisoned after a timed out dynamic attachment request";
const CLEANUP_IN_FLIGHT: &str =
    "a Frida Core cleanup barrier is still queued or executing after its response deadline";
const CANCEL_SETTLEMENT_GRACE: Duration = Duration::from_millis(250);
const CLEANUP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
static NEXT_COMMAND: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FridaRequestError {
    OwnerPoisoned,
    OwnerUnavailable,
    ResponseDropped,
    DeadlineExceeded {
        operation: &'static str,
        timeout: Duration,
    },
    Operation(String),
}

impl std::fmt::Display for FridaRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OwnerPoisoned => formatter.write_str(POISONED_OWNER),
            Self::OwnerUnavailable => formatter.write_str("Frida Core owner thread is unavailable"),
            Self::ResponseDropped => {
                formatter.write_str("Frida Core owner thread dropped the response")
            }
            Self::DeadlineExceeded { operation, timeout } => write!(
                formatter,
                "Frida Core {operation} exceeded the dynamic attachment deadline of {} ms; the owner was poisoned and the native result remains unknown",
                timeout.as_millis()
            ),
            Self::Operation(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for FridaRequestError {}

struct Cancellable {
    pointer: std::ptr::NonNull<frida_sys::GCancellable>,
}

// GLib explicitly permits g_cancellable_cancel() from another thread. The
// object remains referenced by the queued command until the sync call returns.
unsafe impl Send for Cancellable {}
unsafe impl Sync for Cancellable {}

impl Cancellable {
    fn new() -> Result<Self, FridaRequestError> {
        let pointer = unsafe { frida_sys::_frida_g_cancellable_new() };
        std::ptr::NonNull::new(pointer)
            .map(|pointer| Self { pointer })
            .ok_or_else(|| FridaRequestError::Operation("g_cancellable_new returned null".into()))
    }

    fn as_ptr(&self) -> *mut frida_sys::GCancellable {
        self.pointer.as_ptr()
    }

    fn cancel(&self) {
        unsafe { frida_sys::_frida_g_cancellable_cancel(self.pointer.as_ptr()) };
    }

    fn is_cancelled(&self) -> bool {
        unsafe { frida_sys::_frida_g_cancellable_is_cancelled(self.pointer.as_ptr()) != 0 }
    }
}

impl Drop for Cancellable {
    fn drop(&mut self) {
        unsafe { frida_sys::_frida_g_object_unref(self.pointer.as_ptr().cast()) };
    }
}

// This opt-in trace is emitted by the manager, whose stderr is a private log.
// It contains lifecycle metadata only, never target argv, environment or data.
fn diagnostic(id: u64, operation: &str, target: Option<i32>, stage: &str) {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    if !*ENABLED.get_or_init(|| {
        std::env::var_os("HYPERHUB_FRIDA_DIAGNOSTICS").as_deref() == Some(std::ffi::OsStr::new("1"))
    }) {
        return;
    }
    eprintln!(
        "hyperhub-frida-diagnostic manager={} request={id} operation={operation} target={} stage={stage}",
        std::process::id(), target.unwrap_or(0),
    );
}

pub(super) fn diagnostic_stage(operation: &str, target: Option<i32>, stage: &str) {
    diagnostic(0, operation, target, stage);
}

#[derive(Clone, Copy)]
pub(super) enum ExecMonitorAction {
    Prepare,
    RemoveFresh,
    ReinstallFresh,
    Confirm,
    RecoverTransport,
}
impl ExecMonitorAction {
    fn symbol(self) -> &'static str {
        match self {
            Self::Prepare => "hyperhub_exec_monitor_prepare",
            Self::RemoveFresh => "hyperhub_exec_monitor_remove_fresh",
            Self::ReinstallFresh => "hyperhub_exec_monitor_reinstall_fresh",
            Self::Confirm => "hyperhub_exec_monitor_confirm",
            Self::RecoverTransport => "hyperhub_attachment_recover_transport",
        }
    }
}

type Reply<T> = Sender<Result<T, String>>;

impl FridaCore {
    pub fn new() -> Result<Self, String> {
        // Core is a process-wide SDK. In 17.17, failed fork reservations can
        // retain an unused injectee clone; closing its device manager then waits
        // indefinitely even after every managed process has exited. Keep one
        // owner until CLI process exit. Per-process sessions and target-tree
        // completion are still retired explicitly by the child monitor.
        static OWNER: OnceLock<Result<Arc<Inner>, String>> = OnceLock::new();
        OWNER
            .get_or_init(Self::start_owner)
            .as_ref()
            .map(|inner| Self {
                inner: inner.clone(),
            })
            .map_err(Clone::clone)
    }

    fn start_owner() -> Result<Arc<Inner>, String> {
        let (sender, receiver) = mpsc::channel::<QueuedCommand>();
        let (init_sender, init_receiver) = mpsc::sync_channel(1);
        let poisoned = Arc::new(AtomicBool::new(false));
        let worker_poisoned = poisoned.clone();
        let thread = std::thread::Builder::new()
            .name("hyperhub-frida-core".into())
            .spawn(move || match context::Context::new() {
                Ok(mut context) => {
                    let _ = init_sender.send(Ok(()));
                    while let Ok(QueuedCommand { id, command }) = receiver.recv() {
                        let (operation, target) = command.diagnostic_identity();
                        if worker_poisoned.load(Ordering::Acquire)
                            && !command.allowed_when_poisoned()
                        {
                            diagnostic(id, operation, target, "worker_rejected_poisoned");
                            command.reject(POISONED_OWNER.into());
                            continue;
                        }
                        diagnostic(id, operation, target, "worker_begin");
                        match command {
                            Command::Spawn {
                                program,
                                args,
                                env,
                                cwd,
                                stdio,
                                reply,
                            } => {
                                let _ =
                                    reply.send(context.spawn(&program, &args, &env, &cwd, stdio));
                            }
                            Command::Inject {
                                process,
                                library,
                                entrypoint,
                                data,
                                cancellation,
                                reply,
                            } => {
                                let _ = reply.send(context.inject(
                                    process,
                                    &library,
                                    &entrypoint,
                                    &data,
                                    cancellation.as_deref(),
                                ));
                            }
                            Command::EnableChildGating {
                                process,
                                cancellation,
                                reply,
                            } => {
                                let _ = reply.send(
                                    context.enable_child_gating(process, cancellation.as_deref()),
                                );
                            }
                            Command::DisableChildGating {
                                process,
                                cancellation,
                                reply,
                            } => {
                                let _ = reply.send(
                                    context.disable_child_gating(process, cancellation.as_deref()),
                                );
                            }
                            Command::ForkListener {
                                exec_action,
                                process,
                                runtime,
                                prepare,
                                deadline_millis,
                                cancellation,
                                reply,
                            } => {
                                let _ = reply.send(context.fork_listener(
                                    process,
                                    &runtime,
                                    prepare,
                                    exec_action,
                                    cancellation.as_deref(),
                                    deadline_millis,
                                    false,
                                ));
                            }
                            Command::AbortForkListener {
                                process,
                                runtime,
                                reply,
                            } => {
                                let _ = reply.send(context.fork_listener(
                                    process, &runtime, false, None, None, None, true,
                                ));
                            }
                            Command::CleanupDisableChildGating { process, reply } => {
                                let _ = reply.send(context.disable_child_gating(process, None));
                            }
                            Command::CleanupPendingChildren { reply } => {
                                let _ = reply.send(context.pending_children(None));
                            }
                            Command::CleanupResume { process, reply } => {
                                let _ = reply.send(context.resume(process, None));
                            }
                            Command::CleanupRecoverTransport {
                                process,
                                identity,
                                runtime,
                                reply,
                            } => {
                                let result = hyperhub_core::attachments::verify_process(&identity)
                                    .and_then(|_| {
                                        context.fork_listener(
                                            process,
                                            &runtime,
                                            false,
                                            Some(ExecMonitorAction::RecoverTransport),
                                            None,
                                            None,
                                            false,
                                        )
                                    });
                                let _ = reply.send(result);
                            }
                            Command::PendingChildren {
                                cancellation,
                                reply,
                            } => {
                                let _ =
                                    reply.send(context.pending_children(cancellation.as_deref()));
                            }
                            Command::Resume {
                                process,
                                cancellation,
                                reply,
                            } => {
                                let _ =
                                    reply.send(context.resume(process, cancellation.as_deref()));
                            }
                            Command::Shutdown => break,
                        }
                        diagnostic(id, operation, target, "worker_replied");
                    }
                }
                Err(error) => {
                    let _ = init_sender.send(Err(error));
                }
            })
            .map_err(|error| format!("cannot start Frida Core owner thread: {error}"))?;
        let inner = Arc::new(Inner {
            sender,
            thread: Mutex::new(Some(thread)),
            poisoned,
            cleanup: Mutex::new(None),
        });
        init_receiver
            .recv()
            .map_err(|_| "Frida Core owner thread exited during initialization".to_string())??;
        Ok(inner)
    }

    fn request<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> Result<T, String> {
        if self.inner.poisoned.load(Ordering::Acquire) {
            return Err(POISONED_OWNER.into());
        }
        let (reply, receiver) = mpsc::channel();
        let id = NEXT_COMMAND.fetch_add(1, Ordering::Relaxed);
        let command = command(reply);
        let (operation, target) = command.diagnostic_identity();
        diagnostic(id, operation, target, "queued");
        self.inner
            .sender
            .send(QueuedCommand { id, command })
            .map_err(|_| "Frida Core owner thread is unavailable".to_string())?;
        let result = loop {
            match receiver.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => break result,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("Frida Core owner thread dropped the response".into());
                }
                Err(mpsc::RecvTimeoutError::Timeout)
                    if self.inner.poisoned.load(Ordering::Acquire) =>
                {
                    return Err(POISONED_OWNER.into());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        };
        diagnostic(
            id,
            operation,
            target,
            if result.is_ok() {
                "received_ok"
            } else {
                "received_error"
            },
        );
        result
    }

    fn cleanup_request<T: CleanupValue>(
        &self,
        key: CleanupKey,
        command: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, String> {
        let id = NEXT_COMMAND.fetch_add(1, Ordering::Relaxed);
        let (operation, target) = key.diagnostic_identity();
        let (completion, new_request) = {
            let mut cleanup = self
                .inner
                .cleanup
                .lock()
                .map_err(|_| "Frida Core cleanup state is poisoned".to_string())?;
            match cleanup.as_ref() {
                Some(flight) if flight.key == key => (flight.completion.clone(), None),
                Some(flight) => {
                    let old_key = flight.key.clone();
                    let old_completion = flight.completion.clone();
                    let Some(old_result) = old_completion.wait(Duration::ZERO) else {
                        return Err(CLEANUP_IN_FLIGHT.into());
                    };
                    let (old_operation, old_target) = old_key.diagnostic_identity();
                    let summary = old_result.summary();
                    *cleanup = None;
                    drop(cleanup);
                    diagnostic(
                        id,
                        old_operation,
                        old_target,
                        "retired_unclaimed_cleanup_result_before_retry",
                    );
                    return Err(format!(
                        "previous Frida Core {old_operation} cleanup completed ({summary}); retry {operation} after re-evaluating cleanup state"
                    ));
                }
                None => {
                    let (reply, receiver) = mpsc::channel();
                    let completion = Arc::new(CleanupCompletion::new());
                    *cleanup = Some(CleanupFlight {
                        key: key.clone(),
                        completion: completion.clone(),
                    });
                    (completion, Some((command(reply), receiver)))
                }
            }
        };

        let queued_new = new_request.is_some();
        if let Some((command, receiver)) = new_request {
            let result_completion = completion.clone();
            if let Err(error) = std::thread::Builder::new()
                .name("hyperhub-frida-cleanup-result".into())
                .spawn(move || {
                    let result = receiver.recv().unwrap_or_else(|_| {
                        Err("Frida Core owner thread dropped the cleanup response".into())
                    });
                    result_completion.complete(T::pack(result));
                })
            {
                self.clear_cleanup_flight(&key, &completion);
                return Err(format!("cannot track Frida Core cleanup result: {error}"));
            }
            diagnostic(id, operation, target, "queued_cleanup_barrier");
            if self
                .inner
                .sender
                .send(QueuedCommand { id, command })
                .is_err()
            {
                self.clear_cleanup_flight(&key, &completion);
                return Err("Frida Core owner thread is unavailable".into());
            }
        } else {
            diagnostic(id, operation, target, "polling_cleanup_barrier");
        }

        let wait = if queued_new {
            CLEANUP_RESPONSE_TIMEOUT
        } else {
            Duration::ZERO
        };
        let Some(packed) = completion.wait(wait) else {
            diagnostic(id, operation, target, "cleanup_response_pending");
            if !queued_new {
                return Err(CLEANUP_IN_FLIGHT.into());
            }
            return Err(format!(
                "Frida Core {operation} cleanup remains queued or executing after {} ms",
                CLEANUP_RESPONSE_TIMEOUT.as_millis()
            ));
        };
        let Some(result) = T::unpack(&packed) else {
            self.clear_cleanup_flight(&key, &completion);
            return Err("Frida Core cleanup result type does not match its stable key".into());
        };
        self.clear_cleanup_flight(&key, &completion);
        diagnostic(
            id,
            operation,
            target,
            if result.is_ok() {
                "cleanup_received_ok"
            } else {
                "cleanup_received_error"
            },
        );
        result
    }

    fn clear_cleanup_flight(&self, key: &CleanupKey, completion: &Arc<CleanupCompletion>) {
        let Ok(mut cleanup) = self.inner.cleanup.lock() else {
            return;
        };
        if cleanup
            .as_ref()
            .is_some_and(|flight| flight.key == *key && Arc::ptr_eq(&flight.completion, completion))
        {
            *cleanup = None;
        }
    }

    fn request_with_timeout<T>(
        &self,
        timeout: Duration,
        cancel: impl FnOnce(),
        command: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, FridaRequestError> {
        if self.inner.poisoned.load(Ordering::Acquire) {
            return Err(FridaRequestError::OwnerPoisoned);
        }
        let (reply, receiver) = mpsc::channel();
        let id = NEXT_COMMAND.fetch_add(1, Ordering::Relaxed);
        let command = command(reply);
        let (operation, target) = command.diagnostic_identity();
        diagnostic(id, operation, target, "queued_with_deadline");
        self.inner
            .sender
            .send(QueuedCommand { id, command })
            .map_err(|_| FridaRequestError::OwnerUnavailable)?;
        match receiver.recv_timeout(timeout) {
            Ok(result) => {
                diagnostic(
                    id,
                    operation,
                    target,
                    if result.is_ok() {
                        "received_ok"
                    } else {
                        "received_error"
                    },
                );
                result.map_err(FridaRequestError::Operation)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(FridaRequestError::ResponseDropped),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Poison before cancellation. Any queued command is rejected,
                // while the in-flight native call receives a real GLib cancel.
                // A late reply cannot make this process-wide owner usable again.
                self.inner.poisoned.store(true, Ordering::Release);
                cancel();
                diagnostic(id, operation, target, "deadline_exceeded_owner_poisoned");
                // Cancellation is not a completion barrier. Give cooperative
                // foreign code a bounded chance to settle, then return so the
                // manager can publish CleanupPending. The poisoned owner keeps
                // serial ownership of Context; cleanup commands queue behind
                // this call and their own in-flight lease prevents retry
                // accumulation until the worker actually reaches them.
                match receiver.recv_timeout(CANCEL_SETTLEMENT_GRACE) {
                    Ok(_) => diagnostic(id, operation, target, "deadline_cancel_settled"),
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        diagnostic(id, operation, target, "deadline_cancel_response_dropped")
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        diagnostic(id, operation, target, "deadline_cancel_still_unsettled")
                    }
                }
                Err(FridaRequestError::DeadlineExceeded { operation, timeout })
            }
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.sender.send(QueuedCommand {
            id: 0,
            command: Command::Shutdown,
        });
        if let Ok(mut thread) = self.thread.lock() {
            let Some(thread) = thread.take() else {
                return;
            };
            // A poisoned owner may still be inside foreign sync code even
            // after cancellation. Dropping its JoinHandle detaches it; the
            // attachment-manager process exit is the final containment bound.
            if !self.poisoned.load(Ordering::Acquire) {
                let _ = thread.join();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildOrigin {
    Fork,
    Exec,
    Spawn,
    Unknown(u32),
}

impl ChildOrigin {
    fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::Fork,
            1 => Self::Exec,
            2 => Self::Spawn,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingChild {
    pub process: Process,
    pub parent_pid: i32,
    pub origin: ChildOrigin,
    pub skip_agent: bool,
}

pub(super) unsafe fn should_try_device_fallback(error: *mut frida_sys::GError) -> bool {
    !error.is_null()
        && (frida_sys::_frida_g_error_matches(
            error,
            frida_sys::frida_error_quark(),
            frida_sys::FridaError_FRIDA_ERROR_NOT_SUPPORTED as i32,
        ) != 0
            || frida_sys::_frida_g_error_matches(
                error,
                frida_sys::frida_error_quark(),
                frida_sys::FridaError_FRIDA_ERROR_PERMISSION_DENIED as i32,
            ) != 0)
}

pub(super) unsafe fn take_error(error: *mut frida_sys::GError) -> String {
    if error.is_null() {
        return "unknown Frida Core error".into();
    }
    let message = if (*error).message.is_null() {
        "unknown Frida Core error".into()
    } else {
        CStr::from_ptr((*error).message)
            .to_string_lossy()
            .into_owned()
    };
    frida_sys::_frida_g_error_free(error);
    message
}

pub(super) unsafe fn unref(pointer: *mut std::ffi::c_void) {
    if !pointer.is_null() {
        frida_sys::frida_unref(pointer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_identity(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            birth: 1,
            executable: "/fixture/target".into(),
            executable_sha256: "00".repeat(32),
            owner: "fixture".into(),
        }
    }

    fn test_core(worker: impl FnOnce(mpsc::Receiver<QueuedCommand>) + Send + 'static) -> FridaCore {
        let (sender, receiver) = mpsc::channel();
        let poisoned = Arc::new(AtomicBool::new(false));
        let thread = std::thread::spawn(move || worker(receiver));
        FridaCore {
            inner: Arc::new(Inner {
                sender,
                thread: Mutex::new(Some(thread)),
                poisoned,
                cleanup: Mutex::new(None),
            }),
        }
    }

    #[test]
    fn maps_all_known_child_origins() {
        assert_eq!(ChildOrigin::from_raw(0), ChildOrigin::Fork);
        assert_eq!(ChildOrigin::from_raw(1), ChildOrigin::Exec);
        assert_eq!(ChildOrigin::from_raw(2), ChildOrigin::Spawn);
        assert_eq!(ChildOrigin::from_raw(99), ChildOrigin::Unknown(99));
    }

    #[test]
    fn core_handles_share_one_process_lifetime_owner() {
        let first = FridaCore::new().unwrap();
        let second = FridaCore::new().unwrap();
        assert!(Arc::ptr_eq(&first.inner, &second.inner));
        let owner = Arc::downgrade(&first.inner);
        drop(first);
        drop(second);
        assert!(owner.upgrade().is_some());
    }

    #[test]
    fn null_error_has_stable_fallback_message() {
        assert_eq!(
            unsafe { take_error(std::ptr::null_mut()) },
            "unknown Frida Core error"
        );
    }

    #[test]
    fn cancellable_uses_initialized_embedded_glib_runtime() {
        let _core = FridaCore::new().unwrap();
        let cancellation = Cancellable::new().unwrap();
        assert_eq!(
            unsafe { frida_sys::_frida_g_cancellable_is_cancelled(cancellation.as_ptr()) },
            0
        );
        cancellation.cancel();
        assert_ne!(
            unsafe { frida_sys::_frida_g_cancellable_is_cancelled(cancellation.as_ptr()) },
            0
        );
    }

    #[test]
    fn timed_request_poisons_owner_and_later_requests_fail_fast() {
        let (started_send, started_receive) = mpsc::sync_channel(1);
        let (release_send, release_receive) = mpsc::sync_channel(1);
        let (cancel_send, cancel_receive) = mpsc::sync_channel(1);
        let (queued_send, queued_receive) = mpsc::sync_channel(1);
        let core = test_core(move |receiver| {
            let first = receiver.recv().unwrap();
            started_send.send(()).unwrap();
            release_receive.recv().unwrap();
            first.command.reject("late native reply".into());
            queued_send.send(receiver.try_recv().is_ok()).unwrap();
        });
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_on_timeout = cancelled.clone();
        let timed_core = core.clone();
        let timed = std::thread::spawn(move || {
            timed_core.request_with_timeout(
                Duration::from_millis(20),
                move || {
                    cancelled_on_timeout.store(true, Ordering::Release);
                    cancel_send.send(()).unwrap();
                },
                |reply| Command::PendingChildren {
                    cancellation: None,
                    reply,
                },
            )
        });
        started_receive.recv().unwrap();
        cancel_receive.recv().unwrap();
        assert!(core.inner.poisoned.load(Ordering::Acquire));
        release_send.send(()).unwrap();
        let result = timed.join().unwrap();
        assert!(matches!(
            result,
            Err(FridaRequestError::DeadlineExceeded {
                operation: "pending_children",
                ..
            })
        ));
        assert!(cancelled.load(Ordering::Acquire));

        let before = std::time::Instant::now();
        assert_eq!(
            core.request(|reply| Command::PendingChildren {
                cancellation: None,
                reply,
            })
            .unwrap_err(),
            POISONED_OWNER
        );
        assert!(before.elapsed() < Duration::from_millis(100));
        assert!(!queued_receive.recv().unwrap());
        assert!(core.inner.poisoned.load(Ordering::Acquire));
    }

    #[test]
    fn dynamic_non_inject_timeout_uses_generic_poison_and_fast_fail_path() {
        // Timed wrappers allocate an embedded-GLib GCancellable. Initialize
        // the real process-wide SDK before exercising the synthetic owner.
        let _runtime = FridaCore::new().unwrap();
        let (started_send, started_receive) = mpsc::sync_channel(1);
        let (release_send, release_receive) = mpsc::sync_channel(1);
        let core = test_core(move |receiver| {
            let command = receiver.recv().unwrap();
            started_send.send(()).unwrap();
            release_receive.recv().unwrap();
            command.command.reject("late pending-children reply".into());
        });
        let timed_core = core.clone();
        let timed = std::thread::spawn(move || {
            timed_core.pending_children_with_timeout(Duration::from_millis(20))
        });
        started_receive.recv().unwrap();
        std::thread::sleep(Duration::from_millis(30));
        release_send.send(()).unwrap();
        assert!(matches!(
            timed.join().unwrap(),
            Err(FridaRequestError::DeadlineExceeded {
                operation: "pending_children",
                ..
            })
        ));
        let before = std::time::Instant::now();
        assert_eq!(
            core.pending_children().unwrap_err(),
            POISONED_OWNER.to_string()
        );
        assert!(before.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn timed_request_returns_when_cancelled_foreign_call_does_not_settle() {
        let (release_send, release_receive) = mpsc::sync_channel(1);
        let core = test_core(move |receiver| {
            let command = receiver.recv().unwrap();
            release_receive.recv().unwrap();
            command.command.reject("eventual foreign reply".into());
        });

        let before = std::time::Instant::now();
        let result = core.request_with_timeout(
            Duration::from_millis(20),
            || {},
            |reply| Command::PendingChildren {
                cancellation: None,
                reply,
            },
        );
        let elapsed = before.elapsed();
        assert!(matches!(
            result,
            Err(FridaRequestError::DeadlineExceeded {
                operation: "pending_children",
                ..
            })
        ));
        assert!(elapsed >= Duration::from_millis(20));
        assert!(elapsed < Duration::from_millis(600), "elapsed={elapsed:?}");
        assert!(core.inner.poisoned.load(Ordering::Acquire));

        release_send.send(()).unwrap();
    }

    #[test]
    fn stalled_owner_preserves_one_cleanup_result_without_reexecution() {
        let (release_send, release_receive) = mpsc::sync_channel(1);
        let (first_cleanup_done_send, first_cleanup_done_receive) = mpsc::sync_channel(1);
        let (cleanup_count_send, cleanup_count_receive) = mpsc::sync_channel(2);
        let core = test_core(move |receiver| {
            let timed = receiver.recv().unwrap();
            release_receive.recv().unwrap();
            timed.command.reject("late timed reply".into());

            let QueuedCommand { command, .. } = receiver.recv().unwrap();
            cleanup_count_send.send(1).unwrap();
            match command {
                Command::CleanupDisableChildGating { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                command => command.reject("expected first cleanup".into()),
            }
            first_cleanup_done_send.send(()).unwrap();

            let QueuedCommand { command, .. } = receiver.recv().unwrap();
            cleanup_count_send.send(2).unwrap();
            match command {
                Command::CleanupDisableChildGating { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                command => command.reject("expected retry cleanup".into()),
            }
        });

        assert!(matches!(
            core.request_with_timeout(
                Duration::from_millis(20),
                || {},
                |reply| Command::PendingChildren {
                    cancellation: None,
                    reply,
                },
            ),
            Err(FridaRequestError::DeadlineExceeded { .. })
        ));

        let before = std::time::Instant::now();
        let first = core.disable_child_gating_cleanup(Process(41));
        let elapsed = before.elapsed();
        assert!(first
            .unwrap_err()
            .contains("cleanup remains queued or executing"));
        assert!(elapsed >= CLEANUP_RESPONSE_TIMEOUT);
        assert!(
            elapsed < Duration::from_millis(1_500),
            "elapsed={elapsed:?}"
        );

        let before = std::time::Instant::now();
        assert_eq!(
            core.disable_child_gating_cleanup(Process(41)).unwrap_err(),
            CLEANUP_IN_FLIGHT
        );
        assert!(before.elapsed() < Duration::from_millis(50));

        release_send.send(()).unwrap();
        first_cleanup_done_receive.recv().unwrap();
        loop {
            match core.disable_child_gating_cleanup(Process(41)) {
                Ok(()) => break,
                Err(error) if error == CLEANUP_IN_FLIGHT => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("cannot collect stable cleanup result: {error}"),
            }
        }
        assert_eq!(cleanup_count_receive.recv().unwrap(), 1);
        core.disable_child_gating_cleanup(Process(41)).unwrap();
        assert_eq!(cleanup_count_receive.recv().unwrap(), 2);
    }

    #[test]
    fn poisoned_owner_allows_only_dedicated_transport_recovery_cleanup() {
        let core = test_core(move |receiver| {
            let QueuedCommand { command, .. } = receiver.recv().unwrap();
            assert!(command.allowed_when_poisoned());
            match command {
                Command::CleanupRecoverTransport {
                    process,
                    identity,
                    runtime,
                    reply,
                } => {
                    assert_eq!(process, Process(41));
                    assert_eq!(identity, process_identity(41));
                    assert_eq!(runtime, PathBuf::from("fixture-agent"));
                    reply.send(Ok(())).unwrap();
                }
                command => command.reject("expected cleanup transport recovery".into()),
            }
        });
        core.inner.poisoned.store(true, Ordering::Release);

        core.recover_transport_cleanup(
            Process(41),
            std::path::Path::new("fixture-agent"),
            &process_identity(41),
        )
        .unwrap();
    }

    #[test]
    fn completed_disable_does_not_livelock_a_later_abort_key() {
        let (release_send, release_receive) = mpsc::sync_channel(1);
        let core = test_core(move |receiver| {
            let first = receiver.recv().unwrap();
            release_receive.recv().unwrap();
            match first.command {
                Command::CleanupDisableChildGating { reply, .. } => {
                    reply.send(Ok(())).unwrap();
                }
                command => command.reject("expected disable cleanup".into()),
            }
            let second = receiver.recv().unwrap();
            match second.command {
                Command::AbortForkListener { reply, .. } => reply.send(Ok(())).unwrap(),
                command => command.reject("expected abort cleanup".into()),
            }
        });

        assert!(core
            .disable_child_gating_cleanup(Process(41))
            .unwrap_err()
            .contains("cleanup remains queued or executing"));
        release_send.send(()).unwrap();
        loop {
            match core.abort_fork_listener(Process(41), std::path::Path::new("fixture-agent")) {
                Err(error) if error == CLEANUP_IN_FLIGHT => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    assert!(error.contains("previous Frida Core cleanup_disable_child_gating"));
                    assert!(error.contains("retry fork_abort"));
                    break;
                }
                Ok(()) => panic!("different key must not consume and continue in one call"),
            }
        }
        core.abort_fork_listener(Process(41), std::path::Path::new("fixture-agent"))
            .unwrap();
    }

    #[test]
    fn completed_transport_recovery_does_not_livelock_when_status_bypasses_its_key() {
        let (release_send, release_receive) = mpsc::sync_channel(1);
        let core = test_core(move |receiver| {
            let first = receiver.recv().unwrap();
            release_receive.recv().unwrap();
            match first.command {
                Command::CleanupRecoverTransport { reply, .. } => reply.send(Ok(())).unwrap(),
                command => command.reject("expected transport cleanup".into()),
            }
            let second = receiver.recv().unwrap();
            match second.command {
                Command::CleanupPendingChildren { reply } => reply.send(Ok(vec![])).unwrap(),
                command => command.reject("expected pending-child cleanup".into()),
            }
        });
        let identity = process_identity(41);

        assert!(core
            .recover_transport_cleanup(
                Process(41),
                std::path::Path::new("fixture-agent"),
                &identity,
            )
            .unwrap_err()
            .contains("cleanup remains queued or executing"));
        release_send.send(()).unwrap();
        loop {
            match core.pending_children_cleanup() {
                Err(error) if error == CLEANUP_IN_FLIGHT => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    assert!(
                        error.contains("previous Frida Core cleanup_recover_attachment_transport")
                    );
                    assert!(error.contains("retry cleanup_pending_children"));
                    break;
                }
                Ok(_) => panic!("different key must require one state re-evaluation"),
            }
        }
        assert!(core.pending_children_cleanup().unwrap().is_empty());
    }

    #[test]
    fn poisoned_cleanup_is_queued_only_after_timed_arm_settles() {
        let listener = Arc::new(AtomicBool::new(false));
        let worker_listener = listener.clone();
        let (started_send, started_receive) = mpsc::sync_channel(1);
        let (cancel_send, cancel_receive) = mpsc::sync_channel(1);
        let (release_send, release_receive) = mpsc::sync_channel(1);
        let (late_commit_send, late_commit_receive) = mpsc::sync_channel(1);
        let core = test_core(move |receiver| {
            let arm = receiver.recv().unwrap();
            assert!(matches!(arm.command, Command::ForkListener { .. }));
            started_send.send(()).unwrap();
            release_receive.recv().unwrap();
            worker_listener.store(true, Ordering::Release);
            late_commit_send.send(()).unwrap();
            arm.command.reject("late ARM result".into());

            let cleanup = receiver.recv().unwrap();
            match cleanup.command {
                Command::CleanupDisableChildGating { reply, .. } => {
                    worker_listener.store(false, Ordering::Release);
                    reply.send(Ok(())).unwrap();
                }
                command => command.reject("expected poisoned-owner cleanup".into()),
            }
        });
        let timed_core = core.clone();
        let (returned_send, returned_receive) = mpsc::sync_channel(1);
        let timed = std::thread::spawn(move || {
            let result = timed_core.request_with_timeout(
                Duration::from_millis(20),
                move || cancel_send.send(()).unwrap(),
                |reply| Command::ForkListener {
                    exec_action: None,
                    process: Process(41),
                    runtime: PathBuf::from("fixture-agent"),
                    prepare: false,
                    deadline_millis: Some(u64::MAX),
                    cancellation: None,
                    reply,
                },
            );
            returned_send.send(()).unwrap();
            result
        });
        started_receive.recv().unwrap();
        cancel_receive.recv().unwrap();
        assert!(returned_receive.try_recv().is_err());
        assert!(!listener.load(Ordering::Acquire));

        release_send.send(()).unwrap();
        late_commit_receive.recv().unwrap();
        assert!(listener.load(Ordering::Acquire));
        returned_receive.recv().unwrap();
        assert!(matches!(
            timed.join().unwrap(),
            Err(FridaRequestError::DeadlineExceeded {
                operation: "fork_arm",
                ..
            })
        ));

        core.disable_child_gating_cleanup(Process(41)).unwrap();
        assert!(!listener.load(Ordering::Acquire));
    }

    #[test]
    fn poisoned_owner_drop_never_joins_stalled_foreign_call() {
        let core = test_core(|_receiver| std::thread::sleep(Duration::from_millis(250)));
        core.inner.poisoned.store(true, Ordering::Release);
        let before = std::time::Instant::now();
        drop(core);
        assert!(before.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn request_already_queued_returns_when_another_request_poisons_owner() {
        let (started_send, started_receive) = mpsc::sync_channel(1);
        let (release_send, release_receive) = mpsc::sync_channel(1);
        let core = test_core(move |receiver| {
            let command = receiver.recv().unwrap();
            started_send.send(()).unwrap();
            release_receive.recv().unwrap();
            command.command.reject("late native reply".into());
        });
        let waiting_core = core.clone();
        let waiter = std::thread::spawn(move || {
            waiting_core.request(|reply| Command::PendingChildren {
                cancellation: None,
                reply,
            })
        });
        started_receive.recv().unwrap();
        core.inner.poisoned.store(true, Ordering::Release);
        let before = std::time::Instant::now();
        assert_eq!(waiter.join().unwrap().unwrap_err(), POISONED_OWNER);
        assert!(before.elapsed() < Duration::from_millis(100));
        release_send.send(()).unwrap();
    }
}
