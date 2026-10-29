//! Fork callbacks must use Core's Gum instance, which also owns child recovery.
//! The permanent early listener precedes Core's listener. The late listener is
//! rearmed after Core's listener. Logical detach removes Core's temporary fork
//! monitor, so a later activation must also move our late listener behind the
//! newly installed monitor. The early listener remains permanent.
use super::{
    child_gating, context::Context, take_error, unref, CleanupKey, Command, ExecMonitorAction,
    FridaCore, FridaRequestError, Process,
};
use std::ffi::{c_void, CStr, CString};
use std::path::Path;
use std::ptr::NonNull;
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

const RESIDENT: &str = r#"
// Embedded Linux Agents are sealed memfds. A filesystem pathname comparison
// cannot identify their module; require the unique complete resident ABI.
const names = ['hyperhub_fork_listener_is_prepared',
  'hyperhub_fork_listener_mark_prepared', 'hyperhub_fork_listener_is_armed',
  'hyperhub_fork_listener_mark_armed', 'hyperhub_fork_listener_epoch',
  'hyperhub_fork_listener_generation', 'hyperhub_fork_listener_abort_arm',
  'hyperhub_fork_listener_abort_run',
  'hyperhub_fork_listener_confirm_rearm', 'hyperhub_fork_recovery_begin',
  'hyperhub_fork_listener_prepare_rearm',
  'hyperhub_fork_listener_rearm_run',
  'hyperhub_fork_listener_rearm_begin',
  'hyperhub_fork_listener_rearm_commit',
  'hyperhub_fork_listener_rearm_cancel',
  'hyperhub_fork_listener_abort_begin',
  'hyperhub_fork_listener_abort_commit',
  'hyperhub_fork_listener_recovery_pending',
  'hyperhub_fork_listener_enter', 'hyperhub_fork_return_gate', 'frida_fork_publish_main'];
const modules = Process.enumerateModules().map(module => ({
  module, exports: new Map(module.enumerateExports().map(symbol => [symbol.name, symbol.address]))
})).filter(item => names.every(name => {
  const address = item.exports.get(name);
  return address !== undefined && address.compare(item.module.base) >= 0 &&
    address.compare(item.module.base.add(item.module.size)) < 0;
}));
if (modules.length !== 1) throw new Error('resident Agent ABI module is missing or ambiguous');
const runtime = { getExportByName(name) {
  const address = modules[0].exports.get(name);
  if (address === undefined) throw new Error('resident Agent export is missing: ' + name);
  return address;
}};
"#;

const PREPARE: &str = r#"
const address = name => runtime.getExportByName(name);
const call = (name, result = 'void') => new NativeFunction(address(name), result, []);
call('hyperhub_fork_listener_prepare_rearm')();
if (call('hyperhub_fork_listener_is_prepared', 'uint')() === 0) {
  const fork = Module.getGlobalExportByName('fork');
  const early = address('hyperhub_fork_recovery_begin');
  const enter = address('hyperhub_fork_listener_enter');
  const late = address('hyperhub_fork_return_gate');
  const beginRearm = new NativeFunction(address('hyperhub_fork_listener_rearm_begin'),
    'int', ['uint', 'uint64']);
  const commitRearm = new NativeFunction(address('hyperhub_fork_listener_rearm_commit'),
    'int', ['uint', 'uint64']);
  const cancelRearm = call('hyperhub_fork_listener_rearm_cancel', 'int');
  const beginAbort = call('hyperhub_fork_listener_abort_begin', 'int');
  const commitAbort = call('hyperhub_fork_listener_abort_commit', 'int');
  const recoveryPending = call('hyperhub_fork_listener_recovery_pending', 'uint');
  let listener = null;
  let staged = null;
  let stagedPrevious = null;
  let committedReplacement = null;
  let committedPrevious = null;
  let committedPreviousWasPresent = false;
  let rollbackPreviousReplacement = null;
  // A successful detach can still be followed by a failed flush. Keep the
  // handle and its detach state until a later flush acknowledges retirement;
  // retries must not call detach twice on the same Interceptor listener.
  const detachedHandles = new Map();
  const attachLate = () => {
    const handle = Interceptor.attach(fork, { onEnter: enter, onLeave: late });
    detachedHandles.set(handle, false);
    return handle;
  };
  const detachOnce = handle => {
    if (handle !== null && detachedHandles.get(handle) !== true) {
      handle.detach();
      detachedHandles.set(handle, true);
    }
  };
  const wasDetached = handle => handle !== null && detachedHandles.get(handle) === true;
  const forget = handle => { if (handle !== null) detachedHandles.delete(handle); };
  let rearmError = null;
  // This permanent script strongly owns the callback and current listener.
  // Rust holds the gate in one native frame while this synchronous callback
  // runs. JS interruption cannot skip a separate unlock call.
  const applyReplacement = () => {
    try {
      if (staged !== null) throw new Error('fork listener replacement is already staged');
      committedReplacement = null;
      if (wasDetached(committedPrevious)) forget(committedPrevious);
      committedPrevious = null;
      committedPreviousWasPresent = false;
      rollbackPreviousReplacement = null;
      stagedPrevious = listener;
      staged = attachLate();
      Interceptor.flush();
      return 0x48484f4b;
    } catch (error) {
      rearmError = error;
      // An attach may have succeeded before flush reported failure. apply()
      // has not returned its transaction marker, so Rust will not invoke the
      // rollback callback. Retire that partial candidate here; if retirement
      // itself fails, retain the staged handle for abortActive() to retry.
      if (staged !== null) {
        try {
          detachOnce(staged);
          Interceptor.flush();
          forget(staged);
          staged = null;
          stagedPrevious = null;
        } catch (cleanupError) {
          rearmError = new Error(String(error) + '; staged listener cleanup failed: ' + cleanupError);
        }
      }
      return -1;
    }
  };
  const commitReplacement = () => {
    try {
      if (staged === null) throw new Error('fork listener replacement was not staged');
      const previous = stagedPrevious;
      listener = staged;
      committedReplacement = listener;
      committedPrevious = previous;
      committedPreviousWasPresent = previous !== null;
      rollbackPreviousReplacement = null;
      staged = null;
      stagedPrevious = null;
      if (previous !== null) {
        detachOnce(previous);
        Interceptor.flush();
      }
      return 0x48484f4b;
    } catch (error) {
      rearmError = error;
      return -1;
    }
  };
  const rollbackReplacement = () => {
    try {
      if (staged !== null) {
        detachOnce(staged);
        Interceptor.flush();
        forget(staged);
        staged = null;
        stagedPrevious = null;
      } else if (committedReplacement !== null) {
        detachOnce(committedReplacement);
        if (committedPreviousWasPresent) {
          if (wasDetached(committedPrevious)) {
            if (rollbackPreviousReplacement === null)
              rollbackPreviousReplacement = attachLate();
            listener = rollbackPreviousReplacement;
          } else {
            listener = committedPrevious;
          }
        } else {
          listener = null;
        }
        Interceptor.flush();
        forget(committedReplacement);
        if (wasDetached(committedPrevious)) forget(committedPrevious);
      }
      staged = null;
      stagedPrevious = null;
      committedReplacement = null;
      committedPrevious = null;
      committedPreviousWasPresent = false;
      rollbackPreviousReplacement = null;
      return 0x48484f4b;
    } catch (error) {
      rearmError = error;
      return -1;
    }
  };
  const abortActive = () => {
    try {
      // These references may alias. detachOnce records a successful detach so
      // a failed flush can be retried without an "already detached" failure.
      const handles = [staged, listener, committedReplacement,
        committedPrevious, rollbackPreviousReplacement];
      handles.forEach(detachOnce);
      Interceptor.flush();
      handles.forEach(forget);
      staged = null;
      stagedPrevious = null;
      listener = null;
      committedReplacement = null;
      committedPrevious = null;
      committedPreviousWasPresent = false;
      rollbackPreviousReplacement = null;
      return 0x48484f4b;
    } catch (error) {
      rearmError = error;
      return -1;
    }
  };
  Interceptor.attach(fork, { onLeave: early });
  Interceptor.attach(address('hyperhub_fork_listener_mark_armed'), {
    onEnter(args) {
      // The inherited late callback is still waiting for publication in the
      // original child thread. Detaching it queues cleanup that a temporary
      // script unload would wait for, preventing that very publication.
      try {
        const generation = args[0].toUInt32();
        const deadline = args[1].toUInt64();
        let status = beginRearm(generation, deadline);
        if (status === 0 && recoveryPending() === 0) {
        // Existing prepare owners may depend on the old late callback. Refuse
        // before mutation; new prepares wait until a replacement is installed.
        rearmError = null;
        if (applyReplacement() === 0x48484f4b && commitReplacement() === 0x48484f4b)
          status = commitRearm(generation, deadline);
        else
          status = -1;
        if (status !== 0) {
          const rollback = rollbackReplacement();
          const cancelled = rollback === 0x48484f4b ? cancelRearm() : -1;
          if (cancelled !== 0) status = cancelled;
          rearmError = rearmError || new Error('fork listener activation failed: ' + status);
        }
        } else if (status === 0) {
          status = commitRearm(generation, deadline);
          if (status !== 0) {
            const cancelled = cancelRearm();
            if (cancelled !== 0) status = cancelled;
            rearmError = new Error('fork listener recovery commit failed: ' + status);
          }
        }
        this.rearmStatus = status;
      } catch (error) {
        rearmError = error;
        this.rearmStatus = -1;
      }
    },
    onLeave(result) {
      result.replace(this.rearmStatus === undefined ? -4 : this.rearmStatus);
    }
  });
  Interceptor.attach(address('hyperhub_fork_listener_abort_arm'), {
    onEnter() {
      try {
        let status = beginAbort();
        if (status === 0) {
          status = abortActive() === 0x48484f4b ? commitAbort() : -1;
        }
        this.abortStatus = status;
      } catch (error) {
        rearmError = error;
        this.abortStatus = -1;
      }
    },
    onLeave(result) {
      result.replace(this.abortStatus);
    }
  });
  Interceptor.flush();
  call('hyperhub_fork_listener_mark_prepared')();
  send({ hyperhubForkListener: true, permanent: true });
} else {
  send({ hyperhubForkListener: true, permanent: false });
}
"#;

const ARM: &str = r#"
const call = (name, result = 'void') =>
  new NativeFunction(runtime.getExportByName(name), result, []);
const execReady = call('hyperhub_exec_monitor_confirm', 'int')();
if (execReady !== 0) throw new Error('resident exec monitor confirmation failed: ' + execReady);
const generation = call('hyperhub_fork_listener_generation', 'uint')();
const deadline = uint64('__HYPERHUB_DEADLINE_MILLIS__');
const epoch = call('hyperhub_fork_listener_epoch', 'uint');
const before = epoch();
// Cooperative scheduling permits the permanent script's mark callback to run.
const status = new NativeFunction(runtime.getExportByName('hyperhub_fork_listener_mark_armed'),
  'int', ['uint', 'uint64'])(generation, deadline);
if (status !== 0)
  throw new Error('resident fork listener rearm transaction failed: ' + status);
if (epoch() !== ((before + 1) >>> 0))
  throw new Error('resident fork listener did not acknowledge rearm');
if (call('hyperhub_fork_listener_is_armed', 'uint')() !== 1)
  throw new Error('resident fork listener generation was invalidated before commit');
send({ hyperhubForkListener: true, permanent: false });
"#;

const ABORT_ARM: &str = r#"
const abort = new NativeFunction(runtime.getExportByName('hyperhub_fork_listener_abort_arm'),
  'int', []);
const status = abort();
if (status !== 0)
  throw new Error('resident fork listener abort transaction failed: ' + status);
if (new NativeFunction(runtime.getExportByName('hyperhub_fork_listener_is_armed'),
    'uint', [])() !== 0)
  throw new Error('resident fork listener remained armed after abort');
send({ hyperhubForkListener: true, permanent: false });
"#;

const ABORT_UNOWNED: &str = r#"
const call = (name, result = 'void') =>
  new NativeFunction(runtime.getExportByName(name), result, []);
if (call('hyperhub_fork_listener_is_prepared', 'uint')() !== 0)
  throw new Error('unowned fork listener abort found a permanent owner');
const begin = call('hyperhub_fork_listener_abort_begin', 'int')();
if (begin !== 0)
  throw new Error('unowned fork listener abort begin failed: ' + begin);
const status = call('hyperhub_fork_listener_abort_commit', 'int')();
if (status !== 0)
  throw new Error('unowned fork listener abort transaction failed: ' + status);
if (call('hyperhub_fork_listener_is_armed', 'uint')() !== 0)
  throw new Error('unowned fork listener remained armed after abort');
send({ hyperhubForkListener: true, permanent: false });
"#;

fn monotonic_deadline_millis(timeout: Duration) -> Result<u64, FridaRequestError> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut now) } != 0 {
        return Err(FridaRequestError::Operation(
            "cannot read CLOCK_MONOTONIC_RAW for fork ARM deadline".into(),
        ));
    }
    Ok((now.tv_sec.max(0) as u64)
        .saturating_mul(1_000)
        .saturating_add((now.tv_nsec.max(0) as u64) / 1_000_000)
        .saturating_add(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)))
}

fn arm_source(deadline_millis: Option<u64>) -> String {
    // Untimed launch/run requests retain their historical unbounded behavior.
    // This value is consumed only by rearm_run's commit eligibility check; it
    // is never stored as a lifetime limit for an installed listener.
    ARM.replace(
        "__HYPERHUB_DEADLINE_MILLIS__",
        &deadline_millis.unwrap_or(u64::MAX).to_string(),
    )
}

impl FridaCore {
    pub fn exec_monitor(
        &self,
        process: Process,
        runtime: &Path,
        action: ExecMonitorAction,
    ) -> Result<(), String> {
        self.request(|reply| Command::ForkListener {
            process,
            runtime: runtime.into(),
            prepare: false,
            deadline_millis: None,
            exec_action: Some(action),
            cancellation: None,
            reply,
        })
    }

    pub fn recover_transport_cleanup(
        &self,
        process: Process,
        runtime: &Path,
        identity: &hyperhub_core::attachments::ProcessIdentity,
    ) -> Result<(), String> {
        if u32::try_from(process.pid()).ok() != Some(identity.pid) {
            return Err("pending Host cleanup identity does not match its Frida process".into());
        }
        let runtime = runtime.to_path_buf();
        self.cleanup_request(
            CleanupKey::RecoverTransport(identity.clone(), runtime.clone()),
            |reply| Command::CleanupRecoverTransport {
                process,
                identity: identity.clone(),
                runtime,
                reply,
            },
        )
    }

    pub fn prepare_fork_listener(&self, process: Process, runtime: &Path) -> Result<(), String> {
        self.request(|reply| Command::ForkListener {
            exec_action: None,
            process,
            runtime: runtime.into(),
            prepare: true,
            deadline_millis: None,
            cancellation: None,
            reply,
        })
    }

    pub fn arm_fork_listener(&self, process: Process, runtime: &Path) -> Result<(), String> {
        self.request(|reply| Command::ForkListener {
            exec_action: None,
            process,
            runtime: runtime.into(),
            prepare: false,
            deadline_millis: None,
            cancellation: None,
            reply,
        })
    }

    pub fn exec_monitor_with_timeout(
        &self,
        process: Process,
        runtime: &Path,
        action: ExecMonitorAction,
        timeout: Duration,
    ) -> Result<(), FridaRequestError> {
        let cancellation = Arc::new(super::Cancellable::new()?);
        let command_cancellation = cancellation.clone();
        let timeout_cancellation = cancellation.clone();
        self.request_with_timeout(
            timeout,
            move || timeout_cancellation.cancel(),
            move |reply| Command::ForkListener {
                process,
                runtime: runtime.into(),
                prepare: false,
                deadline_millis: None,
                exec_action: Some(action),
                cancellation: Some(command_cancellation),
                reply,
            },
        )
    }

    pub fn prepare_fork_listener_with_timeout(
        &self,
        process: Process,
        runtime: &Path,
        timeout: Duration,
    ) -> Result<(), FridaRequestError> {
        let cancellation = Arc::new(super::Cancellable::new()?);
        let command_cancellation = cancellation.clone();
        let timeout_cancellation = cancellation.clone();
        self.request_with_timeout(
            timeout,
            move || timeout_cancellation.cancel(),
            move |reply| Command::ForkListener {
                exec_action: None,
                process,
                runtime: runtime.into(),
                prepare: true,
                deadline_millis: None,
                cancellation: Some(command_cancellation),
                reply,
            },
        )
    }

    pub fn arm_fork_listener_with_timeout(
        &self,
        process: Process,
        runtime: &Path,
        timeout: Duration,
    ) -> Result<(), FridaRequestError> {
        let cancellation = Arc::new(super::Cancellable::new()?);
        let command_cancellation = cancellation.clone();
        let timeout_cancellation = cancellation.clone();
        let deadline_millis = monotonic_deadline_millis(timeout)?;
        self.request_with_timeout(
            timeout,
            move || timeout_cancellation.cancel(),
            move |reply| Command::ForkListener {
                exec_action: None,
                process,
                runtime: runtime.into(),
                prepare: false,
                deadline_millis: Some(deadline_millis),
                cancellation: Some(command_cancellation),
                reply,
            },
        )
    }
}

// Script lifetime and session lifetime are different. In particular, ARM runs
// after child gating is enabled and before the manager can service held forks.
// Closing another session at that point waits for the remote detach handshake,
// which can depend on that very fork recovery. Borrow the existing gated
// session and unload only this operation's script; the child-gating owner still
// disables and detaches its session at the normal lifecycle boundary.
enum Session<'a> {
    Gated(&'a NonNull<frida_sys::_FridaSession>),
    Temporary(TemporarySession),
}

impl Session<'_> {
    fn as_ptr(&self) -> *mut frida_sys::_FridaSession {
        match self {
            Self::Gated(pointer) => pointer.as_ptr(),
            Self::Temporary(session) => session.pointer.as_ptr(),
        }
    }
}

struct TemporarySession {
    pointer: NonNull<frida_sys::_FridaSession>,
    process: Process,
}

impl Drop for TemporarySession {
    fn drop(&mut self) {
        super::diagnostic_stage(
            "fork_script",
            Some(self.process.pid()),
            "session_detach_begin",
        );
        unsafe {
            frida_sys::frida_session_detach_sync(
                self.pointer.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            unref(self.pointer.as_ptr().cast());
        }
        super::diagnostic_stage(
            "fork_script",
            Some(self.process.pid()),
            "session_detach_complete",
        );
    }
}

struct Script {
    pointer: NonNull<frida_sys::_FridaScript>,
    handler: frida_sys::gulong,
    permanent: bool,
    unloaded: bool,
}
impl Script {
    fn unload_checked(&mut self) -> Result<(), String> {
        if self.permanent || self.unloaded {
            return Ok(());
        }
        super::diagnostic_stage("fork_script", None, "script_unload_begin");
        let mut error = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_script_unload_sync(
                self.pointer.as_ptr(),
                std::ptr::null_mut(),
                &mut error,
            );
        }
        if !error.is_null() {
            return Err(format!("fork listener script unload failed: {}", unsafe {
                take_error(error)
            }));
        }
        self.unloaded = true;
        super::diagnostic_stage("fork_script", None, "script_unload_complete");
        Ok(())
    }
}
impl Drop for Script {
    fn drop(&mut self) {
        unsafe {
            frida_sys::_frida_g_signal_handler_disconnect(
                self.pointer.as_ptr().cast(),
                self.handler,
            );
            if !self.permanent && !self.unloaded {
                super::diagnostic_stage("fork_script", None, "script_unload_begin");
                frida_sys::frida_script_unload_sync(
                    self.pointer.as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                super::diagnostic_stage("fork_script", None, "script_unload_complete");
            }
            unref(self.pointer.as_ptr().cast());
        }
    }
}

type Acknowledgement = Result<bool, String>;

unsafe extern "C" fn message(
    _script: *mut frida_sys::_FridaScript,
    json: *const std::ffi::c_char,
    _data: *mut frida_sys::GBytes,
    opaque: *mut c_void,
) {
    if json.is_null() || opaque.is_null() {
        return;
    }
    let sender = &*opaque.cast::<Sender<Acknowledgement>>();
    let result = parse_acknowledgement(CStr::from_ptr(json).to_bytes());
    if let Some(result) = result {
        let _ = sender.send(result);
    }
}

unsafe extern "C" fn destroy_sender(opaque: *mut c_void, _closure: *mut frida_sys::GClosure) {
    drop(Box::from_raw(opaque.cast::<Sender<Acknowledgement>>()));
}

fn parse_acknowledgement(bytes: &[u8]) -> Option<Acknowledgement> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => return Some(Err(format!("invalid fork listener response: {error}"))),
    };
    match value.get("type")?.as_str()? {
        "error" => Some(Err(format!(
            "fork listener script failed: {}",
            value
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown script error")
        ))),
        "send" if value["payload"]["hyperhubForkListener"] == true => Some(
            value["payload"]["permanent"]
                .as_bool()
                .ok_or_else(|| "fork listener response lacks lifetime".into()),
        ),
        _ => None,
    }
}

impl Context {
    pub(super) fn fork_listener(
        &mut self,
        process: Process,
        runtime: &Path,
        prepare: bool,
        exec_action: Option<ExecMonitorAction>,
        cancellation: Option<&super::Cancellable>,
        deadline_millis: Option<u64>,
        abort_arm: bool,
    ) -> Result<(), String> {
        // The launcher verifies this exact module before injection. Keep the
        // sealed memfd openable; do not resolve its intentionally unnamed link.
        std::fs::metadata(runtime)
            .map_err(|error| format!("cannot inspect resident Agent module: {error}"))?;
        let control=exec_action.map(|action|{
            let verify = if matches!(action, ExecMonitorAction::RecoverTransport) {
                let expected = serde_json::to_string(hyperhub_engine::NATIVE_BASE_MARKER.as_slice()).expect("byte array serializes");
                format!("const expected = {expected}; const actual = new Uint8Array(runtime.getExportByName('HH_AGENT_NATIVE_BASE_FINGERPRINT_V1').readByteArray(expected.length)); if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) throw new Error('resident native base differs from recovery executor');")
            } else { String::new() };
            format!("{verify} const result = new NativeFunction(runtime.getExportByName('{}'), 'int', [])(); if (result !== 0) throw new Error('native exec monitor operation failed: ' + result); send({{ hyperhubForkListener: true, permanent: false }});",action.symbol())
        });
        let arm = arm_source(deadline_millis);
        let unowned_abort = abort_arm && self.unowned_fork_listener_abort.contains(&process);
        let source = CString::new(format!(
            "{RESIDENT}{}",
            if abort_arm {
                if unowned_abort {
                    ABORT_UNOWNED
                } else {
                    ABORT_ARM
                }
            } else {
                control
                    .as_deref()
                    .unwrap_or(if prepare { PREPARE } else { &arm })
            }
        ))
        .map_err(|_| "fork listener script contains NUL")?;
        unsafe {
            let cancellable = cancellation
                .map(super::Cancellable::as_ptr)
                .unwrap_or(std::ptr::null_mut());
            let session = if let Some((_, pointer)) =
                self.child_sessions.iter().find(|(pid, pointer)| {
                    *pid == process && frida_sys::frida_session_is_detached(pointer.as_ptr()) == 0
                }) {
                super::diagnostic_stage("fork_script", Some(process.pid()), "borrow_gated_session");
                Session::Gated(pointer)
            } else {
                super::diagnostic_stage("fork_script", Some(process.pid()), "attach_begin");
                let pointer = child_gating::attach(self.device.as_ptr(), process, cancellation)?;
                super::diagnostic_stage("fork_script", Some(process.pid()), "attach_complete");
                Session::Temporary(TemporarySession { pointer, process })
            };
            let mut error = std::ptr::null_mut();
            super::diagnostic_stage("fork_script", Some(process.pid()), "script_create_begin");
            let raw = frida_sys::frida_session_create_script_sync(
                session.as_ptr(),
                source.as_ptr(),
                std::ptr::null_mut(),
                cancellable,
                &mut error,
            );
            if !error.is_null() {
                return Err(take_error(error));
            }
            super::diagnostic_stage("fork_script", Some(process.pid()), "script_create_complete");
            let pointer = NonNull::new(raw).ok_or("Frida returned a null fork listener script")?;
            let (sender, receiver) = mpsc::channel::<Acknowledgement>();
            let handler = frida_sys::_frida_g_signal_connect_data(
                pointer.as_ptr().cast(),
                c"message".as_ptr(),
                Some(std::mem::transmute::<
                    unsafe extern "C" fn(
                        *mut frida_sys::_FridaScript,
                        *const std::ffi::c_char,
                        *mut frida_sys::GBytes,
                        *mut c_void,
                    ),
                    unsafe extern "C" fn(),
                >(message)),
                Box::into_raw(Box::new(sender)).cast(),
                Some(destroy_sender),
                0,
            );
            let mut script = Script {
                pointer,
                handler,
                permanent: false,
                unloaded: false,
            };
            let operation = (|| -> Result<(), String> {
                super::diagnostic_stage("fork_script", Some(process.pid()), "script_load_begin");
                frida_sys::frida_script_load_sync(pointer.as_ptr(), cancellable, &mut error);
                if !error.is_null() {
                    return Err(take_error(error));
                }
                super::diagnostic_stage("fork_script", Some(process.pid()), "script_load_complete");
                let acknowledgement_deadline = Instant::now() + Duration::from_secs(5);
                let permanent = loop {
                    if cancellation.is_some_and(super::Cancellable::is_cancelled) {
                        return Err("fork listener setup was cancelled".into());
                    }
                    let remaining =
                        acknowledgement_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(
                            "fork listener did not acknowledge setup within 5 seconds".into()
                        );
                    }
                    match receiver.recv_timeout(remaining.min(Duration::from_millis(50))) {
                        Ok(result) => break result?,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err("fork listener acknowledgement channel closed".into());
                        }
                    }
                };
                super::diagnostic_stage("fork_script", Some(process.pid()), "script_acknowledged");
                if permanent {
                    if !prepare || exec_action.is_some() {
                        return Err("temporary fork listener requested permanent lifetime".into());
                    }
                    frida_sys::frida_script_eternalize_sync(
                        pointer.as_ptr(),
                        cancellable,
                        &mut error,
                    );
                    if !error.is_null() {
                        return Err(take_error(error));
                    }
                    script.permanent = true;
                }
                Ok(())
            })();
            let unload = script.unload_checked();
            let result = match (operation, unload) {
                (result, Ok(())) => result,
                (Ok(()), Err(unload)) => Err(unload),
                (Err(operation), Err(unload)) => Err(format!("{operation}; {unload}")),
            };
            if prepare {
                if result.is_err() && script.unloaded {
                    self.unowned_fork_listener_abort.insert(process);
                } else {
                    self.unowned_fork_listener_abort.remove(&process);
                }
            } else if abort_arm && result.is_ok() {
                self.unowned_fork_listener_abort.remove(&process);
            }
            result
        }
    }
}

impl FridaCore {
    pub fn abort_fork_listener(&self, process: Process, runtime: &Path) -> Result<(), String> {
        let runtime = runtime.to_path_buf();
        self.cleanup_request(
            CleanupKey::AbortForkListener(process.pid(), runtime.clone()),
            |reply| Command::AbortForkListener {
                process,
                runtime,
                reply,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_source_has_a_concrete_deadline_for_timed_and_untimed_requests() {
        let timed = arm_source(Some(42));
        assert!(!timed.contains("__HYPERHUB_DEADLINE_MILLIS__"));
        assert!(timed.contains("const deadline = uint64('42');"));

        let untimed = arm_source(None);
        assert!(!untimed.contains("__HYPERHUB_DEADLINE_MILLIS__"));
        assert!(untimed.contains(&format!("const deadline = uint64('{}');", u64::MAX)));
    }

    #[test]
    fn listener_acknowledges_lifetime_and_rejects_script_errors() {
        assert_eq!(
            parse_acknowledgement(
                br#"{"type":"send","payload":{"hyperhubForkListener":true,"permanent":false}}"#
            ),
            Some(Ok(false))
        );
        assert_eq!(
            parse_acknowledgement(
                br#"{"type":"send","payload":{"hyperhubForkListener":true,"permanent":true}}"#
            ),
            Some(Ok(true))
        );
        assert!(
            parse_acknowledgement(br#"{"type":"error","description":"missing export"}"#)
                .unwrap()
                .unwrap_err()
                .contains("missing export")
        );
        assert!(parse_acknowledgement(
            br#"{"type":"send","payload":{"hyperhubForkListener":true}}"#
        )
        .unwrap()
        .is_err());
        assert_eq!(
            parse_acknowledgement(br#"{"type":"send","payload":"unrelated"}"#),
            None
        );
    }
}
