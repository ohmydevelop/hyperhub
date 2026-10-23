//! Fork callbacks must use Core's Gum instance, which also owns child recovery.
//! The permanent early listener precedes Core's listener. The late listener is
//! installed once after Core. An attached child session keeps Core's temporary
//! child gating alive, so inherited listeners retain their order across fork.
use super::{child_gating, context::Context, take_error, unref, Command, FridaCore, Process};
use std::ffi::{c_void, CStr, CString};
use std::path::Path;
use std::ptr::NonNull;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

const RESIDENT: &str = r#"
// Embedded Linux Agents are sealed memfds. A filesystem pathname comparison
// cannot identify their module; require the unique complete resident ABI.
const names = ['hyperhub_fork_listener_is_prepared',
  'hyperhub_fork_listener_mark_prepared', 'hyperhub_fork_listener_is_armed',
  'hyperhub_fork_listener_mark_armed', 'hyperhub_fork_listener_epoch',
  'hyperhub_fork_listener_confirm_rearm', 'hyperhub_fork_recovery_begin',
  'hyperhub_fork_return_gate', 'frida_fork_publish_main'];
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
if (call('hyperhub_fork_listener_is_prepared', 'uint')() === 0) {
  const fork = Module.getGlobalExportByName('fork');
  const early = address('hyperhub_fork_recovery_begin');
  const late = address('hyperhub_fork_return_gate');
  const confirm = call('hyperhub_fork_listener_confirm_rearm', 'uint');
  let listener = null;
  Interceptor.attach(fork, { onLeave: early });
  Interceptor.attach(address('hyperhub_fork_listener_mark_armed'), {
    onEnter() {
      if (listener === null) {
        listener = Interceptor.attach(fork, { onLeave: late });
        Interceptor.flush();
      }
      confirm();
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
const epoch = call('hyperhub_fork_listener_epoch', 'uint');
const before = epoch();
// Cooperative scheduling permits the permanent script's mark callback to run.
call('hyperhub_fork_listener_mark_armed')();
if (epoch() !== ((before + 1) >>> 0) ||
    call('hyperhub_fork_listener_is_armed', 'uint')() !== 1)
  throw new Error('resident fork listener did not acknowledge rearm');
send({ hyperhubForkListener: true, permanent: false });
"#;

impl FridaCore {
    pub fn prepare_fork_listener(&self, process: Process, runtime: &Path) -> Result<(), String> {
        self.request(|reply| Command::ForkListener {
            process,
            runtime: runtime.into(),
            prepare: true,
            reply,
        })
    }

    pub fn arm_fork_listener(&self, process: Process, runtime: &Path) -> Result<(), String> {
        self.request(|reply| Command::ForkListener {
            process,
            runtime: runtime.into(),
            prepare: false,
            reply,
        })
    }
}

struct Session(NonNull<frida_sys::_FridaSession>);
impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            frida_sys::frida_session_detach_sync(
                self.0.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            unref(self.0.as_ptr().cast());
        }
    }
}

struct Script {
    pointer: NonNull<frida_sys::_FridaScript>,
    handler: frida_sys::gulong,
    permanent: bool,
}
impl Drop for Script {
    fn drop(&mut self) {
        unsafe {
            frida_sys::_frida_g_signal_handler_disconnect(
                self.pointer.as_ptr().cast(),
                self.handler,
            );
            if !self.permanent {
                frida_sys::frida_script_unload_sync(
                    self.pointer.as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
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
    ) -> Result<(), String> {
        // The launcher verifies this exact module before injection. Keep the
        // sealed memfd openable; do not resolve its intentionally unnamed link.
        std::fs::metadata(runtime)
            .map_err(|error| format!("cannot inspect resident Agent module: {error}"))?;
        let source = CString::new(format!("{RESIDENT}{}", if prepare { PREPARE } else { ARM }))
            .map_err(|_| "fork listener script contains NUL")?;
        unsafe {
            let session = Session(child_gating::attach(self.device.as_ptr(), process)?);
            let mut error = std::ptr::null_mut();
            let raw = frida_sys::frida_session_create_script_sync(
                session.0.as_ptr(),
                source.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut error,
            );
            if !error.is_null() {
                return Err(take_error(error));
            }
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
            };
            frida_sys::frida_script_load_sync(pointer.as_ptr(), std::ptr::null_mut(), &mut error);
            if !error.is_null() {
                return Err(take_error(error));
            }
            let permanent = receiver
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| {
                    "fork listener did not acknowledge setup within 5 seconds".to_string()
                })??;
            if permanent {
                if !prepare {
                    return Err("temporary fork listener requested permanent lifetime".into());
                }
                frida_sys::frida_script_eternalize_sync(
                    pointer.as_ptr(),
                    std::ptr::null_mut(),
                    &mut error,
                );
                if !error.is_null() {
                    return Err(take_error(error));
                }
                script.permanent = true;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
