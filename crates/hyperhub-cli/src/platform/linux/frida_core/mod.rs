mod child_gating;
mod context;
mod injector;

pub(super) const FRIDA_CORE_VERSION: &str = "17.17.0";

use std::ffi::CStr;
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};

pub use context::{Process, Stdio};

#[derive(Clone)]
pub struct FridaCore {
    inner: Arc<Inner>,
}

struct Inner {
    sender: Sender<Command>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
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
        reply: Reply<u32>,
    },
    EnableChildGating {
        process: Process,
        reply: Reply<()>,
    },
    AdoptForkChild {
        process: Process,
        reply: Reply<()>,
    },
    PendingChildren {
        reply: Reply<Vec<PendingChild>>,
    },
    Resume {
        process: Process,
        reply: Reply<()>,
    },
    Shutdown,
}

type Reply<T> = Sender<Result<T, String>>;

impl FridaCore {
    pub fn new() -> Result<Self, String> {
        let (sender, receiver) = mpsc::channel();
        let (init_sender, init_receiver) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("hyperhub-frida-core".into())
            .spawn(move || match context::Context::new() {
                Ok(mut context) => {
                    let _ = init_sender.send(Ok(()));
                    while let Ok(command) = receiver.recv() {
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
                                reply,
                            } => {
                                let _ = reply.send(context.inject(
                                    process,
                                    &library,
                                    &entrypoint,
                                    &data,
                                ));
                            }
                            Command::EnableChildGating { process, reply } => {
                                let _ = reply.send(context.enable_child_gating(process));
                            }
                            Command::AdoptForkChild { process, reply } => {
                                let _ = reply.send(context.adopt_fork_child(process));
                            }
                            Command::PendingChildren { reply } => {
                                let _ = reply.send(context.pending_children());
                            }
                            Command::Resume { process, reply } => {
                                let _ = reply.send(context.resume(process));
                            }
                            Command::Shutdown => break,
                        }
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
        });
        init_receiver
            .recv()
            .map_err(|_| "Frida Core owner thread exited during initialization".to_string())??;
        Ok(Self { inner })
    }

    fn request<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> Result<T, String> {
        let (reply, receiver) = mpsc::channel();
        self.inner
            .sender
            .send(command(reply))
            .map_err(|_| "Frida Core owner thread is unavailable".to_string())?;
        receiver
            .recv()
            .map_err(|_| "Frida Core owner thread dropped the response".to_string())?
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Shutdown);
        if let Ok(mut thread) = self.thread.lock() {
            if let Some(thread) = thread.take() {
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

    #[test]
    fn maps_all_known_child_origins() {
        assert_eq!(ChildOrigin::from_raw(0), ChildOrigin::Fork);
        assert_eq!(ChildOrigin::from_raw(1), ChildOrigin::Exec);
        assert_eq!(ChildOrigin::from_raw(2), ChildOrigin::Spawn);
        assert_eq!(ChildOrigin::from_raw(99), ChildOrigin::Unknown(99));
    }

    #[test]
    fn null_error_has_stable_fallback_message() {
        assert_eq!(
            unsafe { take_error(std::ptr::null_mut()) },
            "unknown Frida Core error"
        );
    }
}
