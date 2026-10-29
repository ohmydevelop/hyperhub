use super::{
    take_error, unref, ChildOrigin, CleanupKey, Command, FridaCore, FridaRequestError,
    PendingChild, Process,
};
use crate::platform::linux::frida_core::context::Context;
use std::ffi::CStr;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;

impl Context {
    fn retire_detached_sessions(&mut self) {
        self.child_sessions.retain(|(_, session)| unsafe {
            if frida_sys::frida_session_is_detached(session.as_ptr()) == 0 {
                true
            } else {
                unref(session.as_ptr().cast());
                false
            }
        });
    }

    pub(super) fn enable_child_gating(
        &mut self,
        process: Process,
        cancellation: Option<&super::Cancellable>,
    ) -> Result<(), String> {
        self.retire_detached_sessions();
        if self.child_sessions.iter().any(|(pid, _)| *pid == process) {
            return Ok(());
        }
        unsafe {
            let session = attach(self.device.as_ptr(), process, cancellation)?;
            let cancellable = cancellation
                .map(super::Cancellable::as_ptr)
                .unwrap_or(std::ptr::null_mut());
            let mut error = std::ptr::null_mut();
            frida_sys::frida_session_enable_child_gating_sync(
                session.as_ptr(),
                cancellable,
                &mut error,
            );
            if error.is_null() {
                self.child_sessions.push((process, session));
                Ok(())
            } else {
                unref(session.as_ptr().cast());
                Err(take_error(error))
            }
        }
    }

    pub(super) fn disable_child_gating(
        &mut self,
        process: Process,
        cancellation: Option<&super::Cancellable>,
    ) -> Result<(), String> {
        self.retire_detached_sessions();
        let Some(index) = self
            .child_sessions
            .iter()
            .position(|(pid, _)| *pid == process)
        else {
            return Ok(());
        };
        let (_, session) = self.child_sessions[index];
        unsafe {
            let cancellable = cancellation
                .map(super::Cancellable::as_ptr)
                .unwrap_or(std::ptr::null_mut());
            super::diagnostic_stage("disable_child_gating", Some(process.pid()), "disable_begin");
            let mut error = std::ptr::null_mut();
            frida_sys::frida_session_disable_child_gating_sync(
                session.as_ptr(),
                cancellable,
                &mut error,
            );
            if !error.is_null() {
                return Err(take_error(error));
            }
            super::diagnostic_stage(
                "disable_child_gating",
                Some(process.pid()),
                "disable_complete",
            );
            let mut detach_error = std::ptr::null_mut();
            super::diagnostic_stage("disable_child_gating", Some(process.pid()), "detach_begin");
            frida_sys::frida_session_detach_sync(session.as_ptr(), cancellable, &mut detach_error);
            if !detach_error.is_null() {
                return Err(take_error(detach_error));
            }
            super::diagnostic_stage(
                "disable_child_gating",
                Some(process.pid()),
                "detach_complete",
            );
            self.child_sessions.remove(index);
            unref(session.as_ptr().cast());
        }
        Ok(())
    }

    pub(super) fn pending_children(
        &mut self,
        cancellation: Option<&super::Cancellable>,
    ) -> Result<Vec<PendingChild>, String> {
        self.retire_detached_sessions();
        unsafe {
            let cancellable = cancellation
                .map(super::Cancellable::as_ptr)
                .unwrap_or(std::ptr::null_mut());
            let mut error = std::ptr::null_mut();
            let list = frida_sys::frida_device_enumerate_pending_children_sync(
                self.device.as_ptr(),
                cancellable,
                &mut error,
            );
            if !error.is_null() {
                return Err(take_error(error));
            }
            let list = NonNull::new(list)
                .ok_or("frida_device_enumerate_pending_children_sync returned null")?;
            let count = frida_sys::frida_child_list_size(list.as_ptr()).max(0) as usize;
            let mut children = Vec::with_capacity(count);
            for index in 0..count {
                let child = frida_sys::frida_child_list_get(list.as_ptr(), index as i32);
                if child.is_null() {
                    continue;
                }
                let mut env_count = 0;
                let envp = frida_sys::frida_child_get_envp(child, &mut env_count);
                let mut skip_agent = false;
                if !envp.is_null() {
                    for index in 0..env_count.max(0) as usize {
                        let item = *envp.add(index);
                        if !item.is_null() && is_skip_agent_entry(CStr::from_ptr(item)) {
                            skip_agent = true;
                            break;
                        }
                    }
                    frida_sys::_frida_g_strfreev(envp);
                }
                children.push(PendingChild {
                    process: Process(frida_sys::frida_child_get_pid(child) as i32),
                    parent_pid: frida_sys::frida_child_get_parent_pid(child) as i32,
                    origin: ChildOrigin::from_raw(frida_sys::frida_child_get_origin(child) as u32),
                    skip_agent,
                });
            }
            unref(list.as_ptr().cast());
            Ok(children)
        }
    }
}

impl FridaCore {
    pub fn enable_child_gating(&self, process: Process) -> Result<(), String> {
        self.request(|reply| Command::EnableChildGating {
            process,
            cancellation: None,
            reply,
        })
    }

    pub fn disable_child_gating(&self, process: Process) -> Result<(), String> {
        self.request(|reply| Command::DisableChildGating {
            process,
            cancellation: None,
            reply,
        })
    }

    pub fn pending_children(&self) -> Result<Vec<PendingChild>, String> {
        self.request(|reply| Command::PendingChildren {
            cancellation: None,
            reply,
        })
    }

    pub fn enable_child_gating_with_timeout(
        &self,
        process: Process,
        timeout: Duration,
    ) -> Result<(), FridaRequestError> {
        let cancellation = Arc::new(super::Cancellable::new()?);
        let command_cancellation = cancellation.clone();
        let timeout_cancellation = cancellation.clone();
        self.request_with_timeout(
            timeout,
            move || timeout_cancellation.cancel(),
            move |reply| Command::EnableChildGating {
                process,
                cancellation: Some(command_cancellation),
                reply,
            },
        )
    }

    pub fn disable_child_gating_with_timeout(
        &self,
        process: Process,
        timeout: Duration,
    ) -> Result<(), FridaRequestError> {
        let cancellation = Arc::new(super::Cancellable::new()?);
        let command_cancellation = cancellation.clone();
        let timeout_cancellation = cancellation.clone();
        self.request_with_timeout(
            timeout,
            move || timeout_cancellation.cancel(),
            move |reply| Command::DisableChildGating {
                process,
                cancellation: Some(command_cancellation),
                reply,
            },
        )
    }

    pub fn pending_children_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Vec<PendingChild>, FridaRequestError> {
        let cancellation = Arc::new(super::Cancellable::new()?);
        let command_cancellation = cancellation.clone();
        let timeout_cancellation = cancellation.clone();
        self.request_with_timeout(
            timeout,
            move || timeout_cancellation.cancel(),
            move |reply| Command::PendingChildren {
                cancellation: Some(command_cancellation),
                reply,
            },
        )
    }

    pub fn disable_child_gating_cleanup(&self, process: Process) -> Result<(), String> {
        self.cleanup_request(CleanupKey::DisableChildGating(process.pid()), |reply| {
            Command::CleanupDisableChildGating { process, reply }
        })
    }

    pub fn pending_children_cleanup(&self) -> Result<Vec<PendingChild>, String> {
        self.cleanup_request(CleanupKey::PendingChildren, |reply| {
            Command::CleanupPendingChildren { reply }
        })
    }
}

fn is_skip_agent_entry(value: &CStr) -> bool {
    value.to_bytes() == b"HYPERHUB_SKIP_AGENT=1"
}

pub(super) unsafe fn attach(
    device: *mut frida_sys::_FridaDevice,
    process: Process,
    cancellation: Option<&super::Cancellable>,
) -> Result<NonNull<frida_sys::_FridaSession>, String> {
    let options = frida_sys::frida_session_options_new();
    let options = NonNull::new(options).ok_or("frida_session_options_new returned null")?;
    // Core is our injector and fork/exec observer, not an application exit
    // barrier. A resumed native-only child can enter libc _exit while its
    // inherited Core main context is retiring; ExitMonitor then waits for an
    // async preparation that cannot finish. Preserve the application's exit
    // operation. HyperHub observes its lifetime through the OS/owned launcher,
    // independently of Core's optional user-script pre-exit flush monitor.
    frida_sys::frida_session_options_set_exit_monitor(options.as_ptr(), 0);
    let mut error = std::ptr::null_mut();
    let cancellable = cancellation
        .map(super::Cancellable::as_ptr)
        .unwrap_or(std::ptr::null_mut());
    let session = frida_sys::frida_device_attach_sync(
        device,
        process.pid() as u32,
        options.as_ptr(),
        cancellable,
        &mut error,
    );
    unref(options.as_ptr().cast());
    if error.is_null() {
        NonNull::new(session).ok_or("frida_device_attach_sync returned null".into())
    } else {
        Err(take_error(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_the_explicit_skip_marker() {
        assert!(is_skip_agent_entry(c"HYPERHUB_SKIP_AGENT=1"));
        assert!(!is_skip_agent_entry(c"HYPERHUB_SKIP_AGENT=0"));
        assert!(!is_skip_agent_entry(c"OTHER=1"));
    }
}
