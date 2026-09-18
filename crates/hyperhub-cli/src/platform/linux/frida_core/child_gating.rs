use super::{take_error, unref, ChildOrigin, Command, FridaCore, PendingChild, Process};
use crate::platform::linux::frida_core::context::Context;
use std::ffi::CStr;
use std::ptr::NonNull;

impl Context {
    pub(super) fn enable_child_gating(&mut self, process: Process) -> Result<(), String> {
        unsafe {
            let session = attach(self.device.as_ptr(), process)?;
            let mut error = std::ptr::null_mut();
            frida_sys::frida_session_enable_child_gating_sync(
                session.as_ptr(),
                std::ptr::null_mut(),
                &mut error,
            );
            if error.is_null() {
                self.child_sessions.push(session);
                Ok(())
            } else {
                unref(session.as_ptr().cast());
                Err(take_error(error))
            }
        }
    }

    pub(super) fn adopt_fork_child(&mut self, process: Process) -> Result<(), String> {
        unsafe {
            let session = attach(self.device.as_ptr(), process)?;
            let mut error = std::ptr::null_mut();
            frida_sys::frida_device_resume_sync(
                self.device.as_ptr(),
                process.pid() as u32,
                std::ptr::null_mut(),
                &mut error,
            );
            if error.is_null() {
                self.child_sessions.push(session);
                Ok(())
            } else {
                unref(session.as_ptr().cast());
                Err(take_error(error))
            }
        }
    }

    pub(super) fn pending_children(&mut self) -> Result<Vec<PendingChild>, String> {
        unsafe {
            let mut error = std::ptr::null_mut();
            let list = frida_sys::frida_device_enumerate_pending_children_sync(
                self.device.as_ptr(),
                std::ptr::null_mut(),
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
        self.request(|reply| Command::EnableChildGating { process, reply })
    }

    pub fn adopt_fork_child(&self, process: Process) -> Result<(), String> {
        self.request(|reply| Command::AdoptForkChild { process, reply })
    }

    pub fn pending_children(&self) -> Result<Vec<PendingChild>, String> {
        self.request(|reply| Command::PendingChildren { reply })
    }
}

fn is_skip_agent_entry(value: &CStr) -> bool {
    value.to_bytes() == b"HYPERHUB_SKIP_AGENT=1"
}

unsafe fn attach(
    device: *mut frida_sys::_FridaDevice,
    process: Process,
) -> Result<NonNull<frida_sys::_FridaSession>, String> {
    let options = frida_sys::frida_session_options_new();
    let options = NonNull::new(options).ok_or("frida_session_options_new returned null")?;
    let mut error = std::ptr::null_mut();
    let session = frida_sys::frida_device_attach_sync(
        device,
        process.pid() as u32,
        options.as_ptr(),
        std::ptr::null_mut(),
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
