use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED, PROCESS_INFORMATION};

use crate::windows_gum::CloseHandle;

pub(in crate::windows_gum) struct ChildProcessContext {
    pub(in crate::windows_gum) creation_flags: u32,
    pub(in crate::windows_gum) environment: *const c_void,
    pub(in crate::windows_gum) information: *mut PROCESS_INFORMATION,
    pub(in crate::windows_gum) caller_requested_suspended: bool,
    pub(in crate::windows_gum) environment_block: Option<Vec<u16>>,
    pub(in crate::windows_gum) ready_event: HANDLE,
    pub(in crate::windows_gum) prepared: bool,
    pub(in crate::windows_gum) result: i32,
    pub(in crate::windows_gum) executable: Option<String>,
    pub(in crate::windows_gum) command_line: Option<String>,
    pub(in crate::windows_gum) should_hook: bool,
    pub(in crate::windows_gum) policy_version: u64,
    pub(in crate::windows_gum) rule_id: Option<String>,
    pub(in crate::windows_gum) decision_source: String,
}

impl ChildProcessContext {
    pub(in crate::windows_gum) fn new(
        creation_flags: u32,
        environment: *const c_void,
        information: *mut PROCESS_INFORMATION,
        executable: Option<String>,
        command_line: Option<String>,
    ) -> Self {
        Self {
            creation_flags,
            environment,
            information,
            caller_requested_suspended: creation_flags & CREATE_SUSPENDED != 0,
            environment_block: None,
            ready_event: null_mut(),
            prepared: false,
            result: 0,
            executable,
            command_line,
            should_hook: true,
            policy_version: 0,
            rule_id: None,
            decision_source: "unknown".into(),
        }
    }
}

impl Drop for ChildProcessContext {
    fn drop(&mut self) {
        if !self.ready_event.is_null() {
            unsafe { CloseHandle(self.ready_event) };
            self.ready_event = null_mut();
        }
    }
}

pub(in crate::windows_gum) struct NativeChildProcessContext {
    pub(in crate::windows_gum) process_handle: *mut HANDLE,
    pub(in crate::windows_gum) thread_handle: *mut HANDLE,
    pub(in crate::windows_gum) original_thread_flags: u32,
    pub(in crate::windows_gum) effective_thread_flags: u32,
    pub(in crate::windows_gum) result: i32,
    pub(in crate::windows_gum) executable: Option<String>,
    pub(in crate::windows_gum) command_line: Option<String>,
    pub(in crate::windows_gum) should_hook: bool,
    pub(in crate::windows_gum) policy_version: u64,
    pub(in crate::windows_gum) rule_id: Option<String>,
    pub(in crate::windows_gum) decision_source: String,
}

pub(in crate::windows_gum) enum ProcessCreateContext {
    Win32(ChildProcessContext),
    Native(NativeChildProcessContext),
}
