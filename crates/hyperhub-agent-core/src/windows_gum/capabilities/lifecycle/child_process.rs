use crate::hook_runtime::{
    AgentHookPlugin, CallbackCategory, HookCallbackResult, HookDecision, HookError,
};
use crate::windows_gum::runtime::{
    ChildProcessContext, NativeChildProcessContext, PluginRegistrar, ProcessCreateContext,
};
use crate::windows_gum::THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
use std::ptr::null_mut;
use std::sync::Arc;
use windows_sys::Win32::Foundation::{CloseHandle, SetLastError, ERROR_DLL_INIT_FAILED};
use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT};

struct ChildProcessPlugin;

impl AgentHookPlugin for ChildProcessPlugin {
    fn id(&self) -> &'static str {
        "child-process"
    }
}

fn process_decision(executable: Option<&str>) -> crate::ProcessHookDecision {
    let Some(executable) = executable else {
        return crate::ProcessHookDecision {
            hook: true,
            rule_id: None,
            source: "fallback".into(),
            version: 0,
        };
    };
    let executable = normalize_executable_path(executable);
    let endpoint = std::env::var("HYPERHUB_CONTROL_ENDPOINT").ok();
    let session_id = std::env::var("HYPERHUB_SESSION_ID").ok();
    let token = std::env::var("HYPERHUB_SESSION_TOKEN").ok();
    match (endpoint, session_id, token) {
        (Some(endpoint), Some(session_id), Some(token)) => {
            crate::control::decide_process_hook(&endpoint, &session_id, &token, &executable)
        }
        _ => crate::ProcessHookDecision {
            hook: true,
            rule_id: None,
            source: "fallback".into(),
            version: 0,
        },
    }
}

fn normalize_executable_path(executable: &str) -> String {
    let path = std::path::PathBuf::from(executable);
    let resolved = if path.is_absolute() {
        std::fs::canonicalize(&path).unwrap_or(path)
    } else if path.components().count() > 1 {
        std::env::current_dir()
            .map(|current| current.join(&path))
            .ok()
            .and_then(|path| std::fs::canonicalize(&path).ok().or(Some(path)))
            .unwrap_or(path)
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join(&path))
            .find(|candidate| candidate.is_file())
            .and_then(|path| std::fs::canonicalize(&path).ok().or(Some(path)))
            .unwrap_or(path)
    };
    resolved
        .to_string_lossy()
        .trim_start_matches(r"\?")
        .to_owned()
}

pub(crate) fn register(registrar: &mut PluginRegistrar) -> Result<(), HookError> {
    let plugin = Arc::new(ChildProcessPlugin);
    let plugin_id = plugin.id();

    registrar.process_create_before(
        plugin_id,
        CallbackCategory::Control,
        |context| match context {
            ProcessCreateContext::Win32(context) => {
                let decision = process_decision(context.executable.as_deref());
                context.should_hook = decision.hook;
                context.policy_version = decision.version;
                context.rule_id = decision.rule_id;
                context.decision_source = decision.source;
                prepare_win32_child(context)
            }
            ProcessCreateContext::Native(context) => {
                let decision = process_decision(context.executable.as_deref());
                context.should_hook = decision.hook;
                context.policy_version = decision.version;
                context.rule_id = decision.rule_id;
                context.decision_source = decision.source;
                if context.should_hook {
                    context.effective_thread_flags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
                }
                Ok(HookDecision::Continue)
            }
        },
    );
    registrar.process_create_after(plugin_id, CallbackCategory::Control, |context, result| {
        match context {
            ProcessCreateContext::Win32(context) => finish_win32_child(context, result),
            ProcessCreateContext::Native(context) => finish_native_child(context, result),
        }
    });

    registrar.retain_plugin(plugin)
}

fn prepare_win32_child(context: &mut ChildProcessContext) -> HookCallbackResult<i32> {
    if !context.should_hook {
        return Ok(HookDecision::Continue);
    }
    let event_name = super::windows::child_event_name();
    let Some(ready_event) = (unsafe { super::windows::create_child_event(&event_name) }) else {
        return if super::windows::observe_child_failures() {
            Ok(HookDecision::Continue)
        } else {
            unsafe { SetLastError(ERROR_DLL_INIT_FAILED) };
            Ok(HookDecision::Deny(0))
        };
    };
    let block = match unsafe {
        super::windows::build_child_environment(
            context.environment,
            context.creation_flags,
            &event_name,
        )
    } {
        Ok(block) => block,
        Err(()) => {
            unsafe { CloseHandle(ready_event) };
            return if super::windows::observe_child_failures() {
                Ok(HookDecision::Continue)
            } else {
                unsafe { SetLastError(ERROR_DLL_INIT_FAILED) };
                Ok(HookDecision::Deny(0))
            };
        }
    };
    context.creation_flags |= CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    context.environment_block = Some(block);
    context.environment = context
        .environment_block
        .as_ref()
        .expect("environment block was stored")
        .as_ptr()
        .cast();
    context.ready_event = ready_event;
    context.prepared = true;
    Ok(HookDecision::Continue)
}

fn finish_win32_child(
    context: &mut ChildProcessContext,
    result: &mut i32,
) -> HookCallbackResult<i32> {
    context.result = *result;
    if !context.should_hook || !context.prepared {
        return Ok(HookDecision::Continue);
    }
    if *result == 0 {
        if !context.ready_event.is_null() {
            unsafe { CloseHandle(context.ready_event) };
            context.ready_event = null_mut();
        }
        return Ok(HookDecision::Continue);
    }
    let ready_event = context.ready_event;
    context.ready_event = null_mut();
    let result = unsafe {
        super::windows::finish_child_process(
            context.information,
            ready_event,
            context.caller_requested_suspended,
            context.policy_version,
            context.rule_id.as_deref(),
            &context.decision_source,
            context.executable.as_deref(),
        )
    };
    Ok(HookDecision::Return(result))
}

fn finish_native_child(
    context: &mut NativeChildProcessContext,
    result: &mut i32,
) -> HookCallbackResult<i32> {
    context.result = *result;
    if !context.should_hook
        || *result < 0
        || unsafe { (*context.process_handle).is_null() }
        || unsafe { (*context.thread_handle).is_null() }
    {
        return Ok(HookDecision::Continue);
    }
    let status = unsafe {
        super::windows::finish_native_child_process(
            context.process_handle,
            context.thread_handle,
            context.original_thread_flags,
            *result,
            context.policy_version,
            context.rule_id.as_deref(),
            &context.decision_source,
            context.executable.as_deref(),
        )
    };
    Ok(HookDecision::Return(status))
}
