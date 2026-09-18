#![allow(dead_code)]
use std::path::PathBuf;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookBackend {
    Interceptor,
    ElfInterposition,
    Unsupported,
}
pub(crate) trait NativeHookBackend {
    fn backend(&self) -> HookBackend;
    fn install(&self) -> Result<(), String>;
}
pub(crate) trait AgentInjector {
    fn inject(&self, _process: ProcessIdentity) -> Result<(), String>;
    fn attach(&self, _process: ProcessIdentity) -> Result<(), String> {
        Err("running process attach is not implemented".into())
    }
}
pub(crate) trait ProcessInspector {
    fn current_executable(&self) -> Result<PathBuf, String>;
    fn process_executable(&self, pid: u32) -> Result<PathBuf, String>;
}
