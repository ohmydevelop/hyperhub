use std::path::{Path, PathBuf};

#[derive(Debug,Clone,PartialEq,Eq,Hash)]
pub struct ProcessIdentity { pub pid:u32, pub start_time:u64 }

#[derive(Debug)]
pub enum PlatformError { Unsupported(String), Io(std::io::Error) }
impl std::fmt::Display for PlatformError { fn fmt(&self,f:&mut std::fmt::Formatter)->std::fmt::Result { match self { Self::Unsupported(v)=>write!(f,"unsupported platform: {v}"), Self::Io(v)=>write!(f,"platform operation failed: {v}") } } }
impl std::error::Error for PlatformError {}
impl From<std::io::Error> for PlatformError { fn from(v:std::io::Error)->Self{Self::Io(v)} }

pub trait ProcessInspector { fn current_executable(&self)->Result<PathBuf,PlatformError>; fn process_executable(&self,pid:u32)->Result<PathBuf,PlatformError>; fn process_identity(&self,pid:u32)->Result<ProcessIdentity,PlatformError>; }

pub trait AgentLauncher { fn launch_injected(&self,target:&Path,args:&[std::ffi::OsString],env:&[(std::ffi::OsString,std::ffi::OsString)])->Result<i32,PlatformError>; fn launch_plain(&self,target:&Path,args:&[std::ffi::OsString],env:&[(std::ffi::OsString,std::ffi::OsString)])->Result<i32,PlatformError>; }
