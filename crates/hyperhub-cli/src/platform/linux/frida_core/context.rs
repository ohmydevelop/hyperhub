use super::{take_error, unref, Command, FridaCore, FRIDA_CORE_VERSION};
use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::NonNull;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Process(pub(super) i32);

impl Process {
    pub fn pid(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Stdio {
    Inherit,
}

pub(super) struct Context {
    pub(super) manager: NonNull<frida_sys::_FridaDeviceManager>,
    pub(super) device: NonNull<frida_sys::_FridaDevice>,
    pub(super) injector: NonNull<frida_sys::_FridaInjector>,
    pub(super) child_sessions: Vec<NonNull<frida_sys::_FridaSession>>,
}

impl Context {
    pub(super) fn new() -> Result<Self, String> {
        unsafe {
            frida_sys::frida_init();
            let version = frida_sys::frida_version_string();
            let version = (!version.is_null())
                .then(|| CStr::from_ptr(version).to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into());
            if version != FRIDA_CORE_VERSION {
                frida_sys::frida_deinit();
                return Err(format!(
                    "Frida Core runtime version mismatch: expected {FRIDA_CORE_VERSION}, got {version}"
                ));
            }

            let manager = match NonNull::new(frida_sys::frida_device_manager_new()) {
                Some(manager) => manager,
                None => {
                    frida_sys::frida_deinit();
                    return Err("frida_device_manager_new returned null".into());
                }
            };
            let injector = match NonNull::new(frida_sys::frida_injector_new()) {
                Some(injector) => injector,
                None => {
                    close_manager(manager);
                    frida_sys::frida_deinit();
                    return Err("frida_injector_new returned null".into());
                }
            };
            let mut error = std::ptr::null_mut();
            let device = frida_sys::frida_device_manager_get_device_by_type_sync(
                manager.as_ptr(),
                frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL,
                0,
                std::ptr::null_mut(),
                &mut error,
            );
            if !error.is_null() {
                let message = take_error(error);
                close_injector(injector);
                close_manager(manager);
                frida_sys::frida_deinit();
                return Err(message);
            }
            let device = match NonNull::new(device) {
                Some(device) => device,
                None => {
                    close_injector(injector);
                    close_manager(manager);
                    frida_sys::frida_deinit();
                    return Err("frida_device_manager_get_device_by_type_sync returned null".into());
                }
            };
            Ok(Self {
                manager,
                device,
                injector,
                child_sessions: Vec::new(),
            })
        }
    }
}

unsafe fn close_injector(injector: NonNull<frida_sys::_FridaInjector>) {
    frida_sys::frida_injector_close_sync(
        injector.as_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    unref(injector.as_ptr().cast());
}

unsafe fn close_manager(manager: NonNull<frida_sys::_FridaDeviceManager>) {
    frida_sys::frida_device_manager_close_sync(
        manager.as_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    unref(manager.as_ptr().cast());
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            self.child_sessions
                .drain(..)
                .for_each(|session| unref(session.as_ptr().cast()));
            close_injector(self.injector);
            unref(self.device.as_ptr().cast());
            close_manager(self.manager);
            frida_sys::frida_deinit();
        }
    }
}

fn encode_argv(program: &CString, args: &[OsString]) -> Result<Vec<CString>, String> {
    std::iter::once(Ok(program.clone()))
        .chain(args.iter().map(|arg| {
            CString::new(arg.as_os_str().as_bytes())
                .map_err(|_| "argument contains NUL".to_string())
        }))
        .collect()
}

fn encode_environment(env: &[(OsString, OsString)]) -> Result<Vec<CString>, String> {
    env.iter()
        .map(|(key, value)| {
            let mut item = key.as_os_str().as_bytes().to_vec();
            item.push(b'=');
            item.extend_from_slice(value.as_os_str().as_bytes());
            CString::new(item).map_err(|_| "environment contains NUL".to_string())
        })
        .collect()
}

impl Context {
    pub(super) fn spawn(
        &mut self,
        program: &OsString,
        args: &[OsString],
        env: &[(OsString, OsString)],
        cwd: &Path,
        stdio: Stdio,
    ) -> Result<Process, String> {
        let program = CString::new(program.as_os_str().as_bytes())
            .map_err(|_| "program contains NUL".to_string())?;
        let argv = encode_argv(&program, args)?;
        let mut argv_ptrs = argv
            .iter()
            .map(|value| value.as_ptr() as *mut frida_sys::gchar)
            .collect::<Vec<_>>();
        let env = encode_environment(env)?;
        let mut env_ptrs = env
            .iter()
            .map(|value| value.as_ptr() as *mut frida_sys::gchar)
            .collect::<Vec<_>>();
        let cwd = CString::new(cwd.as_os_str().as_bytes())
            .map_err(|_| "working directory contains NUL".to_string())?;

        unsafe {
            let options = frida_sys::frida_spawn_options_new();
            let options =
                NonNull::new(options).ok_or("frida_spawn_options_new returned null".to_string())?;
            frida_sys::frida_spawn_options_set_argv(
                options.as_ptr(),
                argv_ptrs.as_mut_ptr(),
                argv_ptrs.len() as i32,
            );
            frida_sys::frida_spawn_options_set_envp(
                options.as_ptr(),
                env_ptrs.as_mut_ptr(),
                env_ptrs.len() as i32,
            );
            frida_sys::frida_spawn_options_set_cwd(options.as_ptr(), cwd.as_ptr());
            frida_sys::frida_spawn_options_set_stdio(
                options.as_ptr(),
                match stdio {
                    Stdio::Inherit => frida_sys::FridaStdio_FRIDA_STDIO_INHERIT,
                },
            );
            let mut error = std::ptr::null_mut();
            let pid = frida_sys::frida_device_spawn_sync(
                self.device.as_ptr(),
                program.as_ptr(),
                options.as_ptr(),
                std::ptr::null_mut(),
                &mut error,
            );
            unref(options.as_ptr().cast());
            if error.is_null() {
                Ok(Process(pid as i32))
            } else {
                Err(take_error(error))
            }
        }
    }

    pub(super) fn resume(&mut self, process: Process) -> Result<(), String> {
        unsafe {
            let mut error = std::ptr::null_mut();
            frida_sys::frida_device_resume_sync(
                self.device.as_ptr(),
                process.pid() as u32,
                std::ptr::null_mut(),
                &mut error,
            );
            if error.is_null() {
                Ok(())
            } else {
                Err(take_error(error))
            }
        }
    }
}

impl FridaCore {
    pub fn spawn(
        &self,
        program: &OsString,
        args: &[OsString],
        env: &[(OsString, OsString)],
        cwd: &Path,
        stdio: Stdio,
    ) -> Result<Process, String> {
        self.request(|reply| Command::Spawn {
            program: program.clone(),
            args: args.to_vec(),
            env: env.to_vec(),
            cwd: cwd.to_owned(),
            stdio,
            reply,
        })
    }

    pub fn resume(&self, process: Process) -> Result<(), String> {
        self.request(|reply| Command::Resume { process, reply })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_spawn_arguments_including_argv_zero() {
        let program = CString::new("/usr/bin/probe").unwrap();
        let values = encode_argv(&program, &["one".into(), "two words".into()]).unwrap();
        let values = values
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values, ["/usr/bin/probe", "one", "two words"]);
    }

    #[test]
    fn encodes_complete_spawn_environment() {
        let values =
            encode_environment(&[("A".into(), "1".into()), ("B".into(), "two".into())]).unwrap();
        let values = values
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values, ["A=1", "B=two"]);
    }

    #[test]
    fn rejects_nul_in_spawn_values() {
        assert!(encode_argv(&CString::new("probe").unwrap(), &[OsString::from("a\0b")]).is_err());
        assert!(encode_environment(&[("A".into(), OsString::from("a\0b"))]).is_err());
    }
}
