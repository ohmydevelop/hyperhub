use super::{should_try_device_fallback, take_error, Command, FridaCore};
use crate::platform::linux::frida_core::{context::Context, Process};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

impl Context {
    pub(super) fn inject(
        &mut self,
        process: Process,
        library: &Path,
        entrypoint: &str,
        data: &[u8],
    ) -> Result<u32, String> {
        let library = CString::new(library.as_os_str().as_bytes())
            .map_err(|_| "library path contains NUL".to_string())?;
        let entrypoint =
            CString::new(entrypoint).map_err(|_| "entrypoint contains NUL".to_string())?;
        let data = CString::new(data).map_err(|_| "injection data contains NUL".to_string())?;
        unsafe {
            let mut error = std::ptr::null_mut();
            let id = frida_sys::frida_injector_inject_library_file_sync(
                self.injector.as_ptr(),
                process.pid() as u32,
                library.as_ptr(),
                entrypoint.as_ptr(),
                data.as_ptr(),
                std::ptr::null_mut(),
                &mut error,
            );
            if error.is_null() {
                return Ok(id);
            }
            let fallback = should_try_device_fallback(error);
            let first = take_error(error);
            if !fallback {
                return Err(first);
            }
            let mut fallback_error = std::ptr::null_mut();
            let id = frida_sys::frida_device_inject_library_file_sync(
                self.device.as_ptr(),
                process.pid() as u32,
                library.as_ptr(),
                entrypoint.as_ptr(),
                data.as_ptr(),
                std::ptr::null_mut(),
                &mut fallback_error,
            );
            if fallback_error.is_null() {
                Ok(id)
            } else {
                Err(format!(
                    "{first}; device fallback: {}",
                    take_error(fallback_error)
                ))
            }
        }
    }
}

impl FridaCore {
    pub fn inject(
        &self,
        process: Process,
        library: &Path,
        entrypoint: &str,
        data: &CString,
    ) -> Result<u32, String> {
        self.request(|reply| Command::Inject {
            process,
            library: library.to_owned(),
            entrypoint: entrypoint.to_owned(),
            data: data.as_bytes().to_vec(),
            reply,
        })
    }
}
