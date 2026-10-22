use crate::{abi, artifact::Artifact, Engine, Error, Lease, Manifest};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::sync::Arc;

/// Services execute in the resident Host; modules receive only this C trampoline.
/// Engines must not retain the temporary input/output buffers. Clone `calling`
/// before starting asynchronous work; acquiring the current generation would
/// be incorrect when a switch has already overtaken this invocation.
pub trait Host: Send + Sync {
    fn call(
        &self,
        calling: &Lease,
        operation: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, i32>;
}
struct Bridge {
    host: Arc<dyn Host>,
}
struct CallContext<'a> {
    bridge: &'a Bridge,
    calling: &'a Lease,
}

pub struct NativeEngine {
    api: abi::EngineApi,
    owner_epoch: Option<u64>,
    #[cfg(target_os = "linux")]
    fork_handle: usize,
    // Drop order: library finalizers can still access the artifact and bridge.
    _library: libloading::Library,
    artifact: Artifact,
    bridge: Option<Box<Bridge>>,
}

impl NativeEngine {
    /// # Safety
    /// The trusted module must implement the ABI contract, including thread
    /// safety, bounded health checks and no unmanaged work after a call returns.
    /// Integrity verification cannot make arbitrary native code safe. Library
    /// constructors and the entry point execute before table validation.
    pub unsafe fn load(artifact: Artifact, host: Option<Arc<dyn Host>>) -> Result<Self, Error> {
        let library = unsafe { libloading::Library::new(artifact.load_path()) }
            .map_err(|e| Error::Artifact(e.to_string()))?;
        let entry = unsafe { library.get::<abi::Entry>(abi::ENTRY_SYMBOL) }
            .map_err(|e| Error::Artifact(e.to_string()))?;
        let pointer = unsafe { entry() };
        if pointer.is_null() || !pointer.is_aligned() {
            return Err(Error::RequiresRestart);
        }
        // Check the prefix before reading the full versioned structure.
        let size = unsafe { pointer.cast::<u32>().read() };
        if size < std::mem::size_of::<abi::EngineApi>() as u32 {
            return Err(Error::RequiresRestart);
        }
        let api = unsafe { pointer.read() };
        let manifest = artifact.manifest();
        let version_hash: [u8; 32] = Sha256::digest(manifest.version.as_bytes()).into();
        if api.abi != abi::ABI_V1
            || api.abi != manifest.abi
            || api.state_schema != manifest.state_schema
            || api.hooks != manifest.hooks
            || api.version_hash != version_hash
            || api.reserved != 0
            || api.invoke.is_none()
            || api.health.is_none()
        {
            return Err(Error::RequiresRestart);
        }
        #[cfg(target_os = "linux")]
        let (library, fork_handle) = {
            let platform: libloading::os::unix::Library = library.into();
            let raw = platform.into_raw();
            (
                unsafe { libloading::os::unix::Library::from_raw(raw) }.into(),
                raw as usize,
            )
        };
        let owner_epoch = if api.state_schema == 2 && api.hooks & 0x1800 == 0x1800 {
            let mut epoch = [0u8; 8];
            let mut written = 0;
            if unsafe {
                (api.invoke.unwrap())(
                    std::ptr::null(),
                    12,
                    std::ptr::null(),
                    0,
                    epoch.as_mut_ptr(),
                    epoch.len(),
                    &mut written,
                )
            } != abi::OK
                || written != 8
            {
                return Err(Error::RequiresRestart);
            }
            Some(u64::from_le_bytes(epoch))
        } else {
            None
        };
        Ok(Self {
            api,
            owner_epoch,
            #[cfg(target_os = "linux")]
            fork_handle,
            _library: library,
            artifact,
            bridge: host.map(|host| Box::new(Bridge { host })),
        })
    }
}

impl Drop for NativeEngine {
    fn drop(&mut self) {
        if let Some(epoch) = self.owner_epoch.take() {
            let bytes = epoch.to_le_bytes();
            let mut written = 0;
            unsafe {
                (self.api.invoke.unwrap())(
                    std::ptr::null(),
                    13,
                    bytes.as_ptr(),
                    bytes.len(),
                    std::ptr::null_mut(),
                    0,
                    &mut written,
                );
            }
        }
    }
}

impl Engine for NativeEngine {
    fn manifest(&self) -> &Manifest {
        self.artifact.manifest()
    }
    fn health(&self) -> bool {
        unsafe { (self.api.health.unwrap())() == abi::OK }
    }
    #[cfg(target_os = "linux")]
    unsafe fn fork_copy(&self) -> Result<Arc<dyn Engine>, Error> {
        if self.bridge.is_some() {
            return Err(Error::RequiresRestart);
        }
        let artifact = self.artifact.duplicate_after_fork()?;
        Ok(Arc::new(unsafe { Self::load(artifact, None)? }))
    }
    #[cfg(target_os = "linux")]
    fn fork_module_key(&self) -> usize {
        self.fork_handle
    }
    #[cfg(target_os = "linux")]
    unsafe fn fork_reset(&self) -> Result<(), Error> {
        let mut written = 0;
        // Schema 2 freezes the child-reset operation at number 11. It accepts
        // no Host services, native pointers or retained Rust allocations.
        if self.api.state_schema != 2
            || unsafe {
                (self.api.invoke.unwrap())(
                    std::ptr::null(),
                    11,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &mut written,
                )
            } != abi::OK
            || written != 0
        {
            return Err(Error::RequiresRestart);
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    unsafe fn fork_release(&self) {
        unsafe {
            libc::dlclose(self.fork_handle as *mut c_void);
            self.artifact.release_after_fork();
        }
    }
    fn invoke(
        &self,
        calling: &Lease,
        operation: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, i32> {
        if !calling.belongs_to(self) {
            return Err(abi::INVALID);
        }
        let context = self
            .bridge
            .as_ref()
            .map(|bridge| CallContext { bridge, calling });
        let services = context.as_ref().map(|context| abi::HostServices {
            struct_size: std::mem::size_of::<abi::HostServices>() as u32,
            abi: abi::ABI_V1,
            context: (context as *const CallContext<'_>).cast_mut().cast(),
            call: Some(host_call),
        });
        let mut written = 0;
        let code = unsafe {
            (self.api.invoke.unwrap())(
                services.as_ref().map_or(std::ptr::null(), |s| s),
                operation,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        };
        if code != abi::OK {
            return Err(code);
        }
        if written > output.len() {
            return Err(abi::FAILED);
        }
        Ok(written)
    }
}

unsafe extern "C" fn host_call(
    context: *mut c_void,
    operation: u32,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if written.is_null() {
        return abi::INVALID;
    }
    unsafe {
        written.write(0);
    }
    if context.is_null()
        || (input.is_null() && input_len != 0)
        || (output.is_null() && capacity != 0)
        || input_len > isize::MAX as usize
        || capacity > isize::MAX as usize
    {
        return abi::INVALID;
    }
    // Valid, non-overlapping buffers and the context are guaranteed by the
    // trusted module contract; no pointer escapes this call.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let context = unsafe { &*context.cast::<CallContext<'_>>() };
        let input = if input_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(input, input_len) }
        };
        let output = if capacity == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(output, capacity) }
        };
        context
            .bridge
            .host
            .call(context.calling, operation, input, output)
    }));
    match result {
        Ok(Ok(count)) if count <= capacity => {
            unsafe {
                written.write(count);
            }
            abi::OK
        }
        Ok(Err(code)) if code != abi::OK => code,
        _ => abi::FAILED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_host_call_still_initializes_the_output_length() {
        let mut written = usize::MAX;
        let result = unsafe {
            host_call(
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut written,
            )
        };
        assert_eq!(result, abi::INVALID);
        assert_eq!(written, 0);
    }
}
