//! Acquire an Engine for the first time on a native thread while the calling
//! thread owns the ELF loader lock. No HyperHub process or credentials required.
#[cfg(target_os = "linux")]
mod linux {
    use hyperhub_runtime::{Engine, Lease, Manifest, Runtime, Settings};
    use std::sync::{
        atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
        Arc, Mutex,
    };

    struct Initial(Manifest);
    impl Engine for Initial {
        fn manifest(&self) -> &Manifest {
            &self.0
        }
        fn health(&self) -> bool {
            true
        }
        fn invoke(&self, _: &Lease, _: u32, _: &[u8], _: &mut [u8]) -> Result<usize, i32> {
            Ok(0)
        }
    }
    struct Context {
        runtime: Runtime,
        host: Mutex<()>,
        entered: AtomicBool,
        thread: AtomicUsize,
    }
    static CONTEXT: AtomicPtr<Context> = AtomicPtr::new(std::ptr::null_mut());
    extern "C" fn first_acquisition(pointer: *mut libc::c_void) -> *mut libc::c_void {
        let context = unsafe { &*pointer.cast::<Context>() };
        let _host = context.host.lock().unwrap();
        context.entered.store(true, Ordering::Release);
        let lease = context.runtime.acquire();
        assert_eq!(lease.version(), "initial");
        std::ptr::null_mut()
    }
    unsafe extern "C" fn under_loader_lock() {
        let pointer = CONTEXT.load(Ordering::Acquire).cast::<libc::c_void>();
        let context = &*pointer.cast::<Context>();
        let mut thread = std::mem::zeroed();
        assert_eq!(
            libc::pthread_create(&mut thread, std::ptr::null(), first_acquisition, pointer),
            0
        );
        context.thread.store(thread as usize, Ordering::Release);
        while !context.entered.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        // Reproduce the Host/loader lock order without depending on a delay or
        // a particular target application's instruction ordering.
        let _host = context.host.lock().unwrap();
    }
    pub fn run() {
        let mut context = Context {
            runtime: Runtime::new(
                Arc::new(Initial(Manifest {
                    version: "initial".into(),
                    target: "native-loader-fixture".into(),
                    abi: hyperhub_runtime::abi::ABI_V1,
                    state_schema: 1,
                    hooks: 1,
                    size: 1,
                    sha256: "00".repeat(32),
                })),
                Settings::default(),
            )
            .unwrap(),
            host: Mutex::new(()),
            entered: AtomicBool::new(false),
            thread: AtomicUsize::new(0),
        };
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("hh-runtime-loader-{}-{unique}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("constructor.c");
        let module = directory.join("constructor.so");
        std::fs::write(&source, include_str!("runtime_loader_constructor.c")).unwrap();
        assert!(std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-Werror"])
            .arg(format!(
                "-DHYPERHUB_FIXTURE_CALLBACK={}",
                under_loader_lock as *const () as usize
            ))
            .arg(&source)
            .arg("-o")
            .arg(&module)
            .status()
            .unwrap()
            .success());
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(module.as_os_str().as_bytes()).unwrap();
        CONTEXT.store(&mut context, Ordering::Release);
        unsafe {
            libc::alarm(10);
            let handle = libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            assert!(!handle.is_null());
            assert_eq!(
                libc::pthread_join(
                    context.thread.load(Ordering::Acquire) as _,
                    std::ptr::null_mut()
                ),
                0
            );
            libc::alarm(0);
            libc::dlclose(handle);
        }
        std::fs::remove_dir_all(directory).unwrap();
        println!("first Engine acquisition under loader contention completed");
    }
}
fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
}
