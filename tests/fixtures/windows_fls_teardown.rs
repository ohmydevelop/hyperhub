//! Real native-thread FLS callbacks perform their first or last managed IO.
//! Windows invokes these callbacks at thread exit; no DLL entry point joins a thread.
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    ConvertFiberToThread, ConvertThreadToFiber, CreateFiber, CreateThread, DeleteFiber, FlsAlloc,
    FlsFree, FlsSetValue, GetExitCodeThread, SwitchToFiber, WaitForSingleObject,
};

static COMPLETED: AtomicU32 = AtomicU32::new(0);
static FAILURES: AtomicU32 = AtomicU32::new(0);
#[derive(Clone)]
struct Case {
    path: PathBuf,
    port: u16,
    denied: bool,
    warmed: bool,
    slot: u32,
}
fn file_policy(case: &Case) {
    match std::fs::read(&case.path) {
        Ok(bytes) => {
            assert!(!case.denied, "FLS teardown bypassed the file policy");
            assert_eq!(bytes, b"fls-secret-fixture\n");
        }
        Err(error) => {
            assert!(case.denied, "native file read failed: {error}");
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        }
    }
}
unsafe extern "system" fn teardown(value: *const c_void) {
    let case = Box::from_raw(value.cast_mut().cast::<Case>());
    let result = std::panic::catch_unwind(|| {
        file_policy(&case);
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, case.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(b"fls-thread-exit-echo").unwrap();
        let mut reply = [0; 20];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"fls-thread-exit-echo");
    });
    if result.is_err() {
        FAILURES.fetch_add(1, Ordering::AcqRel);
    }
    COMPLETED.fetch_add(1, Ordering::AcqRel);
    println!(
        "fls_callback warmed={} denied={} success={}",
        case.warmed,
        case.denied,
        result.is_ok()
    );
}
unsafe extern "system" fn native_thread(value: *mut c_void) -> u32 {
    let case = Box::from_raw(value.cast::<Case>());
    if case.warmed {
        if std::panic::catch_unwind(|| file_policy(&case)).is_err() {
            FAILURES.fetch_add(1, Ordering::AcqRel);
        }
    }
    let slot = case.slot;
    if FlsSetValue(slot, Box::into_raw(case).cast()) == 0 {
        return 1;
    }
    0
}
struct FiberCase {
    case: Case,
    parent: *mut c_void,
    installed: bool,
}
unsafe extern "system" fn fiber_entry(value: *mut c_void) {
    let context = &mut *value.cast::<FiberCase>();
    loop {
        if !context.installed {
            assert_ne!(
                FlsSetValue(
                    context.case.slot,
                    Box::into_raw(Box::new(context.case.clone())).cast()
                ),
                0
            );
            context.installed = true;
        }
        file_policy(&context.case);
        SwitchToFiber(context.parent);
    }
}
unsafe fn fibers(case: Case) {
    let parent = ConvertThreadToFiber(std::ptr::null_mut());
    assert!(!parent.is_null());
    let mut a = Box::new(FiberCase {
        case: case.clone(),
        parent,
        installed: false,
    });
    let mut b = Box::new(FiberCase {
        case: case.clone(),
        parent,
        installed: false,
    });
    let fiber_a = CreateFiber(0, Some(fiber_entry), (&mut *a as *mut FiberCase).cast());
    let fiber_b = CreateFiber(0, Some(fiber_entry), (&mut *b as *mut FiberCase).cast());
    assert!(!fiber_a.is_null() && !fiber_b.is_null());
    for _ in 0..3 {
        SwitchToFiber(fiber_a);
        file_policy(&case);
        SwitchToFiber(fiber_b);
        file_policy(&case);
    }
    // Freeing another fiber invokes its FLS callbacks in the calling thread.
    // Those callbacks must never clear or borrow the calling fiber's lease.
    DeleteFiber(fiber_a);
    file_policy(&case);
    DeleteFiber(fiber_b);
    file_policy(&case);
    assert_ne!(ConvertFiberToThread(), 0);
    file_policy(&case);
}
pub unsafe fn run(port: u16, path: &str, denied: bool) {
    let slot = FlsAlloc(Some(teardown));
    assert_ne!(slot, u32::MAX, "FlsAlloc failed");
    for warmed in [false, true] {
        for _ in 0..32 {
            let case = Box::new(Case {
                path: PathBuf::from(path),
                port,
                denied,
                warmed,
                slot,
            });
            let thread = CreateThread(
                std::ptr::null(),
                0,
                Some(native_thread),
                Box::into_raw(case).cast(),
                0,
                std::ptr::null_mut(),
            );
            assert!(!thread.is_null(), "CreateThread failed");
            assert_eq!(
                WaitForSingleObject(thread, 30_000),
                WAIT_OBJECT_0,
                "FLS callback hung at thread exit"
            );
            let mut code = 0;
            assert_ne!(GetExitCodeThread(thread, &mut code), 0);
            assert_eq!(code, 0);
            assert_ne!(CloseHandle(thread), 0);
        }
    }
    fibers(Case {
        path: PathBuf::from(path),
        port,
        denied,
        warmed: true,
        slot,
    });
    assert_ne!(FlsFree(slot), 0);
    assert_eq!(
        COMPLETED.load(Ordering::Acquire),
        66,
        "missing FLS callbacks"
    );
    assert_eq!(
        FAILURES.load(Ordering::Acquire),
        0,
        "FLS callback IO failed"
    );
    println!("fls_teardown=ok callbacks=66 fiber_switches=6 denied={denied}");
}
