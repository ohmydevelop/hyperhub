//! Fork recovery signal regression. The handler uses only async-signal-safe IO.
use std::ffi::{c_char, c_int, CString};
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU16, Ordering};

static PATH: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());
static PORT: AtomicU16 = AtomicU16::new(0);
static PIPE: AtomicI32 = AtomicI32::new(-1);
#[repr(C)]
struct Address {
    family: u16,
    port: u16,
    address: u32,
    padding: [u8; 8],
}
unsafe extern "C" {
    fn fork() -> c_int;
    fn signal(number: c_int, handler: unsafe extern "C" fn(c_int)) -> usize;
    fn kill(pid: c_int, number: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn pipe(fds: *mut c_int) -> c_int;
    fn read(fd: c_int, data: *mut u8, size: usize) -> isize;
    fn write(fd: c_int, data: *const u8, size: usize) -> isize;
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn connect(fd: c_int, address: *const Address, length: u32) -> c_int;
    fn __errno_location() -> *mut c_int;
    fn _exit(status: c_int) -> !;
}
unsafe extern "C" fn handler(_: c_int) {
    let file = open(PATH.load(Ordering::Relaxed), 0);
    let file_error = if file < 0 { *__errno_location() } else { 0 };
    if file >= 0 {
        close(file);
    }
    let fd = socket(2, 1, 0);
    let address = Address {
        family: 2,
        port: PORT.load(Ordering::Relaxed).to_be(),
        address: u32::from_ne_bytes([127, 0, 0, 1]),
        padding: [0; 8],
    };
    let connected = if fd >= 0 {
        connect(fd, &address, 16)
    } else {
        -2
    };
    let connect_error = if connected < 0 {
        *__errno_location()
    } else {
        0
    };
    if fd >= 0 {
        close(fd);
    }
    let result = [file, file_error, connected, connect_error];
    if write(PIPE.load(Ordering::Relaxed), result.as_ptr().cast(), 16) != 16 {
        _exit(92);
    }
}
fn main() {
    let path = CString::new(std::env::var("HH_SIGNAL_DENY_FILE").unwrap()).unwrap();
    PATH.store(path.as_ptr() as *mut c_char, Ordering::Relaxed);
    PORT.store(
        std::env::var("HH_SIGNAL_DENY_PORT")
            .unwrap()
            .parse()
            .unwrap(),
        Ordering::Relaxed,
    );
    let mut fds = [-1; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    PIPE.store(fds[1], Ordering::Relaxed);
    assert_ne!(unsafe { signal(10, handler) }, usize::MAX);
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        let mut result = [0_i32; 4];
        let mut received = 0;
        while received < 16 {
            let count = unsafe {
                read(
                    fds[0],
                    result.as_mut_ptr().cast::<u8>().add(received),
                    16 - received,
                )
            };
            if count < 0 && unsafe { *__errno_location() } == 4 {
                continue;
            }
            assert!(count > 0, "signal result read failed");
            received += count as usize;
        }
        eprintln!(
            "FORK_SIGNAL_RESULT file=({},{}) socket=({},{})",
            result[0], result[1], result[2], result[3]
        );
        assert_eq!(
            result,
            [-1, 13, -1, 13],
            "fork recovery signal bypassed policy"
        );
        println!("SIGNAL_CASE_PASS");
        return;
    }
    assert_eq!(unsafe { kill(child, 10) }, 0);
    let mut status = 0;
    assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0, "signal child failed");
}
