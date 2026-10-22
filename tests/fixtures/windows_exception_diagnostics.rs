//! Test-process evidence only. Keep the native exception disposition unchanged.
use std::fmt::Write as _;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::WriteFile,
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, RtlCaptureStackBackTrace, EXCEPTION_POINTERS,
        },
        LibraryLoader::{
            GetModuleFileNameA, GetModuleHandleExA, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        },
    },
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetStdHandle(number: u32) -> HANDLE;
}
struct Buffer {
    bytes: [u8; 8192],
    length: usize,
}
impl std::fmt::Write for Buffer {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let count = text.len().min(self.bytes.len() - self.length);
        self.bytes[self.length..self.length + count].copy_from_slice(&text.as_bytes()[..count]);
        self.length += count;
        Ok(())
    }
}
unsafe fn frame(output: &mut Buffer, pc: *mut core::ffi::c_void) {
    let mut module = std::ptr::null_mut();
    let mut path = [0u8; 512];
    let mut name = "unknown";
    if GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        pc.cast(),
        &mut module,
    ) != 0
    {
        let length = GetModuleFileNameA(module, path.as_mut_ptr(), path.len() as u32) as usize;
        if let Ok(text) = std::str::from_utf8(&path[..length.min(path.len())]) {
            name = std::path::Path::new(text)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown");
        }
    }
    let _ = writeln!(
        output,
        "pc={pc:p} module={name} offset=0x{:x}",
        (pc as usize).wrapping_sub(module as usize)
    );
}
unsafe extern "system" fn exception(info: *mut EXCEPTION_POINTERS) -> i32 {
    use std::sync::atomic::{AtomicBool, Ordering};
    static ENTERED: AtomicBool = AtomicBool::new(false);
    let Some(info) = info.as_ref() else {
        return 0;
    };
    let Some(record) = info.ExceptionRecord.as_ref() else {
        return 0;
    };
    if record.ExceptionCode != 0xc0000005u32 as i32 || ENTERED.swap(true, Ordering::AcqRel) {
        return 0;
    }
    let mut output = Buffer {
        bytes: [0; 8192],
        length: 0,
    };
    let _ = writeln!(
        output,
        "probe_exception code=0xc0000005 operation={} address=0x{:x}",
        record.ExceptionInformation[0], record.ExceptionInformation[1]
    );
    frame(&mut output, record.ExceptionAddress);
    let mut frames = [std::ptr::null_mut(); 32];
    let count = RtlCaptureStackBackTrace(
        0,
        frames.len() as u32,
        frames.as_mut_ptr(),
        std::ptr::null_mut(),
    );
    for pc in &frames[..count as usize] {
        frame(&mut output, *pc);
    }
    let mut written = 0;
    let _ = WriteFile(
        GetStdHandle((-12i32) as u32),
        output.bytes.as_ptr(),
        output.length as u32,
        &mut written,
        std::ptr::null_mut(),
    );
    ENTERED.store(false, Ordering::Release);
    0 // EXCEPTION_CONTINUE_SEARCH
}
pub unsafe fn install() {
    AddVectoredExceptionHandler(1, Some(exception));
}
