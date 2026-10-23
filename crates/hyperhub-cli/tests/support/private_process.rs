//! Hold an OS process handle so failed fixtures never signal a reused PID.
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::{io, path::Path};

pub struct PrivateProcess {
    #[cfg(target_os = "linux")]
    handle: OwnedFd,
    #[cfg(windows)]
    handle: OwnedHandle,
}
impl PrivateProcess {
    pub fn exited(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let mut event = libc::pollfd {
                fd: self.handle.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe { libc::poll(&mut event, 1, 0) > 0 }
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(
                self.handle.as_raw_handle().cast(),
                0,
            ) == windows_sys::Win32::Foundation::WAIT_OBJECT_0
        }
    }
    pub fn capture(pid: u32, executable: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let handle = unsafe { OwnedFd::from_raw_fd(fd) };
            let actual = std::fs::read_link(format!("/proc/{pid}/exe"))?;
            if actual.canonicalize()? != executable.canonicalize()? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture PID executable changed",
                ));
            }
            Ok(Self { handle })
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_TERMINATE,
            };
            const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
                    0,
                    pid,
                )
            };
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
            let mut buffer = vec![0u16; 32768];
            let mut size = buffer.len() as u32;
            if unsafe { QueryFullProcessImageNameW(raw, 0, buffer.as_mut_ptr(), &mut size) } == 0 {
                return Err(io::Error::last_os_error());
            }
            use std::os::windows::ffi::OsStringExt;
            let actual =
                std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..size as usize]));
            if !actual
                .canonicalize()?
                .to_string_lossy()
                .eq_ignore_ascii_case(&executable.canonicalize()?.to_string_lossy())
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture process handle executable changed",
                ));
            }
            Ok(Self { handle })
        }
    }
}
impl Drop for PrivateProcess {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.handle.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(
                self.handle.as_raw_handle().cast(),
                1,
            );
        }
    }
}

pub fn remove_fixture(root: &Path) -> io::Result<()> {
    #[cfg(windows)]
    fn writable(path: &Path) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Ok(());
        }
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                writable(&entry?.path())?;
            }
        } else if metadata.permissions().readonly() {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(false);
            std::fs::set_permissions(path, permissions)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    writable(root)?;
    std::fs::remove_dir_all(root)
}
