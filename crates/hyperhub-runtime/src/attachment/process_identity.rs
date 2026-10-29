//! Read the actual IPC peer process incarnation and executable, never a path
//! supplied in a request. PID reuse is checked around the executable hash.
use std::io;
#[derive(Clone, Debug)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub birth: u64,
    pub executable_sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIncarnation {
    pub pid: u32,
    pub birth: u64,
}
/// Read OS incarnation metadata only. This does not verify an executable and
/// must not replace process_identity at an image or manager trust boundary.
pub fn process_incarnation(pid: u32) -> io::Result<ProcessIncarnation> {
    let created = birth(pid)?;
    if pid == 0 || created == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid process incarnation",
        ));
    }
    Ok(ProcessIncarnation {
        pid,
        birth: created,
    })
}
pub fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    let before = birth(pid)?;
    let path = executable(pid)?;
    use sha2::Digest;
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if birth(pid)? != before {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "IPC peer incarnation changed",
        ));
    }
    Ok(ProcessIdentity {
        pid,
        birth: before,
        executable_sha256: digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}
#[cfg(target_os = "linux")]
fn birth(pid: u32) -> io::Result<u64> {
    let value = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    value
        .rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| io::Error::other("invalid IPC peer process stat"))
}
#[cfg(target_os = "linux")]
fn executable(pid: u32) -> io::Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from(format!("/proc/{pid}/exe")))
}
#[cfg(windows)]
fn with_process<T>(
    pid: u32,
    call: impl FnOnce(windows_sys::Win32::Foundation::HANDLE) -> io::Result<T>,
) -> io::Result<T> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let result = call(handle);
    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    result
}
#[cfg(windows)]
fn birth(pid: u32) -> io::Result<u64> {
    with_process(pid, |handle| {
        let (mut created, mut exited, mut kernel, mut user) = unsafe {
            std::mem::zeroed::<(
                windows_sys::Win32::Foundation::FILETIME,
                windows_sys::Win32::Foundation::FILETIME,
                windows_sys::Win32::Foundation::FILETIME,
                windows_sys::Win32::Foundation::FILETIME,
            )>()
        };
        if unsafe {
            windows_sys::Win32::System::Threading::GetProcessTimes(
                handle,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    })
}
#[cfg(windows)]
fn executable(pid: u32) -> io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    with_process(pid, |handle| {
        let mut path = vec![0u16; 32768];
        let mut count = path.len() as u32;
        if unsafe {
            windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
                handle,
                0,
                path.as_mut_ptr(),
                &mut count,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(std::ffi::OsString::from_wide(&path[..count as usize]).into())
    })
}
#[cfg(not(any(windows, target_os = "linux")))]
fn birth(_: u32) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPC peer process identity is unsupported",
    ))
}
#[cfg(not(any(windows, target_os = "linux")))]
fn executable(_: u32) -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPC peer executable identity is unsupported",
    ))
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    #[test]
    fn incarnation_matches_full_identity_without_claiming_an_image() {
        let pid = std::process::id();
        let light = super::process_incarnation(pid).unwrap();
        let full = super::process_identity(pid).unwrap();
        assert_eq!((light.pid, light.birth), (full.pid, full.birth));
        assert!(super::process_incarnation(0).is_err());
    }
}
