//! Restore an interactive terminal if its managed application exits abnormally.
use std::os::fd::RawFd;

// A crashed TUI cannot disable terminal input reporting. Without this reset,
// mouse/focus/paste reports can become commands in the waiting parent shell.
const RESET_REPORTING: &[u8] = b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1004l\x1b[?2004l\x1b[?1049l\x1b[?25h";

pub(super) struct TerminalRecovery {
    input: RawFd,
    output: RawFd,
    original: libc::termios,
    abnormal: bool,
}

impl TerminalRecovery {
    pub(super) fn capture() -> Option<Self> {
        Self::capture_fds(libc::STDIN_FILENO, libc::STDOUT_FILENO)
    }

    fn capture_fds(input: RawFd, output: RawFd) -> Option<Self> {
        if unsafe { libc::isatty(input) } != 1 || unsafe { libc::isatty(output) } != 1 {
            return None;
        }
        let mut original = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(input, &mut original) } != 0 {
            return None;
        }
        Some(Self {
            input,
            output,
            original,
            abnormal: true,
        })
    }

    pub(super) fn finish(&mut self, result: &Result<i32, String>) {
        self.abnormal = !matches!(result, Ok(0));
    }
}

impl Drop for TerminalRecovery {
    fn drop(&mut self) {
        if !self.abnormal {
            return;
        }
        // Restore the exact mode captured before launch, without interpreting
        // target output or changing the caller's successful stty commands.
        unsafe { libc::tcsetattr(self.input, libc::TCSANOW, &self.original) };
        let mut remaining = RESET_REPORTING;
        while !remaining.is_empty() {
            let count =
                unsafe { libc::write(self.output, remaining.as_ptr().cast(), remaining.len()) };
            if count > 0 {
                remaining = &remaining[count as usize..];
            } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        // Queued reports belong to the terminated application, not its shell.
        unsafe { libc::tcflush(self.input, libc::TCIFLUSH) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn pty() -> (OwnedFd, OwnedFd) {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
    }
    fn mode(fd: RawFd) -> libc::termios {
        let mut value = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(fd, &mut value) }, 0);
        value
    }
    fn raw(fd: RawFd) {
        let mut value = mode(fd);
        unsafe { libc::cfmakeraw(&mut value) };
        assert_eq!(unsafe { libc::tcsetattr(fd, libc::TCSANOW, &value) }, 0);
    }
    #[test]
    fn panic_restores_terminal_and_disables_input_reports() {
        let (master, slave) = pty();
        let fd = slave.as_raw_fd();
        let original = mode(fd);
        let panic = std::panic::catch_unwind(|| {
            let _guard = TerminalRecovery::capture_fds(fd, fd).unwrap();
            raw(fd);
            panic!("simulated launcher failure");
        });
        assert!(panic.is_err());
        let restored = mode(fd);
        assert_eq!(restored.c_iflag, original.c_iflag);
        assert_eq!(restored.c_oflag, original.c_oflag);
        assert_eq!(restored.c_lflag, original.c_lflag);
        assert_eq!(restored.c_cc, original.c_cc);
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 1000) }, 1);
        let mut output = [0u8; 256];
        let count =
            unsafe { libc::read(master.as_raw_fd(), output.as_mut_ptr().cast(), output.len()) };
        assert_eq!(&output[..count as usize], RESET_REPORTING);
    }
    #[test]
    fn successful_command_keeps_its_terminal_changes() {
        let (_master, slave) = pty();
        let fd = slave.as_raw_fd();
        let mut guard = TerminalRecovery::capture_fds(fd, fd).unwrap();
        raw(fd);
        guard.finish(&Ok(0));
        drop(guard);
        assert_eq!(mode(fd).c_lflag & libc::ICANON, 0);
    }
    #[test]
    fn errors_and_nonzero_exits_flush_reports_and_restore_terminal() {
        for result in [Err("control connection failed".into()), Ok(101)] {
            let (master, slave) = pty();
            let fd = slave.as_raw_fd();
            let original = mode(fd);
            let mut guard = TerminalRecovery::capture_fds(fd, fd).unwrap();
            raw(fd);
            let report = b"\x1b[M35\n";
            assert_eq!(
                unsafe { libc::write(master.as_raw_fd(), report.as_ptr().cast(), report.len()) },
                report.len() as isize
            );
            let mut pending = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe { libc::poll(&mut pending, 1, 1000) },
                1,
                "queued report trigger was not observed"
            );
            guard.finish(&result);
            drop(guard);
            assert_eq!(mode(fd).c_lflag, original.c_lflag);
            assert_eq!(
                unsafe { libc::poll(&mut pending, 1, 0) },
                0,
                "terminated application's report leaked into parent input"
            );
        }
    }
    #[test]
    fn non_terminal_io_is_not_modified() {
        let fd = std::fs::File::open("/dev/null").unwrap();
        assert!(TerminalRecovery::capture_fds(fd.as_raw_fd(), fd.as_raw_fd()).is_none());
    }
}
