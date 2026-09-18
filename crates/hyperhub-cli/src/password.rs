use std::io::{self, IsTerminal, Read};
use std::path::Path;
use zeroize::Zeroizing;

/// rpassword 在 Windows 下隐藏输入时会临时把控制台输入模式改成
/// 仅 `ENABLE_PROCESSED_INPUT`（关闭回显与行编辑），并通过它自己新建的
/// `CONIN$`/`CONOUT$` 句柄在 Drop 时恢复。在 Windows Terminal/ConPTY 下，
/// 这种通过非主句柄切换并恢复的方式可能不生效，导致子进程与 PowerShell
/// 继续处于残缺输入状态（退格显示为字面 `^H`、出现 `More?` 等）。
/// 这里再使用本进程自身的标准输入/输出句柄保存并强制恢复一次。
#[cfg(windows)]
pub(crate) struct ConsoleModeGuard {
    input: Option<(windows_sys::Win32::Foundation::HANDLE, u32)>,
    output: Option<(windows_sys::Win32::Foundation::HANDLE, u32)>,
}

#[cfg(windows)]
impl ConsoleModeGuard {
    pub(crate) fn capture() -> Self {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        let read = |handle: windows_sys::Win32::Foundation::HANDLE| {
            if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                return None;
            }
            let mut mode = 0u32;
            (unsafe { GetConsoleMode(handle, &mut mode) } != 0).then_some((handle, mode))
        };
        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        Self {
            input: read(input),
            output: read(output),
        }
    }

    /// 恢复失败返回 `false`，供调用方对无法修复的残缺控制台给出诊断。
    pub(crate) fn restore(&self) -> bool {
        use windows_sys::Win32::System::Console::SetConsoleMode;
        let mut restored = true;
        for slot in [&self.input, &self.output] {
            if let Some((handle, mode)) = slot {
                if unsafe { SetConsoleMode(*handle, *mode) } == 0 {
                    restored = false;
                }
            }
        }
        restored
    }
}

#[cfg(windows)]
impl Drop for ConsoleModeGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(not(windows))]
pub(crate) struct ConsoleModeGuard;

#[cfg(not(windows))]
impl ConsoleModeGuard {
    pub(crate) fn capture() -> Self {
        Self
    }

    pub(crate) fn restore(&self) -> bool {
        true
    }
}

pub const PASSWORD_ENV: &str = "HYPERHUB_CONFIG_PASSWORD";

pub fn acquire(password_file: Option<&Path>, confirm: bool) -> Result<Zeroizing<String>, String> {
    acquire_with_environment(password_file, confirm, take_environment())
}

pub fn acquire_stdin() -> Result<Zeroizing<String>, String> {
    let mut value = String::new();
    io::stdin()
        .read_to_string(&mut value)
        .map_err(|error| format!("cannot read password from stdin: {error}"))?;
    let value = Zeroizing::new(value);
    validate(&value)?;
    Ok(value)
}

pub fn take_environment() -> Option<Zeroizing<String>> {
    let environment_password = std::env::var(PASSWORD_ENV).ok().map(Zeroizing::new);
    // SAFETY: password acquisition happens before application worker threads are started.
    unsafe { std::env::remove_var(PASSWORD_ENV) };
    environment_password
}

pub fn acquire_with_environment(
    password_file: Option<&Path>,
    confirm: bool,
    environment_password: Option<Zeroizing<String>>,
) -> Result<Zeroizing<String>, String> {
    if let Some(path) = password_file {
        validate_password_file(path)?;
        let value = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read password file {}: {error}", path.display()))?
                .trim_end_matches(['\r', '\n'])
                .to_owned(),
        );
        validate(&value)?;
        return Ok(value);
    }
    if let Some(value) = environment_password {
        validate(&value)?;
        return Ok(value);
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(format!(
            "a terminal is required for password input; use --password-file or {PASSWORD_ENV}"
        ));
    }
    let first = prompt_hidden("HyperHub password: ")?;
    validate(&first)?;
    eprintln!();
    if confirm {
        let second = prompt_hidden("Confirm password: ")?;
        eprintln!();
        if *first != *second {
            return Err("password confirmation does not match".into());
        }
    }
    Ok(first)
}

/// 在隐藏输入提示前后保存并强制恢复控制台模式，避免 rpassword 在
/// Windows Terminal/ConPTY 下遗留残缺输入状态。
fn prompt_hidden(message: &str) -> Result<Zeroizing<String>, String> {
    let guard = ConsoleModeGuard::capture();
    let result = rpassword::prompt_password(message)
        .map_err(|error| format!("cannot read password: {error}"));
    if !guard.restore() {
        eprintln!("hyperhub: warning: failed to restore console mode after password prompt");
    }
    result.map(Zeroizing::new)
}

fn validate(value: &str) -> Result<(), String> {
    if value.chars().count() < 8 {
        return Err("password must contain at least 8 characters".into());
    }
    if value.len() > 1024 {
        return Err("password is too long".into());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_password_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("cannot inspect password file {}: {error}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "password file {} must not be accessible by group or others",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_password_file(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("password file does not exist: {}", path.display()));
    }
    Ok(())
}
