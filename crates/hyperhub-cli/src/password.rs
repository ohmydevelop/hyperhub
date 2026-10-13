use base64::Engine;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
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
const API_KEY_PREFIX: &str = "hhk_";
const API_KEY_BYTES: usize = 32;

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

pub fn default_api_key_path() -> Result<PathBuf, String> {
    Ok(hyperhub_core::config_store::hyperhub_home()
        .map_err(|error| error.to_string())?
        .join("runtime/api-key"))
}

pub fn default_runtime_key_path() -> Result<PathBuf, String> {
    Ok(hyperhub_core::config_store::hyperhub_home()
        .map_err(|error| error.to_string())?
        .join("runtime/config-key.bin"))
}

pub fn runtime_key_exists() -> Result<bool, String> {
    Ok(default_runtime_key_path()?.is_file())
}

pub fn load_runtime_keyring(
    api_key_file: Option<&Path>,
) -> Result<hyperhub_core::config_store::ConfigKeyring, String> {
    let api_key = acquire_api_key(api_key_file)?;
    hyperhub_core::config_store::load_runtime_key(
        &default_runtime_key_path()?,
        api_key.as_bytes(),
    )
    .map_err(|error| {
        format!(
            "cannot unlock runtime configuration with the API key: {error}; run `hyperhub start --admin-password-file <file>` once to migrate or repair the runtime key"
        )
    })
}

pub fn save_runtime_keyring(
    keyring: &hyperhub_core::config_store::ConfigKeyring,
    api_key_file: Option<&Path>,
) -> Result<PathBuf, String> {
    let (api_key_path, api_key) = ensure_api_key(api_key_file)?;
    hyperhub_core::config_store::save_runtime_key(
        &default_runtime_key_path()?,
        keyring,
        api_key.as_bytes(),
    )
    .map_err(|error| format!("cannot save runtime configuration key: {error}"))?;
    Ok(api_key_path)
}

pub fn acquire_api_key(path: Option<&Path>) -> Result<Zeroizing<String>, String> {
    let path = match path {
        Some(path) => path.to_owned(),
        None => default_api_key_path()?,
    };
    read_api_key(&path)
}

pub fn ensure_api_key(path: Option<&Path>) -> Result<(PathBuf, Zeroizing<String>), String> {
    let path = match path {
        Some(path) => path.to_owned(),
        None => default_api_key_path()?,
    };
    if path.is_file() {
        return Ok((path.clone(), read_api_key(&path)?));
    }
    let mut bytes = [0u8; API_KEY_BYTES];
    rand::fill(&mut bytes);
    let value = format!(
        "{API_KEY_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    hyperhub_core::config_store::save_private_bytes(&path, value.as_bytes())
        .map_err(|error| format!("cannot create API key file {}: {error}", path.display()))?;
    Ok((path, Zeroizing::new(value)))
}

fn read_api_key(path: &Path) -> Result<Zeroizing<String>, String> {
    validate_secret_file(path, "API key file")?;
    let value = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read API key file {}: {error}", path.display()))?
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    );
    let encoded = value.strip_prefix(API_KEY_PREFIX).ok_or_else(|| {
        format!(
            "API key file {} does not contain a HyperHub API key",
            path.display()
        )
    })?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| {
            format!(
                "API key file {} contains an invalid API key",
                path.display()
            )
        })?;
    if decoded.len() != API_KEY_BYTES {
        return Err(format!(
            "API key file {} contains an invalid API key length",
            path.display()
        ));
    }
    Ok(value)
}

#[cfg(unix)]
fn validate_secret_file(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{label} {} must not be accessible by group or others",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_file(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("{label} does not exist: {}", path.display()));
    }
    Ok(())
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
            "a terminal is required for administrator password input; use --admin-password-file or {PASSWORD_ENV}"
        ));
    }
    if confirm {
        eprintln!("Creating a new HyperHub password\n");
    }
    let first = if confirm {
        prompt_with_feedback("HyperHub password: ", true)?
    } else {
        prompt_with_feedback("HyperHub password: ", true)?
    };
    validate(&first)?;
    eprintln!();
    if confirm {
        let second = prompt_with_feedback("Confirm password: ", true)?;
        eprintln!();
        if *first != *second {
            return Err("password confirmation does not match".into());
        }
    }
    Ok(first)
}

/// 在隐藏或掩码输入提示前后保存并强制恢复控制台模式，避免 rpassword 在
/// Windows Terminal/ConPTY 下遗留残缺输入状态。
pub(crate) fn prompt_secret(message: &str) -> Result<Zeroizing<String>, String> {
    prompt_with_feedback(message, true)
}

fn prompt_with_feedback(message: &str, masked: bool) -> Result<Zeroizing<String>, String> {
    let guard = ConsoleModeGuard::capture();
    let builder = rpassword::ConfigBuilder::new();
    let config = if masked {
        builder.password_feedback_mask('*').build()
    } else {
        builder.password_feedback_hide().build()
    };
    let result = rpassword::prompt_password_with_config(message, config)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_round_trip_uses_a_distinct_format() {
        let path = std::env::temp_dir().join(format!(
            "hyperhub-api-key-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let (created, key) = ensure_api_key(Some(&path)).unwrap();
        assert_eq!(created, path);
        assert!(key.starts_with(API_KEY_PREFIX));
        assert_eq!(read_api_key(&path).unwrap().as_str(), key.as_str());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn password_file_is_not_accepted_as_an_api_key() {
        let path = std::env::temp_dir().join(format!(
            "hyperhub-not-api-key-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, "administrator-password").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        assert!(read_api_key(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
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
