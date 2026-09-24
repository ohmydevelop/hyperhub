use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::IsTerminal;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const REPOSITORY: &str = "ohmydevelop/hyperhub";
const CHECK_INTERVAL_MS: u64 = 12 * 60 * 60 * 1000;
const CHECK_STATE_FILE: &str = "upgrade-check.json";

#[derive(Debug, Clone, Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CheckState {
    last_check_ms: u64,
    latest_version: Option<String>,
    skipped_version: Option<String>,
}

#[derive(Debug, Clone)]
struct ReleaseInfo {
    release: Release,
    version: String,
    archive: ReleaseAsset,
    checksum: String,
}

pub(crate) fn check_on_start() -> Result<bool, String> {
    let now = now_ms();
    let mut state = load_state()?;
    if now.saturating_sub(state.last_check_ms) < CHECK_INTERVAL_MS {
        return Ok(false);
    }

    let result = match check_latest() {
        Ok(result) => result,
        Err(error) => {
            eprintln!("hyperhub: automatic upgrade check failed: {error}");
            state.last_check_ms = now;
            save_state(&state)?;
            return Ok(false);
        }
    };
    state.last_check_ms = now;
    state.latest_version = Some(result.version.clone());
    save_state(&state)?;

    if !is_newer(&result.version, env!("CARGO_PKG_VERSION"))
        || state.skipped_version.as_deref() == Some(&result.version)
    {
        return Ok(false);
    }

    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        eprintln!(
            "hyperhub: update available {} -> {} ({})",
            env!("CARGO_PKG_VERSION"),
            result.version,
            result.release.html_url
        );
        return Ok(false);
    }

    eprintln!(
        "✨ Update available! {} -> {}",
        env!("CARGO_PKG_VERSION"),
        result.version
    );
    eprintln!("Release notes: {}", result.release.html_url);
    eprintln!("1. Update now\n2. Skip\n3. Skip until next version");
    eprint!("Press 1, 2, or 3: ");
    io::stderr().flush().map_err(|error| error.to_string())?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("cannot read upgrade choice: {error}"))?;
    match answer.trim() {
        "1" => {
            perform_upgrade(&result, true)?;
            Ok(true)
        }
        "3" => {
            state.skipped_version = Some(result.version);
            save_state(&state)?;
            Ok(false)
        }
        _ => Ok(false),
    }
}

pub(crate) fn run_manual() -> Result<i32, String> {
    let result = check_latest()?;
    let mut state = load_state()?;
    state.last_check_ms = now_ms();
    state.latest_version = Some(result.version.clone());
    save_state(&state)?;
    if !is_newer(&result.version, env!("CARGO_PKG_VERSION")) {
        println!(
            "HyperHub is already up to date ({})",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(0);
    }
    println!(
        "Updating HyperHub {} -> {}",
        env!("CARGO_PKG_VERSION"),
        result.version
    );
    println!("Release notes: {}", result.release.html_url);
    perform_upgrade(&result, crate::lifecycle::serve_running()?)?;
    Ok(0)
}

pub(crate) fn run_helper(payload: &Path, target: &Path, restart: bool) -> Result<i32, String> {
    thread::sleep(Duration::from_millis(750));
    replace_binary(payload, target)?;
    let _ = fs::remove_file(payload);
    if restart {
        let _ = Command::new(target).arg("start").spawn();
    }
    Ok(0)
}

fn perform_upgrade(info: &ReleaseInfo, restart: bool) -> Result<(), String> {
    let payload = download_payload(info)?;
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    if restart {
        crate::lifecycle::stop()?;
    }
    let temp_dir = std::env::temp_dir().join(format!("hyperhub-upgrade-{}", std::process::id()));
    fs::create_dir_all(&temp_dir).map_err(|error| error.to_string())?;
    let payload_path = temp_dir.join(binary_name());
    fs::write(&payload_path, payload).map_err(|error| error.to_string())?;
    set_executable(&payload_path)?;
    let helper_path = temp_dir.join(format!("hyperhub-updater-{}", binary_name()));
    fs::copy(&current, &helper_path).map_err(|error| error.to_string())?;
    set_executable(&helper_path)?;
    let mut helper = Command::new(&helper_path);
    helper
        .arg("upgrade-helper")
        .arg(&payload_path)
        .arg(&current);
    if restart {
        helper.arg("--restart");
    }
    helper
        .spawn()
        .map_err(|error| format!("cannot start upgrade helper: {error}"))?;
    println!("Upgrade downloaded and will be installed after this process exits.");
    Ok(())
}

fn check_latest() -> Result<ReleaseInfo, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent(format!("hyperhub/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let release: Release = client
        .get(format!(
            "https://api.github.com/repos/{REPOSITORY}/releases/latest"
        ))
        .send()
        .map_err(|error| format!("cannot query GitHub Releases: {error}"))?
        .error_for_status()
        .map_err(|error| format!("GitHub Releases returned an error: {error}"))?
        .json()
        .map_err(|error| format!("invalid GitHub release response: {error}"))?;
    let version = release.tag_name.trim_start_matches('v').to_owned();
    let archive_name = asset_name()?;
    let archive = release
        .assets
        .iter()
        .find(|asset| asset.name == archive_name)
        .cloned()
        .ok_or_else(|| format!("release {version} has no asset {archive_name}"))?;
    let checksum_asset = release
        .assets
        .iter()
        .find(|asset| asset.name == "SHA256SUMS.txt")
        .cloned()
        .ok_or_else(|| format!("release {version} has no SHA256SUMS.txt"))?;
    let checksum = String::from_utf8(
        client
            .get(checksum_asset.browser_download_url)
            .send()
            .map_err(|error| format!("cannot download release checksums: {error}"))?
            .error_for_status()
            .map_err(|error| format!("release checksums returned an error: {error}"))?
            .bytes()
            .map_err(|error| format!("cannot read release checksums: {error}"))?
            .to_vec(),
    )
    .map_err(|error| format!("release checksums are not UTF-8: {error}"))?
    .lines()
    .find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let name = parts.next()?;
        (name == archive_name).then(|| hash.to_owned())
    })
    .ok_or_else(|| format!("SHA256SUMS.txt has no checksum for {archive_name}"))?;
    Ok(ReleaseInfo {
        release,
        version,
        archive,
        checksum,
    })
}

fn download_payload(info: &ReleaseInfo) -> Result<Vec<u8>, String> {
    let bytes = Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("hyperhub/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?
        .get(&info.archive.browser_download_url)
        .send()
        .map_err(|error| format!("cannot download release: {error}"))?
        .error_for_status()
        .map_err(|error| format!("release download returned an error: {error}"))?
        .bytes()
        .map_err(|error| format!("cannot read release download: {error}"))?
        .to_vec();
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual != info.checksum {
        return Err(format!(
            "release checksum mismatch: expected {}, got {actual}",
            info.checksum
        ));
    }
    extract_binary(&bytes, &info.archive.name)
}

fn extract_binary(bytes: &[u8], archive_name: &str) -> Result<Vec<u8>, String> {
    if archive_name.ends_with(".zip") {
        let mut archive =
            zip::ZipArchive::new(Cursor::new(bytes)).map_err(|error| error.to_string())?;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index).map_err(|error| error.to_string())?;
            if Path::new(file.name())
                .file_name()
                .and_then(|name| name.to_str())
                == Some(binary_name())
            {
                let mut output = Vec::new();
                file.read_to_end(&mut output)
                    .map_err(|error| error.to_string())?;
                return Ok(output);
            }
        }
    } else {
        let decoder = flate2::read::GzDecoder::new(Cursor::new(bytes));
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().map_err(|error| error.to_string())? {
            let mut entry = entry.map_err(|error| error.to_string())?;
            if entry
                .path()
                .ok()
                .and_then(|path| path.file_name().map(|name| name == binary_name()))
                .unwrap_or(false)
            {
                let mut output = Vec::new();
                entry
                    .read_to_end(&mut output)
                    .map_err(|error| error.to_string())?;
                return Ok(output);
            }
        }
    }
    Err(format!(
        "release archive does not contain {}",
        binary_name()
    ))
}

fn replace_binary(payload: &Path, target: &Path) -> Result<(), String> {
    let backup = target.with_extension("upgrade-backup");
    let _ = fs::remove_file(&backup);
    fs::rename(target, &backup)
        .map_err(|error| format!("cannot move current HyperHub binary: {error}"))?;
    if let Err(error) = fs::rename(payload, target) {
        let _ = fs::rename(&backup, target);
        return Err(format!("cannot install upgraded HyperHub binary: {error}"));
    }
    let _ = fs::remove_file(backup);
    Ok(())
}

fn asset_name() -> Result<String, String> {
    if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
        return Ok("hyperhub-windows-x64.zip".into());
    }
    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        return Ok("hyperhub-linux-x86_64.tar.gz".into());
    }
    if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        return Ok("hyperhub-linux-aarch64.tar.gz".into());
    }
    Err(format!(
        "automatic upgrades are unsupported on {}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ))
}

fn binary_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "hyperhub.exe"
    } else {
        "hyperhub"
    }
}

fn is_newer(candidate: &str, current: &str) -> bool {
    parse_version(candidate) > parse_version(current)
}

fn parse_version(value: &str) -> (u64, u64, u64) {
    let parts = value
        .trim_start_matches('v')
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect::<Vec<u64>>();
    (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

fn state_path() -> Result<PathBuf, String> {
    Ok(hyperhub_core::config_store::hyperhub_home()
        .map_err(|error| error.to_string())?
        .join(CHECK_STATE_FILE))
}

fn load_state() -> Result<CheckState, String> {
    let path = state_path()?;
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| error.to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(CheckState::default()),
        Err(error) => Err(error.to_string()),
    }
}

fn save_state(state: &CheckState) -> Result<(), String> {
    let path = state_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(|error| error.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn set_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)
            .map_err(|error| error.to_string())?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_stable_versions() {
        assert!(is_newer("0.3.0", "0.2.0"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.2.0", "0.2.0"));
        assert!(!is_newer("0.1.9", "0.2.0"));
    }

    #[test]
    fn parses_release_versions_with_tag_prefix() {
        assert_eq!(parse_version("v1.2.3"), (1, 2, 3));
        assert_eq!(parse_version("1.2"), (1, 2, 0));
    }

    #[test]
    fn rejects_unsupported_release_targets_explicitly() {
        let name = asset_name();
        if !cfg!(target_os = "linux") && !cfg!(target_os = "windows") {
            assert!(name.is_err());
        } else {
            assert!(name.is_ok());
        }
    }
}
