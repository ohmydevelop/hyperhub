use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::IsTerminal;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod bundle;

pub(crate) fn export_bundle(directory: &Path) -> Result<i32, String> {
    let manifest = bundle::export(directory).map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string(&manifest).map_err(|error| error.to_string())?
    );
    Ok(0)
}

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
            perform_upgrade(&result, false, true)?;
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
    perform_upgrade(&result, crate::lifecycle::serve_running()?, false)?;
    Ok(0)
}

pub(crate) fn manage(action: &str, id: Option<&str>) -> Result<i32, String> {
    use hyperhub_core::session::{ControlRequest, ControlResponse};
    let request = if action == "status" {
        ControlRequest::GetReleaseUpgrades {
            id: id.map(str::to_owned),
        }
    } else {
        let key = crate::password::acquire_api_key()?;
        let request = hyperhub_core::release::Request {
            id: id.ok_or("upgrade transaction id is required")?.into(),
            issued_at_ms: now_ms(),
            action: match action {
                "recover" => hyperhub_core::release::Action::Recover,
                "abort" => hyperhub_core::release::Action::Abort,
                _ => return Err("unknown upgrade action".into()),
            },
        };
        let proof = request
            .proof(key.as_bytes())
            .map_err(|error| error.to_string())?;
        ControlRequest::ReleaseUpgrade { request, proof }
    };
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let response = runtime
        .block_on(hyperhub_core::control::control_request(
            &hyperhub_core::control::discovery_control_endpoint(),
            &request,
        ))
        .map_err(|error| error.to_string())?;
    match response {
        ControlResponse::Error { message } => Err(message),
        response => {
            println!(
                "{}",
                serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
            );
            Ok(0)
        }
    }
}

fn perform_upgrade(
    info: &ReleaseInfo,
    running: bool,
    start_after_install: bool,
) -> Result<(), String> {
    let payload = download_payload(info)?;
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    let id = format!("release-{}-{:016x}", now_ms(), rand::random::<u64>());
    let root = hyperhub_core::config_store::hyperhub_home()
        .map_err(|error| error.to_string())?
        .join("runtime/releases")
        .join(&id);
    // The content-addressed installer creates and validates a private parent.
    let payload_manifest = hyperhub_engine::manifest(&payload, &info.version);
    let artifact = hyperhub_runtime::artifact::Artifact::install(
        &root.join("executable"),
        &payload_manifest,
        payload.as_slice(),
    )
    .map_err(|error| error.to_string())?;
    let executable = root.join(binary_name());
    fs::hard_link(artifact.path(), &executable).map_err(|error| error.to_string())?;
    set_executable(&executable)?;
    let export = root.join("bundle");
    let output = Command::new(&executable)
        .arg("export-upgrade-bundle")
        .arg(&export)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cannot inspect release bundle: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "release bundle inspection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let (bundle, engine) = bundle::read(&export, &executable).map_err(|error| error.to_string())?;
    if bundle.version != info.version {
        return Err("release version does not match the verified archive".into());
    }
    let expected_target_sha256 = hyperhub_core::release::installer::digest(&current)
        .map_err(|error| error.to_string())?
        .0;
    if running {
        let request = hyperhub_core::release::Request {
            id: id.clone(),
            issued_at_ms: now_ms(),
            action: hyperhub_core::release::Action::Prepare {
                plan: hyperhub_core::release::Plan {
                    bundle,
                    executable,
                    engine,
                    cache: root.join("engines"),
                    target: current,
                    expected_target_sha256,
                },
                auto_commit: true,
            },
        };
        let key = crate::password::acquire_api_key()?;
        let proof = request
            .proof(key.as_bytes())
            .map_err(|error| error.to_string())?;
        let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
        let response = runtime
            .block_on(hyperhub_core::control::control_request(
                &hyperhub_core::control::discovery_control_endpoint(),
                &hyperhub_core::session::ControlRequest::ReleaseUpgrade { request, proof },
            ))
            .map_err(|error| {
                format!("resident Serve cannot accept this upgrade: {error}; requires_restart")
            })?;
        match response {
            hyperhub_core::session::ControlResponse::ReleaseUpgrade { record } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&record).map_err(|error| error.to_string())?
                );
                if record.phase == hyperhub_core::release::Phase::RequiresRestart {
                    return Err("resident Base requires an explicit restart; no managed process was restarted".into());
                }
                println!("Upgrade accepted: {id}. Resident Serve will finish it after this CLI exits. Use hyperhub status --json to inspect progress.");
            }
            hyperhub_core::session::ControlResponse::Error { message } => return Err(message),
            _ => return Err("resident Serve returned an unexpected upgrade response".into()),
        }
    } else {
        let (_, key) = crate::password::ensure_api_key(&crate::password::default_api_key_path()?)?;
        let job = hyperhub_core::release::installer::SignedJob::sign(
            hyperhub_core::release::installer::Job {
                id: id.clone(),
                attempt: 1,
                issued_at_ms: now_ms(),
                source: executable,
                target: current,
                sha256: bundle.worker_sha256,
                size: bundle.worker_size,
                expected_target_sha256,
                start_after_install,
            },
            key.as_bytes(),
        )
        .map_err(|error| error.to_string())?;
        let job_path = root.join("install.json");
        job.write(&job_path).map_err(|error| error.to_string())?;
        let helper = root.join(format!("installer{}", std::env::consts::EXE_SUFFIX));
        fs::copy(
            std::env::current_exe().map_err(|error| error.to_string())?,
            &helper,
        )
        .map_err(|error| error.to_string())?;
        set_executable(&helper)?;
        Command::new(helper)
            .arg("upgrade-install-helper")
            .arg(&job_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("cannot start installation helper: {error}"))?;
        println!(
            "Installation accepted: {id}. Helper acknowledgement: {}",
            job_path.with_extension("ack.json").display()
        );
    }
    Ok(())
}

pub(crate) fn run_install_helper(path: &Path) -> Result<i32, String> {
    use hyperhub_core::release::installer::{
        self, Acknowledgement, SignedAcknowledgement, SignedJob,
    };
    let key = crate::password::acquire_api_key()?;
    let signed = SignedJob::read(path, key.as_bytes()).map_err(|error| error.to_string())?;
    let result = installer::install(&signed.job);
    let start_after_install = signed.job.start_after_install;
    let installed_target = signed.job.target.clone();
    let ack = Acknowledgement {
        id: signed.job.id,
        attempt: signed.job.attempt,
        issued_at_ms: now_ms(),
        sha256: signed.job.sha256,
        installed: result.is_ok(),
        error: result.as_ref().err().map(|error| error.to_string()),
    };
    let proof = ack
        .proof(key.as_bytes())
        .map_err(|error| error.to_string())?;
    SignedAcknowledgement {
        ack: ack.clone(),
        proof: proof.clone(),
    }
    .write(&path.with_extension("ack.json"))
    .map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    // The persisted signed receipt permits recovery if the resident endpoint is
    // temporarily unavailable. An offline installation needs only this receipt.
    let _ = runtime.block_on(hyperhub_core::control::control_request(
        &hyperhub_core::control::discovery_control_endpoint(),
        &hyperhub_core::session::ControlRequest::ReleaseHelperAck { ack, proof },
    ));
    result.map_err(|error| error.to_string())?;
    if start_after_install {
        let status = Command::new(installed_target)
            .arg("start")
            .status()
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!(
                "installed HyperHub could not start Serve: {status}"
            ));
        }
    }
    Ok(0)
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
    let mut selected = None;
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
                if selected.is_some()
                    || !file.is_file()
                    || file
                        .unix_mode()
                        .is_some_and(|mode| mode & 0o170000 == 0o120000)
                {
                    return Err("release must contain exactly one regular CLI executable".into());
                }
                let size = file.size();
                selected = Some(read_executable(&mut file, size)?);
            }
        }
    } else {
        let decoder = flate2::read::GzDecoder::new(Cursor::new(bytes));
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().map_err(|error| error.to_string())? {
            let mut entry = entry.map_err(|error| error.to_string())?;
            if entry
                .path()
                .map_err(|error| error.to_string())?
                .file_name()
                .is_some_and(|name| name == binary_name())
            {
                if selected.is_some() || !entry.header().entry_type().is_file() {
                    return Err("release must contain exactly one regular CLI executable".into());
                }
                let size = entry.size();
                selected = Some(read_executable(&mut entry, size)?);
            }
        }
    }
    selected.ok_or_else(|| format!("release archive does not contain {}", binary_name()))
}

fn read_executable(reader: &mut impl Read, expected: u64) -> Result<Vec<u8>, String> {
    use hyperhub_core::release::installer::MAX_EXECUTABLE;
    if expected == 0 || expected > MAX_EXECUTABLE {
        return Err("release executable size is invalid".into());
    }
    let mut output = Vec::new();
    reader
        .take(MAX_EXECUTABLE + 1)
        .read_to_end(&mut output)
        .map_err(|error| error.to_string())?;
    if output.len() as u64 != expected {
        return Err("release executable size mismatch".into());
    }
    Ok(output)
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
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)
            .map_err(|error| error.to_string())?
            .permissions();
        permissions.set_mode(0o555);
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
    fn archive_rejects_ambiguous_executables_and_size_mismatch() {
        use zip::write::SimpleFileOptions;
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file(
            format!("package/{}", binary_name()),
            SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(b"first executable").unwrap();
        zip.start_file(
            format!("other/{}", binary_name()),
            SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(b"second executable").unwrap();
        let archive = zip.finish().unwrap().into_inner();
        assert!(extract_binary(&archive, "fixture.zip")
            .unwrap_err()
            .contains("exactly one"));
        assert!(read_executable(&mut Cursor::new(b"truncated"), 100).is_err());
        assert!(read_executable(&mut Cursor::new(b""), 0).is_err());
    }

    #[test]
    fn archive_selects_the_regular_cli_among_engine_bundle_entries() {
        use zip::write::SimpleFileOptions;
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file("package/upgrade/bundle.json", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"{}").unwrap();
        zip.start_file(
            format!("package/{}", binary_name()),
            SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(b"local executable fixture").unwrap();
        let archive = zip.finish().unwrap().into_inner();
        assert_eq!(
            extract_binary(&archive, "fixture.zip").unwrap(),
            b"local executable fixture"
        );
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
