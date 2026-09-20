use rand::random;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const INSTALL_MARKER: &str = ".hyperhub-skill.json";

struct EmbeddedSkillFile {
    path: &'static str,
    bytes: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/embedded_skill.rs"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SkillInstallStatus {
    Current,
    Installed,
    Upgraded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillInstallOutcome {
    pub(crate) status: SkillInstallStatus,
    pub(crate) path: PathBuf,
    pub(crate) bundle_version: &'static str,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SkillInstallMarker {
    schema_version: u32,
    name: String,
    cli_version: String,
    content_sha256: String,
    bundle_version: String,
}

impl SkillInstallMarker {
    fn embedded() -> Self {
        Self {
            schema_version: 1,
            name: EMBEDDED_SKILL_NAME.into(),
            cli_version: EMBEDDED_SKILL_CLI_VERSION.into(),
            content_sha256: EMBEDDED_SKILL_SHA256.into(),
            bundle_version: EMBEDDED_SKILL_BUNDLE_VERSION.into(),
        }
    }
}

pub(crate) fn install_user_skill() -> Result<SkillInstallOutcome, String> {
    let home = user_home_directory()?;
    install_into(&home.join(".agents").join("skills"))
}

fn user_home_directory() -> Result<PathBuf, String> {
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let value = std::env::var_os(variable)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("cannot install HyperHub Skill: {variable} is not set"))?;
    Ok(PathBuf::from(value))
}

fn install_into(skills_root: &Path) -> Result<SkillInstallOutcome, String> {
    let target = skills_root.join(EMBEDDED_SKILL_NAME);
    let marker = SkillInstallMarker::embedded();
    if installed_marker(&target).as_ref() == Some(&marker) {
        return Ok(SkillInstallOutcome {
            status: SkillInstallStatus::Current,
            path: target,
            bundle_version: EMBEDDED_SKILL_BUNDLE_VERSION,
        });
    }

    fs::create_dir_all(skills_root).map_err(|error| {
        format!(
            "cannot create Agent Skill directory {}: {error}",
            skills_root.display()
        )
    })?;
    let suffix = format!("{}-{:016x}", std::process::id(), random::<u64>());
    let staging = skills_root.join(format!(".{}.install-{suffix}", EMBEDDED_SKILL_NAME));
    let backup = skills_root.join(format!(".{}.backup-{suffix}", EMBEDDED_SKILL_NAME));
    remove_entry_if_exists(&staging)?;
    remove_entry_if_exists(&backup)?;
    fs::create_dir(&staging).map_err(|error| {
        format!(
            "cannot create temporary Skill directory {}: {error}",
            staging.display()
        )
    })?;
    set_directory_permissions(&staging)?;

    let prepared = (|| {
        for file in EMBEDDED_SKILL_FILES {
            write_embedded_file(&staging, file)?;
        }
        let mut bytes = serde_json::to_vec_pretty(&marker).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        write_file(&staging.join(INSTALL_MARKER), &bytes)?;
        Ok::<(), String>(())
    })();
    if let Err(error) = prepared {
        let _ = remove_entry_if_exists(&staging);
        return Err(error);
    }

    let existed = fs::symlink_metadata(&target).is_ok();
    if existed {
        fs::rename(&target, &backup).map_err(|error| {
            let _ = remove_entry_if_exists(&staging);
            format!(
                "cannot stage the previous HyperHub Skill {}: {error}",
                target.display()
            )
        })?;
    }
    if let Err(error) = fs::rename(&staging, &target) {
        if existed {
            let _ = fs::rename(&backup, &target);
        }
        let _ = remove_entry_if_exists(&staging);
        return Err(format!(
            "cannot install HyperHub Skill at {}: {error}",
            target.display()
        ));
    }
    if existed {
        remove_entry_if_exists(&backup).map_err(|error| {
            format!(
                "HyperHub Skill was upgraded, but the previous copy could not be removed: {error}"
            )
        })?;
    }

    Ok(SkillInstallOutcome {
        status: if existed {
            SkillInstallStatus::Upgraded
        } else {
            SkillInstallStatus::Installed
        },
        path: target,
        bundle_version: EMBEDDED_SKILL_BUNDLE_VERSION,
    })
}

fn installed_marker(target: &Path) -> Option<SkillInstallMarker> {
    let metadata = fs::symlink_metadata(target).ok()?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return None;
    }
    let bytes = fs::read(target.join(INSTALL_MARKER)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_embedded_file(root: &Path, file: &EmbeddedSkillFile) -> Result<(), String> {
    let relative = safe_relative_path(file.path)?;
    write_file(&root.join(relative), file.bytes)
}

fn safe_relative_path(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("embedded Skill path is unsafe: {value}"));
    }
    Ok(path.to_path_buf())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "cannot create embedded Skill directory {}: {error}",
                parent.display()
            )
        })?;
        set_directory_permissions(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "cannot create embedded Skill file {}: {error}",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .map_err(|error| {
            format!(
                "cannot write embedded Skill file {}: {error}",
                path.display()
            )
        })?;
    set_file_permissions(path)
}

fn remove_entry_if_exists(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    };
    let result = if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_err(|error| format!("cannot remove {}: {error}", path.display()))
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .map_err(|error| format!("cannot secure Skill file {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("cannot secure Skill directory {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hyperhub-skill-{name}-{}-{:016x}",
            std::process::id(),
            random::<u64>()
        ))
    }

    #[test]
    fn embedded_bundle_contains_the_skill_entrypoints() {
        let paths = EMBEDDED_SKILL_FILES
            .iter()
            .map(|file| file.path)
            .collect::<Vec<_>>();
        assert!(paths.contains(&"SKILL.md"));
        assert!(paths.contains(&"agents/openai.yaml"));
        assert!(EMBEDDED_SKILL_BUNDLE_VERSION.starts_with(env!("CARGO_PKG_VERSION")));
        assert_eq!(EMBEDDED_SKILL_SHA256.len(), 64);
    }

    #[test]
    fn installs_skips_and_fully_replaces_an_outdated_skill() {
        let root = temp_root("upgrade");
        let first = install_into(&root).unwrap();
        assert_eq!(first.status, SkillInstallStatus::Installed);
        let skill = root.join(EMBEDDED_SKILL_NAME);
        assert_eq!(
            fs::read(skill.join("SKILL.md")).unwrap(),
            EMBEDDED_SKILL_FILES
                .iter()
                .find(|file| file.path == "SKILL.md")
                .unwrap()
                .bytes
        );
        let stale = skill.join("stale.txt");
        fs::write(&stale, "preserved while current").unwrap();

        let current = install_into(&root).unwrap();
        assert_eq!(current.status, SkillInstallStatus::Current);
        assert!(stale.is_file(), "current bundles must be skipped");

        let marker_path = skill.join(INSTALL_MARKER);
        let mut marker: SkillInstallMarker =
            serde_json::from_slice(&fs::read(&marker_path).unwrap()).unwrap();
        marker.bundle_version = "older".into();
        fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
        let upgraded = install_into(&root).unwrap();
        assert_eq!(upgraded.status, SkillInstallStatus::Upgraded);
        assert!(
            !stale.exists(),
            "upgrades must replace the complete directory"
        );
        assert_eq!(
            installed_marker(&skill),
            Some(SkillInstallMarker::embedded())
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn installation_failure_is_reported_instead_of_being_ignored() {
        let root = temp_root("blocked");
        fs::write(&root, "not-a-directory").unwrap();
        let error = install_into(&root).unwrap_err();
        assert!(error.contains("cannot create Agent Skill directory"));
        fs::remove_file(root).ok();
    }

    #[test]
    fn corrupt_marker_triggers_a_full_reinstall() {
        let root = temp_root("corrupt");
        install_into(&root).unwrap();
        let skill = root.join(EMBEDDED_SKILL_NAME);
        fs::write(skill.join(INSTALL_MARKER), "not-json").unwrap();
        fs::write(skill.join("stale.txt"), "stale").unwrap();
        assert_eq!(
            install_into(&root).unwrap().status,
            SkillInstallStatus::Upgraded
        );
        assert!(!skill.join("stale.txt").exists());
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replacing_a_symlink_does_not_modify_its_target() {
        use std::os::unix::fs::symlink;
        let root = temp_root("symlink");
        let outside = temp_root("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel"), "keep").unwrap();
        symlink(&outside, root.join(EMBEDDED_SKILL_NAME)).unwrap();
        assert_eq!(
            install_into(&root).unwrap().status,
            SkillInstallStatus::Upgraded
        );
        assert!(outside.join("sentinel").is_file());
        assert!(root.join(EMBEDDED_SKILL_NAME).join("SKILL.md").is_file());
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(outside).ok();
    }
}
