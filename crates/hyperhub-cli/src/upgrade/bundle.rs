use hyperhub_runtime::artifact::Artifact;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

include!(concat!(env!("OUT_DIR"), "/embedded_engine.rs"));

use hyperhub_core::release::installer::digest;
use hyperhub_core::release::{engine_name, Base, Bundle};

/// The verified executable exports its own embedded Engine, so installation
/// retains the single executable distribution and does not search a mutable
/// working directory for native code.
pub(crate) fn export(directory: &Path) -> io::Result<Bundle> {
    if EMBEDDED_ENGINE.is_empty() {
        return Err(io::Error::other(
            "this build has no verified embedded Engine",
        ));
    }
    let executable = std::env::current_exe()?;
    let (worker_sha256, worker_size) = digest(&executable)?;
    export_bytes(directory, EMBEDDED_ENGINE, worker_sha256, worker_size)
}

fn export_bytes(
    directory: &Path,
    bytes: &[u8],
    worker_sha256: String,
    worker_size: u64,
) -> io::Result<Bundle> {
    let engine = hyperhub_engine::manifest(bytes, env!("CARGO_PKG_VERSION"));
    let bundle = Bundle {
        format: 1,
        version: engine.version.clone(),
        target: engine.target.clone(),
        base: Base::resident(),
        engine,
        engine_file: engine_name().into(),
        worker_sha256,
        worker_size,
    };
    bundle.validate()?;
    // Artifact::install applies the same private-directory, hash and immutable
    // file checks used by every native Host. The published friendly name is a
    // separate immutable copy for package consumers.
    let artifact = Artifact::install(&directory.join("modules"), &bundle.engine, bytes)
        .map_err(io::Error::other)?;
    write_new(
        &directory.join(engine_name()),
        &fs::read(artifact.path())?,
        true,
    )?;
    write_new(
        &directory.join("bundle.json"),
        &serde_json::to_vec_pretty(&bundle).map_err(io::Error::other)?,
        false,
    )?;
    Ok(bundle)
}

pub(crate) fn read(directory: &Path, executable: &Path) -> io::Result<(Bundle, PathBuf)> {
    let manifest = directory.join("bundle.json");
    let bytes = File::open(manifest)?
        .take(64 * 1024 + 1)
        .bytes()
        .collect::<Result<Vec<_>, _>>()?;
    if bytes.len() > 64 * 1024 {
        return Err(io::Error::other("release manifest exceeds size limit"));
    }
    let bundle: Bundle = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    bundle.validate()?;
    if digest(executable)? != (bundle.worker_sha256.clone(), bundle.worker_size) {
        return Err(io::Error::other(
            "release executable digest or size mismatch",
        ));
    }
    let engine = directory.join(&bundle.engine_file);
    if digest(&engine)? != (bundle.engine.sha256.clone(), bundle.engine.size) {
        return Err(io::Error::other("release Engine digest or size mismatch"));
    }
    Ok((bundle, engine))
}

fn write_new(path: &Path, bytes: &[u8], readonly: bool) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if readonly {
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)?;
    }
    #[cfg(unix)]
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("missing artifact parent"))?,
    )?
    .sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundle_checks_exact_engine_and_executable_bytes_and_rejects_path_changes() {
        let root = std::env::temp_dir().join(format!(
            "hh-bundle-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        let executable = root.join("worker");
        fs::write(&executable, b"local worker fixture").unwrap();
        let (hash, size) = digest(&executable).unwrap();
        let original = export_bytes(&root, b"local Engine fixture", hash, size).unwrap();
        let (read_back, _) = read(&root, &executable).unwrap();
        assert_eq!(read_back.engine, original.engine);
        fs::write(&executable, b"changed worker fixture").unwrap();
        assert!(read(&root, &executable).is_err());
        let mut changed = original.clone();
        changed.engine_file = "../other.so".into();
        assert!(changed.validate().is_err());
        changed = original;
        changed.base.hooks ^= 1;
        assert!(changed.validate().is_err());
        assert!(export_bytes(&root, b"overwrite", "0".repeat(64), 1).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
