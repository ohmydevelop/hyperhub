//! Exact native dependency identity. SDK locations are build inputs, never identity.
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub const GUM_ROOT_ENV: &str = "HYPERHUB_FRIDA_GUM_ROOT";
pub const CORE_ROOT_ENV: &str = "HYPERHUB_FRIDA_CORE_ROOT";

#[derive(Debug)]
pub struct NativeDependencies {
    files: Vec<(&'static str, PathBuf)>,
    native: bool,
}

impl NativeDependencies {
    pub fn from_environment(os: &str) -> io::Result<Self> {
        for name in [GUM_ROOT_ENV, CORE_ROOT_ENV] {
            println!("cargo:rerun-if-env-changed={name}");
        }
        Self::resolve(
            os,
            std::env::var_os(GUM_ROOT_ENV).map(PathBuf::from).as_deref(),
            std::env::var_os(CORE_ROOT_ENV)
                .map(PathBuf::from)
                .as_deref(),
        )
    }

    /// A build without any SDK is allowed for portable Engine/Core unit tests.
    /// Native Agent and Linux CLI builders must additionally call require_native.
    pub fn resolve(os: &str, gum: Option<&Path>, core: Option<&Path>) -> io::Result<Self> {
        let mut files = Vec::new();
        match os {
            "linux" if gum.is_some() || core.is_some() => {
                let gum = gum.ok_or_else(|| missing(GUM_ROOT_ENV))?;
                let core = core.ok_or_else(|| missing(CORE_ROOT_ENV))?;
                reject_linker_alternatives(core, &["libfrida-core.so", "libfrida-core.dylib"])?;
                reject_linker_alternatives(gum, &["libfrida-gum.so", "libfrida-gum.dylib"])?;
                files.extend([
                    ("gum/header", gum.join("frida-gum.h")),
                    ("gum/archive", gum.join("libfrida-gum.a")),
                    ("core/header", core.join("frida-core.h")),
                    ("core/archive", core.join("libfrida-core.a")),
                ]);
            }
            "windows" if gum.is_some() => {
                let gum = gum.unwrap();
                reject_linker_alternatives(
                    gum,
                    &["libfrida-gum.a", "libfrida-gum.dll.a", "frida-gum.dll"],
                )?;
                files.extend([
                    ("gum/header", gum.join("frida-gum.h")),
                    ("gum/archive", gum.join("frida-gum.lib")),
                ]);
            }
            _ => {}
        }
        for (_, path) in &files {
            println!("cargo:rerun-if-changed={}", path.display());
            if !path.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("native SDK input was not found: {}", path.display()),
                ));
            }
        }
        Ok(Self {
            native: !files.is_empty(),
            files,
        })
    }

    pub fn require_native(&self, os: &str) -> io::Result<()> {
        if matches!(os, "linux" | "windows") && !self.native {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "native {os} build requires {GUM_ROOT_ENV}{}; run the platform build script first",
                    if os == "linux" { " and HYPERHUB_FRIDA_CORE_ROOT" } else { "" }
                ),
            ));
        }
        Ok(())
    }

    /// Role, target and profile are framed, so an SDK-free algorithm build can
    /// never advertise the identity of a resident native build.
    pub fn fingerprint(&self, target: &str) -> io::Result<[u8; 32]> {
        let mut digest = Sha256::new();
        field(&mut digest, b"hyperhub-native-dependencies-v1");
        field(&mut digest, target.as_bytes());
        field(
            &mut digest,
            if self.native {
                b"native"
            } else {
                b"non-native"
            },
        );
        for (role, path) in &self.files {
            field(&mut digest, role.as_bytes());
            // Hash the stream itself, not mtime, file name, a manifest claim or
            // only the public version. Rebuilt same-version archives differ.
            let mut input = std::fs::File::open(path)?;
            let mut content = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                content.update(&buffer[..count]);
            }
            field(&mut digest, &content.finalize());
        }
        Ok(digest.finalize().into())
    }
}

fn missing(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("Linux native identity requires the complete Core/Gum pair; {name} is missing"),
    )
}

fn field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

// A same-name alternate library can be chosen before the archive we identify.
// SDK roots for resident builds must expose exactly that static link input.
fn reject_linker_alternatives(root: &Path, names: &[&str]) -> io::Result<()> {
    println!("cargo:rerun-if-changed={}", root.display());
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy().to_ascii_lowercase();
        if names.iter().any(|candidate| {
            name == *candidate
                || (candidate.ends_with(".so") && name.starts_with(&format!("{candidate}.")))
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "native SDK root contains an alternate linker input {}; use a directory with only the selected static SDK archive",
                    entry.path().display()
                ),
            ));
        }
    }
    Ok(())
}
