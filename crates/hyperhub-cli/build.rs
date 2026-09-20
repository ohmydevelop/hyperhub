use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

const FRIDA_VERSION: &str = "17.17.0";
const NEEDLE3_REVISION: &str = "c1fc4d4cb32993156a880ceb8ff171b03b1f166a";
const NEEDLE3_MODEL_SHA256: &str =
    "c9d915eca282ed42d1a09b143b592adb4cc6744ffe2d294adf5cfc5548170c38";

fn main() {
    println!("cargo:rerun-if-env-changed=HYPERHUB_FRIDA_CORE_ROOT");
    println!("cargo:rerun-if-env-changed=HYPERHUB_EMBEDDED_AGENT_PATH");
    println!("cargo:rerun-if-env-changed=HYPERHUB_NEEDLE3_MODEL");
    println!("cargo:rerun-if-env-changed=HYPERHUB_NEEDLE3_RUNNER");
    prepare_embedded_skill();
    prepare_needle3();
    prepare_embedded_agent();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let root = std::env::var_os("HYPERHUB_FRIDA_CORE_ROOT")
        .map(PathBuf::from)
        .expect("HYPERHUB_FRIDA_CORE_ROOT is required to build the Linux CLI");
    let header = root.join("frida-core.h");
    let library = root.join("libfrida-core.a");
    for path in [&header, &library] {
        if !path.is_file() {
            panic!("Frida Core devkit file was not found: {}", path.display());
        }
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let header_text = std::fs::read_to_string(&header)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", header.display()));
    let expected = format!("#define FRIDA_VERSION \"{FRIDA_VERSION}\"");
    if !header_text.lines().any(|line| line.trim() == expected) {
        panic!(
            "Frida Core header version mismatch; expected {FRIDA_VERSION} in {}",
            header.display()
        );
    }

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let expected_machine = match target_arch.as_str() {
        "x86_64" => 62,
        "aarch64" => 183,
        other => panic!("unsupported Linux target architecture: {other}"),
    };
    let actual_machine = archive_elf_machine(&library).unwrap_or_else(|error| {
        panic!(
            "cannot inspect Frida Core archive {}: {error}",
            library.display()
        )
    });
    if actual_machine != expected_machine {
        panic!(
            "Frida Core architecture mismatch: target={target_arch} archive-machine={actual_machine}"
        );
    }

    println!("cargo:rustc-link-search=native={}", root.display());
}

fn prepare_embedded_skill() {
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is required"));
    let manifest = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required"),
    );
    let source = manifest.join("assets").join("skills").join("hyperhub-cli");
    println!("cargo:rerun-if-changed={}", source.display());
    let mut files = Vec::new();
    collect_skill_files(&source, &source, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    if !files.iter().any(|(path, _)| path == "SKILL.md") {
        panic!("embedded HyperHub Skill is missing SKILL.md");
    }
    if !files.iter().any(|(path, _)| path == "agents/openai.yaml") {
        panic!("embedded HyperHub Skill is missing agents/openai.yaml");
    }

    let mut digest = Sha256::new();
    let mut entries = String::new();
    for (relative, path) in &files {
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = std::fs::read(path).unwrap_or_else(|error| {
            panic!("cannot read embedded Skill {}: {error}", path.display())
        });
        digest.update((relative.len() as u64).to_le_bytes());
        digest.update(relative.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(&bytes);
        let source_literal = format!("{:?}", path.canonicalize().unwrap().to_string_lossy());
        entries.push_str(&format!(
            "    EmbeddedSkillFile {{ path: {relative:?}, bytes: include_bytes!({source_literal}) }},\n"
        ));
    }
    let digest = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let version = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is required");
    let bundle_version = format!("{version}+sha256.{digest}");
    std::fs::write(
        output.join("embedded_skill.rs"),
        format!(
            "const EMBEDDED_SKILL_NAME: &str = \"hyperhub-cli\";\n\
             const EMBEDDED_SKILL_CLI_VERSION: &str = {version:?};\n\
             const EMBEDDED_SKILL_SHA256: &str = {digest:?};\n\
             const EMBEDDED_SKILL_BUNDLE_VERSION: &str = {bundle_version:?};\n\
             static EMBEDDED_SKILL_FILES: &[EmbeddedSkillFile] = &[\n{entries}];\n"
        ),
    )
    .expect("cannot write embedded Skill metadata");
}

fn collect_skill_files(root: &Path, directory: &Path, output: &mut Vec<(String, PathBuf)>) {
    let mut entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| {
            panic!(
                "cannot read Skill directory {}: {error}",
                directory.display()
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("cannot enumerate Skill directory: {error}"));
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().unwrap_or_else(|error| {
            panic!("cannot inspect Skill path {}: {error}", path.display())
        });
        if file_type.is_symlink() {
            panic!(
                "embedded Skill must not contain symlinks: {}",
                path.display()
            );
        }
        if file_type.is_dir() {
            collect_skill_files(root, &path, output);
            continue;
        }
        if !file_type.is_file() {
            panic!(
                "embedded Skill contains a non-file entry: {}",
                path.display()
            );
        }
        let relative = path
            .strip_prefix(root)
            .expect("Skill file must remain below its root");
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            panic!("embedded Skill path is invalid: {}", relative.display());
        }
        let relative = relative
            .components()
            .map(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .expect("Skill paths must be UTF-8")
            })
            .collect::<Vec<_>>()
            .join("/");
        output.push((relative, path));
    }
}

fn prepare_needle3() {
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is required"));
    let manifest = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required"),
    );
    let cache = manifest.join("../..").join(".cache").join("needle3");
    std::fs::create_dir_all(&cache).unwrap_or_else(|error| {
        panic!("cannot create Needle 3 cache {}: {error}", cache.display())
    });

    let model = std::env::var_os("HYPERHUB_NEEDLE3_MODEL")
        .map(PathBuf::from)
        .unwrap_or_else(|| cache.join("needle3.cact"));
    ensure_download(
        &model,
        &format!(
            "https://huggingface.co/Cactus-Compute/needle3/resolve/{NEEDLE3_REVISION}/needle3.cact"
        ),
        NEEDLE3_MODEL_SHA256,
        "Needle 3 model",
    );

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let (remote, name, digest) = match (target_os.as_str(), target_arch.as_str()) {
        ("linux", "x86_64") => (
            "linux-x86_64/needle",
            "needle",
            "84994c65f1992c037a696370c567547e769dad168350bf9e0bdb3630a9bb1c28",
        ),
        ("linux", "aarch64") => (
            "linux-arm64/needle",
            "needle",
            "e882ec2e60426cd6a77d1612c081d3f9e91dec12c9740f174de6a1c9dacbddb1",
        ),
        ("windows", "x86_64") => (
            "windows-x86_64/needle.exe",
            "needle.exe",
            "6a2965401432722fda2479e2faae0accbb2cdd965e344009df690e780986196d",
        ),
        ("macos", "aarch64") => (
            "macos-arm64/needle",
            "needle",
            "de023d7fa1bd9553ba5598d2208ed0e4b8960a2e5277f6b70678accd05d29560",
        ),
        _ => panic!(
            "Needle 3 has no embedded runner for target {target_os}-{target_arch}; supported targets are Linux x86_64/aarch64, Windows x86_64, and macOS aarch64"
        ),
    };
    let runner = std::env::var_os("HYPERHUB_NEEDLE3_RUNNER")
        .map(PathBuf::from)
        .unwrap_or_else(|| cache.join(target_os).join(target_arch).join(name));
    ensure_download(
        &runner,
        &format!(
            "https://huggingface.co/Cactus-Compute/needle3/resolve/{NEEDLE3_REVISION}/{remote}"
        ),
        digest,
        "Needle 3 runner",
    );

    let model_destination = output.join("needle3.cact");
    let runner_destination = output.join("needle3-runner.bin");
    std::fs::copy(&model, &model_destination)
        .unwrap_or_else(|error| panic!("cannot embed Needle 3 model {}: {error}", model.display()));
    std::fs::copy(&runner, &runner_destination).unwrap_or_else(|error| {
        panic!("cannot embed Needle 3 runner {}: {error}", runner.display())
    });
    println!("cargo:rerun-if-changed={}", model.display());
    println!("cargo:rerun-if-changed={}", runner.display());
}

fn ensure_download(path: &std::path::Path, url: &str, expected: &str, label: &str) {
    if file_sha256(path).as_deref() == Some(expected) {
        return;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|error| {
            panic!(
                "cannot create {} cache {}: {error}",
                label,
                parent.display()
            )
        });
    }
    let temporary = path.with_extension(format!("download-{}", std::process::id()));
    let status = std::process::Command::new("curl")
        .args(["-fL", "--retry", "3", "--output"])
        .arg(&temporary)
        .arg(url)
        .status()
        .unwrap_or_else(|error| panic!("cannot launch curl to download {label}: {error}"));
    if !status.success() {
        panic!("cannot download {label} from {url}: curl exited with {status}");
    }
    let actual = file_sha256(&temporary)
        .unwrap_or_else(|| panic!("cannot hash downloaded {label} {}", temporary.display()));
    if actual != expected {
        let _ = std::fs::remove_file(&temporary);
        panic!("{label} checksum mismatch: expected {expected}, got {actual}");
    }
    if path.exists() {
        std::fs::remove_file(path).unwrap_or_else(|error| {
            panic!("cannot replace cached {label} {}: {error}", path.display())
        });
    }
    std::fs::rename(&temporary, path).unwrap_or_else(|error| {
        panic!(
            "cannot install downloaded {label} at {}: {error}",
            path.display()
        )
    });
}

fn file_sha256(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

fn prepare_embedded_agent() {
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is required"));
    let metadata = output.join("embedded_agent_meta.rs");
    if std::env::var_os("CARGO_FEATURE_EMBEDDED_AGENT").is_none() {
        std::fs::write(
            metadata,
            "pub const EMBEDDED_AGENT_SHA256: [u8; 32] = [0; 32];\n\
             pub const EMBEDDED_AGENT_SIZE: usize = 0;\n\
             pub const EMBEDDED_AGENT_NAME: &str = \"\";\n",
        )
        .expect("cannot write empty embedded Agent metadata");
        return;
    }

    let source = std::env::var_os("HYPERHUB_EMBEDDED_AGENT_PATH")
        .map(PathBuf::from)
        .expect("HYPERHUB_EMBEDDED_AGENT_PATH is required with embedded-agent");
    println!("cargo:rerun-if-changed={}", source.display());
    let bytes = std::fs::read(&source)
        .unwrap_or_else(|error| panic!("cannot read embedded Agent {}: {error}", source.display()));
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    validate_embedded_agent(&bytes, &target_os, &target_arch)
        .unwrap_or_else(|error| panic!("invalid embedded Agent {}: {error}", source.display()));
    let name = match target_os.as_str() {
        "windows" => "hyperhub_gum_agent.dll",
        "linux" => "libhyperhub_gum_agent.so",
        other => panic!("embedded Agent is unsupported for target OS {other}"),
    };
    let destination = output.join("embedded-agent.bin");
    std::fs::write(&destination, &bytes)
        .unwrap_or_else(|error| panic!("cannot copy embedded Agent: {error}"));
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let digest_text = digest
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        metadata,
        format!(
            "pub const EMBEDDED_AGENT_SHA256: [u8; 32] = [{digest_text}];\n\
             pub const EMBEDDED_AGENT_SIZE: usize = {};\n\
             pub const EMBEDDED_AGENT_NAME: &str = {:?};\n",
            bytes.len(),
            name,
        ),
    )
    .expect("cannot write embedded Agent metadata");
}

fn validate_embedded_agent(bytes: &[u8], target_os: &str, target_arch: &str) -> Result<(), String> {
    match target_os {
        "windows" => validate_pe_agent(bytes, target_arch),
        "linux" => validate_elf_agent(bytes, target_arch),
        other => Err(format!("unsupported target OS {other}")),
    }
}

fn validate_pe_agent(bytes: &[u8], target_arch: &str) -> Result<(), String> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return Err("Agent is not a PE image".into());
    }
    let offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    if offset.checked_add(24).is_none_or(|end| end > bytes.len())
        || &bytes[offset..offset + 4] != b"PE\0\0"
    {
        return Err("Agent has an invalid PE header".into());
    }
    let machine = u16::from_le_bytes(bytes[offset + 4..offset + 6].try_into().unwrap());
    let optional_size =
        u16::from_le_bytes(bytes[offset + 20..offset + 22].try_into().unwrap()) as usize;
    let optional = offset + 24;
    let optional_end = optional
        .checked_add(optional_size)
        .filter(|end| *end <= bytes.len())
        .ok_or("PE image has a truncated optional header")?;
    if optional_size < 2
        || optional_end <= optional
        || bytes[optional..optional + 2] != [0x0b, 0x02]
    {
        return Err("PE Agent is not a valid PE32+ image".into());
    }
    let characteristics = u16::from_le_bytes(bytes[offset + 22..offset + 24].try_into().unwrap());
    let expected = match target_arch {
        "x86_64" => 0x8664,
        other => return Err(format!("unsupported Windows architecture {other}")),
    };
    if machine != expected {
        return Err(format!(
            "PE machine mismatch: expected 0x{expected:04x}, got 0x{machine:04x}"
        ));
    }
    if characteristics & 0x2000 == 0 {
        return Err("PE image is not marked as a DLL".into());
    }
    Ok(())
}

fn validate_elf_agent(bytes: &[u8], target_arch: &str) -> Result<(), String> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err("Agent is not a little-endian ELF64 image".into());
    }
    let image_type = u16::from_le_bytes(bytes[16..18].try_into().unwrap());
    let machine = u16::from_le_bytes(bytes[18..20].try_into().unwrap());
    let expected = match target_arch {
        "x86_64" => 62,
        "aarch64" => 183,
        other => return Err(format!("unsupported Linux architecture {other}")),
    };
    if image_type != 3 {
        return Err(format!("ELF Agent is not ET_DYN: type={image_type}"));
    }
    if machine != expected {
        return Err(format!(
            "ELF machine mismatch: expected {expected}, got {machine}"
        ));
    }
    Ok(())
}

fn archive_elf_machine(path: &std::path::Path) -> Result<u16, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    if !bytes.starts_with(b"!<arch>\n") {
        return Err("not an ar archive".into());
    }
    let mut offset = 8usize;
    let mut machine = None;
    let mut objects = 0usize;
    while offset.checked_add(60).is_some_and(|end| end <= bytes.len()) {
        let header = &bytes[offset..offset + 60];
        let size = std::str::from_utf8(&header[48..58])
            .map_err(|_| "invalid ar member size")?
            .trim()
            .parse::<usize>()
            .map_err(|_| "invalid ar member size")?;
        let data_start = offset + 60;
        let data_end = data_start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or("truncated ar member")?;
        let data = &bytes[data_start..data_end];
        if let Some(position) = data
            .windows(4)
            .take(256)
            .position(|window| window == b"\x7fELF")
        {
            let elf = &data[position..];
            if elf.len() < 20 {
                return Err("truncated ELF object in archive".into());
            }
            if elf[4] != 2 {
                return Err("Frida Core archive contains a non-ELF64 object".into());
            }
            if elf[5] != 1 {
                return Err("Frida Core archive contains a non-little-endian object".into());
            }
            let current = u16::from_le_bytes([elf[18], elf[19]]);
            if machine.is_some_and(|expected| expected != current) {
                return Err(format!(
                    "Frida Core archive contains mixed architectures: {expected} and {current}",
                    expected = machine.unwrap()
                ));
            }
            machine = Some(current);
            objects += 1;
        }
        offset = data_end + (size & 1);
    }
    if objects == 0 {
        Err("no ELF object was found in archive".into())
    } else {
        Ok(machine.expect("ELF object records a machine"))
    }
}
