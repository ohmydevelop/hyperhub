use sha2::{Digest, Sha256};
use std::path::PathBuf;

const FRIDA_VERSION: &str = "17.17.0";

fn main() {
    println!("cargo:rerun-if-env-changed=HYPERHUB_FRIDA_CORE_ROOT");
    println!("cargo:rerun-if-env-changed=HYPERHUB_EMBEDDED_AGENT_PATH");
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
