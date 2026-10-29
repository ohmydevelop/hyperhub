#[path = "../../../build_support/native_base.rs"]
#[allow(dead_code)]
mod native_base;

#[path = "../../../build_support/native_dependencies.rs"]
#[allow(dead_code)]
mod native_dependencies;

use native_dependencies::NativeDependencies;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "hyperhub-native-dependency-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }
    fn sdk(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::create_dir_all(&path).unwrap();
        for (file, contents) in [
            ("frida-gum.h", "gum header 17.17.0"),
            ("libfrida-gum.a", "gum archive"),
            ("frida-gum.lib", "windows gum archive"),
            ("frida-core.h", "core header 17.17.0"),
            ("libfrida-core.a", "core archive with embedded payload"),
        ] {
            std::fs::write(path.join(file), contents).unwrap();
        }
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn linux(gum: &Path, core: &Path) -> [u8; 32] {
    NativeDependencies::resolve("linux", Some(gum), Some(core))
        .unwrap()
        .fingerprint("x86_64-unknown-linux-gnu")
        .unwrap()
}

#[test]
fn every_same_version_archive_and_header_change_changes_the_identity() {
    let fixture = Fixture::new();
    let gum = fixture.sdk("gum");
    let core = fixture.sdk("core");
    let original = linux(&gum, &core);
    for (root, name) in [
        (&gum, "libfrida-gum.a"),
        (&gum, "frida-gum.h"),
        (&core, "libfrida-core.a"),
        (&core, "frida-core.h"),
    ] {
        let path = root.join(name);
        let bytes = std::fs::read(&path).unwrap();
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert_ne!(original, linux(&gum, &core), "ignored {name}");
        std::fs::write(path, bytes).unwrap();
    }
}

#[test]
fn relocation_and_mtime_do_not_change_identical_dependency_bytes() {
    let fixture = Fixture::new();
    let first = fixture.sdk("first location");
    let second = fixture.sdk("second location");
    assert_eq!(linux(&first, &first), linux(&second, &second));
    let original = linux(&first, &second);
    let path = first.join("libfrida-gum.a");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(path, bytes).unwrap();
    assert_eq!(original, linux(&first, &second));
}

#[test]
fn dependency_roles_and_target_are_separated() {
    let fixture = Fixture::new();
    let sdk = fixture.sdk("sdk");
    let original = linux(&sdk, &sdk);
    let gum = std::fs::read(sdk.join("libfrida-gum.a")).unwrap();
    let core = std::fs::read(sdk.join("libfrida-core.a")).unwrap();
    std::fs::write(sdk.join("libfrida-core.a"), gum).unwrap();
    std::fs::write(sdk.join("libfrida-gum.a"), core).unwrap();
    assert_ne!(original, linux(&sdk, &sdk));
    let inputs = NativeDependencies::resolve("linux", Some(&sdk), Some(&sdk)).unwrap();
    assert_ne!(
        inputs.fingerprint("aarch64-unknown-linux-gnu").unwrap(),
        inputs.fingerprint("x86_64-unknown-linux-gnu").unwrap()
    );
}

#[test]
fn partial_or_incomplete_linux_pair_is_rejected() {
    let fixture = Fixture::new();
    let sdk = fixture.sdk("sdk");
    assert!(NativeDependencies::resolve("linux", Some(&sdk), None).is_err());
    assert!(NativeDependencies::resolve("linux", None, Some(&sdk)).is_err());
    for name in [
        "frida-core.h",
        "libfrida-core.a",
        "frida-gum.h",
        "libfrida-gum.a",
    ] {
        let path = sdk.join(name);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(NativeDependencies::resolve("linux", Some(&sdk), Some(&sdk)).is_err());
        std::fs::write(path, bytes).unwrap();
    }
}

#[test]
fn sdk_free_algorithm_profile_cannot_be_used_for_a_resident_build() {
    let inputs = NativeDependencies::resolve("linux", None, None).unwrap();
    assert!(inputs.require_native("linux").is_err());
    assert!(inputs.require_native("windows").is_err());
    let fixture = Fixture::new();
    let sdk = fixture.sdk("sdk");
    let native = NativeDependencies::resolve("linux", Some(&sdk), Some(&sdk)).unwrap();
    assert!(native.require_native("linux").is_ok());
    assert_ne!(
        inputs.fingerprint("x86_64-unknown-linux-gnu").unwrap(),
        native.fingerprint("x86_64-unknown-linux-gnu").unwrap()
    );
}

#[test]
fn windows_msvc_and_gnu_bind_gum_bytes_and_macos_needs_no_sdk() {
    let fixture = Fixture::new();
    let sdk = fixture.sdk("sdk");
    std::fs::remove_file(sdk.join("libfrida-gum.a")).unwrap();
    let inputs = NativeDependencies::resolve("windows", Some(&sdk), None).unwrap();
    inputs.require_native("windows").unwrap();
    for target in ["x86_64-pc-windows-msvc", "x86_64-pc-windows-gnu"] {
        let original = inputs.fingerprint(target).unwrap();
        let path = sdk.join("frida-gum.lib");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"same-version rebuilt official Gum").unwrap();
        assert_ne!(original, inputs.fingerprint(target).unwrap());
        std::fs::write(path, bytes).unwrap();
    }
    std::fs::remove_file(sdk.join("frida-gum.h")).unwrap();
    assert!(NativeDependencies::resolve("windows", Some(&sdk), None).is_err());
    NativeDependencies::resolve("macos", None, None)
        .unwrap()
        .require_native("macos")
        .unwrap();
}

#[test]
fn alternate_linker_libraries_cannot_hide_unidentified_native_bytes() {
    let fixture = Fixture::new();
    let sdk = fixture.sdk("sdk");
    for name in ["libfrida-core.so", "libfrida-core.so.1", "libfrida-gum.so"] {
        let path = sdk.join(name);
        std::fs::write(&path, b"alternate selected library").unwrap();
        assert!(NativeDependencies::resolve("linux", Some(&sdk), Some(&sdk)).is_err());
        std::fs::remove_file(path).unwrap();
    }
    assert!(NativeDependencies::resolve("windows", Some(&sdk), None).is_err());
    std::fs::remove_file(sdk.join("libfrida-gum.a")).unwrap();
    NativeDependencies::resolve("windows", Some(&sdk), None).unwrap();
}

#[test]
fn final_native_base_changes_when_only_same_version_sdk_bytes_change() {
    let fixture = Fixture::new();
    let sdk = fixture.sdk("sdk");
    let dependencies = native_base::native_dependencies::NativeDependencies::resolve(
        "linux",
        Some(&sdk),
        Some(&sdk),
    )
    .unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let before = native_base::fingerprint_with_dependencies(
        &root,
        "x86_64-unknown-linux-gnu",
        "linux",
        &dependencies,
    )
    .unwrap();
    std::fs::write(
        sdk.join("libfrida-core.a"),
        b"same-version patched embedded payload",
    )
    .unwrap();
    let after = native_base::fingerprint_with_dependencies(
        &root,
        "x86_64-unknown-linux-gnu",
        "linux",
        &dependencies,
    )
    .unwrap();
    assert_ne!(before, after);
}
