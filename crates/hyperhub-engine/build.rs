#[path = "../../build_support/native_base.rs"]
mod native_base;
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rustc-env=HYPERHUB_ENGINE_TARGET={}",
        std::env::var("TARGET").expect("Cargo target")
    );
    let root =
        std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest"))
            .join("../..");
    let digest = native_base::fingerprint(
        &root,
        &std::env::var("TARGET").unwrap(),
        &std::env::var("CARGO_CFG_TARGET_OS").unwrap(),
    )
    .expect("cannot fingerprint resident native Base");
    println!(
        "cargo:rerun-if-changed={}",
        root.join("build_support/native_base.rs").display()
    );
    let marker = format!("{}{digest}\0", native_base::MARKER_PREFIX);
    let serve = native_base::serve_fingerprint(
        &root,
        &std::env::var("TARGET").unwrap(),
        &std::env::var("CARGO_CFG_TARGET_OS").unwrap(),
    )
    .expect("cannot fingerprint resident Serve Base");
    std::fs::write(std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("native_base.rs"),
        format!("pub const NATIVE_BASE_SHA256: &str = {digest:?};\npub const SERVE_BASE_SHA256: &str = {serve:?};\npub const NATIVE_BASE_MARKER: [u8; {}] = {:?};\n#[used]\n#[no_mangle]\npub static HH_NATIVE_BASE_FINGERPRINT_V1: [u8; {}] = NATIVE_BASE_MARKER;\n", marker.len(), marker.as_bytes(), marker.len()))
        .expect("cannot write native Base fingerprint");
}
