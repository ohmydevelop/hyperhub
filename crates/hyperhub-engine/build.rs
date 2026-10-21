fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rustc-env=HYPERHUB_ENGINE_TARGET={}",
        std::env::var("TARGET").expect("Cargo target")
    );
}
