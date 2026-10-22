#[path = "../../../build_support/native_base.rs"]
#[allow(dead_code)]
mod native_base;

#[test]
fn comments_formatting_and_test_modules_do_not_change_the_base() {
    let original = "pub fn hook(x:u32)->u32{x+1}";
    let edited = r#"
        //! Resident entry.
        /// Handle a native call.
        pub fn hook (x: u32) -> u32 { x + 1 }
        #[cfg(test)]
        #[cfg(windows)]
        mod tests { #[test] fn regression() { assert_eq!(super::hook(1), 2); } }
    "#;
    assert_eq!(
        native_base::normalized(original).unwrap(),
        native_base::normalized(edited).unwrap()
    );
}

#[test]
fn native_hook_and_body_changes_are_significant() {
    let original = native_base::normalized("pub fn hook(x:u32)->u32{x+1}").unwrap();
    for changed in [
        "pub fn hook(x:u32)->u32{x+2}",
        "pub fn hook(x:u32)->u32{x+1} pub fn new_hook(){}",
        "pub fn hook(x:u64)->u64{x+1}",
        "#[cfg(windows)] pub fn hook(x:u32)->u32{x+1}",
        "#[cfg(any(test, windows))] pub fn hook(x:u32)->u32{x+1}",
        "#[cfg(any(test, all(windows, feature=\"gum-agent\")))] pub fn hook(x:u32)->u32{x+1}",
    ] {
        assert_ne!(original, native_base::normalized(changed).unwrap());
    }
}

#[test]
fn platform_test_modules_in_resident_sources_do_not_change_the_base() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for path in [
        "crates/hyperhub-agent-core/src/engine_call/slots.rs",
        "crates/hyperhub-agent-core/src/control.rs",
        "crates/hyperhub-agent-core/src/sandbox/mod.rs",
        "crates/hyperhub-agent-core/src/sandbox/network.rs",
        "crates/hyperhub-runtime/src/artifact.rs",
    ] {
        let source = std::fs::read_to_string(root.join(path)).unwrap();
        let edited = source.replace("#[test]", "#[test]\n#[ignore = \"test-only fixture edit\"]");
        assert_ne!(
            source, edited,
            "test-only source edit did not apply: {path}"
        );
        assert_eq!(
            native_base::normalized(&source).unwrap(),
            native_base::normalized(&edited).unwrap(),
            "test-only edits changed the resident Base: {path}"
        );
    }
}

#[test]
fn invalid_rust_is_rejected_instead_of_producing_a_fingerprint() {
    assert!(native_base::normalized("pub fn {").is_err());
}

#[test]
fn compiled_base_metadata_matches_current_resident_sources() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert_eq!(
        native_base::fingerprint(&root, hyperhub_engine::TARGET, std::env::consts::OS).unwrap(),
        hyperhub_engine::NATIVE_BASE_SHA256
    );
    assert_eq!(
        native_base::serve_fingerprint(&root, hyperhub_engine::TARGET, std::env::consts::OS)
            .unwrap(),
        hyperhub_engine::SERVE_BASE_SHA256
    );
}
