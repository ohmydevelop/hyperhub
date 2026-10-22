//! Rustc fixture dependencies are taken from this running Cargo test's dependency
//! directory. Production Engine processing modules compile into the fixture DSO.
pub fn configure(command: &mut std::process::Command) {
    let executable = std::env::current_exe().expect("current Cargo test path");
    let parent = executable.parent().expect("Cargo dependency directory");
    let example_dependencies;
    let dependencies = if parent.file_name().is_some_and(|name| name == "examples") {
        example_dependencies = parent.parent().unwrap().join("deps");
        example_dependencies.as_path()
    } else {
        parent
    };
    command.arg("--cfg").arg("test");
    command
        .arg("-L")
        .arg(format!("dependency={}", dependencies.display()));
    for name in [
        "serde",
        "serde_json",
        "regex",
        "ipnet",
        "sha2",
        "hyperhub_runtime",
        "hyperhub_engine",
        "libloading",
    ] {
        let prefix = format!("lib{name}-");
        let library = std::fs::read_dir(dependencies)
            .expect("Cargo dependencies")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    (n.starts_with(&prefix) && n.ends_with(".rlib"))
                        || n == format!("lib{name}.rlib")
                })
            })
            .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
            .unwrap_or_else(|| panic!("missing compiled fixture dependency {name}"));
        command
            .arg("--extern")
            .arg(format!("{name}={}", library.display()));
    }
}
