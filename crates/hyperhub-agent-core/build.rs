fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_GUM_AGENT");
    println!("cargo:rerun-if-env-changed=HYPERHUB_FRIDA_GUM_ROOT");

    if std::env::var_os("CARGO_FEATURE_GUM_AGENT").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
    {
        let root = std::env::var_os("HYPERHUB_FRIDA_GUM_ROOT")
            .map(std::path::PathBuf::from)
            .expect("HYPERHUB_FRIDA_GUM_ROOT is required to build the Gum Agent");
        let library = root.join("frida-gum.lib");
        if !library.is_file() {
            panic!("Frida Gum library was not found at {}", library.display());
        }
        println!("cargo:rustc-link-search=native={}", root.display());

        for library in [
            "dnsapi", "iphlpapi", "psapi", "winmm", "ws2_32", "advapi32", "crypt32", "gdi32",
            "kernel32", "ole32", "secur32", "shell32", "shlwapi", "user32", "setupapi",
        ] {
            println!("cargo:rustc-link-lib=dylib={library}");
        }
    }

    if std::env::var_os("CARGO_FEATURE_GUM_AGENT").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
    {
        let root = std::env::var_os("HYPERHUB_FRIDA_GUM_ROOT")
            .map(std::path::PathBuf::from)
            .expect("HYPERHUB_FRIDA_GUM_ROOT is required to build the Linux Gum Agent");
        let library = root.join("libfrida-gum.a");
        if !library.is_file() {
            panic!("Frida Gum library was not found at {}", library.display());
        }
        println!("cargo:rustc-link-search=native={}", root.display());
        println!("cargo:rustc-link-lib=static=frida-gum");
        for library in ["dl", "pthread", "m", "rt", "resolv"] {
            println!("cargo:rustc-link-lib=dylib={library}");
        }
    }
}
