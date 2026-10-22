//! Native-module owner and regex allocation reclamation, on each native platform.
use hyperhub_engine::{contract::*, runtime::{artifact::Artifact, native::NativeEngine, Runtime, Settings}};
use std::{path::PathBuf, sync::Arc};
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let module = PathBuf::from(&args[1]);
    let cache = PathBuf::from(&args[2]);
    let bytes = std::fs::read(&module).unwrap();
    let manifest = hyperhub_engine::manifest(&bytes, args[3].to_str().unwrap());
    let load = || {
        let artifact = Artifact::install(&cache, &manifest, bytes.as_slice()).unwrap();
        Runtime::new(Arc::new(unsafe { NativeEngine::load(artifact, None) }.unwrap()), Settings::default()).unwrap()
    };
    let first = load();
    let second = load();
    let cached = cache.join(format!("{}{}", manifest.sha256, std::env::consts::DLL_SUFFIX));
    let diagnostic = unsafe { libloading::Library::new(cached) }.unwrap();
    let stats = unsafe { *diagnostic.get::<unsafe extern "C" fn(*mut u64)>(b"hh_fixture_lifecycle_stats\0").unwrap() };
    let query = || { let mut result = [0; 4]; unsafe { stats(result.as_mut_ptr()) }; result };
    assert_eq!(query(), [2, 0, 0, 0]);
    let request = PolicyInput {
        snapshot: [("default_action", "pass")].into_iter().collect(),
        target: "ordinary-file".into(), operation: "read".into(), command_line: String::new(),
    };
    let pinned = first.acquire();
    assert_eq!(hyperhub_engine::policy(&pinned, FILE_POLICY, &request).unwrap().action, "pass");
    assert_eq!(query(), [2, 1, 1, 0]);
    drop(first);
    assert_eq!(query(), [2, 1, 1, 0], "a live lease retains its logical module owner");
    drop(pinned);
    assert_eq!(query(), [1, 1, 1, 0], "another Engine sharing this DSO retains compiled regex objects");
    assert_eq!(hyperhub_engine::policy(&second.acquire(), FILE_POLICY, &request).unwrap().action, "pass");
    drop(second);
    assert_eq!(query(), [0, 0, 0, 1], "last owner must Drop actual compiled objects, even while diagnostic OS mapping remains");
    let third = load();
    assert_eq!(query(), [1, 0, 0, 1]);
    assert_eq!(hyperhub_engine::policy(&third.acquire(), FILE_POLICY, &request).unwrap().action, "pass");
    drop(third);
    assert_eq!(query(), [0, 0, 0, 2]);
    #[cfg(target_os = "linux")]
    double_owner_fork(&manifest, &bytes, &cache, query);
    drop(diagnostic);
    println!("NATIVE_MODULE_LIFETIME_OK");
}

#[cfg(target_os = "linux")]
fn double_owner_fork(manifest: &hyperhub_engine::runtime::Manifest, bytes: &[u8], cache: &std::path::Path,
    stats: impl Fn() -> [u64; 4]) {
    use hyperhub_engine::management::{self, Command, Reply};
    unsafe extern "C" { fn fork() -> i32; fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(code: i32) -> !; fn alarm(seconds: u32) -> u32; }
    let artifact = Artifact::install(cache, manifest, bytes).unwrap();
    let runtime = Runtime::new(Arc::new(unsafe { NativeEngine::load(artifact, None) }.unwrap()), Settings::default()).unwrap();
    let old = runtime.acquire();
    let source = cache.join(format!("{}{}", manifest.sha256, std::env::consts::DLL_SUFFIX));
    for command in [Command::Prepare { id: "double".into(), manifest: manifest.clone(), source, cache: cache.into() },
        Command::CommitHeld { id: "double".into() }] {
        assert!(!matches!(unsafe { management::execute(&runtime, command) }, Reply::Error { .. }));
    }
    let current = runtime.acquire();
    assert_eq!(stats()[0], 2);
    let frozen = runtime.freeze_fork().unwrap();
    let child = unsafe { fork() }; assert!(child >= 0);
    if child == 0 {
        unsafe { alarm(10); }
        let rebased = unsafe { frozen.into_child_image().rebuild() }.unwrap();
        let old = rebased.rebind(&old).unwrap();
        let current = rebased.rebind(&current).unwrap();
        let runtime = rebased.runtime.clone(); drop(rebased);
        assert_eq!(stats()[0], 2, "one reset per DSO must retain both rebuilt logical owners");
        let request = PolicyInput { snapshot: [("default_action", "pass")].into_iter().collect(),
            target: "ordinary-file".into(), operation: "read".into(), command_line: String::new() };
        assert_eq!(hyperhub_engine::policy(&old, FILE_POLICY, &request).unwrap().action, "pass");
        runtime.rollback("double", "child-only rollback").unwrap();
        drop(current); runtime.observe().unwrap();
        assert_eq!(stats()[0], 1);
        assert_eq!(stats()[2], 1, "remaining owner must retain actual compiled policy");
        drop(runtime); drop(old);
        assert_eq!(stats()[0..3], [0, 0, 0]);
        unsafe { _exit(0); }
    }
    drop(frozen);
    let mut status = 0; assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0, "shared-module child ownership failed");
    assert_eq!(stats()[0], 2, "child reset must not alter parent owners");
    runtime.rollback("double", "parent cleanup").unwrap();
    drop(current); runtime.observe().unwrap(); drop(runtime); drop(old);
    assert_eq!(stats()[0..3], [0, 0, 0]);
}
