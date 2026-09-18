#![cfg(all(target_os = "linux", feature = "gum-agent"))]

use super::{adapters::native, gum};
use std::ffi::c_void;
use std::sync::OnceLock;

#[derive(Clone, Copy)]
enum HookMode {
    Replace(*mut c_void),
    Listen(usize),
}

impl HookMode {
    fn compatible_with(self, other: Self) -> bool {
        match (self, other) {
            (Self::Replace(left), Self::Replace(right)) => left == right,
            (Self::Listen(left), Self::Listen(right)) => left == right,
            _ => false,
        }
    }
}

struct Descriptor {
    id: u32,
    symbol: &'static str,
    semantic_hook: &'static str,
    mode: HookMode,
    required: bool,
}

unsafe impl Sync for Descriptor {}

static DESCRIPTORS: &[Descriptor] = &[
    replace(
        1,
        "getaddrinfo",
        "dns.resolve",
        native::getaddrinfo as *mut c_void,
        true,
    ),
    replace(
        2,
        "freeaddrinfo",
        "dns.release",
        native::freeaddrinfo as *mut c_void,
        true,
    ),
    replace(
        3,
        "connect",
        "socket.connect",
        native::connect as *mut c_void,
        true,
    ),
    replace(4, "send", "socket.send", native::send as *mut c_void, true),
    replace(5, "recv", "socket.recv", native::recv as *mut c_void, true),
    replace(
        6,
        "close",
        "handle.close",
        native::close as *mut c_void,
        true,
    ),
    listen(
        7,
        "fcntl",
        "socket.nonblocking",
        native::LISTENER_FCNTL,
        true,
    ),
    listen(8, "ioctl", "socket.ioctl", native::LISTENER_IOCTL, true),
    listen(9, "open", "file.open", native::LISTENER_OPEN, true),
    listen(10, "open64", "file.open", native::LISTENER_OPEN, false),
    listen(11, "openat", "file.open", native::LISTENER_OPENAT, true),
    listen(12, "openat64", "file.open", native::LISTENER_OPENAT, false),
    replace(13, "creat", "file.open", native::creat as *mut c_void, true),
    replace(14, "read", "file.read", native::read as *mut c_void, true),
    replace(
        15,
        "write",
        "file.write",
        native::write as *mut c_void,
        true,
    ),
    replace(
        16,
        "unlink",
        "file.delete",
        native::unlink as *mut c_void,
        true,
    ),
    replace(
        17,
        "unlinkat",
        "file.delete",
        native::unlinkat as *mut c_void,
        true,
    ),
    replace(
        18,
        "rename",
        "file.rename",
        native::rename as *mut c_void,
        true,
    ),
    replace(
        19,
        "renameat",
        "file.rename",
        native::renameat as *mut c_void,
        true,
    ),
    replace(
        20,
        "execve",
        "process.create",
        native::execve as *mut c_void,
        true,
    ),
    replace(
        21,
        "posix_spawn",
        "process.create",
        native::posix_spawn as *mut c_void,
        true,
    ),
    replace(
        22,
        "posix_spawnp",
        "process.create",
        native::posix_spawnp as *mut c_void,
        true,
    ),
    replace(23, "mmap", "file.map", native::mmap as *mut c_void, true),
    replace(
        24,
        "mprotect",
        "file.protect",
        native::mprotect as *mut c_void,
        true,
    ),
    replace(
        25,
        "munmap",
        "file.unmap",
        native::munmap as *mut c_void,
        true,
    ),
];

const fn replace(
    id: u32,
    symbol: &'static str,
    semantic_hook: &'static str,
    replacement: *mut c_void,
    required: bool,
) -> Descriptor {
    Descriptor {
        id,
        symbol,
        semantic_hook,
        mode: HookMode::Replace(replacement),
        required,
    }
}

const fn listen(
    id: u32,
    symbol: &'static str,
    semantic_hook: &'static str,
    listener_kind: usize,
    required: bool,
) -> Descriptor {
    Descriptor {
        id,
        symbol,
        semantic_hook,
        mode: HookMode::Listen(listener_kind),
        required,
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct HookInstallReport {
    pub(crate) installed: usize,
    pub(crate) optional_missing: Vec<&'static str>,
    pub(crate) aliases: usize,
}

struct ResolvedGroup {
    target: *mut c_void,
    mode: HookMode,
    descriptors: Vec<&'static Descriptor>,
}

fn group_resolved(
    resolved: Vec<(&'static Descriptor, *mut c_void)>,
) -> Result<Vec<ResolvedGroup>, String> {
    let mut groups = Vec::<ResolvedGroup>::new();
    for (descriptor, target) in resolved {
        if let Some(group) = groups.iter_mut().find(|group| group.target == target) {
            if !group.mode.compatible_with(descriptor.mode) {
                return Err(format!(
                    "Linux symbols '{}' and '{}' resolve to the same address with incompatible hooks",
                    group.descriptors[0].symbol, descriptor.symbol
                ));
            }
            group.descriptors.push(descriptor);
        } else {
            groups.push(ResolvedGroup {
                target,
                mode: descriptor.mode,
                descriptors: vec![descriptor],
            });
        }
    }
    Ok(groups)
}

enum InstalledHook {
    Replacement(*mut c_void),
    Listener(*mut gum::GumInvocationListener),
}

static INSTALLED: OnceLock<HookInstallReport> = OnceLock::new();

pub fn install() -> Result<&'static HookInstallReport, String> {
    if let Some(report) = INSTALLED.get() {
        return Ok(report);
    }
    unsafe {
        let interceptor = gum::initialize()?;
        let mut resolved = Vec::new();
        let mut report = HookInstallReport::default();
        for descriptor in DESCRIPTORS {
            match gum::find_export(descriptor.symbol) {
                Some(target) => resolved.push((descriptor, target)),
                None if descriptor.required => {
                    return Err(format!(
                        "required Linux symbol '{}' was not found",
                        descriptor.symbol
                    ));
                }
                None => report.optional_missing.push(descriptor.symbol),
            }
        }
        let groups = group_resolved(resolved)?;
        report.aliases = DESCRIPTORS.len() - report.optional_missing.len() - groups.len();
        gum::begin(interceptor);
        let mut installed = Vec::<InstalledHook>::new();
        for group in groups {
            let install_result = match group.mode {
                HookMode::Replace(replacement) => {
                    gum::replace(interceptor, group.target, replacement).and_then(|original| {
                        for descriptor in &group.descriptors {
                            gum::set_original(descriptor.symbol, original).map_err(|_| -5)?;
                        }
                        Ok(InstalledHook::Replacement(group.target))
                    })
                }
                HookMode::Listen(kind) => match gum::make_call_listener(
                    native::variadic_on_enter,
                    native::variadic_on_leave,
                    kind as *mut c_void,
                ) {
                    Ok(listener) => gum::attach(interceptor, group.target, listener)
                        .map(|_| InstalledHook::Listener(listener)),
                    Err(_) => Err(-5),
                },
            };
            match install_result {
                Ok(hook) => {
                    report.installed += group.descriptors.len();
                    installed.push(hook);
                }
                Err(status) => {
                    rollback(interceptor, &installed);
                    gum::end(interceptor);
                    return Err(format!(
                        "Gum failed installing '{}' status={status}",
                        group.descriptors[0].symbol
                    ));
                }
            }
        }
        gum::end(interceptor);
        INSTALLED
            .set(report)
            .map_err(|_| "Linux Gum already initialized".to_string())?;
        Ok(INSTALLED.get().expect("Linux Gum report was stored"))
    }
}

unsafe fn rollback(interceptor: *mut gum::GumInterceptor, installed: &[InstalledHook]) {
    for hook in installed.iter().rev() {
        match hook {
            InstalledHook::Replacement(target) => gum::revert(interceptor, *target),
            InstalledHook::Listener(listener) => gum::detach(interceptor, *listener),
        }
    }
}

pub(crate) fn manifest() -> Vec<(u32, &'static str, &'static str, bool)> {
    DESCRIPTORS
        .iter()
        .map(|descriptor| {
            (
                descriptor.id,
                descriptor.symbol,
                descriptor.semantic_hook,
                descriptor.required,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn descriptors_have_unique_complete_bindings() {
        let mut ids = HashSet::new();
        let mut symbols = HashSet::new();
        for descriptor in DESCRIPTORS {
            assert!(ids.insert(descriptor.id), "duplicate id {}", descriptor.id);
            assert!(
                symbols.insert(descriptor.symbol),
                "duplicate symbol {}",
                descriptor.symbol
            );
            match descriptor.mode {
                HookMode::Replace(replacement) => {
                    assert!(!replacement.is_null(), "{}", descriptor.symbol)
                }
                HookMode::Listen(kind) => assert_ne!(kind, 0, "{}", descriptor.symbol),
            }
            assert!(
                !descriptor.semantic_hook.is_empty(),
                "{}",
                descriptor.symbol
            );
        }
        assert_eq!(DESCRIPTORS.len(), 25);
        assert!(
            !DESCRIPTORS
                .iter()
                .find(|d| d.symbol == "open64")
                .unwrap()
                .required
        );
        assert!(
            !DESCRIPTORS
                .iter()
                .find(|d| d.symbol == "openat64")
                .unwrap()
                .required
        );
    }

    #[test]
    fn aliases_share_one_compatible_hook() {
        let open = DESCRIPTORS.iter().find(|d| d.symbol == "open").unwrap();
        let open64 = DESCRIPTORS.iter().find(|d| d.symbol == "open64").unwrap();
        let groups = group_resolved(vec![
            (open, 1usize as *mut c_void),
            (open64, 1usize as *mut c_void),
        ])
        .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].descriptors.len(), 2);
    }

    #[test]
    fn manifest_preserves_descriptor_order() {
        let manifest = manifest();
        assert_eq!(manifest.first().map(|entry| entry.1), Some("getaddrinfo"));
        assert_eq!(manifest.last().map(|entry| entry.1), Some("munmap"));
        assert_eq!(manifest[2].2, "socket.connect");
    }
}
