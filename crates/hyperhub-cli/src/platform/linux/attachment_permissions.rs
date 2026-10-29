//! Read-only gates for injection paths whose future ptrace rights are unknown.
use hyperhub_core::attachments::{Backend, Scope};

fn classify_gum_permission(scope: Scope, yama: u32) -> Result<(), String> {
    match (scope, yama) {
        (_, 0) => Ok(()),
        (Scope::Process, 1) => Err(format!(
            "gum_requires_unrestricted_ptrace: Yama ptrace_scope={yama}; preserving protection across root exec requires Frida's creation monitor, whose fork recovery cannot preserve target behavior here; use --backend ptrace"
        )),
        (Scope::Tree, 1 | 2) => Err(format!(
            "gum_tree_requires_unrestricted_ptrace: Yama ptrace_scope={yama}; future children do not inherit the target's debugger permission and Frida may terminate them during recovery; use --backend ptrace"
        )),
        (_, 2 | 3) => Err(format!(
            "gum_injection_permission_unproven: Yama ptrace_scope={yama}; use --backend ptrace where supported"
        )),
        _ => Err("gum_injection_permission_unproven: unrecognized Yama ptrace_scope".into()),
    }
}

pub fn validate_attachment_backend(
    _pid: u32,
    scope: Scope,
    backend: Backend,
) -> Result<(), String> {
    if backend != Backend::Gum {
        return Ok(());
    }
    let yama = match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(value) => value.trim().parse::<u32>().map_err(|_| {
            "gum_injection_permission_unproven: invalid Yama ptrace_scope".to_string()
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => {
            return Err(format!(
                "gum_injection_permission_unproven: cannot read Yama ptrace_scope: {error}"
            ))
        }
    };
    classify_gum_permission(scope, yama)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_yama_never_promises_future_child_permissions() {
        for scope in [Scope::Process, Scope::Tree] {
            assert!(classify_gum_permission(scope, 0).is_ok());
            assert!(classify_gum_permission(scope, 3).is_err());
            assert!(classify_gum_permission(scope, 99).is_err());
        }
        assert!(classify_gum_permission(Scope::Process, 1)
            .unwrap_err()
            .contains("gum_requires_unrestricted_ptrace"));
        for yama in [1, 2] {
            assert!(classify_gum_permission(Scope::Tree, yama)
                .unwrap_err()
                .contains("gum_tree_requires_unrestricted_ptrace"));
        }
        assert!(classify_gum_permission(Scope::Process, 2).is_err());
    }
}
