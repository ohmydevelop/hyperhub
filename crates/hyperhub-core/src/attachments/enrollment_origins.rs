//! A Core origin enters this set only at its own creation or through the
//! verified direct-parent pipe. Requests and disk records never add origins.
use super::ProcessIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub(super) const MAX_ORIGINS: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnrollmentOrigin {
    pub(super) pid: u32,
    pub(super) birth: u64,
}
impl EnrollmentOrigin {
    pub(super) fn current() -> Result<Self, String> {
        let pid = std::process::id();
        let birth = super::process_birth(pid).ok_or("cannot identify Core enrollment origin")?;
        Ok(Self { pid, birth })
    }
    pub(super) fn from_process(identity: &ProcessIdentity) -> Self {
        Self {
            pid: identity.pid,
            birth: identity.birth,
        }
    }
    fn valid(self) -> bool {
        self.pid != 0 && self.birth != 0
    }
}

pub(super) fn extend_origins(
    origins: &[EnrollmentOrigin],
    owner: EnrollmentOrigin,
    child: EnrollmentOrigin,
) -> Result<Vec<EnrollmentOrigin>, String> {
    let unique = origins.iter().copied().collect::<HashSet<_>>();
    if origins.is_empty()
        || origins.len() > MAX_ORIGINS
        || unique.len() != origins.len()
        || origins.iter().any(|origin| !origin.valid())
        || !owner.valid()
        || !child.valid()
        || !unique.contains(&owner)
    {
        return Err(
            "successor Core enrollment origins are malformed or lack their verified predecessor"
                .into(),
        );
    }
    let mut next = origins.to_vec();
    if !unique.contains(&child) {
        if next.len() == MAX_ORIGINS {
            return Err(
                "Core enrollment origin capacity reached; original Core remains active".into(),
            );
        }
        next.push(child);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn successor_origins_are_bounded_unique_and_never_evict_history() {
        let a = EnrollmentOrigin { pid: 1, birth: 11 };
        let b = EnrollmentOrigin { pid: 2, birth: 22 };
        let c = EnrollmentOrigin { pid: 3, birth: 33 };
        let ab = extend_origins(&[a], a, b).unwrap();
        let abc = extend_origins(&ab, b, c).unwrap();
        assert_eq!(abc, vec![a, b, c]);
        assert_eq!(extend_origins(&abc, c, c).unwrap(), abc);
        assert!(extend_origins(&[a, a], a, b).is_err());
        assert!(extend_origins(&[a], b, c).is_err());
        assert!(extend_origins(&[EnrollmentOrigin { pid: 0, birth: 11 }], a, b).is_err());
        let full = (1..=MAX_ORIGINS as u32)
            .map(|pid| EnrollmentOrigin {
                pid,
                birth: u64::from(pid),
            })
            .collect::<Vec<_>>();
        let original = full.clone();
        assert!(extend_origins(
            &full,
            full[0],
            EnrollmentOrigin {
                pid: 100,
                birth: 100
            }
        )
        .is_err());
        assert_eq!(full, original);
        let mut over = full.clone();
        over.push(EnrollmentOrigin {
            pid: 101,
            birth: 101,
        });
        assert!(extend_origins(&over, over[0], over[1]).is_err());
    }
}
