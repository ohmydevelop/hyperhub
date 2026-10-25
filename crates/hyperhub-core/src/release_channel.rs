//! Release precedence and default state isolation. Build metadata never changes precedence.

pub fn version(value: &str) -> Option<semver::Version> {
    let value = value.strip_prefix('v').unwrap_or(value);
    // Keep the existing numeric shorthand accepted by internal deployment fixtures.
    let normalized;
    let value = if value.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        match value.split('.').count() {
            1 => {
                normalized = format!("{value}.0.0");
                &normalized
            }
            2 => {
                normalized = format!("{value}.0");
                &normalized
            }
            _ => value,
        }
    } else {
        value
    };
    let mut parsed = semver::Version::parse(value).ok()?;
    parsed.build = semver::BuildMetadata::EMPTY;
    Some(parsed)
}

pub fn is_prerelease(value: &str) -> bool {
    version(value).is_some_and(|v| !v.pre.is_empty())
}

pub fn development_build() -> bool {
    is_prerelease(env!("CARGO_PKG_VERSION"))
}

pub fn default_home_name() -> &'static str {
    if development_build() {
        ".hyperhub-dev"
    } else {
        ".hyperhub"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_precedence_includes_prerelease_and_ignores_build_metadata() {
        let ordered = [
            "0.2.15",
            "0.3.0-alpha.1",
            "0.3.0-alpha.2",
            "0.3.0-alpha.10",
            "0.3.0-rc.1",
            "0.3.0",
        ];
        for pair in ordered.windows(2) {
            assert!(version(pair[0]).unwrap() < version(pair[1]).unwrap());
        }
        assert_eq!(version("v1.2.3+first"), version("1.2.3+second"));
        assert_eq!(version("1.2"), version("1.2.0"));
        assert_eq!(version("3"), version("3.0.0"));
    }

    #[test]
    fn invalid_releases_cannot_authorize_an_update() {
        for invalid in [
            "", "garbage", "1..2", "01.2.3", "1.2.3.4", "1.2.3-", "1.2.3+", "vv1.2.3",
        ] {
            assert!(version(invalid).is_none(), "{invalid}");
        }
        assert!(is_prerelease("0.3.0-alpha.1"));
        assert!(!is_prerelease("0.3.0+build"));
        assert!(!is_prerelease("broken-alpha"));
    }
}
