use std::path::Path;

pub fn exact(path: &Path) -> String {
    exact_for_platform(&path.to_string_lossy(), cfg!(windows))
}

fn exact_for_platform(path: &str, windows: bool) -> String {
    // Match the Windows file adapter's object_path/handle_path representation.
    // A backslash is a literal filename character on POSIX and stays intact.
    let normalized = if windows {
        path.trim_start_matches(r"\??\")
            .trim_start_matches(r"\\?\")
            .replace('\\', "/")
    } else {
        path.to_owned()
    };
    format!("^{}$", regex::escape(&normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_paths_match_the_normalized_adapter_path_exactly() {
        let normalized = "C:/Users/runner.name/AppData/Local/Temp/hh-[one](two)+$/dummy^.txt";
        for raw in [
            r"C:\Users\runner.name\AppData\Local\Temp\hh-[one](two)+$\dummy^.txt",
            r"\??\C:\Users\runner.name\AppData\Local\Temp\hh-[one](two)+$\dummy^.txt",
            r"\\?\C:\Users\runner.name\AppData\Local\Temp\hh-[one](two)+$\dummy^.txt",
        ] {
            let pattern = regex::Regex::new(&exact_for_platform(raw, true)).unwrap();
            assert!(pattern.is_match(normalized));
            assert!(!pattern.is_match(raw));
            for different in [
                format!("prefix{normalized}"),
                format!("{normalized}.bak"),
                normalized.replace('.', "X"),
                normalized.replace('[', ""),
            ] {
                assert!(
                    !pattern.is_match(&different),
                    "literal path pattern matched a different path: {different}"
                );
            }
        }
    }

    #[test]
    fn posix_paths_keep_literal_backslashes_and_regex_characters() {
        let raw = r"/var/tmp/hh-[one](two)+$/literal\dummy^.txt";
        let pattern = regex::Regex::new(&exact_for_platform(raw, false)).unwrap();
        assert!(pattern.is_match(raw));
        assert!(!pattern.is_match(&raw.replace('\\', "/")));
        assert!(!pattern.is_match(&raw.replace('.', "X")));
        assert!(!pattern.is_match(&format!("{raw}.bak")));
        assert!(!pattern.is_match(&format!("prefix{raw}")));
    }
}
