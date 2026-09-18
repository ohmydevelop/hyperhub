pub fn normalize_executable(executable: &str) -> String {
    executable.trim().replace('\\', "/")
}
