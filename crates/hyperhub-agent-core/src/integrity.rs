use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub(crate) fn verify_agent_runtime(path: &Path) -> Result<(), ()> {
    let Some(expected_hash) = std::env::var_os("HYPERHUB_AGENT_SHA256") else {
        return Ok(());
    };
    let expected_hash = parse_hash(&expected_hash.to_string_lossy()).ok_or(())?;
    let expected_size = std::env::var("HYPERHUB_AGENT_SIZE")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(())?;
    let mut file = std::fs::File::open(path).map_err(|_| ())?;
    if file.metadata().map_err(|_| ())?.len() != expected_size {
        return Err(());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    (actual == expected_hash).then_some(()).ok_or(())
}

fn parse_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut result = [0u8; 32];
    for (index, output) in result.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_complete_sha256_values() {
        assert_eq!(parse_hash(&"00".repeat(32)), Some([0; 32]));
        assert!(parse_hash("00").is_none());
        assert!(parse_hash(&"gg".repeat(32)).is_none());
    }
}
