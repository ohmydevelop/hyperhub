use crate::contract::*;
pub(crate) fn execute(input: &[u8]) -> Result<Vec<u8>, i32> {
    if input.len() < 8 || input.len() > MAX_TRUST_REQUEST {
        return Err(INVALID);
    }
    let extension_len = u32::from_le_bytes(input[..4].try_into().map_err(|_| INVALID)?) as usize;
    let root_len = u32::from_le_bytes(input[4..8].try_into().map_err(|_| INVALID)?) as usize;
    let root_start = 8usize.checked_add(extension_len).ok_or(INVALID)?;
    let source_start = root_start.checked_add(root_len).ok_or(INVALID)?;
    if extension_len > 16 || root_len > 1024 * 1024 || source_start > input.len() {
        return Err(INVALID);
    }
    let extension = std::str::from_utf8(&input[8..root_start]).map_err(|_| INVALID)?;
    let root = &input[root_start..source_start];
    let source = &input[source_start..];
    if extension == "!der" {
        return Ok(if !root.is_empty() && source == root {
            vec![1]
        } else {
            Vec::new()
        });
    }
    if source.len() > 32 * 1024 * 1024
        || (!extension.is_empty()
            && !matches!(
                extension.to_ascii_lowercase().as_str(),
                "pem" | "crt" | "cer"
            ))
        || !contains(source, b"-----BEGIN CERTIFICATE-----")
        || contains(source, b"PRIVATE KEY-----")
    {
        return Ok(Vec::new());
    }
    let mut output = source.to_vec();
    if !output.ends_with(b"\n") {
        output.push(b'\n');
    }
    if !root.is_empty() && !contains(source, root) {
        output.extend_from_slice(root);
        if !output.ends_with(b"\n") {
            output.push(b'\n');
        }
    }
    Ok(output)
}
fn contains(input: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && input.windows(needle.len()).any(|w| w == needle)
}
