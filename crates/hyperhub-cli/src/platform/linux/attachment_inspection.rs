//! Reject an incompatible instrumentation base by a defined ELF dynamic ABI
//! export. Embedded Agent bytes inside an unrelated executable are not exports.
use std::collections::BTreeMap;
use std::io;

#[derive(Clone, Copy)]
struct Mapping {
    start: usize,
    end: usize,
    offset: u64,
}
struct Object<'a> {
    pid: u32,
    maps: &'a [Mapping],
}
impl Object<'_> {
    fn read(&self, address: usize, length: usize) -> Result<Vec<u8>, String> {
        if length > 64 * 1024 * 1024 {
            return Err("ELF inspection metadata exceeds its bounded size".into());
        }
        let mut bytes = vec![0u8; length];
        let mut copied = 0;
        while copied < length {
            let at = address
                .checked_add(copied)
                .ok_or("ELF inspection address overflow")?;
            let range = self
                .maps
                .iter()
                .find(|range| at >= range.start && at < range.end)
                .ok_or("ELF metadata is outside its readable object")?;
            let count = (length - copied).min(range.end - at);
            let local = libc::iovec {
                iov_base: bytes[copied..].as_mut_ptr().cast(),
                iov_len: count,
            };
            let remote = libc::iovec {
                iov_base: at as *mut _,
                iov_len: count,
            };
            let result =
                unsafe { libc::process_vm_readv(self.pid as i32, &local, 1, &remote, 1, 0) };
            if result <= 0 {
                return Err(format!(
                    "cannot inspect target ELF metadata: {}",
                    io::Error::last_os_error()
                ));
            }
            copied += result as usize;
        }
        Ok(bytes)
    }
    fn pointer(&self, bias: usize, value: u64) -> Result<usize, String> {
        let raw = usize::try_from(value)
            .map_err(|_| "ELF pointer is outside the native address space")?;
        if self
            .maps
            .iter()
            .any(|map| raw >= map.start && raw < map.end)
        {
            Ok(raw)
        } else {
            bias.checked_add(raw)
                .ok_or_else(|| "ELF load bias overflow".into())
        }
    }
    fn exported_agent_abi(&self) -> Result<bool, String> {
        let Some(first) = self.maps.iter().find(|map| map.offset == 0) else {
            return Ok(false);
        };
        let header = self.read(first.start, 64)?;
        if &header[..4] != b"\x7fELF" {
            return Ok(false);
        }
        if header[4] != 2 || header[5] != 1 {
            return Err(
                "live instrumentation requires a native 64-bit little-endian ELF target".into(),
            );
        }
        let phoff = usize::try_from(u64_at(&header, 32))
            .map_err(|_| "ELF program header offset overflow")?;
        let phentsize = u16_at(&header, 54) as usize;
        let phnum = u16_at(&header, 56) as usize;
        if phentsize < 56 || phnum > 4096 {
            return Err("ELF program headers are invalid".into());
        }
        let programs = self.read(
            first
                .start
                .checked_add(phoff)
                .ok_or("ELF program header address overflow")?,
            phentsize
                .checked_mul(phnum)
                .ok_or("ELF program header size overflow")?,
        )?;
        let mut bias = None;
        let mut dynamic = None;
        for program in programs.chunks_exact(phentsize) {
            let kind = u32_at(program, 0);
            if kind == 1 && u64_at(program, 8) == 0 {
                bias = first.start.checked_sub(u64_at(program, 16) as usize);
            }
            if kind == 2 {
                dynamic = Some((u64_at(program, 16), u64_at(program, 40)));
            }
        }
        let (Some(bias), Some((dynamic, size))) = (bias, dynamic) else {
            return Ok(false);
        };
        let dynamic = self.read(
            self.pointer(bias, dynamic)?,
            usize::try_from(size).map_err(|_| "ELF dynamic table size overflow")?,
        )?;
        let (mut symtab, mut strtab, mut strsize, mut syment, mut hash, mut gnu_hash) =
            (0, 0, 0, 24, 0, 0);
        for entry in dynamic.chunks_exact(16) {
            let value = u64_at(entry, 8);
            match u64_at(entry, 0) {
                0 => break,
                4 => hash = value,
                5 => strtab = value,
                6 => symtab = value,
                10 => strsize = value,
                11 => syment = value,
                0x6ffffef5 => gnu_hash = value,
                _ => {}
            }
        }
        if symtab == 0 || strtab == 0 {
            return Ok(false);
        }
        if syment != 24 {
            return Err("ELF dynamic symbol width is unsupported".into());
        }
        let count = if hash != 0 {
            u32_at(&self.read(self.pointer(bias, hash)?, 8)?, 4) as usize
        } else if gnu_hash != 0 {
            self.gnu_symbol_count(self.pointer(bias, gnu_hash)?)?
        } else {
            return Err("ELF dynamic symbol bound is unavailable".into());
        };
        if count > 1_000_000 {
            return Err("ELF dynamic symbol count exceeds its bounded size".into());
        }
        let symbols = self.read(
            self.pointer(bias, symtab)?,
            count.checked_mul(24).ok_or("ELF symbol size overflow")?,
        )?;
        let strings = self.read(
            self.pointer(bias, strtab)?,
            usize::try_from(strsize).map_err(|_| "ELF string table size overflow")?,
        )?;
        Ok(symbols
            .chunks_exact(24)
            .any(|symbol| is_agent_export(symbol, &strings)))
    }
    fn gnu_symbol_count(&self, address: usize) -> Result<usize, String> {
        let header = self.read(address, 16)?;
        let buckets = u32_at(&header, 0) as usize;
        let offset = u32_at(&header, 4) as usize;
        let bloom = u32_at(&header, 8) as usize;
        if buckets > 1_000_000 || bloom > 1_000_000 {
            return Err("ELF GNU hash table exceeds its bounded size".into());
        }
        let bucket_address = address
            .checked_add(16)
            .and_then(|value| value.checked_add(bloom.checked_mul(8)?))
            .ok_or("ELF GNU hash address overflow")?;
        let bucket_bytes = self.read(bucket_address, buckets * 4)?;
        let last = bucket_bytes
            .chunks_exact(4)
            .map(|bytes| u32_at(bytes, 0) as usize)
            .max()
            .unwrap_or(0);
        if last < offset {
            return Ok(offset);
        }
        let chains = bucket_address
            .checked_add(buckets * 4)
            .ok_or("ELF GNU hash chain address overflow")?;
        for index in last..1_000_000 {
            let at = chains
                .checked_add((index - offset) * 4)
                .ok_or("ELF GNU hash chain address overflow")?;
            if u32_at(&self.read(at, 4)?, 0) & 1 != 0 {
                return Ok(index + 1);
            }
        }
        Err("ELF GNU hash chain has no bounded terminator".into())
    }
}
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn is_agent_export(symbol: &[u8], strings: &[u8]) -> bool {
    let binding = symbol[4] >> 4;
    let kind = symbol[4] & 15;
    let visibility = symbol[5] & 3;
    if !matches!(binding, 1 | 2) || visibility == 1 || visibility == 2 || u16_at(symbol, 6) == 0 {
        return false;
    }
    let Some(name) = strings.get(u32_at(symbol, 0) as usize..) else {
        return false;
    };
    let name = &name[..name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len())];
    (kind == 2 && name == b"hh_agent_abi_version")
        || (kind == 1 && name == b"HH_AGENT_NATIVE_BASE_FINGERPRINT_V1")
}
pub(super) fn reject_incompatible_agent(pid: u32) -> Result<(), String> {
    let maps =
        std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|error| error.to_string())?;
    let mut objects: BTreeMap<(String, u64), Vec<Mapping>> = BTreeMap::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(protection), Some(offset), Some(device), Some(inode)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if !protection.starts_with('r') {
            continue;
        }
        let Ok(inode) = inode.parse::<u64>() else {
            continue;
        };
        if inode == 0 {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end), Ok(offset)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
            u64::from_str_radix(offset, 16),
        ) else {
            continue;
        };
        if end > start {
            objects
                .entry((device.to_owned(), inode))
                .or_default()
                .push(Mapping { start, end, offset });
        }
    }
    for maps in objects.values() {
        if (Object { pid, maps }).exported_agent_abi()? {
            return Err("target contains an incompatible HyperHub native Agent ABI without a current-instance attachment; refusing overlapping instrumentation".into());
        }
    }
    Ok(())
}
pub(super) fn matches_pinned_agent(pid: u32, device: u64, inode: u64) -> Result<bool, String> {
    let text =
        std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|error| error.to_string())?;
    let mut maps = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(protection), Some(offset), Some(dev), Some(number)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let Some((major, minor)) = dev.split_once(':') else {
            continue;
        };
        if !protection.starts_with('r')
            || number.parse::<u64>().ok() != Some(inode)
            || u32::from_str_radix(major, 16).ok() != Some(libc::major(device))
            || u32::from_str_radix(minor, 16).ok() != Some(libc::minor(device))
        {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end), Ok(offset)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
            u64::from_str_radix(offset, 16),
        ) else {
            continue;
        };
        maps.push(Mapping { start, end, offset });
    }
    if maps.is_empty() {
        return Ok(false);
    }
    (Object { pid, maps: &maps }).exported_agent_abi()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intrinsic_identity_requires_a_defined_export() {
        let strings = b"\0hh_agent_abi_version\0HH_AGENT_NATIVE_BASE_FINGERPRINT_V1\0";
        let mut symbol = [0u8; 24];
        symbol[0] = 1;
        symbol[4] = 0x12;
        symbol[6] = 1;
        assert!(is_agent_export(&symbol, strings));
        symbol[6] = 0;
        assert!(!is_agent_export(&symbol, strings));
        symbol[6] = 1;
        symbol[5] = 2;
        assert!(!is_agent_export(&symbol, strings));
        symbol[5] = 0;
        symbol[0] = 2;
        assert!(!is_agent_export(&symbol, strings));
    }
    #[test]
    fn embedded_bytes_are_not_dynamic_exports() {
        assert!(!is_agent_export(&[0u8; 24], b"hh_agent_abi_version\0"));
    }
}
