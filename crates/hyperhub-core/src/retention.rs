//! 审计事件与 transcript 的 `date=YYYY-MM-DD` 分区存储、归档与保留清理。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MS_PER_DAY: u64 = 86_400_000;

/// UTC epoch 毫秒 → 自 1970-01-01 起的天数（UTC 日期键）。
pub fn date_key(epoch_ms: u64) -> u32 {
    (epoch_ms / MS_PER_DAY) as u32
}

pub fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// 根目录 + UTC 日期键 → Hive 风格的 `root/date=YYYY-MM-DD` 分区。
pub fn date_partition_directory(root: &Path, key: u32) -> PathBuf {
    let (year, month, day) = civil_from_days(key as i64);
    root.join(format!("date={year:04}-{month:02}-{day:02}"))
}

/// 归档非当天日志，并按日期分区删除超过保留窗口的日志。
pub fn run_log_retention(root: &Path, file_name: &str, today_key: u32, retention_days: u32) {
    for (key, directory) in dated_directories(root) {
        if is_expired(key, today_key, retention_days) {
            let _ = fs::remove_file(directory.join(file_name));
            let _ = fs::remove_file(directory.join(format!("{file_name}.gz")));
            let _ = fs::remove_dir(&directory);
            continue;
        }
        if key < today_key {
            let source = directory.join(file_name);
            let destination = directory.join(format!("{file_name}.gz"));
            if source.is_file() && !destination.exists() {
                let _ = gzip_file(&source, &destination);
            }
        }
    }
}

/// 按日期分区删除超过保留窗口的 transcript；`0` 表示永久保留。
pub fn run_transcript_retention(root: &Path, today_key: u32, retention_days: u32) {
    for (key, directory) in dated_directories(root) {
        if is_expired(key, today_key, retention_days) {
            let _ = fs::remove_dir_all(&directory);
        }
    }
}

fn is_expired(key: u32, today_key: u32, retention_days: u32) -> bool {
    retention_days > 0 && key < today_key.saturating_sub(retention_days.saturating_sub(1))
}

fn dated_directories(root: &Path) -> Vec<(u32, PathBuf)> {
    let mut result = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return result;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(key) = entry.file_name().to_str().and_then(parse_partition_date) else {
            continue;
        };
        if date_partition_directory(root, key) == path {
            result.push((key, path));
        }
    }
    result
}

fn parse_partition_date(value: &str) -> Option<u32> {
    let value = value.strip_prefix("date=")?;
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return None;
    }
    let year = value[0..4].parse::<i64>().ok()?;
    let month = value[5..7].parse::<u32>().ok()?;
    let day = value[8..10].parse::<u32>().ok()?;
    u32::try_from(days_from_civil(year, month, day)?).ok()
}

fn gzip_file(source: &Path, destination: &Path) -> io::Result<()> {
    let input = fs::File::open(source)?;
    let output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
    let mut reader = io::BufReader::new(input);
    io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;
    fs::remove_file(source)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let adjusted_year = if month <= 2 { year - 1 } else { year };
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let yoe = (adjusted_year - era * 400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe as i64 - 719468;
    let (actual_year, actual_month, actual_day) = civil_from_days(days);
    (actual_year == year && actual_month == month && actual_day == day).then_some(days)
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146096
    } / 146097;
    let doe = (shifted - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hyperhub-{name}-{}-{}",
            std::process::id(),
            unix_timestamp_ms()
        ))
    }

    #[test]
    fn date_key_maps_to_hive_partition() {
        let key = parse_partition_date("date=2026-01-09").unwrap();
        assert_eq!(
            date_partition_directory(Path::new("audit"), key),
            Path::new("audit").join("date=2026-01-09")
        );
        assert!(parse_partition_date("date=2026-02-30").is_none());
    }

    #[test]
    fn retention_archives_kept_days_and_removes_expired_partitions() {
        let root = test_root("retention");
        let old_key = parse_partition_date("date=2026-01-01").unwrap();
        let yesterday_key = parse_partition_date("date=2026-01-08").unwrap();
        let today_key = parse_partition_date("date=2026-01-09").unwrap();
        for key in [old_key, yesterday_key, today_key] {
            let directory = date_partition_directory(&root, key);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("hyperhub.jsonl"), b"log").unwrap();
        }

        run_log_retention(&root, "hyperhub.jsonl", today_key, 3);

        assert!(!date_partition_directory(&root, old_key).exists());
        assert!(date_partition_directory(&root, yesterday_key)
            .join("hyperhub.jsonl.gz")
            .is_file());
        assert!(date_partition_directory(&root, today_key)
            .join("hyperhub.jsonl")
            .is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn log_retention_does_not_delete_unrelated_files_in_a_date_partition() {
        let root = test_root("retention-shared-directory");
        let old_key = parse_partition_date("date=2026-01-01").unwrap();
        let today_key = parse_partition_date("date=2026-01-09").unwrap();
        let directory = date_partition_directory(&root, old_key);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("hyperhub.jsonl"), b"log").unwrap();
        fs::write(directory.join("unrelated.txt"), b"keep").unwrap();

        run_log_retention(&root, "hyperhub.jsonl", today_key, 3);

        assert!(!directory.join("hyperhub.jsonl").exists());
        assert_eq!(fs::read(directory.join("unrelated.txt")).unwrap(), b"keep");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn transcript_retention_removes_only_expired_partitions() {
        let root = test_root("transcript-retention");
        let old_key = parse_partition_date("date=2026-01-01").unwrap();
        let today_key = parse_partition_date("date=2026-01-09").unwrap();
        for key in [old_key, today_key] {
            let directory = date_partition_directory(&root, key).join("session-1");
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("1-up.bin"), b"capture").unwrap();
        }

        run_transcript_retention(&root, today_key, 3);

        assert!(!date_partition_directory(&root, old_key).exists());
        assert!(date_partition_directory(&root, today_key)
            .join("session-1")
            .join("1-up.bin")
            .is_file());
        let _ = fs::remove_dir_all(root);
    }
}
