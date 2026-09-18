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

/// 从旧 `{stem}-YYYYMMDD.jsonl[.gz]` 文件名解析日期键。
pub fn parse_legacy_log_date(stem: &str, file_name: &str) -> Option<u32> {
    let prefix = format!("{stem}-");
    let name = file_name.strip_prefix(&prefix)?;
    let name = name
        .strip_suffix(".jsonl.gz")
        .or_else(|| name.strip_suffix(".jsonl"))?;
    parse_compact_date(name)
}

/// 把旧平铺日志迁移到日期目录。发生目标冲突时保留源文件，不覆盖已有数据。
pub fn migrate_legacy_logs(base: &Path, root: &Path, stem: &str, file_name: &str) {
    if base.is_file() {
        if let Some(key) = modified_date_key(base) {
            let destination = date_partition_directory(root, key).join(file_name);
            move_without_overwrite(base, &destination);
        }
    }

    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let source = entry.path();
        if !source.is_file() || source == base {
            continue;
        }
        let Some(name) = source.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(key) = parse_legacy_log_date(stem, name) else {
            continue;
        };
        let destination_name = if name.ends_with(".gz") {
            format!("{file_name}.gz")
        } else {
            file_name.to_string()
        };
        let destination = date_partition_directory(root, key).join(destination_name);
        move_without_overwrite(&source, &destination);
    }

    for (key, legacy_directory) in legacy_dated_directories(root) {
        for legacy_name in [file_name.to_string(), format!("{file_name}.gz")] {
            let source = legacy_directory.join(&legacy_name);
            if source.is_file() {
                let destination = date_partition_directory(root, key).join(legacy_name);
                move_without_overwrite(&source, &destination);
            }
        }
        prune_empty_legacy_date_parents(root, &legacy_directory);
    }
}

/// 把旧平铺或 `YYYY/MM/DD` transcript 目录迁移到日期分区。
pub fn migrate_legacy_transcripts(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let source = entry.path();
        if !source.is_dir() {
            continue;
        }
        let Some(name) = source.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if is_year_component(name) || parse_partition_date(name).is_some() {
            continue;
        }
        let Some(key) = modified_date_key(&source) else {
            continue;
        };
        let destination = date_partition_directory(root, key).join(name);
        move_without_overwrite(&source, &destination);
    }

    for (key, legacy_directory) in legacy_dated_directories(root) {
        let Ok(sessions) = fs::read_dir(&legacy_directory) else {
            continue;
        };
        for session in sessions.flatten() {
            let source = session.path();
            if !source.is_dir() {
                continue;
            }
            let destination = date_partition_directory(root, key).join(session.file_name());
            move_without_overwrite(&source, &destination);
        }
        prune_empty_legacy_date_parents(root, &legacy_directory);
    }
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

fn legacy_dated_directories(root: &Path) -> Vec<(u32, PathBuf)> {
    let mut result = Vec::new();
    let Ok(years) = fs::read_dir(root) else {
        return result;
    };
    for year in years.flatten() {
        let year_path = year.path();
        let Some(year) = year.file_name().to_str().and_then(parse_year) else {
            continue;
        };
        let Ok(months) = fs::read_dir(&year_path) else {
            continue;
        };
        for month in months.flatten() {
            let month_path = month.path();
            let Some(month) = month.file_name().to_str().and_then(parse_two_digits) else {
                continue;
            };
            let Ok(days) = fs::read_dir(&month_path) else {
                continue;
            };
            for day in days.flatten() {
                let day_path = day.path();
                let Some(day) = day.file_name().to_str().and_then(parse_two_digits) else {
                    continue;
                };
                let Some(days) = days_from_civil(year, month, day) else {
                    continue;
                };
                if let Ok(key) = u32::try_from(days) {
                    result.push((key, day_path));
                }
            }
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

fn parse_compact_date(value: &str) -> Option<u32> {
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let year = value[0..4].parse::<i64>().ok()?;
    let month = value[4..6].parse::<u32>().ok()?;
    let day = value[6..8].parse::<u32>().ok()?;
    u32::try_from(days_from_civil(year, month, day)?).ok()
}

fn parse_year(value: &str) -> Option<i64> {
    (is_year_component(value))
        .then(|| value.parse().ok())
        .flatten()
}

fn is_year_component(value: &str) -> bool {
    value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_two_digits(value: &str) -> Option<u32> {
    if value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

fn modified_date_key(path: &Path) -> Option<u32> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| date_key(duration.as_millis().min(u64::MAX as u128) as u64))
}

fn move_without_overwrite(source: &Path, destination: &Path) {
    if destination.exists() {
        return;
    }
    let Some(parent) = destination.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_ok() {
        let _ = fs::rename(source, destination);
    }
}

fn prune_empty_legacy_date_parents(root: &Path, day_directory: &Path) {
    let Some(month) = day_directory.parent() else {
        return;
    };
    let Some(year) = month.parent() else {
        return;
    };
    let _ = fs::remove_dir(day_directory);
    if month != root {
        let _ = fs::remove_dir(month);
    }
    if year != root {
        let _ = fs::remove_dir(year);
    }
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
        let key = parse_compact_date("20260109").unwrap();
        assert_eq!(
            date_partition_directory(Path::new("audit"), key),
            Path::new("audit").join("date=2026-01-09")
        );
        assert!(parse_compact_date("20260230").is_none());
    }

    #[test]
    fn migrates_flat_logs_into_the_date_partition() {
        let root = test_root("log-migration");
        fs::create_dir_all(&root).unwrap();
        let base = root.join("hyperhub.jsonl");
        let legacy = root.join("hyperhub-20260108.jsonl");
        fs::write(&base, b"base").unwrap();
        fs::write(&legacy, b"legacy").unwrap();
        migrate_legacy_logs(&base, &root, "hyperhub", "hyperhub.jsonl");

        let legacy_key = parse_compact_date("20260108").unwrap();
        assert_eq!(
            fs::read(date_partition_directory(&root, legacy_key).join("hyperhub.jsonl")).unwrap(),
            b"legacy"
        );
        assert!(!legacy.exists());
        assert!(!base.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn migration_keeps_both_files_when_the_destination_exists() {
        let root = test_root("log-migration-collision");
        let key = parse_compact_date("20260108").unwrap();
        let destination = date_partition_directory(&root, key).join("hyperhub.jsonl");
        let legacy = root.join("hyperhub-20260108.jsonl");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, b"destination").unwrap();
        fs::write(&legacy, b"legacy").unwrap();

        migrate_legacy_logs(
            &root.join("hyperhub.jsonl"),
            &root,
            "hyperhub",
            "hyperhub.jsonl",
        );

        assert_eq!(fs::read(destination).unwrap(), b"destination");
        assert_eq!(fs::read(&legacy).unwrap(), b"legacy");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn migrates_the_previous_nested_log_layout() {
        let root = test_root("nested-log-migration");
        let key = parse_compact_date("20260108").unwrap();
        let legacy_directory = root.join("2026").join("01").join("08");
        fs::create_dir_all(&legacy_directory).unwrap();
        fs::write(legacy_directory.join("hyperhub.jsonl"), b"legacy").unwrap();

        migrate_legacy_logs(
            &root.join("hyperhub.jsonl"),
            &root,
            "hyperhub",
            "hyperhub.jsonl",
        );

        assert_eq!(
            fs::read(date_partition_directory(&root, key).join("hyperhub.jsonl")).unwrap(),
            b"legacy"
        );
        assert!(!root.join("2026").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn retention_archives_kept_days_and_removes_expired_partitions() {
        let root = test_root("retention");
        let old_key = parse_compact_date("20260101").unwrap();
        let yesterday_key = parse_compact_date("20260108").unwrap();
        let today_key = parse_compact_date("20260109").unwrap();
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
        let old_key = parse_compact_date("20260101").unwrap();
        let today_key = parse_compact_date("20260109").unwrap();
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
        let old_key = parse_compact_date("20260101").unwrap();
        let today_key = parse_compact_date("20260109").unwrap();
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

    #[test]
    fn migrates_legacy_transcript_sessions_into_the_current_date_partition() {
        let root = test_root("transcript-migration");
        let session = root.join("session-1");
        fs::create_dir_all(&session).unwrap();
        fs::write(session.join("1-up.bin"), b"capture").unwrap();

        migrate_legacy_transcripts(&root);

        let destination =
            date_partition_directory(&root, date_key(unix_timestamp_ms())).join("session-1");
        assert_eq!(fs::read(destination.join("1-up.bin")).unwrap(), b"capture");
        assert!(!session.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn migrates_the_previous_nested_transcript_layout() {
        let root = test_root("nested-transcript-migration");
        let key = parse_compact_date("20260108").unwrap();
        let legacy_session = root.join("2026").join("01").join("08").join("session-1");
        fs::create_dir_all(&legacy_session).unwrap();
        fs::write(legacy_session.join("1-up.bin"), b"capture").unwrap();

        migrate_legacy_transcripts(&root);

        assert_eq!(
            fs::read(
                date_partition_directory(&root, key)
                    .join("session-1")
                    .join("1-up.bin")
            )
            .unwrap(),
            b"capture"
        );
        assert!(!root.join("2026").exists());
        let _ = fs::remove_dir_all(root);
    }
}
