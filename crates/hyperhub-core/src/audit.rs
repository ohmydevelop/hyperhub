use crate::policy::ConnectionContext;
use crate::retention::{
    date_key, date_partition_directory, run_log_retention, run_transcript_retention,
    unix_timestamp_ms,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize)]
pub struct TranscriptMetadata {
    pub direction: &'static str,
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub captured_size: u64,
    pub truncated: bool,
}

#[derive(Debug)]
struct AuditOutput {
    root: Option<PathBuf>,
    file_name: String,
    current_date: Option<u32>,
    file: Option<File>,
    transcript_dir: Option<PathBuf>,
    retention_days: u32,
    debug: bool,
    debug_output: Option<PathBuf>,
    debug_file: Option<File>,
    now_ms: fn() -> u64,
    run_id: String,
    next_sequence: u64,
}

#[derive(Debug, Clone)]
pub struct AuditWriter(Arc<Mutex<AuditOutput>>);

const AUDIT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy)]
enum AuditCategory {
    Connection,
    Session,
    System,
}

impl AuditCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Session => "session",
            Self::System => "system",
        }
    }
}

impl AuditWriter {
    pub fn open(path: Option<&Path>) -> std::io::Result<Self> {
        Self::open_with_debug(path, false)
    }

    pub fn open_with_debug(path: Option<&Path>, debug: bool) -> std::io::Result<Self> {
        Self::open_with_debug_output(path, debug, None)
    }

    pub fn open_with_debug_output(
        path: Option<&Path>,
        debug: bool,
        debug_output: Option<&Path>,
    ) -> std::io::Result<Self> {
        Self::open_with_retention(path, None, 0, debug, debug_output)
    }

    pub fn open_with_retention(
        path: Option<&Path>,
        transcript_dir: Option<&Path>,
        retention_days: u32,
        debug: bool,
        debug_output: Option<&Path>,
    ) -> std::io::Result<Self> {
        Self::open_with_retention_and_clock(
            path,
            transcript_dir,
            retention_days,
            debug,
            debug_output,
            unix_timestamp_ms,
        )
    }

    fn open_with_retention_and_clock(
        path: Option<&Path>,
        transcript_dir: Option<&Path>,
        retention_days: u32,
        debug: bool,
        debug_output: Option<&Path>,
        clock: fn() -> u64,
    ) -> std::io::Result<Self> {
        let base = path.map(Path::to_path_buf);
        let dir = base
            .as_ref()
            .and_then(|path| path.parent())
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .or_else(|| base.as_ref().map(|_| PathBuf::from(".")));
        let file_name = base
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("security-alerts.jsonl")
            .to_string();
        let now = clock();
        let today = date_key(now);
        let run_id = new_run_id(now);
        if let Some(dir) = dir.as_ref() {
            run_log_retention(dir, &file_name, today, retention_days);
        }
        if let Some(transcript_dir) = transcript_dir {
            run_transcript_retention(transcript_dir, today, retention_days);
        }
        let file = match dir.as_ref() {
            Some(dir) => open_daily(dir, &file_name, today).ok(),
            None => None,
        };
        let debug_output = debug_output.map(Path::to_path_buf);
        let debug_file = if debug {
            open_append(debug_output.as_deref())?
        } else {
            None
        };
        Ok(Self(Arc::new(Mutex::new(AuditOutput {
            root: dir,
            file_name,
            current_date: Some(today),
            file,
            transcript_dir: transcript_dir.map(Path::to_path_buf),
            retention_days,
            debug,
            debug_output,
            debug_file,
            now_ms: clock,
            run_id,
            next_sequence: 1,
        }))))
    }

    /// 热更新详细调试事件输出。关闭时立即停止输出；再次开启时重新打开输出文件。
    pub fn set_debug(&self, enabled: bool) -> std::io::Result<()> {
        let mut guard = self.0.lock().expect("audit mutex poisoned");
        if guard.debug == enabled {
            return Ok(());
        }
        if enabled {
            guard.debug_file = open_append(guard.debug_output.as_deref())?;
        } else {
            guard.debug_file = None;
        }
        guard.debug = enabled;
        Ok(())
    }

    pub fn debug_enabled(&self) -> bool {
        self.0.lock().expect("audit mutex poisoned").debug
    }

    pub fn connection(
        &self,
        event: &str,
        context: &ConnectionContext,
        rule_id: Option<&str>,
        action: &str,
        outcome: &str,
        bytes: Option<(u64, u64)>,
        duration_ms: Option<u128>,
        attributes: Option<Value>,
    ) {
        let mut dimensions = Map::new();
        dimensions.insert("session_id".into(), json!(context.session_id));
        dimensions.insert("connection_id".into(), json!(context.connection_id));
        dimensions.insert("process_pid".into(), json!(context.process.pid));
        dimensions.insert(
            "process_executable".into(),
            json!(context.process.executable),
        );
        dimensions.insert("destination_ip".into(), json!(context.destination.ip));
        dimensions.insert(
            "destination_hostname".into(),
            json!(context.destination.hostnames.first()),
        );
        dimensions.insert("destination_port".into(), json!(context.destination.port));
        dimensions.insert("protocol".into(), json!(context.protocol));
        dimensions.insert("rule_id".into(), json!(rule_id));
        dimensions.insert("action".into(), json!(action));
        dimensions.insert("outcome".into(), json!(outcome));
        dimensions.insert("bytes_up".into(), json!(bytes.map(|value| value.0)));
        dimensions.insert("bytes_down".into(), json!(bytes.map(|value| value.1)));
        dimensions.insert(
            "duration_ms".into(),
            json!(duration_ms.map(|value| value.min(u64::MAX as u128) as u64)),
        );
        self.write_record(
            AuditCategory::Connection,
            event,
            dimensions,
            attributes.unwrap_or_else(empty_attributes),
        );
    }

    /// 当前审计文件的实际路径（配置路径会展开为 `date=YYYY-MM-DD` 分区）。
    pub fn current_log_path(&self) -> Option<PathBuf> {
        let guard = self.0.lock().ok()?;
        guard.file.as_ref()?;
        Some(
            date_partition_directory(guard.root.as_deref()?, guard.current_date?)
                .join(&guard.file_name),
        )
    }

    pub fn system_event(&self, event: &str, attributes: Value) {
        self.write_record(AuditCategory::System, event, Map::new(), attributes);
    }

    pub fn session_event(
        &self,
        event: &str,
        session_id: &str,
        process_pid: Option<u32>,
        process_executable: Option<&str>,
        attributes: Value,
    ) {
        let mut dimensions = Map::new();
        dimensions.insert("session_id".into(), json!(session_id));
        dimensions.insert("process_pid".into(), json!(process_pid));
        dimensions.insert("process_executable".into(), json!(process_executable));
        self.write_record(AuditCategory::Session, event, dimensions, attributes);
    }

    pub fn security_alert(
        &self,
        session_id: &str,
        process_pid: Option<u32>,
        process_executable: Option<&str>,
        attributes: Value,
    ) {
        self.session_event(
            "security_alert",
            session_id,
            process_pid,
            process_executable,
            attributes,
        );
    }

    pub fn security_debug(
        &self,
        session_id: &str,
        process_pid: Option<u32>,
        process_executable: Option<&str>,
        attributes: Value,
    ) {
        let mut dimensions = Map::new();
        dimensions.insert("session_id".into(), json!(session_id));
        dimensions.insert("process_pid".into(), json!(process_pid));
        dimensions.insert("process_executable".into(), json!(process_executable));
        self.write_record_debug_only(
            AuditCategory::Session,
            "security_debug",
            dimensions,
            attributes,
        );
    }

    fn write_record(
        &self,
        category: AuditCategory,
        event: &str,
        dimensions: Map<String, Value>,
        attributes: Value,
    ) {
        self.write_record_inner(category, event, dimensions, attributes, false);
    }

    fn write_record_debug_only(
        &self,
        category: AuditCategory,
        event: &str,
        dimensions: Map<String, Value>,
        attributes: Value,
    ) {
        self.write_record_inner(category, event, dimensions, attributes, true);
    }

    fn write_record_inner(
        &self,
        category: AuditCategory,
        event: &str,
        mut dimensions: Map<String, Value>,
        attributes: Value,
        debug_only: bool,
    ) {
        let Ok(mut guard) = self.0.lock() else {
            return;
        };
        let now = (guard.now_ms)();
        let today = date_key(now);
        if guard.current_date != Some(today) || guard.file.is_none() {
            if guard.current_date != Some(today) {
                if let Some(root) = &guard.root {
                    run_log_retention(root, &guard.file_name, today, guard.retention_days);
                }
                if let Some(transcript_dir) = &guard.transcript_dir {
                    run_transcript_retention(transcript_dir, today, guard.retention_days);
                }
                guard.current_date = Some(today);
            }
            guard.file = guard
                .root
                .as_ref()
                .and_then(|root| open_daily(root, &guard.file_name, today).ok());
        }
        let sequence = guard.next_sequence;
        guard.next_sequence = guard.next_sequence.saturating_add(1);
        let mut record = Map::new();
        record.insert("schema_version".into(), json!(AUDIT_SCHEMA_VERSION));
        record.insert("timestamp_ms".into(), json!(now));
        record.insert("run_id".into(), json!(guard.run_id));
        record.insert("sequence".into(), json!(sequence));
        record.insert("category".into(), json!(category.as_str()));
        record.insert("event".into(), json!(event));
        record.append(&mut dimensions);
        record.insert("attributes".into(), normalize_attributes(attributes));
        let Ok(line) = serde_json::to_vec(&record) else {
            return;
        };
        if guard.debug {
            if let Some(file) = guard.debug_file.as_mut() {
                if file.write_all(b"[hyperhub-debug] ").is_ok()
                    && file.write_all(&line).is_ok()
                    && file.write_all(b"\n").is_ok()
                {
                    let _ = file.flush();
                }
            } else {
                eprintln!("[hyperhub-debug] {}", String::from_utf8_lossy(&line));
            }
        }
        if debug_only {
            return;
        }
        let Some(file) = guard.file.as_mut() else {
            return;
        };
        if file.write_all(&line).is_ok() {
            let _ = file.write_all(b"\n");
            let _ = file.flush();
        }
    }
}

fn open_append(path: Option<&Path>) -> std::io::Result<Option<File>> {
    let Some(path) = path else {
        return Ok(None);
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(Some)
}

fn open_daily(root: &Path, file_name: &str, today: u32) -> std::io::Result<File> {
    let path = date_partition_directory(root, today).join(file_name);
    open_append(Some(&path)).map(|file| file.expect("daily audit file"))
}

fn new_run_id(started_at_ms: u64) -> String {
    format!(
        "{started_at_ms:013x}-{:08x}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    )
}

fn empty_attributes() -> Value {
    Value::Object(Map::new())
}

fn normalize_attributes(value: Value) -> Value {
    match value {
        Value::Object(_) => value,
        Value::Null => empty_attributes(),
        value => json!({ "value": value }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn epoch_clock() -> u64 {
        0
    }

    #[test]
    fn writes_to_the_date_partition_and_reports_the_actual_path() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-audit-layout-test-{}-{}",
            std::process::id(),
            unix_timestamp_ms()
        ));
        let template = root.join("hyperhub.jsonl");
        let writer = AuditWriter::open_with_retention_and_clock(
            Some(&template),
            None,
            7,
            false,
            None,
            epoch_clock,
        )
        .unwrap();
        let expected = root.join("date=1970-01-01").join("hyperhub.jsonl");
        assert_eq!(
            writer.current_log_path().as_deref(),
            Some(expected.as_path())
        );
        writer.system_event("layout_test", serde_json::json!({}));
        assert!(expected.is_file());
        let record: Value = serde_json::from_str(
            std::fs::read_to_string(&expected)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(record["schema_version"], 2);
        assert_eq!(record["category"], "system");
        assert_eq!(record["event"], "layout_test");
        assert_eq!(record["sequence"], 1);
        assert!(record["run_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(record["attributes"].is_object());
        drop(writer);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn emits_stable_dimensions_and_deduplication_keys() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-audit-schema-test-{}-{}",
            std::process::id(),
            unix_timestamp_ms()
        ));
        let template = root.join("hyperhub.jsonl");
        let writer = AuditWriter::open_with_retention_and_clock(
            Some(&template),
            None,
            7,
            false,
            None,
            epoch_clock,
        )
        .unwrap();
        writer.session_event(
            "session_auth",
            "session-1",
            Some(42),
            Some("ssh.exe"),
            json!({"mode": "password"}),
        );
        let context = crate::policy::ConnectionContext {
            session_id: "session-1".into(),
            connection_id: 7,
            process: crate::policy::ProcessInfo {
                pid: 42,
                tid: 42,
                executable: "ssh.exe".into(),
            },
            destination: crate::policy::Destination {
                ip: "127.0.0.1".parse().unwrap(),
                port: 22,
                hostnames: vec!["host.example".into()],
            },
            protocol: crate::policy::Protocol::Ssh,
        };
        writer.connection(
            "close",
            &context,
            Some("ssh-rule"),
            "proxy",
            "closed",
            Some((10, 20)),
            Some(30),
            None,
        );
        drop(writer);

        let path = date_partition_directory(&root, 0).join("hyperhub.jsonl");
        let records = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["category"], "session");
        assert_eq!(records[0]["session_id"], "session-1");
        assert_eq!(records[0]["process_pid"], 42);
        assert_eq!(records[0]["process_executable"], "ssh.exe");
        assert_eq!(records[0]["attributes"]["mode"], "password");
        assert!(records[0].get("client_pid").is_none());
        assert_eq!(records[1]["category"], "connection");
        assert_eq!(records[1]["process_pid"], 42);
        assert_eq!(records[1]["destination_hostname"], "host.example");
        assert_eq!(records[1]["duration_ms"], 30);
        assert!(records[1].get("pid").is_none());
        assert_eq!(records[0]["run_id"], records[1]["run_id"]);
        assert_eq!(records[0]["sequence"], 1);
        assert_eq!(records[1]["sequence"], 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn security_alerts_are_canonical_and_debug_passes_are_debug_only() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-security-alert-test-{}-{}",
            std::process::id(),
            unix_timestamp_ms()
        ));
        let audit_path = root.join("security-alerts.jsonl");
        let debug_path = root.join("security-debug.log");
        let writer =
            AuditWriter::open_with_debug_output(Some(&audit_path), true, Some(&debug_path))
                .unwrap();
        writer.security_alert(
            "session-1",
            Some(42),
            Some("/usr/bin/bash"),
            serde_json::json!({
                "kind": "process",
                "operation": "create",
                "action": "deny",
                "enforcement": "blocked",
                "target": "/usr/bin/rm",
                "process_argv_redacted": ["bash", "-c", "rm -rf ."],
                "target_argv_redacted": ["rm", "-rf", "."]
            }),
        );
        writer.security_debug(
            "session-1",
            Some(42),
            Some("/usr/bin/bash"),
            serde_json::json!({
                "kind": "process",
                "operation": "create",
                "action": "allow",
                "enforcement": "allowed"
            }),
        );
        drop(writer);

        let audit = std::fs::read_to_string(
            date_partition_directory(&root, date_key(unix_timestamp_ms()))
                .join("security-alerts.jsonl"),
        )
        .unwrap();
        let records = audit
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["schema_version"], 2);
        assert_eq!(records[0]["event"], "security_alert");
        assert_eq!(
            records[0]["attributes"]["target_argv_redacted"],
            serde_json::json!(["rm", "-rf", "."])
        );
        let debug = std::fs::read_to_string(debug_path).unwrap();
        assert!(debug.contains("security_debug"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn creates_audit_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-audit-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = root.join("nested").join("audit.jsonl");
        let writer = AuditWriter::open(Some(&path)).unwrap();
        drop(writer);
        let dated = date_partition_directory(&root.join("nested"), date_key(unix_timestamp_ms()))
            .join("audit.jsonl");
        assert!(dated.is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn debug_output_can_be_toggled_without_restarting_the_writer() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-debug-toggle-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = root.join("terminal.log");
        let writer = AuditWriter::open_with_debug_output(None, false, Some(&path)).unwrap();

        assert!(!writer.debug_enabled());
        writer.system_event("disabled_event", serde_json::json!({}));
        assert!(!path.exists());

        writer.set_debug(true).unwrap();
        assert!(writer.debug_enabled());
        writer.system_event("enabled_event", serde_json::json!({}));
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("enabled_event"));
        let content_len = content.len();

        writer.set_debug(false).unwrap();
        assert!(!writer.debug_enabled());
        writer.system_event("disabled_again_event", serde_json::json!({}));
        let unchanged = std::fs::read_to_string(&path).unwrap();
        assert_eq!(unchanged.len(), content_len);
        assert!(!unchanged.contains("disabled_again_event"));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn writes_debug_events_to_the_selected_terminal_output() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-debug-output-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = root.join("terminal.log");
        let writer = AuditWriter::open_with_debug_output(None, true, Some(&path)).unwrap();
        writer.system_event("test_event", serde_json::json!({"value": 1}));
        drop(writer);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[hyperhub-debug]"));
        assert!(content.contains("test_event"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

pub fn redact_header(name: &str, value: &str, allowlist: &[String]) -> Option<String> {
    if [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
    ]
    .iter()
    .any(|item| name.eq_ignore_ascii_case(item))
    {
        return Some("[REDACTED]".into());
    }
    if allowlist.iter().any(|item| name.eq_ignore_ascii_case(item)) {
        Some(value.into())
    } else {
        None
    }
}

pub fn redact_path(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}
