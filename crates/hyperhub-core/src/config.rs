use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

/// 默认路由在配置界面、策略决策与审计中的稳定保留 ID。
pub const DEFAULT_ROUTE_ID: &str = "default";

fn default_socks_listen() -> String {
    "127.0.0.1:18444".into()
}
fn default_pending_session_ttl_secs() -> u64 {
    60
}
fn default_timeout_ms() -> u64 {
    10_000
}
fn default_body_limit() -> usize {
    1024 * 1024
}
fn default_protection_scan_bytes() -> usize {
    1024 * 1024
}
fn default_provenance_window_bytes() -> usize {
    64
}
fn default_provenance_min_matches() -> usize {
    3
}
fn default_guard_timeout_ms() -> u64 {
    2_000
}
fn default_guard_min_confidence() -> f64 {
    0.60
}
fn default_guard_cache_ttl_ms() -> u64 {
    30_000
}
fn default_retention_days() -> u32 {
    7
}
fn default_true() -> bool {
    true
}

/// Generate the stable identity used by independently editable configuration items.
pub fn new_config_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn legacy_config_uuid(kind: &str, identity: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"hyperhub/config-item-uuid/v1\0");
    hash.update(kind.as_bytes());
    hash.update([0]);
    hash.update(identity.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

pub fn valid_config_uuid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(index, character)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                character == '-'
            } else {
                character.is_ascii_hexdigit()
            }
        })
        && matches!(value.as_bytes()[14].to_ascii_lowercase(), b'1'..=b'5')
        && matches!(
            value.as_bytes()[19].to_ascii_lowercase(),
            b'8' | b'9' | b'a' | b'b'
        )
}

fn default_firewall_default() -> Option<FirewallDefaultRule> {
    Some(FirewallDefaultRule {
        action: FirewallAction::Pass,
    })
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid TOML in {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Validation(String),
    #[error("secret environment variable is not set: {0}")]
    MissingSecretEnv(String),
    #[error("failed to read secret file {path}: {source}")]
    SecretFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("secret file is accessible by group or others: {0}")]
    InsecureSecretFile(PathBuf),
}

#[derive(Debug, Clone, Serialize)]
pub struct Config {
    #[serde(default)]
    pub mode: EnforcementMode,
    /// 输出详细的运行时调试事件；可通过配置界面热更新。
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub default_route: DefaultRoute,
    #[serde(default)]
    pub listener: ListenerConfig,
    #[serde(default)]
    pub audit: AuditPolicy,
    #[serde(default)]
    pub environment: Vec<EnvironmentVariable>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    #[serde(default)]
    pub protections: Vec<ProtectionProfile>,
    #[serde(default)]
    pub root_certificates: Vec<RootCertificate>,
    #[serde(default)]
    pub ssh_host_keys: Vec<SshHostKey>,
    #[serde(default, rename = "routes")]
    pub rules: Vec<RouteRule>,
    /// 用于在校验阶段为已移除的顶层字段生成可操作的迁移错误。
    #[serde(default, flatten)]
    pub legacy: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct ConfigWire {
    #[serde(default)]
    mode: EnforcementMode,
    #[serde(default)]
    debug: bool,
    #[serde(default)]
    firewall: FirewallConfig,
    #[serde(default)]
    sandbox: SandboxConfig,
    #[serde(default)]
    default_route: DefaultRoute,
    #[serde(default)]
    listener: ListenerConfig,
    #[serde(default)]
    audit: AuditPolicy,
    #[serde(default)]
    environment: Vec<EnvironmentVariable>,
    #[serde(default)]
    upstreams: Vec<Upstream>,
    #[serde(default)]
    plugins: Vec<PluginConfig>,
    #[serde(default)]
    protections: Vec<ProtectionProfile>,
    #[serde(default)]
    root_certificates: Vec<RootCertificate>,
    #[serde(default)]
    ssh_host_keys: Vec<SshHostKey>,
    #[serde(default, rename = "routes")]
    rules: Vec<RouteRule>,
    #[serde(default, flatten)]
    legacy: HashMap<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ConfigWire::deserialize(deserializer)?;
        let mut config = Self {
            mode: wire.mode,
            debug: wire.debug,
            firewall: wire.firewall,
            sandbox: wire.sandbox,
            default_route: wire.default_route,
            listener: wire.listener,
            audit: wire.audit,
            environment: wire.environment,
            upstreams: wire.upstreams,
            plugins: wire.plugins,
            protections: wire.protections,
            root_certificates: wire.root_certificates,
            ssh_host_keys: wire.ssh_host_keys,
            rules: wire.rules,
            legacy: wire.legacy,
        };
        config.ensure_item_uuids();
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Enforce,
            debug: false,
            firewall: FirewallConfig::default(),
            sandbox: SandboxConfig::default(),
            default_route: DefaultRoute::default(),
            listener: ListenerConfig::default(),
            audit: AuditPolicy::default(),
            environment: Vec::new(),
            upstreams: Vec::new(),
            plugins: Vec::new(),
            protections: Vec::new(),
            root_certificates: Vec::new(),
            ssh_host_keys: Vec::new(),
            rules: Vec::new(),
            legacy: HashMap::new(),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.apply_managed_audit_paths(path);
        config.validate()?;
        Ok(config)
    }

    /// 审计存储由 HyperHub 托管，固定放在活动配置文件旁的 `audit/` 目录。
    /// 旧配置中的路径字段只保留反序列化兼容，加载后统一覆盖。
    pub fn apply_managed_audit_paths(&mut self, config_path: &Path) {
        let root = config_path.parent().unwrap_or_else(|| Path::new("."));
        let audit_root = root.join("audit");
        self.audit.log = Some(audit_root.join("hyperhub.jsonl"));
        self.audit.transcript_dir = Some(audit_root.join("transcripts"));
    }

    /// Return the complete serializable configuration with every inline secret
    /// replaced. Environment and file secret references remain visible because
    /// they do not contain the referenced secret value.
    pub fn redacted(&self) -> Self {
        let mut config = self.clone();
        for variable in &mut config.environment {
            variable.value.redact();
        }
        for upstream in &mut config.upstreams {
            if let Some(username) = &mut upstream.username {
                username.redact();
            }
            if let Some(password) = &mut upstream.password {
                password.redact();
            }
            for value in upstream.headers.values_mut() {
                value.redact();
            }
        }
        for plugin in &mut config.plugins {
            if let Some(secret) = &mut plugin.secret {
                secret.redact();
            }
            if let Some(password) = &mut plugin.password {
                password.redact();
            }
            for value in plugin.headers.values_mut() {
                value.redact();
            }
            for account in &mut plugin.ssh_accounts {
                for private_key in &mut account.private_keys {
                    private_key.value.redact();
                }
                for password in &mut account.passwords {
                    password.redact();
                }
            }
        }
        for protection in &mut config.protections {
            for provider in &mut protection.intelligence.providers {
                if let Some(api_key) = &mut provider.api_key {
                    api_key.redact();
                }
            }
        }
        config
    }

    pub fn ensure_item_uuids(&mut self) {
        let ensure = |uuid: &mut String, kind: &str, identity: &str| {
            if uuid.is_empty() {
                *uuid = legacy_config_uuid(kind, identity);
            }
        };
        for item in &mut self.upstreams {
            ensure(&mut item.uuid, "upstream", &item.id);
        }
        for item in &mut self.plugins {
            ensure(&mut item.uuid, "plugin", &item.id);
        }
        for protection in &mut self.protections {
            ensure(&mut protection.uuid, "protection", &protection.id);
            for provider in &mut protection.intelligence.providers {
                ensure(
                    &mut provider.uuid,
                    "protection-provider",
                    &format!("{}|{}", protection.id, provider.id),
                );
            }
        }
        for item in &mut self.rules {
            ensure(&mut item.uuid, "route", &item.id);
        }
        for item in &mut self.environment {
            ensure(&mut item.uuid, "environment", &item.name);
        }
        for item in &mut self.root_certificates {
            ensure(
                &mut item.uuid,
                "root-certificate",
                &format!(
                    "{}|{}",
                    item.host.as_deref().unwrap_or("global"),
                    item.fingerprint
                ),
            );
        }
        for item in &mut self.ssh_host_keys {
            ensure(&mut item.uuid, "ssh-host-key", &item.host);
        }
        for item in &mut self.firewall.rules {
            ensure(&mut item.uuid, "network-rule", &item.id);
        }
        for item in &mut self.sandbox.process.rules {
            ensure(&mut item.uuid, "process-rule", &item.id);
        }
        for item in &mut self.sandbox.file.rules {
            ensure(&mut item.uuid, "file-rule", &item.id);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_legacy()?;
        self.validate_item_uuids()?;
        let listen = self
            .listener
            .socks_listen
            .parse::<std::net::SocketAddr>()
            .map_err(|_| {
                ConfigError::Validation("listener.socks_listen must be an IP socket address".into())
            })?;
        if !listen.ip().is_loopback() {
            return Err(ConfigError::Validation(
                "listener.socks_listen must use a loopback address".into(),
            ));
        }
        if listen.port() == 0 {
            return Err(ConfigError::Validation(
                "listener.socks_listen must use a non-zero port".into(),
            ));
        }
        if self.listener.pending_session_ttl_secs == 0 {
            return Err(ConfigError::Validation(
                "listener.pending_session_ttl_secs must be positive".into(),
            ));
        }
        let mut environment_names = HashSet::new();
        for variable in &self.environment {
            let normalized = variable.name.to_ascii_uppercase();
            if !valid_environment_name(&variable.name) {
                return Err(ConfigError::Validation(format!(
                    "environment variable '{}' has an invalid name",
                    variable.name
                )));
            }
            if normalized.starts_with("HYPERHUB_") {
                return Err(ConfigError::Validation(format!(
                    "environment variable '{}' uses the reserved HYPERHUB_ prefix",
                    variable.name
                )));
            }
            if !environment_names.insert(normalized) {
                return Err(ConfigError::Validation(format!(
                    "duplicate environment variable '{}'",
                    variable.name
                )));
            }
            if let SecretValue::Inline { value } = &variable.value {
                if value.contains('\0') {
                    return Err(ConfigError::Validation(format!(
                        "environment variable '{}' contains a NUL character",
                        variable.name
                    )));
                }
            }
        }
        let upstream_ids = unique_ids("upstream", self.upstreams.iter().map(|v| v.id.as_str()))?;
        for upstream in &self.upstreams {
            upstream
                .address
                .parse::<std::net::SocketAddr>()
                .map_err(|_| {
                    ConfigError::Validation(format!(
                        "upstream '{}' address must be an IP socket address",
                        upstream.id
                    ))
                })?;
            if upstream.kind == UpstreamKind::Socks5
                && upstream.username.is_some() != upstream.password.is_some()
            {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}' SOCKS5 username and password must be configured together",
                    upstream.id
                )));
            }
            validate_headers(
                &upstream.headers,
                &format!("upstream '{}'", upstream.id),
                true,
            )?;
        }

        let _plugin_ids = unique_ids("plugin", self.plugins.iter().map(|v| v.id.as_str()))?;
        for plugin in &self.plugins {
            reject_removed_fields(&plugin.legacy, &format!("plugin '{}'", plugin.id))?;
            validate_headers(&plugin.headers, &format!("plugin '{}'", plugin.id), false)?;
            if plugin.protocols.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "plugin '{}' must declare at least one protocol",
                    plugin.id
                )));
            }
            match plugin.kind {
                PluginKind::Audit => {
                    if plugin.body_limit == 0 {
                        return Err(ConfigError::Validation(format!(
                            "audit plugin '{}' content transcript limit (body_limit) must be positive",
                            plugin.id
                        )));
                    }
                    let legacy_git_transcript = plugin.git_transcript.is_none()
                        && plugin.protocols.contains(&PluginProtocol::Git);
                    if plugin.capture_body
                        && !plugin.protocols.contains(&PluginProtocol::Http)
                        && !legacy_git_transcript
                    {
                        return Err(ConfigError::Validation(format!(
                            "audit plugin '{}' enables HTTP content transcript (capture_body) but does not declare the http protocol",
                            plugin.id
                        )));
                    }
                    if plugin.ssh_transcript && !plugin.protocols.contains(&PluginProtocol::Ssh) {
                        return Err(ConfigError::Validation(format!(
                            "audit plugin '{}' enables SSH content transcript (ssh_transcript) but does not declare the ssh protocol",
                            plugin.id
                        )));
                    }
                    if plugin.git_transcript_enabled()
                        && !plugin.protocols.contains(&PluginProtocol::Git)
                    {
                        return Err(ConfigError::Validation(format!(
                            "audit plugin '{}' enables Git content transcript (git_transcript) but does not declare the git protocol",
                            plugin.id
                        )));
                    }
                    if plugin.websocket_capture != WebSocketCapture::Off
                        && !plugin.protocols.contains(&PluginProtocol::Ws)
                    {
                        return Err(ConfigError::Validation(format!(
                            "audit plugin '{}' enables WS content transcript (websocket_capture) but does not declare the ws protocol",
                            plugin.id
                        )));
                    }
                    if plugin.content_transcript_enabled()
                        && !plugin.transcript_client_upload
                        && !plugin.transcript_server_response
                    {
                        return Err(ConfigError::Validation(format!(
                            "audit plugin '{}' enables content transcript but disables both transcript directions",
                            plugin.id
                        )));
                    }
                    if plugin.http_scheme.is_some()
                        || plugin.secret.is_some()
                        || plugin.http_name.is_some()
                        || plugin.username.is_some()
                        || plugin.password.is_some()
                        || !plugin.ssh_accounts.is_empty()
                        || !plugin.headers.is_empty()
                    {
                        return Err(ConfigError::Validation(format!(
                            "audit plugin '{}' cannot contain credential fields",
                            plugin.id
                        )));
                    }
                }
                PluginKind::Credential => validate_credential_fields(plugin)?,
                PluginKind::Convert => {
                    return Err(ConfigError::Validation(format!(
                        "convert plugin '{}' is not implemented yet",
                        plugin.id
                    )));
                }
            }
        }

        let protection_ids = unique_ids(
            "protection",
            self.protections.iter().map(|value| value.id.as_str()),
        )?;
        for protection in &self.protections {
            if protection.data.max_scan_bytes == 0 {
                return Err(ConfigError::Validation(format!(
                    "protection '{}' max_scan_bytes must be positive",
                    protection.id
                )));
            }
            if !(16..=4096).contains(&protection.data.provenance_window_bytes) {
                return Err(ConfigError::Validation(format!(
                    "protection '{}' provenance_window_bytes must be between 16 and 4096",
                    protection.id
                )));
            }
            if protection.data.provenance_min_matches == 0 {
                return Err(ConfigError::Validation(format!(
                    "protection '{}' provenance_min_matches must be positive",
                    protection.id
                )));
            }
            if protection.intelligence.timeout_ms == 0 {
                return Err(ConfigError::Validation(format!(
                    "protection '{}' intelligence timeout_ms must be positive",
                    protection.id
                )));
            }
            if !(0.0..=1.0).contains(&protection.intelligence.min_confidence) {
                return Err(ConfigError::Validation(format!(
                    "protection '{}' intelligence min_confidence must be between 0 and 1",
                    protection.id
                )));
            }
            let _provider_ids = unique_ids(
                "protection provider",
                protection
                    .intelligence
                    .providers
                    .iter()
                    .map(|provider| provider.id.as_str()),
            )?;
            for provider in &protection.intelligence.providers {
                if !provider.enabled {
                    continue;
                }
                let (endpoint, model, requires_key) = match provider.provider {
                    IntelligenceProviderKind::Typesafe => (
                        provider
                            .endpoint
                            .as_deref()
                            .unwrap_or("https://api.typesafe.ai/v1/systemone"),
                        provider.model.as_deref().unwrap_or("jev-latest"),
                        true,
                    ),
                    IntelligenceProviderKind::Openrouter => (
                        provider
                            .endpoint
                            .as_deref()
                            .unwrap_or("https://openrouter.ai/api/v1/systemone"),
                        provider.model.as_deref().unwrap_or("typesafe/jev-1.13"),
                        true,
                    ),
                    IntelligenceProviderKind::Custom => (
                        provider.endpoint.as_deref().ok_or_else(|| {
                            ConfigError::Validation(format!(
                                "custom provider '{}' in protection '{}' requires endpoint",
                                provider.id, protection.id
                            ))
                        })?,
                        provider.model.as_deref().ok_or_else(|| {
                            ConfigError::Validation(format!(
                                "custom provider '{}' in protection '{}' requires model",
                                provider.id, protection.id
                            ))
                        })?,
                        false,
                    ),
                };
                if model.trim().is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "provider '{}' in protection '{}' requires a non-empty model",
                        provider.id, protection.id
                    )));
                }
                if requires_key && provider.api_key.is_none() {
                    return Err(ConfigError::Validation(format!(
                        "provider '{}' in protection '{}' requires api_key",
                        provider.id, protection.id
                    )));
                }
                let url = reqwest::Url::parse(endpoint).map_err(|error| {
                    ConfigError::Validation(format!(
                        "provider '{}' in protection '{}' has invalid endpoint: {error}",
                        provider.id, protection.id
                    ))
                })?;
                let http_loopback = url.scheme() == "http"
                    && url.host_str().is_some_and(|host| {
                        host.eq_ignore_ascii_case("localhost")
                            || host
                                .parse::<std::net::IpAddr>()
                                .is_ok_and(|ip| ip.is_loopback())
                    });
                if url.scheme() != "https" && !http_loopback {
                    return Err(ConfigError::Validation(format!(
                        "provider '{}' in protection '{}' must use HTTPS unless endpoint is loopback HTTP",
                        provider.id, protection.id
                    )));
                }
            }
        }

        if self.default_route.allow_sensitive_upload {
            return Err(ConfigError::Validation(
                "default_route cannot allow sensitive uploads".into(),
            ));
        }
        if self.default_route.deny && self.default_route.protection_enabled {
            return Err(ConfigError::Validation(
                "default_route cannot enable protection while deny is true".into(),
            ));
        }
        if self.default_route.protection_enabled {
            let id = self.default_route.protection.as_deref().ok_or_else(|| {
                ConfigError::Validation(
                    "default_route protection_enabled requires protection".into(),
                )
            })?;
            if !protection_ids.contains(id) {
                return Err(ConfigError::Validation(format!(
                    "default_route references unknown protection '{id}'"
                )));
            }
        }

        let mut certificate_fingerprints = HashSet::new();
        for certificate in &self.root_certificates {
            if certificate.fingerprint.len() != 64
                || !certificate
                    .fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(ConfigError::Validation(format!(
                    "root certificate fingerprint '{}' must be a 64-character hex SHA-256",
                    certificate.fingerprint
                )));
            }
            if let Some(host) = certificate.host.as_deref() {
                validate_trust_host(host).map_err(ConfigError::Validation)?;
            }
            let identity = (
                certificate
                    .host
                    .as_deref()
                    .unwrap_or("global")
                    .to_ascii_lowercase(),
                certificate.fingerprint.to_ascii_lowercase(),
            );
            if !certificate_fingerprints.insert(identity) {
                return Err(ConfigError::Validation(format!(
                    "duplicate TLS trust certificate '{}' for '{}'",
                    certificate.fingerprint,
                    certificate.host.as_deref().unwrap_or("global")
                )));
            }
        }

        let mut ssh_hosts = HashSet::new();
        for key in &self.ssh_host_keys {
            if key.host.trim().is_empty()
                || key.key_type.trim().is_empty()
                || key.key_blob.trim().is_empty()
            {
                return Err(ConfigError::Validation(format!(
                    "SSH host key entry is incomplete"
                )));
            }
            if !ssh_hosts.insert(key.host.clone()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate SSH host key for '{}'",
                    key.host
                )));
            }
        }

        let mut sandbox_process_ids = HashSet::new();
        for rule in &self.sandbox.process.rules {
            if rule.id.trim().is_empty() || !sandbox_process_ids.insert(rule.id.clone()) {
                return Err(ConfigError::Validation(format!(
                    "empty or duplicate process sandbox rule id '{}'",
                    rule.id
                )));
            }
            if !rule.enabled {
                continue;
            }
            validate_sandbox_protection(
                &protection_ids,
                rule.protection_enabled,
                rule.protection.as_deref(),
                &format!("process sandbox rule '{}'", rule.id),
            )?;
            if !rule.patterns.iter().any(|pattern| pattern.enabled) {
                return Err(ConfigError::Validation(format!(
                    "process sandbox rule '{}' must contain an enabled regex pattern",
                    rule.id
                )));
            }
            for pattern in &rule.patterns {
                if pattern.executable.trim().is_empty() && pattern.command_line.trim().is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "process sandbox rule '{}' contains an empty regex pattern",
                        rule.id
                    )));
                }
                for value in [&pattern.executable, &pattern.command_line] {
                    if !value.is_empty() {
                        regex::Regex::new(value).map_err(|error| {
                            ConfigError::Validation(format!(
                                "process sandbox rule '{}' contains invalid regex '{}': {error}",
                                rule.id, value
                            ))
                        })?;
                    }
                }
            }
        }
        let mut sandbox_file_ids = HashSet::new();
        for rule in &self.sandbox.file.rules {
            if rule.id.trim().is_empty() || !sandbox_file_ids.insert(rule.id.clone()) {
                return Err(ConfigError::Validation(format!(
                    "empty or duplicate file sandbox rule id '{}'",
                    rule.id
                )));
            }
            if !rule.enabled {
                continue;
            }
            validate_sandbox_protection(
                &protection_ids,
                rule.protection_enabled,
                rule.protection.as_deref(),
                &format!("file sandbox rule '{}'", rule.id),
            )?;
            if !rule.patterns.iter().any(|pattern| pattern.enabled) {
                return Err(ConfigError::Validation(format!(
                    "file sandbox rule '{}' must contain an enabled regex pattern",
                    rule.id
                )));
            }
            for pattern in &rule.patterns {
                if pattern.pattern.trim().is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "file sandbox rule '{}' contains an empty regex pattern",
                        rule.id
                    )));
                }
                regex::Regex::new(&pattern.pattern).map_err(|error| {
                    ConfigError::Validation(format!(
                        "file sandbox rule '{}' contains invalid regex '{}': {error}",
                        rule.id, pattern.pattern
                    ))
                })?;
            }
            if rule.operations.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "file sandbox rule '{}' must contain at least one operation",
                    rule.id
                )));
            }
        }

        let mut firewall_rule_ids = HashSet::new();
        for rule in &self.firewall.rules {
            if rule.id.trim().is_empty() || !firewall_rule_ids.insert(rule.id.clone()) {
                return Err(ConfigError::Validation(format!(
                    "empty or duplicate firewall rule id '{}'",
                    rule.id
                )));
            }
            if !rule.enabled {
                continue;
            }
            if rule.endpoints.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "firewall rule '{}' must contain at least one endpoint",
                    rule.id
                )));
            }
            for endpoint in &rule.endpoints {
                match parse_route_target(&endpoint.target).map_err(|message| {
                    ConfigError::Validation(format!(
                        "firewall rule '{}' contains invalid target '{}': {message}",
                        rule.id, endpoint.target
                    ))
                })? {
                    RouteTarget::Domain {
                        path_prefix: Some(_),
                        ..
                    } => {
                        return Err(ConfigError::Validation(format!(
                            "firewall rule '{}' target '{}' cannot contain a URL path",
                            rule.id, endpoint.target
                        )));
                    }
                    _ => {}
                }
            }
            if rule
                .endpoints
                .iter()
                .any(|endpoint| endpoint.port == Some(0))
            {
                return Err(ConfigError::Validation(format!(
                    "firewall rule '{}' contains invalid port 0",
                    rule.id
                )));
            }
        }

        let mut rule_ids = HashSet::new();
        for rule in &self.rules {
            if rule.id.trim() == DEFAULT_ROUTE_ID {
                return Err(ConfigError::Validation(format!(
                    "route id '{DEFAULT_ROUTE_ID}' is reserved for the built-in default route"
                )));
            }
            if rule.id.trim().is_empty() || !rule_ids.insert(rule.id.clone()) {
                return Err(ConfigError::Validation(format!(
                    "empty or duplicate route id '{}'",
                    rule.id
                )));
            }
            if !rule.enabled {
                continue;
            }
            if rule.endpoints.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "route '{}' must contain at least one target; use default_route for a global action",
                    rule.id
                )));
            }
            for endpoint in &rule.endpoints {
                if endpoint.port == Some(0) {
                    return Err(ConfigError::Validation(format!(
                        "route '{}' contains invalid port 0",
                        rule.id
                    )));
                }
                parse_route_target(&endpoint.target).map_err(|message| {
                    ConfigError::Validation(format!(
                        "route '{}' contains invalid target '{}': {message}",
                        rule.id, endpoint.target
                    ))
                })?;
            }
            if rule.protection_enabled {
                let id = rule.protection.as_deref().ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "route '{}' protection_enabled requires protection",
                        rule.id
                    ))
                })?;
                if !protection_ids.contains(id) {
                    return Err(ConfigError::Validation(format!(
                        "route '{}' references unknown protection '{id}'",
                        rule.id
                    )));
                }
            }
            if rule.allow_sensitive_upload {
                for endpoint in &rule.endpoints {
                    match parse_route_target(&endpoint.target).map_err(ConfigError::Validation)? {
                        RouteTarget::Domain {
                            wildcard: false, ..
                        } => {}
                        _ => {
                            return Err(ConfigError::Validation(format!(
                                "route '{}' can allow sensitive uploads only for exact domain targets",
                                rule.id
                            )));
                        }
                    }
                }
            }
            if rule.deny
                && (rule.upstream.is_some()
                    || !rule.plugins.is_empty()
                    || rule.protection_enabled
                    || rule.allow_sensitive_upload
                    || rule.rewrite_host.is_some()
                    || rule.rewrite_port.is_some())
            {
                return Err(ConfigError::Validation(format!(
                    "deny route '{}' cannot configure forwarding or plugins",
                    rule.id
                )));
            }
            if let Some(id) = &rule.upstream {
                if !upstream_ids.contains(id) {
                    return Err(ConfigError::Validation(format!(
                        "route '{}' references unknown upstream '{id}'",
                        rule.id
                    )));
                }
            }
            let mut bound: HashSet<(PluginKind, PluginProtocol)> = HashSet::new();
            for id in &rule.plugins {
                let Some(plugin) = self.plugin(id) else {
                    return Err(ConfigError::Validation(format!(
                        "route '{}' references unknown plugin '{id}'",
                        rule.id
                    )));
                };
                if plugin.kind == PluginKind::Convert {
                    return Err(ConfigError::Validation(format!(
                        "route '{}' references unimplemented convert plugin '{id}'",
                        rule.id
                    )));
                }
                for protocol in &plugin.protocols {
                    if !bound.insert((plugin.kind, *protocol)) {
                        return Err(ConfigError::Validation(format!(
                            "route '{}' binds multiple {} plugins for the same protocol",
                            rule.id,
                            match plugin.kind {
                                PluginKind::Audit => "audit",
                                PluginKind::Credential => "credential",
                                PluginKind::Convert => "convert",
                            }
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_item_uuids(&self) -> Result<(), ConfigError> {
        let mut seen = HashSet::new();
        let mut register = |kind: &str, name: &str, uuid: &str| {
            if !valid_config_uuid(uuid) {
                return Err(ConfigError::Validation(format!(
                    "{kind} '{name}' has invalid UUID '{uuid}'"
                )));
            }
            if !seen.insert(uuid.to_ascii_lowercase()) {
                return Err(ConfigError::Validation(format!(
                    "{kind} '{name}' reuses configuration UUID '{uuid}'"
                )));
            }
            Ok(())
        };
        for item in &self.upstreams {
            register("upstream", &item.id, &item.uuid)?;
        }
        for item in &self.plugins {
            register("plugin", &item.id, &item.uuid)?;
        }
        for protection in &self.protections {
            register("protection", &protection.id, &protection.uuid)?;
            for provider in &protection.intelligence.providers {
                register("protection provider", &provider.id, &provider.uuid)?;
            }
        }
        for item in &self.rules {
            register("route", &item.id, &item.uuid)?;
        }
        for item in &self.environment {
            register("environment variable", &item.name, &item.uuid)?;
        }
        for item in &self.root_certificates {
            register("root certificate", &item.fingerprint, &item.uuid)?;
        }
        for item in &self.ssh_host_keys {
            register("SSH host key", &item.host, &item.uuid)?;
        }
        for item in &self.firewall.rules {
            register("network rule", &item.id, &item.uuid)?;
        }
        for item in &self.sandbox.process.rules {
            register("process sandbox rule", &item.id, &item.uuid)?;
        }
        for item in &self.sandbox.file.rules {
            register("file sandbox rule", &item.id, &item.uuid)?;
        }
        Ok(())
    }

    fn validate_legacy(&self) -> Result<(), ConfigError> {
        reject_removed_fields(&self.legacy, "top level")?;
        for rule in &self.firewall.rules {
            reject_removed_fields(&rule.legacy, &format!("firewall rule '{}'", rule.id))?;
        }
        for rule in &self.sandbox.process.rules {
            reject_removed_fields(&rule.legacy, &format!("process sandbox rule '{}'", rule.id))?;
        }
        for rule in &self.sandbox.file.rules {
            reject_removed_fields(&rule.legacy, &format!("file sandbox rule '{}'", rule.id))?;
        }
        for rule in &self.rules {
            reject_removed_fields(&rule.legacy, &format!("route '{}'", rule.id))?;
        }
        Ok(())
    }

    pub fn upstream(&self, id: &str) -> Option<&Upstream> {
        self.upstreams.iter().find(|v| v.id == id)
    }
    pub fn plugin(&self, id: &str) -> Option<&PluginConfig> {
        self.plugins.iter().find(|v| v.id == id)
    }
    pub fn protection(&self, id: &str) -> Option<&ProtectionProfile> {
        self.protections.iter().find(|value| value.id == id)
    }
}

fn validate_sandbox_protection(
    protection_ids: &HashSet<String>,
    enabled: bool,
    protection: Option<&str>,
    owner: &str,
) -> Result<(), ConfigError> {
    if !enabled {
        return Ok(());
    }
    let id = protection.ok_or_else(|| {
        ConfigError::Validation(format!("{owner} protection_enabled requires protection"))
    })?;
    if !protection_ids.contains(id) {
        return Err(ConfigError::Validation(format!(
            "{owner} references unknown protection '{id}'"
        )));
    }
    Ok(())
}

fn reject_removed_fields(
    legacy: &HashMap<String, serde_json::Value>,
    owner: &str,
) -> Result<(), ConfigError> {
    let mut keys = legacy.keys().collect::<Vec<_>>();
    keys.sort_unstable();
    for key in keys {
        let migration = match key.as_str() {
            "targets" if owner.starts_with("route '") => Some(
                "replace it with endpoints = [{ target = \"...\", port = 443 }] (omit port to match any port)",
            ),
            "regex" => Some("remove [regex] and replace references with ordinary rule values"),
            "process" => Some("remove [process]; HyperHub now hooks root and child processes"),
            "ip_cidrs" | "target_regex" => Some("move destination values to targets"),
            "ports" => Some(
                "replace separate target/port lists with endpoints = [{ target = \"...\", port = 443 }]",
            ),
            "paths" | "path_regex" | "path_regex_ref" => {
                Some("replace it with patterns = [{ enabled = true, pattern = \"...\" }]")
            }
            "executables" | "command_lines" | "executable_regex" | "executable_regex_ref" => {
                Some("replace it with bound process patterns containing executable and command_line")
            }
            "command_line_regex" | "command_line_regex_ref" => Some(
                "replace it with bound patterns = [{ executable = \"...\", command_line = \"...\" }]",
            ),
            "http_path_regex" | "http_path_regex_ref" => Some("use a URL path prefix in targets"),
            "process_regex" | "process_regex_ref" => {
                Some("remove it; rules are no longer scoped by process")
            }
            "bearer_paths" | "git_http_paths" => {
                Some("move the URL scope to route endpoints and use http_scheme = 'token'")
            }
            "http_method" => Some("remove it; routes no longer match HTTP methods"),
            _ => None,
        };
        return Err(ConfigError::Validation(match migration {
            Some(migration) => format!("{owner} contains removed field '{key}'; {migration}"),
            None => format!("{owner} contains unknown field '{key}'"),
        }));
    }
    Ok(())
}

fn validate_trust_host(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("TLS host trust entry is empty".into());
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(format!("TLS host trust '{value}' must include host:port"));
    };
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() || port.parse::<u16>().ok().is_none_or(|port| port == 0) {
        return Err(format!("TLS host trust '{value}' is invalid"));
    }
    Ok(())
}

fn unique_ids<'a>(
    kind: &str,
    ids: impl Iterator<Item = &'a str>,
) -> Result<HashSet<String>, ConfigError> {
    let mut result = HashSet::new();
    for id in ids {
        if id.trim().is_empty() || !result.insert(id.to_owned()) {
            return Err(ConfigError::Validation(format!(
                "empty or duplicate {kind} id '{id}'"
            )));
        }
    }
    Ok(result)
}

fn validate_credential_fields(plugin: &PluginConfig) -> Result<(), ConfigError> {
    let mut http = false;
    let mut ssh = false;
    for protocol in &plugin.protocols {
        match protocol {
            PluginProtocol::Http => http = true,
            PluginProtocol::Ssh => ssh = true,
            _ => {}
        }
    }
    if http {
        validate_http_credential(plugin)?;
    }
    if ssh {
        validate_ssh_credential(plugin)?;
    }
    if !http && !ssh {
        return Err(ConfigError::Validation(format!(
            "credential plugin '{}' must target http or ssh protocol",
            plugin.id
        )));
    }
    Ok(())
}

fn validate_http_credential(plugin: &PluginConfig) -> Result<(), ConfigError> {
    if let Some(scheme) = plugin.http_scheme {
        match scheme {
            HttpAuthScheme::Basic => {
                let username = plugin.username.as_deref().unwrap_or("");
                if username.is_empty()
                    || username.contains(':')
                    || plugin.password.is_none()
                    || plugin.secret.is_some()
                    || plugin.http_name.is_some()
                {
                    return Err(ConfigError::Validation(format!(
                        "HTTP credential '{}' basic requires username and password only",
                        plugin.id
                    )));
                }
            }
            HttpAuthScheme::Token => {
                let username = plugin.username.as_deref().unwrap_or("");
                if username.trim().is_empty()
                    || username.contains(':')
                    || plugin.secret.is_none()
                    || matches!(plugin.secret.as_ref(), Some(SecretValue::Inline { value }) if value.is_empty())
                    || plugin.password.is_some()
                    || plugin.http_name.is_some()
                {
                    return Err(ConfigError::Validation(format!(
                        "HTTP credential '{}' token requires username and secret",
                        plugin.id
                    )));
                }
            }
            HttpAuthScheme::LegacyScopedToken => return Err(ConfigError::Validation(format!(
                "HTTP credential '{}' uses removed scheme 'scoped_token'; use 'token' and move bearer_paths/git_http_paths to route endpoints",
                plugin.id
            ))),
            HttpAuthScheme::Bearer | HttpAuthScheme::XApiKey => {
                if plugin.secret.is_none()
                    || plugin.username.is_some()
                    || plugin.password.is_some()
                    || plugin.http_name.is_some()
                {
                    return Err(ConfigError::Validation(format!(
                        "HTTP credential '{}' {:?} requires only a secret value",
                        plugin.id, scheme
                    )));
                }
            }
            HttpAuthScheme::Cookie | HttpAuthScheme::QueryParameter => {
                let name = plugin.http_name.as_deref().unwrap_or("");
                if name.is_empty()
                    || plugin.secret.is_none()
                    || plugin.username.is_some()
                    || plugin.password.is_some()
                {
                    return Err(ConfigError::Validation(format!(
                        "HTTP credential '{}' {:?} requires a name and secret value",
                        plugin.id, scheme
                    )));
                }
                if scheme == HttpAuthScheme::Cookie {
                    validate_http_token(name, &format!("credential '{}' cookie", plugin.id))?;
                }
            }
            HttpAuthScheme::CustomHeaders => {
                if plugin.secret.is_some()
                    || plugin.username.is_some()
                    || plugin.password.is_some()
                    || plugin.http_name.is_some()
                    || plugin.headers.is_empty()
                {
                    return Err(ConfigError::Validation(format!(
                        "HTTP credential '{}' custom_headers requires at least one custom header and no primary fields",
                        plugin.id
                    )));
                }
            }
        }
        let primary = match scheme {
            HttpAuthScheme::Basic | HttpAuthScheme::Bearer | HttpAuthScheme::Token => {
                "authorization"
            }
            HttpAuthScheme::LegacyScopedToken => "",
            HttpAuthScheme::XApiKey => "x-api-key",
            HttpAuthScheme::Cookie => "cookie",
            HttpAuthScheme::QueryParameter => "",
            HttpAuthScheme::CustomHeaders => "",
        };
        if !primary.is_empty()
            && plugin
                .headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case(primary))
        {
            return Err(ConfigError::Validation(format!(
                "HTTP credential '{}' custom headers duplicate its authentication header",
                plugin.id
            )));
        }
    } else if plugin.headers.is_empty() {
        return Err(ConfigError::Validation(format!(
            "HTTP credential '{}' has no authentication scheme or headers",
            plugin.id
        )));
    } else if plugin.secret.is_some()
        || plugin.username.is_some()
        || plugin.password.is_some()
        || plugin.http_name.is_some()
    {
        return Err(ConfigError::Validation(format!(
            "HTTP credential '{}' primary fields require an authentication scheme",
            plugin.id
        )));
    }
    Ok(())
}

fn validate_ssh_credential(plugin: &PluginConfig) -> Result<(), ConfigError> {
    if plugin.ssh_accounts.is_empty() {
        return Err(ConfigError::Validation(format!(
            "SSH credential '{}' requires at least one account",
            plugin.id
        )));
    }
    let mut usernames = HashSet::new();
    for (account_index, account) in plugin.ssh_accounts.iter().enumerate() {
        if account.username.trim().is_empty() {
            return Err(ConfigError::Validation(format!(
                "SSH credential '{}' account #{} requires a username",
                plugin.id,
                account_index + 1
            )));
        }
        if !usernames.insert(account.username.as_str()) {
            return Err(ConfigError::Validation(format!(
                "SSH credential '{}' contains duplicate username '{}'",
                plugin.id, account.username
            )));
        }
        if account.private_keys.is_empty() && account.passwords.is_empty() {
            return Err(ConfigError::Validation(format!(
                "SSH credential '{}' account '{}' requires at least one private key or password",
                plugin.id, account.username
            )));
        }
        for (key_index, key) in account.private_keys.iter().enumerate() {
            if key.name.trim().is_empty() {
                return Err(ConfigError::Validation(format!(
                    "SSH credential '{}' account '{}' private key #{} requires a name",
                    plugin.id,
                    account.username,
                    key_index + 1
                )));
            }
        }
        for (password_index, password) in account.passwords.iter().enumerate() {
            if matches!(password, SecretValue::Inline { value } if value.is_empty()) {
                return Err(ConfigError::Validation(format!(
                    "SSH credential '{}' account '{}' password #{} must not be empty",
                    plugin.id,
                    account.username,
                    password_index + 1
                )));
            }
        }
    }
    Ok(())
}

fn validate_headers(
    headers: &HashMap<String, SecretValue>,
    owner: &str,
    upstream: bool,
) -> Result<(), ConfigError> {
    for name in headers.keys() {
        validate_header_name(name, owner)?;
        if !upstream && is_forbidden_target_header(name) {
            return Err(ConfigError::Validation(format!(
                "{owner} cannot inject hop-by-hop header '{name}'"
            )));
        }
    }
    Ok(())
}

fn validate_header_name(name: &str, owner: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        Err(ConfigError::Validation(format!(
            "{owner} contains invalid header name '{name}'"
        )))
    } else {
        Ok(())
    }
}

fn validate_http_token(value: &str, owner: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        Err(ConfigError::Validation(format!(
            "{owner} contains invalid name '{value}'"
        )))
    } else {
        Ok(())
    }
}

/// 编译后的路由目标：域名（含可选 URL 路径前缀）、IP 或 CIDR。
#[derive(Debug, Clone, PartialEq)]
pub enum RouteTarget {
    Domain {
        host: String,
        wildcard: bool,
        path_prefix: Option<String>,
    },
    Ip(std::net::IpAddr),
    Network(IpNet),
}

/// 解析路由目标条目：`[http(s)://]host[/path]`（host 支持 `*.` 前缀）、IP 或 CIDR。
/// URL 路径前缀只用于 HTTP 家族请求的按请求匹配（见 `policy::CompiledRule::matches_http`）。
pub fn parse_route_target(value: &str) -> Result<RouteTarget, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("target cannot be empty".into());
    }
    if let Ok(network) = value.parse::<IpNet>() {
        return Ok(RouteTarget::Network(network));
    }
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return Ok(RouteTarget::Ip(ip));
    }
    let mut rest = value;
    let lower = value.to_ascii_lowercase();
    for scheme in ["http://", "https://"] {
        if lower.starts_with(scheme) {
            rest = &value[scheme.len()..];
            break;
        }
    }
    if rest.contains("://") {
        return Err("URL 目标仅支持 http:// 或 https:// 协议".into());
    }
    let (host_part, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], Some(&rest[slash..])),
        None => (rest, None),
    };
    if host_part.is_empty() {
        return Err("URL 目标缺少主机名".into());
    }
    if host_part.contains(':') {
        return Err("URL 目标不能内联端口，请在绑定目标中单独设置 port".into());
    }
    let (host_part, wildcard) = match host_part.strip_prefix("*.") {
        Some(host) => (host, true),
        None => (host_part, false),
    };
    if host_part.contains('*') {
        return Err("域名通配符仅支持最左侧完整标签 '*.'，例如 *.example.com".into());
    }
    let host = host_part.trim_end_matches('.').to_ascii_lowercase();
    if wildcard && (host.parse::<std::net::IpAddr>().is_ok() || host.parse::<IpNet>().is_ok()) {
        return Err("IP 或 CIDR 目标不支持通配符".into());
    }
    if host.is_empty()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("URL 目标主机必须是有效的域名".into());
    }
    let path_prefix = match path {
        Some(path) if path.contains('?') || path.contains('#') => {
            return Err("URL 目标路径不能包含查询参数或片段".into());
        }
        Some(path) if route_path_is_ambiguous(path) => {
            return Err("URL 目标路径不能包含点分段、反斜杠或歧义百分号编码".into());
        }
        Some(path) => {
            let trimmed = path.trim_end_matches('/');
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        None => None,
    };
    Ok(RouteTarget::Domain {
        host,
        wildcard,
        path_prefix,
    })
}

fn route_path_is_ambiguous(path: &str) -> bool {
    if path.contains('\\') || path.split('/').any(|segment| matches!(segment, "." | "..")) {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    ["%2e", "%2f", "%5c", "%25"]
        .iter()
        .any(|encoded| lower.contains(encoded))
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_forbidden_target_header(name: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-authorization",
    ];
    FORBIDDEN
        .iter()
        .any(|value| name.eq_ignore_ascii_case(value))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    #[serde(default = "default_socks_listen")]
    pub socks_listen: String,
    #[serde(default = "default_pending_session_ttl_secs")]
    pub pending_session_ttl_secs: u64,
}
impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            socks_listen: default_socks_listen(),
            pending_session_ttl_secs: default_pending_session_ttl_secs(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    #[default]
    Enforce,
    Observe,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallAction {
    #[default]
    Pass,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallDefaultRule {
    pub action: FirewallAction,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxAction {
    #[default]
    Pass,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SandboxDefaultRule {
    #[serde(default)]
    pub action: SandboxAction,
}

impl Default for SandboxDefaultRule {
    fn default() -> Self {
        Self {
            action: SandboxAction::Pass,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    #[serde(default)]
    pub process: ProcessSandboxConfig,
    #[serde(default)]
    pub file: FileSandboxConfig,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrefilterPolicy {
    #[default]
    None,
    NetworkUpload,
    SensitiveRead,
    ArchiveOrEncode,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSandboxConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub default: SandboxDefaultRule,
    #[serde(default)]
    pub error_action: SandboxAction,
    #[serde(default)]
    pub rules: Vec<ProcessSandboxRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSandboxRule {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub action: SandboxAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<ProcessSandboxPattern>,
    #[serde(default)]
    pub protection_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<String>,
    #[serde(default)]
    pub prefilter_policy: PrefilterPolicy,
    #[serde(default, flatten)]
    pub legacy: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSandboxPattern {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub executable: String,
    #[serde(default)]
    pub command_line: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSandboxConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub default: SandboxDefaultRule,
    #[serde(default)]
    pub error_action: SandboxAction,
    #[serde(default)]
    pub rules: Vec<FileSandboxRule>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FileSandboxOperation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSandboxRule {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub action: SandboxAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<FileSandboxPattern>,
    #[serde(default)]
    pub operations: Vec<FileSandboxOperation>,
    #[serde(default)]
    pub protection_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<String>,
    #[serde(default)]
    pub prefilter_policy: PrefilterPolicy,
    #[serde(default, flatten)]
    pub legacy: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSandboxPattern {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_firewall_default")]
    pub default: Option<FirewallDefaultRule>,
    #[serde(default)]
    pub error_action: FirewallAction,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default: default_firewall_default(),
            error_action: FirewallAction::Pass,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    pub action: FirewallAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<FirewallEndpoint>,
    #[serde(default, flatten)]
    pub legacy: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallEndpoint {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    #[default]
    Observe,
    Enforce,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionAction {
    #[default]
    Pass,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceProviderKind {
    Typesafe,
    Openrouter,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataProtectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_protection_scan_bytes")]
    pub max_scan_bytes: usize,
    #[serde(default = "default_true")]
    pub detect_managed_secrets: bool,
    #[serde(default = "default_true")]
    pub detect_known_tokens: bool,
    #[serde(default = "default_true")]
    pub detect_private_keys: bool,
    #[serde(default = "default_true")]
    pub detect_prompt_injection: bool,
    #[serde(default = "default_provenance_window_bytes")]
    pub provenance_window_bytes: usize,
    #[serde(default = "default_provenance_min_matches")]
    pub provenance_min_matches: usize,
}

impl Default for DataProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_scan_bytes: default_protection_scan_bytes(),
            detect_managed_secrets: true,
            detect_known_tokens: true,
            detect_private_keys: true,
            detect_prompt_injection: true,
            provenance_window_bytes: default_provenance_window_bytes(),
            provenance_min_matches: default_provenance_min_matches(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelligenceProviderConfig {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub provider: IntelligenceProviderKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<SecretValue>,
    #[serde(default)]
    pub mode: ProtectionMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelligenceProtectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_guard_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_guard_min_confidence")]
    pub min_confidence: f64,
    #[serde(default)]
    pub error_action: ProtectionAction,
    #[serde(default)]
    pub low_confidence_action: ProtectionAction,
    #[serde(default = "default_guard_cache_ttl_ms")]
    pub cache_ttl_ms: u64,
    #[serde(default)]
    pub providers: Vec<IntelligenceProviderConfig>,
}

impl Default for IntelligenceProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_ms: default_guard_timeout_ms(),
            min_confidence: default_guard_min_confidence(),
            error_action: ProtectionAction::Pass,
            low_confidence_action: ProtectionAction::Pass,
            cache_ttl_ms: default_guard_cache_ttl_ms(),
            providers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionProfile {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: ProtectionMode,
    #[serde(default)]
    pub data: DataProtectionConfig,
    #[serde(default)]
    pub intelligence: IntelligenceProtectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultRoute {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub deny: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<String>,
    #[serde(default)]
    pub protection_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<String>,
    #[serde(default)]
    pub allow_sensitive_upload: bool,
}

impl Default for DefaultRoute {
    fn default() -> Self {
        Self {
            enabled: true,
            deny: false,
            plugins: Vec::new(),
            protection_enabled: false,
            protection: None,
            allow_sensitive_upload: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicy {
    /// 由 `Config::apply_managed_audit_paths` 设置；旧字段可读取但不再导出。
    #[serde(default, skip_serializing)]
    pub log: Option<PathBuf>,
    #[serde(default, skip_serializing)]
    pub transcript_dir: Option<PathBuf>,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_true")]
    pub connections: bool,
    #[serde(default)]
    pub header_allowlist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentVariable {
    #[serde(default)]
    pub uuid: String,
    pub name: String,
    pub value: SecretValue,
}
impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            log: None,
            transcript_dir: None,
            retention_days: default_retention_days(),
            connections: true,
            header_allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    /// Human-friendly destination selectors: 精确域名、`*.` 子域通配、
    /// URL 形式 `[http(s)://]host[/path]`、IP 或 CIDR。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<RouteEndpoint>,
    #[serde(default)]
    pub deny: bool,
    pub rewrite_host: Option<String>,
    pub rewrite_port: Option<u16>,
    pub upstream: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<String>,
    #[serde(default)]
    pub protection_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<String>,
    #[serde(default)]
    pub allow_sensitive_upload: bool,
    #[serde(default, flatten)]
    pub legacy: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteEndpoint {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCertificate {
    #[serde(default)]
    pub uuid: String,
    /// SHA-256 of the certificate DER, used as the identity and storage file name.
    pub fingerprint: String,
    /// Exact TLS host pin (`host:port`). None means a globally trusted root certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshHostKey {
    #[serde(default)]
    pub uuid: String,
    /// 目标主机（host 或 host:port）。
    pub host: String,
    pub key_type: String,
    /// OpenSSH 公钥 blob（base64）。
    pub key_blob: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketCapture {
    #[default]
    Off,
    Frames,
    Messages,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamKind {
    Socks5,
    HttpConnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    #[serde(rename = "type")]
    pub kind: UpstreamKind,
    pub address: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    pub username: Option<SecretValue>,
    pub password: Option<SecretValue>,
    #[serde(default)]
    pub headers: HashMap<String, SecretValue>,
}
impl Upstream {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    Audit,
    Credential,
    Convert,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PluginProtocol {
    Http,
    Ws,
    Git,
    Ssh,
    Response,
    Message,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpAuthScheme {
    Basic,
    Bearer,
    Token,
    #[serde(rename = "scoped_token")]
    LegacyScopedToken,
    XApiKey,
    Cookie,
    QueryParameter,
    CustomHeaders,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshPrivateKey {
    pub name: String,
    pub value: SecretValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshAccount {
    pub username: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_keys: Vec<SshPrivateKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passwords: Vec<SecretValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    #[serde(rename = "kind")]
    pub kind: PluginKind,
    #[serde(default)]
    pub protocols: Vec<PluginProtocol>,
    /// 凭证注入参数（kind = credential）。
    #[serde(default)]
    pub http_scheme: Option<HttpAuthScheme>,
    #[serde(default)]
    pub secret: Option<SecretValue>,
    #[serde(default)]
    pub http_name: Option<String>,
    pub username: Option<String>,
    pub password: Option<SecretValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_accounts: Vec<SshAccount>,
    #[serde(default)]
    pub headers: HashMap<String, SecretValue>,
    #[serde(default, flatten)]
    pub legacy: HashMap<String, serde_json::Value>,
    /// 协议审计参数（kind = audit）。
    /// HTTP 请求/响应正文转录。保留字段名以兼容现有配置。
    #[serde(default)]
    pub capture_body: bool,
    #[serde(default = "default_body_limit")]
    pub body_limit: usize,
    /// 原生 Git 数据流转录。`None` 表示旧配置，兼容沿用
    /// `capture_body && protocols contains git` 的历史行为。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_transcript: Option<bool>,
    #[serde(default)]
    pub ssh_transcript: bool,
    #[serde(default)]
    pub websocket_capture: WebSocketCapture,
    /// 内容转录方向；旧配置缺省保持双向捕获。
    #[serde(default = "default_true")]
    pub transcript_client_upload: bool,
    #[serde(default = "default_true")]
    pub transcript_server_response: bool,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            uuid: new_config_uuid(),
            id: String::new(),
            kind: PluginKind::Audit,
            protocols: Vec::new(),
            http_scheme: None,
            secret: None,
            http_name: None,
            username: None,
            password: None,
            ssh_accounts: Vec::new(),
            headers: HashMap::new(),
            legacy: HashMap::new(),
            capture_body: false,
            body_limit: default_body_limit(),
            git_transcript: None,
            ssh_transcript: false,
            websocket_capture: WebSocketCapture::Off,
            transcript_client_upload: true,
            transcript_server_response: true,
        }
    }
}

impl PluginConfig {
    pub fn http_transcript_enabled(&self) -> bool {
        self.capture_body && self.protocols.contains(&PluginProtocol::Http)
    }

    pub fn git_transcript_enabled(&self) -> bool {
        self.git_transcript
            .unwrap_or_else(|| self.capture_body && self.protocols.contains(&PluginProtocol::Git))
    }

    pub fn content_transcript_enabled(&self) -> bool {
        self.http_transcript_enabled()
            || self.git_transcript_enabled()
            || self.ssh_transcript
            || self.websocket_capture != WebSocketCapture::Off
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SecretValue {
    Inline {
        value: String,
    },
    Env {
        env: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        prefix: String,
    },
    File {
        file: PathBuf,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        prefix: String,
    },
}

impl SecretValue {
    fn redact(&mut self) {
        if let Self::Inline { value } = self {
            *value = "<redacted>".into();
        }
    }

    pub fn resolve(&self) -> Result<String, ConfigError> {
        match self {
            Self::Inline { value } => Ok(value.clone()),
            Self::Env { env: name, prefix } => std::env::var(name)
                .map(|value| format!("{prefix}{value}"))
                .map_err(|_| ConfigError::MissingSecretEnv(name.clone())),
            Self::File { file: path, prefix } => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let meta = fs::metadata(path).map_err(|source| ConfigError::SecretFile {
                        path: path.clone(),
                        source,
                    })?;
                    if meta.permissions().mode() & 0o077 != 0 {
                        return Err(ConfigError::InsecureSecretFile(path.clone()));
                    }
                }
                fs::read_to_string(path)
                    .map(|value| format!("{prefix}{}", value.trim()))
                    .map_err(|source| ConfigError::SecretFile {
                        path: path.clone(),
                        source,
                    })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_legacy_top_level_and_regex_sections() {
        let config: Config = toml::from_str(
            r#"
                [regex]
                [[regex.process]]
                id = "legacy-process"
                pattern = "client"

                [process]
                enabled = true

                [[process.rules]]
                id = "legacy-rule"
                action = "hook"
                process_regex_ref = "legacy-process"
            "#,
        )
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("removed field"));
        assert!(error.contains("regex") || error.contains("process"));
    }

    #[test]
    fn rejects_legacy_rule_reference_fields() {
        for input in [
            r#"[[firewall.rules]]
id = "legacy"
action = "deny"
process_regex_ref = "legacy"
targets = ["example.com"]"#,
            r#"[[sandbox.file.rules]]
id = "legacy"
action = "deny"
process_regex_ref = "legacy-process"
path_regex_ref = "legacy-file"
paths = ["C:/secret"]
operations = ["read"]"#,
            r#"[[sandbox.process.rules]]
id = "legacy"
action = "deny"
process_regex_ref = "legacy-process"
executable_regex_ref = "legacy-exec"
command_line_regex_ref = "legacy-cmd"
executables = ["git.exe"]
command_lines = ["--secret"]"#,
            r#"[[routes]]
id = "legacy"
process_regex_ref = "legacy-process"
ip_cidrs = ["10.0.0.0/8"]
ports = [443]
targets = ["example.com"]"#,
        ] {
            let config: Config = toml::from_str(input).unwrap();
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("field"), "{error}");
        }
    }

    #[test]
    fn debug_defaults_to_disabled_and_can_be_loaded() {
        let default_config: Config = toml::from_str("").unwrap();
        assert!(!default_config.debug);

        let config: Config = toml::from_str("debug = true").unwrap();
        assert!(config.debug);
    }

    #[test]
    fn example_config_is_valid() {
        let config: Config = toml::from_str(include_str!("../../../examples/hyperhub.toml"))
            .expect("example configuration must parse");
        config
            .validate()
            .expect("example configuration must validate");
    }

    #[test]
    fn managed_audit_paths_override_legacy_values_and_are_not_exported() {
        let mut config: Config = toml::from_str(
            r#"
                [audit]
                log = "custom/events.jsonl"
                transcript_dir = "custom/content"

                [[plugins]]
                id = "ws"
                kind = "audit"
                protocols = ["ws"]
                websocket_capture = "frames"
            "#,
        )
        .unwrap();
        config.apply_managed_audit_paths(Path::new("state/config.bin"));
        assert_eq!(config.audit.log, Some("state/audit/hyperhub.jsonl".into()));
        assert_eq!(
            config.audit.transcript_dir,
            Some("state/audit/transcripts".into())
        );
        config.validate().unwrap();
        let exported = toml::to_string(&config).unwrap();
        assert!(!exported.contains("log ="));
        assert!(!exported.contains("transcript_dir"));
    }

    #[test]
    fn audit_capture_capabilities_require_their_protocols() {
        let mut config = Config::default();
        config.audit.transcript_dir = Some("audit/transcripts".into());
        config.plugins.push(PluginConfig {
            uuid: new_config_uuid(),
            id: "audit".into(),
            kind: PluginKind::Audit,
            protocols: vec![PluginProtocol::Http],
            ssh_transcript: true,
            ..PluginConfig::default()
        });
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not declare the ssh protocol"));

        config.plugins[0].ssh_transcript = false;
        config.plugins[0].websocket_capture = WebSocketCapture::Messages;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not declare the ws protocol"));

        config.plugins[0].websocket_capture = WebSocketCapture::Off;
        config.plugins[0].git_transcript = Some(true);
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not declare the git protocol"));

        config.plugins[0].git_transcript = Some(false);
        config.plugins[0].protocols = vec![PluginProtocol::Ssh];
        config.plugins[0].capture_body = true;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not declare the http protocol"));

        config.plugins[0].protocols = vec![PluginProtocol::Http];
        config.plugins[0].transcript_client_upload = false;
        config.plugins[0].transcript_server_response = false;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("disables both transcript directions"));
    }

    #[test]
    fn legacy_git_capture_body_maps_to_git_transcript() {
        let profile: PluginConfig = toml::from_str(
            r#"
                id = "git-audit"
                kind = "audit"
                protocols = ["git"]
                capture_body = true
            "#,
        )
        .unwrap();

        assert!(profile.git_transcript.is_none());
        assert!(profile.git_transcript_enabled());
        assert!(!profile.http_transcript_enabled());
        assert!(profile.transcript_client_upload);
        assert!(profile.transcript_server_response);
    }

    #[test]
    fn socks_listener_requires_a_loopback_address_and_non_zero_port() {
        let mut config = Config::default();
        config.listener.socks_listen = "0.0.0.0:18444".into();
        assert!(config.validate().is_err());
        config.listener.socks_listen = "127.0.0.1:0".into();
        assert!(config.validate().is_err());
        config.listener.socks_listen = "127.0.0.1:18444".into();
        config.validate().unwrap();
    }

    #[test]
    fn legacy_items_receive_deterministic_configuration_uuids() {
        let source = r#"
            [[routes]]
            id = "legacy-route"
            endpoints = [{ target = "example.com", port = 443 }]

            [[plugins]]
            id = "legacy-credential"
            kind = "credential"
            protocols = ["http"]
            http_scheme = "bearer"
            secret = { value = "token" }
        "#;
        let first: Config = toml::from_str(source).unwrap();
        let second: Config = toml::from_str(source).unwrap();
        assert_eq!(first.rules[0].uuid, second.rules[0].uuid);
        assert_eq!(first.plugins[0].uuid, second.plugins[0].uuid);
        assert!(valid_config_uuid(&first.rules[0].uuid));
        assert!(valid_config_uuid(&first.plugins[0].uuid));
        first.validate().unwrap();
    }

    #[test]
    fn configuration_item_uuids_must_be_unique_and_valid() {
        let mut config = Config::default();
        let shared = new_config_uuid();
        config.rules.push(RouteRule {
            uuid: shared.clone(),
            id: "one".into(),
            enabled: true,
            priority: 1,
            endpoints: vec![RouteEndpoint {
                target: "one.example".into(),
                port: Some(443),
            }],
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: Vec::new(),
            legacy: Default::default(),
            protection_enabled: false,
            protection: None,
            allow_sensitive_upload: false,
        });
        config.environment.push(EnvironmentVariable {
            uuid: shared,
            name: "DUPLICATE_UUID".into(),
            value: SecretValue::Inline {
                value: "value".into(),
            },
        });
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("reuses"));
        config.environment[0].uuid = "not-a-uuid".into();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid UUID"));
    }

    #[test]
    fn redacted_config_preserves_structure_and_hides_all_inline_secrets() {
        let mut config = Config::default();
        config.environment.push(EnvironmentVariable {
            uuid: new_config_uuid(),
            name: "TOKEN".into(),
            value: SecretValue::Inline {
                value: "environment-secret".into(),
            },
        });
        config.upstreams.push(Upstream {
            uuid: new_config_uuid(),
            id: "proxy".into(),
            kind: UpstreamKind::Socks5,
            address: "127.0.0.1:1080".into(),
            timeout_ms: 1000,
            username: Some(SecretValue::Inline {
                value: "username-secret".into(),
            }),
            password: Some(SecretValue::Inline {
                value: "password-secret".into(),
            }),
            headers: HashMap::from([(
                "authorization".into(),
                SecretValue::Inline {
                    value: "header-secret".into(),
                },
            )]),
        });
        let mut plugin = PluginConfig::default();
        plugin.id = "credential".into();
        plugin.kind = PluginKind::Credential;
        plugin.secret = Some(SecretValue::Inline {
            value: "plugin-secret".into(),
        });
        plugin.ssh_accounts.push(SshAccount {
            username: "git".into(),
            private_keys: vec![SshPrivateKey {
                name: "default".into(),
                value: SecretValue::Inline {
                    value: "private-key".into(),
                },
            }],
            passwords: vec![SecretValue::Inline {
                value: "ssh-password".into(),
            }],
        });
        config.plugins.push(plugin);

        let original = serde_json::to_value(&config).unwrap();
        let redacted = serde_json::to_value(config.redacted()).unwrap();
        assert_eq!(
            original.pointer("/upstreams/0/address"),
            redacted.pointer("/upstreams/0/address")
        );
        let encoded = serde_json::to_string(&redacted).unwrap();
        for secret in [
            "environment-secret",
            "username-secret",
            "password-secret",
            "header-secret",
            "plugin-secret",
            "private-key",
            "ssh-password",
        ] {
            assert!(!encoded.contains(secret));
        }
        assert_eq!(encoded.matches("<redacted>").count(), 7);
    }

    #[test]
    fn validates_session_environment_names() {
        let mut config = Config::default();
        config.environment.push(EnvironmentVariable {
            uuid: new_config_uuid(),
            name: "GH_TOKEN".into(),
            value: SecretValue::Inline {
                value: "secret".into(),
            },
        });
        config.validate().unwrap();
        config.environment[0].name = "HYPERHUB_SESSION_ID".into();
        assert!(config.validate().is_err());
        config.environment[0].name = "1INVALID".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn reserves_the_default_route_id() {
        let mut config = Config::default();
        config.rules.push(RouteRule {
            uuid: new_config_uuid(),
            id: DEFAULT_ROUTE_ID.into(),
            enabled: true,
            priority: 0,
            endpoints: Vec::new(),
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: Vec::new(),
            legacy: Default::default(),
            protection_enabled: false,
            protection: None,
            allow_sensitive_upload: false,
        });
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("reserved for the built-in default route"));
    }

    #[test]
    fn validates_type_driven_http_credentials() {
        let bearer: Config = toml::from_str(
            r#"
                [[plugins]]
                id = "bearer"
                kind = "credential"
                protocols = ["http"]
                http_scheme = "bearer"
                secret = { value = "token" }
                [plugins.headers.X-Tenant]
                value = "tenant-1"
            "#,
        )
        .unwrap();
        bearer.validate().unwrap();

        let token: Config = toml::from_str(
            r#"
                [[plugins]]
                id = "project"
                kind = "credential"
                protocols = ["http"]
                http_scheme = "token"
                username = "project_bot"
                secret = { value = "token" }
                [plugins.headers.PRIVATE-TOKEN]
                value = ""
                [plugins.headers.X-Tenant]
                value = "tenant-1"
            "#,
        )
        .unwrap();
        token.validate().unwrap();

        let mut duplicate_authorization = token.clone();
        duplicate_authorization.plugins[0].headers.insert(
            "Authorization".into(),
            SecretValue::Inline {
                value: "client-value".into(),
            },
        );
        assert!(duplicate_authorization
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate its authentication header"));

        let mut empty_secret = token.clone();
        empty_secret.plugins[0].secret = Some(SecretValue::Inline {
            value: String::new(),
        });
        assert!(empty_secret.validate().is_err());

        for legacy in [
            r#"
                [[plugins]]
                id = "legacy"
                kind = "credential"
                protocols = ["http"]
                http_scheme = "scoped_token"
                username = "project_bot"
                secret = { value = "token" }
                bearer_paths = ["/api/v4"]
                git_http_paths = ["/group/project.git"]
            "#,
            r#"
                [[plugins]]
                id = "legacy-field"
                kind = "credential"
                protocols = ["http"]
                http_scheme = "bearer"
                secret = { value = "token" }
                bearer_paths = ["/api/v4"]
            "#,
        ] {
            let legacy: Config = toml::from_str(legacy).unwrap();
            let error = legacy.validate().unwrap_err().to_string();
            assert!(error.contains("route endpoints"), "{error}");
        }
        let legacy_scheme: Config = toml::from_str(
            r#"
                [[plugins]]
                id = "legacy-scheme"
                kind = "credential"
                protocols = ["http"]
                http_scheme = "scoped_token"
                username = "project_bot"
                secret = { value = "token" }
            "#,
        )
        .unwrap();
        let error = legacy_scheme.validate().unwrap_err().to_string();
        assert!(error.contains("removed scheme 'scoped_token'"), "{error}");

        let additional: Config = toml::from_str(
            r#"
                [[plugins]]
                id = "basic"
                kind = "credential"
                protocols = ["http"]
                http_scheme = "basic"
                username = "user"
                password = { value = "pass" }

                [[plugins]]
                id = "cookie"
                kind = "credential"
                protocols = ["http"]
                http_scheme = "cookie"
                http_name = "session"
                secret = { value = "token" }

                [[plugins]]
                id = "query"
                kind = "credential"
                protocols = ["http"]
                http_scheme = "query_parameter"
                http_name = "api_key"
                secret = { value = "token" }
            "#,
        )
        .unwrap();
        additional.validate().unwrap();

        let custom_without_headers: Config = toml::from_str(
            r#"
                [[plugins]]
                id = "custom"
                kind = "credential"
                protocols = ["http"]
                http_scheme = "custom_headers"
            "#,
        )
        .unwrap();
        assert!(custom_without_headers
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires at least one custom header"));
    }

    #[test]
    fn validates_ssh_credential_requires_key_or_password() {
        let valid: Config = toml::from_str(
            r#"
                [[plugins]]
                id = "deploy"
                kind = "credential"
                protocols = ["ssh"]

                [[plugins.ssh_accounts]]
                username = "ubuntu"

                [[plugins.ssh_accounts.private_keys]]
                name = "deploy-key"
                value = { value = "key" }
            "#,
        )
        .unwrap();
        valid.validate().unwrap();

        let invalid: Config = toml::from_str(
            r#"
                [[plugins]]
                id = "deploy"
                kind = "credential"
                protocols = ["ssh"]
            "#,
        )
        .unwrap();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn ssh_credential_validates_key_and_password_shapes() {
        let mut config = Config::default();
        config.plugins.push(PluginConfig {
            uuid: new_config_uuid(),
            id: "deploy".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Ssh],
            ssh_accounts: vec![SshAccount {
                username: "ubuntu".into(),
                private_keys: Vec::new(),
                passwords: vec![SecretValue::Inline {
                    value: "pass".into(),
                }],
            }],
            ..PluginConfig::default()
        });
        config.validate().unwrap();

        let mut blank_name = Config::default();
        blank_name.plugins.push(PluginConfig {
            uuid: new_config_uuid(),
            id: "deploy".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Ssh],
            ssh_accounts: vec![SshAccount {
                username: "ubuntu".into(),
                private_keys: vec![SshPrivateKey {
                    name: " ".into(),
                    value: SecretValue::Inline {
                        value: "key".into(),
                    },
                }],
                passwords: Vec::new(),
            }],
            ..PluginConfig::default()
        });
        assert!(blank_name
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires a name"));

        let mut empty_password = Config::default();
        empty_password.plugins.push(PluginConfig {
            uuid: new_config_uuid(),
            id: "deploy".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Ssh],
            ssh_accounts: vec![SshAccount {
                username: "ubuntu".into(),
                private_keys: Vec::new(),
                passwords: vec![SecretValue::Inline {
                    value: String::new(),
                }],
            }],
            ..PluginConfig::default()
        });
        assert!(empty_password
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must not be empty"));
    }

    #[test]
    fn ssh_credential_validates_account_identity_and_credentials() {
        let account = |username: &str| SshAccount {
            username: username.into(),
            private_keys: Vec::new(),
            passwords: vec![SecretValue::Inline {
                value: "pass".into(),
            }],
        };
        let config_with = |accounts| {
            let mut config = Config::default();
            config.plugins.push(PluginConfig {
                uuid: new_config_uuid(),
                id: "deploy".into(),
                kind: PluginKind::Credential,
                protocols: vec![PluginProtocol::Ssh],
                ssh_accounts: accounts,
                ..PluginConfig::default()
            });
            config
        };

        let duplicate = config_with(vec![account("ubuntu"), account("ubuntu")]);
        assert!(duplicate
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate username"));

        let blank = config_with(vec![account(" ")]);
        assert!(blank
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires a username"));

        let missing_credentials = config_with(vec![SshAccount {
            username: "root".into(),
            private_keys: Vec::new(),
            passwords: Vec::new(),
        }]);
        assert!(missing_credentials
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires at least one private key or password"));
    }

    #[test]
    fn disabled_route_skips_semantic_validation() {
        let mut config = Config::default();
        config.rules.push(RouteRule {
            uuid: new_config_uuid(),
            id: "parked".into(),
            enabled: false,
            priority: 0,
            endpoints: vec![RouteEndpoint {
                target: "http://[invalid".into(),
                port: None,
            }],
            deny: true,
            rewrite_host: None,
            rewrite_port: None,
            upstream: Some("missing".into()),
            plugins: vec!["missing".into()],
            legacy: Default::default(),
            protection_enabled: false,
            protection: None,
            allow_sensitive_upload: false,
        });
        config.validate().unwrap();
        config.rules[0].enabled = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn parses_url_form_targets_with_http_only_schemes() {
        assert_eq!(
            parse_route_target("git.example.com/group/repo").unwrap(),
            RouteTarget::Domain {
                host: "git.example.com".into(),
                wildcard: false,
                path_prefix: Some("/group/repo".into()),
            }
        );
        assert_eq!(
            parse_route_target("HTTPS://Git.Example.COM/Api/").unwrap(),
            RouteTarget::Domain {
                host: "git.example.com".into(),
                wildcard: false,
                path_prefix: Some("/Api".into()),
            }
        );
        assert_eq!(
            parse_route_target("http://*.example.com/v1").unwrap(),
            RouteTarget::Domain {
                host: "example.com".into(),
                wildcard: true,
                path_prefix: Some("/v1".into()),
            }
        );
        assert_eq!(
            parse_route_target("example.com").unwrap(),
            RouteTarget::Domain {
                host: "example.com".into(),
                wildcard: false,
                path_prefix: None,
            }
        );
        assert_eq!(
            parse_route_target("10.0.0.0/8").unwrap(),
            RouteTarget::Network("10.0.0.0/8".parse().unwrap())
        );
        assert!(parse_route_target("ftp://example.com/feed").is_err());
        for invalid in [
            "*example.com",
            "api.*.example.com",
            "**.example.com",
            "*",
            "*.10.0.0.1",
            "*.10.0.0.0/8",
            "example.com/api/../admin",
            "example.com/api/%2fadmin",
            "example.com/api\\admin",
        ] {
            assert!(parse_route_target(invalid).is_err(), "accepted {invalid}");
        }
        assert!(parse_route_target("example.com:8080/api").is_err());
        assert!(parse_route_target("https://example.com/a?b=c").is_err());
        assert_eq!(
            parse_route_target("https://example.com/").unwrap(),
            RouteTarget::Domain {
                host: "example.com".into(),
                wildcard: false,
                path_prefix: None,
            }
        );
    }

    #[test]
    fn rejects_removed_route_fields() {
        for input in [
            r#"[[routes]]
id = "legacy"
target_regex = "^api\\.example\\.com$""#,
            r#"[[routes]]
id = "legacy"
process_regex_ref = "legacy-process"
ip_cidrs = ["10.0.0.0/8"]
ports = [443]
targets = ["example.com"]"#,
            r#"[[routes]]
id = "legacy"
http_method = "GET"
http_path_regex_ref = "legacy-path""#,
            r#"[regex.http_path]
id = "legacy-path"
pattern = "^/private$""#,
        ] {
            let config: Config = toml::from_str(input).unwrap();
            assert!(config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("removed field"));
        }
    }

    #[test]
    fn rejects_unknown_and_removed_fields_with_migration_guidance() {
        let unknown: Config = toml::from_str("legacy_field = true").unwrap();
        assert!(unknown
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unknown field 'legacy_field'"));

        let scoped: Config = toml::from_str(
            r#"[[routes]]
id = "legacy-ssh"
ports = [22]
targets = []"#,
        )
        .unwrap();
        let error = scoped.validate().unwrap_err().to_string();
        assert!(error.contains("removed field 'ports'"));
        assert!(error.contains("replace separate target/port lists with endpoints"));

        let kept: Config = toml::from_str(
            r#"[[routes]]
id = "legacy-https"
ports = [443]
targets = ["github.com"]"#,
        )
        .unwrap();
        assert!(kept.validate().is_err());
    }

    #[test]
    fn rejects_empty_target_user_routes() {
        let config: Config = toml::from_str(
            r#"[[routes]]
id = "global"
enabled = true"#,
        )
        .unwrap();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must contain at least one target"));
    }

    #[test]
    fn rejects_typos_in_container_default_sections() {
        for input in [
            r#"[firewall]
enalbed = true"#,
            r#"[sandbox.file]
enalbed = true"#,
            r#"[sandbox.process]
enalbed = true"#,
            r#"[firewall.default]
aktion = "deny""#,
        ] {
            assert!(toml::from_str::<Config>(input).is_err(), "{input}");
        }
    }

    #[test]
    fn sandbox_rules_require_enabled_regex_patterns() {
        let mut config = Config::default();
        config.sandbox.process.enabled = true;
        config.sandbox.process.rules.push(ProcessSandboxRule {
            uuid: new_config_uuid(),
            id: "empty".into(),
            enabled: true,
            priority: 0,
            action: SandboxAction::Deny,
            patterns: Vec::new(),
            protection_enabled: false,
            protection: None,
            prefilter_policy: PrefilterPolicy::None,
            legacy: Default::default(),
        });
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("enabled regex pattern"));
        config.sandbox.process.rules[0].patterns = vec![ProcessSandboxPattern {
            enabled: true,
            executable: "git\\.exe$".into(),
            command_line: String::new(),
        }];
        config.validate().unwrap();

        config.sandbox.file.enabled = true;
        config.sandbox.file.rules.push(FileSandboxRule {
            uuid: new_config_uuid(),
            id: "missing-path".into(),
            enabled: true,
            priority: 0,
            action: SandboxAction::Deny,
            patterns: Vec::new(),
            operations: vec![FileSandboxOperation::Read],
            protection_enabled: false,
            protection: None,
            prefilter_policy: PrefilterPolicy::None,
            legacy: Default::default(),
        });
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("enabled regex pattern"));
        config.sandbox.file.rules[0].patterns = vec![FileSandboxPattern {
            enabled: true,
            pattern: "secret$".into(),
        }];
        config.validate().unwrap();

        config.sandbox.file.rules[0].operations.clear();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("at least one operation"));
    }

    #[test]
    fn validates_firewall_rules_and_defaults_to_disabled_pass() {
        let default: Config = toml::from_str("").unwrap();
        assert!(!default.firewall.enabled);
        assert_eq!(
            default.firewall.default.as_ref().map(|rule| rule.action),
            Some(FirewallAction::Pass)
        );

        let config: Config = toml::from_str(
            r#"
                [firewall]
                enabled = true

                [firewall.default]
                action = "deny"

                [[firewall.rules]]
                id = "block-example"
                priority = 100
                action = "deny"
                [[firewall.rules.endpoints]]
                target = "example.com"
                port = 443
                [[firewall.rules.endpoints]]
                target = "10.0.0.0/8"
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.firewall.default.unwrap().action,
            FirewallAction::Deny
        );
    }

    #[test]
    fn rejects_duplicate_and_unconditional_firewall_rules() {
        let mut config = Config::default();
        config.firewall.enabled = true;
        config.firewall.rules = vec![
            FirewallRule {
                uuid: new_config_uuid(),
                id: "duplicate".into(),
                enabled: true,
                priority: 0,
                action: FirewallAction::Deny,
                endpoints: vec![FirewallEndpoint {
                    target: "example.com".into(),
                    port: None,
                }],
                legacy: Default::default(),
            },
            FirewallRule {
                uuid: new_config_uuid(),
                id: "duplicate".into(),
                enabled: true,
                priority: 0,
                action: FirewallAction::Pass,
                endpoints: vec![FirewallEndpoint {
                    target: "other.example".into(),
                    port: None,
                }],
                legacy: Default::default(),
            },
        ];
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate firewall rule"));

        config.firewall.rules.truncate(1);
        config.firewall.rules[0].endpoints.clear();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("at least one endpoint"));
    }

    #[test]
    fn rejects_invalid_firewall_targets_and_ports() {
        let mut config = Config::default();
        config.firewall.enabled = true;
        config.firewall.rules.push(FirewallRule {
            uuid: new_config_uuid(),
            id: "invalid".into(),
            enabled: true,
            priority: 0,
            action: FirewallAction::Deny,
            endpoints: vec![FirewallEndpoint {
                target: "https://example.com/private".into(),
                port: None,
            }],
            legacy: Default::default(),
        });
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cannot contain a URL path"));

        config.firewall.rules[0].endpoints = vec![FirewallEndpoint {
            target: "example.com".into(),
            port: Some(0),
        }];
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("port 0"));
    }

    #[test]
    fn tls_trust_allows_global_and_host_scopes_but_rejects_duplicate_scope() {
        let fingerprint = "01".repeat(32);
        let mut config = Config::default();
        config.root_certificates.push(RootCertificate {
            uuid: new_config_uuid(),
            fingerprint: fingerprint.clone(),
            host: None,
            enabled: true,
        });
        config.root_certificates.push(RootCertificate {
            uuid: new_config_uuid(),
            fingerprint: fingerprint.clone(),
            host: Some("localhost:443".into()),
            enabled: true,
        });
        config.validate().unwrap();
        config.root_certificates.push(RootCertificate {
            uuid: new_config_uuid(),
            fingerprint,
            host: Some("localhost:443".into()),
            enabled: true,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn protection_defaults_to_disabled_on_routes_and_default_route() {
        let config: Config = toml::from_str(
            r#"
            [[routes]]
            id = "api"
            [[routes.endpoints]]
            target = "api.example.com"
            "#,
        )
        .unwrap();
        assert!(!config.default_route.protection_enabled);
        assert!(!config.rules[0].protection_enabled);
        assert!(!config.rules[0].allow_sensitive_upload);
        config.validate().unwrap();
    }

    #[test]
    fn sensitive_upload_requires_an_exact_domain_route() {
        let mut config = Config::default();
        config.rules.push(RouteRule {
            uuid: new_config_uuid(),
            id: "trusted".into(),
            enabled: true,
            priority: 0,
            endpoints: vec![RouteEndpoint {
                target: "api.example.com".into(),
                port: Some(443),
            }],
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec![],
            protection_enabled: false,
            protection: None,
            allow_sensitive_upload: true,
            legacy: Default::default(),
        });
        config.validate().unwrap();
        config.rules[0].endpoints[0].target = "*.example.com".into();
        assert!(config.validate().is_err());
        config.rules[0].allow_sensitive_upload = false;
        config.default_route.allow_sensitive_upload = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn protection_provider_secret_is_redacted() {
        let mut config = Config::default();
        config.protections.push(ProtectionProfile {
            uuid: new_config_uuid(),
            id: "guard".into(),
            enabled: true,
            mode: ProtectionMode::Observe,
            data: DataProtectionConfig::default(),
            intelligence: IntelligenceProtectionConfig {
                providers: vec![IntelligenceProviderConfig {
                    uuid: new_config_uuid(),
                    id: "jev".into(),
                    enabled: true,
                    provider: IntelligenceProviderKind::Typesafe,
                    endpoint: None,
                    model: None,
                    api_key: Some(SecretValue::Inline {
                        value: "secret-key".into(),
                    }),
                    mode: ProtectionMode::Observe,
                }],
                ..IntelligenceProtectionConfig::default()
            },
        });
        config.validate().unwrap();
        let redacted = serde_json::to_string(&config.redacted()).unwrap();
        assert!(!redacted.contains("secret-key"));
        assert!(redacted.contains("<redacted>"));
    }
}
