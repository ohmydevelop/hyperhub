use crate::config::{
    AuditPolicy, Config, DefaultRoute, EnforcementMode, EnvironmentVariable, FileSandboxConfig,
    FileSandboxOperation, FileSandboxPattern, FileSandboxRule, FirewallAction, FirewallConfig,
    FirewallDefaultRule, FirewallEndpoint, FirewallRule, HttpAuthScheme, ListenerConfig,
    ModelGatewayConfig, PluginConfig, PluginKind, PluginProtocol, ProcessSandboxConfig,
    ProcessSandboxPattern, ProcessSandboxRule, RootCertificate, RouteEndpoint, RouteRule,
    SandboxAction, SandboxConfig, SandboxDefaultRule, SecretValue, SshAccount, SshHostKey,
    Upstream, UpstreamKind, WebSocketCapture,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub const CONFIG_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocument {
    pub schema_version: u32,
    pub gateway: GatewayDocument,
    pub sandbox: SandboxDocument,
    #[serde(default)]
    pub environment_variables: Vec<EnvironmentVariable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayDocument {
    pub mode: EnforcementMode,
    pub debug: bool,
    pub listener: ListenerDocument,
    #[serde(default)]
    pub model_gateway: ModelGatewayConfig,
    #[serde(default)]
    pub proxies: Vec<ProxyDocument>,
    #[serde(default)]
    pub credentials: Vec<CredentialDocument>,
    pub audit: AuditDocument,
    pub routing: RoutingDocument,
    pub trust: TrustDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerDocument {
    pub socks_address: String,
    pub pending_session_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyDocument {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    #[serde(rename = "type")]
    pub kind: UpstreamKind,
    pub address: String,
    pub timeout_milliseconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<ProxyAuthenticationDocument>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, SecretValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyAuthenticationDocument {
    pub username: SecretValue,
    pub password: SecretValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialDocument {
    HttpBasic {
        #[serde(default)]
        uuid: String,
        id: String,
        username: String,
        password: SecretValue,
    },
    HttpBearer {
        #[serde(default)]
        uuid: String,
        id: String,
        secret: SecretValue,
    },
    HttpToken {
        #[serde(default)]
        uuid: String,
        id: String,
        username: String,
        secret: SecretValue,
    },
    HttpXApiKey {
        #[serde(default)]
        uuid: String,
        id: String,
        secret: SecretValue,
    },
    HttpCookie {
        #[serde(default)]
        uuid: String,
        id: String,
        name: String,
        secret: SecretValue,
    },
    HttpQueryParameter {
        #[serde(default)]
        uuid: String,
        id: String,
        name: String,
        secret: SecretValue,
    },
    HttpCustomHeaders {
        #[serde(default)]
        uuid: String,
        id: String,
        headers: HashMap<String, SecretValue>,
    },
    Ssh {
        #[serde(default)]
        uuid: String,
        id: String,
        accounts: Vec<SshAccount>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDocument {
    pub settings: AuditSettingsDocument,
    #[serde(default)]
    pub profiles: Vec<AuditProfileDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSettingsDocument {
    pub retention_days: u32,
    pub connections: bool,
    #[serde(default)]
    pub header_allowlist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditProfileDocument {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    pub protocols: Vec<PluginProtocol>,
    pub capture: AuditCaptureDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCaptureDocument {
    pub http_body: bool,
    pub body_limit_bytes: usize,
    pub git_transcript: bool,
    pub ssh_transcript: bool,
    pub websocket: WebSocketCapture,
    pub directions: AuditDirectionsDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDirectionsDocument {
    pub client_upload: bool,
    pub server_response: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingDocument {
    pub default: DefaultRouteDocument,
    #[serde(default)]
    pub routes: Vec<RouteDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultRouteDocument {
    pub enabled: bool,
    pub decision: DefaultDecisionDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultDecisionDocument {
    pub action: DecisionAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDocument {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    pub enabled: bool,
    pub priority: i32,
    pub endpoints: Vec<RouteEndpoint>,
    pub decision: RouteDecisionDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDecisionDocument {
    pub action: DecisionAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrite: Option<RouteRewriteDocument>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRewriteDocument {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDocument {
    #[serde(default)]
    pub tls_certificates: Vec<TlsCertificateDocument>,
    #[serde(default)]
    pub ssh_host_keys: Vec<SshHostKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCertificateDocument {
    #[serde(default)]
    pub uuid: String,
    pub fingerprint: String,
    pub scope: TlsScopeDocument,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TlsScopeDocument {
    Global,
    Host { authority: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxDocument {
    pub network: NetworkPolicyDocument,
    pub file: FilePolicyDocument,
    pub process: ProcessPolicyDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyDocument {
    pub enabled: bool,
    pub default_action: DecisionAction,
    pub error_action: DecisionAction,
    #[serde(default)]
    pub rules: Vec<NetworkRuleDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePolicyDocument {
    pub enabled: bool,
    pub default_action: DecisionAction,
    pub error_action: DecisionAction,
    #[serde(default)]
    pub rules: Vec<FileRuleDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicyDocument {
    pub enabled: bool,
    pub default_action: DecisionAction,
    pub error_action: DecisionAction,
    #[serde(default)]
    pub rules: Vec<ProcessRuleDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRuleDocument {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    pub enabled: bool,
    pub priority: i32,
    pub action: DecisionAction,
    pub endpoints: Vec<FirewallEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRuleDocument {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    pub enabled: bool,
    pub priority: i32,
    pub action: DecisionAction,
    pub patterns: Vec<FileSandboxPattern>,
    pub operations: Vec<FileSandboxOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRuleDocument {
    #[serde(default)]
    pub uuid: String,
    pub id: String,
    pub enabled: bool,
    pub priority: i32,
    pub action: DecisionAction,
    pub patterns: Vec<ProcessSandboxPattern>,
}

impl ConfigDocument {
    pub fn from_config(config: &Config) -> Self {
        let credential_ids = config
            .plugins
            .iter()
            .filter(|plugin| plugin.kind == PluginKind::Credential)
            .map(|plugin| plugin.id.as_str())
            .collect::<HashSet<_>>();
        let audit_ids = config
            .plugins
            .iter()
            .filter(|plugin| plugin.kind == PluginKind::Audit)
            .map(|plugin| plugin.id.as_str())
            .collect::<HashSet<_>>();
        let split = |ids: &[String]| {
            let credentials = ids
                .iter()
                .filter(|id| credential_ids.contains(id.as_str()))
                .cloned()
                .collect();
            let audits = ids
                .iter()
                .filter(|id| audit_ids.contains(id.as_str()))
                .cloned()
                .collect();
            (credentials, audits)
        };
        let (default_credentials, default_audits) = split(&config.default_route.plugins);
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            gateway: GatewayDocument {
                mode: config.mode,
                debug: config.debug,
                listener: ListenerDocument {
                    socks_address: config.listener.socks_listen.clone(),
                    pending_session_ttl_seconds: config.listener.pending_session_ttl_secs,
                },
                model_gateway: config.model_gateway.clone(),
                proxies: config
                    .upstreams
                    .iter()
                    .cloned()
                    .map(ProxyDocument::from)
                    .collect(),
                credentials: config
                    .plugins
                    .iter()
                    .filter(|plugin| plugin.kind == PluginKind::Credential)
                    .map(CredentialDocument::from_plugin)
                    .collect(),
                audit: AuditDocument {
                    settings: AuditSettingsDocument {
                        retention_days: config.audit.retention_days,
                        connections: config.audit.connections,
                        header_allowlist: config.audit.header_allowlist.clone(),
                    },
                    profiles: config
                        .plugins
                        .iter()
                        .filter(|plugin| plugin.kind == PluginKind::Audit)
                        .map(AuditProfileDocument::from_plugin)
                        .collect(),
                },
                routing: RoutingDocument {
                    default: DefaultRouteDocument {
                        enabled: config.default_route.enabled,
                        decision: DefaultDecisionDocument {
                            action: decision(config.default_route.deny),
                            credentials: default_credentials,
                            audit_profiles: default_audits,
                        },
                    },
                    routes: config
                        .rules
                        .iter()
                        .map(|route| {
                            let (credentials, audits) = split(&route.plugins);
                            RouteDocument {
                                uuid: route.uuid.clone(),
                                id: route.id.clone(),
                                enabled: route.enabled,
                                priority: route.priority,
                                endpoints: route.endpoints.clone(),
                                decision: RouteDecisionDocument {
                                    action: decision(route.deny),
                                    proxy: route.upstream.clone(),
                                    rewrite: (route.rewrite_host.is_some()
                                        || route.rewrite_port.is_some())
                                    .then(|| RouteRewriteDocument {
                                        host: route.rewrite_host.clone(),
                                        port: route.rewrite_port,
                                    }),
                                    credentials,
                                    audit_profiles: audits,
                                },
                            }
                        })
                        .collect(),
                },
                trust: TrustDocument {
                    tls_certificates: config
                        .root_certificates
                        .iter()
                        .map(|certificate| TlsCertificateDocument {
                            uuid: certificate.uuid.clone(),
                            fingerprint: certificate.fingerprint.clone(),
                            scope: certificate
                                .host
                                .clone()
                                .map_or(TlsScopeDocument::Global, |authority| {
                                    TlsScopeDocument::Host { authority }
                                }),
                            enabled: certificate.enabled,
                        })
                        .collect(),
                    ssh_host_keys: config.ssh_host_keys.clone(),
                },
            },
            sandbox: SandboxDocument {
                network: NetworkPolicyDocument {
                    enabled: config.firewall.enabled,
                    default_action: firewall_action(
                        config
                            .firewall
                            .default
                            .as_ref()
                            .map(|item| item.action)
                            .unwrap_or_default(),
                    ),
                    error_action: firewall_action(config.firewall.error_action),
                    rules: config
                        .firewall
                        .rules
                        .iter()
                        .map(NetworkRuleDocument::from)
                        .collect(),
                },
                file: FilePolicyDocument {
                    enabled: config.sandbox.file.enabled,
                    default_action: sandbox_action(config.sandbox.file.default.action),
                    error_action: sandbox_action(config.sandbox.file.error_action),
                    rules: config
                        .sandbox
                        .file
                        .rules
                        .iter()
                        .map(FileRuleDocument::from)
                        .collect(),
                },
                process: ProcessPolicyDocument {
                    enabled: config.sandbox.process.enabled,
                    default_action: sandbox_action(config.sandbox.process.default.action),
                    error_action: sandbox_action(config.sandbox.process.error_action),
                    rules: config
                        .sandbox
                        .process
                        .rules
                        .iter()
                        .map(ProcessRuleDocument::from)
                        .collect(),
                },
            },
            environment_variables: config.environment.clone(),
        }
    }

    pub fn into_config(self) -> Result<Config, String> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(format!(
                "unsupported configuration schema {}; expected {}",
                self.schema_version, CONFIG_SCHEMA_VERSION
            ));
        }
        let mut plugins = self
            .gateway
            .credentials
            .into_iter()
            .map(CredentialDocument::into_plugin)
            .collect::<Result<Vec<_>, _>>()?;
        plugins.extend(
            self.gateway
                .audit
                .profiles
                .into_iter()
                .map(AuditProfileDocument::into_plugin),
        );
        let mut config = Config {
            mode: self.gateway.mode,
            debug: self.gateway.debug,
            firewall: FirewallConfig {
                enabled: self.sandbox.network.enabled,
                default: Some(FirewallDefaultRule {
                    action: into_firewall_action(self.sandbox.network.default_action),
                }),
                error_action: into_firewall_action(self.sandbox.network.error_action),
                rules: self
                    .sandbox
                    .network
                    .rules
                    .into_iter()
                    .map(FirewallRule::from)
                    .collect(),
            },
            sandbox: SandboxConfig {
                process: ProcessSandboxConfig {
                    enabled: self.sandbox.process.enabled,
                    default: SandboxDefaultRule {
                        action: into_sandbox_action(self.sandbox.process.default_action),
                    },
                    error_action: into_sandbox_action(self.sandbox.process.error_action),
                    rules: self
                        .sandbox
                        .process
                        .rules
                        .into_iter()
                        .map(ProcessSandboxRule::from)
                        .collect(),
                },
                file: FileSandboxConfig {
                    enabled: self.sandbox.file.enabled,
                    default: SandboxDefaultRule {
                        action: into_sandbox_action(self.sandbox.file.default_action),
                    },
                    error_action: into_sandbox_action(self.sandbox.file.error_action),
                    rules: self
                        .sandbox
                        .file
                        .rules
                        .into_iter()
                        .map(FileSandboxRule::from)
                        .collect(),
                },
            },
            default_route: DefaultRoute {
                enabled: self.gateway.routing.default.enabled,
                deny: self.gateway.routing.default.decision.action == DecisionAction::Deny,
                plugins: join_bindings(
                    self.gateway.routing.default.decision.credentials,
                    self.gateway.routing.default.decision.audit_profiles,
                ),
            },
            listener: ListenerConfig {
                socks_listen: self.gateway.listener.socks_address,
                pending_session_ttl_secs: self.gateway.listener.pending_session_ttl_seconds,
            },
            model_gateway: self.gateway.model_gateway,
            audit: AuditPolicy {
                log: None,
                transcript_dir: None,
                retention_days: self.gateway.audit.settings.retention_days,
                connections: self.gateway.audit.settings.connections,
                header_allowlist: self.gateway.audit.settings.header_allowlist,
            },
            environment: self.environment_variables,
            upstreams: self
                .gateway
                .proxies
                .into_iter()
                .map(ProxyDocument::into_upstream)
                .collect::<Result<Vec<_>, _>>()?,
            plugins,
            root_certificates: self
                .gateway
                .trust
                .tls_certificates
                .into_iter()
                .map(|certificate| RootCertificate {
                    uuid: certificate.uuid,
                    fingerprint: certificate.fingerprint,
                    host: match certificate.scope {
                        TlsScopeDocument::Global => None,
                        TlsScopeDocument::Host { authority } => Some(authority),
                    },
                    enabled: certificate.enabled,
                })
                .collect(),
            ssh_host_keys: self.gateway.trust.ssh_host_keys,
            rules: self
                .gateway
                .routing
                .routes
                .into_iter()
                .map(|route| RouteRule {
                    uuid: route.uuid,
                    id: route.id,
                    enabled: route.enabled,
                    priority: route.priority,
                    endpoints: route.endpoints,
                    deny: route.decision.action == DecisionAction::Deny,
                    rewrite_host: route.decision.rewrite.as_ref().and_then(|v| v.host.clone()),
                    rewrite_port: route.decision.rewrite.and_then(|v| v.port),
                    upstream: route.decision.proxy,
                    plugins: join_bindings(
                        route.decision.credentials,
                        route.decision.audit_profiles,
                    ),
                    legacy: HashMap::new(),
                })
                .collect(),
            legacy: HashMap::new(),
        };
        config.ensure_item_uuids();
        config.validate().map_err(|error| error.to_string())?;
        Ok(config)
    }

    pub fn to_value(config: &Config) -> Result<Value, serde_json::Error> {
        serde_json::to_value(Self::from_config(config))
    }

    pub fn from_value(value: Value) -> Result<Config, String> {
        serde_json::from_value::<Self>(value)
            .map_err(|error| format!("invalid configuration schema v2: {error}"))?
            .into_config()
    }
}

impl From<Upstream> for ProxyDocument {
    fn from(value: Upstream) -> Self {
        let authentication = value
            .username
            .zip(value.password)
            .map(|(username, password)| ProxyAuthenticationDocument { username, password });
        Self {
            uuid: value.uuid,
            id: value.id,
            kind: value.kind,
            address: value.address,
            timeout_milliseconds: value.timeout_ms,
            authentication,
            headers: value.headers,
        }
    }
}

impl ProxyDocument {
    fn into_upstream(self) -> Result<Upstream, String> {
        let (username, password) = self.authentication.map_or((None, None), |auth| {
            (Some(auth.username), Some(auth.password))
        });
        Ok(Upstream {
            uuid: self.uuid,
            id: self.id,
            kind: self.kind,
            address: self.address,
            timeout_ms: self.timeout_milliseconds,
            username,
            password,
            headers: self.headers,
        })
    }
}

impl CredentialDocument {
    fn from_plugin(plugin: &PluginConfig) -> Self {
        let uuid = plugin.uuid.clone();
        let id = plugin.id.clone();
        if plugin.protocols.contains(&PluginProtocol::Ssh) {
            return Self::Ssh {
                uuid,
                id,
                accounts: plugin.ssh_accounts.clone(),
            };
        }
        match plugin.http_scheme.unwrap_or(HttpAuthScheme::CustomHeaders) {
            HttpAuthScheme::Basic => Self::HttpBasic {
                uuid,
                id,
                username: plugin.username.clone().unwrap_or_default(),
                password: plugin.password.clone().unwrap_or_else(empty_secret),
            },
            HttpAuthScheme::Bearer => Self::HttpBearer {
                uuid,
                id,
                secret: plugin.secret.clone().unwrap_or_else(empty_secret),
            },
            HttpAuthScheme::Token => Self::HttpToken {
                uuid,
                id,
                username: plugin.username.clone().unwrap_or_default(),
                secret: plugin.secret.clone().unwrap_or_else(empty_secret),
            },
            HttpAuthScheme::XApiKey => Self::HttpXApiKey {
                uuid,
                id,
                secret: plugin.secret.clone().unwrap_or_else(empty_secret),
            },
            HttpAuthScheme::Cookie => Self::HttpCookie {
                uuid,
                id,
                name: plugin.http_name.clone().unwrap_or_default(),
                secret: plugin.secret.clone().unwrap_or_else(empty_secret),
            },
            HttpAuthScheme::QueryParameter => Self::HttpQueryParameter {
                uuid,
                id,
                name: plugin.http_name.clone().unwrap_or_default(),
                secret: plugin.secret.clone().unwrap_or_else(empty_secret),
            },
            HttpAuthScheme::CustomHeaders | HttpAuthScheme::LegacyScopedToken => {
                Self::HttpCustomHeaders {
                    uuid,
                    id,
                    headers: plugin.headers.clone(),
                }
            }
        }
    }

    fn into_plugin(self) -> Result<PluginConfig, String> {
        let mut plugin = PluginConfig::default();
        plugin.kind = PluginKind::Credential;
        match self {
            Self::HttpBasic {
                uuid,
                id,
                username,
                password,
            } => {
                plugin.uuid = uuid;
                plugin.id = id;
                plugin.protocols = vec![PluginProtocol::Http];
                plugin.http_scheme = Some(HttpAuthScheme::Basic);
                plugin.username = Some(username);
                plugin.password = Some(password);
            }
            Self::HttpBearer { uuid, id, secret } => {
                plugin.uuid = uuid;
                plugin.id = id;
                plugin.protocols = vec![PluginProtocol::Http];
                plugin.http_scheme = Some(HttpAuthScheme::Bearer);
                plugin.secret = Some(secret);
            }
            Self::HttpToken {
                uuid,
                id,
                username,
                secret,
            } => {
                plugin.uuid = uuid;
                plugin.id = id;
                plugin.protocols = vec![PluginProtocol::Http];
                plugin.http_scheme = Some(HttpAuthScheme::Token);
                plugin.username = Some(username);
                plugin.secret = Some(secret);
            }
            Self::HttpXApiKey { uuid, id, secret } => {
                plugin.uuid = uuid;
                plugin.id = id;
                plugin.protocols = vec![PluginProtocol::Http];
                plugin.http_scheme = Some(HttpAuthScheme::XApiKey);
                plugin.secret = Some(secret);
            }
            Self::HttpCookie {
                uuid,
                id,
                name,
                secret,
            } => {
                plugin.uuid = uuid;
                plugin.id = id;
                plugin.protocols = vec![PluginProtocol::Http];
                plugin.http_scheme = Some(HttpAuthScheme::Cookie);
                plugin.http_name = Some(name);
                plugin.secret = Some(secret);
            }
            Self::HttpQueryParameter {
                uuid,
                id,
                name,
                secret,
            } => {
                plugin.uuid = uuid;
                plugin.id = id;
                plugin.protocols = vec![PluginProtocol::Http];
                plugin.http_scheme = Some(HttpAuthScheme::QueryParameter);
                plugin.http_name = Some(name);
                plugin.secret = Some(secret);
            }
            Self::HttpCustomHeaders { uuid, id, headers } => {
                plugin.uuid = uuid;
                plugin.id = id;
                plugin.protocols = vec![PluginProtocol::Http];
                plugin.http_scheme = Some(HttpAuthScheme::CustomHeaders);
                plugin.headers = headers;
            }
            Self::Ssh { uuid, id, accounts } => {
                plugin.uuid = uuid;
                plugin.id = id;
                plugin.protocols = vec![PluginProtocol::Ssh];
                plugin.ssh_accounts = accounts;
            }
        }
        Ok(plugin)
    }
}

impl AuditProfileDocument {
    fn from_plugin(plugin: &PluginConfig) -> Self {
        Self {
            uuid: plugin.uuid.clone(),
            id: plugin.id.clone(),
            protocols: plugin.protocols.clone(),
            capture: AuditCaptureDocument {
                http_body: plugin.capture_body,
                body_limit_bytes: plugin.body_limit,
                git_transcript: plugin.git_transcript_enabled(),
                ssh_transcript: plugin.ssh_transcript,
                websocket: plugin.websocket_capture,
                directions: AuditDirectionsDocument {
                    client_upload: plugin.transcript_client_upload,
                    server_response: plugin.transcript_server_response,
                },
            },
        }
    }

    fn into_plugin(self) -> PluginConfig {
        PluginConfig {
            uuid: self.uuid,
            id: self.id,
            kind: PluginKind::Audit,
            protocols: self.protocols,
            http_scheme: None,
            secret: None,
            http_name: None,
            username: None,
            password: None,
            ssh_accounts: Vec::new(),
            headers: HashMap::new(),
            legacy: HashMap::new(),
            capture_body: self.capture.http_body,
            body_limit: self.capture.body_limit_bytes,
            git_transcript: Some(self.capture.git_transcript),
            ssh_transcript: self.capture.ssh_transcript,
            websocket_capture: self.capture.websocket,
            transcript_client_upload: self.capture.directions.client_upload,
            transcript_server_response: self.capture.directions.server_response,
        }
    }
}

impl From<&FirewallRule> for NetworkRuleDocument {
    fn from(value: &FirewallRule) -> Self {
        Self {
            uuid: value.uuid.clone(),
            id: value.id.clone(),
            enabled: value.enabled,
            priority: value.priority,
            action: firewall_action(value.action),
            endpoints: value.endpoints.clone(),
        }
    }
}
impl From<NetworkRuleDocument> for FirewallRule {
    fn from(value: NetworkRuleDocument) -> Self {
        Self {
            uuid: value.uuid,
            id: value.id,
            enabled: value.enabled,
            priority: value.priority,
            action: into_firewall_action(value.action),
            endpoints: value.endpoints,
            legacy: HashMap::new(),
        }
    }
}
impl From<&FileSandboxRule> for FileRuleDocument {
    fn from(value: &FileSandboxRule) -> Self {
        Self {
            uuid: value.uuid.clone(),
            id: value.id.clone(),
            enabled: value.enabled,
            priority: value.priority,
            action: sandbox_action(value.action),
            patterns: value.patterns.clone(),
            operations: value.operations.clone(),
        }
    }
}
impl From<FileRuleDocument> for FileSandboxRule {
    fn from(value: FileRuleDocument) -> Self {
        Self {
            uuid: value.uuid,
            id: value.id,
            enabled: value.enabled,
            priority: value.priority,
            action: into_sandbox_action(value.action),
            patterns: value.patterns,
            operations: value.operations,
            legacy: HashMap::new(),
        }
    }
}
impl From<&ProcessSandboxRule> for ProcessRuleDocument {
    fn from(value: &ProcessSandboxRule) -> Self {
        Self {
            uuid: value.uuid.clone(),
            id: value.id.clone(),
            enabled: value.enabled,
            priority: value.priority,
            action: sandbox_action(value.action),
            patterns: value.patterns.clone(),
        }
    }
}
impl From<ProcessRuleDocument> for ProcessSandboxRule {
    fn from(value: ProcessRuleDocument) -> Self {
        Self {
            uuid: value.uuid,
            id: value.id,
            enabled: value.enabled,
            priority: value.priority,
            action: into_sandbox_action(value.action),
            patterns: value.patterns,
            legacy: HashMap::new(),
        }
    }
}

fn empty_secret() -> SecretValue {
    SecretValue::Inline {
        value: String::new(),
    }
}

fn decision(deny: bool) -> DecisionAction {
    if deny {
        DecisionAction::Deny
    } else {
        DecisionAction::Allow
    }
}

fn firewall_action(action: FirewallAction) -> DecisionAction {
    match action {
        FirewallAction::Pass => DecisionAction::Allow,
        FirewallAction::Deny => DecisionAction::Deny,
    }
}

fn sandbox_action(action: SandboxAction) -> DecisionAction {
    match action {
        SandboxAction::Pass => DecisionAction::Allow,
        SandboxAction::Deny => DecisionAction::Deny,
    }
}

fn into_firewall_action(action: DecisionAction) -> FirewallAction {
    match action {
        DecisionAction::Allow => FirewallAction::Pass,
        DecisionAction::Deny => FirewallAction::Deny,
    }
}

fn into_sandbox_action(action: DecisionAction) -> SandboxAction {
    match action {
        DecisionAction::Allow => SandboxAction::Pass,
        DecisionAction::Deny => SandboxAction::Deny,
    }
}

fn join_bindings(mut credentials: Vec<String>, audits: Vec<String>) -> Vec<String> {
    credentials.extend(audits);
    credentials
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{new_config_uuid, PluginConfig};
    use serde_json::json;

    #[test]
    fn schema_v2_separates_credentials_audit_and_routing() {
        let mut config = Config::default();
        let mut credential = PluginConfig::default();
        credential.uuid = new_config_uuid();
        credential.id = "api-token".into();
        credential.kind = PluginKind::Credential;
        credential.protocols = vec![PluginProtocol::Http];
        credential.http_scheme = Some(HttpAuthScheme::Bearer);
        credential.secret = Some(SecretValue::Inline {
            value: "secret".into(),
        });
        config.plugins.push(credential);
        config.rules.push(RouteRule {
            uuid: new_config_uuid(),
            id: "api".into(),
            enabled: true,
            priority: 300,
            endpoints: vec![RouteEndpoint {
                target: "https://api.example.test/v1".into(),
                port: Some(443),
            }],
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec!["api-token".into()],
            legacy: HashMap::new(),
        });
        let value = ConfigDocument::to_value(&config.redacted()).unwrap();
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["gateway"]["credentials"][0]["type"], "http_bearer");
        assert_eq!(
            value["gateway"]["credentials"][0]["secret"]["value"],
            "<redacted>"
        );
        assert!(value["gateway"]["credentials"][0]
            .get("capture_body")
            .is_none());
        assert_eq!(
            value["gateway"]["routing"]["routes"][0]["decision"]["credentials"],
            json!(["api-token"])
        );
        assert!(value.get("plugins").is_none());
        assert!(value.get("firewall").is_none());
    }

    #[test]
    fn schema_v2_round_trips_and_rejects_legacy_or_unknown_fields() {
        let config = Config::default();
        let value = ConfigDocument::to_value(&config).unwrap();
        ConfigDocument::from_value(value.clone()).unwrap();

        let mut legacy = value.clone();
        legacy.as_object_mut().unwrap().remove("schema_version");
        legacy
            .as_object_mut()
            .unwrap()
            .insert("plugins".into(), json!([]));
        assert!(ConfigDocument::from_value(legacy)
            .unwrap_err()
            .contains("schema v2"));

        let mut unknown = value;
        unknown["gateway"]["unexpected"] = json!(true);
        assert!(ConfigDocument::from_value(unknown)
            .unwrap_err()
            .contains("unknown field"));
    }
}
