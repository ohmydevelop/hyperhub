use crate::config::{
    parse_route_target, Config, PluginConfig, RouteRule, RouteTarget, DEFAULT_ROUTE_ID,
};
use crate::plugin::PluginSet;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub tid: u32,
    pub executable: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    pub ip: IpAddr,
    pub port: u16,
    #[serde(default)]
    pub hostnames: Vec<String>,
}

impl Destination {
    pub fn authority_host(&self) -> String {
        self.hostnames
            .first()
            .cloned()
            .unwrap_or_else(|| self.ip.to_string())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Unknown,
    Http,
    Tls,
    Ssh,
    Git,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionContext {
    pub session_id: String,
    pub connection_id: u64,
    pub process: ProcessInfo,
    pub destination: Destination,
    pub protocol: Protocol,
}

#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub rule_id: Option<String>,
    pub deny: bool,
    pub upstream: Option<String>,
    pub plugins: PluginSet,
    pub destination: Destination,
}

#[derive(Debug, Clone)]
pub struct HttpRouteDecision {
    pub rule_id: Option<String>,
    pub deny: bool,
    pub plugins: PluginSet,
}

#[derive(Debug)]
struct CompiledRule {
    order: usize,
    rule: RouteRule,
    endpoints: Vec<CompiledRouteEndpoint>,
    plugins: PluginSet,
}

#[derive(Debug)]
struct CompiledRouteEndpoint {
    target: RouteTarget,
    port: Option<u16>,
}

#[derive(Debug)]
pub struct PolicySnapshot {
    default_route: Option<CompiledDefaultRoute>,
    rules: Vec<CompiledRule>,
}

#[derive(Debug)]
struct CompiledDefaultRoute {
    deny: bool,
    plugins: PluginSet,
}

impl PolicySnapshot {
    pub fn compile(config: &Config) -> Result<Self, String> {
        let mut rules = Vec::with_capacity(config.rules.len());
        for (order, rule) in config.rules.iter().cloned().enumerate() {
            if !rule.enabled {
                continue;
            }
            let endpoints = rule
                .endpoints
                .iter()
                .map(|endpoint| {
                    parse_route_target(&endpoint.target)
                        .map_err(|message| {
                            format!(
                                "route '{}' contains invalid target '{}': {message}",
                                rule.id, endpoint.target
                            )
                        })
                        .map(|target| CompiledRouteEndpoint {
                            target,
                            port: endpoint.port,
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let plugins = PluginSet(
                rule.plugins
                    .iter()
                    .map(|id| {
                        config.plugin(id).cloned().ok_or_else(|| {
                            format!("route '{}' references unknown plugin '{id}'", rule.id)
                        })
                    })
                    .collect::<Result<Vec<PluginConfig>, _>>()?,
            );
            rules.push(CompiledRule {
                order,
                rule,
                endpoints,
                plugins,
            });
        }
        let default_route = if config.default_route.enabled {
            let plugins = PluginSet(
                config
                    .default_route
                    .plugins
                    .iter()
                    .map(|id| {
                        config.plugin(id).cloned().ok_or_else(|| {
                            format!("default route references unknown plugin '{id}'")
                        })
                    })
                    .collect::<Result<Vec<PluginConfig>, _>>()?,
            );
            Some(CompiledDefaultRoute {
                deny: config.default_route.deny,
                plugins,
            })
        } else {
            None
        };
        rules.sort_by_key(|entry| (Reverse(entry.rule.priority), entry.order));
        Ok(Self {
            default_route,
            rules,
        })
    }

    pub fn decide(&self, context: &ConnectionContext) -> RouteDecision {
        for entry in &self.rules {
            if entry.matches_connection(context) {
                return entry.decision(context);
            }
        }
        match &self.default_route {
            Some(default) => RouteDecision {
                rule_id: Some(DEFAULT_ROUTE_ID.to_string()),
                deny: default.deny,
                upstream: None,
                plugins: default.plugins.clone(),
                destination: context.destination.clone(),
            },
            None => RouteDecision {
                rule_id: None,
                deny: false,
                upstream: None,
                plugins: PluginSet::default(),
                destination: context.destination.clone(),
            },
        }
    }

    pub fn decide_http(
        &self,
        context: &ConnectionContext,
        path_and_query: &str,
    ) -> HttpRouteDecision {
        for entry in &self.rules {
            if entry.matches_connection(context) && entry.matches_http(context, path_and_query) {
                return HttpRouteDecision {
                    rule_id: Some(entry.rule.id.clone()),
                    deny: entry.rule.deny,
                    plugins: entry.plugins.clone(),
                };
            }
        }
        match &self.default_route {
            Some(default) => HttpRouteDecision {
                rule_id: Some(DEFAULT_ROUTE_ID.to_string()),
                deny: default.deny,
                plugins: default.plugins.clone(),
            },
            None => HttpRouteDecision {
                rule_id: None,
                deny: false,
                plugins: PluginSet::default(),
            },
        }
    }
}

impl CompiledRule {
    fn matches_connection(&self, context: &ConnectionContext) -> bool {
        if !self.endpoints.iter().any(|endpoint| {
            endpoint
                .port
                .is_none_or(|port| port == context.destination.port)
                && match &endpoint.target {
                    RouteTarget::Ip(ip) => context.destination.ip == *ip,
                    RouteTarget::Network(network) => network.contains(&context.destination.ip),
                    RouteTarget::Domain { host, wildcard, .. } => {
                        context.destination.hostnames.iter().any(|candidate| {
                            let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
                            domain_matches(&candidate, host, *wildcard)
                        })
                    }
                }
        }) {
            return false;
        }
        true
    }

    fn matches_http(&self, context: &ConnectionContext, path_and_query: &str) -> bool {
        self.http_target_matches(context, path_and_query)
    }

    /// URL 形式 target 的路径前缀约束（仅 HTTP 家族请求路径生效；非 HTTP 协议
    /// 无路径概念，targets 退化为纯主机匹配）。无 URL 条目时放行所有路径；命中
    /// 某条目的主机后，该条目无前缀则放行该主机所有路径，有前缀则要求路径命中。
    fn http_target_matches(&self, context: &ConnectionContext, path_and_query: &str) -> bool {
        let mut has_url_target = false;
        for endpoint in &self.endpoints {
            if endpoint
                .port
                .is_some_and(|port| port != context.destination.port)
            {
                continue;
            }
            let RouteTarget::Domain {
                host,
                wildcard,
                path_prefix,
            } = &endpoint.target
            else {
                continue;
            };
            let host_matched = context.destination.hostnames.iter().any(|candidate| {
                let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
                domain_matches(&candidate, host, *wildcard)
            });
            if !host_matched {
                continue;
            }
            match path_prefix {
                None => return true,
                Some(prefix) => {
                    has_url_target = true;
                    if path_matches_prefix(path_and_query, prefix) {
                        return true;
                    }
                }
            }
        }
        !has_url_target
    }

    fn decision(&self, context: &ConnectionContext) -> RouteDecision {
        let mut destination = context.destination.clone();
        if let Some(host) = &self.rule.rewrite_host {
            if let Ok(ip) = host.parse::<IpAddr>() {
                destination.ip = ip;
                destination.hostnames.clear();
            } else {
                destination.hostnames = vec![host.to_ascii_lowercase()];
            }
        }
        if let Some(port) = self.rule.rewrite_port {
            destination.port = port;
        }
        RouteDecision {
            rule_id: Some(self.rule.id.clone()),
            deny: self.rule.deny,
            upstream: self.rule.upstream.clone(),
            plugins: self.plugins.clone(),
            destination,
        }
    }
}

fn domain_matches(candidate: &str, configured: &str, wildcard: bool) -> bool {
    if wildcard {
        candidate != configured && candidate.ends_with(&format!(".{configured}"))
    } else {
        candidate == configured
    }
}

/// URL 路径前缀命中：`/api` 命中 `/api`、`/api/` 与 `/api/...`，不命中 `/api2`。
fn path_matches_prefix(path_and_query: &str, prefix: &str) -> bool {
    let path = path_and_query.split(['?', '#']).next().unwrap_or("");
    if path_is_ambiguous(path) {
        return false;
    }
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn path_is_ambiguous(path: &str) -> bool {
    if path.contains('\\') || path.split('/').any(|segment| matches!(segment, "." | "..")) {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    ["%2e", "%2f", "%5c", "%25"]
        .iter()
        .any(|encoded| lower.contains(encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PluginKind, PluginProtocol, RouteEndpoint, RouteRule};

    fn endpoints(targets: &[&str]) -> Vec<RouteEndpoint> {
        targets
            .iter()
            .map(|target| RouteEndpoint {
                target: (*target).into(),
                port: None,
            })
            .collect()
    }

    fn context() -> ConnectionContext {
        ConnectionContext {
            session_id: "s".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "/usr/bin/ssh".into(),
            },
            destination: Destination {
                ip: "1.2.3.4".parse().unwrap(),
                port: 22,
                hostnames: vec!["github.com".into()],
            },
            protocol: Protocol::Unknown,
        }
    }

    #[test]
    fn priority_rewrite_and_default() {
        let mut config = Config::default();
        config.rules = vec![
            RouteRule {
                uuid: crate::config::new_config_uuid(),
                id: "low".into(),
                enabled: true,
                priority: 1,
                endpoints: endpoints(&["github.com"]),
                deny: true,
                rewrite_host: None,
                rewrite_port: None,
                upstream: None,
                plugins: vec![],
                legacy: Default::default(),
            },
            RouteRule {
                uuid: crate::config::new_config_uuid(),
                id: "high".into(),
                enabled: true,
                priority: 5,
                endpoints: endpoints(&["github.com"]),
                deny: false,
                rewrite_host: Some("10.0.0.2".into()),
                rewrite_port: Some(2222),
                upstream: None,
                plugins: vec![],
                legacy: Default::default(),
            },
        ];
        let decision = PolicySnapshot::compile(&config).unwrap().decide(&context());
        assert_eq!(decision.rule_id.as_deref(), Some("high"));
        assert_eq!(decision.destination.ip.to_string(), "10.0.0.2");
        assert_eq!(decision.destination.port, 2222);
    }

    #[test]
    fn disabled_rule_is_not_matched() {
        let mut config = Config::default();
        config.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: "off".into(),
            enabled: false,
            priority: 100,
            endpoints: endpoints(&["github.com"]),
            deny: true,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec![],
            legacy: Default::default(),
        });
        let policy = PolicySnapshot::compile(&config).unwrap();
        let decision = policy.decide(&context());
        assert_eq!(decision.rule_id.as_deref(), Some(DEFAULT_ROUTE_ID));
        assert!(!decision.deny);
    }

    #[test]
    fn default_route_reports_its_id_deny_and_plugins() {
        let mut config = Config::default();
        config.plugins.push(PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "audit-all".into(),
            kind: PluginKind::Audit,
            protocols: vec![PluginProtocol::Http],
            ..PluginConfig::default()
        });
        config.default_route.deny = true;
        config.default_route.plugins = vec!["audit-all".into()];
        let policy = PolicySnapshot::compile(&config).unwrap();
        let decision = policy.decide(&context());
        assert_eq!(decision.rule_id.as_deref(), Some(DEFAULT_ROUTE_ID));
        assert!(decision.deny);
        assert_eq!(
            decision
                .plugins
                .audit_for(PluginProtocol::Http)
                .map(|plugin| plugin.id.as_str()),
            Some("audit-all")
        );
    }

    #[test]
    fn exact_domain_target_does_not_match_subdomains_or_other_hosts() {
        let mut config = Config::default();
        config.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: "baidu".into(),
            enabled: true,
            priority: 100,
            endpoints: endpoints(&["baidu.com"]),
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec![],
            legacy: Default::default(),
        });
        let policy = PolicySnapshot::compile(&config).unwrap();
        let mut request = context();
        request.destination.port = 443;
        request.destination.hostnames = vec!["www.baidu.com".into()];
        assert_eq!(
            policy.decide(&request).rule_id.as_deref(),
            Some(DEFAULT_ROUTE_ID)
        );
        request.destination.hostnames = vec!["baidu.com".into()];
        assert_eq!(policy.decide(&request).rule_id.as_deref(), Some("baidu"));
        request.destination.hostnames = vec!["example.com".into()];
        assert_eq!(
            policy.decide(&request).rule_id.as_deref(),
            Some(DEFAULT_ROUTE_ID)
        );
    }

    #[test]
    fn route_endpoint_binds_target_and_gateway_port() {
        let mut config = Config::default();
        config.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: "https-only".into(),
            enabled: true,
            priority: 100,
            endpoints: vec![RouteEndpoint {
                target: "example.com".into(),
                port: Some(443),
            }],
            deny: true,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec![],
            legacy: Default::default(),
        });
        let policy = PolicySnapshot::compile(&config).unwrap();
        let mut request = context();
        request.destination.hostnames = vec!["example.com".into()];
        request.destination.port = 443;
        assert_eq!(
            policy.decide(&request).rule_id.as_deref(),
            Some("https-only")
        );
        request.destination.port = 80;
        assert_eq!(
            policy.decide(&request).rule_id.as_deref(),
            Some(DEFAULT_ROUTE_ID)
        );
    }

    #[test]
    fn wildcard_targets_match_subdomains_but_not_apex() {
        let mut config = Config::default();
        config.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: "friendly".into(),
            enabled: true,
            priority: 100,
            endpoints: endpoints(&["*.github.com", "1.2.3.4", "10.0.0.0/8"]),
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec![],
            legacy: Default::default(),
        });
        let policy = PolicySnapshot::compile(&config).unwrap();
        let mut request = context();
        request.destination.ip = "192.0.2.1".parse().unwrap();
        request.destination.hostnames = vec!["api.github.com".into()];
        assert_eq!(policy.decide(&request).rule_id.as_deref(), Some("friendly"));
        request.destination.hostnames = vec!["a.b.github.com".into()];
        assert_eq!(policy.decide(&request).rule_id.as_deref(), Some("friendly"));
        request.destination.hostnames = vec!["github.com".into()];
        assert_eq!(
            policy.decide(&request).rule_id.as_deref(),
            Some(DEFAULT_ROUTE_ID)
        );
        request.destination.hostnames = vec!["example.com".into()];
        request.destination.ip = "10.1.2.3".parse().unwrap();
        assert_eq!(policy.decide(&request).rule_id.as_deref(), Some("friendly"));
        request.destination.ip = "192.0.2.1".parse().unwrap();
        assert_eq!(
            policy.decide(&request).rule_id.as_deref(),
            Some(DEFAULT_ROUTE_ID)
        );
    }

    #[test]
    fn url_form_targets_match_request_paths_only_for_http_family() {
        let mut config = Config::default();
        config.plugins.push(PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "api-token".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Http],
            ..PluginConfig::default()
        });
        config.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: "api".into(),
            enabled: true,
            priority: 1,
            endpoints: endpoints(&["api.example.com/v1", "cdn.example.com"]),
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec!["api-token".into()],
            legacy: Default::default(),
        });
        let policy = PolicySnapshot::compile(&config).unwrap();

        let mut request = context();
        request.destination.hostnames = vec!["api.example.com".into()];
        request.destination.port = 80;
        request.protocol = Protocol::Http;

        // 连接级：URL 目标退化为主机匹配，路径不影响连接决策。
        assert_eq!(policy.decide(&request).rule_id.as_deref(), Some("api"));

        // 按请求：/v1 前缀命中（含子路径与查询串），非前缀路径不命中，大小写敏感。
        let matched = policy.decide_http(&request, "/v1/users?page=2");
        assert_eq!(matched.rule_id.as_deref(), Some("api"));
        assert_eq!(
            matched
                .plugins
                .credential_for(PluginProtocol::Http)
                .map(|p| p.id.as_str()),
            Some("api-token")
        );
        assert_eq!(
            policy.decide_http(&request, "/v1").rule_id.as_deref(),
            Some("api")
        );
        assert_eq!(
            policy.decide_http(&request, "/v2/users").rule_id.as_deref(),
            Some(DEFAULT_ROUTE_ID)
        );
        assert_eq!(
            policy
                .decide_http(&request, "/v10/users")
                .rule_id
                .as_deref(),
            Some(DEFAULT_ROUTE_ID)
        );
        assert_eq!(
            policy.decide_http(&request, "/V1/users").rule_id.as_deref(),
            Some(DEFAULT_ROUTE_ID)
        );
        for ambiguous in [
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/%2Fadmin",
            "/v1/%252e%252e/admin",
            "/v1\\admin",
        ] {
            assert_eq!(
                policy.decide_http(&request, ambiguous).rule_id.as_deref(),
                Some(DEFAULT_ROUTE_ID),
                "matched ambiguous path {ambiguous}"
            );
        }

        // 无前缀条目命中主机时放行该主机所有路径。
        request.destination.hostnames = vec!["cdn.example.com".into()];
        assert_eq!(
            policy.decide_http(&request, "/anything").rule_id.as_deref(),
            Some("api")
        );

        // 非 HTTP 协议：URL 路径约束不生效（无路径概念），连接级主机匹配即可。
        let mut ssh_config = Config::default();
        ssh_config.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: "ssh-host".into(),
            enabled: true,
            priority: 1,
            endpoints: endpoints(&["git.example.com/repo"]),
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec![],
            legacy: Default::default(),
        });
        let policy = PolicySnapshot::compile(&ssh_config).unwrap();
        request.destination.hostnames = vec!["git.example.com".into()];
        request.protocol = Protocol::Ssh;
        assert_eq!(policy.decide(&request).rule_id.as_deref(), Some("ssh-host"));
    }
}
