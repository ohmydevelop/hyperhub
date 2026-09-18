use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigSection {
    Gateway,
    Basic,
    Proxy,
    Credential,
    Audit,
    Route,
    Certificate,
    Sandbox,
    Network,
    SandboxProcess,
    Files,
    Process,
    Environment,
}

impl ConfigSection {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Gateway => "网关",
            Self::Basic => "基础",
            Self::Proxy => "代理",
            Self::Credential => "凭证",
            Self::Audit => "审计",
            Self::Route => "路由",
            Self::Certificate => "证书",
            Self::Sandbox => "沙盒",
            Self::Network => "网络",
            Self::SandboxProcess => "子进程",
            Self::Files => "文件",
            Self::Process => "进程",
            Self::Environment => "环境变量",
        }
    }

    pub(crate) fn breadcrumb(self) -> String {
        match self {
            Self::Gateway | Self::Sandbox | Self::Process | Self::Environment => {
                self.label().into()
            }
            Self::Basic
            | Self::Proxy
            | Self::Credential
            | Self::Audit
            | Self::Route
            | Self::Certificate => format!("网关 / {}", self.label()),
            Self::Network | Self::SandboxProcess | Self::Files => {
                format!("沙盒 / {}", self.label())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigChangeAction {
    Add,
    Modify,
    Delete,
}

impl ConfigChangeAction {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Add => "新增",
            Self::Modify => "修改",
            Self::Delete => "删除",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigChangeDescription {
    pub(crate) action: ConfigChangeAction,
    pub(crate) section: ConfigSection,
    pub(crate) item_kind: String,
    pub(crate) item_name: Option<String>,
    pub(crate) item_uuid: Option<String>,
    pub(crate) field: Option<String>,
    pub(crate) details: Vec<String>,
    pub(crate) summary: String,
}

pub(crate) fn describe_request(
    current: &Value,
    operations: &[Value],
) -> Result<ConfigChangeDescription, String> {
    let mutation = operations
        .iter()
        .rev()
        .find(|operation| operation.get("op").and_then(Value::as_str) != Some("test"))
        .ok_or("configuration request has no mutation")?;
    let object = mutation
        .as_object()
        .ok_or("configuration request mutation must be an object")?;
    let operation = object
        .get("op")
        .and_then(Value::as_str)
        .ok_or("configuration request mutation is missing string field 'op'")?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or("configuration request mutation is missing string field 'path'")?;
    let tokens = pointer_tokens(path)?;
    let context = item_context(current, mutation, &tokens);
    let action = match operation {
        "add" if context.whole_item => ConfigChangeAction::Add,
        "remove" if context.whole_item => ConfigChangeAction::Delete,
        "add" | "replace" | "remove" => ConfigChangeAction::Modify,
        other => return Err(format!("unsupported semantic mutation '{other}'")),
    };
    let breadcrumb = context.section.breadcrumb();
    let target = match &context.item_name {
        Some(name) if context.item_kind == context.section.label() => {
            format!("{breadcrumb}「{name}」")
        }
        Some(name) => format!("{breadcrumb} / {}「{name}」", context.item_kind),
        None if context.item_kind == context.section.label() => breadcrumb,
        None => format!("{breadcrumb} / {}", context.item_kind),
    };
    let summary = match &context.field {
        Some(field) => format!("{} {target}：{field}", action.label()),
        None => format!("{} {target}", action.label()),
    };
    Ok(ConfigChangeDescription {
        action,
        section: context.section,
        item_kind: context.item_kind,
        item_name: context.item_name,
        item_uuid: context.item_uuid,
        field: context.field,
        details: context.details,
        summary,
    })
}

pub(crate) fn allow_deny_label(deny: bool) -> &'static str {
    if deny {
        "拒绝"
    } else {
        "放行"
    }
}

pub(crate) fn route_behavior_label(deny: bool, has_upstream: bool) -> &'static str {
    if deny {
        "拒绝"
    } else if has_upstream {
        "经代理"
    } else {
        "直连"
    }
}

pub(crate) fn new_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub(crate) fn valid_uuid(value: &str) -> bool {
    hyperhub_core::config::valid_config_uuid(value)
}

pub(crate) fn unique_valid_uuids<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = HashSet::new();
    values.all(|value| valid_uuid(value) && seen.insert(value))
}

struct ItemContext {
    section: ConfigSection,
    item_kind: String,
    item_name: Option<String>,
    item_uuid: Option<String>,
    field: Option<String>,
    details: Vec<String>,
    whole_item: bool,
}

fn item_context(current: &Value, mutation: &Value, tokens: &[String]) -> ItemContext {
    let value = mutation.get("value");
    match tokens {
        [root, _, rest @ ..] if root == "upstreams" => collection_context(
            current,
            value,
            tokens,
            2,
            ConfigSection::Proxy,
            "代理",
            "id",
            rest,
        ),
        [root, _, rest @ ..] if root == "plugins" => {
            let item = collection_item(current, value, tokens, 2);
            let kind = item
                .and_then(|item| item.get("kind"))
                .and_then(Value::as_str);
            let (section, label) = match kind {
                Some("credential") => (ConfigSection::Credential, "凭证"),
                Some("audit") => (ConfigSection::Audit, "审计插件"),
                _ => (ConfigSection::Gateway, "插件"),
            };
            context_from_item(item, section, label, "id", rest)
        }
        [root, _, rest @ ..] if root == "routes" => collection_context(
            current,
            value,
            tokens,
            2,
            ConfigSection::Route,
            "路由",
            "id",
            rest,
        ),
        [root, _, rest @ ..] if root == "environment" => collection_context(
            current,
            value,
            tokens,
            2,
            ConfigSection::Environment,
            "环境变量",
            "name",
            rest,
        ),
        [root, _, rest @ ..] if root == "root_certificates" => collection_context(
            current,
            value,
            tokens,
            2,
            ConfigSection::Certificate,
            "根证书",
            "fingerprint",
            rest,
        ),
        [root, _, rest @ ..] if root == "ssh_host_keys" => collection_context(
            current,
            value,
            tokens,
            2,
            ConfigSection::Certificate,
            "SSH 主机密钥",
            "host",
            rest,
        ),
        [root, rules, _, rest @ ..] if root == "firewall" && rules == "rules" => {
            collection_context(
                current,
                value,
                tokens,
                3,
                ConfigSection::Network,
                "网络规则",
                "id",
                rest,
            )
        }
        [root, area, rules, _, rest @ ..]
            if root == "sandbox" && area == "process" && rules == "rules" =>
        {
            collection_context(
                current,
                value,
                tokens,
                4,
                ConfigSection::SandboxProcess,
                "子进程规则",
                "id",
                rest,
            )
        }
        [root, area, rules, _, rest @ ..]
            if root == "sandbox" && area == "file" && rules == "rules" =>
        {
            collection_context(
                current,
                value,
                tokens,
                4,
                ConfigSection::Files,
                "文件规则",
                "id",
                rest,
            )
        }
        [root, rest @ ..] => singleton_context(root, rest),
        [] => ItemContext {
            section: ConfigSection::Gateway,
            item_kind: "完整配置".into(),
            item_name: None,
            item_uuid: None,
            field: None,
            details: Vec::new(),
            whole_item: false,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn collection_context(
    current: &Value,
    value: Option<&Value>,
    tokens: &[String],
    item_depth: usize,
    section: ConfigSection,
    label: &str,
    identity_field: &str,
    rest: &[String],
) -> ItemContext {
    let item = collection_item(current, value, tokens, item_depth);
    context_from_item(item, section, label, identity_field, rest)
}

fn collection_item<'a>(
    current: &'a Value,
    value: Option<&'a Value>,
    tokens: &[String],
    item_depth: usize,
) -> Option<&'a Value> {
    if tokens.get(item_depth - 1).is_some_and(|token| token == "-") {
        return value;
    }
    let pointer = format!(
        "/{}",
        tokens[..item_depth]
            .iter()
            .map(|token| escape_pointer(token))
            .collect::<Vec<_>>()
            .join("/")
    );
    current
        .pointer(&pointer)
        .or_else(|| (tokens.len() == item_depth).then_some(value).flatten())
}

fn context_from_item(
    item: Option<&Value>,
    section: ConfigSection,
    label: &str,
    identity_field: &str,
    rest: &[String],
) -> ItemContext {
    let item_name = item
        .and_then(|item| item.get(identity_field))
        .and_then(Value::as_str)
        .map(short_identity);
    let item_uuid = item
        .and_then(|item| item.get("uuid"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let details = item
        .map(|item| item_details(section, item))
        .unwrap_or_default();
    ItemContext {
        section,
        item_kind: label.into(),
        item_name,
        item_uuid,
        field: field_label(rest),
        details,
        whole_item: rest.is_empty(),
    }
}

fn singleton_context(root: &str, rest: &[String]) -> ItemContext {
    let (section, item_kind) = match root {
        "mode" | "debug" | "listener" => (ConfigSection::Basic, "基础设置"),
        "default_route" => (ConfigSection::Route, "默认路由"),
        "audit" => (ConfigSection::Audit, "审计设置"),
        "firewall" => (ConfigSection::Network, "网络沙盒"),
        "sandbox" => (ConfigSection::Sandbox, "沙盒设置"),
        _ => (ConfigSection::Gateway, "配置"),
    };
    let mut field_tokens = vec![root.to_owned()];
    field_tokens.extend_from_slice(rest);
    ItemContext {
        section,
        item_kind: item_kind.into(),
        item_name: None,
        item_uuid: None,
        field: field_label(&field_tokens),
        details: Vec::new(),
        whole_item: false,
    }
}

fn item_details(section: ConfigSection, item: &Value) -> Vec<String> {
    let enabled =
        item.get("enabled")
            .and_then(Value::as_bool)
            .map(|enabled| if enabled { "启用" } else { "停用" });
    match section {
        ConfigSection::Proxy => vec![format!(
            "类型={}，地址={}，超时={} ms",
            item.get("type").and_then(Value::as_str).unwrap_or("未设置"),
            item.get("address")
                .and_then(Value::as_str)
                .unwrap_or("未设置"),
            item.get("timeout_ms").and_then(Value::as_u64).unwrap_or(0)
        )],
        ConfigSection::Credential => {
            let protocols = item
                .get("protocols")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let ssh_only = protocols.iter().any(|value| value.as_str() == Some("ssh"))
                && !protocols.iter().any(|value| value.as_str() == Some("http"));
            if ssh_only {
                vec![format!(
                    "SSH 凭证，账号={} 个，敏感值=已脱敏",
                    item.get("ssh_accounts")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .unwrap_or(0)
                )]
            } else {
                vec![format!(
                    "HTTP 认证={}，协议={}，敏感值={}",
                    item.get("http_scheme")
                        .and_then(Value::as_str)
                        .unwrap_or("未设置"),
                    string_array(item.get("protocols")),
                    if item.get("secret").is_some() || item.get("password").is_some() {
                        "已设置（脱敏）"
                    } else {
                        "未设置"
                    }
                )]
            }
        }
        ConfigSection::Audit => vec![format!(
            "协议={}，HTTP 内容转录={}，SSH 内容转录={}",
            string_array(item.get("protocols")),
            yes_no(
                item.get("capture_body")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            ),
            yes_no(
                item.get("ssh_transcript")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            )
        )],
        ConfigSection::Route => {
            let mut details = vec![format!(
                "{}，优先级={}，行为={}",
                enabled.unwrap_or("启用"),
                item.get("priority").and_then(Value::as_i64).unwrap_or(0),
                route_behavior_label(
                    item.get("deny").and_then(Value::as_bool).unwrap_or(false),
                    item.get("upstream").is_some_and(|value| !value.is_null())
                )
            )];
            let targets = item
                .get("endpoints")
                .and_then(Value::as_array)
                .map(|endpoints| {
                    endpoints
                        .iter()
                        .filter_map(|endpoint| {
                            let target = endpoint.get("target")?.as_str()?;
                            Some(match endpoint.get("port").and_then(Value::as_u64) {
                                Some(port) => format!("{target}（端口 {port}）"),
                                None => target.to_owned(),
                            })
                        })
                        .collect::<Vec<_>>()
                        .join("，")
                })
                .unwrap_or_else(|| "未设置".into());
            details.push(format!("目标={targets}"));
            let plugins = string_array(item.get("plugins"));
            if plugins != "未设置" {
                details.push(format!("插件={plugins}"));
            }
            details
        }
        ConfigSection::Environment => vec!["变量值=已脱敏".into()],
        ConfigSection::Certificate => vec![format!("状态={}", enabled.unwrap_or("启用"))],
        ConfigSection::Network => vec![format!(
            "{}，优先级={}，动作={}，目标={} 条",
            enabled.unwrap_or("启用"),
            item.get("priority").and_then(Value::as_i64).unwrap_or(0),
            allow_deny_label(item.get("action").and_then(Value::as_str) == Some("deny")),
            item.get("endpoints")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0)
        )],
        ConfigSection::SandboxProcess | ConfigSection::Files => vec![format!(
            "{}，优先级={}，动作={}",
            enabled.unwrap_or("启用"),
            item.get("priority").and_then(Value::as_i64).unwrap_or(0),
            allow_deny_label(item.get("action").and_then(Value::as_str) == Some("deny"))
        )],
        _ => Vec::new(),
    }
}

fn string_array(value: Option<&Value>) -> String {
    let values = value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("，")
        })
        .unwrap_or_default();
    if values.is_empty() {
        "未设置".into()
    } else {
        values
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "开启"
    } else {
        "关闭"
    }
}

fn field_label(tokens: &[String]) -> Option<String> {
    if tokens.is_empty() {
        return None;
    }
    let joined = tokens.join("/");
    let label = match joined.as_str() {
        "mode" => "运行模式",
        "debug" => "调试事件",
        "listener/socks_listen" => "SOCKS5 监听地址",
        "listener/pending_session_ttl_secs" => "待激活会话有效期",
        "enabled" => "启用状态",
        "priority" => "优先级",
        "endpoints" => "目标",
        "deny" => "拒绝动作",
        "rewrite_host" => "重写主机",
        "rewrite_port" => "重写端口",
        "upstream" => "代理",
        "plugins" => "插件绑定",
        "http_scheme" => "HTTP 认证方式",
        "secret/value" => "认证值",
        "username" => "用户名",
        "password/value" => "密码",
        "headers" => "Headers",
        "address" => "代理地址",
        "timeout_ms" => "超时",
        "value/value" => "变量值",
        "retention_days" | "audit/retention_days" => "审计保留天数",
        "connections" | "audit/connections" => "连接审计",
        "default/action" => "默认动作",
        "error_action" => "出错动作",
        "patterns" => "匹配模式",
        "operations" => "允许操作",
        other => {
            let label = match tokens.first().map(String::as_str) {
                Some("enabled") => "启用状态",
                Some("priority") => "优先级",
                Some("endpoints") => "目标",
                Some("plugins") => "插件绑定",
                Some("headers") => "Headers",
                Some("secret") => "认证值",
                Some("password") => "密码",
                Some("value") => "变量值",
                Some("patterns") => "匹配模式",
                Some("operations") => "允许操作",
                _ => return Some(other.replace('/', " / ")),
            };
            return Some(label.into());
        }
    };
    Some(label.into())
}

fn short_identity(value: &str) -> String {
    const LIMIT: usize = 64;
    if value.chars().count() <= LIMIT {
        value.to_owned()
    } else {
        format!("{}…", value.chars().take(LIMIT).collect::<String>())
    }
}

fn pointer_tokens(path: &str) -> Result<Vec<String>, String> {
    if !path.starts_with('/') {
        return Err(format!("JSON pointer must start with '/': {path}"));
    }
    path[1..]
        .split('/')
        .map(|token| {
            let mut output = String::new();
            let mut chars = token.chars();
            while let Some(character) = chars.next() {
                if character != '~' {
                    output.push(character);
                    continue;
                }
                match chars.next() {
                    Some('0') => output.push('~'),
                    Some('1') => output.push('/'),
                    _ => return Err(format!("invalid JSON pointer escape in '{path}'")),
                }
            }
            Ok(output)
        })
        .collect()
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn describes_add_modify_and_delete_with_tui_vocabulary() {
        let current = json!({
            "debug": false,
            "plugins": [{"uuid": "11111111-1111-4111-8111-111111111111", "id": "existing", "kind": "credential", "secret": {"value": "x"}}],
            "routes": [{"uuid": "22222222-2222-4222-8222-222222222222", "id": "old-route", "priority": 10}]
        });
        let added = describe_request(
            &current,
            &[json!({
                "op": "add",
                "path": "/plugins/-",
                "value": {"uuid": "33333333-3333-4333-8333-333333333333", "id": "devboard", "kind": "credential"}
            })],
        )
        .unwrap();
        assert_eq!(added.action, ConfigChangeAction::Add);
        assert_eq!(added.section.breadcrumb(), "网关 / 凭证");
        assert_eq!(
            added.item_uuid.as_deref(),
            Some("33333333-3333-4333-8333-333333333333")
        );
        assert_eq!(added.summary, "新增 网关 / 凭证「devboard」");

        let modified = describe_request(
            &current,
            &[json!({"op": "replace", "path": "/routes/0/priority", "value": 20})],
        )
        .unwrap();
        assert_eq!(modified.action, ConfigChangeAction::Modify);
        assert_eq!(modified.summary, "修改 网关 / 路由「old-route」：优先级");
        assert!(modified.details[0].contains("行为=直连"));

        let deleted =
            describe_request(&current, &[json!({"op": "remove", "path": "/plugins/0"})]).unwrap();
        assert_eq!(deleted.action, ConfigChangeAction::Delete);
        assert_eq!(deleted.summary, "删除 网关 / 凭证「existing」");
    }

    #[test]
    fn generated_ids_are_rfc4122_uuid_v4_values() {
        let first = new_uuid();
        let second = new_uuid();
        assert!(valid_uuid(&first));
        assert!(valid_uuid(&second));
        assert_ne!(first, second);
        assert_eq!(&first[14..15], "4");
        assert!(matches!(&first[19..20], "8" | "9" | "a" | "b"));
    }
}
