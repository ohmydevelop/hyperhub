# HyperHub 配置数据参考（Schema v2）

生成 JSON Patch 前必须运行 `hyperhub show`。输出中的数组索引、UUID、ID 和当前默认值是生成 Patch 的唯一依据。配置根对象必须包含 `schema_version: 2`；旧的顶层 `plugins`、`routes`、`firewall` 等结构不受支持。

## 顶层结构

```json
{
  "schema_version": 2,
  "gateway": {
    "mode": "enforce",
    "debug": false,
    "listener": {"socks_address":"127.0.0.1:18444","pending_session_ttl_seconds":60},
    "protections": [],
    "proxies": [],
    "credentials": [],
    "audit": {"settings": {}, "profiles": []},
    "routing": {"default": {}, "routes": []},
    "trust": {"tls_certificates": [], "ssh_host_keys": []}
  },
  "sandbox": {"network": {}, "file": {}, "process": {}},
  "environment_variables": []
}
```

## Patch、UUID 与 Secret

- 只使用 RFC 6902 `add`、`replace`、`remove`、`test`。
- 新增集合对象使用 `/-` 并省略 `uuid`，由 CLI 生成。
- 修改或删除前先以 `show` 中的 UUID 绑定当前索引：

  ```json
  [
    {"op":"test","path":"/gateway/routing/routes/2/uuid","value":"现有 UUID"},
    {"op":"replace","path":"/gateway/routing/routes/2/priority","value":400}
  ]
  ```

- 整体替换现有对象时必须保留原 UUID；不得复制其他对象的 UUID。
- 真实敏感值只能使用审批占位符：`{"value":"${APPROVE:meaningful-name}"}`。
- `config patch` 不需要密码；它只提交禁止包含真实 Secret 的 Proposal。真实 Secret、Provider API Key 和私钥只能在人工 `approve` 时输入。
- 如果修改被规则引用的 ID（例如 `/gateway/protections/0/id`），必须在同一 Patch 中同步更新所有 `protection`/引用字段，并使用 UUID `test` 保护每个修改对象。CLI 会在拆分请求无法独立校验时自动合并为一个原子审批请求；`request_count: 1` 表示该原子请求，不要把它拆成多个 Patch。

## 环境变量

```json
{"op":"add","path":"/environment_variables/-","value":{"name":"EXAMPLE_TOKEN","value":{"value":"${APPROVE:example-token}"}}}
```

变量名不能使用 `HYPERHUB_` 保留前缀。

## 代理

```json
{
  "op":"add",
  "path":"/gateway/proxies/-",
  "value":{
    "id":"corp-proxy",
    "type":"http_connect",
    "address":"192.0.2.10:8080",
    "timeout_milliseconds":10000,
    "authentication":{
      "username":{"value":"${APPROVE:proxy-username}"},
      "password":{"value":"${APPROVE:proxy-password}"}
    }
  }
}
```

`type` 只能是 `socks5` 或 `http_connect`。无认证时省略 `authentication`。

## 凭证

凭证位于 `/gateway/credentials`，每种类型只包含自身需要的字段。

```json
{"id":"example-bearer","type":"http_bearer","secret":{"value":"${APPROVE:example-bearer-token}"}}
```

其他 HTTP 类型：

```json
{"id":"basic","type":"http_basic","username":"api-user","password":{"value":"${APPROVE:password}"}}
{"id":"token","type":"http_token","username":"api-user","secret":{"value":"${APPROVE:token}"}}
{"id":"api-key","type":"http_x_api_key","secret":{"value":"${APPROVE:api-key}"}}
{"id":"cookie","type":"http_cookie","name":"session","secret":{"value":"${APPROVE:cookie}"}}
{"id":"query","type":"http_query_parameter","name":"token","secret":{"value":"${APPROVE:query-token}"}}
{"id":"headers","type":"http_custom_headers","headers":{"Authorization":{"value":"${APPROVE:authorization-header}"}}}
```

SSH 凭证：

```json
{
  "id":"example-ssh",
  "type":"ssh",
  "accounts":[{"username":"deploy","passwords":[{"value":"${APPROVE:ssh-password}"}],"private_keys":[]}]
}
```

## 智能防护 Profile

Profile 位于 `/gateway/protections`。建议先创建 `observe` Profile，确认审计结果后再切换到 `enforce`。新增 Profile 省略 `uuid`：

```json
{
  "op":"add",
  "path":"/gateway/protections/-",
  "value":{
    "id":"agent-egress",
    "enabled":true,
    "mode":"observe",
    "data":{
      "enabled":true,
      "max_scan_bytes":1048576,
      "detect_managed_secrets":true,
      "detect_known_tokens":true,
      "detect_private_keys":true,
      "detect_prompt_injection":true,
      "provenance_window_bytes":64,
      "provenance_min_matches":3
    },
    "intelligence":{
      "enabled":true,
      "timeout_ms":2000,
      "min_confidence":0.6,
      "error_action":"pass",
      "low_confidence_action":"pass",
      "cache_ttl_ms":30000,
      "provider":{
        "id":"jev-primary",
        "protocol":"system_one",
        "endpoint":"https://guard.example.test/system-one",
        "model":"jev-latest",
        "api_key":{"value":"${APPROVE:jev-api-key}"}
      }
    }
  }
}
```

约束：

- `mode` 只能是 `observe` 或 `enforce`；`enabled` 必须为 `true` 才会生效。
- `intelligence.enabled=true` 时必须提供完整 Provider；远程 Endpoint 使用 HTTPS，只有回环地址可以使用 HTTP。
- `error_action` 和 `low_confidence_action` 为 `pass` 或 `deny`，默认建议 `pass`。
- Provider API Key 是敏感值，只能使用 `${APPROVE:name}`，不能写真实值。
- 远程 Provider 只接收脱敏动作和检测结果摘要，不发送真实凭证、Header、Query、私钥或原始正文。

## 路由与智能防护绑定

普通路由：

```json
{
  "op":"add",
  "path":"/gateway/routing/routes/-",
  "value":{
    "id":"example-api",
    "enabled":true,
    "priority":300,
    "endpoints":[{"target":"https://api.example.com/v1","port":443}],
    "decision":{"action":"allow","credentials":["example-bearer"]}
  }
}
```

智能防护路由必须同时设置 `action: "smart"` 和 `protection`：

```json
{
  "op":"add",
  "path":"/gateway/routing/routes/-",
  "value":{
    "id":"protected-api",
    "enabled":true,
    "priority":300,
    "endpoints":[{"target":"https://api.example.com/v1","port":443}],
    "decision":{"action":"smart","protection":"agent-egress"}
  }
}
```

- 路由动作只能是 `allow`、`deny` 或 `smart`。
- `smart` 必须引用已存在的 `/gateway/protections` ID；`allow`/`deny` 不应设置 `protection`。
- `deny` 不能同时配置 `proxy`、`rewrite`、`credentials` 或 `audit_profiles`。
- `proxy` 引用 `/gateway/proxies` 中的 ID；`credentials` 与 `audit_profiles` 分别引用对应集合的 ID。
- 默认路由 `/gateway/routing/default` 使用相同的 `action`、`protection`、`credentials` 和 `audit_profiles` 语义。
- `allow_sensitive_upload` 只有用户明确要求时才设置为 `true`。
- 高 `priority` 优先；同优先级保持配置顺序。

## 审计

审计配置分为全局设置 `/gateway/audit/settings` 和可绑定路由的 Profiles `/gateway/audit/profiles`：

```json
{
  "id":"ssh-audit",
  "protocols":["ssh"],
  "capture":{
    "http_body":false,
    "body_limit_bytes":1048576,
    "git_transcript":false,
    "ssh_transcript":true,
    "websocket":"off",
    "directions":{"client_upload":true,"server_response":true}
  }
}
```

`websocket` 可为 `off`、`frames`、`messages`。只有用户明确要求时才开启内容转录。

## 沙盒与智能防护

三个策略统一使用 `enabled`、`default_action`、`error_action` 和 `rules`：

- 网络：`/sandbox/network`
- 文件：`/sandbox/file`
- 子进程：`/sandbox/process`

规则动作支持 `allow`、`deny`、`smart`。使用 `smart` 时必须在规则上设置 `protection`，并引用已存在的 Profile；`allow`/`deny` 规则不要设置 `protection`。默认动作和错误动作不要使用 `smart`。

网络规则示例：

```json
{
  "op":"add",
  "path":"/sandbox/network/rules/-",
  "value":{
    "id":"protected-egress",
    "enabled":true,
    "priority":300,
    "action":"smart",
    "protection":"agent-egress",
    "endpoints":[{"target":"api.example.com","port":443}]
  }
}
```

文件规则使用正则 `patterns` 和 `operations`：

```json
{
  "op":"add",
  "path":"/sandbox/file/rules/-",
  "value":{
    "id":"protected-secret-read",
    "enabled":true,
    "priority":300,
    "action":"smart",
    "protection":"agent-egress",
    "patterns":[{"enabled":true,"pattern":"^/home/user/\\.ssh/.*$"}],
    "operations":["read"]
  }
}
```

进程规则使用包含 `executable`、`command_line` 的正则 `patterns`：

```json
{
  "op":"add",
  "path":"/sandbox/process/rules/-",
  "value":{
    "id":"protected-upload-command",
    "enabled":true,
    "priority":300,
    "action":"smart",
    "protection":"agent-egress",
    "patterns":[{"enabled":true,"executable":"^curl$","command_line":".*"}]
  }
}
```

## TLS 与 SSH 主机信任

信任项位于：

- `/gateway/trust/tls_certificates`
- `/gateway/trust/ssh_host_keys`

TLS `scope` 为 `{"type":"global"}` 或 `{"type":"host","authority":"host:port"}`。不要凭空生成证书指纹或 SSH 公钥；需要采集或导入时让用户运行 `hyperhub config`。首次信任和后续证书/主机密钥变化会由 HyperHub 管理并审计。

## 变更后的验证

用户完成 `approve` 后再执行：

```sh
hyperhub validate --password-file /path/to/password
hyperhub show
hyperhub status --json
hyperhub logs --lines 100
```

智能防护重点确认 Profile、规则引用、`observe/enforce` 模式、Provider 状态和审计事件；发现校验失败或 Provider 异常时，不要重复提交相同 Patch。
