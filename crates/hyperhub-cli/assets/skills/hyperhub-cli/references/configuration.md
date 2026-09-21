# HyperHub 配置数据参考（Schema v2）

生成 JSON Patch 前必须运行 `hyperhub show`。输出中的数组索引、UUID、ID 和当前默认值是生成 Patch 的唯一依据。配置根对象必须包含 `schema_version: 2`；旧的顶层 `plugins`、`routes`、`firewall` 等结构不受支持。

## 顶层结构

```json
{
  "schema_version": 2,
  "gateway": {
    "mode": "enforce",
    "debug": false,
    "listener": {},
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

## Patch 与 UUID

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

### HTTP Bearer

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

### SSH

```json
{
  "id":"example-ssh",
  "type":"ssh",
  "accounts":[{
    "username":"deploy",
    "passwords":[{"value":"${APPROVE:ssh-password}"}],
    "private_keys":[]
  }]
}
```

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

## 路由

```json
{
  "op":"add",
  "path":"/gateway/routing/routes/-",
  "value":{
    "id":"example-api",
    "enabled":true,
    "priority":300,
    "endpoints":[{"target":"https://api.example.com/v1","port":443}],
    "decision":{
      "action":"allow",
      "credentials":["example-bearer"]
    }
  }
}
```

- `action` 只能是 `allow` 或 `deny`。
- `deny` 不能同时配置 `proxy`、`rewrite`、`credentials` 或 `audit_profiles`。
- `proxy` 引用 `/gateway/proxies` 中的 ID。
- `credentials` 与 `audit_profiles` 分别引用对应集合的 ID。
- 默认路由位于 `/gateway/routing/default`，使用相同的 `action`、`credentials` 和 `audit_profiles` 语义。
- 高 `priority` 优先；同优先级保持配置顺序。

## 沙盒

三个策略统一使用 `enabled`、`default_action`、`error_action` 和 `rules`；动作只能是 `allow` 或 `deny`。

- 网络：`/sandbox/network`
- 文件：`/sandbox/file`
- 子进程：`/sandbox/process`

网络规则使用 `endpoints`；文件规则使用正则 `patterns` 和 `operations`；进程规则使用包含 `executable`、`command_line` 的正则 `patterns`。

## TLS 与 SSH 主机信任

信任项位于：

- `/gateway/trust/tls_certificates`
- `/gateway/trust/ssh_host_keys`

TLS `scope` 为 `{"type":"global"}` 或 `{"type":"host","authority":"host:port"}`。不要凭空生成证书指纹或 SSH 公钥；需要采集或导入时让用户运行 `hyperhub config`。
