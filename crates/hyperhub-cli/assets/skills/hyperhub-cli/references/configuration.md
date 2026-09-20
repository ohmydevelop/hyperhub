# HyperHub 配置数据参考

生成 JSON Patch 前必须先运行 `hyperhub show`。当前配置是对象索引、UUID、已有 ID 和默认值的唯一依据；本参考只补充空列表中看不到的对象结构。

## Patch 规则

- 顶层可修改路径：`/mode`、`/debug`、`/listener`、`/audit`、`/default_route`、`/environment`、`/upstreams`、`/plugins`、`/routes`、`/firewall`、`/sandbox/file`、`/sandbox/process`。
- 新增数组对象使用 `/-` 并省略 `uuid`，由 CLI 生成。
- 修改或删除数组对象前，用 `test` 绑定从 `show` 取得的 UUID，避免索引变化后操作错误对象：

  ```json
  [
    {"op":"test","path":"/routes/2/uuid","value":"现有 UUID"},
    {"op":"replace","path":"/routes/2/priority","value":400}
  ]
  ```

- 整体替换现有对象时必须保留原 `uuid`。不得复制其他对象的 UUID。
- 高 `priority` 规则优先；同优先级保持配置中的先后顺序。
- `target` 可使用精确域名、`*.example.com`、IP、CIDR；路由还支持 `https://host/path` 或 `http://host/path`。防火墙目标不能包含 URL 路径。
- 端口省略表示任意端口；端口必须为 `1..65535`。
- 引用的 upstream/plugin ID 必须已存在。按“先新增被引用对象，再新增路由”的顺序提交；同一路由不能为同一协议绑定多个同类凭证或审计插件。
- 提交后以 CLI 校验结果为准；不要添加 `show` 和本参考中都不存在的字段。

## Secret 数据

真实敏感值必须通过审批占位符输入：

```json
{"value":"${APPROVE:meaningful-name}"}
```

完整 SecretValue 形式为：

```json
[
  {"value":"${APPROVE:api-token}"},
  {"env":"TOKEN_ENV","prefix":""},
  {"file":"/secure/token-file","prefix":"Bearer "}
]
```

只有用户明确要求引用环境变量或权限受限文件时才使用 `env`/`file`；否则使用审批占位符。

## 环境变量

```json
{
  "op":"add",
  "path":"/environment/-",
  "value":{
    "name":"EXAMPLE_TOKEN",
    "value":{"value":"${APPROVE:example-token}"}
  }
}
```

变量名必须匹配常规环境变量标识符，且不能使用 `HYPERHUB_` 保留前缀。

## 上游代理

`type` 只能是 `socks5` 或 `http_connect`：

```json
{
  "op":"add",
  "path":"/upstreams/-",
  "value":{
    "id":"corp-proxy",
    "type":"http_connect",
    "address":"192.0.2.10:8080",
    "timeout_ms":10000,
    "username":{"value":"${APPROVE:proxy-username}"},
    "password":{"value":"${APPROVE:proxy-password}"},
    "headers":{}
  }
}
```

不需要认证时省略 `username`、`password` 和 `headers`。

## HTTP 凭证插件

### Bearer

```json
{
  "id":"example-bearer",
  "kind":"credential",
  "protocols":["http"],
  "http_scheme":"bearer",
  "secret":{"value":"${APPROVE:example-bearer-token}"}
}
```

### Basic

```json
{
  "id":"example-basic",
  "kind":"credential",
  "protocols":["http"],
  "http_scheme":"basic",
  "username":"api-user",
  "password":{"value":"${APPROVE:example-basic-password}"}
}
```

### X-API-Key

```json
{
  "id":"example-api-key",
  "kind":"credential",
  "protocols":["http"],
  "http_scheme":"x_api_key",
  "secret":{"value":"${APPROVE:example-api-key}"}
}
```

### 自定义请求头

```json
{
  "id":"example-headers",
  "kind":"credential",
  "protocols":["http"],
  "http_scheme":"custom_headers",
  "headers":{
    "Authorization":{"value":"${APPROVE:authorization-header}"},
    "X-Tenant":{"value":"${APPROVE:tenant-header}"}
  }
}
```

其他 HTTP 类型：

- `token`：需要 `username` 和 `secret`。
- `cookie`：需要 `http_name` 和 `secret`。
- `query_parameter`：需要 `http_name` 和 `secret`。
- 不得使用已移除的 `scoped_token`。

## SSH 凭证插件

每个账号至少包含一个密码或私钥：

```json
{
  "id":"example-ssh",
  "kind":"credential",
  "protocols":["ssh"],
  "ssh_accounts":[
    {
      "username":"deploy",
      "passwords":[{"value":"${APPROVE:ssh-password}"}],
      "private_keys":[]
    }
  ]
}
```

私钥形式：

```json
{
  "name":"default",
  "value":{"value":"${APPROVE:ssh-private-key}"}
}
```

## 审计插件

```json
{
  "id":"http-audit",
  "kind":"audit",
  "protocols":["http","ws"],
  "capture_body":false,
  "body_limit":1048576,
  "git_transcript":false,
  "ssh_transcript":false,
  "websocket_capture":"off",
  "transcript_client_upload":true,
  "transcript_server_response":true
}
```

`websocket_capture` 可为 `off`、`frames`、`messages`。只有用户明确要求内容转录时才开启正文、Git、SSH 或 WebSocket 捕获。

## 路由

```json
{
  "op":"add",
  "path":"/routes/-",
  "value":{
    "id":"example-api",
    "enabled":true,
    "priority":300,
    "endpoints":[
      {"target":"https://api.example.com/v1","port":443}
    ],
    "deny":false,
    "rewrite_host":null,
    "rewrite_port":null,
    "upstream":null,
    "plugins":["example-bearer"]
  }
}
```

- 拒绝路由使用 `deny:true`，且不能同时配置 upstream 或 plugins。
- `upstream` 是 `/upstreams` 中的 ID。
- `plugins` 是 `/plugins` 中的 ID 列表。
- 默认路由结构：

  ```json
  {"enabled":true,"deny":false,"plugins":[]}
  ```

## 网络防火墙

替换完整策略时使用：

```json
{
  "enabled":true,
  "default":{"action":"pass"},
  "error_action":"deny",
  "rules":[
    {
      "id":"deny-private-range",
      "enabled":true,
      "priority":300,
      "action":"deny",
      "endpoints":[{"target":"10.0.0.0/8"}]
    }
  ]
}
```

`action`、默认动作和错误动作只能是 `pass` 或 `deny`。启用后必须有明确默认动作。

## 文件沙盒

路径模式是正则表达式；操作可选 `read`、`write`、`create`、`delete`、`rename`：

```json
{
  "enabled":true,
  "default":{"action":"pass"},
  "error_action":"deny",
  "rules":[
    {
      "id":"deny-secrets-read",
      "enabled":true,
      "priority":300,
      "action":"deny",
      "patterns":[{"enabled":true,"pattern":"^/home/user/\\.secrets(?:/.*)?$"}],
      "operations":["read"]
    }
  ]
}
```

## 子进程沙盒

`executable` 和 `command_line` 都是正则；每个启用规则至少设置其中一个：

```json
{
  "enabled":true,
  "default":{"action":"pass"},
  "error_action":"deny",
  "rules":[
    {
      "id":"deny-shell",
      "enabled":true,
      "priority":300,
      "action":"deny",
      "patterns":[
        {"enabled":true,"executable":".*/(?:bash|sh)$","command_line":""}
      ]
    }
  ]
}
```

## 运行模式、监听与审计设置

```json
[
  {"op":"replace","path":"/mode","value":"enforce"},
  {"op":"replace","path":"/debug","value":false},
  {"op":"replace","path":"/listener/pending_session_ttl_secs","value":60},
  {"op":"replace","path":"/audit/retention_days","value":7}
]
```

- `mode` 只能是 `enforce` 或 `observe`。
- SOCKS 监听地址必须为本机回环地址和非零端口。
- 修改监听地址前提醒用户现有连接可能受影响。

## TLS 与 SSH 主机信任

不要凭空生成 `/root_certificates` 的证书指纹或 `/ssh_host_keys` 的主机公钥。需要导入证书、信任 TLS 主机或抓取 SSH 主机密钥时，让用户运行：

```sh
hyperhub config
```

由交互配置界面完成证书文件导入、`https://host[:port]` 或 `ssh://host[:port]` 信任操作。
