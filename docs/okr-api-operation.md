# OKR API 凭证注入操作手册

目标接口：`http://api.example.com/okr/api/permission/query`。该接口仅限受限网络；外部网络先连接 VPN。

## 1. 配置令牌

运行 `hyperhub config`，在“凭证”中新建 HTTP 凭证，鉴权方式选择 `Bearer`，鉴权值只输入原始 `pt_...` 令牌，不要输入 `Bearer ` 前缀。令牌直接写入加密的 `~/.hyperhub/config.bin`，TUI 和审计日志均不显示 Header 值。

对应 route 可以只授权该接口，而不是授权整个域名：

```toml
[[credentials]]
id = "okr-token"
type = "http"
http_scheme = "bearer"
secret = { value = "pt_替换为真实令牌" }

[[routes]]
id = "okr-permission-query"
priority = 300
protocol = "http"
action = "proxy"
credential = "okr-token"
[[routes.endpoints]]
target = "api.example.com/okr/api/permission/query"
port = 80
```

URL 形式 `endpoints` 目标（`host/path`）的路径前缀在 HTTP 请求阶段匹配原始 path（不含 query），同时匹配绑定端口；只有命中该目标的请求才会注入凭证。

## 2. 构建与校验

```powershell
cd E:\ct\hyperhub
.\scripts\build.ps1
.\target\release\hyperhub.exe import .\examples\hyperhub.toml
.\target\release\hyperhub.exe validate
```

该命令校验 TOML，并使用主密码加密保存为当前运行配置。需要调整 OKR route 时，运行 `hyperhub config`，选择“路由”后按 `Enter/e` 打开完整表单并保存。

## 3. 启动服务

在第一个 PowerShell 窗口运行：

```powershell
cd E:\ct\hyperhub
.\target\release\hyperhub.exe start
```

## 4. 运行无感授权请求

在第二个 PowerShell 窗口运行。curl 命令中不要提供 `Authorization`：

```powershell
.\target\release\hyperhub.exe run curl.exe `
  'http://api.example.com/okr/api/permission/query' `
  -H 'Content-Type: application/json'
```

Gum Agent 支持 Windows CFG/XFG x64 目标，可直接使用系统 curl 或 PortableGit curl。

HyperHub attach curl 后从已解密到内存的配置注入 `Authorization: Bearer pt_...`。直接运行同一个 curl 命令不会注入凭证，也不会产生 HyperHub 连接审计。

## 5. 验证审计

B 组必须成功，并且 `audit/date=YYYY-MM-DD/hyperhub.jsonl` 只记录注入的 Header 名称 `authorization`，不能包含真实 token。

如果 curl 已配置本地 HTTP 代理，其 loopback 或非 loopback 代理端点都会由 HyperHub 接管。`serve` 从 absolute-form/CONNECT 首包恢复真实目标、重新执行域名规则；没有显式配置其他 upstream 时，审计和凭证注入完成后仍通过 curl 原来选择的 HTTP 代理发送。

同一原则也适用于目标程序配置的 SOCKS5 代理：Hook 只接管到代理端点的 TCP；`serve` 转发并解析目标程序的 SOCKS5 CONNECT（无认证或 RFC 1929），按内层最终目标重新执行规则，然后继续通过原 SOCKS5 代理连接。

Windows Agent 会 Hook `getaddrinfo/GetAddrInfoW`，通过控制面向 `serve` 请求会话级 Fake-IP。SOCKS5 到达服务端后，Fake-IP 会在规则匹配前恢复为 `api.example.com`，因此 `targets` 可以安全使用精确域名，用户不再需要 `--resolve`。
