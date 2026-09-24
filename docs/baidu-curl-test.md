# 使用 curl 测试 https://baidu.com

本测试验证三件事：直接启动的 curl 不会进入 HyperHub；仅运行 `serve` 仍不会捕获；只有经 `hyperhub run curl ...` attach 的 curl 才会经过 SOCKS5、TLS MITM、HTTP 解密和 Header 注入。

`serve` 在内存中生成根 CA，Agent 从认证控制面取得公开根证书并注入 curl 的 Schannel 验证流程；测试不需要 `--cacert`，也不会修改系统证书库。

Gum Agent 支持 CFG/XFG x64 目标，可直接使用 Windows 系统 curl：

```powershell
$curl = 'C:\Windows\System32\curl.exe'
.\target\release\hyperhub.exe doctor --target $curl
```

本机也验证了 PortableGit curl 8.19.0 的异步 DNS 路径。

## 1. 构建

```powershell
cd E:\ct\hyperhub
.\scripts\build.ps1

Remove-Item .\audit\security-alerts.jsonl -Force -ErrorAction SilentlyContinue

.\target\release\hyperhub.exe import .\examples\hyperhub.toml
.\target\release\hyperhub.exe validate
& $curl -V

```

首次执行时输入并确认主密码；命令会校验示例 TOML并加密保存。后续可用 `hyperhub config` 在 TUI 中直接修改路由字段。

## 2. A 组：没有 serve、没有 attach

```powershell
& $curl --http1.1 -sS -o NUL `
  -w "A http=%{http_code} remote=%{remote_ip}\n" https://baidu.com/
```

预期 HTTP 状态为 `200` 或站点当前返回的 3xx，且不存在 HyperHub connect 审计。

## 3. 启动 serve

后台启动 Serve：

```powershell
cd E:\ct\hyperhub
.\target\release\hyperhub.exe start
```

## 4. C 组：有 serve、没有 attach

在原窗口直接运行：

```powershell
& $curl --http1.1 -sS -o NUL `
  -w "C http=%{http_code} remote=%{remote_ip}\n" https://baidu.com/

Get-Content .\audit\security-alerts.jsonl -ErrorAction SilentlyContinue |
  Select-String '"event":"connect"'
```

第二条命令不应输出内容。

## 5. B 组：attach curl

```powershell
.\target\release\hyperhub.exe run `
  $curl `
  --http1.1 `
  -sS -o NUL `
  -w "B http=%{http_code} remote=%{remote_ip}\n" `
  https://baidu.com/
```

attach 后 `remote_ip` 应显示 `198.18.0.0/15` 或 `fdfe:6879:7065:7268:7562::/96` 会话 Fake-IP；同时以 HyperHub 审计确认请求进入 `serve`。

## 6. 查看解密后的审计

```powershell
Get-Content .\audit\security-alerts.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Format-List event,hostname,destination_ip,destination_port,protocol,rule_id,outcome,detail
```

至少应出现：

- `event=connect`、`hostname=baidu.com`、`protocol=tls`、`rule_id=baidu-curl-https`；
- `event=http_request`，其中 `detail.method=GET`；
- 如果配置为该域名引用 HTTP credential，则 `detail.injected_headers` 只记录 Header 名称，不记录值。

Windows Agent 会将 curl 的 `getaddrinfo` 请求转换为由 `serve` 管理的会话级 Fake-IP；代理在规则匹配和 TLS 建连前恢复 `baidu.com`，因此测试不再需要 `--resolve`。
