# HyperHub 当前架构

## 总览

```text
目标程序（Windows x64）
  │
  └─ embedded Gum Agent（运行时验证并释放）
       ├─ Frida Gum Interceptor
       ├─ Rust DNS / Winsock / Schannel Hook
       ├─ Fake-IP 与 socket 状态
       └─ SOCKS5 RFC 1929 会话握手
              │
              ▼
hyperhub serve 127.0.0.1:18444
       ├─ 会话认证与域名恢复
       ├─ 路由、重写、deny / passthrough
       ├─ HTTP(S) 终止与 Header 注入
       ├─ HTTP CONNECT / SOCKS5 上游
       └─ JSONL 审计
              │
              ▼
        目标服务或上游代理
```

仓库运行代码全部使用 Rust。Frida Gum 以经过校验的预编译静态库链接进 Agent，不需要 CMake、C/C++ 编译器、QBDI、GumJS 或 JavaScript。

## 启动与控制面

`hyperhub.exe` 同时提供管理命令和目标启动入口：

```powershell
hyperhub config
hyperhub start --debug
hyperhub status
hyperhub validate
hyperhub doctor --target app.exe
hyperhub run app.exe args...
```

申请 Session 时先走自动鉴权：Serve 从 Named Pipe 获取真实客户端 PID，沿父进程链查找并核验有效 Session 成员，命中后直接创建新的 pending Session。没有有效父 Session 时才返回 challenge，由 CLI 读取主密码并完成 HMAC-SHA256 证明。客户端自报的 PID 不参与自动授权判断。

唯一运行配置为 `~/.hyperhub/config.bin`。内存仍使用 TOML `Config` 模型，磁盘使用 Argon2id、HKDF-SHA256 和 XChaCha20-Poly1305 加密；TUI 直接编辑对象，外部 TOML/BIN 通过 `import`/`export` 命令导入或导出。

启动目标时：

1. CLI 先申请自动父进程鉴权；未命中时与 `serve` 进行一次性 challenge-response，主密码不经过 Named Pipe。
2. `serve` 返回 60 秒有效的 pending bootstrap。
3. CLI 校验内嵌 Agent 的长度、SHA-256、格式和架构，释放到当前用户私有的内容寻址运行时目录，并锁定副本防止写入或替换。
4. CLI 使用 `CREATE_SUSPENDED` 创建目标并将真实 PID 绑定为 Session 根进程。
5. 通过远程 `LoadLibraryW` 注入已验证的 Gum Agent，等待 Hook ready 后恢复主线程。
6. Agent 对 `CreateProcessA/W`、`CreateProcessInternalA/W` 和 `NtCreateUserProcess` 在每次注入前重新验证 Agent 完整性，并重复挂起、bootstrap、登记、注入和恢复流程，使普通 x64 后代共享 Session；缺少环境的原生创建路径通过可信父进程从控制面补取 bootstrap。MSYS/Cygwin 的 `fork`/`vfork` 导出 Hook 在调用前申请租约，内部 `CreateProcessW` 仅在当前线程租约、完整 `_CH_FORK` child-info 和完全相同命令行同时成立时透明放行。fork 返回后的子分支重新创建 Agent 状态和语义 Hook runtime、取得最新快照并提交 Hook manifest/策略版本证明；后续普通 exec/spawn 仍按标准流程接管。
7. Serve 独立监控根进程、已登记后代和 fork 候选；成员退出时只移除自身。fork 准备租约最长 300 秒且每 Session 最多 64 个，候选必须在 10 秒内证明。`enforce` 超时会终止候选，`observe` 会保留进程并记录未覆盖事件。Windows 控制管道按用户 SID 隔离；SOCKS 监听地址发生占用时自动选择同一回环地址的空闲端口并向 Agent 下发实际地址。最后一个成员退出且没有有效租约后才撤销 Session、Fake-IP、后代权限和活动连接；激活后的 Session 本身没有 TTL。

管理面不增加 TCP 端口，目标凭证和 CA 私钥不会发送给 Agent。`GetStatus` 通过同一控制端点返回当前 session 和活动连接快照，以 `session_id + pid + connection_id` 关联进程、原始目标、内层最终目标、原始客户端代理、route 和处理阶段；响应不包含会话 token 或凭证。`serve --output <file>` 可重定向控制台输出；同时指定 `--debug` 时，脱敏实时事件也写入该文件。审计存储由 HyperHub 托管：事件固定写入 `<config-root>/audit/date=YYYY-MM-DD/hyperhub.jsonl`，内容转录固定写入 `<config-root>/audit/transcripts/date=YYYY-MM-DD/<session-id>/...`；这种 Hive 风格日期分区可被 DuckDB、Spark 和日志采集器直接裁剪。每条事件使用带 `schema_version`、`run_id + sequence`、`category` 和公共查询维度的稳定信封，协议特有数据放在 `attributes`。显式 `--output` 路径不做日期展开。

### 审计事件契约

HyperHub 是本机代理而不是高吞吐日志平台，正常规模下一天一个文件能避免小时级小文件，同时仍可按 UTC 日期裁剪。JSONL 每行独立、追加写入；`run_id + sequence` 是一次 Serve 运行内的唯一采集键，服务重启后 `run_id` 改变、`sequence` 从 1 重新开始。

- 所有事件固定包含 `schema_version`、`timestamp_ms`、`run_id`、`sequence`、`category`、`event` 和对象类型为 JSON object 的 `attributes`。
- `session` 事件把 `session_id`、`process_pid`、`process_executable` 放在顶层。
- `connection` 事件额外固定提供 `connection_id`、目标地址、`protocol`、`rule_id`、`action`、`outcome`、`bytes_up/down` 和 `duration_ms`；暂时没有值时写 `null`，避免同类事件字段漂移。
- `system` 事件不伪造 session 或 connection 维度。协议、诊断和扩展字段进入 `attributes`；新增可选属性不要求提升 schema 版本，重命名或改变顶层字段语义必须提升版本。
- transcript 不进入事件 JSONL，只记录路径、方向、大小、SHA-256 和截断状态等元数据，避免聚合扫描读取大块正文。

## Gum Agent

Agent 是 Rust `cdylib`，静态链接 Frida Gum 17.17.0。当前拦截：

- `getaddrinfo`、`GetAddrInfoW`。
- `connect`、`WSAConnect`、`ConnectEx`。
- `send/recv`、`WSASend/WSARecv`。
- `ioctlsocket`、`closesocket`。
- Schannel 凭证和安全上下文入口。
- `CreateProcessA`、`CreateProcessW`。

Gum 补丁作用于进程，新线程不需要独立 VM。它不依赖目标语言、符号或动态/静态链接方式，只要目标最终经过上述 Windows ABI 即可覆盖。绕过 Winsock 的直接 syscall 或私有网络实现不在当前范围内。

IPv4、IPv6 与 loopback TCP 连接使用同一条 Hook 路径。Agent 不区分直达目标、本地 HTTP/SOCKS5 代理或其他协议，只保存原始目标并重定向到 `serve`；仅精确绕过 `serve` 自身入口并使用线程递归保护。使用 Fake-IP 的外部连接会保存域名，并在开始传输应用数据前完成一次 SOCKS5 会话握手。

## TLS 信任

`serve` 启动时在内存中生成根 CA，按域名动态签发叶子证书。Agent 从控制面取得公开根证书，并在目标主逻辑启动前安装两种进程内信任入口：

- Schannel 使用进程私有的“系统 ROOT + HyperHub ROOT”证书集合，严格校验证书链、有效期、服务端用途和 SAN/目标主机名。
- 文件型 TLS 客户端通过通用 `SSL_CERT_FILE` 读取“系统 ROOT + 目标原有 bundle + HyperHub ROOT”的临时 PEM bundle；`SSL_CERT_DIR` 指向当前 Agent 的私有目录。
- 不修改系统 Root Store，不绕过 pinning。

只有主动读取 `SSL_CERT_FILE` 的 Rustls/OpenSSL 等客户端能使用文件型覆盖；完全内置根集合或自定义证书验证器不做程序特异性适配。macOS SecTrust 尚未覆盖。

`received fatal alert: UnknownCA` 出现在服务端接受目标 TLS 的阶段时，表示目标 TLS 栈拒绝了 HyperHub 动态证书。上游真实证书校验失败会被单独标记为 `upstream TLS handshake failed`，避免混淆两个方向。

## 服务端

`serve` 当前合并本地控制面、SOCKS5 listener、会话注册表、策略、TLS MITM、上游连接器和审计写入器。连接处理顺序为：

1. 验证 RFC 1929 会话身份。
2. 从 Fake-IP 或 SOCKS5 地址恢复域名、IP 和端口。
3. 识别目标原始发送的 HTTP、HTTPS、SSH、Git、HTTP Proxy 或 SOCKS5 Proxy 流量。
4. 按 priority 和文件顺序匹配 route。
5. 执行 deny、passthrough、地址重写或标准上游代理；未显式指定 upstream 时按协议继承 `HTTPS_PROXY`、`HTTP_PROXY`、`ALL_PROXY`，并遵守 `NO_PROXY`。
6. 对支持的协议注入凭证并写入脱敏审计。

WebSocket Upgrade 的 audit profile 支持 `off`、`frames` 和 `messages`。`frames` 保存 TLS 解密后的原始帧；`messages` 在旁路解析中去除客户端 mask、重组分片、解析控制帧，并按握手结果解压 `permessage-deflate`，文本写入 JSONL，二进制写为 Base64。在线字节始终原样转发。每个 Upgrade 分配独立 stream ID，避免 HTTP/2 多路 Upgrade 覆盖同一连接的转录文件；转录遵守 `body_limit` 并记录 SHA-256、大小与截断状态。

上游优先级为“路由显式 upstream → 环境代理 → 同会话同目标已观察到的客户端代理 → 直接连接”。当目标的一部分连接先使用本地 HTTP/SOCKS5 代理、另一部分连接同一域名时，`serve` 会保持会话级代理亲和性；关联键包含 session、目标域名和端口，不依赖进程名或应用协议。环境代理支持 HTTP CONNECT、SOCKS5 和代理 URL Basic 凭证；连接目标本身就是环境代理端点时强制直连，避免代理递归。

HTTP 策略在连接阶段使用进程、域名、IP、端口和 URL 形式 target（`host/path`）选择目标、upstream 和协议处理器；普通域名仅精确匹配，`*.example.com` 匹配任意层级子域名但不匹配根域名。URL 形式 target 的路径前缀在 HTTP/1.1 或解密后的 HTTP/2 请求阶段按未解码的 `path_and_query` 逐请求匹配（`path == prefix || path.starts_with(prefix + "/")`），非 HTTP 协议退化为纯主机匹配。因此一个复用连接中的不同 URL 可以获得不同凭证或 deny 结果，query 仍只以脱敏形式进入审计。

HTTP/1.1 的 `101 Switching Protocols` 和 HTTP/2 Extended CONNECT 均由 `serve` 在握手审计后接管客户端与上游的数据流，并执行全双工转发。WebSocket 帧内容保持透明；启用转录时旁路记录帧或消息，隧道审计同时记录协议、双向字节数、耗时和关闭结果。

所有原始字节转发统一经过 `DuplexBridge`，由同一个 `ConnectionContext` 关联客户端流、上游流、会话、目标和审计。普通 TCP、未知协议、TLS 解密后的非 HTTP 流量以及 HTTP Upgrade 不再维护各自的复制循环。探测阶段读出的数据由 `PrefixedIo` 无损回放；未配置明确协议时，自定义非 HTTP ALPN 和标准端口上的未知明文会退回原始 TCP，避免端口推断强行进入 HTTP 处理器。

Hook 层不解析应用层协议，也不会包装每次 `send()`。

## 当前边界

- Agent 仅实现 Windows x64。
- 不支持 UDP、QUIC/HTTP3。
- 不支持直接 syscall 网络和 certificate pinning 绕过。
- 非阻塞 socket 当前在第一次 I/O 前同步完成 SOCKS5 握手，完整异步状态机仍需完善。
- SSH 终止和完整转录能力仍需继续验收。

## Linux ELF 后端

Linux 默认对动态、静态和 stripped ELF 使用 CLI 内置的 ptrace syscall supervisor，建立不依赖 Agent 注入的可靠性基线。动态 ELF 可通过 `--backend gum` 显式选择 Frida Core + Gum Interceptor 优化；静态 ELF 的标准 Gum 注入不受支持。后端选择发生在 Agent runtime 解析与 Frida Core 初始化之前，因此默认 ptrace 即使系统中没有 Agent `.so` 也能启动。ptrace 后端不加载目标 libc、不要求符号表，按 DNS、网络、descriptor、文件、映射和进程意图分派 syscall；当系统解析器不产生可观测 DNS 报文时，Serve 在 TLS SNI 或 HTTP Host 出现后精化路由。

TCP connect 在 syscall entry 改写为 HyperHub SOCKS listener，并在目标上下文中完成认证与 CONNECT。UDP DNS只观察不重定向；A/AAAA 响应恢复 IP→域名关联。file/process sandbox 在副作用前判定，deny 通过无副作用 syscall 和返回值替换实现。clone/fork/vfork/exec 后代由同一 supervisor 跟踪并登记真实 PID。

静态 TCP 最终仍进入同一个 Serve listener，因此服务端会再次执行 firewall、route、代理和审计决策。当前第一阶段只启用全量 `PTRACE_SYSCALL` 保底路径；seccomp、pidfd、eBPF 与更快的跨进程内存 API 必须等保底语义稳定后再作为可回退优化引入。
