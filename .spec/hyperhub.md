# HyperHub

## 目标

HyperHub 通过一个本地入口为 Windows x64、Linux x86_64 和 Linux aarch64 目标程序提供透明 TCP 代理、规则路由、凭证注入和审计。

## 组件

```text
hyperhub / hyperhub.exe
├─ hyperhub serve          # 控制面、SOCKS5 数据面、策略、MITM、审计
├─ hyperhub run target ... # 注册会话、验证并释放内嵌 Agent、挂起启动和注入
└─ embedded Gum Agent
   ├─ 出站域名/IP/端口 Firewall
   ├─ DNS 与 TCP 重定向
   ├─ SOCKS5 会话认证
   ├─ 子进程/文件沙盒
   └─ 平台信任适配
```

项目运行代码全部使用 Rust。Frida Gum 只作为预编译静态插桩库，不使用 GumJS 或 JavaScript。

配置 TUI 按产品能力域组织，而不是与 Agent 内置插件一一对应：

- **进程**：观测活跃注入进程，不再提供 Hook 范围规则。
- **网关**：概览及基础、代理、凭证、审计、路由和证书配置。
- **沙盒**：网络、文件和子进程规则及能力概览。
- **环境变量**：保持独立配置入口。

左侧树形导航始终展开，父项和子项均可选；Agent 内部保留 Firewall、ProcessSandbox、FileSandbox、NetworkRedirect、CaTrust 和 ChildProcess 六个内置回调插件。

## Hook 边界

Hook 层保持协议无关，只处理 DNS、TCP、socket 生命周期和 CA 信任。应用层协议识别、路由、凭证和审计全部位于 `serve`。

Agent 内的 Hook 扩展分为三个独立边界：

1. **Hook 层**（`windows_gum::gum`、`windows_gum::manager` 与 `windows_gum::adapters`）只负责 Gum 生命周期、发现原生符号、安装 replacement、保存 original 槽位，以及把 A/W、Winsock 扩展函数等 ABI 差异转换成语义 Context。
2. **回调插件层**（`hook_runtime`、`windows_gum::runtime` 与 `windows_gum::capabilities`）按语义 Hook 点维护冻结后的有序回调链。Gateway 聚合网络重定向和 CA 信任，Sandbox 聚合 Firewall，ChildProcess 保持独立 Lifecycle 能力。出站 Firewall、网络重定向、CA 信任和子进程接管作为内置插件注册；新增业务只需注册回调，不修改 Hook 安装器。回调同步执行，保留线程级重入旁路，并按 Hook 点或插件覆盖的 fail-open/fail-closed 策略隔离错误和 panic。Firewall 在网络重定向前按不可变快照检查原始域名、IP/CIDR 和端口；Agent 后台每秒向 `serve` 上报心跳并按配置版本原子替换快照，Hook 热路径仍只读取当前快照。域名规则用于经 DNS Fake-IP 建立的连接，IP/CIDR 规则用于直接 IP 连接。未启用、快照无效且没有可用默认规则时固定 pass，拒绝事件通过有界队列异步上报 `serve`。`status` 和配置 TUI 的“进程”分类只展示最近有心跳的已注入进程及其 Firewall 快照版本。
3. **serve 协议插件层**负责 SOCKS5、TLS、HTTP/SSH 等控制面和应用层协议。它通过现有 Agent C ABI 与 Agent 协作，不参与原生 Hook 安装，也不直接持有原生函数指针。

新增原生 API 时在对应 adapter 增加 replacement/original 绑定并由 HookManager 聚合；新增业务处理时在对应 Gateway、Sandbox 或 Lifecycle capability 注册语义回调。Agent 初始化完成后回调注册表冻结，热路径只读不可变数组。Capability 不持有 original 槽位，也不依赖父模块通配导入。

每条连接只在应用数据开始前发送一次标准 SOCKS5 CONNECT；后续 TCP 字节流保持不变。目标原本使用 HTTP Proxy 或 SOCKS5 Proxy 时，其原始代理握手作为应用数据交给 `serve` 识别。

HTTP route 使用 `endpoints` 绑定的域名、IP、CIDR 或 URL 形式目标（`host/path`）与可选端口匹配；upstream 和地址重写在连接阶段决定。URL 形式 target 的路径前缀在 HTTP/1.1 或解密后的 HTTP/2 请求阶段逐请求匹配原始 `path_and_query`；Header 凭证注入和 deny 在请求阶段执行。

全局命名正则库与进程筛选已移除。路由与网络规则都使用各自的 `endpoints` 绑定目标与可选端口，分别在网关侧与 Agent 侧匹配；文件规则使用可独立启停的路径正则 `patterns + operations`；子进程规则使用可独立启停的“可执行文件正则 + 命令行正则” `patterns`。旧字段在加载时明确报错，必须人工迁移。

HTTP/1.1 WebSocket Upgrade 与 HTTP/2 Extended CONNECT 在 URL 前缀匹配和凭证注入完成后转换为双向隧道。隧道不修改帧数据；审计可选择保存原始帧，或旁路解析 mask、分片和 `permessage-deflate` 后保存消息，并记录协议、字节数、耗时与完成状态。

TCP、TLS 非 HTTP 明文及 HTTP Upgrade 使用统一 `DuplexBridge` 关联客户端与上游。协议探测不得消费首包；未知协议和自定义非 HTTP ALPN 自动回退到原始字节透传，专用处理器只用于语义审计或凭证注入。

## 发布

Windows 和 Linux 发布包均只包含对应平台/架构的单个 CLI；Agent 在构建阶段内嵌，运行时只从经过长度、SHA-256、格式和架构验证的私有运行时副本加载。

```text
Windows: hyperhub.exe
Linux:   hyperhub
```

## 用户态 Sandbox 边界

Sandbox Agent capability 包含 network、process-sandbox 和 file-sandbox。子进程沙盒只控制已注入进程后续创建的子程序；文件沙盒在 ntdll 文件/Section 入口执行同步 pass/deny，并异步审计 deny。该边界不包含动态进程扫描、直接 syscall 防绕过、AppContainer 或内核 minifilter。

## Linux 平台边界

Linux Agent 使用官方 `frida-sys` Rust bindings 调用 Frida Core 完成挂起启动和注入，并由 `unix_gum/` 的 Frida Gum Interceptor 安装原生 Hook；Frida child gating 负责挂起 exec/spawn 后代并递归注入，子进程沙盒按可执行文件与命令行执行 pass/deny；纯 `fork()` 子进程仅继承当前 Agent 映像，后续再 `exec` 的覆盖不在首期保证内；启动器校验目标与 Agent 的 ELF64 架构及动态解释器，Serve 校验根进程路径和启动时间；Windows 继续使用 Frida Gum Interceptor。平台接口、Session、规则快照和语义回调与 Windows 共用，原生 ABI 适配位于 Unix adapter。静态 ELF、secure-exec、直接 syscall 和运行中进程 Attach 不作首期覆盖保证。
