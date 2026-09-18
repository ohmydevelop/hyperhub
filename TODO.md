# 路线图

## 网关能力

- [ ] **数据网关**：支持 HTTP/HTTPS、SSH 审计；注入授权、审计流量并记录流量。
- [ ] **模型网关**：将 ChatGPT、Claude、Grok、Cursor、Kimi 订阅转换为 API 网关。

## 先导功能

- [ ] **凭证网关**：托管 SSH、Git 等凭证，运行时自动注入，避免通过环境变量和默认文件泄露。
- [ ] **数据审计**：审计 SSH、HTTP、WebSocket 流量。

# 网关设计

## 目标架构

- 支持递归解析，最多递归 2 层。
- `TCP -> Hub SOCKS5 -> TLS / SOCKS5 / HTTP / SSH`
- 接收下游数据后逐层探测，直到确定协议类型或达到深度限制；发送到上游时逐层还原。

## 目标场景

- `HTTP / WebSocket`
- `HTTP / Git`
- `SSH / Git`
- `TCP / TLS / HTTP / WebSocket`
- `TCP / TLS / HTTP / Git`
- `TCP / TLS`
- `TCP / SOCKS5`
- `Git over HTTP`
- `Git over SSH`
- `WebSocket over HTTP`
- `WebSocket over TLS`

## 运行时沙盒

目标：使用 DBI 实现运行时指令沙盒，监控应用（包括 Agent）的一举一动。

1. **第一原理**：任何应用（Agent）要操作系统资源，必须通过 syscall。
2. **木桶效应**：Agent 受大模型吞吐瓶颈影响，对性能要求不敏感。

## 无感接入要求

- [ ] 不需要安装 Root 证书。
- [ ] 不需要安装内核模块。
- [ ] 不需要配置代理。
- [ ] 不需要配置 TUN 网卡。
- [ ] 不需要修改任何配置，出现问题时可直接停用。
- [ ] 无额外环境依赖。
- [ ] 支持 Windows、Linux、macOS。
- [ ] 支持 x64、ARM64。
- [ ] 支持任意应用，与 Agent 架构无关。

# 协议状态机

## 待完成

- [ ] 为每个协议模块提供统一的审计 / 流量记录接口。`HandlerContext` 已注入 `AuditWriter`，协议特有记录（WebSocket 帧、SSH transcript 等）待扩展。

# 配置管理

- [ ] 提供 TUI 配置入口：`hyperhub config`。
- [ ] 配置文件使用 TOML 格式，加密存储于 `~/.hyperhub/config.bin`。
- [ ] 支持导入、导出加密或未加密的 bin 文件。
- [ ] 首次运行时提示用户设置并确认密码。

## Serve 鉴权

- [x] **自动鉴权**：serve 收到 pipe 后，向上查看父进程是否有有效 session；有则允许创建 session，否则进入密码鉴权。
- [x] **密码鉴权**：输入密码申请 session。
- [ ] **进程自动授权**：在进程列表下新增自动授权功能。
  - [ ] 列出当前所有非系统进程，并按启动时间排序。
  - [ ] 使用 `Space` 勾选进程后，将该进程及其子进程视为已授权。
  - [ ] 自动授权效果与密码鉴权后的 session 一致；区别在于前者通过进程授权，后者通过密码 session。

# 凭证配置

## SSH 凭证编辑

- [ ] 支持私钥点击打开，并支持添加多个私钥。
- [ ] 支持通过私钥路径导入或自动生成私钥。
- [ ] 选中私钥后按回车预览，预览界面支持复制。
- [ ] 私钥支持命名；默认使用公钥简短信息作为名称。
- [ ] 弹出公钥时，用户可以使用鼠标正常复制，且不会选中 TUI 边框。
- [ ] 支持配置多个用户名及对应密码。

# TUI 与交互

## 布局

- **网关**：基础、代理、凭证、审计、路由、证书。
- **沙盒**：网络、文件；用于审计行为。
- **进程**：规则。
- **环境变量**。

## 交互规则

- 使用 Space 代替 Enter 进行选项切换。
- 路由首页也使用 Space 实现启用 / 禁用。
- 支持空格直接切换开关，不必进入详情页后再切换启用状态。
- 基础列表字段顺序：ID、优先级、进程正则、启用、目标、端口、代理、凭证、审计。
- 进程正则放在优先级后面，优先保证文字长度和排版。

示例：

```text
│  基础              ││> [x] https://git.example.com  priority=0  Http/Proxy  │
│  监听              ││  [x] deepseek                    priority=0  Http/Proxy  │
```

## 文件沙盒

- [ ] 支持文件正则匹配，以及阻断、告警、放行动作。

# 环境变量

- 添加默认环境变量；不要全部隐藏，使用 mask 掩码隐藏中间部分；为空时显示为空。
- `GITLAB_HOST`：空
- `GITLAB_TOKEN`：空
- `GH_TOKEN`：空

# 审计

- [ ] 重新设计审计模块字段。

# Hook

- [ ] 设计快速扩展机制：新增 Hook 模块并注册回调函数即可扩展功能。
- [ ] 支持监听所有文件创建和打开操作，并通过规则引擎检测。

# Bug

- [ ] 所有输入框无法移动光标修改中间文字。
- [ ] 进程规则无法按 Enter 进入编辑界面。
- [ ] 网络沙盒中的“未配置（pass）”默认动作是否可以移除，统一将初始配置设为 `pass`？

# 测试

## 稳定性

- [ ] 大量 fuzz 测试。
- [ ] 并发、多线程测试。

## 对抗测试

- [ ] 针对文件、网络、进程和权限边界设计对抗测试，验证阻断策略是否可绕过。

## 兼容性

- [ ] 二进制程序：支持但不限于以下形式。
  - Go：静态编译、动态编译、有符号、无符号。
  - Rust：静态编译、动态编译、有符号、无符号。
  - C：静态编译、动态编译、有符号、无符号。
  - Python、Node.js、C#、Java。
- [ ] 多系统：Windows、Linux、macOS。
- [ ] 多架构：x64、ARM64。
- [ ] 多软件：对某些常用软件进行测测试

# TODO

## LLM Native

- [ ] 通过意图进行规则配置以及事件分析。
- [x] LLM 通过 CLI 读取脱敏配置，并使用绑定当前状态的 approval token 进行人工确认后修改。

## 模块化重构

- 重构项目结构，使其更加模块化、可扩展。
- Serve 协议模块化：
  - `protocols/https.rs`
  - `protocols/http.rs`
- Hook 模块化：新增 Hook 时按模板创建文件并注册 Hook，包括 Hook 点、回调函数等。

## 协议状态机

- 首层状态机已落地：`protocol::classify_ingress` 按首包分类（Raw、PlainHttp、HttpConnect、Socks5、Tls），`plan_for` 分派表路由到各协议 handler 模块（https、http、http_proxy、bridge）；新增协议时添加 detector、handler 并注册到 `builtin_detectors` / `builtin_handlers`。
- 外层代理协议端到端保留：HTTP CONNECT 原样转发、响应原样中继、2xx 后进行 TLS MITM；SOCKS5 greeting 在 `handle_authenticated` 内预处理；absolute-form 维持 origin-form + Host 转发；`connect_for` 如实记录 `UpstreamTransport`（Direct / Tunneled）。
- 递归多层探测与深度限制：`protocol::stack::run_stack` 逐层探测入栈（SSH → HTTP proxy CONNECT → HTTP → TLS → Git → Raw），`MAX_PROTOCOL_DEPTH = 8` 超限即出栈透传；TLS MITM 解密后与 CONNECT 隧道 2xx 后均下钻 `run_stack`；新增协议时添加 `ProtocolHandler` 模块并注册到 `builtin_protocols()`。

## 凭证配置

- 支持 HTTP Basic。
- 支持 HTTP Authorization: Bearer。
- 支持 HTTP X-API-Key。
- 支持 SSH。

## Serve 鉴权

- 已支持自动鉴权：Serve 沿父进程链查找有效 Session，命中后允许创建新的 Session。
- 已支持密码鉴权：无有效父 Session 时，通过密码 challenge-response 申请 Session。
