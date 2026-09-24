# HyperHub

[![CI](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml/badge.svg)](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ohmydevelop/hyperhub?include_prereleases)](https://github.com/ohmydevelop/hyperhub/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**面向 AI Agent、自动化工具和开发工作流的进程级网络安全网关。**

HyperHub 让 Agent 在执行联网任务时拥有清晰、可控、可审计的网络边界：无需修改目标程序，即可统一管理代理、访问策略、凭证和审计记录，让每一次联网动作都可控、可解释、可追溯。

## 本地优先

HyperHub 采用 **local-first** 设计：网关、策略、凭证和审计记录默认在本机管理和保存，不依赖云端控制台。所有受控访问由本地策略统一决定并按配置执行，适合对隐私、凭证和执行边界有要求的 AI Agent 与自动化任务。

## 核心能力

- **进程级网络控制**：按程序、目标、端口和协议管理出站访问
- **统一代理与凭证**：集中配置上游代理和访问凭证，避免敏感信息散落在脚本中
- **策略化执行**：支持放行、拒绝、观察等执行模式
- **全链路审计**：记录连接、协议、访问目标和会话活动
- **Agent 友好**：适合 AI Agent、CLI 工具、构建任务和自动化脚本
- **跨平台运行**：支持 Windows 和 Linux

## 获取最新版

Linux 可直接使用安装脚本：

```bash
curl -fsSL https://github.com/ohmydevelop/hyperhub/releases/latest/download/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://github.com/ohmydevelop/hyperhub/releases/latest/download/install.ps1 | iex
```

也可以从 [GitHub Releases](https://github.com/ohmydevelop/hyperhub/releases) 下载对应平台的单文件 CLI：

- Windows x64：`hyperhub.exe`
- Linux x86_64：`hyperhub`
- Linux aarch64：`hyperhub`

下载后直接运行 `hyperhub --help`（Windows 使用 `hyperhub.exe --help`）即可查看帮助。

## 快捷命令

安装完成后会同时生成 `hsh` 快捷命令，用于直接进入受 HyperHub 管理的 Shell：

```bash
hsh                 # Linux：默认进入当前用户 Shell，通常为 bash
HYPERHUB_SHELL=sh hsh
```

Windows 会生成 `hsh.cmd`，在 PowerShell 或 CMD 中直接运行即可进入受控 `cmd.exe`：

```powershell
hsh
hsh /c whoami
```

`hsh` 只是 `hyperhub run bash/sh/cmd` 的便捷入口，不会改变目标 Shell 自身的参数语义。

## 基础使用

```bash
# 首次使用：创建本地配置
hyperhub config

# 启动本地网关
hyperhub start

# 检查并安装最新版 CLI；运行中会先优雅停止 Serve，升级后尝试恢复启动
hyperhub upgrade

# 在受控边界内启动命令行会话
hyperhub run bash       # Linux
hyperhub.exe run cmd    # Windows
```

### 隔离运行实例

像 `CODEX_HOME` 一样，设置 `HYPERHUB_HOME`（推荐绝对路径） 即可选择独立实例，无需修改系统 `HOME`：

```bash
sandbox=$(mktemp -d)
export HYPERHUB_HOME="$sandbox/hyperhub"
printf '%s\n' 'local-test-password' > "$sandbox/password"
chmod 600 "$sandbox/password"

./target/release/hyperhub start --password-file "$sandbox/password"
./target/release/hyperhub status --json
./target/release/hyperhub show
```

PowerShell：

```powershell
$sandbox = Join-Path $env:TEMP "hyperhub-$([guid]::NewGuid())"
$env:HYPERHUB_HOME = Join-Path $sandbox 'hyperhub'
New-Item -ItemType Directory -Force $sandbox | Out-Null
Set-Content -NoNewline (Join-Path $sandbox 'password') 'local-test-password'

.\target\release\hyperhub.exe start --password-file (Join-Path $sandbox 'password')
.\target\release\hyperhub.exe status --json
```

每个 `HYPERHUB_HOME` 独立保存配置、审批队列、脱敏视图、日志、审计数据、证书、Chat 运行资产和控制端点。`status --json` 会显示实例的 `hyperhub_home`、`control_endpoint` 和实际 `socks_address`。

SOCKS5 默认从配置端口 `18444` 开始监听；端口被占用时依次尝试 `18445`、`18446`，直到找到可用端口。`hyperhub run` 通过该实例的本地控制端点建立 Session 并取得实际端口，因此不依赖固定端口。

结束时保持同一个 `HYPERHUB_HOME`：

```bash
./target/release/hyperhub stop
unset HYPERHUB_HOME
```

控制端点不提供人工配置入口：Unix 自动使用 `$HYPERHUB_HOME/runtime/control.sock`，Windows 自动根据当前用户与 `HYPERHUB_HOME` 派生 named pipe。Agent Skill 仍安装在 Agent 通用 Skill 目录，因为它是无敏感信息的共享 CLI 操作说明，不属于某个运行实例。

正式支持的运行时环境变量只有 3 个：

- `HYPERHUB_HOME`：选择配置与 Serve 实例；
- `HYPERHUB_CONFIG_PASSWORD`：非交互提供配置密码；
- `HYPERHUB_SHELL`：仅供 `hsh` 快捷命令选择目标 Shell。

`HYPERHUB_CONTROL_ENDPOINT`、Session token、SOCKS 地址等变量由 HyperHub 向受管进程自动注入，属于内部协议，用户不应设置。

安装脚本另支持 3 个一次性变量：`HYPERHUB_REPO`、`HYPERHUB_VERSION`、`HYPERHUB_INSTALL_DIR`。源码构建另支持 5 个开发变量：`HYPERHUB_FRIDA_GUM_ROOT`、`HYPERHUB_FRIDA_CORE_ROOT`、`HYPERHUB_EMBEDDED_AGENT_PATH`、`HYPERHUB_NEEDLE3_MODEL`、`HYPERHUB_NEEDLE3_RUNNER`。因此普通运行只需考虑 3 个变量；连同安装和源码构建入口，正式支持人工设置的变量共 11 个。

### Agent Skill 自动安装

HyperHub CLI 内嵌用于 Agent 操作配置的 `hyperhub-cli` Skill。每次执行 `hyperhub start`（包括 `restart`）时都会检查用户级通用目录：

```text
~/.agents/skills/hyperhub-cli
```

首次运行会完整安装；CLI 版本或 Skill 内容摘要变化时会原子替换升级；版本一致则跳过。安装失败会阻止 `start`，避免 Serve 已运行但 Agent 仍使用缺失或过期的操作说明。Skill 仅通过已安装 CLI 工作，不依赖 HyperHub 源码或当前目录。

如果 Agent 不支持发现 `agents/skills` 目录，可直接读取 CLI 内嵌的完整操作说明：

```bash
hyperhub skill
```

该命令只输出 Skill 和配置数据参考，不需要密码，也不会修改配置。

### Linux 执行后端

Linux 默认使用 `ptrace-syscall` 作为动态、静态和 stripped ELF 的通用可靠性基线。普通运行无需指定：

```bash
hyperhub run -- curl https://example.com
```

动态 ELF 可显式选择 Gum Interceptor 作为性能优化：

```bash
hyperhub run --backend gum -- curl https://example.com
```

`--backend gum` 依赖 Agent 注入且不支持静态 ELF；默认 ptrace 不依赖 Gum Agent。可用 `hyperhub run --dry-run -- ...` 查看实际后端。

### 一次认证，整个会话复用

首次进入 `hyperhub run cmd` 或 `hyperhub run bash` 时完成一次 HyperHub 会话认证。进入 shell 后，在**同一个会话**中继续执行 `curl`、`git`、`ssh` 或其他命令时，子进程会自动继承当前会话，**无需为每条命令再次输入 HyperHub 主密码**：

```bash
hyperhub run bash

# 以下命令直接执行，不需要重复输入 HyperHub 主密码
curl https://example.com
git clone https://example.com/repo.git
ssh user@example.com
```

这里的“免密码”指不重复输入 HyperHub 主密码；目标服务自身要求的登录密码、密钥或二次验证仍按目标服务规则执行。同一用户在同一个 Serve 实例下从其他终端启动程序时，也可复用本次授权，直到执行 `hyperhub auth clear` 或重启 Serve。

```bash
# 查看运行状态和实时日志
hyperhub status
hyperhub logs --follow

# 清除本次 Serve 的免重复认证状态
hyperhub auth clear

# 停止网关服务
hyperhub stop
```

Windows 使用 `hyperhub.exe` 替换 `hyperhub`。具体参数可通过 `hyperhub --help` 查看。

## TLS 与 SSH 首次信任

对需要网关检查的自签名 TLS 站点以及 SSH 主机，HyperHub 使用 TOFU（Trust On First Use）：首次访问自动把证书或 SSH 主机密钥按精确主机/地址和端口写入加密配置；后续值发生变化时拒绝连接并审计。

也可以在 `hyperhub config` 的“证书”分类中人工管理：

- 导入本地 PEM/DER：添加全局根证书；
- 输入 `https://host[:port]`：信任该 TLS 主机的当前叶证书；
- 输入 `ssh://host[:port]`：信任该 SSH 主机的当前主机密钥；
- 已有记录可以停用或删除。

```bash
hyperhub config --password-file ~/.hyperhub/password
hyperhub show
```

`show` 会保留证书/主机、端口、指纹和启用状态，但不会显示其他敏感配置。TOFU 只能检测首次记录后的替换；若第一次连接也可能遭受主动中间人攻击，应预先人工导入并通过独立渠道核对指纹。

## 本地 Needle 3 配置 Chat

HyperHub 单文件程序内嵌 Needle 3 模型和对应平台推理引擎。运行 Chat 后输入
HyperHub 主密码，即可在本地对话中直接创建、修改或删除配置：

```bash
hyperhub chat
# 或从权限为 0600 的密码文件读取
hyperhub chat --password-file ~/.hyperhub/password
```

对话界面采用与 Codex CLI 相同的信息层级：顶部会话标识、中央消息流、底部圆角输入框和状态栏。`Enter` 发送，`Ctrl+J` 换行，`Ctrl+C` 退出。

Chat 已通过主密码解锁配置，因此模型工具调用会在完整校验后直接加密保存，并在 Serve 运行时热更新，**不会进入 `approve` 队列**。模型推理只在本机回环地址运行，Needle telemetry 被强制关闭；可以输入 API key、Token 和密码等敏感值。聊天内容只保存在当前进程内存中，工具摘要不会回显敏感值。

## LLM 通过 CLI 配置

仓库提供 `$hyperhub-cli` Skill。LLM 先通过 `hyperhub show` 读取完整的脱敏 JSON 配置并提交 JSON Patch；CLI 将请求写入加密审批队列，但不会在规划阶段修改活动配置：

```bash
hyperhub show
hyperhub config patch patch.json

# 人工在真实终端执行，并按提示输入 HyperHub 密码
hyperhub approve
```

`hyperhub show` 不需要密码，输出与导出配置 1:1 对应的 Schema v2 JSON，唯一差异是敏感值显示为 `<redacted>`。配置按 `gateway`、`sandbox` 和 `environment_variables` 分类，凭证与审计 Profile 分离；代理、凭证、审计 Profile、路由、环境变量、信任项及沙盒规则等对象都持久化 UUID。v0.2 不读取或迁移旧配置格式。`approve` 另为每条待审请求分配 UUID，按 `n/m` 显示“新增 / 修改 / 删除”、配置对象 UUID、与 Config TUI 一致的分类路径和脱敏变更，并允许批准、编辑、拒绝或暂退；需要真实 key 时使用星号掩码输入引导。每次决定都会持久化，进程意外中断后再次执行 `hyperhub approve` 会从第一条未处理请求继续。已批准请求立即加密保存，并在 Serve 运行时热更新。完整流程见 [`docs/cli-llm-workflow.md`](docs/cli-llm-workflow.md)。

## 自动构建与发布

向公开仓库推送符合 `vX.Y.Z` 格式的 Git tag 后，GitHub Actions 会自动构建 Windows x64、Linux x86_64 和 Linux aarch64 版本，打包生成校验清单，并创建对应的 GitHub Release。当前版本使用：

```bash
git tag v0.2.0
git push origin v0.1.0
```

## 协议感知扫描

HyperHub 采用**多阶段、协议感知、上下文关联的流量扫描技术**，不是传统的端口扫描器。它从进程行为、域名解析、TCP 连接、TLS 握手到应用层协议逐层建立访问上下文，并将进程、目标、端口、协议与路径信息汇聚为统一的策略输入。

扫描引擎通过分层协议指纹识别和无损首包探测，识别 HTTP/HTTPS、HTTP/2、WebSocket、Git、SSH、代理协议以及未知 TCP 流量；随后结合实时策略快照完成路由决策、风险拦截、凭证注入和审计留痕。对未知协议自动降级为透明转发，对已识别协议进行精细化治理，在覆盖范围、兼容性与可观测性之间取得平衡。

> HyperHub 仍在持续开发中，实际功能以当前版本为准。
