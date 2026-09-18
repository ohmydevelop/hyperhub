# HyperHub

[![CI](https://github.com/flash-dev-ctrl/hyperhub/actions/workflows/ci.yml/badge.svg)](https://github.com/flash-dev-ctrl/hyperhub/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/flash-dev-ctrl/hyperhub?include_prereleases)](https://github.com/flash-dev-ctrl/hyperhub/releases)
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
curl -fsSL https://github.com/flash-dev-ctrl/hyperhub/releases/latest/download/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://github.com/flash-dev-ctrl/hyperhub/releases/latest/download/install.ps1 | iex
```

也可以从 [GitHub Releases](https://github.com/flash-dev-ctrl/hyperhub/releases) 下载对应平台的单文件 CLI：

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

# 在受控边界内启动命令行会话
hyperhub run bash       # Linux
hyperhub.exe run cmd    # Windows
```

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

## 自动构建与发布

向公开仓库推送符合 `vX.Y.Z` 格式的 Git tag 后，GitHub Actions 会自动构建 Windows x64、Linux x86_64 和 Linux aarch64 版本，打包生成校验清单，并创建对应的 GitHub Release。第一版使用：

```bash
git tag v0.1.0
git push origin v0.1.0
```

## 协议感知扫描

HyperHub 采用**多阶段、协议感知、上下文关联的流量扫描技术**，不是传统的端口扫描器。它从进程行为、域名解析、TCP 连接、TLS 握手到应用层协议逐层建立访问上下文，并将进程、目标、端口、协议与路径信息汇聚为统一的策略输入。

扫描引擎通过分层协议指纹识别和无损首包探测，识别 HTTP/HTTPS、HTTP/2、WebSocket、Git、SSH、代理协议以及未知 TCP 流量；随后结合实时策略快照完成路由决策、风险拦截、凭证注入和审计留痕。对未知协议自动降级为透明转发，对已识别协议进行精细化治理，在覆盖范围、兼容性与可观测性之间取得平衡。

> HyperHub 仍在持续开发中，实际功能以当前版本为准。
