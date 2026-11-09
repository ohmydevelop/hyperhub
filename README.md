# HyperHub

[![CI](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml/badge.svg)](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ohmydevelop/hyperhub)](https://github.com/ohmydevelop/hyperhub/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**面向 AI Agent 和自动化工作流的本地进程级安全网关。**

无需修改应用，即可管理 Agent 的访问权限与凭证。支持 Linux 和 Windows，目前处于开发阶段。

## 核心亮点

- **进程级防护**：管理托管程序及其子进程的网络、文件和进程访问。
- **凭证与审计**：集中管理凭证，记录关键安全行为。
- **Agent 协作**：用自然语言配置安全策略，变更由你审批。

## 安装

Linux：

```bash
curl -fsSL https://github.com/ohmydevelop/hyperhub/releases/latest/download/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://github.com/ohmydevelop/hyperhub/releases/latest/download/install.ps1 | iex
```

## 启动

启动网关，再通过 HyperHub 运行 Agent（以 Codex 为例）：

```bash
hyperhub start
hyperhub run -- codex
```

首次启动按提示设置管理员密码，并自动安装 `hyperhub-cli` Skill。以上命令也适用于 PowerShell；将 `codex` 替换为你使用的 Agent 命令即可。

## 使用 Agent

在支持 Skill 的 Agent 中输入：

```text
请使用 $hyperhub-cli 查看当前配置，并帮我配置需要的安全策略。
```

Agent 提交变更后，由你在终端完成审批：

```bash
hyperhub approve
```

Agent 未发现 Skill 时，让它读取 `hyperhub skill` 的输出。

更多说明：[CLI 与 Agent 使用](docs/cli-llm-workflow.md) · [平台与保护范围](docs/hook-intent-matrix.md)
