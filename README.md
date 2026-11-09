# HyperHub

[![CI](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml/badge.svg)](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ohmydevelop/hyperhub)](https://github.com/ohmydevelop/hyperhub/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**面向任意程序的本地进程级安全网关。**

为 curl、SSH、AI Agent 等程序统一管理访问权限与凭证，无需修改应用。支持 Linux 和 Windows，目前处于开发阶段。

## 核心亮点

- **进程级防护**：管理托管程序及其子进程的网络、文件和进程访问。
- **凭证与审计**：集中管理凭证，记录关键安全行为。
- **AI 辅助配置**：用自然语言配置安全策略，变更由你审批。

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

```bash
hyperhub start
```

## 使用

在支持 Skill 的 AI Agent 中输入，让 AI 引导配置和使用：

```text
请使用 $hyperhub-cli 查看当前配置，并帮我配置需要的安全策略。
```

更多说明：[CLI 与 Agent 使用](docs/cli-llm-workflow.md) · [平台与保护范围](docs/hook-intent-matrix.md)
