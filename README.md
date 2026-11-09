# HyperHub

[![CI](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml/badge.svg)](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ohmydevelop/hyperhub)](https://github.com/ohmydevelop/hyperhub/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**本地进程级安全网关。**

无需修改应用，为托管程序提供访问控制、凭证托管和安全审计。支持 Linux 和 Windows，目前处于开发阶段。

## 核心亮点

- **访问控制**：按进程管理网络连接、文件访问和子进程创建。
- **凭证托管**：集中管理凭证，按访问策略注入。
- **安全审计**：记录关键安全事件，便于追踪和排查。
- **AI 辅助配置**：通过 Skill 用自然语言配置策略，由你审批变更。

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

## 配置与使用

在支持 Skill 的 AI 助手中输入：

```text
请使用 $hyperhub-cli，帮我配置访问策略并运行需要托管的程序。
```

更多说明：[使用指南](docs/cli-llm-workflow.md) · [平台与保护范围](docs/hook-intent-matrix.md)
