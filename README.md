# HyperHub

[![CI](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml/badge.svg)](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ohmydevelop/hyperhub)](https://github.com/ohmydevelop/hyperhub/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**面向 AI Agent 和自动化工作流的本地进程级安全网关。**

HyperHub 在本机统一管理 Agent 的网络、进程、文件、凭证、策略和审计边界，不要求修改目标程序。项目目前处于开发阶段，支持 Linux 和 Windows。

## 技术重点

- **进程级控制**：覆盖进程创建、文件访问和网络连接。
- **本地策略执行**：支持 allow、deny、smart、observe/enforce 与失败策略。
- **智能防护**：本地脱敏检测结合 Jev Provider，支持风险判定与动作审计。
- **统一审计**：安全动作写入 `security_alert`，Debug 放行事件写入 `security_debug`。
- **本地优先与跨平台**：配置、凭证和审计数据保存在本机；支持 Linux、Windows。

## 安装

Linux：

```bash
curl -fsSL https://github.com/ohmydevelop/hyperhub/releases/latest/download/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://github.com/ohmydevelop/hyperhub/releases/latest/download/install.ps1 | iex
```

## 快速开始

启动本地网关：

```bash
hyperhub start
```

首次启动会引导你设置管理员密码。`start` 同时安装 Agent Skill，供支持 Skill 的 Agent 使用。以下命令在 Linux 和 Windows PowerShell 中均可使用。

通过 HyperHub 启动需要托管的程序：

```bash
hyperhub run -- program args...
```

例如，托管 Codex：

```bash
hyperhub run -- codex
```

## 让 Agent 配置策略

在 Agent 中输入：

```text
请使用 $hyperhub-cli 检查当前 HyperHub 配置，并根据我的需求生成待审批的安全配置变更；不要代替我执行 approve。
```

Agent 会读取脱敏配置、生成 JSON Patch 并提交审批。新增凭证、重设密码或轮换 API Key 时，Agent 使用审批占位符；真实敏感值由你在审批界面输入。

收到审批请求后，在真实终端运行：

```bash
hyperhub approve
```

也可以运行 `hyperhub config`，直接使用交互式配置编辑器。Agent 无法发现已安装的 Skill 时，可让它读取 `hyperhub skill` 的输出。

## 常用命令

| 命令 | 用途 |
| --- | --- |
| `hyperhub show` | 查看脱敏配置 |
| `hyperhub status --json` | 查看网关状态和托管进程 |
| `hyperhub logs` | 查看日志 |
| `hyperhub doctor` | 检查运行环境 |
| `hyperhub restart` | 重启本地网关 |
| `hyperhub stop` | 停止本地网关 |
| `hyperhub upgrade` | 检查并安装最新版本 |

## 保护范围

保护范围是通过 `hyperhub run` 托管的进程树。独立运行的服务或执行器需要单独纳入托管；仅启动网关不能覆盖全系统进程。可通过 `hyperhub status --json` 中的 `sessions[].processes` 核对实际执行器。

文件策略按路径和操作授权，检查硬链接创建、符号链接解析和同时请求读写等场景。路径规则不能自动识别未观测过的既有硬链接别名，也不能替代操作系统级隔离。具体覆盖范围与限制见 [Hook 与平台覆盖](docs/hook-intent-matrix.md)。

## 文档

- [系统架构](docs/architecture.md)
- [CLI / Agent 配置流程](docs/cli-llm-workflow.md)
- [智能防护与 Jev Benchmark](docs/benchmarks/smart-protection.md)
- [Hook 与平台覆盖](docs/hook-intent-matrix.md)
