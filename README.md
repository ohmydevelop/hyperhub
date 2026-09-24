# HyperHub

[![CI](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml/badge.svg)](https://github.com/ohmydevelop/hyperhub/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ohmydevelop/hyperhub)](https://github.com/ohmydevelop/hyperhub/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**面向 AI Agent 和自动化工作流的本地进程级安全网关。**

HyperHub 在本机统一管理 Agent 的网络、进程、文件、凭证、策略和审计边界，不要求修改目标程序。

## 技术重点

- **进程级控制**：覆盖进程创建、文件访问和网络连接。
- **本地策略执行**：支持 allow、deny、smart、observe/enforce 与失败策略。
- **智能防护**：本地脱敏检测结合 Jev Provider，支持风险判定与动作审计。
- **统一审计**：安全动作写入 `security_alert`，Debug 放行事件写入 `security_debug`。
- **本地优先与跨平台**：配置、凭证和审计数据保存在本机；支持 Linux、Windows。

详细设计与验证：

- [系统架构](docs/architecture.md)
- [智能防护与 Jev Benchmark](docs/benchmarks/smart-protection.md)
- [CLI / Agent 配置流程](docs/cli-llm-workflow.md)
- [Hook 与平台覆盖](docs/hook-intent-matrix.md)

## 安装

Linux：

```bash
curl -fsSL https://github.com/ohmydevelop/hyperhub/releases/latest/download/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://github.com/ohmydevelop/hyperhub/releases/latest/download/install.ps1 | iex
```

## 使用

启动本地网关：

```bash
hyperhub start
```

Windows 使用 `hyperhub.exe start`。

启动后，在你的 Agent 中输入：

```text
请使用 $hyperhub-cli 检查当前 HyperHub 配置，并根据我的需求生成待审批的安全配置变更；不要代替我执行 approve。
```

Agent Skill 会指导 Agent 读取脱敏配置、生成 JSON Patch，并等待你在真实终端人工审批。
