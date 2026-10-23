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

通过 `hyperhub run -- program args...` 启动需要托管的程序。保护范围是实际托管的进程树，不是全系统。已经运行的外部服务或执行器不会因为客户端位于托管终端内而自动纳入范围；客户端若通过 IPC 把命令交给另一个常驻进程，文件读取和命令执行发生在哪个进程中，就需要单独核对那个执行进程的托管状态。

`hyperhub status --json` 的 `sessions[].processes` 列出当前 Serve 登记的全部成员，包含根进程和子进程。只看根进程名称不足以判断某个成员是否被托管；应核对实际执行器的 PID、进程创建身份和完整成员列表。Serve 显示 `running`、环境变量已继承或 `doctor --target` 能力检查通过，都不能单独证明某个执行器正受保护。成员未出现在当前登记中，也不能仅凭这一点区分从未托管、重启后登记丢失或外部执行器委托；需要结合会话生命周期日志和隔离复现定位。

兼容版本支持在线升级：

```text
hyperhub upgrade
hyperhub upgrade status
hyperhub status --json
```

常驻 Serve 在发起命令退出后继续协调 Engine、转发 worker 和安装 helper。旧连接保留原代次，新调用使用新代次；安装确认与旧连接排空分别显示。最多保留四个旧代次，达到上限时拒绝后续升级。失败事务可用 `hyperhub upgrade recover <id>` 查询并恢复；全局完成决定之前可用 `hyperhub upgrade abort <id>` 中止。

首次从旧版本迁移需要在维护窗口安装常驻基座并重启受管理程序。之后只有基座、Hook 集合和状态契约兼容的更新可以在线切换；不兼容时明确返回 `requires_restart`，不会自动重启目标。Linux 支持 ptrace 和 Gum，Windows 支持 Gum。详细边界和验证入口见[平滑升级记录](docs/features/2026-10-22.md)。

启动后，在你的 Agent 中输入：

```text
请使用 $hyperhub-cli 检查当前 HyperHub 配置，并根据我的需求生成待审批的安全配置变更；不要代替我执行 approve。
```

Agent Skill 会指导 Agent 读取脱敏配置、生成 JSON Patch，并等待你在真实终端人工审批。
