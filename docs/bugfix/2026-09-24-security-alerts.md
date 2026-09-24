# Bugfix 2026-09-24

- 智能防护、沙盒和防火墙拒绝事件原先分别写入判定事件与执行事件，导致同一次动作产生重复日志且字段语义不一致。
- 修复：安全动作统一写入 `security_alert`；Debug 模式的允许动作写入 `security_debug`。
- 进程事件区分 `process_argv_redacted` 与 `target_argv_redacted`，文件、网络和路由事件只保留适用字段。
- 审计 Schema 升级为版本 2，启用全新的 `security-alerts.jsonl` 日志文件，不迁移旧日志或旧审计事件。
