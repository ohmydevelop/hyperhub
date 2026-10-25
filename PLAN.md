# 动态 attach/detach 开发版执行计划

## 状态与发布约束

- 基线：origin/main 5a624d52ee2717a8870d7721a59a6af7d1455ab2（v0.2.15 后的发布记录）。
- 分支：dev/dynamic-attach；独立工作树 hyperhub-attach-dev。不得改动原主工作树的用户文件。
- 目标：实现通过人工审批操作的动态附加、解除接管与安全卸载，完整验证后发布 v0.3.0-alpha.1 GitHub Pre-release。
- 不合并主分支；草稿 PR 保持草稿，完整自动测试、压力测试和用户真实试用稳定反馈均满足后才准备合并。
- 所有进度与结论必须区分实现、实际执行、平台验证和未完成项。不得为赶发布降低门槛或将驻留报告成完整卸载。

## 已确认的产品契约

1. 覆盖 Linux ptrace、Linux Gum、Windows Gum；新开发版 run 与 attach 共用可撤销生命周期。旧版基座不兼容则拒绝，不叠加注入。
2. attach <pid> [--scope process|tree] [--backend auto|ptrace|gum] 和 detach <attachment-id> 只创建审批；approve [request-id] 人工审核，status --json 提供 attachments。
3. 默认 tree 覆盖目标全部线程、既有后代与未来后代；process 仅目标全部线程。树外执行器不自动接管。
4. 运行时审批独立于配置补丁，绑定进程创建/可执行文件身份、所属用户、范围、后端及策略版本；执行前复核。批准后授权十分钟有效、单次消费、用途隔离；API Key 不足以单独授权。
5. 审批和执行分离；准备、接管、解除、排空、驻留、完整卸载、降级、失败与清理未完成必须如实可查询。日志、请求、授权与恢复持久化且幂等。
6. 连续运行优先：不重启、不主动杀外部目标、不破坏允许的既有连接，不污染目标 stdio/TTY，不改 HOME/环境/信任配置/cwd。管理通信走私有 IPC。
7. Serve/CLI 断连继续缓存策略及配置失败动作；动态 ptrace tracer 致命退出保活并明确报告降级，不能宣称继续强制拦截。动态 attach 不使用 EXITKILL。
8. 解除时停止新策略接管和后代传播，保留旧资源最低兼容处理。只撤销本次拥有的 Hook；等待活动回调退出后才能释放代码。超时不得强制释放或断连接。
9. FAKE-IP 映射跨附加代次保留且不得重用仍可缓存的地址；不能证明缓存不再使用时允许驻留至进程退出。连接数归零不是卸载证明。
10. 重复 attach 复用兼容基座；操作与同目标升级互斥。run 解除后启动器仍负责前台等待和退出码传递，保留原启动失败语义。
11. 硬门槛是允许业务语义连续；实测暂停、吞吐和尾延迟，对比未接管和同后端 run，不编造统一 SLA。
12. 开发版默认独立 .hyperhub-dev；指定标签安装、独立二进制目录、不写全局 PATH/覆盖稳定快捷方式。Skill 位于开发实例私有目录。预发行禁用自动替换，不增加开发升级通道。
13. GitHub prerelease=true、make_latest=false，稳定安装和升级不进入 alpha。SemVer 和 Bundle/标签一致。README 不增加版本迁移说明。
14. macOS 不在首版；aarch64 构建/QEMU 验证与原生 attach 硬件验证分别报告。

## 里程碑与负责人

- [x] M0：创建工作树、记录契约、规划职责。
- [ ] M1：共用类型与审批/执行协议、身份/授权、持久化状态和客户端接口。
- [ ] M2：Linux ptrace 与 Gum 动态接管及可撤销 Host。
- [ ] M3：Windows 原生动态接管与 Gum 可撤销 Host。
- [ ] M4：CLI 集成、开发实例/Skill 隔离、SemVer 与预发行发布流程、文档与 Skill。
- [ ] M5：源码 fixture、统一 Suite 注册、审批负例、故障/恢复/TTY/FAKE-IP/连接连续性验证。
- [ ] M6：全工作区、Linux Suite、原生 Windows 回归、每后端至少 100 次循环与连续两小时压力，公开性能数据。
- [ ] M7：最终开发分支 CI、alpha 标签与正式 Pre-release，实际下载包校验与运行验收，保持草稿 PR。

## 验证和协作规则

- 子 agent 仅修改分配的模块，不提交；主 agent 自检并按 committing-changes 完成中文提交，每次提交立即推送本开发分支并检查 CI。
- 共用协议先固定，接口变更先通知。不得覆盖其他 agent 或用户修改。所有 Cargo 构建/测试由主 agent 排期，避免共享构建输出竞争。
- 构建产物仅进入独立工作树 target；测试私有临时目录、虚构凭证和本地服务，不对真实用户程序执行 attach/detach。
- 已有测试不可弱化；保留失败、重试、未触发和未验证记录。关键外部行为必须有源码 fixture 并注册现有 Suite。
- 完整测试：cargo fmt --all -- --check、cargo test --workspace --all-targets --locked、Linux Gum、Linux 统一 Suite、原生 Windows Hook Suite、Skill 契约。
- 压力：三后端各至少 100 次循环和两小时混合运行；检查退出码、允许业务输出、TTY、连接及预热后的 Hook/线程/FD/句柄/模块数量不持续累积。
- 对照：未接管与同后端 run。性能计时前先正确性 preflight；不把失败、重试、未完成工作计入有效吞吐。
- 实际发布包检查：六个公开附件摘要、归档 manifest/版本/架构、README/Skill/Bundle，以及隔离审批和 attach/detach。

## 执行记录

- 2026-10-25：确认主分支与远端一致，主工作树仅有用户未跟踪图片；创建独立分支和工作树。可用磁盘约 92 GiB、内存约 12 GiB；本机 5 CPU，构建需统一排期。
