# 动态 attach 覆盖审查草案

本目录是源码仍在变更期间的审查快照，不是发布冻结，也不是一次正式执行报告。审批固定根第一期源码已在该快照之后修改，当前 model/plan 的源文件摘要因此待重新审查；下列 checker 计数描述上一次文档快照，不是新代码的当前通过状态。`BENCHMARK.draft.md` 由 benchmark skill 的 canonical checker 生成；本文件只解释审查范围和缺口。

## 本次模型与检查

- 保留原有 9 项义务、3 个 backend 和 attach/run 两个入口，共 6 个比较组合。
- 将原有聚合要求拆成 82 个可核对的子边界，没有取消原验收义务或降低 100 个成功循环、7200 秒目标活动的要求。
- 计划有 43 个场景：31 个有源码入口及触发/断言引用，12 个保持 planned。入口存在与已实现断言不表示执行通过。
- design 检查退出码为 0；implemented 检查退出码为 1。设计边界为 82/82，实现边界为 52/82。正式申报执行及有效测量均为 0/82。
- 模型摘要：`5f44b700169fa4f3238bf264aa259f6bab94fcc850d97a655890190d8eff929e`。
- 计划摘要：`73edcf2302fc805765b5d4dbce1a485a9041c2ab574dac1b13d2a158055510ed`。

源码行引用绑定真正的触发语句与结果断言。源文件和入口产物均记录 SHA-256；后续修改这些文件会使当前检查失效，必须重新审查并建立新快照。这里没有生成 `run.json`，也没有将旧候选的诊断结果改写成当前模型的执行记录。

## 主要缺口

审批公钥固定、独立密码首次登记、配置 expectedRoot 和 API-only 冷启动未登记状态已加入第一期源码，受限握手与固定根专项已实际执行；这些结果不等于所有平台和当前完整 workspace 通过。密码轮换链及已接受操作历史的可信持久化仍未实现。现有签名、TTL、单次消费和密码轮换测试不能证明普通可写 verifier/ledger 文件具有可信完整性。用户已确认保持无特权部署和可信控制面边界；接口与状态转换见 [AUTHORITY-ANCHOR-DESIGN.draft.md](AUTHORITY-ANCHOR-DESIGN.draft.md)。

FAKE-IP 必须区分 ObservedExternal 和 HyperHub-issued。原先 Linux 样例没有建立该地址的原生路由，却要求 detach 后连接成功，这个 oracle 无效。旧失败应保留为诊断，不能作为已确认产品缺陷或修复通过的证据。来源分离、真正原生基线、缓存不复用和额外目的地尚需完整覆盖，见 [DETACHED-ALIAS-DNS-DESIGN.draft.md](DETACHED-ALIAS-DNS-DESIGN.draft.md)。

Windows 原生执行、目标程序自己的终端与键盘语义、MSYS/Cygwin fork/clone、确切创建提交边界、部分物理卸载与 session 撤销联合证据仍有缺口。Windows GNU 编译或 Rust CreateProcess 样例不能替代这些执行边界。

双重故障后的原始 root 与 manager 均退出、owned Host READY 后 helper 创建失败、detach cutoff 跨 fork/rebuild、所有 backend 的并发线程创建，以及 detached 期间热更新后首次操作的同步策略更新，仍需各自完整触发与独立 oracle。已有内部状态机测试仅覆盖其实际 seam，不代替目标程序行为。

100 次成功循环和 7200 秒活动测量、Windows 原生执行、最终公开的六个包及远端 CI 尚未绑定当前模型的正式有效结果。历史诊断不填充这些缺口。

## 测量协议的差别

Linux 每个性能窗口实际执行 32 对 snapshot/socket，共 64 个经校验命令；分别保留两类延迟、窗口耗时和有效命令吞吐。Windows 每个窗口实际执行 50 个 snapshot，记录独立窗口耗时、样本及吞吐。两者是不同工作负载，不应复制命令数或直接解释为同一吞吐基准。

压力窗口从目标就绪后开始。循环审批耗时、固定无审批窗口、带 pacing 的混合活动分别记录；不能把等待、失败或 setup 计入成功工作量。Windows 资源采样为独立 handle/thread/memory 采样，Linux 检查 warmup 后 FD/thread/native mapping；源码断言不能替代真正完成的长期运行。

## 已保留的诊断和待回归修正

`diagnostics.draft.json` 保留 r4 ptrace 第三次 attach 审批失败的原始证据及文件摘要：前两轮完成，复用的 Draining 槽在人工审查期间变成 Detached，随后 `create_record` 返回 File exists。新的状态机回归检查 fresh request/attachment/session id、旧 receipt 保留和 target/scope/backend/policy 不变；人工审批路径还需以新候选实际回归，不能用额外 sleep 或忽略失败处理。

ptrace manager 恢复后的 EngineHost member 绑定，以及状态查询保留原 backend 拒绝原因，也已建立源码修正。新候选的实际结果由主 agent 收集；本审查没有提前记为通过。

## 复查入口

使用 `/home/a/.agents/skills/benchmark/scripts/benchmark_contract.py check`，参数为当前目录中的 model/plan、上述模型摘要、`--require-standard`，分别运行 `--stage design` 与 `--stage implemented`。后者应保留未达标退出码，直到缺口真实关闭。完整命令、各场景入口和逐项引用见生成的 [BENCHMARK.draft.md](BENCHMARK.draft.md)。

## 后续开发证据（未刷新模型摘要）

独立KVM guest使用官方摘要验证的Debian13镜像、内核6.12.113、Yama0；HyperHub与源码fixture均由普通uid1000运行，不共享宿主Home，不修改宿主系统策略。r10 Gum tree的fork读取拒绝符合策略，但随后exec子进程退出133；独立process原root self-exec后立即读取成功，仍未覆盖该执行转换。两项失败均保留，不能以旧process100轮固定映像通过填充exec边界。所有Gum路径已收紧为仅Yama0候选前提，权限前提不代替本项正确性修复。

r10固定映像process100轮和r6 ptrace175轮/7200.075秒已实际完成，仅属各自不可变候选的诊断证据，未转换为当前草案run.json。真实目标RawTTY夹具已加入逐阶段render确认和supervisor退出后模式恢复检查，本地native、ptrace attach/run、Gum process attach均两轮通过；Windows仍缺原生执行。跨producer历史与卸载publication admission屏障正在开发，签名receipt、轮换链、Core可信交接与MSYS尚未完成。

## r13 诊断检查点（不填入正式覆盖分母）

不可变 CLI 的 SHA-256 为 `4a8576d45e6d35456b9d6d1c751a69ffeab10ae1f69c71ea4a17c6aa59e186ca`，318 个构建输入在构建与测试结束时保持一致。五阶段构建退出码为 0；独立 Core lib 为 367 passed / 1 ignored，Runtime lib 为 17 passed。默认 workspace 仍因两项 `engine_host_live` 普通 owned 启动超过原有 15 秒 `TARGET_PID` 窗口而失败；Agent Gum 则为 68 passed / 1 failed（新 maps parser 单元的端地址参数错误，修正待重跑）。保留所有失败，不把子集通过写成完整 workspace 通过。

同一 `engine_host_live` 测试程序仅将 CLI 换为该不可变 release 候选后，7 项通过，22.11 秒；其中默认门控的 Gum 路径没有原生执行，不能计入平台覆盖。这个对照支持大型 debug 映像重复哈希的延迟定位，不替代默认 debug 验收。后续负向 role prefilter、普通 API-only owned-launch 初始化优化和 file smart-protection 版本绑定仍等待新源码专项及默认 debug 回归。

隔离 Yama0 KVM 中 Gum tree 两轮实际通过 19 项检查，包括已有 child 与 attach 后 fork/exec/vfork 的保护和再次附加。它仍是短诊断，不能填充 100 成功循环或 7200 秒要求。证据路径和原始文件摘要保存在 `diagnostics.draft.json`；未建立正式 `run.json`。

## 下次冻结必须纳入的新增边界

以下是后续源码和真实反例补出的模型增量，尚未加入上方旧模型的 82 项边界。旧的设计覆盖计数不能证明这些边界已经覆盖；重新冻结时必须保留原义务并审查这些增量，不能只更新源码摘要。

| 边界 | 必须验证的触发与独立结果 | 当前证据范围 |
| --- | --- | --- |
| 原 root 的 exec | 同映像连续两次、不同映像、非主线程与基于 FD 的 exec；同 PID 的首次操作仍拒绝，终端/环境不变；原审批身份保留，可信执行代次推进 | r10 原 root 丢失保护反例已实际触发；r13 KVM Gum 同映像 root exec 后首次读取拒绝、exec_epoch=1 已通过，连续两次/变映像/非主线程/FD 路径尚未全部执行 |
| exec 后的审批 | 旧代次批准不能在新 root 或后代直接消费；root 退出后后代仍保留可信代次；新的 Detach 预览绑定当前映像 | 不可由可写 record 或单独 hash 推导；尚需新候选 |
| fork 返回门与监听器退休 | 新 child 已重建 SDK 时，旧回调仍在执行；管理器重新 arm/卸载临时脚本不能与返回门互等 | r11 双侧原生栈已确认等待环；r13 KVM Gum tree 两轮 fork/exec/vfork/显式 child 环境及再次附加已实际通过，长期和更广交错未覆盖 |
| 分配器与内存保护 Hook | SDK 初始化和普通目标堆扩容在分配器锁内调用 mprotect，不得再次分配；文件映射从 PROT_NONE 取得读取权仍须受策略限制，路径空格/换行及映射读取失败不能被当成匿名区域 | r12 初次就绪死锁有原生栈；r13 tree 初次就绪通过。r10 对照已实际读取空白路径映射，以及映射元数据失败时 dummy 文件；r13 allocator/path/mapping 完整套件仍失败，不能宣称全部修复 |
| Preparing 与卸载期间的新 child | 原生 spawn 预留、Host 注册、DNS prefetch 与输出发布分别交错；成功覆盖所有已提交成员，或明确拒绝且取消同一阶段、目标继续运行 | 签名 DNS admission 已有单元；完整并发捕获未通过 |
| process 范围的外部 child | fork、exec、vfork、posix_spawn 保持原生行为和显式环境，root 的执行监测不扩大保护范围 | r11 spawn-env 进度超时反例；不能以此前 fork 通过代替 |
| 跨发行者地址缓存 | 既有 child 发放并只传 sockaddr 后真实退出；未做 DNS 的 parent 在离线、解除、重新附加后使用同一旧地址，新地址不覆盖旧 slot | 已有源码入口；全局历史与大快照恢复仍待实际验收 |
| DNS 来源冲突 | 原生答案已落入合成池；显式合成应拒绝且不消耗 slot，观察结果不能升级成 Issued；需要未证明域名能力的策略应拒绝 | 保留池及指纹单元实际通过；外部附加默认原生与策略门禁仍在开发 |
| 正常 Core 交接 | 真正子进程接管审批与历史状态，旧 Core 保留已代理的长连接及未完成握手直至排空；冷启动不能从文件建立验证根 | 现有原生直连重启测试不等于代理连接连续性；尚未完成 |
| 目标真实终端 | 独立审批终端之外，目标持续接收完整键盘字节并逐阶段显示唯一输出；supervisor 在 worker 退出后核对模式恢复和退出码 | Linux native/ptrace attach/run/Gum process attach 实际短回归通过；Windows 尚未原生执行 |
| Windows 伪 fork | 真实 MSYS/Cygwin 源码触发句柄转移、SDK 重建、异步 DNS/待完成代理握手及 TLS/FLS 回调；不依赖修改目标环境 | CreateProcess 和 GNU 交叉编译均不填充该项 |
| Gum 权限前提 | process、tree、run 在受限或未知 Yama 下执行前拒绝，auto 选择 ptrace；Yama0 正例另行完整执行 | 本机受限负例与隔离 KVM 正例尝试均有记录，KVM 发现的失败保持未通过 |

## R15 与后续局部检查点（非最终验收）

R15 的 325 个列明构建输入保持一致；CLI SHA-256 为 `aeee8405f0c504dea799eb01e6e58f7a7096d611c46fad599b75cc78dfc39192`。默认工作区实际 716 项通过、25 项忽略，Gum SDK 75 项通过。真实隔离 KVM 的 process 冷线程／fork／libc 退出／父进程回收完整通过，四种映射文件名各两轮通过。tree 子进程发布确认、离线重启后的别名重新激活、原 root 自我 exec 后的控制线程退订仍分别失败，保留其完整失败，不能用部分断言通过覆盖。

后续局部检查点的真实私有 IPC 持有证明、CLI 取消、fork 回执和能力分类测试通过，native 与 Windows GNU all-targets 检查通过。受限 Yama 的三个真实拒绝场景通过，报告明确为 `partial`、`coverage_complete=false`。这些结果尚未等于新嵌入候选的真实目标验收；原生 Windows、MSYS、连续长连接的 Core 交接和密码轮换仍是未关闭项。精确日志及摘要索引保存在忽略目录 `target/diagnostics/r15-evidence-index.json`；没有生成正式 run.json，也没有刷新旧模型的正式执行分子。
