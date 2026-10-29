# 2026-10-28 Fork 恢复：管理连接断开时单 runner 仲裁（源码补丁 + 确定性回归，未提交）

## 问题与证据

- 实测崩溃：`target/diagnostics/candidate-r37/guest/busy-crash-symbols-forensic-03/debug/48863-gdb.txt`
  主目标 Thread9（signal handler）→ `frida_agent_runner_recreate_agent_thread_after_fork_co`
  （`agent.vala:539`）；raw ELF 偏移 `0x176d69` 对应 `controller.recreate_agent_thread()` 报错后的
  `assert_not_reached`；同栈 `recover_from_fork`（`:480`）→ `run`（`:296`）。
- 根因：fork 恢复把“管理 DBus 连接已正常关闭”当不可能错误：
  1. `do_prepare_to_fork()` 的 `error(...)`（`g_error`）在 prepare 失败时 abort。
  2. `recreate_agent_thread_after_fork()` 中 `setup_connection_with_stream` 失败（`:546`）与
     `controller.recreate_agent_thread()` 失败（`:560`）均 `assert_not_reached`。
  仅改日志不落 `main_loop.quit()` 会让 `stop_agent_thread()` join 永久阻塞。

## 状态机与错误/线程所有权（主审三点已修）

- 单 runner 仲裁用代次化原子槽 `recovery_generation` + `recovery_runner_owner`，**独立于 `transition_mutex`**：
  - `begin_recovery_cycle()`：每个 `recover_from_fork` / `recover_from_specialization` 入口递增代次并
    重置 owner=0（recover 串行，上一 runner 已退出）。
  - `try_claim_recovery_runner()`：`CAS(owner, 0, 当前代次)`，两来源都走它。
  - owner 槽在 main_loop 退出时**不再清 0**，只在下一恢复周期入口 re-arm，避免中途清空被抢。
- **入口早拒（主审 1）**：`resume_after_transition()` 在 `#if LINUX` 的 fd/cloak、`ThreadIgnoreScope`、
  `run_after_transition` 等任何生命周期变更**之前**先 claim；败者立即 `unload_policy = DEFERRED; return;`，
  不碰共享 Runner 与环境。
- **本地 fallback 完整收尾（主审 2）**：`start_fallback_agent_thread()` 的 lambda 跑
  `run_after_transition()` 后调 `finish_recovery_runner()`：`PROCESS_TRANSITION` 直接返回、
  `is_eternal` 走 `keep_running_eternalized()`、否则 `release_shared_instance()`，与远端 resume 一致。
- 错误/所有权：prepare 失败保留 `fork_*` 默认值并继续 `quit()`；recover 阶段由代次 CAS 保证
  “非致命、不永久等待、恰好一个恢复线程”。plain 卸载 / eternal 驻留语义不变。
- **残余 ABA（主审 3，如实标注）**：跨代次的“旧远端线程迟到并抢新代次”在无代次 token 时
  与合法 resume 不可区分（DBus `recreate_agent_thread(pid,injectee_id)` 不携带代次）。owner 槽
  re-arm 已把窗口收窄到“上一 runner 退出后、下一恢复周期 claim 前”；彻底关闭需在 recreate 调用/helper
  通道携带代次 token，属本轮补丁范围外，交由主 agent 的 host 侧钩子/统一 Suite 验证。

## 补丁（third_party/frida/patches/fork-recovery-disconnect.patch）

- 只改 `lib/agent/agent.vala`，基线 post-2-patches（`bd80a8bb…`）：
  - 新增 `recovery_generation` / `recovery_runner_owner` 字段。
  - `resume_after_transition` 入口早拒；新增 `begin_recovery_cycle` / `try_claim_recovery_runner` /
    `finish_recovery_runner` / `start_fallback_agent_thread`。
  - `do_prepare_to_fork` catch：`error` → 日志 + 重置 prepare 输出 + 落 `quit()`。
  - `recreate_agent_thread_after_fork`：`:546` 与 `:560` 的 `assert_not_reached` 与 `else` 统一走 fallback。
  - `recover_from_fork` / `recover_from_specialization` 各加一次 `begin_recovery_cycle()`。
- 自检：`git apply --check` 对 post-2-patches 基线通过；`git diff --check` 通过；index blob 前后与
  `git hash-object` 一致（`eff2c42b…→3c941f33…`）。
- patch SHA256：`5a49db5db19445223b4f6493bf948bfbeeb2fac089a81d0dc27b2dc06c75374f`
- post-image `lib/agent/agent.vala` SHA256（增量补丁在 child-agent-lifetime 之后应用后的值）：
  `3e1b64ea411b6ff23d9e385843470b571f58fde6dbc717e41936d11f6f5c4c75`。
  **注意：不要把 `child-agent-lifetime.patch` 的旧 postimage 直接改成这个最终值**——那会让前一
  apply 阶段校验错。patch 链的 postimage 校验顺序由 Root 统一处理（显式链或整合），本 agent 只生成
  正确增量 patch，不改 manifest/scripts。

## 回归 fixture（tests/fixtures/frida-native/core-fork-disconnect.c）

- 自包含、pipe 驱动、有 watchdog 与 deadline 的有界轮询，不依赖时序 sleep 判定。
- 用链接器 `--wrap` 包装 frida-core 自带的 GDBus 回复函数，在**发送回复前关闭 fixture 自己的
  GDBusConnection**，实现真实中途故障；`recreate` 故障 matcher 精确匹配原方法
  `RecreateAgentThread` 与 token 新方法 `RecreateAgentThreadWithToken`，只吞本 fixture 首个指定
  reply，baseline 与修后均触发。
- 模式：`plain` / `recreate` / `prepare` / `setup` / `eternal-recreate` / `eternal-prepare` /
  `eternal-setup` / `eternal-control`（native no-fault eternal 对照，建立基础设施基线）。
- 只包本 fixture 自己的方法调用（method 名 + 单次原子 CAS），其余转发 `__real_`；未知签名直接失败/
  不匹配。
- 断言：不崩溃、不挂起、`close_triggered==1` 且（`setup*` 模式 `setup_shutdown_done==1`，其余
  `close_completed>=1`）；父/子业务 ping 与退出连续；`plain`/`recreate` 必须 `child thread==1`
  （唯一被证明的单线程不变量）；其余模式由 target 上报**排序 TID 集合**，断言业务线程存活
  （child 主 TID 在集合内）且两次采样 TID 集稳定，并把集合打印给 harness 与 `eternal-control`
  基线比较。**不把 raw 线程数当唯一 owner 证明，不做 `==2` 空断**；确切基础设施线程集合
  常数待 Root 真运行校准后回报。

## eternal 语义与 child 继承（源码证据）

- `agent.vala` `ensure_eternalized()` 置 `_is_eternal=true` 并发 `eternalized()`；`query_eternalized()`
  返回 `_is_eternal`。`_is_eternal` 是 Runner 字段，经 `fork()` 内存复制被 child 继承；
  `recover_from_fork(CHILD)` 不重置它。因此 **parent 在 fork 前 eternalize，child 真实继承 eternal**，
  不是“parent 永恒就代表 child 永恒”的猜测，而是字段复制事实。
- 运行时证明：`eternal-recreate` 中 child 经 gating 正常恢复，attach/probe/detach 后仍保持
  `thread==2`（agent 常驻），即真正 eternal；`eternal-prepare`/`eternal-setup` 中 child 无控制器
  走本地 fallback，`finish_recovery_runner` 因 `is_eternal` 走 `keep_running_eternalized`，保留
  必要 runner（精确 `==2`）。

## Helper 握手顺序证据（跨代次 stale remote 判定）

- `src/linux/frida-helper-backend.vala`：`recreate_injectee_thread` → `perform(RejuvenateTask)` →
  `InjectSession.rejuvenate` → `launch_loader(RELAUNCH)`。`launch_loader` 先 `loader_call.execute`
  （在目标内启动 loader 线程 R），再 `future_agent.wait_async` 等到 READY，然后 `agent.ack()`，
  最后才逐层返回（`rejuvenate` → `recreate_injectee_thread` → helper IPC → host `recreate_agent_thread`
  → GDBus 发送 reply）。
- `src/linux/helpers/loader.c` `frida_main`：`frida_load` 用 `pthread_create` 起 worker R；R 先
  send HELLO/READY，随后 **`frida_receive_ack` 阻塞等待 ACK**，收到 ACK 后才调用
  `agent_entrypoint_impl`（即 `main()` → `resume_after_transition()` → claim）。
- 结论：helper 的 `agent.ack()` 是 `write_all_async.begin`（**异步发起**），在 `recreate_thread`
  返回前已发出，但 R 的 claim 在另一条线程上、紧随 ACK 之后，**与 `recreate_thread` 返回及 DBus
  reply 并发，无 happens-before**。因此**不能证明“recreate_thread 返回前远端已进入
  resume_after_transition 并 claim”**；claim 时机是竞态。
- 由此：旧 R 重新读取 Runner 当前 `recovery_generation` 冒充新代次的窗口真实存在。要彻底关闭必须
  把**不复用的代次/所有权 token 沿 DBus `recreate_agent_thread(pid,injectee_id)` → helper →
  loader → `main()` 携带到入口**（例如把代次嵌入 `agent_parameters`/injector state）。该通道在
  agent.vala 单文件补丁内不可改，故此项**阻断**，不以“范围外”伪装完成。

## child setup 连接故障的确定性回归（阻断证据）

- `setup_connection_with_stream`（`agent.vala:544`）失败需要 child 的 `fork_child_socket` 有效、
  但 host 侧 `start_child_connection` 持有的 local 端 `fds[0]` 已关闭。
- `PrepareToFork` 的 FD reply 只暴露 `fd_list` 中的 child 端 `fds[1]`（且 `g_unix_fd_list_append`
  会 `dup`）；在 `return_value_with_unix_fd_list` 包装内关闭 `fds[1]` 会让 `sendmsg(SCM_RIGHTS)`
  返回 EBADF，退化为 prepare-disconnect（已覆盖），不能触发 `:546`。
- 确定性触发 `:546` 需在 FD 传递阶段关闭 host 的 `fds[0]`（`start_child_connection` 内部对象，
  包装函数拿不到），或 wrap `socketpair` 记录该 fd 后延迟关闭。后者依赖 Linux socketpair 返回相邻
  fd 的实现细节，fixture 侧判定为主 agent 可进一步实现的候选，本交付不伪称已覆盖。

## setup fault 回归（已实现为真实故障，非静态检查）

- fixture `core-fork-disconnect.c` 新增 `setup` 模式：包 `return_value_with_unix_fd_list`，
  对 `PrepareToFork` 的 `fd_list[0]` 用 `g_unix_fd_list_get` 取得副本 fd，对该副本
  `shutdown(SHUT_RDWR)` 后 `close`，再调用 `__real_return_value_with_unix_fd_list` 把**原有效
  reply+fd** 传回父进程。副本与原 fd 指向同一 socket，shutdown 使 child 收到的 socket 已关闭，
  从而确定性命中 `setup_connection_with_stream` 失败路径（`:546`）。
- 断言：`close_triggered==1` 且 `setup_shutdown_done==1`（证明只触发一次且实际进入该分支）。
- 保留 `plain`/`recreate`/`prepare`。`gcc -fsyntax-only -Werror` 通过；运行通过由 Root 真实编译
  后判定，不把静态检查写成运行通过。

## fork patch token 通道：分阶段实现（Root 编译/回归，本 agent 不改 manifest/scripts/GLib/Rust）

目标：让远端 resume 携带“不复用、绑定 Runner 实例”的 token，旧入口不能再读当前代次冒充新代；
claim 用单个原子代次+claimed 状态，避免先校验再 CAS 的 TOCTOU。

### 已否决：injectee_id 作为 token（独立 review 更正）

- 否决原因：**injectee_id 不是每次 rejuvenation 的唯一单调值**。同一父进程反复 fork 时
  `fork_parent_injectee_id` 保留，多次 `recreate_agent_thread` 复用同一个 injectee_id；只有
  child 的 clone_id 才变化。因此不能把 injectee_id 当 token，也不能仅比较该值。
- 更正：token 必须是 **Runner 侧产生的、映像生命周期内不复用的 launch ID**，沿内部 token 方法透传；
  或 helper 每次请求生成并通过先前安全协商把期望 ID 准确交回 Runner。本轮采用前者。

### 正确设计（Runner 生成 launch ID，内部 token 方法透传）

- 阶段 A（token 管道，无行为变化）：
  - `lib/base/session.vala`：`AgentController` 的 `recreate_agent_thread` 增 `uint64 launch_id`
    入参（内部 DBus，非公开 Injector ABI）；`LinuxInjectorState` 增 `public uint64 launch_id;`。
  - `src/linux/helpers/inject-context.h`：loader context 与 `FridaLinuxInjectorState` 增同名字段。
  - `src/host-session-service.vala`、`src/linux/linjector.vala`、
    `src/linux/frida-helper-types/process/service/backend.vala`（backend/RejuvenateTask/
    InjectSession/launch 与 RemoteAgent）：把 launch_id 一路透传到 loader context 写入。
  - `src/linux/helpers/loader.c` `frida_load`：**在 `pthread_create` 前**把 launch_id/ctrlfds/
    fallback 地址/本线程身份复制到私有 per-launch 冻结块；`frida_main` 只读冻结块，不再从共享
    ctx 取新通道；并把 `launch_id` 写入 `injector_state`。
- 阶段 B（agent 校验 token）：
  - `agent.vala` `Runner` 增单调 `launch_id_counter` + 实例唯一前缀；`recreate_agent_thread_after_fork`
    在调 `controller.recreate_agent_thread` 前生成 launch_id 存入 `expected_launch_id` 并透传。
  - `Agent.main` 在 fresh/resume 分流**之前**读取 `injector_state.launch_id`：非空且与
    `expected_launch_id` 不符即旧 resume → 返回有记录 DEFERRED，不碰 shared_instance/Environment，
    防 plain fallback 已清 shared_instance 后旧 remote 误走 fresh。
  - `resume_after_transition` 入口同一校验；claim 用单原子代次+claimed，单次 CAS。
- 阶段 C（单原子 claim）：把 `recovery_generation`/`recovery_runner_owner` 合成一个原子字
  `recovery_claim`（代次+claimed），`try_claim` 单次 CAS，消除 validate-then-CAS 窗口。
- 阶段 D（loser 语义与 plain 收尾）：
  - 现有 `demonitor` 只 cancel 监视协程、不 cancel/join loader pthread，不能代替 token；loser 用
    薄 native `pthread_self`/`pthread_detach` wrapper 后返回**有记录 DEFERRED**，不让 loader 按共享
    `ctx->worker` 去 detach 别的线程，也不 IMMEDIATE（避免 dlclose/deallocate）。
  - plain 本地 `GLib.Thread` 无法安全 dlclose 自身映像：本轮允许**真实保守 Resident**，不声称完整
    物理卸载，不用改 eternal 掩盖。
  - plain 收尾补 `Environment._deinit`：由唯一 owner 在释放 Runner/ignore scope 且确认晚入口不再
    访问已关闭 GLib 后执行，不在捕获 `this` 的 lambda 里直接补。

阶段 A–D 需 Root 真实编译并跑统一 Suite；本 agent 本轮先冻结 setup fixture，token 通道按 A→D 分批
落地，不在未编译前宣称运行通过。

## 主 agent 待执行

1. 注册补丁到 `manifest.json` 与 `scripts/native-deps/bootstrap.py`（core_patches 追加），并按
   Root 的 patch 链/顺序校验 postimage（不简单把 child-agent-lifetime 旧 postimage 改成最终新值）。
2. 在 `scripts/native-deps/regressions.py` 编译本 fixture 时追加：
   `-Wl,--wrap=_frida_g_dbus_method_invocation_return_value
    -Wl,--wrap=_frida_g_dbus_method_invocation_return_value_with_unix_fd_list`，
   并执行 `plain` / `recreate` / `prepare` / `setup` 四模式。
3. 用 host 侧 DBus 注入钩子 / 统一 Suite 覆盖 `setup_connection_with_stream` 中途失败与
   跨代次 stale-remote-resume 的残余 ABA（本 fixture 与补丁不伪称已运行时证明）。
