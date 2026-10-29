# 会话发行历史与跨进程消费者

状态：协议与实现检查点草案。Core/Runtime/SDK 的有序 provenance、签名历史分页、发行 ACK、登记屏障、Detach admission gate 与恢复路径已写入源码，尚待下一候选编译和实际执行；不得将源码存在当作覆盖。r9/r10 的实际 stop/start 双轮验证已经证明旧缓存地址可恢复且新地址不复用；该结果只覆盖发行者仍存活并可导出本地表的旧协议路径。下述跨发行者路径尚未据此通过。Core 代做 DNS、猜测某个 IP 段属于 HyperHub、消费端重新解析域名均不是本方案。

## 缺口与源码复现

同一 tree session 的 child 通过 HH ABI 解析 A，只将 sockaddr 的地址字节经 pipe 交给 parent，随后 child 退出。parent 没有做 DNS，因此没有本地 Issued 记录。Active 时 Core 的 session 全局 `name_by_fake` 仍可解释 A；Detach 或 Core 丢失会话后，parent 的本地 native 表与 live-Host union 都可能遗漏 A。

源代码回归使用 attach 前已经存在的 child，避免将另一个 post-Active fork 缺陷混作本例。child 获得真实 HH-issued A 后传纯 IP，parent 存入连接缓存，child 正常退出。要求：Active 下旧 A echo 正确；审批 Detach 后关闭私有 Serve，parent 仍以 producer 当时的 native 地址连接本地 oracle；重新启动并审批 reattach 后，先验证 A，再发行不同 B，要求 A 仍正确且 B 不等于 A。parent 不得额外查询 DNS 来填补测试前提。Linux 和 Windows 均需对应源码，不以 native Rust CreateProcess 代替其他 fork 契约。

## 已确定的记录语义

`ResolveName` 在既有请求中携带 SDK 于原同步解析边界采集的 native provenance。Core 必须认证实际 peer 为 session 的存活 member，issuer PID/birth 由 Core 填写，不由 caller 自报。原始有序地址需要保留 IP、IPv6 scope 和 flow；原生解析错误与因当前策略抑制查询的 unavailable 必须区分。

共享类型为 `NativeAddress { ip, scope_id, flowinfo }` 和 `NativeFallback { family, addresses, failure, unavailable }`。failure 与 unavailable 互斥，二者出现时地址列表为空。字段、地址顺序和标量均参与 fingerprint，不排序地址。相同 hostname/family 但 native fingerprint 不同的解析必须分配新 slot，旧 slot 不覆盖、不回收。远端可解析但本地失败的名字不能因此在 Active 阶段突然失败；它保留明确的 native 不可用结果，不能在 Detached 时重新查询或猜地址。

## 发行提交

Core 对每个 session 串行执行发行、ready-member catchup 和 Detach 历史提交。Native SDK 的独立 publication guard 覆盖从 native prefetch 开始到 native map 写入及 ABI 输出发布结束；不能将所有 active calls 当作 DNS 屏障，因为原始阻塞 I/O 必须继续存活。

每条发行记录含序号、地址、hostname、完整 native provenance、实际 issuer PID/birth 和 ambiguity。Core 在回复 alias 前先记录、签名并持久化，向所有 ready members 传播带完整数据的签名 delta、seq/head 并收到 ACK。任何存活成员未 ACK 时，不把本次 alias 交给应用；已预留 slot 不重新赋给其他含义。死亡成员只能在实际 OS birth/liveness 证实后移除。

新 member 在应用恢复前取得完整历史、验证前缀并 ACK 后才标记 ready。注册与发行需使用同一个 session 屏障，防止在快照和 resume 之间漏掉一条已成功发行的记录。SDK 的历史锁不能跨等待 Core 的 RPC，否则 Core 向正在解析的 publisher fanout 会死锁。

## 签名与快照

签名源是 Host 在可信初始化时固定的 Core attestation key，或由已验证管理员授权/轮换链认可的后继；不能从 journal 自报公钥建立信任。

signed payload 含 instance、attachment、原 root、session、immutable host binding、base_sequence、previous_head、sequence、head、records 和 complete。每条记录用固定域和规范编码串接前一个 head。delta 覆盖连续的 base+1..sequence；full 从 1 开始，接收方已有的本地前缀必须精确一致。SDK 只合并，不删除旧保留地址；旧 seq/head 不能回滚，冲突及缺尾必须标记 unproven。

Detach 在移除策略前向所有存活成员提交完整全局兼容表并取得 ACK，因此已退出 producer 的原始 native 结果仍到达实际 consumer。保留旧连接的必要引用继续保留；元数据提交本身不解除策略。

## 重启和持久化边界

正常 restart 必须由旧 Core 自己创建受控 successor，通过仅给真实 child 的匿名通道交接内存 attestation key、受信操作状态和发行历史。不能向任意 same-SHA caller 导出私钥，也不能在旧 Core 已死亡后从普通文件补私钥。

真正 cold startup 只可从实际存活 Host 已固定的旧 Core 公钥及其 seq/head 验证 journal。任意自报文件 key、有效旧前缀回滚、缺失已发行尾部都不能被当成完整历史。新 Core 的发行签名权需要受信后继证明；当前新鲜 Attach 授权已签署精确受控 Core 公钥，恢复时可在同次已批准操作中认可新 signer；Runtime 保留实际 signer 与 endorsement floor，不能改写 immutable Bootstrap 或回滚。正常 restart 的内存 key 交接、第二期审批 receipt 与密码轮换链仍未完成，不据此宣称冷启动续办与平滑升级已经闭合。

普通 run 不新增密码。没有可信 Core attestation 时必须明确发行能力 unavailable；不得接受 unsigned provenance，也不得将普通 observed DNS 升级为 Issued 来源。跨 managed session 或未管理进程传递 HH alias 仍须单独说明命名空间边界，不以 tree 内修复宣称全系统透明。


## 当前源码检查点与待执行验证

Core 的 `attachments/alias_control.rs` 现在负责同一 session 的登记、分页、发行、持久化与屏障。`RegisterAliasHost` 对 SDK 以实际 IPC peer 识别自身；manager 的目标 hint 只对已登记的实际 manager incarnation 开放。无需 native_ready 才能登记：先完成历史 catchup，再允许应用恢复。Resolve 回复携带该地址自身的 sequence/head，SDK 必须已经安装精确 provenance 后才能发布地址。

页大小按外层 JSON 的真实编码计量。签名字节数组的 JSON 膨胀不能靠仅限制 payload 字节数解决。普通 catchup 使用连续分页；全历史恢复导出仍受单帧上限约束，超限应明确拒绝，完整分页恢复游标仍是缺口，不能截断并标 complete。

已写入的 Core 单元/私有 IPC 回归为 `signed_history_pages_preserve_dead_producer_provenance_and_exact_prefix`、`signed_history_wire_rejects_tampered_native_meaning_or_scope` 与 `registered_alias_publication_requires_signed_host_ack`。最后一项使用实际私有 Host listener，先拒绝 ACK，要求 Core 不返回地址，再确认重试相同已预留 slot；它不替代真实 tree 里已退出 producer 的源码回归。另有 native fingerprint 改变需新 slot、池耗尽不复用、原始 native 回答落入保留池时拒绝合成三项 allocator 回归。前三项原始 allocator 回归在 r11 Core suite 实际通过；首次私有 listener 夹具因缺少自己的 runtime 父目录失败，修正 setup 后已实际通过。新增 `inline_registration_can_progress_while_publisher_awaits_host_ack` 后，四项 alias_control 定向测试实际通过（含测试体 6.41 秒）。这些是未冻结开发源的 diagnostic 结果，不计入正式 model/plan 执行分母。

`PrepareDetachment` 只关闭新的 synthetic publication admission，不提前解除策略或推进 accepted detach cutoff。已经开始的独立 guard 正常排空；新尝试退出计数后有界等待，不能用它们永久顶住计数。Core 将新登记的 member 暂留在 ready=false，逐次发现实际 Host，排空计数后提交历史。尚在初始化的 Host 以精确 `activation_busy` 返回，Core 对同一次未提交操作取消 pause 后重试，不能笼统吞掉协议/认证错误。完成时只有全部实际存活 Host 已 policy-off 且 pending publication 为零才开放新登记。此协议还需实际 busy-spawn/fork/exec 回归证明，不能凭锁顺序审查计为执行通过。

曾提出 Unix atfork 可能出现 parent Agent mutex→Core History→child Register 锁环。两位平台 owner 查明 `fork::parent` 在 libc parent callback 内先释放 alias pin、Agent/runtime guards 与 snapshot，再进入 Core onLeave；只有创建 GATE 保留。因此该特定冻结状态锁环未获源码证实，不为此扩大重构。实际 Yama0 fork/exec/crossproducer 仍需执行。

## 原生地址命名空间的限制

普通动态 attach 的原生 DNS 保持原始地址及 Observed 来源，不应隐式发行 HH 地址。显式 SDK 合成与受控 owned-run 兼容只在专用地址池契约内成立。生产者原生回答若已位于 IPv4 `198.18.0.0/15` 或精确 HH IPv6 前缀，则拒绝合成，不能把外部假地址重新标成 Issued。

即使全局历史完整，也无法观察 attach 前已经缓存、经未知 IPC/文件传入的 foreign 地址。原始数值地址没有来源标签时，既有 foreign `.1` 与新 HH `.1` 无法仅凭 sockaddr 区分。更换随机 IPv4 段不提供零碰撞证明；本方案不声称消除这个信息边界。该限制进入签名 capability report。原生 DNS 保持/显式 profile 的平台行为仍须下一检查点落地与执行，不能用记录限制替代实现。


## r12 后锁顺序回归

另一个独立于 atfork 的锁环已由源码确认：单线程 Host Activate 同步等待 RegisterAliasHost，而 Core 持有 History 时等待同一个 Host 的反向 Apply。现在 per-session operation mutex 只序列化发行/RootImage/Detach 操作；History 只短持有，所有反向 Host RPC 均在 History 外执行，ACK 后再检查精确 seq/head、当前 root state、member incarnation/endpoint 和新 ready 注册。注册本身不等待 operation mutex。

`inline_registration_can_progress_while_publisher_awaits_host_ack` 在真实私有 Host listener 的 Apply 回调中执行登记，已实际通过；旧的持 History 反向 RPC 会阻塞到 transport timeout。它证明这个具体锁顺序，不替代实际 busy creation、root exec 与 broker reservation 的组合回归。Finish Detach 还核对 SDK spawn_calls=0；backend 自己的创建 reservation/capture 也必须为零，不能仅依赖两次 PID 扫描。

r12 首次真实 Gum tree 注入的 30 秒 readiness 失败已由隔离 guest 原生栈定位为 allocator 重入：初始化 malloc 中触发 mprotect hook，而映射扫描使用 std::fs/Vec 再次分配。它不是已证实的签名拒绝或旧 fork READY 错误。平台 owner 正在修复可信初始化作用域及普通匿名映射的无分配分类，原始失败保留；不能在未重建回归前记为已修好。

大型历史后续优先利用实际存活 Host 的已验证 signer/seq/head 与本地连续签名 journal，而非传输无限 full snapshot。已被真实 retained head 覆盖的记录链可用该 head 核对；额外尾部必须有已知/历史已认可 signer 的签名才能保留其含义，未知 key、缺尾或冲突拒绝，不从文件自报公钥建立信任。当前只记录这个设计，尚未实现、未做大型真实 fixture，不计为关闭 large export 缺口。
