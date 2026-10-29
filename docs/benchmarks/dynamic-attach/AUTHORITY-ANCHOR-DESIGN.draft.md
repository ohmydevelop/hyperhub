# 审批公钥固定与轮换：接口草案

状态：第一期固定根代码已实现，相关受限密码登记、Serve role lease 与固定根负例已在诊断检查点执行通过；这不表示当前持续修改后的完整 workspace 或发布门槛通过。第二期密码轮换链、可信完成历史及升级交接尚未完成。沿用现有无特权受管进程部署，不新增独立权限服务。配置和受信任程序属于 TCB，不承诺抵御同一用户对全部 TCB 或其内存的接管。本文不表示已通过发布门槛。

## 目标与信任范围

Serve 与每个目标 Host 必须在内存中固定审批公钥。普通磁盘文件只能携带缓存、候选轮换记录和审计材料，不能自行登记公钥、替换内存中的公钥或证明某个操作曾获批准。文件所有者与私有权限仍是必要的访问限制，但不能替代这个完整性边界。

正常 `serve/start`、已有策略服务和新 `run` 保持 API-only 自动启动。API-only 冷启动的审批状态为 `Unenrolled`，不能对现有外部目标执行 attach、detach、reactivate、recovery。创建待审批请求和读取状态仍可用。首次真实管理员 `approve` 解锁当前配置后，在私有、经过 OS 认证的同连接握手中短暂提交密码。Core 独立解密精确配置并派生公钥后完成登记，然后 CLI 签署、Core 消费并执行该请求。密码和私钥不持久化，不写日志或 Debug。

不承诺在没有操作系统隔离时抵御同一用户对全部配置、运行文件、受信任程序及其内存的完整接管。控制 endpoint/lease 也必须保持可信；不宣称抵御同一用户替换整个控制面命名空间或读取受信进程内存/私有句柄。这里必须关闭的是：普通公钥缓存变化可以直接改变运行中验证器信任根。将缓存挪到另一个同样可替换的文件，或用 API 已知主密钥包装它，均不能完成此目标。

## 已实现与尚未关闭的位置

- Core 的 `verify_signature` 已从进程内固定的 authority 验证；`authority.json` 只保留审计/缓存，不能登记或替换根。
- Host 使用实际内存固定公钥验证；删除、改写发现文件不会替换既有验证器。新 child/fork 保留经过验证的父级内存 pin。
- Core 的受限登记通过同连接短帧提交真实密码，独立解密精确实例配置；普通 runtime API master 不等于管理员签名 seed。发送密码前校验真实 OS peer 与受控 Serve lease，peer 同 SHA 单独不构成管理员权限。
- `config_tui.rs` 密码保存路径仍缺 old-root 签署的连续轮换链。当前拒绝未证明的替换，不能以缓存文件补根。轮换必须先持久化可恢复候选、原子提交新配置，再随新根签署的新鲜具体操作推进 Host，不能只收到候选证书就提前换根。
- 已接受消费/完成操作仍依赖原 Core 的可信内存；冷启动不能从 ledger 自报公钥恢复权限。持有委托操作私钥的真实 manager、签名接受/完成证明和 true-child Core 内存交接属于未完成的第二期。

## 建议的共享类型

以下为接口形状，不是实现代码。所有签名使用不同的明确域，字节编码必须固定。

```rust
struct ApprovalPublicState {
    instance_id: String,
    epoch: u64,
    config_generation: [u8; 16],
    public_key: [u8; 32],
    predecessor_digest: Option<[u8; 32]>,
}

enum ApprovalTrust {
    Unenrolled,
    Enrolled(ApprovalPublicState),
}

struct EnrollmentChallenge {
    instance_id: String,
    nonce: [u8; 32],
    expires_at_ms: u64,
    config_generation: [u8; 16],
    config_snapshot_digest: [u8; 32],
    cli_pid: u32,
    cli_birth: u64,
}

struct RotationRecord {
    instance_id: String,
    epoch: u64,
    previous_public_key: [u8; 32],
    next_public_key: [u8; 32],
    previous_config_generation: [u8; 16],
    next_config_generation: [u8; 16],
    previous_record_digest: [u8; 32],
    previous_signature: Vec<u8>,
    next_signature: Vec<u8>,
}
```

`previous_signature` 由旧密码导出的旧私钥签署，提供存活 Host 所需的正向信任。建议同时要求新私钥的 `next_signature`：密码轮换后冷启动只登记当前公钥时，可以验证旧批准所属的前驱关系；不能把一个没有当前公钥确认的任意前驱当成历史权威。历史关系的证明也不等于证明某个操作曾经被接受。

## 首次管理员登记

第一期采用独立密码验证。原草案中“CLI 只签候选公钥 challenge，Core 按 peer 映像身份接受”的方案已弃用。进程可委托预先打开的连接句柄；peer PID 和映像摘要不能单独证明写入由真实 CLI 代码发起。同连接 nonce 也不能消除句柄委托。因此候选公钥签名不再是首次登记权限。

1. `approve` 验证用户密码和待审批请求，取得同一次人工确认。
2. CLI 与真实 Core 建立 OS 认证连接，核对实际 PID、birth、映像和 owner，并要求与该配置实例的受控 Serve lease 完整一致。控制 endpoint、lease 命名空间和受信程序属于明确的 TCB；SHA 单独不证明服务角色。lease 只发布实际 incarnation，不发布或登记公钥。Core 固定 challenge 对应的实例、配置代次、完整加密配置摘要、CLI incarnation、短时 nonce。
3. CLI 在发送密码前再次核对本地绝对配置实例、代次、摘要、自己的 incarnation 和实际 Core incarnation/映像。相同配置字节不能替代实例绑定。
4. 发送密码使用独立原始帧：64 字节 nonce 和最多 16 KiB 密码。发送缓冲、接收缓冲、字段复制均由 `Zeroizing` 管理；密码不经过普通 JSON/Debug/ControlRequest。握手有 60 秒上限；挑战无论验证成功或失败均单次使用。
5. Core 自己用该密码解密 challenge 对应的配置，独立派生密码域公钥；不接受 caller 任意指定的公钥。若与固定 expectedRoot 或现有 root 不同，则要求有效轮换链，第一期明确拒绝。
6. 真实审批继续签署精确请求，不增加一次密码输入或人工确认。API-only 冷启动和读取普通 authority/ledger 文件均不登记。

私有 IPC 中的瞬时密码是本次明确采用的内部认证选择。Core 是现有 TCB；API key 和配置运行主密钥不能代替这个独立密码验证。首次根不会仅因客户端自报 hash、PID、候选公钥或任意同名程序而建立。

## 配置中的 expectedRoot

新配置在持有真实管理员密码的保存路径生成独立密码域 Ed25519 公钥，存入加密容器现有、受 AEAD AAD 认证的 32 字节头部槽。该槽此前在 encrypted 容器中全为零。密码 seed 不写入配置或运行 envelope。

运行 API key 只解锁既有配置快照。runtime-only 保存保留已认证的同代次公钥，不派生或选择新的密码根。Serve 只在启动加载 TCB 配置时固定 expectedRoot；它与 Enrolled 是两个状态。读取 authority.json、ledger 或后续发现文件不能替换它。

## Host 固定根与普通 run

外部 attach 必须在管理员登记完成后创建 Bootstrap，其审批根不可为空。Host 的初始化与后续命令只接受这个根及其有效轮换链。

新配置的 API-only `run` 使用启动时固定的 expectedRoot 初始化 Host，即使 Core 尚未 Enrolled，也不增加密码输入。Host 具有可独立验证的密码公钥；Core 完全冷启动后，真实 approve 登记相同公钥即可产生可验证的新授权，无需重启目标。

旧配置可能没有 expectedRoot。普通 run 仍然可启动，起始 Host 根为空，但不能在收到首次 proof 时读取文件认根。第一期仅允许通过原始 Core 的已固定内存 attestation 公钥登记：Host 发出一次随机 challenge，原始 Core 在真实密码登记后签署 instance、attachment、原 root、Host PID/birth、challenge 和内存管理员根；Host 只接受精确原始 Core incarnation 与签名。子进程只能继承实际内存中已有的根。

旧配置从未有锚、空根 Host 的原始 Core 又完全死亡时，第一期明确不支持登记；不会从文件补根，也不会要求普通 run 新增密码。这是遗留兼容缺口，不是新配置路径的通过结论。新 CLI 版本、原始 Core attestation 连续交接及旧根签署的密码轮换仍需第二期验证。

## 密码轮换状态

| 当前状态 | 输入 | 结果 |
| --- | --- | --- |
| Unenrolled | API-only 启动或普通 verifier 文件 | 保持 Unenrolled |
| Unenrolled | 经受限真实密码审批验证的登记 | Enrolled(epoch 0/current generation) |
| Enrolled | 同一根的重复登记 | 幂等，不改变 epoch |
| Enrolled | 不同根但无有效前驱签名 | 拒绝，保留旧根 |
| Enrolled | 连续 epoch、精确实例/代次且前驱签名有效的轮换 | 固定新 epoch，不允许回退 |
| Enrolled | 同 epoch 不同公钥或重复 config generation | 拒绝 |
| 任意状态 | 过期/错误 peer/challenge 已消费 | 拒绝，不修改信任状态 |

密码变更期间，先构造并持久化经验证的轮换候选，再原子提交新配置代次。失败保存必须保留旧代次的可用信任路径。存活 Host 只在完整链验证通过后推进；缺链应保持旧根并报告原因，不能静默换根或中断业务连接。

旧密码不可用时不能制造一条看似连续的轮换链。显式重置属于新的信任建立，需要明确实例/Host 兼容语义，不能自动授权旧 Host 的变更。

## API-only 重启

- **正常自动重启**：已有 Serve 内存固定根时，旧 Serve 自己创建替换进程，通过匿名内存交接传递根状态、已接受操作状态及证明身份的连续性。绑定自己真正创建的新 PID/birth 和一次性 nonce；Windows PPID 字段单独不够。新进程需与仍存活的旧 Serve 进行实际 OS peer 认证，不能只信管道里自报的根。
- **完全冷启动**：没有存活可信交接源时保持 Unenrolled，仍提供现有策略服务与普通 run。实际管理员 approve 才能建立当前审批根。不得从 authority、ledger、Execution 或发现文件自动补根。
- **已有 Host**：继续缓存策略。已固定用户根的 Host 可验证后续管理员签名及轮换链；只有空根的旧 Host 则需要上述受限首次登记通路。这个兼容性成本必须显式报告。

## 消费记录、完成续办与恢复

当前 consumed ledger 保存当时公钥，有助于操作续办，但其文件内容不能独立证明“这个公钥已被信任且操作已接受”。最终方案必须关联 Serve 内存中的已接受操作记录，或关联由当时已可信证明身份认证的消费/完成记录。

- 新操作只按当前内存 epoch 验证；旧 epoch 不得新消费。
- 历史续办只允许精确已经接受的 nonce、用途、目标、实例、session、manager incarnation；不因历史公钥关系就允许新操作。
- 历史文件被修改、缺失或无法验证时，不能以 API token 兜底。
- fresh cleanup recovery 仍需新的当前管理员批准；历史 completion 只能证明旧 session 已退役，不能创建/复活 membership 或激活 Host。

## 第二期委托操作证明：独立模块检查点

`hyperhub-runtime::attachment::operation` 与 Core `attachments::operation` 已增加独立协议模块，尚未编译执行本轮新增测试，也尚未接入 CLI/Host。manager key 只存在内存、无 Clone/Serialize/secret getter，每次签署核对创建 PID/birth，scope 另绑定随机 role epoch。Core challenge registry 有明确容量、短 TTL、单次移除和管理员 proof digest 去重；验错也销毁该 challenge。accepted certificate 使用独立 domain，严格 canonical 解码及精确 scope 比较，拒绝弱公钥、超帧、未知字段、错实例/Host binding/session/token hash/root image/exec epoch/claimant/key。历史接受证据可在原持有证明窗口结束后验证，仍不能单独授权新生命周期命令。

本检查点没有改变既有 Authorization/Execution 或 Host 命令必填项。模块入口要求调用方先从真实验证过的管理员证明导出完整 expected scope；当前 grant 尚未签 claimant，creator-pipe 签署顺序与后续 Host command challenge 也未接入。因此不能宣称 bearer proof 重用问题已端到端关闭。新增 Runtime 四项和 Core 五项单元覆盖仍等待主 agent 执行。

### Creator 与消费接线源码检查点（待编译执行）

R15 后的局部源码现已接入等待 helper 的 creator-only stdin/stdout 管道：子进程在读取 Execution、运行凭证或目标之前完成 Begin/Hello/Commit；CLI 对真正创建的 PID/birth/映像和公开 claimant 做核对，然后将实际 claimant 签入 Authorization（及其加密 Execution）。resident/owned 操作从实际 OS-peer 绑定的现有 manager relay 查询公钥，不能从文件取代。

Core BeginAttachmentConsumption 校验真实 caller、完整管理员签名、当前 Core 背书、记录中的不可变 Host binding、Bootstrap 和当前执行代次；Consume 再验证新鲜持有证明，在同一个 RootImage 检查与 nonce 消费临界区内接受。返回的 accepted certificate 由 manager 验证并保留在 RAM。证书不落入 Execution/env/recovery。失败的未提交 fresh helper 清理为 Failed；已有 recovery 残留保留真实状态和原 owner。已提交 helper 使用真实 Child handle 监测启动退出，不能仅根据可写记录推测 helper 已准备好。

新增测试源码为一个真实私有 Core IPC 回归、三个 CLI bootstrap 单元、两个实际 CLI EOF/超帧取消回归。它们本轮尚未执行，后续需 native/Windows GNU 编译和真实审批 attach/reattach/detach 对照。这里只接通 manager 与 Core 的消费证明；Host 仍未要求 accepted certificate 和独立一次性 command challenge，不能宣称 bearer Admin proof 重用已端到端关闭。

### Host 命令边界（尚未实现）

Admin grant 需要签署实际 manager 的 PID、birth 和只存在于该 manager 内存的临时公钥。Fresh attach 先创建等待中的真实 helper，经匿名管道取得其公钥，确认它的实际 incarnation 后才签 grant 并发送执行信号；等待 helper 不得注入或消费权限。既有 run/resident manager 通过 OS-peer 绑定的只读 relay 返回现有公钥。API-only 普通 owned 启动仍不增加密码，但日后生命周期操作使用同一管理员证明流程。key owner 记录创建时 PID，fork 后的 child 不得使用继承的私钥签署 manager 操作。

Core 的一次性 consume challenge 绑定完整 Admin proof digest、实例、attachment/session、实际 claimant PID/birth、公钥和短时 nonce。manager 先证明持有该私钥，Core 才能执行 nonce 消费和任何目标变更；不能先消费再要求 completion 私钥。Core 返回的 accepted-operation certificate 绑定同一 Admin proof digest、token hash、Host binding、effective root image/exec_epoch、claimant、公钥及 nonce，并由 Admin grant 精确背书的当前 Core key 签署。文件可以保存这个签名材料，不能保存委托私钥或用自报公钥建立 verifier。

Host 的新生命周期命令同时需要原 Admin proof、该 accepted certificate，以及 manager 对 Host 新 challenge 的委托签名。签名字节包括独立 domain、certificate digest、确切命令、attachment/session/Host binding、实际 Host PID/birth、challenge、expected root image/exec_epoch。challenge 一次性；同一已完成命令的 ACK 可以幂等返回，不能授权另一个命令或代次。只收到密码签名、可解密 Execution token 或 Core certificate 均不单独授权目标变更。精确已接受的 Detach/Retire 续办保留原证据，不因十分钟窗口结束而变成新操作。

本切片需要直接负例：其他 claimant、API-only 启动的同映像 helper、缺私钥、签名换命令/Host/代次、重用 challenge、fork 后签名、篡改 accepted certificate，以及丢 ACK 后相同操作重试。密码轮换链、真正 Core 子进程交接及大历史恢复另行验证；不能由本节的接口设计计为已实现或已执行。

## 兼容与验证清单

本开发版尚未发布，推荐更新 Bootstrap/生命周期协议和 NativeBase 身份；缺少固定根能力的旧基座明确拒绝本协议，不做不安全兼容分支。既有 public CLI 的 attach/detach/approve 语法可以保留，status 新增 `approval_trust`、epoch 和需要登记的原因；不显示密码、私钥或 challenge secret。

必须分别记录以下验证。第一期已有下述专项执行证据；尚未闭合的链、交接和平台组合保留 planned，不能由一个专项结果替代整项验证：

1. Core 与 Host 登记后，普通公钥文件变化不能改变固定根。
2. API-only 冷启动不登记根，但正常启动、策略服务和普通 run 可用。
3. 首个真正管理员 approve 一次完成登记与原请求；错误密码、错误 peer、旧 challenge、重复 challenge 均拒绝。
4. 新 run 的空根 Host 在登记前拒绝生命周期变更；受限登记通路成功后可正常 detach/reactivate。
5. 单次及连续密码轮换；丢链、乱序、跨实例、重复 epoch、回退和失败保存。
6. 自动重启的真实父子交接、Windows parent-field 不等于真正创建关系、旧交接源死亡与完全冷启动。
7. 已接受 detach 跨轮换与丢 ACK 续办；未接受 nonce、修改历史记录、不同 manager 或 session 不得续办。
8. Root 非空/为空的 Host 分别覆盖 Native Windows、MSYS/Cygwin fork、Linux ptrace 和 Linux Gum；不以普通 native exec 样例替代 fork 重建。

第一期代码已加入进程内根、真实密码私有握手、配置 expectedRoot、原始 Core 的 Host 登记证书和内存 accepted-operation 约束。r10 私有登记同连接两项、受控 lease 和签名 Core-key 字段专项已实际通过；r13 Core lib 367 项与 Runtime lib 17 项通过，包含固定根与可信 RootImage 内存边界。完整 workspace 仍失败，后续修改需重新验证。连续密码轮换链、可信历史持久化与升级/重启交接仍是第二期缺口；不能由本文宣称全部修复。


## 当前映像与执行代次

同一 PID、birth 甚至同一 executable hash 的 exec 都是新的受管执行代次。新的 `Spec.current_target` 与 `Spec.exec_epoch`、Detach 的 `target/exec_epoch` 都进入管理员签名；最初 `Spec.target` 与 Bootstrap 绑定保持不变。实际 manager 在 OS exec startup gate 中报告 nonce，Core 从可信内存推进 RootImage epoch；同 nonce 重试幂等，同映像第二次 exec 仍推进。普通 record.json 的 epoch 不是验证器来源。

Fresh/rebuilt SDK 使用自己生成的 nonce，取得绑定真实 Host PID/birth 的当前 RootImage 快照；接收现有广播与延迟旧快照时，不回滚，而是重新 challenge。已有 descendant 保存经固定/已认可 Core key 签署的 root 映像与代次，因此原 root 退出后仍能核对后续审批，不把 survivor 改写成最初 root。

Core 的两项最初 RootImage 单元测试已执行通过：同映像两次/变映像、nonce 重试、同或后退时钟，以及普通 record 不能设置可信内存。后续增加的 retained orphan scope、registry live-member 和 Report-vs-consume 互斥回归已包含在 r13 Core lib 通过结果中。ptrace 实际 PTRACE_EVENT_EXEC 已接入，但各实际 exec 变体、root-dead reattach 和 busy exec/fork 仍需独立源码回归；不能用原有 child exec 或 orphan detach 代替。该互斥不覆盖 kernel exec 发生但尚未 Report 的窗口，也不代替 Host 的委托 accepted-operation 证明。

原始 Core attestation 为 None 的 ordinary run 仍保持既有启动行为。RootSome/原 Core key None 的后续管理员元数据登记仍需第二期具体操作背书通路；RootNone 且原始 Core 已完全死亡的旧 Host 无可验证登记锚，不从文件补根。状态必须如实表示能力不可用，不能因普通 run 成功而宣称所有生命周期操作都已验证。

## 来源与原生 DNS 模式检查点（待本轮测试）

能力分类现按实际来源选择，不能仅凭可写 `record.origin` 判断 owned run。存活 manager 的 profile 来自其进程内不可变 Execution context，通过实际 OS peer 查询，只有 origin/native_dns_mode/session/Host binding 等公开元数据。死 manager 的加密 Bootstrap 仅为候选，须由 Core 可信 RootImage binding 验证；冷 Core 只有记录、没有存活可信来源时保持 unproven，不从文件初始化来源。Core 冷恢复先核对实际 manager 的 RAM profile 再采用 RootImage，避免把记录中的新 mode 当成既有事实。

CLI proposal/approve/执行复核，以及 Core possession/activation/recovery 和配置热更新，均使用相同来源分类。外部 PreserveAnswers 的必要域名目的条件明确拒绝，owned SyntheticPool 保留独立启动契约。配置更新在取得 config_update 锁之前检查并持有 attachment OperationGuard，profile 处理只短持 RAM 锁、不调用 Core；不在持 config_update 时反向等待 manager。新增回归仅检查拒绝前后 RuntimeSnapshot 版本和内存配置不变，以及改写 origin/Bootstrap mode 或仅有冷记录不能建立新来源。

R16 的 rootchallenge 背书修复已通过默认 workspace 与 Gum 专项；cross-producer offline/restart/reattach 两轮实际通过。process-issued 重复场景仍失败，不能用 tree 通过代替；SDK 正在增加私有错误阶段以区分 root snapshot、alias history 和注册。Host delegated command、密码轮换、handoff 和其他未关闭边界保持独立。

## process 接收方小修检查点（待 R18 测试）

Core 不能用面向目标 Host 的 own-PID wrapper 验证 process-scope 背书。原过滤路径在 Core 中调用该 wrapper，因 Core PID 不等于受保护 root PID 而丢弃合法 proof；tree 不触发此条件，解释了 tree 通过而 process 重附加失败的差异。现增加显式接收方纯验证 API，Core 只传已通过真实注册/成员验证的 recipient PID，并核对签名快照的 host_pid；Host 原 API 继续使用自己的实际 PID，不放宽 scope_tree。新增跨平台纯 scope 回归与 Core 同一背书测试的 process/tree 两种模式，含旧 wrapper 拒绝的直接对照。

配置写盘边界仍未关闭：普通 config_cli 当前先保存配置再推送 live update；Core 拒绝内存更新不代表磁盘未变，冷重启与 GetTrust/订阅分发还需要独立门禁与事务。上面的 RuntimeSnapshot 回归不能填充这个缺口。本轮不混入该事务，源码冻结后由主 agent 先验证 process 修复。

### Manager 自查的 listener 等待环（待 R18 复测）

R17 process 场景在 y 后、Host alias 逻辑前出现 EAGAIN11。源码确认：manager 正在自己的单线程 relay 中处理 reattach callback，执行配置校验时又经 proven origin 向自己的 relay 查询 execution_profile，导致读取超时。现只有实际 PID/birth/映像完整核验一致的 self-role 走 RAM；RAM 缺失明确拒绝，不退回 socket、文件或猜测 profile。远程仍核验 OS peer，错误增加身份、RAM、RPC、解码和 binding 阶段前缀。新确定性单元使用不可查询的 endpoint，验证 self 查询仍返回正确 profile、改写 origin 被拒绝、RAM 缺失与错误 birth 不会 fallback。此修复与 process recipient 验证同一小检查点，真实复测未完成，不将 EAGAIN 当成已证实的内存/配额问题。
