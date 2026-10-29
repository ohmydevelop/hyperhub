# 缓存地址解除接管：本地 SDK 兼容设计草案

状态：只读设计，未据本文实施协议或操作真实目标。当前选择是复用目标自身的原始 resolver/connect，不新增 Core DNS RPC。审批信任边界尚待用户确认；本地兼容不能代替可靠的生命周期授权。

## 现有代理不能作为解除接管后的兜底

`SocksService::handle_authenticated` 恢复名称后仍执行 firewall、routing、credential 和 MITM。`IngressTransport::Raw` 不表示跳过这些策略。Detached 后的新连接若继续走旧 Socks，仍可能被刚更新的 deny 或凭证规则影响，不符合“停止新的策略接管”。

旧的已建立代理连接可以继续保留必要兼容。新的 native 连接应使用目标本来的解析和网络环境。

## 必须区分来源

| 来源 | 记录条件 | 解除后行为 |
| --- | --- | --- |
| ObservedExternal | 原始 DNS/getaddrinfo 观测到的地址 | 原地址交给原始 native connect，不再走 HyperHub policy/gateway |
| Issued | SDK 成功调用 HyperHub allocator 并把自产地址交给应用 | 从 SDK 私有发行映射取原 hostname，调用目标原始 resolver，再调用原始 connect |
| Unknown | 仅位于某个保留地址段，找不到可靠发行记录 | 不能猜 hostname 或把它当作 HyperHub 自产地址 |
| Ambiguous | 同一地址出现不一致的名称身份 | 不得静默选择一个名称；需要明确拒绝或在暴露冲突地址前解决 |

不能仅凭 `198.18/15` 或 IPv6 前缀识别 Issued。Linux ptrace 与 Unix getaddrinfo 目前主要记录原响应，并不因此成为发行者。Clash/TUN 原生路由是否可达，必须与未接管的同环境基线一致；原生本就失败的地址不能要求 HyperHub 改写成成功。

## 建议的 SDK 状态接口

以下只是接口形状；具体模块命名随现有网络状态结构确定。

```rust
enum AliasOrigin { Issued, ObservedExternal, Ambiguous }

struct AliasIdentity {
    address: IpAddr,
    hostname: String,
    origin: AliasOrigin,
    issuance_epoch: u64,
}

fn record_issued_resolution(hostname, address, issuance_epoch) -> Result;
fn record_observed_resolution(hostname, address) -> Result;
fn classify_cached_address(address) -> Option<AliasIdentity>;
```

`record_issued_resolution` 只在真实 allocator 成功后调用。普通 `record_dns` 不能把 Issued 降为 ObservedExternal，也不能用另一个名称覆盖它。

仅“拒绝覆盖旧名称”还不够：如果应用已经收到与旧 Issued 地址相同、却属于另一名称的外部地址，下一次只有 sockaddr 的 connect 无法识别应用的原意。实现必须在地址暴露前避免冲突，或把歧义明确保留为不可透明处理的错误；不能静默连接旧名称。

## 连接状态转换

1. 回调在进入时取得当前 lifecycle epoch 和调用 guard。
2. Active 继续使用现有策略路径。
3. Detached/compatibility 状态遇到 ObservedExternal 或普通地址，直接调用原始 native connect。
4. 遇到 Issued，从私有发行映射取得原名称，在目标本来 namespace/环境中调用未被 HyperHub 包装的原始 resolver。
5. 使用 resolver 给出的原生地址调用原始 connect。原始 resolver 若返回 foreign FAKE-IP/TUN 地址，仍按原生结果处理，不去猜一个所谓真实公网 IP。
6. reattach 后的新回调使用新策略；已经在旧代次开始的调用按既定准入完成，不能在中途被误送回旧 Socks。

不增加后台隐式重试、额外 TCP 连接或流量复制。辅助 resolver 调用结束后，应恢复 connect 进入前的 errno/WSA/LastError，然后由原始 connect 决定最终错误。保持 family、端口、IPv6 scope、长度、非阻塞/EINPROGRESS 与调用者 sockaddr 缓冲区。

老代理 socket 的 peer/flags 兼容仍需保留到资源排空；新建 native socket 不应被旧 metadata 或 firewall snapshot 重新接管。比较 getpeer/错误值时以同类原生调用为准，不硬编码“peer 必须是公网 IP”。

## 缓存生命周期

应用可能在 DNS TTL 结束后继续持有自产 alias。连接数归零也不能证明应用已丢弃它。Issued 身份不得被重分配，必要组件可驻留至进程退出或有独立充分的失效证明。

单纯缓存 ObservedExternal 不是无限驻留的理由；原生网络本来可以解释它时，不需要 HyperHub 为新连接继续服务。Core/Serve 离线也不应阻断这种本地兼容。

地址池耗尽不能通过复用仍可能被缓存的 Issued 地址解决。来源冲突、未知映射与无法安全解析必须如实报告，不能假装完全卸载或连接成功。

## 必需测试与当前缺口

1. ObservedExternal：先运行同环境原生基线，再 Active/Detach，使用同一缓存 sockaddr；解除后结果、错误、peer 和 flags 与基线一致。
2. Issued：通过真实 HyperHub SDK allocator 缓存一次，Active 热更新 deny 后新连被拒；批准 Detach 后按原 hostname 的原生解析/连接成功，旧长连接始终传输正确。
3. Serve 离线：解除后的本地 Issued 解析和 ObservedExternal native 连接不依赖旧网关。
4. reattach：第一条新调用使用新策略，旧回调按原准入完成，旧授权不得把新 Active 调用变成兼容调用。
5. 两名称同地址、TTL 到期、多个 detach 代次、发行池耗尽：不覆盖身份、不静默误连、不复用仍被缓存地址。
6. IPv4/IPv6、scope、非阻塞、原始缓冲区、errno/LastError、旧代理 socket 与新 native socket 分别断言。
7. fork/MSYS/Cygwin 重建复制正确的来源、映射、epoch 与已接受的 detach 状态；native exec 不替代此边界。

旧 Linux fixture 在没有 native route 的情况下要求一个外部 FAKE 地址解除后必定成功，这个 oracle 无效。保留原始诊断失败，但不能据此宣称产品故障或已修复。两个来源需要分开的源码场景；尚未核对稳定触发/断言的部分保持 planned。

## 未选择的 Core DNS 方案

此前评估过由已接受 Detach 登记冻结 alias 集合，再通过 Core 返回真实 IP。它增加授权、持久化、命名空间与 Serve 离线依赖，还可能改变目标的原生 resolver/TUN 语义。因此不作为当前最小方案，也未实施；不能以旧 Socks 代理代替它来让 fixture 通过。
