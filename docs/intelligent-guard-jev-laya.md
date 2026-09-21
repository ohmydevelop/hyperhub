# Jev / Laya 智能阻断可行性探索

## 结论

HyperHub 可以接入 Jev 风格的智能判定，但应把它设计为**确定性规则之后的附加门禁**，不能替代现有路由、防火墙和沙盒规则。

建议先实现统一的异步 `System One` 判定接口，提供两个可替换后端：

1. **远程 Jev**：直接调用 TypeSafe 或 OpenRouter 的 System One 接口，适合低本地资源占用和较低延迟的场景。
2. **本地 Laya sidecar**：由独立 Python 进程加载模型，HyperHub 只通过回环 HTTP/Unix socket/命名管道调用；不要把 Python、PyTorch 或模型权重嵌入 HyperHub 单文件。

Laya 的协议形状与 JevShield 使用的 `choice`、`noul`、`score` 三原语兼容，但当前公开 checkpoint 不足以直接作为生产阻断器。在本机 CPU 实测中，单次判定约 2.0–4.4 秒、进程峰值常驻约 2.86 GiB，并且漏判了合成的凭证外泄请求。现阶段 Laya 适合离线评估或 `observe` 影子模式；要进入 `enforce`，至少需要领域数据微调、校准、对抗集和 GPU/专用推理服务。

## 调研基线

调研基于 2026-09-20 获取的源码：

- JevShield `b669def84f0d7b71a8165ad1888d7fb9daf1a4ac`，包版本 `0.1.1`，Apache-2.0。
- Laya `d113dca2512fb3eaca313534bc54c7162d87c1d4`，包版本 `0.3.4`，Apache-2.0。
- HyperHub `fef61d1`，分支 `feat/jev-laya-guard`。

JevShield 的核心做法值得复用：

- 把待评估内容声明为“不可信数据而非指令”，降低 state 内提示注入的影响。
- 一次请求同时回答风险等级、不可逆概率和影响面三个问题。
- 未知等级、缺字段和畸形数值按最危险结果处理。
- 默认阻断矩阵：

  ```text
  (risk >= critical_danger && P(destructive) > 0.75)
  ||
  (blast_radius >= 3 && P(destructive) > 0.5)
  ```

JevShield 自带的无密钥 fallback 只是关键词启发式，只适合作为开发降级，不应标记成模型智能判定。它当前针对 Python 工具调用，而 HyperHub 需要把输入改造成网络连接/HTTP 请求上下文。

Laya 可以直接返回同名的 `answers` 映射，字段包含：

- `risk_level.choice`
- `is_destructive.noul`
- `blast_radius.score`
- 每个答案的 `confidence` 和概率分布

因此远程 Jev 与本地 Laya 可以共用请求、响应、策略解析和审计结构，不需要在 HyperHub 热路径中维护两套判定语义。

## HyperHub 接入位置

当前 `PolicySnapshot::decide` 是同步确定性决策，并被 SOCKS/协议栈多个路径调用；HTTP 在拿到请求路径后还会执行 `decide_http` 二次细化。现有插件运行时主要承载审计与凭证注入，钩子没有异步返回阻断结果的能力。

不建议把模型调用直接塞进 `PolicySnapshot`：

- 远程或本地模型调用是异步、高延迟、可失败的 I/O。
- `PolicySnapshot` 应继续保持纯内存、确定性和可快速热更新。
- 同一连接可能经历 DNS、connect、TLS、HTTP 等多个阶段，需要显式规定在哪一层判定和去重。

推荐的数据面顺序：

```text
确定性 firewall / sandbox
  -> route 决策
  -> 智能 guard（仅对显式绑定 guard 的 allow 请求运行）
  -> 凭证注入
  -> 上游连接或请求发送
  -> 审计
```

确定性 `deny` 永远优先，模型只能把原本允许的动作升级为拒绝，不能反向覆盖静态拒绝。

### 分阶段判定

- `connect`：适用于未知 TCP、TLS、SSH、Git，只能看到进程、主机/IP、端口和协议，语义较弱。默认只观察，不建议直接阻断。
- `http_request`：拿到 method、authority、规范化 path 后执行，最适合第一期 enforce。
- WebSocket message、SSH command、Git 操作语义需要更高层解析，后续单独增加，不应把整段原始流量直接发送给模型。

## 推荐配置模型

智能 guard 应成为独立配置对象，而不是继续扩张当前以凭证/审计字段为主的 `PluginConfig`：

```toml
[[guards]]
id = "jev-risk-gate"
provider = "system_one"
endpoint = "https://api.typesafe.ai/v1/systemone"
model = "jev-latest"
credential = "jev-api-key"
stages = ["http_request"]
mode = "observe"       # observe | enforce
timeout_ms = 500
error_action = "pass"  # pass | deny
min_confidence = 0.60
cache_ttl_ms = 30000

[[routes]]
id = "production-api"
guards = ["jev-risk-gate"]
```

本地 Laya 使用同一配置结构，只把 endpoint 指向回环 sidecar。密钥必须复用 HyperHub 加密凭证对象，不进入环境变量、审计或模型 state。

第一期默认值应偏向安全上线而不是“模型故障即断网”：

- 新 guard 默认 `mode = observe`。
- 只有用户显式切换到 `enforce` 才影响流量。
- `error_action` 可配置；通用路由建议 `pass` 并记录高优先级审计，极敏感路由可显式选 `deny`。
- 低置信度在无交互 Serve 中不能弹确认框；`observe` 时记录，`enforce` 时按独立 `low_confidence_action` 处理。

## 模型输入与隐私边界

远程 Jev 会把 state 发送到第三方，因此默认只允许下列脱敏字段：

- 判定阶段、route/rule ID；
- 进程 basename，不发送完整命令行和用户目录；
- 协议、method、hostname、port；
- 规范化 path，query 默认只保留参数名，不保留值；
- `credential_present`、`body_present`、字节数等布尔值/元数据；
- 可选的、本地生成的语义标签。

默认禁止发送：

- Authorization、Cookie、API key、SSH key；
- query 值；
- 请求/响应正文；
- 环境变量；
- 完整本地路径和命令行。

模型输入必须带固定的角色界定，所有网络字段都视为不可信数据，不能成为修改判定准则的指令。审计只记录 provider、模型、延迟、结果、置信度、fallback/error 和输入摘要哈希，不记录原始敏感 state。

## 本地 Laya 实测

测试环境：Linux x86_64、5 vCPU、15 GiB 内存、无 GPU、Python 3.14.4、PyTorch `2.14.0+cpu`、Laya `0.3.4`、`convaiinnovations/laya-typed-decisions`。

模型文件约 807 MiB。首次下载并加载耗时 96.151 秒；加载后的 Python 进程峰值 RSS 约 2858.8 MiB。5 个合成案例、每个 3 次推理，共 15 个样本：

| 案例 | 中位延迟 | JevShield 矩阵结果 |
| --- | ---: | --- |
| 安全 GET | 2289.93 ms | pass |
| Git push | 2225.17 ms | pass |
| 强制删除生产数据库 | 4086.04 ms | block |
| 向攻击者域名上传凭证 | 2345.26 ms | **pass（漏判）** |
| 危险请求字段内提示注入 | 2711.93 ms | block |

全部样本中位延迟 2466.29 ms，平均 2701.42 ms。所有 `risk_level` confidence 都很低（约 0.02–0.11），说明公开 checkpoint 与该网络阻断任务不匹配，不能仅靠调阈值修复。

可复现实验：

```bash
python -m venv .venv
# Linux CPU 可先按 PyTorch 官方方式安装 CPU wheel，再安装 Laya。
.venv/bin/pip install laya
.venv/bin/python scripts/benchmark-smart-guard-laya.py \
  --model convaiinnovations/laya-typed-decisions \
  --device cpu \
  --runs 3
```

Windows 使用 `.venv\Scripts\python.exe` 和 `.venv\Scripts\pip.exe`。脚本只使用合成、已脱敏案例，输出 JSON Lines，支持 `--case`、`--threads`、`--output` 和本地 checkpoint 路径。

Laya 项目公布的几十毫秒数据来自 T4 GPU；不能把 GPU 指标套用到 HyperHub 常见的 CPU-only 本机环境。若继续推进本地方案，应优先验证：

1. CUDA/Metal/DirectML 可用设备上的 p50/p95 与冷启动。
2. INT8/ONNX Runtime 或更小模型是否能把 RSS 压到 1 GiB 以下。
3. 针对 HyperHub 请求上下文微调后的漏判率、误杀率和校准误差。
4. sidecar 崩溃、升级、模型下载、离线安装和跨平台生命周期。

## 分阶段落地建议

### Phase 0：协议与离线评估

- 固化 provider-neutral 请求/响应结构和 JevShield 策略矩阵。
- 用历史脱敏审计生成标注集，先测规则基线、Jev 和 Laya，不接数据面。
- 指标至少包括危险动作召回率、正常流量误杀率、p50/p95、fallback 率和置信度校准。

### Phase 1：Jev observe

- 新增异步 guard manager、超时、并发上限、熔断、缓存和审计。
- 只在显式绑定 route 的 HTTP request 阶段调用。
- 默认 observe，线上收集判定而不改变结果。

### Phase 2：小范围 enforce

- 只对已标注、可恢复的少量 route 开启。
- 静态规则仍是第一道门；模型只做追加 deny。
- 建立 provider 不可用、超时、低置信度和格式错误的回归测试。

### Phase 3：本地 Laya 可选后端

只有在领域微调后达到门槛，且目标设备资源/延迟可接受时再提供。建议由 HyperHub 管理独立 sidecar 生命周期，保持主二进制轻量和故障隔离。

## 当前判断

- **Jev：可行，建议先做 provider-neutral 的远程 observe PoC。** 最大风险是第三方数据边界、网络依赖和服务故障策略。
- **Laya：协议兼容，但公开模型直接用于本地实时阻断目前不可行。** CPU 延迟、内存和漏判均不达标；可保留为本地 sidecar 研究后端，不进入默认发行物。
- **HyperHub：接入点清晰，但需要异步 guard 层，不能直接改同步 `PolicySnapshot` 或复用现有审计/凭证钩子假装完成阻断。**

## 实现状态（2026-09-20）

首期实现已将本地数据保护与智能判定合并为可复用的 `ProtectionProfile`。普通路由与默认路由均可绑定防护，默认关闭；运行时先执行本地秘密与来源扫描，再把脱敏 findings 交给 System One Provider。远程 Provider 不接收正文、凭证、Header 值或 Query 值。本地 Laya 仍通过自定义回环 endpoint 接入，HyperHub 不负责其模型和进程生命周期。
