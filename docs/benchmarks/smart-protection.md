# Smart Protection Benchmark

## Purpose

The smart-protection matrix supports two paths:

```text
direct:    local prefilter -> redacted full argv -> provider -> allow/deny
hyperhub:  ptrace/Gum process hook -> local prefilter -> control channel -> gateway -> Jev -> process allow/deny -> audit
```

The default backend is a deterministic local Mock Jev server. It requires no API key or
external network. Optional `--backend jev` and `--backend laya` modes are for local
experiments only and are not CI gates.

## Run

```bash
python3 scripts/benchmark-smart-protection.py
```

Output is written to `target/benchmarks/smart-protection/`:

- `cases.jsonl`: one structured record per case;
- `summary.json`: machine-readable status, latency, and gates;
- `report.md`: human-readable matrix report;
- `checks.tsv`: per-case assertions.

The benchmark exits non-zero when a functional, privacy, or default Mock latency gate
fails. Timeout/error cases are included in the functional matrix but excluded from the
healthy-provider latency percentile.

### HyperHub 完整链路 + Jev

完整链路模式不直接读取或传入 Jev Key。Key 必须已经存放在 HyperHub 加密配置中，
并且目标进程规则已绑定一个启用了智能判定和 Jev Provider 的智能防护配置：

```bash
umask 077
printf '%s' 'your-config-password' > /tmp/hyperhub-password

python3 scripts/benchmark-smart-protection.py \
  --backend jev \
  --transport hyperhub \
  --hyperhub-bin ./target/release/hyperhub \
  --password-file /tmp/hyperhub-password \
  --timeout-ms 10000 \
  --output target/benchmarks/smart-protection-hyperhub-jev
```

该模式使用 `tests/fixtures/smart-protection/hyperhub-cases.json`，并通过一个临时的、
无网络副作用的 `curl` 测试替身触发真实 `hyperhub run`。检查项包括：

- ptrace/Gum 进程 Hook 是否命中绑定规则；
- 本地预筛选是否决定查询网关；
- 网关是否产生 `smart_protection_decision` 审计事件；
- Jev deny 是否在进程创建前变成 `EACCES`；
- Jev pass 是否允许测试替身执行；
- 审计输出中是否泄漏命令行测试 Secret。

完整链路模式只接受 `--password-file`，不会把配置密码或 Jev Key写入报告。

## Matrix

The fixture covers safe operations, recoverable writes, sensitive-file exfiltration,
private-key transfer, base64/pipe and archive bypasses, destructive requests, prompt
injection context, command-line secret redaction, local hard-deny, observe mode, provider
malformed/low-confidence/timeout behavior, and a benign archive false-positive case.

The local baseline uses a deterministic score plus hard-deny rules:

- score below 60: no provider query;
- score at least 60: query the provider;
- known managed-secret match or static sandbox deny: local hard deny;
- command-line values are redacted while executable, argument names, ordering, target,
and operation structure are preserved.

## Default gates

- local prefilter P99: `< 1 ms`;
- healthy Mock provider P95: `< 50 ms`;
- no synthetic secret may occur in the provider payload;
- every hard-deny case must block without a provider query;
- every Mock deny case must produce a deny in enforce mode;
- observe mode must record a would-deny result while allowing the action.

## Agent / ptrace 预筛选状态

Sandbox snapshot 可以携带：

```toml
protection = "agent-egress"
prefilter_policy = "network_upload"
```

Gum Agent 与 Linux ptrace supervisor 都会执行本地 score/hard-deny/query 判定，
保留完整参数结构并脱敏敏感值，然后通过控制通道向网关请求智能判断。网关写入
`smart_protection_decision`，deny 会在 `execve`/`execveat` 返回前阻断。默认规则不设置
`protection`，不会改变既有 sandbox 行为。
