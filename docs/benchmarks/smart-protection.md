# Smart Protection Benchmark

## Purpose

The smart-protection matrix evaluates the complete decision boundary before Agent-side
sandbox integration is implemented:

```text
local prefilter -> redacted full argv -> gateway provider -> allow/deny -> privacy/audit checks
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
