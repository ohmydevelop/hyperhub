# Worker component model freeze

Model digest: `6ec4c18b1e24d970e0d92e61c788a834d5d2e4a79205f630c2c210ad7df4dfe9`

Initial freeze: 2026-10-22. Repository base HEAD:
`31b6caf96ffebc4f75cf3c318e3ade29504ec36f`; the model identifies the actual working
source snapshot by file content hashes. The snapshot includes production worker,
private IPC, cancellation ownership, resident session/config/audit/runtime and
hidden CLI entry dependencies, plus Cargo build configuration.

Review type is self-review by the worker component author. The parent agent
reviewed control-loss cancellation and required explicit shared socket markers
that preserve queued data and legal TCP half-closes. This contribution does not
constitute independent review of the entire performance model.

The model binds five obligations and nine explicit flow sub-boundaries, alongside
all sixteen fault-catalog applicability decisions. The accepted API budgets are
prepare within30000ms and commit within100ms for the declared local workload.
Five process-group trials per state are a bounded development sample budget;
request observations within a trial are correlated.

Before this freeze, implementation review corrected detached WebSocket lifetime,
whole-phase send deadlines, per-offer timer thread growth, failed-candidate cache
ownership, and control-loss cancellation/reclamation. Draft model sources were
updated as those actual production changes completed. Earlier pilot data informs
the protocol and remains pilot evidence; final measurements use this frozen
snapshot and the final immutable0.2.13 CLI.

After this freeze, a bound source or requirement change requires explicit review,
a documented change record, a new model digest and matching plan. Regeneration
cannot remove required states, obligations or sub-boundaries to hide a gap. The
runner checks hashes and never edits the model or acceptance baseline.

Coverage amendment before formal execution, 2026-10-22: dependency review added
the complete Core, Runtime, Engine, Agent and CLI Rust source/build manifests and
shared NativeBase build support. These inputs affect native preflight, embedded
artifact compatibility, or the actual worker business path; fingerprints include
platform branches conservatively. Initial digest was `f89519493f221e842a16a425ce5a0da8f38fb22972849840ae16fa127234dd14`.
No existing source had drifted. Five obligations, nine flow boundaries, all
fault decisions, four workload states, sample budgets and acceptance limits are
unchanged. This is an explicit dependency-coverage correction, not a change to
the measured denominator. Formal execution starts only after this revised freeze.

Functional correction and coverage extension before the next formal run,
2026-10-22: fork/exec enrollment, retained-socket connection identity and native
exit attribution required reviewed Core, Agent or CLI corrections. Worker
review also fixed real descriptor-exhaustion completion marking and
ungranted claim cleanup after control loss. Both worker regressions failed
before the fixes and passed afterward. The model retains all five obligations,
original nine boundaries and four measured states, and adds two explicit fault
boundaries. The runner now executes forwarding unit regressions before the
12 native integration cases. The Unix-only exhaustion trigger is explicitly
not observed on Windows; no successful test suite substitutes for that trigger.
The existing transfer case now also rejects a duplicate live identity across
worker generations before any CONNECT payload. The 30s/100ms limits, work
accounting and five-group sample budget are unchanged.
Prior digest `d1d99010dc5151aeee4015c328b487a8976c61bc5e92b9175595ab63cdd42168` and its reports remain historical evidence only.
Bound source changes reviewed for this new snapshot:
- `benchmarks/forward-workers/CONTRACT.md`
- `crates/hyperhub-agent-core/src/gateway/network.rs`
- `crates/hyperhub-agent-core/src/lib.rs`
- `crates/hyperhub-agent-core/src/runtime.rs`
- `crates/hyperhub-cli/src/platform/linux/engine_control.rs`
- `crates/hyperhub-cli/src/platform/linux/launcher.rs`
- `crates/hyperhub-cli/src/platform/linux/syscall_supervisor.rs`
- `crates/hyperhub-core/src/control.rs`
- `crates/hyperhub-core/src/engine_host_control_tests.rs`
- `crates/hyperhub-core/src/engine_host_exit.rs`
- `crates/hyperhub-core/src/engine_hosts.rs`
- `crates/hyperhub-core/src/engine_hosts_tests.rs`
- `crates/hyperhub-core/src/forward/manager/resident.rs`
- `crates/hyperhub-core/src/forward/worker.rs`
- `crates/hyperhub-core/src/upgrade/admission.rs`
- `crates/hyperhub-core/src/upgrade/admission_tests.rs`
- `crates/hyperhub-core/src/upgrade/participant.rs`
- `crates/hyperhub-core/tests/forward_workers.rs`


The r2 implementation gate initially rejected missing entrypoint artifact paths
for the two new unit regression sources. The plan now includes those paths in
each entrypoint. This metadata correction preceded any formal native execution;
model digest, obligations, boundaries and acceptance criteria are unchanged.
The rejected attempt remains under `target/benchmarks/forward-workers/formal-013-r2/`.
