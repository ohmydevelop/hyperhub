# Worker component model freeze

Model digest: `df0e0ab65eb5288b2bc0c9f1699367f5eaa9646df5f19fa8e9fc0499c73cfbea`

Initial freeze: 2026-10-22. Repository base HEAD:
`31b6caf96ffebc4f75cf3c318e3ade29504ec36f`; the model identifies the actual working
source snapshot by file content hashes. The snapshot includes production worker,
private IPC, cancellation ownership, resident session/config/audit/runtime and
hidden CLI entry dependencies, plus Cargo build configuration.

Review type is self-review by the worker component author. The parent agent
reviewed control-loss cancellation and required explicit shared socket markers
that preserve queued data and legal TCP half-closes. This contribution does not
constitute independent review of the entire performance model.

The current model binds five obligations and fourteen explicit flow/fault
boundaries, alongside all sixteen fault-catalog applicability decisions. The accepted API budgets are
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

Windows native ABI correction before formal r3 execution, 2026-10-22:
CI39762239928 exposed four actual socket failures caused by assuming that
Winsock GET returns a four-byte boolean. The strict decoder now supports only
the known one-byte BOOLEAN and four-byte DWORD representations, while SET
continues using four bytes. The model retains all five obligations, eleven
existing boundaries and four workload states, and adds the explicit native
boolean representation boundary. F03 becomes required for this narrow decoder
boundary; general frame fuzzing is still excluded from this fixed-work report.
The new cross-platform decoder unit brings Linux forwarding preflight to24tests.
All existing native socket and actual12 integration tests remain enabled.
No performance threshold, logical work or five-group sample budget changes.
Prior r2 evidence remains evidence for its own source and binary snapshot.
Prior model digest: `6ec4c18b1e24d970e0d92e61c788a834d5d2e4a79205f630c2c210ad7df4dfe9`. Reviewed changed bound sources:
- `benchmarks/forward-workers/CONTRACT.md`
- `crates/hyperhub-core/src/forward/cancellation.rs`

Native Windows inherited stdio correction before formal r4 execution, 2026-10-22:
CI39763436851 exposed a 36.069625-second blocked Bootstrap and a control-loss
shutdown hang. Rust parent stdio uses overlapped IO, while the old test pair
used synchronous CreatePipe handles. The production fix cancels exact pipe
handles and synchronous thread IO, then waits for real completion before close.
The model retains five obligations, all twelve existing boundaries, all states
and all sample/acceptance budgets. It adds two mandatory Windows-only read/write
boundaries with a separate actual native evidence record. Linux cannot observe
these triggers and keeps that record blocked until exact-source Windows CI
passes the new real-stdio unit and twelve actual worker cases. Linux-only raw
measurements and their incomplete coverage report remain preserved. No Unix
result is substituted for Windows evidence. Previous r3 evidence remains bound
to its own snapshot and does not establish this correction.
Prior model digest: `dc63d466b15e31f0f000d8ce4b5cde3948cd94c954aad3ddf52fce177a3ea7f8`. Reviewed changed bound sources:
- `benchmarks/forward-workers/CONTRACT.md`
- `crates/hyperhub-core/src/forward/wire/windows.rs`
- `crates/hyperhub-core/tests/forward_workers/faults.rs`
New source-bound evidence tools:
- `scripts/verify-forward-workers-windows.py`
- `scripts/benchmark-forward-workers.py`


Native Host Windows error preservation before formal r5 execution, 2026-10-23:
CI39780021457 exposed a real managed target failure before the joint release
could open its first stream: connect_timeout returned an error with OS code zero
although resident audit recorded a successful CONNECT. Hook generation cleanup
called FlsGetValue after the adapter restored the application error; the FLS API
cleared LastError. The Host now preserves the caller's error across fiber-slot
operations and Engine/Hook generation entry and cleanup. Native unit and source
fixture regressions belong to the separate project Hook/joint-release Suite.
This component model keeps all five obligations, fourteen flow/fault boundaries,
four states, logical work, five-trial sample budget and 30s/100ms limits.
The changed Host bytes affect NativeBase and the embedded final CLI; therefore
r4 timing and sensitivity remain historical evidence and r5 uses a new immutable
CLI and fresh measurements. No r4 samples or Windows passes are relabeled.
The mandatory actual Windows stdio unit and twelve worker regressions remain
blocked until a successful exact-source native CI run supplies their evidence.
Prior model digest: `d4b2d3fc305f606b732d0b5e5a4b5fd783954b0c7ba76b09fe15de696d6ca473`. Reviewed changed bound sources:
- `crates/hyperhub-agent-core/src/engine_call.rs`
- `crates/hyperhub-agent-core/src/engine_call/slots.rs`
- `crates/hyperhub-agent-core/src/windows_gum/gum.rs`


NativeBase test-only dependency correction before formal r6 execution, 2026-10-23:
Main review found that five test modules used compound cfg(test, platform)
attributes that the NativeBase source collector did not classify as test-only.
Equivalent separate cfg(test) and platform attributes now keep those real test
bodies out of the retained Base fingerprint. Native production behavior and all
platform test conditions are unchanged. The existing Engine fingerprint test
now mutates test-only bodies in all five real files and requires unchanged Base;
it also retains a production-cfg sensitivity assertion. Main owns the complete
native compatibility and Hook acceptance; this report remains component scope.
The five bound dependency file bytes and embedded CLI/Base change, so r6 uses a
new immutable CLI and fresh formal/sensitivity measurements. All five obligations,
fourteen boundaries, four workload states, 20 fresh process-group trials and the
30s/100ms budgets remain unchanged. r5 raw timing, sensitivity, frozen model/plan
and Linux-only incomplete gate remain historical; its successful individual
Windows job is not substituted for r6 exact-source CI evidence.
Prior model digest: `99d0485647d2f03fcdad3e9be223245a7cc5f34e14f1feaeb96f8ca1ffac6e49`. Reviewed changed bound sources:
- `crates/hyperhub-agent-core/src/control.rs`
- `crates/hyperhub-agent-core/src/engine_call/slots.rs`
- `crates/hyperhub-agent-core/src/sandbox/mod.rs`
- `crates/hyperhub-agent-core/src/sandbox/network.rs`
- `crates/hyperhub-runtime/src/artifact.rs`


Final worker formal6 source review, 2026-10-23T08:30:50.419876+08:00:
Fresh complete source binding after reviewed authenticated fork handoff, recovery signal masking, parent authorization pruning, retained session cleanup and process-lifetime Frida Core owner. Existing five worker obligations and all thresholds remain unchanged.
The complete corpus now binds 195 source files, including every
Rust source under all five participating crates. Five obligations, fourteen
flow/fault boundaries, four workload states, sample counts, correctness oracles,
measurement boundaries, prepare30000ms and commit100ms limits remain unchanged.
The final immutable CLI SHA-256 is `535729536f8b00b993f58b04ef401458da9dcf9256f11da07933584e0037af94`; NativeBase is
`a23dc05b4ddf025d13f5d429fb0326dba4d5414f7b7991c74993f8cc1819bef2`. Source commit: `0df20519b2a6af4d16d29da7b2e872e624a5f785`.
Previous model digest: `9ab3d91db67b055550d88fba9fb7ee6a33cd0189575530da536a6ef01ffb1e8f`. Older runs retain their own sources and
binaries; none of their samples or Windows records supplies this new snapshot.
Native Windows correctness must come from the whole-success exact-source CI,
while fresh Linux performance remains separate from that native evidence.
Changed source bindings:
- `crates/hyperhub-agent-core/src/unix_gum/adapters/native.rs`: `9714b6d22bfe29cc905e665ffe9aa4dd4d0ea9dab60925bd551f6cbe9660cfd6` -> `7773e2b84aec9564264ab8cad530c334cda0079ed025c41cbfb0a9c8dde90276`
- `crates/hyperhub-agent-core/src/unix_gum/fork.rs`: `bb1cf8954c9760c3a9659cc1c74c35acae15bb9ec7eb19d6a586dfe1c6f19d67` -> `90d48a66b88bc2cebdf5eef4f9a74988d63567f209b658ef0b03c03da3fecddc`
- `crates/hyperhub-agent-core/src/unix_gum/gum.rs`: `1ff18d9a3b452810ae78a9f3ca0ce1b95518d45f103e4fbe0b4385d09ebf0fe1` -> `f982244b1ade21b8ab3060660e8b1e48905dfa3d0e7120465dc367c424f8f323`
- `crates/hyperhub-agent-core/src/unix_gum/mod.rs`: `a3ce92534cbba523a9d84c60b095a776413f71b3a0033efc6b414b727fcae3e7` -> `12d83a39b753cf826cc72f719d861e1412f3757f80513643738c7b40eb94cf51`
- `crates/hyperhub-cli/src/platform/linux/frida_core/child_gating.rs`: `db25e199b2e2125260803f810ed37453e66c51804957645a4c22c15a271d61b5` -> `a251bb64afb86b95b006f61c914c829bdab19df046015c06b80b52e07dcbe0a0`
- `crates/hyperhub-cli/src/platform/linux/frida_core/context.rs`: `8d1f1c1a6b098f238045d31f409e454b262b90ba285e2f34851a8e66a54d69eb` -> `747e7a5cfc6570d1dd39d96ef655e32914fbe553b04ec76eda30ac1122be4d9b`
- `crates/hyperhub-cli/src/platform/linux/frida_core/mod.rs`: `1cee8330fe1095c6f4ea930e23590121513dcc0b5c97343d3e1b732aa09e0948` -> `759ea620add421aae68eb0d2247c0fc5383f56f6ddb650999d0258f98a1fadf8`
- `crates/hyperhub-cli/src/platform/linux/launcher.rs`: `8bb1443b7db840efb2d902c4752319b5b2af0794fe0143801d07fd3945225842` -> `73d408a10750fba6ecfabad2251cc0e8d14f5123add8a08063971929caaa9d9a`
- `crates/hyperhub-cli/src/platform/linux/mod.rs`: `b8a617ea8efcf42949c1f4444047c49f764a58369d3a83762df5c65b8229b3be` -> `65ab5e181e7a4d1a4080c96ad96fc29d71b911acfc9b6779ec53732be098a800`
Added source bindings:
- `crates/hyperhub-agent-core/src/unix_gum/fork_handoff.rs`: `fcc344df772dc4dcbf10cfec7d7aad1aa771162eb9f0088acea4757b89a5ca7e`
- `crates/hyperhub-cli/src/platform/linux/fork_handoff.rs`: `4ec85b2ef49d2439b947b91f3ec09951023c3a03e3f397b36d5b46665d70d013`
- `crates/hyperhub-cli/src/platform/linux/frida_core/fork_listener.rs`: `6f03c7d2c088ac0ef3c6d4d842f4c432661ad5d049ab8302c156c9a13f620e87`
Reviewed separately compiled native test inputs changed after artifact capture (not production implementation changes):
- `crates/hyperhub-cli/tests/engine_host_live.rs`: `ecffb2af5dc1ac7bb793ab2b3f6013edd10bbaf4c26d95bc1478a00e749b22a0` -> `7fe5db95d3cc7c4e8841e8466b03ca6df16aface9461a82941b52398d0b2d268`
