# Hook correctness fixes and release

User authorization: repair the seven findings from the Fake-IP/coverage investigation, verify the fixes, and publish a new release. Preserve the unrelated `Pasted image.png`. The issue note from this investigation is task-owned.

## Milestones

1. Confirm release version/process and executable verification environments. DONE: next release v0.2.10; origin/main is current; GitHub authentication works. Existing tag workflow builds Linux x86_64/aarch64 and Windows x64. Windows GNU cross-check is available; native Windows runs via CI.
2. Linux implementation and local self-review DONE: full unified Suite passes with 46 independent semantic cases; CLI 137, Agent core 21, core 189 and Gum Agent 28 tests pass. Commit/push the Linux correction and track CI next.
3. Fix Windows GetAddrInfoEx asynchronous parameter preservation and ConnectEx initial payload handling. Add native source regression fixtures to a Windows verification entry point. Run available Windows build/tests (CI if no local Windows host), review, commit, immediately push, and inspect CI.
4. Run formatting, workspace all-target tests, Linux unified Suite and cross-platform CI. Fix failures; inspect all task changes and update issues/bugfix records.
5. Bump the next available patch version, commit and immediately push. Wait for required CI. Publish the corresponding tag/release through the existing workflow, then verify release artifacts and status.

## Decisions and constraints

- No changes to the user's running Serve, DNS, credentials or security configuration. Test services/configuration must be local and isolated.
- Keep unknown/expired session Fake-IP refusal. Fix domain tracking instead of allowing the reserved range.
- Prefer explicit failure over unmediated traffic where a syscall cannot safely preserve connect/payload/completion semantics; document compatibility behavior and assert it.
- Model fd tables separately from open-file-description state. Cover sharing, copying, close/reuse, unshare and exec transitions as applicable.
- Tests must check destination identity, gateway traversal, policy result and side effects, rather than hook counts alone.
- Follow project commit skill; each successful commit is immediately pushed. No force push or remote-history rewrite.
- The review's io_uring/zero-copy/TCP-DNS/namespace candidates were not verified findings; do not silently broaden this release into unrelated backend redesign.
- Do not publish a successful-verification claim for a platform that did not run. Resolve any material release blocker before tagging.

## Prior evidence

- Current main revision: fc23354; workspace version 0.2.9.
- Local pre-fix probes and results: target/diagnostics/fake-ip/ and target/diagnostics/coverage-audit/.
- Four reproduced classes: DNS I/O omissions, pipelined DNS misattribution, CLONE_FILES fd reuse/nonblocking mismatch, TCP Fast Open bypass.
- Three static findings: Windows GetAddrInfoEx completion arguments, ConnectEx initial payload ordering, Linux mmap/mprotect Read checks.

## Implementation and verification progress

- Linux DNS transaction tracker now matches socket identity, resolver, transaction ID and question; scalar/vectored/batch sends are recorded only after successful native sends, and receive batches use actual completed counts.
- Descriptor state is keyed by explicit fd-table identity shared by CLONE_FILES, copied otherwise, detached on unshare/close_range(UNSHARE)/exec; open-file-description nonblocking state retains its shared socket identity.
- Linux Fast Open sendto/sendmsg/sendmmsg and Gum sendto/sendmsg return EOPNOTSUPP before kernel network side effects. Windows ConnectEx initial data returns WSAEOPNOTSUPP before redirection; empty-payload ConnectEx remains supported.
- Linux ptrace/Gum mmap/mprotect check Read for readable/executable mappings and Write for writable mappings.
- Windows GetAddrInfoExW async calls retain original arguments and native cancellation/completion mechanisms. Callback and GetAddrInfoExOverlappedResult paths record resolved addresses before application consumption. Immediate completion follows Microsoft's synchronous-result contract and releases its registry entry.
- Added independent source fixtures and Linux/Windows semantic Suite runners. The Windows runner is registered in CI and includes Gum Agent unit tests; its pre-existing six test initializers missing `protection` were corrected so those tests can compile.
- Local workspace tests passed (136 CLI, 21 Agent core, 189 core), and initial 25-case Linux semantic suite passed. A full Linux Suite subsequently passed after the Gum exit-status fix. Expanded partial-batch/fd-lifetime/exit cases are being rerun.
- Additional release blocker found by the existing Suite: explicit Gum could lose the target exit status when Frida reaped it. Added private per-PID exit metadata from on_exit/_exit/_Exit and consume it only as a fallback; missing status is now an error rather than a fabricated success. Dedicated C source regression covers main return and three exit APIs.
- Windows implementation and probe cross-check passed; `--all-targets` exposed the pre-existing test-initializer omissions, now repaired. Native CI validation is pending.
- All diagnostic logs and machine results are under target/diagnostics/release-fixes/.
- Windows commit ba5c881 was self-reviewed, committed and immediately pushed to origin/main. CI run 38724715889 is in progress; no tag or release has been published.
- The Linux Suite passed once with 37 expanded cases; later reruns exposed an intermittent Gum descendant stop. Exit telemetry now uses raw syscalls like the existing signal_ready path, avoiding Hook reentry and inherited runtime locks. The pidfd status probe is nonblocking. Final verification remains required.
- File mapping checks conservatively include Read for PROT_WRITE-only mappings because writable pages can be readable on supported architectures. Anonymous mappings ignore the unused fd. Added explicit write-only mapping/upgrade denials plus pwrite positive controls; the expanded Suite now has 45 behavioral cases.

Commit grouping adjustment: commit Windows corrections and native Suite registration first after cross-target/self-review, immediately push and start CI. Continue diagnosing an intermittent Linux Gum descendant hang seen in the expanded full-suite rerun, then commit/push the Linux corrections after verification. Version/release preparation remains separate. Do not tag until both platform paths pass.

- Windows follow-up 570ca68 corrected a pre-existing native replacement-range assertion exposed by the newly enabled Gum tests (60/61 passed before correction). It was immediately pushed; CI run 38725416243 is in progress.
- Latest Linux full Suite passed with 46 semantic cases and 13 sandbox deny assertions, including nonleader thread exec. Pointer arithmetic/partial-batch malformed iovec regression also passed. All primary Linux changes have been self-reviewed; no release tag yet.
