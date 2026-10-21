# Remove runtime API Key CLI parameters (2026-10-21)

User request: remove explicit runtime API Key parameters. Commands must read the current HyperHub Home's runtime/api-key internally and retain all authentication and envelope checks. Preserve administrator/backup password options, real user state and the unrelated image. User now explicitly requests publication; do not change the user's installed binary or running Serve.

1. DONE: traced all CLI parsers, Serve spawning, configuration saves, bundled guidance and unified regression runners. The new removed-option regression failed against the old parser because start accepted --password-file (target/diagnostics/remove-api-key-options/before.log).
2. DONE: removed --api-key-file and runtime --password-file from all commands, option structs and help. Use instance paths consistently for runtime key operations and child Serve startup; preserve target arguments after the run boundary. Reject removed options with an actionable message.
3. DONE: updated affected scripts, suites and active documentation, preserving historical release records. Isolated CLI checks cover automatic authentication, missing/wrong keys, instance isolation and removed-option rejection. Local fixtures seed upgrade-check timestamps to avoid external GitHub requests. CLI-only changes use module/integration regressions, not a new target-program Benchmark.
4. DONE locally: formatting, workspace all-target tests (CLI 147, Agent core 22, core 189), final CLI tests, isolated multi-home and sequential approval integration, Skill contract, Bash/Python checks, 17-case mock smart-protection runner and Windows GNU all-target cross-check passed. The approval live-update subcase was skipped because the real user Serve is running; CI uses isolated runners for that subcase and native Windows execution. Main agent reviewed the complete diff and compatibility record. Commit via the repository skill, immediately push and follow exact-commit CI to completion; GitHub records the final CI result. Evidence: target/diagnostics/remove-api-key-options/. No changes to the user Serve, real credentials or installed binary.

Decision: instance selection remains HYPERHUB_HOME; no credential values move to argv or a new environment variable. The custom API Key path CLI override is intentionally removed together with its alias. The encrypted configuration format and per-session authentication remain unchanged.

## Release v0.2.12

Preflight: implementation a2de33e passed CI 39573901055 on Linux and native Windows, including the live approval subcase and 46 Linux semantic regressions. Preflight confirmed that the prior latest release was v0.2.11 and origin had no v0.2.12 tag.

1. DONE: workspace/local lockfile versions and release default are 0.2.12; dependency versions are unchanged. Formatting, locked metadata and complete diff checks passed. Version commit 624a864 was immediately pushed.
2. DONE: version commit 624a864 passed all three jobs in CI 39575366681. The annotated v0.2.12 tag was pushed on that validated commit. Release workflow 39576424981 passed all three builds and publication. v0.2.12 is public with six assets; removed-parameter migration is prominent in its release notes.
3. DONE: https://github.com/ohmydevelop/hyperhub/releases/tag/v0.2.12 is the latest non-draft, non-prerelease release. Downloaded all six assets; all archive SHA-256 and inner manifests match, Linux ELF/Windows PE headers identify the correct architectures, and installers match source. Published Linux x86_64 --help/doctor and embedded Agent verification passed. All nine CLI entries reject both removed options with a migration message; the published binary also passed isolated multi-home/automatic-authentication, missing/wrong key rejection and envelope repair regressions. Evidence: target/diagnostics/release-0.2.12/{source-ci.json,release-ci.json,release.json,multi-home.log,release-assets/verification.json,release-assets/smoke.json,release-assets/architectures.json}. ARM64 was cross-built, not run on native hardware; macOS is outside the release matrix.
4. Publication and verification records are complete. Self-review and commit/push documentation, then follow its exact-commit CI; the GitHub run is the durable final CI record. The release tag remains on validated source commit 624a864. The unrelated image, real user configuration/key files, installed binary and running Serve remain untouched.

# Completed: Runtime key persistence correction (2026-10-16)

User request: change the unreasonable offline-save key rotation and fix the resulting stale runtime envelope. Preserve the user's real encrypted configuration, API key, runtime envelope, and unrelated image. Diagnose/verify with isolated temporary homes and dummy credentials; administrator entry remains a human terminal action.

1. Persistence paths reviewed. DONE: TUI offline saves rotated descriptors; runtime wrapping was delayed to normal exit; refresh could persist an unauthenticated key, and discarding a password edit returned the unsaved password.
2. DONE: ordinary TUI saves preserve the descriptor; explicit password changes rotate it. Save-time wrapping supports custom API keys, discards retain the last persisted password, and refresh validates the administrator password before writing.
3. DONE: startup preflight checks generation and decryptability, and authenticated approval persistence repairs existing envelopes. Existing container/ABI formats are unchanged.
4. DONE locally: the old implementation failed the new offline-save regression; CLI 145, Agent core 22, core 189, isolated CLI lifecycle, formatting, Skill contract and Windows GNU all-target checks passed. Eight module regressions cover persistence and authentication transitions. Native Windows and concentrated Linux checks run in CI on the exact pushed commit. No external target-program Benchmark is needed for this persistence/CLI bug.
5. DONE: implementation commit 9c3d764 was immediately pushed; CI 38843994114 passed all Linux and native Windows jobs. Self-review and daily records are complete.

## Release v0.2.11 (explicitly requested)

User explicitly requested publication. The persistence fix is released as v0.2.11; do not replace the user's installed binary or input their password. Preflight confirmed that tag v0.2.11 was absent and the prior public release was v0.2.10.

1. DONE: workspace/local lockfile versions and release default are 0.2.11; dependency versions are unchanged. Formatting, locked metadata and complete diff checks passed. Version commit 5fb1248 was immediately pushed.
2. DONE: version commit 5fb1248 passed all three jobs in CI 38845354365 (Linux targets, Linux tests and native Windows tests). The annotated v0.2.11 tag was pushed on this validated commit.
3. DONE: release workflow 38846014324 passed all three builds and publication. https://github.com/ohmydevelop/hyperhub/releases/tag/v0.2.11 is the latest non-draft, non-prerelease release with all six assets. Downloaded all assets, verified all archive and inner manifest hashes, and confirmed installers match source. Published Linux x86_64 --help/doctor passed with embedded Agent verification. The same published binary passed the isolated multi-home lifecycle, wrong-password protection, stale-envelope rejection and administrator repair regression. Evidence: target/diagnostics/release-0.2.11/{source-ci.json,release-ci.json,release.json,multi-home.log,release-assets/verification.json,release-assets/smoke.json}. ARM64 was cross-built, not run on native hardware; macOS is outside the release matrix.
4. Publication and verification records are complete. Self-review, commit/push task-owned documentation and follow its CI; the exact commit's GitHub run remains the durable final CI record. The release tag stays on validated source commit 5fb1248. The unrelated image and real user configuration/key files remain untouched.

Decisions: do not replace encryption formats, delete/recreate user configuration, or silently regenerate an API key. Ordinary saves use a fresh AEAD nonce under the existing key, without unnecessary KDF rotation. Keep password rotation prohibited while Serve is running, including a runtime recheck at save time. Multi-file write failures must be reported, not presented as a successful save.

Progress: the offline-save regression was run against the old implementation and failed with a descriptor change (target/diagnostics/runtime-key-fix/before.log). The same test now passes. CLI module suite passed 145 tests, including eight new persistence/authentication regressions. Workspace all-target tests, isolated CLI lifecycle and Windows GNU all-target checks passed. Implementation keeps existing container formats and makes envelope failures retryable; it does not introduce a multi-file transaction or claim crash-atomic password rotation. All local evidence is under target/diagnostics/runtime-key-fix/.

# Completed prior task: Hook correctness fixes and release

User authorization: repair the seven findings from the Fake-IP/coverage investigation, verify the fixes, and publish a new release. Preserve the unrelated `Pasted image.png`. The issue note from this investigation is task-owned.

## Milestones

1. Confirm release version/process and executable verification environments. DONE: next release v0.2.10; origin/main is current; GitHub authentication works. Existing tag workflow builds Linux x86_64/aarch64 and Windows x64. Windows GNU cross-check is available; native Windows runs via CI.
2. Linux implementation and local self-review DONE: full unified Suite passes with 46 independent semantic cases; CLI 137, Agent core 22, core 189 and Gum Agent 29 tests pass. Linux corrections are committed and pushed; Linux CI jobs passed.
3. Windows implementation DONE: native CI passes Gum unit tests and 12 executable cases, including event/callback/cancel, raw status reads, empty/nonempty ConnectEx and exact gateway/domain audit assertions. All implementation commits were immediately pushed.
4. Verification DONE: formatting, workspace all-target tests, Linux unified Suite and every cross-platform job in CI 38729792711 passed. Reviewed the final implementation and updated issue/bugfix records.
5. Release DONE: v0.2.10 at e8959f9 passed CI 38730652435, and release workflow 38731520406 published Linux x86_64/aarch64 and Windows x64. Downloaded all assets, verified archive SHA-256 and every inner manifest, confirmed installers match source, and passed published Linux x86_64 --help/doctor with embedded Agent verification. ARM64 was cross-built, not run on native hardware; macOS was not tested.

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
- Linux corrections c048347 were committed and immediately pushed. Both Linux CI jobs passed. Windows CI now passes all 61 Gum tests and all five native probes, but the first managed probe fails before execution because the Agent initialization event is not signaled. Preserve fail-closed startup; diagnose the loader result and worker/bootstrap/hook stages before publishing.
- Added opt-in per-process initialization evidence to the Windows Suite and loader exit status to the timeout error. Windows GNU all-target checks passed for both CLI and Gum Agent. Version 0.2.10 metadata is prepared but remains separate from this diagnostic change; no release tag exists.

- Windows diagnostic CI 38727251196 isolated the failure to installation of the newly added GetAddrInfoExOverlappedResult replacement; bootstrap and all preceding hooks succeed, then the transaction rolls back. Reject weakening hook completeness or resuming an uninstrumented target. Remove this replacement (IDs remain the existing 1..47) and bridge event-mode completion with a stable internal OVERLAPPED/native callback, copying status and recording DNS before signaling the original caller event. Native cancellation handles remain unchanged. Added direct-status and callback/event identity probes plus completion unit tests. Cross-target all-target check and Python syntax check passed; native CI is next.
- Commit a35eb26 was immediately pushed. CI 38728500583 passes both Linux jobs, Windows Gum tests and all 12 native/managed executable probes. Its final audit assertion correctly catches missing DNS attribution: protocol versions 4/6 and native AF_* values form different DNS keys. Normalize the internal DNS map by parsed IP address for recording, SOCKS targeting and firewall lookup while retaining ABI signatures. Add family-value regression and preserve the audit evidence; rerun the shared Linux Suite because this correction is platform independent.
- The shared-key correction passes workspace all-target tests (CLI 137, Agent core 22, core 189), Linux Gum 29, and a fresh complete Linux unified Suite (46 semantic cases, 12 original audited connections, 13 denies). Windows GNU all-target cross-check passed. Native Windows audit verification remains the final implementation blocker.

- Windows job 116404455847 in CI 38729792711 succeeded after the shared-key fix. Downloaded artifact confirms 12/12 zero exits and exactly four gateway connections, with localhost on all three DNS-positive cases. Linux unit/integration job passed; Linux cross-target Suite is finishing. Prepare final version metadata/docs commit, require its complete CI before pushing the release tag.
- CI 38729792711 completed successfully across all three jobs. Final version update changes only workspace/lockfile versions, release default and verification records; no dependency upgrades or runtime behavior changes. Preserve the unrelated image and publish only after the final commit's CI succeeds.

- Final version CI 38730652435 passed at e8959f9. Annotated tag v0.2.10 was pushed; release workflow 38731520406 succeeded, publishing all three platform archives, checksums and installers. Release notes were updated. Downloaded-artifact integrity and smoke verification are running before final handoff.

- Release handoff evidence is complete: https://github.com/ohmydevelop/hyperhub/releases/tag/v0.2.10 is the latest non-draft, non-prerelease version. All three archive hashes and inner manifests match; downloaded x86_64 smoke tests pass. Evidence: target/diagnostics/release-fixes/release-assets/{verification.json,smoke.json}. Final documentation-only commit records completion; the release tag remains on the validated source commit.
