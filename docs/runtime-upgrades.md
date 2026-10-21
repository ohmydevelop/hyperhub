# Resident runtime upgrades

## Implementation status

The `hyperhub-runtime` crate supplies module, generation and socket-transfer
primitives. The first production processing group now uses `hyperhub-engine`:
DNS normalization, connection planning, SOCKS packet encoding and reply validation.
Linux ptrace and Linux/Windows Gum route those operations through generation
leases. Agent sockets retain their original Engine through all handshake phases,
including `dup`; ptrace retains its tracer, descriptor state and syscall leases.

The Agent exposes trusted in-process prepare/commit/abort/query/observe/rollback
through `hh_agent_engine_control`. This is not an authenticated remote endpoint.
External callers still need the planned coordinator and authenticated transport.
`hyperhub upgrade` still uses the previous binary replacement workflow. This
revision does not enable automatic live upgrades from the CLI. The remaining
Hook capability groups, Serve workers, durable coordination, release packaging
and end-to-end upgrade suites remain tracked in `PLAN.md`.

## Ownership and compatibility

A resident Host owns process identity, native Hook bridges, descriptors, sessions,
DNS/Fake-IP maps, connection state, asynchronous completion records, and locks.
An Engine supplies replaceable processing code. The V1 module ABI contains C
scalars, explicitly sized structures, pointers to borrowed byte buffers, opaque
Host context handles, and C function pointers. No Rust object crosses that ABI.
The Host and module keep their own allocators and buffers.

A trusted release manifest declares the target, ABI, Host state schema, native
Hook set, version, file size and SHA-256. All four compatibility fields must match
the installed Host. Adding or removing a native Hook point requires maintenance;
an incompatible candidate returns `requires_restart` without running its loader.
The trusted manifest must be authenticated by the release/coordinator layer.
A file hash alone does not authenticate its publisher.

Native modules are trusted executable code. Integrity and ABI checks do not
sandbox constructors, entry points, module destructors, or callbacks. A native
fault can terminate the Host. A deadline cannot preempt arbitrary native code
inside the Host address space. The contract requires bounded health checks,
thread-safe stateless invocation, no retained borrowed pointers, and no unmanaged
threads or callbacks that outlive a call. The library loader is therefore an
explicit unsafe boundary.

## Module lifetime

The cache uses digest-based names and installs without replacing existing files.
Files are validated again on opening, and must be regular, read-only objects.
On Linux the loader uses the verified descriptor through `/proc/self/fd`; Windows
keeps a handle that denies write/delete sharing. The cache must be a private
Host-owned directory (mode 0700 on Unix; the coordinator must create an equivalent
user-only ACL on Windows). These measures do not protect against another process
with the same owner's authority deliberately changing permissions or memory.

`Runtime::acquire` returns a generation lease without taking the transaction
mutex. A call invokes only that lease's implementation. Syscall entry/exit pairs,
asynchronous completion/cancellation, and forwarding connections must retain the
lease across their complete lifetime. Host services receive the exact calling
lease through a per-call opaque C context. They must clone that lease before
starting asynchronous work, even if the active generation has already changed;
acquiring the current generation there would pin the wrong implementation.
Dropping the current-generation pointer
cannot unload code still referenced by a lease. Module reclamation and abort
cleanup run after releasing the transaction mutex because destructors can invoke
Host services.

## Transactions

`prepare(id, manifest, loader)` reserves one transaction and loads/checks a
candidate outside the transaction mutex. Repeated IDs return the saved result;
using one ID for different manifests is rejected. An abort or timeout wins over
a late loader result. `commit` atomically changes the dispatch pointer. The
previous generation stays reserved through health observation, then drains until
its remaining leases are released. The default reservation is 30 seconds.

A failed health check, or an explicit coordinator rollback during the reservation,
restores dispatch to the previous generation. Existing calls can still finish on
the failed generation; rollback does not undo completed IO. A stale transaction
cannot roll back a later upgrade. The resident owner must call `observe` to run
health checks and expire the rollback reservation; queries do not perform native
health checks. Preparation expiration is checked by transaction/status operations.

The defaults permit four retained old generations, a 30-second preparation
budget, and a 100-millisecond switching-lock budget. They are engineering budgets,
not real-time guarantees. When retention or bounded transaction history is full,
new transactions are rejected. No lease is revoked to make room. The transaction
history is process-local in this layer; durable recovery and multi-participant
coordination remain separate integration work.

## Verification

`cargo test -p hyperhub-runtime --locked` runs direct state/lifetime regressions
and builds `tests/fixtures/upgrade_engine.rs` into real shared libraries. The two
versions compute different results for the same input. The suite checks that new
leases run new code while pending leases still run old code, including health
rollback and Host callbacks across the C ABI. It also checks abort during load,
incompatible manifests and native tables, damaged files, concurrent cache
installation, bounded retention, transaction retries, concurrent dispatch, and
reentrant module destruction. Workspace tests register these automatically on
Linux and native Windows CI. These tests do not establish live Hook coverage,
forwarding continuity, performance budgets, or native macOS support.

## Accepted socket handoff primitive

`handoff` provides platform-specific accepted TCP socket transfer without closing
or reconnecting the client stream. Unix uses a private connected datagram channel
and `SCM_RIGHTS`; descriptor and correlation payload stay in one datagram.
Receivers reject missing/multiple descriptors and truncated payload/control data,
close all rejected descriptors, validate a connected stream, and set close-on-exec.
Windows exports `WSAPROTOCOL_INFOW` for one specified worker PID and imports it
with overlapped IO and handle inheritance disabled. A fresh worker initializes
Winsock independently. Serialized protocol storage is initialized and aligned;
no Rust structure padding is exposed. Offers require matching architecture.

This primitive deliberately does not choose a worker, authenticate a public
endpoint, or grant connection ownership. The ingress must retain the actual
worker process identity/handle and a private authenticated control channel. The
required protocol is offer, readiness acknowledgement, then explicit ownership
grant. A worker must not perform stream IO before the grant. Keep the original
socket until acknowledgement/grant; never retry delivery after granting ownership
because the first worker might have already performed business IO.

The `socket_handoff` integration suite starts separate local worker processes.
It hands accepted streams to old/new workers under the same listener, closes the
ingress copies, interleaves messages on both streams, drains the new worker, and
continues IO on the old stream before its natural close. Unix rejection tests
check actual peer EOF to prove rejected descriptors were closed. Windows CI runs
the native cross-process duplication path. This tests the transport primitive;
Serve worker processes, authoritative sessions/Fake-IP lookup, cancellation,
audit forwarding and upgrade orchestration still need integration.

## Network Host integration

Build the independent native network module with
`cargo build -p hyperhub-engine --release --locked`. It exports `hh_engine_v1`.
The initial Host fallback uses the same processing implementation, with the
same JSON byte schema, and does not require a downloaded module. Its manifest
identity is logical; native candidates use the actual file size and digest.
The network operation mask describes this processing group, not complete native
Hook coverage. Changes to the native bridges or other Host capabilities are not
made hot-reloadable by this group alone.

The Host supplies snapshots of the data required by a processing call and owns
all mutations: session/token, DNS/Fake-IP identity, socket IDs, nonblocking/IO
state, and descriptor sharing. No Rust value crosses the native boundary. Agent
Hook guards pin one generation across synchronous calls; Windows asynchronous
DNS records pin it until completion/cancellation and restore it when publishing
results. User callbacks can enter new calls on the current generation. Windows
fork rebuilding clears copied thread-local context; copied parent guards cannot
restore it into the rebuilt child. This is not a claim that all fork/exec upgrade
histories have been verified.

Management loading, health checks and reclamation run without the Agent-state
mutex. Trusted internal module IO bypasses target Hook enforcement, as other
Host control work does. Public network transports must not invoke these commands
before authentication. The C entry requires reply capacity before performing a
mutation, so a buffer-size probe cannot prepare or commit a generation.

`tests/fixtures/network_upgrade_engine.rs` is independently compiled by the Agent
Host suite. It changes DNS normalization, CONNECT domain encoding and reply
validation. The suite uses the exported C ABI to switch real module code while
checking stable process/state identity, old/new socket behavior, delayed DNS
recording, descriptor duplication, reclamation and incompatible state rejection.
Its minimal decoder accepts controlled ASCII test requests only. It is not a
production module parser. Existing Linux ptrace/Gum and Windows Hook suites cover
the initial Engine path; remote-coordinated live native-Hook switching and
persistent TLS/SSH/WebSocket upgrades still require separate end-to-end tests.
