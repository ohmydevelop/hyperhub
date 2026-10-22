# Windows Hook reliability Suite

Run from PowerShell on Windows after building the release CLI:

```powershell
./scripts/test-windows-hooks.ps1
```

The existing entry builds the source fixture, runs Gum unit tests and the native
Engine upgrade integration, then compares the unmanaged and managed source
program against a local echo server. Each run uses a private HyperHub home and
local test credentials. The Suite does not use the installed configuration.

The schedule is fixed before execution. It includes ten ordinary cases per
backend, then eight fresh processes per backend for concurrent cancellation.
Each single cancellation case completes 64 requests. Each concurrent process
completes 256 requests across four threads, mixing manual-reset event,
completion callback and status-accessor polling. A barrier overlaps request
entry on each iteration; it does not control the internal Windows scheduler.
Every target calls `WSACleanup` immediately after completing its requests.

The independent oracle requires a zero process exit code, a completed Winsock
cleanup marker, exact completion counts, per-request callback identity, the
original event identity and permitted terminal status. Every cancellation case
must observe at least one accepted native cancellation; otherwise its intended
condition is unproven and the Suite fails. Completion may win a cancellation
race. The Suite accepts success or the documented cancellation terminal statuses
and does not require cancellation to win every request. Non-cancellation DNS and
ConnectEx cases must still produce exactly four managed gateway connections,
including hostname attribution in three distinct DNS sessions. Cancellation
must not produce gateway connections.

The fiber teardown case requires 66 completed callbacks and six fiber switches
per backend, including policy checks in late callbacks. The error-semantics case
uses Rust's `TcpStream::connect_timeout` against the local echo server and checks
that an invalid socket preserves `WSAENOTSOCK` (10038), missing file and process
operations preserve `ERROR_FILE_NOT_FOUND` (2), and a managed denied file returns
`ERROR_ACCESS_DENIED` (5). The missing executable is an absolute path inside the
private fixture. The unmanaged run validates the same OS failure-code oracles.
These cases add 67 managed gateway connections to the four DNS/ConnectEx
connections, for an exact total of 71. The complete schedule has 36 fresh target
processes and 4,480 cancellation requests across both backends.

`results.json` retains every process result, repetition index, stdout, stderr and
cancellation counts. Timeout output and native exception diagnostics are retained
on failure. A failed target stops the Suite; no target is retried. The test-only
exception handler records access violations and leaves their disposition intact.

The pending status oracle follows Microsoft's
[GetAddrInfoExOverlappedResult contract](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexoverlappedresult):
the accessor returns `WSAEINPROGRESS` while pending. This differs from
`GetAddrInfoExW` returning `WSA_IO_PENDING`. Cancellation behavior follows
[GetAddrInfoExCancel](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexcancel).

These are bounded reliability regressions. Passing this schedule does not prove
all native thread interleavings, determine the cause of a prior intermittent
access violation, or measure performance.
