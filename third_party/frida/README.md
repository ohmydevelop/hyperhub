# Building the native Frida dependencies

The standard Linux setup builds the fixed source recipe in `manifest.json`.
It applies the reviewed source patches before building Core, Gum and the native
and compatibility payloads. The complete official Go and V8 backends remain
enabled and compatibility remains `auto`. Windows continues to use the official
Gum devkit through `scripts/build.ps1`.

On Linux, install Rust and the host build prerequisites. For Debian/Ubuntu:

```sh
sudo apt-get install build-essential pkg-config git ca-certificates python3 clang libclang-dev
./scripts/build.sh
```

The native dependency recipe requires Python 3.12 or later and a Linux x86_64
build host. It can produce both x86_64 and aarch64 SDK pairs. All current Linux
CI/release builders use that build host, including the ARM64 cross build.
An ARM64 native host can consume an SDK pair produced by this recipe; it does
not fall back to the unmodified upstream devkit when native source building is
unavailable. Windows uses its existing PowerShell workflow:

```powershell
.\scripts\build.ps1
```

`frida-devkit.sh` writes exactly two paths, Gum followed by Core. Build logs go
to stderr. The first invocation downloads pinned public source, SDK bundles,
Node, Go and official Frida compiler/sysroot layers into a private cache. No
Docker installation, system tool installation or user configuration change is
performed by the source builder. It needs several GiB of free space for source,
toolchains and build outputs; later invocations verify and reuse the cache.

```sh
./scripts/frida-devkit.sh x86_64
./scripts/frida-devkit.sh aarch64
```

The x86_64 recipe uses the official glibc 2.5 baseline for both x64 and x86
compatibility payloads. ARM64 uses the official glibc 2.17 baseline. SDK GLib
and GIO are rebuilt from their fixed source and recipe before any payload is
linked. Both installed archives must be complete rather than thin archives.
The GLib provenance retains its original fields and adds a separate GIO record;
both record the preserved original and rebuilt archive SHA-256. SDK audits allow
only these two exact recorded replacements and verify their original backups
against the pinned bundle. Every other SDK archive must match that bundle. Public headers are packaged
without compiler sysroot libc headers. The source builder checks archive
architectures, public-header compilation with baseline GCC and host GCC/Clang,
safe-reader object symbols and all native/compat agent GLIBC version requirements.
The ABI check permits only Gum's existing optional weak `__libc_dlopen_mode`
private hook, which upstream checks for NULL; strong or unknown private symbol
requirements and numeric GLIBC requirements above the baseline remain errors.
Configured target GCC/G++, binutils, cgo tools and compiler sysroot are checked
explicitly before building Core, rather than inferred from PATH.
Native loader and bootstrapper blobs are also rebuilt from the reviewed C
source, including the x86 compatibility payloads. The private helper build uses
upstream Meson and the pinned target tools. Its nolibc headers are fixed by
commit and individual checksums in `linux-nolibc.json`. Core consumes generated
artifacts from an explicit private directory; the source checkout's prebuilt
blobs are not overwritten. Generated ELF and binary artifacts have separate
source and output provenance checks.

Its unified dependency regression stage exercises GWakeup success/fault paths
and, for x86_64, both final devkit archives and the existing plain-C execve error
fixture through Core. Its four child-lifetime cases cover inherited eternity,
plain unload, first eternalization in the child after fork, and an inherited
eternal child resumed before any initial session. The plain cases must return
to the fixture's single business thread, so retaining every child cannot pass.
Two local GDBus retirement cases pause actual method dispatch or asynchronous
invocation completion until after connection disposal. They require closed
errors for pending and subsequent calls, send, flush and close, repeated
disposal, and release of callback, registration and connection references.
The fixture uses only its own socket pair and does not attach to a process.
Disposal marks the connection closed and completes pending calls before stopping
its worker; queued replies cannot re-enter a retired worker. Flush holds a
private worker reference while waiting outside the connection lock. Disposal
does not queue a new closed signal that would retain a dying connection.
Three context-discovery cases exercise the actual Core coroutine after its
temporary connection has already closed or been disposed, including overlapping
cache generations. They require the real worker context, cache hits without new
probes, actual closed errors, and release of every probe object. Discovery keeps
each Promise local to its generation and handles auxiliary-connection retirement
after obtaining the context, including builds with assertions disabled.

Tests spawn only those fixtures and require the build host
to permit that ordinary Frida child tracing. They do not change ptrace policy.
The Core lifetime fix adds a separate internal `AgentLifetimeProvider1` DBus
interface; existing Frida 17 interface signatures and the public C API stay
unchanged. The Host subscribes before querying the child's actual monotonic
state, not a parent snapshot. The five-second query is served by the existing
Agent recovery mainloop while it awaits resume permission. Unsupported/timed
out queries publish an explicit unknown state: attachment returns its error,
retry is possible, and native resume never guesses unloading is safe. Only
known non-eternal children unload on last-session or no-session resume.

ARM64 payloads are cross-built and statically checked; this stage does not claim
an ARM64 runtime test.

The cache is `.cache/frida-native/<recipe SHA-256>/<architecture>/`. Its identity
covers this manifest, patches, build/validation scripts, regression source and
license notices. `HYPERHUB_FRIDA_CACHE_ROOT` selects another cache root, and
`HYPERHUB_FRIDA_BUILD_JOBS=1` reduces the default two native build jobs. Download
archives are checked against fixed digests. A completed Core/Gum pair receives
identical `hyperhub-frida-sdk.json` receipts listing the recipe and every output
file's actual SHA-256. Every reuse verifies both receipts and all file bytes;
unknown extra files, missing files, wrong architecture or an older recipe are
rejected. The script records source-build, GLib/SDK, payload ABI and regression
evidence beside the outputs. This is a replayable source recipe with verified
inputs and recorded outputs; byte-for-byte reproducible output is not claimed.

To move a pair to another build host, copy both complete `devkits/gum` and
`devkits/core` directories, including their receipts and license files, then run:

```sh
export HYPERHUB_FRIDA_GUM_ROOT=/path/to/source-built/gum
export HYPERHUB_FRIDA_CORE_ROOT=/path/to/source-built/core
./scripts/build.sh
```

The Windows remote Linux orchestrator defaults to transferring source and
building the pinned recipe on an x86_64 remote host. Its optional
`-LinuxFridaGumRoot` and `-LinuxFridaCoreRoot` parameters transfer a complete
source-built Linux pair; these are required for a native ARM64 remote host.
The chosen committed source revision must contain the same source recipe.
The remote build validates the receipts before compiling HyperHub.

Low-level Cargo invocation is a separate interface: Linux CLI and Gum Agent
builds require both `HYPERHUB_FRIDA_GUM_ROOT` and `HYPERHUB_FRIDA_CORE_ROOT` and the
normal bindgen include configuration. Such explicit SDK roots are bound by
actual archive and header bytes, including externally built SDKs; a shared
`17.17.0` version alone does not prove the reviewed patches are present. The low-level
build does not certify arbitrary SDKs as this patched source recipe. Roots must
contain the selected static archive without alternate same-name dynamic or GNU
archives that could shadow it in the linker search.

The resident Native Base fingerprint contains these actual dependency bytes,
with target, dependency role and native profile separated. Changing even a
same-version library or header changes Agent/Engine/CLI compatibility; relocating
the identical SDK does not. Cargo tracks both root environment variables, root
directories and the native input files. Plain Engine/Core algorithm tests with
neither root use a distinct SDK-free profile. Gum Agent, Linux CLI and embedded
builds reject that profile. Ordinary macOS Core/Serve builds require no Frida
SDK; this recipe does not add macOS attachment support.

Source contract tests need neither downloads nor a native compiler:

```sh
python3 -m unittest discover -s tests -p test_frida_native_dependencies.py
```

See [NOTICE.md](NOTICE.md) for the source locations, modifications and retained
upstream license terms. Generated libraries, toolchains and caches are ignored
build artifacts and are not committed.
