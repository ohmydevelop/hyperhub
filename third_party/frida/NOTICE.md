# Frida native dependency source and modifications

HyperHub builds Frida Core and Gum 17.17.0 from the official repositories pinned
in `manifest.json`, using the official releng recipes and SDK dependency bundles.
The source-build cache retains the complete corresponding source checkouts,
build configuration, private toolchains, generated object files and provenance.
The repository contains the source recipe and the reviewed source patches; it does
not distribute compiled native libraries here.

- Core: https://github.com/frida/frida-core/tree/c812943c457376c906802f7bb79d13c67a6e4d22
- Gum: https://github.com/frida/frida-gum/tree/ddc10c5559cbb41a3dd72866bfba6ff3945ffa5c
- releng: https://github.com/frida/releng/tree/c9cc18138b364f691573c695e1fe47ddc4c56f26
- GLib: https://github.com/frida/glib/tree/790ffa82e80d99fba8a3db494e46f907d560893c

HyperHub modifications, 2026-10-28:

1. Core SpawnMonitor on Linux reads execution metadata through owned, bounded
   copies and preserves kernel error-return semantics for invalid user pointers.
2. GLib `g_try_eventfd` uses `eventfd2` with atomic flags; only ENOSYS falls back
   to legacy eventfd, followed by checked CLOEXEC/NONBLOCK setup and owned FD
   cleanup. The same GLib source is rebuilt for native and compatibility payloads.
3. Core queries the recovering child's actual eternal lifetime through an
   additive internal interface after subscribing to lifetime signals. Unknown
   query state is retained with a bounded error and may be retried; ordinary
   non-eternal children still unload. Children resumed without an initial
   session follow the same known-lifetime rule.
4. GLib GDBus connection disposal sets the closed state and completes pending
   calls before releasing the worker. Queued replies return a closed error;
   send, flush, close and message processing synchronize worker lifetime with
   disposal. Blocking flush retains an independent private worker reference.
5. Devkit packaging restricts header inlining to public source/generated/SDK
   headers so compiler sysroot libc headers stay outside the portable API header.
6. Core D-Bus context discovery retains each probe's own Promise across cache
   invalidation and handles retirement of its temporary connection after the
   real worker context has been obtained, without an unreachable error branch.
7. Native loader and bootstrapper artifacts are built from the reviewed helper
   source. Their 19 nolibc headers come from Linux v6.2, commit
   `c9c3395d5e3dcc6daee66c6908354d47bf98cb0c`, under `tools/include/nolibc`,
   with Frida's existing nolibc tweaks. These headers retain their original
   copyrights and `LGPL-2.1 OR MIT` identifiers; HyperHub provides them under
   LGPL-2.1, with the license text in `COPYING.LGPL-2.1`.

Core and Gum retain their original wxWindows Library Licence terms, including
its exception; copies are in `COPYING.CORE` and `COPYING.GUM`. HyperHub permits
that same exception for its Core patches. GLib's modified `glib/gwakeup.c`,
`gio/gdbusconnection.c`, `gio/gdbusprivate.c` and `gio/gdbusprivate.h` retain
LGPL-2.1-or-later; the changes to those files use the same license. The GNU Library
GPL v2 and GNU Lesser GPL v2.1 texts accompany these notices. Original copyright
and per-file licensing notices remain in the downloaded source. Other SDK
components retain their upstream licenses in the corresponding source/SDK.

A release that includes these dependencies must retain the applicable notices
and provide the corresponding modified source and relinking material required
by the applicable upstream licenses. This source recipe is a build input; it
does not itself publish a release or replace that release's license materials.
