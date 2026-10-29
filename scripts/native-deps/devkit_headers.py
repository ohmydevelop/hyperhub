"""Restrict header inlining to public project/generated/SDK header trees."""
from pathlib import Path


def install_header_allowlist(devkit, root: Path, build: Path, sdk: Path):
    root, build, sdk = root.resolve(), build.resolve(), sdk.resolve()
    allowed = [root / "source", build / "src", build / "lib",
               build / "subprojects/frida-gum", sdk / "include",
               sdk / "lib/glib-2.0/include"]
    # Keep the initial source/build/deps collection broad enough for an isolated
    # layout, then filter it before inlining. In particular, never inline a
    # compiler sysroot merely because the toolchain lives under the job root.
    devkit.REPO_ROOT = root

    def public_headers_only(headers, meson_config, include_cflags):
        return [header for header in headers
                if any(header.resolve().is_relative_to(prefix) for prefix in allowed)]

    devkit.exclude_libc_headers = public_headers_only
    return [str(path) for path in allowed]
