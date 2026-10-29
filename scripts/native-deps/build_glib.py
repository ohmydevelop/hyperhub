"""Rebuild GLib and GIO in the pinned SDK with its official recipe and sysroot."""
import hashlib
import json
import tarfile
import shutil
import sys

from common import MANIFEST, run, sha256


def build_glib(root, architecture, compilers, environment, jobs):
    sys.path.insert(0, str(root / "source"))
    from releng import deps
    from releng.machine_spec import MachineSpec
    from releng.meson_configure import configure
    from releng.meson_make import make

    build_machine = MachineSpec.parse("linux-x86_64")
    host = MachineSpec.parse(MANIFEST["toolchains"][architecture]["triplet"])
    toolchain, _ = deps.ensure_toolchain(build_machine, root / "deps")
    sdk, _ = deps.ensure_sdk(host, root / "deps")
    cap_ninja(toolchain / "bin/ninja", jobs)
    verify_sdk_archives(root, sdk, architecture)
    package = deps.load_dependency_parameters().packages["glib"]
    if package.version != MANIFEST["source"]["glib"]["revision"]:
        raise ValueError("GLib recipe revision differs from the pinned source")
    options = [item.value for item in package.options
               if item.when is None or eval(item.when, {"machine": host, "bundle": deps.Bundle.SDK})]
    build = root / ("glib-build-" + architecture)
    if not (build / "build.ninja").exists():
        configure(sourcedir=root / "glib-source", builddir=build, prefix=sdk,
                  host_machine=host, environ=environment,
                  extra_meson_options=["-Dlibdir=lib", *options])
    config = (build / "config.h").read_text()
    eventfd_available = "#define HAVE_EVENTFD 1" in config
    if architecture in ("x86_64", "x86") and eventfd_available:
        raise ValueError("Baseline SDK unexpectedly bypasses the fixed g_try_eventfd")
    make(sourcedir=root / "glib-source", builddir=build,
         targets=["glib-2.0", "gio-2.0"], environ=environment)
    archives = {}
    for component in ("glib", "gio"):
        name = f"lib{component}-2.0.a"
        library = build / component / name
        target = sdk / "lib" / name
        archives[component] = install_sdk_archive(library, target, compilers[architecture],
                                                  MANIFEST["toolchains"][architecture]["triplet"])
    report = {"architecture": architecture, "glib_revision": package.version,
              "recipe_options": options, "have_eventfd": eventfd_available,
              **archives["glib"], "gio": archives["gio"]}
    (root / ("glib-provenance-" + architecture + ".json")).write_text(json.dumps(report, indent=2) + "\n")
    verify_sdk_archives(root, sdk, architecture)
    return sdk


def install_sdk_archive(library, target, compiler, triplet):
    """Install one complete archive and retain the original SDK bytes for audit."""
    original = target.with_name(target.stem + ".original.a")
    if not original.exists():
        shutil.copy2(target, original)
    with library.open("rb") as stream:
        magic = stream.read(8)
    if magic == b"!<thin>\n":
        # MRI reads relative file names in the archive directory. This also
        # supports project/cache roots containing spaces without shell quoting.
        merged = library.with_name(library.stem + "-hyperhub-merged.a")
        merged.unlink(missing_ok=True)
        run([compiler / (triplet + "-ar"), "-M"], cwd=library.parent,
            input=f"create {merged.name}\naddlib {library.name}\nsave\nend\n", text=True)
        with merged.open("rb") as stream:
            if stream.read(8) != b"!<arch>\n":
                raise ValueError(f"Archive conversion did not produce a complete archive: {library}")
        shutil.copy2(merged, target)
    elif magic == b"!<arch>\n":
        shutil.copy2(library, target)
    else:
        raise ValueError(f"Unknown archive format: {library}")
    return {"original_archive_sha256": sha256(original), "fixed_archive_sha256": sha256(target)}


def cap_ninja(ninja, jobs):
    upstream = ninja.with_name("ninja.upstream")
    if not upstream.exists():
        ninja.rename(upstream)
    ninja.write_text('#!/bin/sh\nexec "$(dirname "$0")/ninja.upstream" -j' + str(jobs) + ' "$@"\n')
    ninja.chmod(0o755)


def verify_sdk_archives(root, sdk, architecture):
    """Only the exact recorded GLib and GIO archives may differ from the SDK."""
    provenance = root / ("glib-provenance-" + architecture + ".json")
    report = json.loads(provenance.read_text()) if provenance.exists() else {}
    if not isinstance(report, dict):
        raise ValueError("Invalid SDK archive provenance")
    # Preserve the historical top-level GLib fields. GIO must have its own
    # explicit record; provenance cannot authorize overrides of other libraries.
    allowed = {"lib/libglib-2.0.a": report, "lib/libgio-2.0.a": report.get("gio", {})}
    if any(not isinstance(record, dict) for record in allowed.values()):
        raise ValueError("Invalid SDK archive provenance")
    rows = []
    with tarfile.open(root / f"deps/sdk-linux-{architecture}.tar.xz") as archive:
        for item in archive:
            if not item.isfile() or not item.name.endswith(".a"):
                continue
            relative = item.name.removeprefix("./")
            path = sdk / relative
            with archive.extractfile(item) as stream:
                expected = hashlib.file_digest(stream, "sha256").hexdigest()
            actual = sha256(path)
            record = allowed.get(relative, {})
            fixed = record.get("fixed_archive_sha256")
            if actual != expected and actual != fixed:
                raise ValueError(f"Unverified SDK archive modification: {path}")
            if relative in allowed:
                if record.get("original_archive_sha256", expected) != expected:
                    raise ValueError(f"Recorded original archive does not match its SDK bundle: {path}")
                original = path.with_name(path.stem + ".original.a")
                if original.exists() and sha256(original) != expected:
                    raise ValueError(f"Preserved original archive does not match its SDK bundle: {path}")
            rows.append({"file": relative, "original_sha256": expected, "actual_sha256": actual,
                         "allowed_glib_override": relative == "lib/libglib-2.0.a" and actual != expected,
                         "allowed_gio_override": relative == "lib/libgio-2.0.a" and actual != expected})
    if not rows:
        raise ValueError("Pinned SDK bundle contains no static archives")
    (root / ("sdk-archive-audit-" + architecture + ".json")).write_text(json.dumps(rows, indent=2) + "\n")
