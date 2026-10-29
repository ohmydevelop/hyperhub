"""Build the patched upstream Linux injection helpers without editing source artifacts."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

from bootstrap import fetch
from common import MANIFEST, VENDOR, run, sha256

NOLIBC = VENDOR / "linux-nolibc.json"
NOLIBC_COMPATIBILITY = VENDOR / "patches/linux-helper-nolibc-compatibility.patch"
ARCHITECTURES = {"x86_64": ("x86_64", "x86"), "aarch64": ("arm64",)}
MACHINES = {"x86_64": (2, 62, "x86_64"), "x86": (1, 3, "i686"), "arm64": (2, 183, "aarch64")}


def tree_hashes(root):
    paths = sorted(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError(f"Helper inputs or outputs contain a symlink: {root}")
    return {path.relative_to(root).as_posix(): sha256(path) for path in paths if path.is_file()}


def prepare_helpers_source(root):
    """Reconstruct expected scratch bytes, then check rather than overwrite warm inputs."""
    specification = json.loads(NOLIBC.read_text())
    original = root / "source/src/linux/helpers"
    patch = original / "patches/linux-nolibc-tweaks.patch"
    compatibility = NOLIBC_COMPATIBILITY
    if sha256(patch) != specification["tweaks_sha256"]:
        raise ValueError("Unreviewed upstream nolibc tweaks")
    if sha256(compatibility) != specification["compatibility_patch_sha256"]:
        raise ValueError("Unreviewed HyperHub nolibc compatibility patch")
    destination = root / "helpers-source"
    with tempfile.TemporaryDirectory(prefix="helpers-source-", dir=root / "tmp") as temporary:
        scratch = Path(temporary)
        inputs = [*original.glob("*.c"), *original.glob("*.h"), original / "helper.lds", original / "meson.build"]
        for path in inputs:
            if path.is_symlink():
                raise ValueError(f"Symlink helper source: {path}")
            shutil.copy2(path, scratch / path.name)
        kernel = scratch / "ext/linux"
        for name, expected in specification["headers"].items():
            if Path(name).name != name or not name.endswith(".h"):
                raise ValueError("Invalid pinned nolibc header name")
            url = ("https://raw.githubusercontent.com/torvalds/linux/" + specification["revision"]
                   + "/" + specification["directory"] + "/" + name)
            download = fetch(url, root / "downloads/linux-nolibc" / name, expected)
            header = kernel / specification["directory"] / name
            header.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(download, header)
        # An isolated repository at the scratch root prevents Git from finding
        # the caller's parent worktree and silently skipping ignored cache
        # paths. The upstream patch is rooted at the kernel subset; HyperHub's
        # compatibility patch is rooted at the complete helper source tree.
        # Pin every Git setting that can change patch matching or whitespace
        # bytes; user and system configuration must not alter reviewed inputs.
        git = ["git", "-c", "core.autocrlf=false",
               "-c", "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab",
               "-c", "apply.whitespace=nowarn", "-c", "apply.ignoreWhitespace=false"]
        run([*git, "init", "--quiet", scratch])
        run([*git, "apply", "--directory=ext/linux", "--check", patch.resolve()], cwd=scratch)
        run([*git, "apply", "--directory=ext/linux", patch.resolve()], cwd=scratch)
        run([*git, "apply", "--check", compatibility.resolve()], cwd=scratch)
        run([*git, "apply", compatibility.resolve()], cwd=scratch)
        shutil.rmtree(scratch / ".git")
        types = (kernel / specification["directory"] / "types.h").read_text()
        strict = types.find("#define __KERNEL_STRICT_NAMES")
        uapi = types.find("#include <linux/time.h>")
        if strict < 0 or uapi < 0 or strict > uapi:
            raise ValueError("Patched nolibc does not request strict kernel UAPI names")
        expected = tree_hashes(scratch)
        if destination.exists():
            if tree_hashes(destination) != expected:
                raise ValueError("Warm helper source differs from current reviewed inputs")
        else:
            shutil.copytree(scratch, destination)
    return destination, {"nolibc_specification_sha256": sha256(NOLIBC),
                         "nolibc": specification, "tweaks_sha256": sha256(patch),
                         "compatibility_patch_sha256": sha256(compatibility),
                         "source_files": expected}


def helper_tools(root, arch, compilers):
    triplet = MANIFEST["toolchains"][arch]["triplet"]
    tools = {name: compilers[arch] / (triplet + "-" + suffix)
             for name, suffix in (("c", "gcc"), ("ar", "gcc-ar"), ("strip", "strip"),
                                  ("objcopy", "objcopy"), ("readelf", "readelf"), ("nm", "gcc-nm"))}
    tools["meson"] = root / "source/releng/meson/meson.py"
    tools["ninja"] = root / "deps/toolchain-linux-x86_64/bin/ninja"
    tools["ninja_upstream"] = tools["ninja"].with_name("ninja.upstream")
    for path in tools.values():
        if not path.is_file():
            raise ValueError(f"Missing pinned helper tool: {path}")
    try:
        sysroot_output = subprocess.check_output([tools["c"], "-print-sysroot"], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("Helper compiler does not report a pinned sysroot") from error
    if not sysroot_output:
        raise ValueError("Helper compiler does not report a pinned sysroot")
    sysroot = Path(sysroot_output).resolve()
    if not sysroot.is_relative_to(compilers[arch].parent.resolve()):
        raise ValueError("Helper compiler uses an external sysroot")
    if subprocess.check_output([tools["c"], "-dumpmachine"], text=True).strip() != triplet:
        raise ValueError("Helper compiler target differs from the pinned target")
    return tools, {"toolchain": MANIFEST["toolchains"][arch], "sysroot": str(sysroot),
                   "meson_revision": MANIFEST["source"]["meson"],
                   "tools": {name: {"path": str(path), "sha256": sha256(path)} for name, path in tools.items()}}


def cross_file(arch, tools):
    def quoted(value):
        # MachineFileParser doubles backslashes before parsing. Triple-quoted
        # strings preserve apostrophes without relying on backslash escapes.
        value = str(value)
        if "'''" in value or "\n" in value or "\r" in value:
            raise ValueError("Helper tool path cannot be represented in a Meson machine file")
        return "'''" + value + "'''"
    binaries = "\n".join(f"{name} = {quoted(tools[name])}" for name in ("c", "ar", "strip", "objcopy"))
    family = "aarch64" if arch == "arm64" else arch
    return ("[binaries]\n" + binaries + "\n[host_machine]\nsystem = 'linux'\n"
            + f"cpu_family = '{family}'\ncpu = '{MACHINES[arch][2]}'\nendian = 'little'\n"
            + "[properties]\nneeds_exe_wrapper = true\n")


def verify_payload(elf, binary, arch, entrypoint):
    """Reject payloads needing a dynamic loader or relocation after extraction."""
    if elf.is_symlink() or binary.is_symlink():
        raise ValueError("Helper outputs must be regular files")
    try:
        return _verify_payload(elf, binary, arch, entrypoint)
    except (struct.error, IndexError, UnicodeError) as error:
        raise ValueError(f"Malformed helper ELF: {elf}") from error


def _verify_payload(elf, binary, arch, entrypoint):
    data = elf.read_bytes()
    elf_class, machine, _ = MACHINES[arch]
    if len(data) < 64 or data[:7] != bytes([127, 69, 76, 70, elf_class, 1, 1]):
        raise ValueError(f"Wrong helper ELF class/encoding: {elf}")
    wide = elf_class == 2
    header = struct.unpack_from("<HHIQQQIHHHHHH" if wide else "<HHIIIIIHHHHHH", data, 16)
    if header[0] != 3 or header[1] != machine:
        raise ValueError(f"Wrong helper ELF machine/type: {elf}")
    section_format = "<IIQQQQIIQQ" if wide else "<IIIIIIIIII"
    section_size = struct.calcsize(section_format)
    if header[10] != section_size or header[11] == 0 or header[12] >= header[11]:
        raise ValueError("Invalid helper ELF section table")

    def region(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("Truncated helper ELF")
        return data[offset:offset + size]

    sections = [struct.unpack(section_format, region(header[5] + i * section_size, section_size))
                for i in range(header[11])]
    strings = sections[header[12]]
    names = region(strings[4], strings[5])
    named = {names[s[0]:].split(b"\0", 1)[0].decode(): (i, s) for i, s in enumerate(sections)}
    if ".payload" not in named:
        raise ValueError("Helper ELF has no payload")
    index, payload = named[".payload"]
    if payload[3] != 0 or payload[5] == 0 or not (payload[2] & 4):
        raise ValueError("Helper payload must start at address zero and contain code")
    if binary.read_bytes() != region(payload[4], payload[5]):
        raise ValueError("Helper binary differs from its ELF payload")
    found = False
    for section in sections:
        kind, flags, size = section[1], section[2], section[5]
        if kind in (4, 9) and size:
            raise ValueError("Helper ELF contains relocations")
        if kind == 8 and flags & 2 and size:
            raise ValueError("Helper ELF contains unextracted BSS")
        if kind == 6:
            fmt = "<qQ" if wide else "<iI"
            for offset in range(0, size, struct.calcsize(fmt)):
                tag, value = struct.unpack(fmt, region(section[4] + offset, struct.calcsize(fmt)))
                if tag in (1, 22) or (tag == 30 and value & 4):
                    raise ValueError("Helper ELF requires a dynamic library or text relocations")
        if kind not in (2, 11):
            continue
        string_table = sections[section[6]]
        symbols = region(string_table[4], string_table[5])
        fmt = "<IBBHQQ" if wide else "<IIIBBH"
        stride = struct.calcsize(fmt)
        if section[9] != stride or size % stride:
            raise ValueError("Invalid helper symbol table")
        for offset in range(0, size, stride):
            symbol = struct.unpack(fmt, region(section[4] + offset, stride))
            name = symbols[symbol[0]:].split(b"\0", 1)[0].decode()
            section_index, value = (symbol[3], symbol[4]) if wide else (symbol[5], symbol[1])
            if name and section_index == 0:
                raise ValueError(f"Undefined helper symbol: {name}")
            if name == entrypoint:
                if section_index != index or value != 0:
                    raise ValueError("Helper entrypoint is not at payload offset zero")
                found = True
    for i in range(header[9]):
        if struct.unpack("<I", region(header[4] + i * header[8], 4))[0] == 3:
            raise ValueError("Helper ELF has a program interpreter")
    if not found:
        raise ValueError("Helper ELF lacks its entrypoint symbol")
    return {"machine": machine, "elf_class": elf_class, "entrypoint": entrypoint,
            "payload_address": 0, "payload_size": payload[5],
            "elf_sha256": sha256(elf), "binary_sha256": sha256(binary)}


def build_helpers(root, architecture, compilers, environment, jobs=2):
    if architecture not in ARCHITECTURES:
        raise ValueError(f"Unsupported Linux helper architecture: {architecture}")
    source, sources = prepare_helpers_source(root)
    artifacts = root / "helpers-artifacts"
    for arch in ARCHITECTURES[architecture]:
        tools, provenance = helper_tools(root, arch, compilers)
        machine_file = cross_file(arch, tools)
        inputs = {**sources, **provenance, "architecture": arch, "cross_file": machine_file}
        build = root / ("helpers-build-" + arch)
        report_path = root / ("helpers-provenance-" + arch + ".json")
        destination = artifacts / "native" / arch
        prior = json.loads(report_path.read_text()) if report_path.exists() else None
        if prior is not None and prior["inputs"] != inputs:
            raise ValueError("Warm helper build inputs changed")
        if prior is None:
            if build.exists() or destination.exists():
                raise ValueError("Incomplete helper build requires a fresh private recipe cache")
            machine_path = root / ("helpers-" + arch + ".txt")
            machine_path.write_text(machine_file)
            env = {**environment, "NINJA": str(tools["ninja"])}
            run([sys.executable, tools["meson"], "setup", build, source,
                 "--cross-file", machine_path, "-Db_lto=true"], env=env)
            intro = json.loads((build / "meson-info/intro-compilers.json").read_text())
            if Path(intro["host"]["c"]["exelist"][0]).resolve() != tools["c"].resolve():
                raise ValueError("Helper Meson selected an unpinned compiler")
            run([tools["ninja"], "-j", jobs, "-C", build, "bootstrapper.bin", "loader.bin"], env=env)
            destination.mkdir(parents=True)
            for name in ("bootstrapper", "loader"):
                shutil.copy2(build / (name + ".bin"), destination / (name + ".bin"))
        if set(tree_hashes(destination)) != {"bootstrapper.bin", "loader.bin"}:
            raise ValueError("Unrecorded helper artifacts")
        results = {}
        for name, entrypoint in (("bootstrapper", "frida_bootstrap"), ("loader", "frida_load")):
            elf, binary = build / (name + ".so"), destination / (name + ".bin")
            if not elf.is_file():
                raise ValueError("Incomplete helper build requires a fresh private recipe cache")
            results[name] = verify_payload(elf, binary, arch, entrypoint)
            # Verify extraction with the pinned objcopy as well as direct ELF
            # section comparison. Never silently replace the packaged bytes.
            with tempfile.TemporaryDirectory(prefix="helper-extract-", dir=root / "tmp") as temporary:
                extracted = Path(temporary) / "payload.bin"
                run([tools["objcopy"], "-O", "binary", "-j", ".payload", elf, extracted])
                if sha256(extracted) != sha256(binary):
                    raise ValueError("Pinned objcopy disagrees with the packaged helper")
        report = {"inputs": inputs, "outputs": results}
        if prior is not None and prior != report:
            raise ValueError("Warm helper output differs from its provenance")
        if prior is None:
            report_path.write_text(json.dumps(report, indent=2) + "\n")
    return artifacts
