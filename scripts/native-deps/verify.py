"""Verify devkit object machines, header consumers and payload ABI baselines."""
import json
import re
import shutil
import struct
import subprocess

from common import MANIFEST, run


def archive_machines(path):
    machines = set()
    with path.open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise ValueError(f"Expected complete, non-thin archive: {path}")
        while header := stream.read(60):
            if len(header) != 60 or header[58:] != b"`\n":
                raise ValueError(f"Invalid archive header: {path}")
            size = int(header[48:58].strip())
            position = stream.tell()
            prefix = stream.read(min(size, 20))
            if prefix[:4] == b"\x7fELF":
                if len(prefix) < 20 or prefix[5] != 1:
                    raise ValueError("Truncated or non-little-endian ELF archive object")
                machines.add(struct.unpack("<H", prefix[18:20])[0])
            elif header[:16].strip() not in (b"/", b"//", b"/SYM64/"):
                raise ValueError(f"Unrecognized archive member: {header[:16]!r}")
            end = position + size + size % 2
            if end > path.stat().st_size:
                raise ValueError(f"Truncated archive member: {path}")
            stream.seek(end)
    return machines



def glibc_requirements(symbols, baseline):
    """Check actual dynamic requirements; optional Gum weak hooks are not minima."""
    versions = set()
    optional = set()
    violations = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":") or "@GLIBC_" not in fields[7]:
            continue
        match = re.fullmatch(r"([^@]+)@{1,2}GLIBC_([0-9]+(?:\.[0-9]+)*|PRIVATE)", fields[7])
        if match is None:
            violations.append(line.strip())
            continue
        name, version = match.groups()
        if version == "PRIVATE":
            # Pinned Gum gum.c declares exactly this function weak and checks
            # its address for NULL before use. It exists in the unmodified
            # official baseline and must not be treated as a required version.
            if name == "__libc_dlopen_mode" and fields[3:7] == ["FUNC", "WEAK", "DEFAULT", "UND"]:
                optional.add(name)
            else:
                violations.append(line.strip())
        elif fields[6] == "UND":
            required = tuple(map(int, version.split(".")))
            versions.add(required)
            if required > baseline:
                violations.append(line.strip())
    if violations:
        raise ValueError(f"Payload violates GLIBC {baseline}: " + "; ".join(violations))
    if not versions:
        raise ValueError("Payload has no identifiable numeric GLIBC requirements")
    return {"maximum_glibc": list(max(versions)), "optional_weak_private_symbols": sorted(optional)}

def verify_outputs(root, architecture, gum, core, compilers):
    arch = "arm64" if architecture == "aarch64" else architecture
    triplet = MANIFEST["toolchains"][arch]["triplet"]
    tools = compilers[arch]
    compiler = tools / (triplet + "-gcc")
    expected_machine = 183 if architecture == "aarch64" else 62
    for kind, kit in (("gum", gum), ("core", core)):
        if archive_machines(kit / f"libfrida-{kind}.a") != {expected_machine}:
            raise ValueError(f"Wrong devkit object architecture: {kit}")
        for consumer in [compiler, shutil.which("gcc"), shutil.which("clang")]:
            if consumer is None:
                raise ValueError("Host GCC and Clang are required for portable header checks")
            run([consumer, "-fsyntax-only", "-I" + str(kit), kit / f"frida-{kind}-example.c"])
    build = root / ("build-" + architecture)
    payloads = [(build / "lib/agent", (2, 17) if architecture == "aarch64" else (2, 5), tools, triplet)]
    if architecture == "x86_64":
        payloads.append((build / "compat/arch-support.bundle.p/x86/lib/agent", (2, 5),
                         compilers["x86"], MANIFEST["toolchains"]["x86"]["triplet"]))
    report = []
    for directory, baseline, tools, triplet in payloads:
        for name in ("frida-agent.so", "libfrida-agent-modulated.so", "libfrida-agent-raw.so"):
            path = directory / name
            symbols = subprocess.check_output([tools / (triplet + "-readelf"), "--dyn-syms", "--wide", path], text=True)
            try:
                requirements = glibc_requirements(symbols, baseline)
            except ValueError as error:
                raise ValueError(f"{path}: {error}") from error
            report.append({"file": str(path.relative_to(root)), **requirements})
    glue = build / "lib/payload/libfrida-payload-1.0.a.p/spawn-monitor-glue.c.o"
    symbols = subprocess.check_output([compilers[arch] / (MANIFEST["toolchains"][arch]["triplet"] + "-nm"), glue], text=True)
    if not all(name in symbols for name in ("_frida_spawn_monitor_try_read_string", "_frida_spawn_monitor_try_read_strv")):
        raise ValueError("Safe metadata reader object is missing from the source build")
    (root / "payload-abi-verification.json").write_text(json.dumps(report, indent=2) + "\n")
