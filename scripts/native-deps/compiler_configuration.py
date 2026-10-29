"""Assert the configured target tools instead of assuming PATH selected them."""
import json
from pathlib import Path
import shlex
import subprocess

from common import MANIFEST


def require_tool(commands, key, compiler_bin, triplet, tool):
    actual = commands.get(key, [])
    if isinstance(actual, str):
        actual = shlex.split(actual)
    expected = compiler_bin / (triplet + "-" + tool)
    if not actual or Path(actual[0]).resolve() != expected.resolve():
        raise ValueError(f"Configured target {key} is not the pinned {expected}: {actual}")
    return actual


def verify_configuration(build, architecture, compilers, configuration):
    arch = "arm64" if architecture == "aarch64" else architecture
    triplet = MANIFEST["toolchains"][arch]["triplet"]
    compiler_bin = compilers[arch]
    tools = {}
    for key, tool in (("c", "gcc"), ("cpp", "g++"), ("ar", "gcc-ar"), ("nm", "gcc-nm"),
                      ("ranlib", "gcc-ranlib"), ("strip", "strip"), ("readelf", "readelf"),
                      ("objcopy", "objcopy"), ("objdump", "objdump")):
        tools[key] = require_tool(configuration, key, compiler_bin, triplet, tool)
    intro = json.loads((build / "meson-info/intro-compilers.json").read_text())
    for language, tool in (("c", "gcc"), ("cpp", "g++")):
        require_tool({language: intro["host"][language]["exelist"]}, language, compiler_bin, triplet, tool)
    cgo = json.loads((build / "tools/cgo/go-config.json").read_text())
    require_tool({"CC": cgo["env"].get("CC")}, "CC", compiler_bin, triplet, "gcc")
    for key, tool in (("ar", "gcc-ar"), ("nm", "gcc-nm"), ("ranlib", "gcc-ranlib")):
        require_tool(cgo, key, compiler_bin, triplet, tool)
    sysroot = Path(subprocess.check_output([tools["c"][0], "-print-sysroot"], text=True).strip()).resolve()
    if not sysroot.is_relative_to(compiler_bin.parent.resolve()):
        raise ValueError(f"Configured target compiler uses an external sysroot: {sysroot}")
    report = {"target": architecture, "tools": tools, "sysroot": str(sysroot),
              "glibc_baseline": MANIFEST["toolchains"][arch]["glibc_baseline"]}
    (build / "hyperhub-toolchain-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
