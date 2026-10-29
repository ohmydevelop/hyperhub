"""Build the official Core/Gum targets, then package only public headers."""
import json
import os
from pathlib import Path
import pickle
import re
import runpy
import shutil
import sys

from common import MANIFEST, VENDOR, run, sha256
from build_helpers import build_helpers
from devkit_headers import install_header_allowlist
from compiler_configuration import verify_configuration


def build_devkits(root, architecture, environment, compilers, jobs=2):
    source = root / "source"
    helper_artifacts = build_helpers(root, architecture, compilers, environment, jobs)
    build = root / ("build-" + architecture)
    build.mkdir(exist_ok=True)
    if not (build / "build.ninja").exists():
        run([source / "configure", "--host=" + architecture + "-linux-gnu", "--",
             "-Ddevkits=core", "-Dfrida-gum:devkits=gum", "-Dassets=embedded",
             "-Dfrida_version=" + MANIFEST["version"],
             "-Dlinux_helper_artifacts_root=" + str(helper_artifacts)], cwd=build, env=environment)
    sys.path.insert(0, str(source))
    from releng import env
    from releng.machine_spec import MachineSpec
    machine_name = "linux-arm64" if architecture == "aarch64" else "linux-x86_64"
    configuration = env.load_meson_config(MachineSpec.parse(machine_name), "", build)
    verify_configuration(build, architecture, compilers, configuration)
    config = build / "tools/cgo/go-config.json"
    if not config.exists():
        raise ValueError("Default Go compiler backend was not configured")
    data = json.loads(config.read_text())
    for key in ("TMPDIR", "npm_config_cache", "GOCACHE", "GOPATH", "GOMODCACHE", "GOFLAGS", "GOMAXPROCS", "GOTOOLCHAIN"):
        data["env"][key] = environment[key]
    updated = json.dumps(data, indent=2) + "\n"
    if config.read_text() != updated:
        config.write_text(updated)
    targets = json.loads((build / "meson-info/intro-targets.json").read_text())
    support = next(item for item in targets if item["name"] == "arch-support")
    outputs = {Path(path).name for path in support["filename"]}
    if architecture == "x86_64" and not {"frida-helper", "frida-agent.so"}.issubset(outputs):
        raise ValueError("Default x86 compatibility outputs are missing")
    options = json.loads((build / "meson-info/intro-buildoptions.json").read_text())
    helper_root = next((item["value"] for item in options if item["name"] == "linux_helper_artifacts_root"), None)
    if helper_root != str(helper_artifacts):
        raise ValueError("Core did not configure the generated Linux helper artifacts")
    compat = next(item["value"] for item in options if item["name"] == "compat")
    if compat != ["auto"]:
        raise ValueError(f"Default compatibility changed: {compat}")
    gum_config = (build / "subprojects/frida-gum/config.h").read_text()
    if re.search(r"^#define HAVE_V8(?:\s+1)?$", gum_config, re.MULTILINE) is None:
        raise ValueError("Default V8 support was not configured")
    run(["make", "frida-core-api", "frida-core-library", "frida-gumjs-inspector-1.0"], cwd=build, env=environment)

    sys.path.insert(0, str(source))
    from releng import devkit
    state = pickle.loads((build / "frida-env.dat").read_bytes())
    machine = state["host"] or state["build"]
    os.environ.update(machine.make_merged_environment(environment))
    sdk_arch = "arm64" if architecture == "aarch64" else architecture
    install_header_allowlist(devkit, root, build, root / ("deps/sdk-linux-" + sdk_arch))
    artifacts = []
    for kit in ("core-devkit", "gum-devkit"):
        target = next(item for item in targets if item["name"] == kit)
        command = target["target_sources"][0]["compiler"]
        if Path(command[1]).resolve() != source / "releng/mkdevkit.py":
            raise ValueError("Unexpected official packager command")
        sys.argv = command[1:]
        runpy.run_path(command[1], run_name="__main__")
        artifacts.extend(Path(filename) for filename in target["filename"])
    report = {"architecture": architecture, "compat": compat, "v8": True,
              "go_backend_mode": data["mode"], "helper_artifacts_root": str(helper_artifacts.relative_to(root)), "arch_support_outputs": sorted(outputs),
              "artifacts": [{"file": str(path.relative_to(root)), "sha256": sha256(path)}
                            for path in sorted(artifacts)]}
    (root / ("build-provenance-" + architecture + ".json")).write_text(json.dumps(report, indent=2) + "\n")
    output = root / "devkits"
    for kit, relative in (("core", "src/devkit"), ("gum", "subprojects/frida-gum/gum/devkit")):
        destination = output / kit
        destination.mkdir(parents=True, exist_ok=True)
        for path in (build / relative).iterdir():
            if path.is_file():
                shutil.copy2(path, destination / path.name)
        for name in ("COPYING.CORE", "COPYING.GUM", "COPYING.LGPL-2", "COPYING.LGPL-2.1", "NOTICE.md"):
            shutil.copy2(VENDOR / name, destination / name)
    return output / "gum", output / "core"
