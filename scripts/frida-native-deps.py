#!/usr/bin/env python3
"""Build or verify the patched Linux Frida Core/Gum pair; stdout is two paths."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import sys
import time

if sys.version_info < (3, 12):
    raise SystemExit("Frida source dependency setup requires Python 3.12 or later")

sys.path.insert(0, str(Path(__file__).resolve().parent / "native-deps"))
from common import REPO, recipe_identity, verify_pair, write_pair_receipt
from bootstrap import prepare_sources, prepare_tools
from build_glib import build_glib
from build_devkits import build_devkits
from verify import verify_outputs
from regressions import regressions


def build_environment(root, node, go, compilers):
    environment = dict(os.environ)
    for name in list(environment):
        if name in {"CC", "CXX", "CPP", "LD", "AR", "RANLIB", "STRIP", "OBJC", "OBJCXX",
                    "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR",
                    "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "NPM_TOKEN", "NODE_AUTH_TOKEN"} or name.endswith("_FOR_BUILD") or name.lower().startswith("npm_config_"):
            environment.pop(name)
    private_npmrc = root / "tools/npmrc"
    private_npmrc.write_text("")
    private_global_npmrc = root / "tools/npm-globalrc"
    private_global_npmrc.write_text("")
    environment.update(
        TMPDIR=str(root / "tmp"), FRIDA_DEPS=str(root / "deps"),
        XDG_CACHE_HOME=str(root / "tools/cache"),
        npm_config_cache=str(root / "tools/npm-cache"),
        npm_config_userconfig=str(private_npmrc), npm_config_globalconfig=str(private_global_npmrc),
        GOCACHE=str(root / "tools/go-cache"), GOPATH=str(root / "tools/gopath"),
        GOMODCACHE=str(root / "tools/gopath/pkg/mod"), GOFLAGS="-p=1", GOMAXPROCS="2",
        GOTOOLCHAIN="local", GOENV="off", GOWORK="off", GOPROXY="https://proxy.golang.org,direct", GOSUMDB="sum.golang.org",
        GIT_TERMINAL_PROMPT="0")
    environment["PATH"] = os.pathsep.join([str(node), str(go), *(str(path) for path in compilers.values()),
                                          environment.get("PATH", "")])
    return environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", choices=("x86_64", "aarch64"), default=platform.machine())
    parser.add_argument("--cache-root", type=Path, default=REPO / ".cache/frida-native")
    parser.add_argument("--gum-root", type=Path)
    parser.add_argument("--core-root", type=Path)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--print-recipe", action="store_true")
    args = parser.parse_args()
    recipe = recipe_identity()
    if args.print_recipe:
        return [recipe]
    if args.gum_root is not None or args.core_root is not None:
        if args.gum_root is None or args.core_root is None:
            parser.error("custom SDKs require both --gum-root and --core-root")
        gum, core = args.gum_root.resolve(), args.core_root.resolve()
        verify_pair(gum, core, args.architecture, recipe)
        return [str(gum), str(core)]
    root = args.cache_root.resolve() / recipe / args.architecture
    root.mkdir(parents=True, exist_ok=True)
    with (root / "build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        gum, core = root / "devkits/gum", root / "devkits/core"
        if (gum / "hyperhub-frida-sdk.json").exists() or (core / "hyperhub-frida-sdk.json").exists() or args.verify_only:
            verify_pair(gum, core, args.architecture, recipe)
            return [str(gum), str(core)]
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("This baseline source recipe requires a Linux x86_64 build host. "
                             "Build the requested target there, then supply the verified Core/Gum SDK pair.")
        missing = [name for name in ("git", "make", "gcc", "g++", "clang", "pkg-config") if shutil.which(name) is None]
        if missing:
            raise ValueError("Missing source-build prerequisites: " + ", ".join(missing))
        started = time.monotonic()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        for name in ("tmp", "tools", "logs"):
            (root / name).mkdir(exist_ok=True)
        # Source preparation can invoke Git; even it uses this private temp root.
        os.environ["TMPDIR"] = str(root / "tmp")
        os.environ["GIT_TERMINAL_PROMPT"] = "0"
        prepare_sources(root)
        node, go, compilers = prepare_tools(root, args.architecture)
        if args.prepare_only:
            print(f"Verified pinned source/tool inputs at {root}", file=sys.stderr)
            return []
        environment = build_environment(root, node, go, compilers)
        os.environ.update(environment)
        architectures = ("x86_64", "x86") if args.architecture == "x86_64" else ("x86_64", "arm64")
        for architecture in architectures:
            build_glib(root, architecture, compilers, environment, args.jobs)
        gum, core = build_devkits(root, args.architecture, environment, compilers, args.jobs)
        verify_outputs(root, args.architecture, gum, core, compilers)
        regressions(root, args.architecture, gum, core, compilers, environment)
        # Only successful static and runnable regression gates publish a receipt.
        # Subsequent invocations rehash the delivered pair before returning it.
        write_pair_receipt(gum, core, args.architecture, recipe)
        (root / "completed.json").write_text(json.dumps({"recipe_sha256": recipe,
            "architecture": args.architecture, "elapsed_seconds": time.monotonic() - started,
            "target_runtime_executed": args.architecture == "x86_64"}, indent=2) + "\n")
        return [str(gum), str(core)]


if __name__ == "__main__":
    # Releng and all descendant configure/Make/Ninja processes write diagnostics
    # to stderr, so shell callers always receive only the resulting SDK paths.
    with os.fdopen(os.dup(sys.stdout.fileno()), "w") as output:
        sys.stdout.flush()
        os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
        try:
            result = main()
        except (OSError, ValueError, KeyError) as error:
            print(f"Frida source dependency setup failed: {error}", file=sys.stderr)
            raise SystemExit(1)
        for line in result:
            print(line, file=output)
