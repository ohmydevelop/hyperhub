"""Unified deterministic dependency regressions; execute only our own fixtures."""
import json
import subprocess

from common import MANIFEST, REPO, run

CASES = ["path-bad", "path-null", "argv-bad", "envp-bad", "argv-string-bad",
         "envp-string-bad", "path-guard", "argv-guard", "envp-guard",
         "argv-string-guard", "envp-string-guard", "valid-missing",
         "null-vectors-missing", "empty-vectors-missing", "over-budget-argv"]
FIXTURES = REPO / "tests/fixtures/frida-native"


def execute(command, environment, rows, label):
    result = subprocess.run([str(item) for item in command], env=environment,
                            capture_output=True, text=True, timeout=30)
    row = {"case": label, "returncode": result.returncode,
           "stdout": result.stdout, "stderr": result.stderr}
    rows.append(row)
    if result.returncode:
        raise ValueError(f"Native dependency regression failed: {row}")
    return result


def regressions(root, architecture, gum, core, compilers, environment):
    output = root / "regressions"
    output.mkdir(exist_ok=True)
    rows = []
    try:
        for arch in ("x86_64", "x86") if architecture == "x86_64" else ("x86_64",):
            triplet = MANIFEST["toolchains"][arch]["triplet"]
            compiler = compilers[arch] / (triplet + "-gcc")
            sdk = root / ("deps/sdk-linux-" + arch)
            flags = ["-O0", "-Wall", "-Wextra", "-Werror", "-I" + str(sdk / "include/glib-2.0"),
                     "-I" + str(sdk / "lib/glib-2.0/include")]
            if arch == "x86":
                sysroot = subprocess.check_output([compiler, "-print-sysroot"], text=True).strip()
                flags += ["-Wl,--dynamic-linker," + sysroot + "/lib/ld-linux.so.2", "-Wl,-rpath," + sysroot + "/lib"]
            for name in ("gwakeup-flags", "gwakeup-fallback"):
                binary = output / (name + "-" + arch)
                command = [compiler, *flags, FIXTURES / (name + ".c"), sdk / "lib/libglib-2.0.a",
                           "-pthread", "-ldl", "-lm", "-lrt", "-lresolv", "-o", binary]
                if name.endswith("fallback"):
                    command += ["-Wl,--wrap=" + symbol for symbol in ("syscall", "fcntl", "fcntl64", "close", "g_unix_open_pipe")]
                run(command, env=environment)
                for mode in range(7) if name.endswith("fallback") else (None,):
                    execute([binary, *([] if mode is None else [mode])], environment, rows, f"{arch}/{name}/{mode}")
        # ARM64 is cross-linked and statically verified above. No ARM runtime
        # success is claimed on this x86_64 build host.
        if architecture == "x86_64":
            compiler = compilers["x86_64"] / "x86_64-linux-gnu-gcc"
            sdk = root / "deps/sdk-linux-x86_64"
            for kind, kit in (("gum", gum), ("core", core)):
                binary = output / (kind + "-final-gwakeup")
                run([compiler, "-DFRIDA_PREFIXED", "-I" + str(sdk / "include/glib-2.0"),
                     "-I" + str(sdk / "lib/glib-2.0/include"), FIXTURES / "gwakeup-flags.c",
                     kit / f"libfrida-{kind}.a", "-pthread", "-ldl", "-lm", "-lrt", "-lresolv", "-o", binary], env=environment)
                execute([binary], environment, rows, kind + "/final-gwakeup")
            target = output / "execve-errors"
            runner = output / "core-errors"
            run([compiler, "-O0", "-Wall", "-Wextra", REPO / "tests/fixtures/linux_execve_error_probe.c", "-o", target], env=environment)
            run([compiler, "-O0", "-Wall", "-Wextra", "-I" + str(core), FIXTURES / "core-error-runner.c",
                 core / "libfrida-core.a", "-pthread", "-ldl", "-lm", "-lrt", "-lresolv",
                 "-Wl,--export-dynamic", "-o", runner], env=environment)
            lifetime = output / "core-child-eternal"
            run([compiler, "-O0", "-Wall", "-Wextra", "-I" + str(core), FIXTURES / "core-child-eternal.c",
                 core / "libfrida-core.a", "-pthread", "-ldl", "-lm", "-lrt", "-lresolv",
                 "-Wl,--export-dynamic", "-o", lifetime], env=environment)
            for mode in ("eternal", "plain", "child-late-eternal", "eternal-no-initial-session"):
                execute([lifetime, mode], environment, rows, "child-lifetime/" + mode)
            retirement = output / "core-dbus-retirement"
            run([compiler, "-O0", "-Wall", "-Wextra", "-Werror", "-I" + str(core),
                 FIXTURES / "core-dbus-retirement.c", core / "libfrida-core.a",
                 "-pthread", "-ldl", "-lm", "-lrt", "-lresolv", "-o", retirement], env=environment)
            for mode in ("dispatch", "async"):
                execute([retirement, mode], environment, rows, "dbus-retirement/" + mode)
            context_retirement = output / "core-dbus-context-retirement"
            run([compiler, "-O0", "-Wall", "-Wextra", "-Werror", "-I" + str(core),
                 FIXTURES / "core-dbus-context-retirement.c", core / "libfrida-core.a",
                 "-pthread", "-ldl", "-lm", "-lrt", "-lresolv",
                 "-Wl,--wrap=_frida_g_dbus_connection_close",
                 "-Wl,--wrap=_frida_g_dbus_connection_close_finish",
                 "-o", context_retirement], env=environment)
            for mode in ("closed", "disposed", "overlap"):
                execute([context_retirement, mode], environment, rows, "dbus-context-retirement/" + mode)
            fork_recovery = output / "core-fork-disconnect"
            run([compiler, "-O0", "-Wall", "-Wextra", "-Werror", "-I" + str(core),
                 FIXTURES / "core-fork-disconnect.c", core / "libfrida-core.a",
                 "-pthread", "-ldl", "-lm", "-lrt", "-lresolv",
                 "-Wl,--export-dynamic", "-o", fork_recovery], env=environment)
            for mode in ("plain", "child-close", "eternal-control", "eternal-child-close",
                         "controller-close-fork", "controller-exit-fork"):
                result = execute([fork_recovery, mode], environment, rows, "fork-disconnect/" + mode)
                if result.stderr:
                    raise ValueError(
                        "Fork recovery wrote internal diagnostics to target stderr: "
                        f"mode={mode!r} stderr={result.stderr!r}"
                    )
            for case in CASES:
                native_report = output / (case + ".native.txt")
                core_report = output / (case + ".core.txt")
                for path in (native_report, core_report):
                    path.unlink(missing_ok=True)
                execute([target, case, native_report], environment, rows, case + "/native")
                execute([runner, target, case, core_report], environment, rows, case + "/core")
                if native_report.read_text() != core_report.read_text():
                    raise ValueError(f"Core changed native error-return semantics: {case}")
    finally:
        (output / "results.json").write_text(json.dumps({"target_runtime_executed": architecture == "x86_64",
                                                       "results": rows}, indent=2) + "\n")
