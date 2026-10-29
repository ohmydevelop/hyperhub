#!/usr/bin/env python3
"""Behavioral regressions independent of the syscall hit-count manifest."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[3]
EXECVE_ERROR_CASES = (
    "path-bad", "path-null", "argv-bad", "envp-bad", "argv-string-bad",
    "envp-string-bad", "path-guard", "argv-guard", "envp-guard",
    "argv-string-guard", "envp-string-guard", "valid-missing",
    "null-vectors-missing", "empty-vectors-missing", "over-budget-argv",
)
spec = importlib.util.spec_from_file_location("echo", Path(__file__).with_name("echo_server.py"))
echo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(echo)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def backend_plan(gum_available, reason):
    backends = ("ptrace", "gum") if gum_available else ("ptrace",)
    skipped = [] if gum_available else [
        {"check":"gum."+case,"status":"skip","details":reason}
        for case in ["loader_exit","fast_open","exit_variants","mapping_permissions","execve_errors"]
    ]
    return backends, skipped


def actual_backend_plan():
    # Use the exact read-only classifier used by the enclosing shell Suite.
    script = 'source "$1"; linux_suite_classify_yama; printf "%s\\n%s\\n" "$linux_gum_available" "$linux_gum_reason"'
    result = subprocess.run(["bash","-eu","-c",script,"capability",str(ROOT/"scripts/lib/linux-suite.sh")],check=True,capture_output=True,text=True)
    available,reason=result.stdout.splitlines()
    return backend_plan(available=="1",reason)


def run_suite(hyperhub, output):
    backends, skipped = actual_backend_plan()
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="hyperhub-hook-regressions-") as temporary:
        work = Path(temporary)
        environment = {key: value for key, value in os.environ.items()
                       if key in ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ")}
        for key, name in (("HOME", "user-home"), ("HYPERHUB_HOME", "home"),
                          ("XDG_RUNTIME_DIR", "runtime"), ("TMPDIR", "tmp")):
            directory = work / name
            directory.mkdir(mode=0o700)
            environment[key] = str(directory)
        password = work / "admin-password"
        password.write_text("local-regression-password\n")
        password.chmod(0o600)
        target = work / "mapped-file"
        target.write_bytes(b"local fixture" + bytes(4096))
        mapping_control = work / "mapping-control"
        mapping_control.write_bytes(target.read_bytes())
        port = free_port()
        config_path = work / "config.toml"
        pattern = json.dumps("^" + re.escape(str(target)) + "$")
        exec_denied = json.dumps("^" + re.escape(str(work / "execve_error") + ".policy-denied") + "$")
        config_path.write_text(f"""schema_version = 2
environment_variables = []
[gateway]
mode = "enforce"
debug = false
[gateway.listener]
socks_address = "127.0.0.1:{port}"
pending_session_ttl_seconds = 60
[gateway.audit.settings]
connections = true
retention_days = 7
header_allowlist = []
[gateway.routing.default]
enabled = true
[gateway.routing.default.decision]
action = "allow"
[gateway.trust]
tls_certificates = []
ssh_host_keys = []
[sandbox.network]
enabled = false
default_action = "allow"
error_action = "allow"
rules = []
[sandbox.process]
enabled = true
default_action = "allow"
error_action = "allow"
[[sandbox.process.rules]]
id = "deny-execve-policy-control"
enabled = true
priority = 100
action = "deny"
patterns = [{{enabled = true, executable = {exec_denied}, command_line = ""}}]
[sandbox.file]
enabled = true
default_action = "allow"
error_action = "deny"
[[sandbox.file.rules]]
id = "deny-mapped-read"
enabled = true
priority = 100
action = "deny"
operations = ["read"]
patterns = [{{enabled = true, pattern = {pattern}}}]
""")
        imported = subprocess.run([str(hyperhub), "import", str(config_path), "--admin-password-file", str(password)],
                                  env=environment, capture_output=True, text=True, timeout=20)
        if imported.returncode:
            raise AssertionError(imported.stderr)
        binaries = {}
        for name in ("dns_io", "shared_fd", "fastopen", "mapping_read", "exit", "execve_error"):
            binary = work / name
            subprocess.run(["cc", "-O0", "-Wall", "-Wextra", "-Werror", "-pthread",
                            str(ROOT / "tests/fixtures" / f"linux_{name}_probe.c"), "-o", str(binary)], check=True)
            binaries[name] = binary
        with (output / "serve.log").open("w") as log:
            serve = subprocess.Popen([str(hyperhub), "serve", "--admin-password-file", str(password)],
                                     env=environment, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                while True:
                    status = subprocess.run([str(hyperhub), "status", "--json"], env=environment,
                                            capture_output=True, text=True)
                    if status.returncode == 0 and json.loads(status.stdout).get("state") == "running":
                        break
                    if serve.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError("isolated Serve did not start")
                    time.sleep(0.05)

                def execute(name, arguments, expected=0, backend="ptrace", extra=None, pass_fds=()):
                    env = dict(environment, **(extra or {}))
                    command = [str(hyperhub), "run", "--backend", backend, "--", str(binaries[name]), *arguments]
                    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=20,
                                            pass_fds=pass_fds)
                    item = {"case": name + ":" + ":".join(arguments[::2]), "backend": backend,
                            "arguments": arguments, "expected_returncode": expected,
                            "passed_fds": list(pass_fds), "returncode": result.returncode,
                            "stdout": result.stdout, "stderr": result.stderr}
                    results.append(item)
                    if result.returncode != expected:
                        raise AssertionError(json.dumps(item))
                    return result

                def mapping_case(mode, path, sharing, backend, denied):
                    # Open outside the managed tree. The mapping probe must not
                    # depend on an O_RDWR open that the Read policy now rejects.
                    payload = path.read_bytes()
                    descriptor = os.open(path, os.O_RDWR)
                    try:
                        metadata = os.fstat(descriptor)
                        assert metadata.st_size == len(payload) and len(payload) >= 4096
                        assert os.pread(descriptor, len(payload), 0) == payload
                        assert os.stat(path).st_ino == metadata.st_ino
                        env = {"HH_MAPPING_INHERITED_FD": str(descriptor),
                               "HH_MAPPING_EXPECTED_BYTE": str(payload[0])}
                        result = execute("mapping_read", [mode, str(path), sharing],
                                         13 if denied else 0, backend, extra=env,
                                         pass_fds=(descriptor,))
                        marker = (f"mapping-fd=verified fd={descriptor} device={metadata.st_dev} "
                                  f"inode={metadata.st_ino} size={metadata.st_size}")
                        assert marker in result.stdout, result
                        if mode == "write":
                            assert "write-control=allowed" in result.stdout
                            assert path.read_bytes() == b"x" + payload[1:]
                        else:
                            stage = "mprotect" if mode.startswith("upgrade") else "mmap"
                            outcome = "denied" if denied else "allowed"
                            assert f"read-map={outcome} stage={stage}" in result.stdout, result
                            assert path.read_bytes() == payload
                    finally:
                        os.close(descriptor)

                for backend in backends:
                    execute("exit", ["loader"], 7, backend)
                    # The explicit error_action=allow permits native errors
                    # when metadata is unavailable. A readable denied target
                    # separately proves valid process policy is enforced.
                    for case in (*EXECVE_ERROR_CASES, "policy-deny"):
                        result = execute("execve_error", [case], backend=backend)
                        match = re.search(
                            rf"^{re.escape(case)} native=(-?\d+)/(\d+) libc=(-?\d+)/(\d+) expected=-1/(\d+)$",
                            result.stdout, re.MULTILINE)
                        assert match is not None, result
                        native_result, native_error, libc_result, libc_error, expected_error = map(int, match.groups())
                        assert native_result == libc_result == -1 and libc_error == expected_error, result
                        if case != "policy-deny":
                            assert native_error == libc_error, result

                original_response = echo.dns_response
                echo.dns_response = lambda request: original_response(request)[:-4] + socket.inet_aton(
                    "198.18.99.7" if request[1] == 1 else "198.18.99.8")
                # Preserve request order; each UDP packet carries its own transaction identity.
                echo.DnsServer.process_request = echo.socketserver.UDPServer.process_request
                with echo.EchoServer(("127.0.0.1", 0), echo.EchoHandler) as tcp, echo.DnsServer(
                        ("127.0.0.1", 0), echo.DnsHandler) as dns:
                    servers = (tcp, dns)
                    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
                    for thread in threads:
                        thread.start()
                    try:
                        for mode in ("sendto", "recvmsg", "sendmmsg", "sendmmsg-partial", "writev", "readv", "recvmmsg", "pipeline"):
                            execute("dns_io", [mode, str(dns.server_address[1]), str(tcp.server_address[1])],
                                    extra={"HYPERHUB_DNS_PORTS": str(dns.server_address[1])})
                        ordinary = execute("fastopen", ["connect", str(tcp.server_address[1])])
                        assert f"kernel_peer_port={port} " in ordinary.stdout
                        for backend in backends:
                            for mode in ("sendto", "sendmsg"):
                                denied = execute("fastopen", [mode, str(tcp.server_address[1])], 0, backend)
                                assert "fastopen=unsupported" in denied.stdout
                    finally:
                        for server in servers:
                            server.shutdown()
                        for thread in threads:
                            thread.join()
                for mode in ("shared", "copy", "unshare", "exec", "thread-exec"):
                    execute("shared_fd", [mode])
                for backend in backends:
                    for mode in ("return", "exit", "_exit", "_Exit"):
                        execute("exit", [mode], 7, backend)
                for backend in backends:
                    for shared in ("private", "shared"):
                        for mode in ("read", "upgrade", "write-map", "upgrade-write"):
                            mapping_case(mode, target, shared, backend, True)
                            mapping_case(mode, mapping_control, shared, backend, False)
                        mapping_case("write", target, shared, backend, False)
                # Audit destinations, not just successful echo payloads or hook counts.
                audit = []
                for path in (work / "home/audit").rglob("security-alerts.jsonl"):
                    audit.extend(json.loads(line) for line in path.read_text().splitlines())
                connections = [item for item in audit if item.get("event") == "connect"
                               and item.get("process_executable") == str(binaries["dns_io"])]
                assert len(connections) == 8, connections
                assert all(item.get("destination_hostname") == "localhost" for item in connections), connections
                fast = [item for item in audit if item.get("event") == "connect"
                        and item.get("process_executable") == str(binaries["fastopen"])]
                assert len(fast) == 1, fast
            finally:
                serve.terminate()
                try:
                    serve.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    serve.kill()
                    serve.wait()
                (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    status="partial" if skipped else "pass"
    (output/"coverage.json").write_text(json.dumps({"status":status,"coverage_complete":not skipped,"executed_cases":len(results),"skipped_checks":skipped},indent=2)+"\n")
    print(f"Hook semantic regressions {status}: {len(results)} executed cases, {len(skipped)} skipped groups")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hyperhub", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    run_suite(arguments.hyperhub.resolve(), arguments.output.resolve())
