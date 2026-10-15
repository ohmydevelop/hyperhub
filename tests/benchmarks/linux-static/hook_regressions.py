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
spec = importlib.util.spec_from_file_location("echo", Path(__file__).with_name("echo_server.py"))
echo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(echo)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run_suite(hyperhub, output):
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="hyperhub-hook-regressions-") as temporary:
        work = Path(temporary)
        environment = dict(os.environ, HYPERHUB_HOME=str(work / "home"))
        password = work / "admin-password"
        password.write_text("local-regression-password\n")
        password.chmod(0o600)
        target = work / "mapped-file"
        target.write_bytes(b"local fixture" + bytes(4096))
        port = free_port()
        config_path = work / "config.toml"
        pattern = json.dumps("^" + re.escape(str(target)) + "$")
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
enabled = false
default_action = "allow"
error_action = "allow"
rules = []
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
        for name in ("dns_io", "shared_fd", "fastopen", "mapping_read", "exit"):
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

                def execute(name, arguments, expected=0, backend="ptrace", extra=None):
                    env = dict(environment, **(extra or {}))
                    command = [str(hyperhub), "run", "--backend", backend, "--password-file",
                               str(work / "home/runtime/api-key"), "--", str(binaries[name]), *arguments]
                    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=20)
                    item = {"case": name + ":" + ":".join(arguments[::2]), "backend": backend,
                            "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
                    results.append(item)
                    if result.returncode != expected:
                        raise AssertionError(json.dumps(item))
                    return result

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
                        for backend in ("ptrace", "gum"):
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
                for backend in ("ptrace", "gum"):
                    for mode in ("return", "exit", "_exit", "_Exit"):
                        execute("exit", [mode], 7, backend)
                for backend in ("ptrace", "gum"):
                    for shared in ("private", "shared"):
                        for mode in ("read", "upgrade", "write-map", "upgrade-write"):
                            denied = execute("mapping_read", [mode, str(target), shared], 13, backend)
                            assert "read-map=denied" in denied.stdout
                        execute("mapping_read", ["write", str(target), shared], 0, backend)
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
    print(f"Hook semantic regressions passed: {len(results)} cases")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hyperhub", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    run_suite(arguments.hyperhub.resolve(), arguments.output.resolve())
