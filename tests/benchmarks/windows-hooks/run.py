#!/usr/bin/env python3
"""Native-versus-managed asynchronous DNS and ConnectEx source regressions."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("echo", ROOT / "tests/benchmarks/linux-static/echo_server.py")
echo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(echo)


def run(hyperhub, probe, output):
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="hyperhub-windows-hooks-") as temporary:
        work = Path(temporary)
        environment = dict(os.environ, HYPERHUB_HOME=str(work / "home"), HYPERHUB_AGENT_DEBUG="1",
                           HYPERHUB_AGENT_INIT_LOG=str(output / "agent-init.log"))
        password = work / "admin-password"
        password.write_text("local-windows-regression-password\n")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = work / "config.toml"
        config.write_text(f'''schema_version = 2
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
[sandbox.file]
enabled = false
default_action = "allow"
error_action = "allow"
rules = []
[sandbox.process]
enabled = false
default_action = "allow"
error_action = "allow"
rules = []
''')
        imported = subprocess.run([str(hyperhub), "import", str(config), "--admin-password-file", str(password)],
                                  env=environment, capture_output=True, text=True, timeout=30)
        assert imported.returncode == 0, imported.stderr
        with (output / "serve.log").open("w") as log:
            serve = subprocess.Popen([str(hyperhub), "serve", "--admin-password-file", str(password)],
                                     env=environment, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while True:
                    state = subprocess.run([str(hyperhub), "status", "--json"], env=environment,
                                           capture_output=True, text=True)
                    if state.returncode == 0 and json.loads(state.stdout).get("state") == "running":
                        break
                    assert serve.poll() is None and time.monotonic() < deadline, "Serve did not start"
                    time.sleep(0.05)
                with echo.EchoServer(("127.0.0.1", 0), echo.EchoHandler) as server:
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    try:
                        # Fixed exploration budget, never retry a failed process.
                        # Each concurrent process issues 256 requests then calls
                        # WSACleanup immediately. Fresh processes exercise exit
                        # and teardown independently of caller-storage reuse.
                        modes = [(mode, 0) for mode in (
                            "dns-event", "dns-poll", "dns-callback", "dns-cancel",
                            "dns-cancel-callback", "dns-cancel-poll",
                            "connectex-empty", "connectex-data")]
                        modes.extend(("dns-cancel-concurrent", index) for index in range(8))
                        for managed in (False, True):
                            for mode, iteration in modes:
                                command = [str(probe), mode, str(server.server_address[1])]
                                if managed:
                                    command = [str(hyperhub), "run", "--", *command]
                                try:
                                    result = subprocess.run(command, env=environment, capture_output=True,
                                                            text=True, timeout=60)
                                except subprocess.TimeoutExpired as error:
                                    decode = lambda value: value.decode(errors="replace") if isinstance(value, bytes) else value or ""
                                    item = {"mode": mode, "iteration": iteration, "managed": managed,
                                            "exit_code": None, "timed_out": True,
                                            "stdout": decode(error.stdout), "stderr": decode(error.stderr)}
                                    results.append(item)
                                    raise AssertionError("Windows Hook target exceeded 60 seconds", item) from error
                                item = {"mode": mode, "iteration": iteration, "managed": managed,
                                        "exit_code": result.returncode, "stdout": result.stdout,
                                        "stderr": result.stderr}
                                results.append(item)
                                assert result.returncode == 0, item
                                assert "dns_cleanup stage=done" in result.stderr, item
                                if mode.startswith("dns-cancel"):
                                    expected = 256 if mode == "dns-cancel-concurrent" else 64
                                    item["terminal_count"] = result.stdout.count("dns=terminal status=")
                                    item["cancel_accepted_count"] = result.stdout.count("cancel_status=0\n")
                                    assert item["terminal_count"] == expected, item
                                    assert item["cancel_accepted_count"] > 0, (
                                        "Cancellation did not occur; coverage is unproven", item)
                                marker = ("connectex=unsupported-initial-data" if managed and mode == "connectex-data"
                                          else "dns=terminal" if mode.startswith("dns-cancel")
                                          else "dns=ok" if mode.startswith("dns-") else "connectex=ok")
                                assert marker in result.stdout, item
                    finally:
                        server.shutdown()
                        thread.join()
                audit = []
                for path in (work / "home/audit").rglob("security-alerts.jsonl"):
                    audit.extend(json.loads(line) for line in path.read_text().splitlines())
                (output / "audit.json").write_text(json.dumps(audit, indent=2) + "\n")
                dns = [entry for entry in audit if entry.get("event") == "connect"
                       and entry.get("destination_hostname") == "localhost"]
                assert len(dns) == 3, f"async DNS connections lost hostname attribution: {audit}"
                assert len({entry["session_id"] for entry in dns}) == 3, "DNS modes did not each reach the gateway"
                connections = [entry for entry in audit if entry.get("event") == "connect"]
                assert len(connections) == 4, f"unexpected managed connection side effects: {connections}"
            finally:
                serve.terminate()
                try:
                    serve.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    serve.kill()
                    serve.wait()
                (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"Windows Hook semantic regressions passed: {len(results)} cases")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hyperhub", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.hyperhub.resolve(), args.probe.resolve(), args.output.resolve())
