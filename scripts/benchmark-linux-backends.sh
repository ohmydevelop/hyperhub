#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hyperhub="$root/target/release/hyperhub"
result_dir="$root/target/benchmarks/linux-backends"
fixture_dir=
iterations=1
include_large=0
rebuild_fixtures=0
build_release=1

usage() {
  cat <<'USAGE'
usage: scripts/benchmark-linux-backends.sh [options]

Build HyperHub when needed, reuse versioned benchmark fixtures, and execute the
complete Linux ptrace-baseline/explicit-Gum functional and performance suite.

options:
  --iterations N       measured launches per workload (default: 1)
  --output DIR         suite result directory (default: target/benchmarks/linux-backends)
  --fixtures DIR       reusable fixture cache
  --hyperhub PATH      HyperHub CLI path
  --full               include BusyBox, gh, yq, and ripgrep performance workloads
  --rebuild-fixtures   force regeneration of cached fixture binaries
  --skip-build         use the supplied/existing CLI and Agent without cargo build
  -h, --help           show this help
USAGE
}

while (($#)); do
  case "$1" in
    --iterations)
      [[ $# -ge 2 ]] || { echo 'missing value for --iterations' >&2; exit 2; }
      iterations=$2
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || { echo 'missing value for --output' >&2; exit 2; }
      result_dir=$2
      shift 2
      ;;
    --fixtures)
      [[ $# -ge 2 ]] || { echo 'missing value for --fixtures' >&2; exit 2; }
      fixture_dir=$2
      shift 2
      ;;
    --hyperhub)
      [[ $# -ge 2 ]] || { echo 'missing value for --hyperhub' >&2; exit 2; }
      hyperhub=$2
      shift 2
      ;;
    --full)
      include_large=1
      shift
      ;;
    --rebuild-fixtures)
      rebuild_fixtures=1
      shift
      ;;
    --skip-build)
      build_release=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ $iterations =~ ^[1-9][0-9]*$ ]] || { echo '--iterations must be a positive integer' >&2; exit 2; }
case "$(uname -m)" in
  x86_64) architecture=x86_64 ;;
  aarch64|arm64) architecture=aarch64 ;;
  *) echo "unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac
[[ -n $fixture_dir ]] || fixture_dir="$root/target/benchmarks/linux-fixtures/$architecture"

for command in openssl ssh ssh-keygen sshd; do
  command -v "$command" >/dev/null 2>&1 || { echo "required command is unavailable: $command" >&2; exit 1; }
done

if ((build_release)); then
  cd "$root"
  mapfile -t devkits < <("$root/scripts/frida-devkit.sh" "$architecture")
  export HYPERHUB_FRIDA_GUM_ROOT=${devkits[0]}
  export HYPERHUB_FRIDA_CORE_ROOT=${devkits[1]}
  compiler_include=$(cc -print-file-name=include)
  export BINDGEN_EXTRA_CLANG_ARGS="-I$HYPERHUB_FRIDA_CORE_ROOT -isystem $compiler_include ${BINDGEN_EXTRA_CLANG_ARGS:-}"
  cargo build --release --locked -p hyperhub-agent-core --features gum-agent
  export HYPERHUB_EMBEDDED_AGENT_PATH="$root/target/release/libhyperhub_gum_agent.so"
  cargo build --release --locked -p hyperhub --no-default-features --features embedded-agent
fi

[[ -x $hyperhub ]] || { echo "HyperHub is not executable: $hyperhub" >&2; exit 1; }
hyperhub=$(realpath "$hyperhub")

original_home=$HOME
original_rustup_home=${RUSTUP_HOME:-"$original_home/.rustup"}
original_cargo_home=${CARGO_HOME:-"$original_home/.cargo"}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/hyperhub-static-coverage.XXXXXX")
serve_pid=
echo_pid=
credential_pid=
trust_tls_pid=
trust_ssh_pid=
hot_update_pid=
cleanup() {
    [[ -z $hot_update_pid ]] || { kill "$hot_update_pid" 2>/dev/null || true; wait "$hot_update_pid" 2>/dev/null || true; }
  [[ -z $trust_ssh_pid ]] || { kill "$trust_ssh_pid" 2>/dev/null || true; wait "$trust_ssh_pid" 2>/dev/null || true; }
  [[ -z $trust_tls_pid ]] || { kill "$trust_tls_pid" 2>/dev/null || true; wait "$trust_tls_pid" 2>/dev/null || true; }
  [[ -z $credential_pid ]] || { kill "$credential_pid" 2>/dev/null || true; wait "$credential_pid" 2>/dev/null || true; }
  [[ -z $echo_pid ]] || { kill "$echo_pid" 2>/dev/null || true; wait "$echo_pid" 2>/dev/null || true; }
  [[ -z $serve_pid ]] || { kill "$serve_pid" 2>/dev/null || true; wait "$serve_pid" 2>/dev/null || true; }
  python3 - "$temporary" <<'PY'
import pathlib
import shutil
import sys
shutil.rmtree(pathlib.Path(sys.argv[1]), ignore_errors=True)
PY
}
trap cleanup EXIT INT TERM

export RUSTUP_HOME=$original_rustup_home
export CARGO_HOME=$original_cargo_home
mkdir -p "$result_dir" "$fixture_dir"
result_dir=$(cd "$result_dir" && pwd)
fixture_dir=$(cd "$fixture_dir" && pwd)
checks_file="$result_dir/checks.tsv"
printf 'check\tstatus\tdetails\n' > "$checks_file"
record_check() {
  local name=$1 details=${2:-}
  details=${details//$'\t'/ }
  details=${details//$'\n'/ }
  printf '%s\tpass\t%s\n' "$name" "$details" >> "$checks_file"
}
password_file="$temporary/password"
printf 'static-coverage-password\n' > "$password_file"
chmod 0600 "$password_file"

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
}

start_serve() {
  local stdout=$1 stderr=$2
  "$hyperhub" serve --password-file "$password_file" >"$stdout" 2>"$stderr" &
  serve_pid=$!
  for ((attempt = 0; attempt < 100; attempt++)); do
    status=$("$hyperhub" status --json 2>/dev/null || true)
    if grep -Eq '"state"[[:space:]]*:[[:space:]]*"running"' <<<"$status" \
      && grep -Eq '"pid"[[:space:]]*:[[:space:]]*'"$serve_pid"'([,[:space:]}]|$)' <<<"$status"; then
      return
    fi
    kill -0 "$serve_pid" 2>/dev/null || {
      cat "$stderr" >&2
      echo 'HyperHub Serve exited during static coverage test' >&2
      exit 1
    }
    sleep 0.05
  done
  echo 'timed out waiting for HyperHub Serve' >&2
  exit 1
}

stop_serve() {
  [[ -z $serve_pid ]] && return
  kill "$serve_pid" 2>/dev/null || true
  wait "$serve_pid" 2>/dev/null || true
  serve_pid=
}

write_base_config() {
  local path=$1 port=$2
  cat > "$path" <<TOML
schema_version = 2
environment_variables = []

[gateway]
mode = "enforce"
debug = false

[gateway.listener]
socks_address = "127.0.0.1:$port"
pending_session_ttl_seconds = 60

[gateway.audit.settings]
retention_days = 7
connections = true
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
TOML
}

export HOME="$temporary/pass-home"
mkdir -p "$HOME"
config_file="$temporary/pass.toml"
write_base_config "$config_file" "$(free_port)"
"$hyperhub" import "$config_file" --password-file "$password_file" >/dev/null
start_serve "$temporary/pass-serve.stdout.log" "$temporary/pass-serve.stderr.log"

benchmark_args=(
  --iterations "$iterations"
  --output "$result_dir"
  --fixtures "$fixture_dir"
  --hyperhub "$hyperhub"
  --password-file "$password_file"
)
((include_large)) || benchmark_args+=(--skip-large)
((rebuild_fixtures)) && benchmark_args+=(--rebuild-fixtures)
"$root/scripts/benchmark-linux-static.sh" "${benchmark_args[@]}"
record_check performance.workloads "iterations=$iterations large=$include_large"

python3 - "$result_dir/summary.csv" <<'PY'
import csv
import pathlib
import sys
rows = list(csv.DictReader(pathlib.Path(sys.argv[1]).open(encoding="utf-8")))
if not {"c", "go", "rust"}.issubset({row["workload"] for row in rows}):
    raise SystemExit("Linux backend benchmark summary is incomplete")
if any(not row["hyperhub_median_ms"] for row in rows):
    raise SystemExit("static coverage did not produce HyperHub measurements")
PY

# Copy the single-file CLI away from the build tree. The default dynamic/static
# backend must remain ptrace, while explicit Gum must use the embedded Agent
# without relying on a sidecar runtime or discovery path.
standalone_hyperhub="$temporary/hyperhub-embedded-agent"
cp "$hyperhub" "$standalone_hyperhub"
chmod 0755 "$standalone_hyperhub"
(
  cd "$temporary"
  "$standalone_hyperhub" run \
    --password-file "$password_file" \
    -- /bin/true >/dev/null
  "$standalone_hyperhub" run \
    --backend gum \
    --password-file "$password_file" \
    -- /bin/true >/dev/null 2>"$temporary/dynamic-embedded-runtime.stderr.log"
  "$standalone_hyperhub" run \
    --password-file "$password_file" \
    -- "$fixture_dir/linux-static-c" --intent-read /etc/hosts >/dev/null
)
record_check backend.runtime_boundary "dynamic/static default ptrace; explicit Gum uses embedded Agent"

pass_audit=$(find "$HOME/.hyperhub/audit" -name hyperhub.jsonl -type f -print -quit)
[[ -n $pass_audit ]] || { echo 'static coverage audit was not created' >&2; exit 1; }
connections=$(grep -c '"event":"connect"' "$pass_audit" || true)
if ((connections < 6)); then
  echo "expected at least 6 audited static connections, got $connections" >&2
  exit 1
fi
if ! grep -q '"destination_hostname":"localhost"' "$pass_audit"; then
  echo 'static DNS correlation did not restore localhost in connection audit' >&2
  exit 1
fi
record_check static.connections "audited=$connections"
record_check static.dns "localhost restored"

# Run the adversarial C fixture once with hook coverage accounting enabled.
ports_file="$temporary/hook-ports"
: > "$ports_file"
python3 "$root/tests/benchmarks/linux-static/echo_server.py" "$ports_file" &
echo_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -s $ports_file ]] && break
  sleep 0.05
done
read -r echo_port dns_port < "$ports_file"
dynamic_probe="$fixture_dir/linux-dynamic-probe"
dynamic_source="$root/tests/fixtures/linux_probe.c"
hot_update_probe="$fixture_dir/linux-ptrace-hot-update-probe"
hot_update_source="$root/tests/fixtures/linux_ptrace_hot_update_probe.c"
if ((rebuild_fixtures)) || [[ ! -x $dynamic_probe || $dynamic_source -nt $dynamic_probe ]]; then
  cc -O2 -Wall -Wextra "$dynamic_source" -o "$dynamic_probe"
fi
if ((rebuild_fixtures)) || [[ ! -x $hot_update_probe || $hot_update_source -nt $hot_update_probe ]]; then
  cc -O2 -Wall -Wextra "$hot_update_source" -o "$hot_update_probe"
fi
python3 - "$fixture_dir/manifest.json" "$dynamic_probe" "$hot_update_probe" <<'PYCODE'
import hashlib
import json
import pathlib
import sys
manifest_path = pathlib.Path(sys.argv[1])
binaries = {
    "dynamic-c": ("dynamic-probe", pathlib.Path(sys.argv[2])),
    "ptrace-hot-update": ("dynamic-probe", pathlib.Path(sys.argv[3])),
}
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["fixtures"] = [
    fixture for fixture in manifest["fixtures"] if fixture["workload"] not in binaries
]
for workload, (kind, binary) in binaries.items():
    manifest["fixtures"].append(
        {
            "workload": workload,
            "kind": kind,
            "path": str(binary),
            "bytes": binary.stat().st_size,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
    )
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PYCODE
"$hyperhub" run \
  --backend ptrace \
  --password-file "$password_file" \
  -- "$dynamic_probe" 127.0.0.1 "$echo_port" \
  >/dev/null 2>"$temporary/dynamic-ptrace.stderr.log"
record_check dynamic.ptrace_descendants "fork+exec,posix_spawn,posix_spawnp"

dynamic_hook_report="$result_dir/dynamic-hooks.json"
HYPERHUB_AGENT_DEBUG=1 \
HYPERHUB_DYNAMIC_HOOK_REPORT=$dynamic_hook_report \
  "$hyperhub" run \
    --backend gum \
    --password-file "$password_file" \
    -- "$dynamic_probe" 127.0.0.1 "$echo_port" \
    >/dev/null 2>"$temporary/dynamic-probe.stderr.log"
if ! grep -q 'Linux hooks installed=25 optional_missing=0 manifest=25' \
  "$temporary/dynamic-probe.stderr.log"; then
  cat "$temporary/dynamic-probe.stderr.log" >&2
  echo 'dynamic Linux Hook manifest was not fully installed' >&2
  exit 1
fi
python3 - "$dynamic_hook_report" <<'PY'
import json
import pathlib
import sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["missing_required"]:
    raise SystemExit(f"missing dynamic hook groups: {report['missing_required']}")
PY
record_check dynamic.gum_manifest "report=$dynamic_hook_report"

hook_report="$result_dir/hooks.json"
HYPERHUB_DNS_PORTS=$dns_port \
HYPERHUB_STATIC_HOOK_REPORT=$hook_report \
HYPERHUB_STATIC_REQUIRE_ALL_HOOKS=1 \
  "$hyperhub" run \
    --password-file "$password_file" \
    -- "$fixture_dir/linux-static-c" 127.0.0.1 "$echo_port" "$dns_port" >/dev/null
kill "$echo_pid" 2>/dev/null || true
wait "$echo_pid" 2>/dev/null || true
echo_pid=
python3 - "$hook_report" <<'PY'
import json
import pathlib
import sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["missing_required"]:
    raise SystemExit(f"missing static hook points: {report['missing_required']}")
PY
record_check static.ptrace_manifest "report=$hook_report"
stop_serve

# Reproduce the dynamic ptrace route-refinement bug with a source fixture. The
# client connects to localhost by IP at the syscall boundary; only the HTTP Host
# and path reveal the credential route.
export HOME="$temporary/credential-home"
mkdir -p "$HOME"
credential_ports="$temporary/credential-port"
: > "$credential_ports"
credential_secret=benchmark-local-secret
python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  --server "$credential_ports" "$credential_secret" &
credential_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -s $credential_ports ]] && break
  sleep 0.05
done
[[ -s $credential_ports ]] || { echo 'HTTP credential fixture did not publish its port' >&2; exit 1; }
credential_port=$(cat "$credential_ports")
credential_config="$temporary/credential.toml"
write_base_config "$credential_config" "$(free_port)"
cat >> "$credential_config" <<TOML

[[gateway.credentials]]
id = "benchmark-http-bearer"
type = "http_bearer"
secret = { value = "$credential_secret" }

[[gateway.routing.routes]]
id = "benchmark-http-route"
enabled = true
priority = 500
endpoints = [{ target = "http://localhost/probe", port = $credential_port }]
[gateway.routing.routes.decision]
action = "allow"
credentials = ["benchmark-http-bearer"]
TOML
"$hyperhub" import "$credential_config" --password-file "$password_file" >/dev/null
start_serve "$temporary/credential-serve.stdout.log" "$temporary/credential-serve.stderr.log"
"$hyperhub" run \
  --backend ptrace \
  --password-file "$password_file" \
  -- python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  localhost "$credential_port"
wait "$credential_pid"
credential_pid=
credential_audit=$(find "$HOME/.hyperhub/audit" -name hyperhub.jsonl -type f -print -quit)
[[ -n $credential_audit ]] || { echo 'credential regression audit was not created' >&2; exit 1; }
grep -q '"rule_id":"benchmark-http-route"' "$credential_audit" || {
  cat "$credential_audit" >&2
  echo 'ptrace protocol refinement did not select the HTTP credential route' >&2
  exit 1
}
record_check dynamic.ptrace_http_credential "route=benchmark-http-route"
stop_serve

# A long-running ptrace target must receive file/process sandbox changes without
# being restarted. This guards parity with Gum's versioned sandbox subscription.
export HOME="$temporary/hot-update-home"
mkdir -p "$HOME" "$temporary/hot-update"
hot_target="$temporary/hot-update/target.txt"
printf 'hot-update-target\n' > "$hot_target"
hot_config="$temporary/hot-update/config.toml"
write_base_config "$hot_config" "$(free_port)"
"$hyperhub" import "$hot_config" --password-file "$password_file" >/dev/null
start_serve "$temporary/hot-update-serve.stdout.log" "$temporary/hot-update-serve.stderr.log"
hot_fifo="$temporary/hot-update/commands.fifo"
hot_output="$temporary/hot-update/output.log"
mkfifo "$hot_fifo"
exec 9<>"$hot_fifo"
"$hyperhub" run --backend ptrace --password-file "$password_file" -- \
  "$hot_update_probe" "$hot_target" /usr/bin/true \
  <&9 >"$hot_output" 2>"$temporary/hot-update/target.stderr.log" &
hot_update_pid=$!
wait_for_hot_line() {
  local pattern=$1 expected=$2
  for ((attempt = 0; attempt < 200; attempt++)); do
    count=$(grep -Ec "$pattern" "$hot_output" 2>/dev/null || true)
    ((count >= expected)) && return
    kill -0 "$hot_update_pid" 2>/dev/null || {
      cat "$hot_output" >&2
      cat "$temporary/hot-update/target.stderr.log" >&2
      echo "ptrace hot-update fixture exited before '$pattern'" >&2
      exit 1
    }
    sleep 0.025
  done
  cat "$hot_output" >&2
  echo "timed out waiting for ptrace hot-update result '$pattern'" >&2
  exit 1
}
wait_for_hot_line '^ready$' 1
printf 'read\n' >&9
wait_for_hot_line '^read:ok$' 1
printf 'hold\n' >&9
wait_for_hot_line '^hold:ok$' 1
printf 'exec\n' >&9
wait_for_hot_line '^exec:ok$' 1
printf 'spawn\n' >&9
wait_for_hot_line '^spawn:ok$' 1
hot_patch="$temporary/hot-update/patch.json"
python3 - "$hot_patch" "$hot_target" <<'PYCODE'
import json, pathlib, re, sys
path = pathlib.Path(sys.argv[1])
target = sys.argv[2]
patch = [
    {
        "op": "replace",
        "path": "/sandbox/file",
        "value": {
            "enabled": True,
            "default_action": "allow",
            "error_action": "deny",
            "rules": [{
                "uuid": "11111111-1111-4111-8111-111111111111",
                "id": "deny-hot-read",
                "enabled": True,
                "priority": 100,
                "action": "deny",
                "patterns": [{"enabled": True, "pattern": f"^{re.escape(target)}$"}],
                "operations": ["read"],
            }],
        },
    },
    {
        "op": "replace",
        "path": "/sandbox/process",
        "value": {
            "enabled": True,
            "default_action": "allow",
            "error_action": "deny",
            "rules": [{
                "uuid": "22222222-2222-4222-8222-222222222222",
                "id": "deny-hot-exec",
                "enabled": True,
                "priority": 100,
                "action": "deny",
                "patterns": [{"enabled": True, "executable": "^/usr/bin/true$", "command_line": ""}],
            }],
        },
    },
]
path.write_text(json.dumps(patch, indent=2) + "\n", encoding="utf-8")
PYCODE
"$hyperhub" config patch "$hot_patch" \
  >"$temporary/hot-update/patch.out"
python3 - "$hyperhub" "$password_file" "$temporary/hot-update/approve.log" <<'PYCODE'
import os, pathlib, pty, select, subprocess, sys, time
binary, password, log_path = sys.argv[1:]
master, slave = pty.openpty()
process = subprocess.Popen(
    [binary, "approve", "--password-file", password],
    stdin=slave,
    stdout=slave,
    stderr=slave,
    env=os.environ.copy(),
    close_fds=True,
)
os.close(slave)
os.write(master, b"a\na\n")
output = bytearray()
deadline = time.monotonic() + 30
while process.poll() is None:
    if time.monotonic() > deadline:
        process.kill()
        raise SystemExit("approve timed out")
    ready, _, _ = select.select([master], [], [], 0.2)
    if ready:
        try:
            output.extend(os.read(master, 65536))
        except OSError:
            pass
process.wait()
pathlib.Path(log_path).write_bytes(output)
os.close(master)
if process.returncode != 0:
    raise SystemExit(f"approve failed with {process.returncode}")
PYCODE
printf 'read\n' >&9
wait_for_hot_line '^read:denied:' 1
printf 'held-read\n' >&9
wait_for_hot_line '^held-read:denied:' 1
printf 'exec\n' >&9
wait_for_hot_line '^exec:denied:' 1
printf 'spawn\n' >&9
wait_for_hot_line '^spawn:denied:' 1
printf 'quit\n' >&9
exec 9>&-
wait "$hot_update_pid"
hot_update_pid=
hot_audit=$(find "$HOME/.hyperhub/audit" -name hyperhub.jsonl -type f -print -quit)
[[ $(grep -c '"event":"sandbox_denied"' "$hot_audit" || true) -ge 4 ]] || {
  cat "$hot_audit" >&2
  echo 'ptrace hot-update denials were not audited' >&2
  exit 1
}
record_check sandbox.ptrace_hot_update "same_pid open+held-fd+fork-exec+posix_spawn allow->deny"
stop_serve

# Trust-on-first-use regression: a self-signed TLS leaf is pinned to the exact
# host:port, reused on the second visit, and rejected after certificate rotation.
export HOME="$temporary/trust-home"
mkdir -p "$HOME" "$temporary/trust"
trust_tls_port_file="$temporary/trust/tls-port"
: > "$trust_tls_port_file"
trust_tls_key="$temporary/trust/tls-key.pem"
trust_tls_cert="$temporary/trust/tls-cert.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout "$trust_tls_key" -out "$trust_tls_cert" >/dev/null 2>&1
python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  --tls-server "$trust_tls_port_file" placeholder-token "$trust_tls_cert" "$trust_tls_key" &
trust_tls_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -s $trust_tls_port_file ]] && break
  sleep 0.05
done
trust_tls_port=$(cat "$trust_tls_port_file")
trust_ssh_port=$(free_port)
trust_config="$temporary/trust.toml"
write_base_config "$trust_config" "$(free_port)"
cat >> "$trust_config" <<TOML

[[gateway.audit.profiles]]
id = "trust-http-audit"
protocols = ["http"]
[gateway.audit.profiles.capture]
http_body = false
body_limit_bytes = 1048576
git_transcript = false
ssh_transcript = false
websocket = "off"
[gateway.audit.profiles.capture.directions]
client_upload = true
server_response = true

[[gateway.routing.routes]]
id = "trust-tls-route"
enabled = true
priority = 600
endpoints = [{ target = "https://localhost/probe", port = $trust_tls_port }]
[gateway.routing.routes.decision]
action = "allow"
audit_profiles = ["trust-http-audit"]

[[gateway.routing.routes]]
id = "trust-ssh-route"
enabled = true
priority = 600
endpoints = [{ target = "localhost", port = $trust_ssh_port }]
[gateway.routing.routes.decision]
action = "allow"
TOML
"$hyperhub" import "$trust_config" --password-file "$password_file" >/dev/null
start_serve "$temporary/trust-serve.stdout.log" "$temporary/trust-serve.stderr.log"
"$hyperhub" run --backend ptrace --password-file "$password_file" -- \
  python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  --tls-client localhost "$trust_tls_port"
wait "$trust_tls_pid"
trust_tls_pid=
python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  --tls-server "$trust_tls_port_file" placeholder-token "$trust_tls_cert" "$trust_tls_key" &
trust_tls_pid=$!
"$hyperhub" run --backend ptrace --password-file "$password_file" -- \
  python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  --tls-client localhost "$trust_tls_port"
wait "$trust_tls_pid"
trust_tls_pid=
"$hyperhub" show > "$temporary/trust-show.json"
python3 - "$temporary/trust-show.json" "$trust_tls_port" <<'PYCODE'
import json, pathlib, sys
config = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
authority = f"localhost:{sys.argv[2]}"
certificates = config["gateway"]["trust"]["tls_certificates"]
assert any(item.get("scope", {}).get("authority") == authority and item.get("enabled") for item in certificates), (authority, certificates)
PYCODE
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout "$trust_tls_key" -out "$trust_tls_cert" >/dev/null 2>&1
python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  --tls-server "$trust_tls_port_file" placeholder-token "$trust_tls_cert" "$trust_tls_key" &
trust_tls_pid=$!
set +e
"$hyperhub" run --backend ptrace --password-file "$password_file" -- \
  python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  --tls-client localhost "$trust_tls_port" >/dev/null 2>"$temporary/trust-tls-rotated.stderr.log"
rotated_tls_status=$?
set -e
wait "$trust_tls_pid" 2>/dev/null || true
trust_tls_pid=
((rotated_tls_status != 0)) || { echo 'rotated TLS certificate was unexpectedly trusted' >&2; exit 1; }
record_check trust.tls_tofu "authority=localhost:$trust_tls_port rotation=rejected"

# SSH uses the same TOFU rule: first key is persisted, the same key is accepted,
# and a replacement key for the exact host:port is rejected and audited.
sshd_bin=$(command -v sshd)
trust_ssh_dir="$temporary/trust/ssh"
mkdir -p "$trust_ssh_dir"
ssh-keygen -q -t ed25519 -N '' -f "$trust_ssh_dir/host-key"
cat > "$trust_ssh_dir/sshd_config" <<EOFSSH
Port $trust_ssh_port
ListenAddress 127.0.0.1
HostKey $trust_ssh_dir/host-key
PidFile $trust_ssh_dir/sshd.pid
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin no
StrictModes no
LogLevel ERROR
EOFSSH
"$sshd_bin" -D -e -f "$trust_ssh_dir/sshd_config" >"$temporary/trust-sshd.log" 2>&1 &
trust_ssh_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  (echo >/dev/tcp/127.0.0.1/$trust_ssh_port) >/dev/null 2>&1 && break
  sleep 0.05
done
set +e
"$hyperhub" run --backend ptrace --password-file "$password_file" -- \
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -p "$trust_ssh_port" nobody@localhost true \
  >/dev/null 2>"$temporary/trust-ssh-first.stderr.log"
set -e
"$hyperhub" show > "$temporary/trust-show-ssh.json"
python3 - "$temporary/trust-show-ssh.json" "$trust_ssh_port" <<'PYCODE'
import json, pathlib, sys
config = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
authority = f"127.0.0.1:{sys.argv[2]}"
keys = config["gateway"]["trust"]["ssh_host_keys"]
assert any(item.get("host") == authority and item.get("enabled") for item in keys), (authority, keys)
PYCODE
kill "$trust_ssh_pid"
wait "$trust_ssh_pid" 2>/dev/null || true
trust_ssh_pid=
ssh-keygen -q -t ed25519 -N '' -f "$trust_ssh_dir/host-key-rotated"
sed -i "s#HostKey .*#HostKey $trust_ssh_dir/host-key-rotated#" "$trust_ssh_dir/sshd_config"
"$sshd_bin" -D -e -f "$trust_ssh_dir/sshd_config" >>"$temporary/trust-sshd.log" 2>&1 &
trust_ssh_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  (echo >/dev/tcp/127.0.0.1/$trust_ssh_port) >/dev/null 2>&1 && break
  sleep 0.05
done
set +e
"$hyperhub" run --backend ptrace --password-file "$password_file" -- \
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -p "$trust_ssh_port" nobody@localhost true \
  >/dev/null 2>"$temporary/trust-ssh-rotated.stderr.log"
set -e
kill "$trust_ssh_pid"
wait "$trust_ssh_pid" 2>/dev/null || true
trust_ssh_pid=
trust_audit=$(find "$HOME/.hyperhub/audit" -name hyperhub.jsonl -type f -print -quit)
grep -q '"outcome":"ssh_host_key_mismatch"' "$trust_audit" || {
  cat "$trust_audit" >&2
  echo 'rotated SSH host key was not rejected' >&2
  exit 1
}
record_check trust.ssh_tofu "authority=127.0.0.1:$trust_ssh_port rotation=rejected"
stop_serve

# Enable file and process sandbox rules and verify every configured intent is denied.
export HOME="$temporary/deny-home"
mkdir -p "$HOME" "$temporary/intents"
for name in read write delete rename-old; do
  printf 'intent\n' > "$temporary/intents/$name"
done
sandbox_config="$temporary/sandbox.toml"
write_base_config "$sandbox_config" "$(free_port)"
python3 - "$sandbox_config" <<'PYCODE'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace("[sandbox.file]\nenabled = false\ndefault_action = \"allow\"\nerror_action = \"allow\"\nrules = []", "[sandbox.file]\nenabled = true\ndefault_action = \"allow\"\nerror_action = \"deny\"")
text = text.replace("[sandbox.process]\nenabled = false\ndefault_action = \"allow\"\nerror_action = \"allow\"\nrules = []", "[sandbox.process]\nenabled = true\ndefault_action = \"allow\"\nerror_action = \"deny\"")
path.write_text(text, encoding="utf-8")
PYCODE
cat >> "$sandbox_config" <<TOML

[[sandbox.file.rules]]
enabled = true
id = "deny-read"
priority = 100
action = "deny"
operations = ["read"]
patterns = [{ pattern = "^$temporary/intents/read$" }]

[[sandbox.file.rules]]
enabled = true
id = "deny-write"
priority = 100
action = "deny"
operations = ["write"]
patterns = [{ pattern = "^$temporary/intents/write$" }]

[[sandbox.file.rules]]
enabled = true
id = "deny-create"
priority = 100
action = "deny"
operations = ["create"]
patterns = [{ pattern = "^$temporary/intents/create$" }]

[[sandbox.file.rules]]
enabled = true
id = "deny-delete"
priority = 100
action = "deny"
operations = ["delete"]
patterns = [{ pattern = "^$temporary/intents/delete$" }]

[[sandbox.file.rules]]
enabled = true
id = "deny-rename-target"
priority = 100
action = "deny"
operations = ["rename"]
patterns = [{ pattern = "^$temporary/intents/rename-new$" }]

[[sandbox.process.rules]]
enabled = true
id = "deny-true"
priority = 100
action = "deny"
patterns = [{ executable = ".*/true$", command_line = "" }]

[[sandbox.process.rules]]
enabled = true
id = "deny-fork"
priority = 100
action = "deny"
patterns = [{ executable = ".*/linux-static-c$", command_line = "--intent-fork" }]
TOML
"$hyperhub" import "$sandbox_config" --password-file "$password_file" >/dev/null
start_serve "$temporary/deny-serve.stdout.log" "$temporary/deny-serve.stderr.log"

expect_denied() {
  local name=$1
  shift
  set +e
  "$hyperhub" run \
    --password-file "$password_file" \
    -- "$fixture_dir/linux-static-c" "$@" >/dev/null 2>"$temporary/$name.stderr.log"
  local code=$?
  set -e
  if [[ $code -eq 0 ]]; then
    echo "static intent unexpectedly passed: $name" >&2
    exit 1
  fi
}
expect_denied read --intent-read "$temporary/intents/read"
expect_denied write --intent-write "$temporary/intents/write"
expect_denied create --intent-create "$temporary/intents/create"
expect_denied delete --intent-delete "$temporary/intents/delete"
expect_denied rename --intent-rename "$temporary/intents/rename-old" "$temporary/intents/rename-new"
expect_denied process-fork --intent-fork
expect_denied process-exec --intent-exec /usr/bin/true
expect_denied process-child-exec --intent-child-exec /usr/bin/true

deny_audit=$(find "$HOME/.hyperhub/audit" -name hyperhub.jsonl -type f -print -quit)
[[ -n $deny_audit ]] || { echo 'sandbox deny audit was not created' >&2; exit 1; }
denied=$(grep -c '"event":"sandbox_denied"' "$deny_audit" || true)
if ((denied < 8)); then
  echo "expected 8 sandbox deny events, got $denied" >&2
  exit 1
fi
record_check sandbox.denies "events=$denied"
python3 "$root/tests/benchmarks/linux-static/suite_report.py" \
  "$checks_file" \
  "$result_dir/summary.csv" \
  "$fixture_dir/manifest.json" \
  "$result_dir/suite.json" \
  "$result_dir/suite-report.md"
printf 'Linux backend benchmark passed; connections=%d dynamic_hooks=%s static_hooks=%s sandbox_denies=%d\n' \
  "$connections" "$dynamic_hook_report" "$hook_report" "$denied"
printf 'suite: %s\nreport: %s\nfixtures: %s\n' \
  "$result_dir/suite.json" "$result_dir/suite-report.md" "$fixture_dir/manifest.json"
