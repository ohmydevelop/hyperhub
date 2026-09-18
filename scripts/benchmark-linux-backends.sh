#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hyperhub="$root/target/release/hyperhub"
runtime="$root/target/release/libhyperhub_gum_agent.so"
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
complete Linux dynamic-Gum/static-ptrace functional and performance suite.

options:
  --iterations N       measured launches per workload (default: 1)
  --output DIR         suite result directory (default: target/benchmarks/linux-backends)
  --fixtures DIR       reusable fixture cache
  --hyperhub PATH      HyperHub CLI path
  --runtime PATH       external Gum Agent runtime path
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
    --runtime)
      [[ $# -ge 2 ]] || { echo 'missing value for --runtime' >&2; exit 2; }
      runtime=$2
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

if ((build_release)); then
  cd "$root"
  mapfile -t devkits < <("$root/scripts/frida-devkit.sh" "$architecture")
  export HYPERHUB_FRIDA_GUM_ROOT=${devkits[0]}
  export HYPERHUB_FRIDA_CORE_ROOT=${devkits[1]}
  compiler_include=$(cc -print-file-name=include)
  export BINDGEN_EXTRA_CLANG_ARGS="-I$HYPERHUB_FRIDA_CORE_ROOT -isystem $compiler_include ${BINDGEN_EXTRA_CLANG_ARGS:-}"
  cargo build --release --locked -p hyperhub-agent-core --features gum-agent
  cargo build --release --locked -p hyperhub
fi

[[ -x $hyperhub ]] || { echo "HyperHub is not executable: $hyperhub" >&2; exit 1; }
[[ -f $runtime ]] || { echo "Linux Gum Agent runtime does not exist: $runtime" >&2; exit 1; }
hyperhub=$(realpath "$hyperhub")
runtime=$(realpath "$runtime")

original_home=$HOME
original_rustup_home=${RUSTUP_HOME:-"$original_home/.rustup"}
original_cargo_home=${CARGO_HOME:-"$original_home/.cargo"}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/hyperhub-static-coverage.XXXXXX")
serve_pid=
echo_pid=
cleanup() {
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
    if "$hyperhub" status --json 2>/dev/null \
      | grep -Eq '"state"[[:space:]]*:[[:space:]]*"running"'; then
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
mode = "enforce"

[listener]
socks_listen = "127.0.0.1:$port"
pending_session_ttl_secs = 60

[audit]
connections = true

[firewall]
enabled = false

[default_route]
enabled = true
deny = false
plugins = []
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

# Copy the CLI away from every runtime discovery location. A static target must
# still start, proving this backend does not resolve or validate a Gum Agent.
standalone_hyperhub="$temporary/hyperhub-no-agent-runtime"
cp "$hyperhub" "$standalone_hyperhub"
chmod 0755 "$standalone_hyperhub"
(
  cd "$temporary"
  if "$standalone_hyperhub" run \
    --password-file "$password_file" \
    -- /bin/true >/dev/null 2>"$temporary/dynamic-no-runtime.stderr.log"; then
    echo 'dynamic ELF unexpectedly started without a Gum Agent runtime' >&2
    exit 1
  fi
  if ! grep -q 'agent runtime was not found' "$temporary/dynamic-no-runtime.stderr.log"; then
    cat "$temporary/dynamic-no-runtime.stderr.log" >&2
    echo 'dynamic ELF did not fail at Gum Agent runtime resolution' >&2
    exit 1
  fi
  "$standalone_hyperhub" run \
    --password-file "$password_file" \
    -- "$fixture_dir/linux-static-c" --intent-read /etc/hosts >/dev/null
)
record_check backend.runtime_boundary "dynamic requires Gum; static runs without Agent"

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
if ((rebuild_fixtures)) || [[ ! -x $dynamic_probe || $dynamic_source -nt $dynamic_probe ]]; then
  cc -O2 -Wall -Wextra "$dynamic_source" -o "$dynamic_probe"
fi
python3 - "$fixture_dir/manifest.json" "$dynamic_probe" <<'PYCODE'
import hashlib
import json
import pathlib
import sys
manifest_path = pathlib.Path(sys.argv[1])
binary = pathlib.Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["fixtures"] = [
    fixture for fixture in manifest["fixtures"] if fixture["workload"] != "dynamic-c"
]
manifest["fixtures"].append(
    {
        "workload": "dynamic-c",
        "kind": "dynamic-probe",
        "path": str(binary),
        "bytes": binary.stat().st_size,
        "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
)
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PYCODE
dynamic_hook_report="$result_dir/dynamic-hooks.json"
HYPERHUB_AGENT_DEBUG=1 \
HYPERHUB_DYNAMIC_HOOK_REPORT=$dynamic_hook_report \
  "$hyperhub" run \
    --runtime "$runtime" \
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

# Enable file and process sandbox rules and verify every configured intent is denied.
export HOME="$temporary/deny-home"
mkdir -p "$HOME" "$temporary/intents"
for name in read write delete rename-old; do
  printf 'intent\n' > "$temporary/intents/$name"
done
sandbox_config="$temporary/sandbox.toml"
write_base_config "$sandbox_config" "$(free_port)"
cat >> "$sandbox_config" <<TOML

[sandbox.file]
enabled = true
error_action = "deny"

[sandbox.file.default]
action = "pass"

[[sandbox.file.rules]]
id = "deny-read"
priority = 100
action = "deny"
operations = ["read"]
patterns = [{ pattern = "^$temporary/intents/read$" }]

[[sandbox.file.rules]]
id = "deny-write"
priority = 100
action = "deny"
operations = ["write"]
patterns = [{ pattern = "^$temporary/intents/write$" }]

[[sandbox.file.rules]]
id = "deny-create"
priority = 100
action = "deny"
operations = ["create"]
patterns = [{ pattern = "^$temporary/intents/create$" }]

[[sandbox.file.rules]]
id = "deny-delete"
priority = 100
action = "deny"
operations = ["delete"]
patterns = [{ pattern = "^$temporary/intents/delete$" }]

[[sandbox.file.rules]]
id = "deny-rename-target"
priority = 100
action = "deny"
operations = ["rename"]
patterns = [{ pattern = "^$temporary/intents/rename-new$" }]

[sandbox.process]
enabled = true
error_action = "deny"

[sandbox.process.default]
action = "pass"

[[sandbox.process.rules]]
id = "deny-true"
priority = 100
action = "deny"
patterns = [{ executable = ".*/true$", command_line = "" }]

[[sandbox.process.rules]]
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
