#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$root/scripts/lib/linux-suite.sh"
hyperhub="$root/target/release/hyperhub"
result_dir="$root/target/benchmarks/linux-backends"
fixture_dir=
iterations=1
include_large=0
rebuild_fixtures=0
build_release=1
restricted_yama_only=0

usage() {
  cat <<'USAGE'
usage: scripts/benchmark-linux-backends.sh [options]

Build HyperHub when needed, reuse versioned benchmark fixtures, and execute the
Linux ptrace-baseline/explicit-Gum functional and performance suite. Gum positive
tests require unrestricted Yama. Restricted environments retain ptrace tests and
Gum refusal tests, with PARTIAL coverage reported for skipped Gum positives.

options:
  --iterations N       measured launches per workload (default: 1)
  --output DIR         suite result directory (default: target/benchmarks/linux-backends)
  --fixtures DIR       reusable fixture cache
  --hyperhub PATH      HyperHub CLI path
  --full               include BusyBox, gh, yq, and ripgrep performance workloads
  --rebuild-fixtures   force regeneration of cached fixture binaries
  --skip-build         use the supplied/existing CLI and Agent without cargo build
  --restricted-yama-only  run source-based rejection/auto-fallback regressions only
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
    --restricted-yama-only)
      restricted_yama_only=1
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

linux_suite_classify_yama
if ((restricted_yama_only)); then
  [[ $linux_gum_negative == 1 ]] || { echo '--restricted-yama-only requires actual Yama scope 1, 2 or 3' >&2; exit 2; }
  [[ -x $hyperhub ]] || { echo "HyperHub is not executable: $hyperhub" >&2; exit 1; }
  hyperhub=$(realpath "$hyperhub")
  mkdir -p "$result_dir"
  permission_reports=()
  for attachment_case in attach-tree attach-process run-tree; do
    attachment_origin=${attachment_case%-*}
    attachment_scope=${attachment_case#*-}
    permission_root=$(mktemp -d "$result_dir/dynamic-gum-yama-${attachment_case}.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend gum --origin "$attachment_origin" --scope "$attachment_scope" --target-pty --unsupported-negative \
      --output "$permission_root/report"
    permission_reports+=("$permission_root/report/result.json")
  done
  python3 - "$root" "$result_dir" "$architecture" "${permission_reports[@]}" <<'PYYAMA'
import hashlib,json,pathlib,sys
root,result=map(pathlib.Path,sys.argv[1:3]);architecture=sys.argv[3]
source=root/'tests/fixtures/dynamic_attach_target.c'
fixtures=[];checks=[]
for path in map(pathlib.Path,sys.argv[4:]):
    case=json.loads(path.read_text());assert case['status']=='pass'
    binary=path.parent/'dynamic-attach-target'
    fixtures.append({'workload':case['scenario'],'kind':'dynamic-probe','path':str(binary),'source':str(source.relative_to(root)),'bytes':binary.stat().st_size,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
    checks.append({'check':'dynamic.'+case['scenario'],'status':'pass','details':'expected capability refusal; '+str(path)})
assert len(checks)==3,checks
checks.append({'check':'coverage.full_linux_suite','status':'skip','details':'restricted-only mode did not execute the positive Linux test matrix'})
(result/'checks.tsv').write_text('check\tstatus\tdetails\n'+''.join('\t'.join(row[key]for key in ['check','status','details'])+'\n'for row in checks))
(result/'summary.csv').write_text('workload,kind,binary_bytes,native_median_ms,hyperhub_median_ms,overhead_ms,overhead_ratio\n')
(result/'fixtures.json').write_text(json.dumps({'architecture':architecture,'probe_fingerprint':hashlib.sha256(source.read_bytes()).hexdigest(),'fixtures':fixtures},indent=2)+'\n')
PYYAMA
  python3 "$root/tests/benchmarks/linux-static/suite_report.py" \
    "$result_dir/checks.tsv" "$result_dir/summary.csv" "$result_dir/fixtures.json" \
    "$result_dir/suite.json" "$result_dir/suite-report.md"
  exit 0
fi

for command in openssl ssh ssh-keygen sshd; do
  command -v "$command" >/dev/null 2>&1 || { echo "required command is unavailable: $command" >&2; exit 1; }
done

# Source-level Engine regressions below also require the exact native SDK pair
# when the product release build is skipped.
mapfile -t devkits < <("$root/scripts/frida-devkit.sh" "$architecture")
export HYPERHUB_FRIDA_GUM_ROOT=${devkits[0]}
export HYPERHUB_FRIDA_CORE_ROOT=${devkits[1]}
compiler_include=$(cc -print-file-name=include)
export BINDGEN_EXTRA_CLANG_ARGS="-I$HYPERHUB_FRIDA_CORE_ROOT -isystem $compiler_include ${BINDGEN_EXTRA_CLANG_ARGS:-}"
if ((build_release)); then
  cd "$root"
  cargo build --release --locked -p hyperhub-agent-core --features gum-agent
  export HYPERHUB_EMBEDDED_AGENT_PATH="$root/target/release/libhyperhub_gum_agent.so"
  cargo build --release --locked -p hyperhub-engine
  export HYPERHUB_EMBEDDED_ENGINE_PATH="$root/target/release/libhyperhub_engine.so"
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
  for diagnostic_log in "$temporary"/*.stderr.log; do
    [[ ! -f $diagnostic_log ]] || cp "$diagnostic_log" "$result_dir/" || true
  done
  if [[ -f "$temporary/dynamic-embedded-runtime.stderr.log" ]]; then
    cp "$temporary/dynamic-embedded-runtime.stderr.log" "$result_dir/embedded-runtime.stderr.log" || true
  fi
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
# Agent CA bundles belong to this suite and are removed with its private root.
mkdir -m 0700 "$temporary/runtime"
export XDG_RUNTIME_DIR="$temporary/runtime"
mkdir -p "$result_dir" "$fixture_dir"
result_dir=$(cd "$result_dir" && pwd)
fixture_dir=$(cd "$fixture_dir" && pwd)
checks_file="$result_dir/checks.tsv"
printf 'check\tstatus\tdetails\n' > "$checks_file"
record_check() { linux_suite_record pass "$1" "${2:-}"; }
python3 "$root/tests/test_linux_suite_reporting.py"
record_check suite.reporting_contract "deterministic capability dispatch and complete/partial/failure report assertions"
record_check environment.gum_capability "yama=$linux_yama_scope; gum_positive_tests=$linux_gum_available; $linux_gum_reason"
run_restricted_gum_tests() {
  if [[ $linux_gum_negative != 1 ]]; then
    if [[ $linux_gum_available != 1 ]]; then record_skip dynamic.gum_permission_refusals "$linux_gum_reason; no recognized restricted mode to test"; fi
    return
  fi
  local case_name origin scope directory
  for case_name in attach-tree attach-process run-tree; do
    origin=${case_name%-*}; scope=${case_name#*-}
    directory=$(mktemp -d "$result_dir/dynamic-gum-yama-${case_name}.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend gum --origin "$origin" --scope "$scope" --target-pty --unsupported-negative \
      --output "$directory/report"
    record_check "dynamic.gum_refusal_${case_name}" "report=$directory/report/result.json; actualpreflightrefusal; targetunchanged; automaticbackendpermissionchecked"
  done
}
admin_password_file="$temporary/password"
printf 'static-coverage-password\n' > "$admin_password_file"
chmod 0600 "$admin_password_file"

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
  "$hyperhub" serve >"$stdout" 2>"$stderr" &
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
"$hyperhub" import "$config_file" --admin-password-file "$admin_password_file" >/dev/null
start_serve "$temporary/pass-serve.stdout.log" "$temporary/pass-serve.stderr.log"

benchmark_args=(
  --iterations "$iterations"
  --output "$result_dir"
  --fixtures "$fixture_dir"
  --hyperhub "$hyperhub"
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
thread_exit_probe="$fixture_dir/linux-thread-exit-probe"
thread_exit_source="$root/tests/fixtures/linux_thread_exit_probe.c"
if ((rebuild_fixtures)) || [[ ! -x $thread_exit_probe || $thread_exit_source -nt $thread_exit_probe ]]; then
  cc -O2 -Wall -Wextra -pthread "$thread_exit_source" -o "$thread_exit_probe"
fi
standalone_hyperhub="$temporary/hyperhub-embedded-agent"
cp "$hyperhub" "$standalone_hyperhub"
chmod 0755 "$standalone_hyperhub"
(
  cd "$temporary"
  "$standalone_hyperhub" run \
    -- /bin/true >/dev/null
  linux_suite_run_backend gum backend.embedded_gum_runtime "standalone embedded Agent" \
    "$standalone_hyperhub" run --backend gum -- /bin/true \
    >/dev/null 2>"$temporary/dynamic-embedded-runtime.stderr.log"
  "$standalone_hyperhub" run -- "$thread_exit_probe" "$temporary/ptrace-thread-exit.txt" >/dev/null
  linux_suite_run_backend gum backend.gum_thread_exit "late pthread teardown" \
    "$standalone_hyperhub" run --backend gum -- "$thread_exit_probe" "$temporary/gum-thread-exit.txt" >/dev/null
  lifecycle_iterations="${HYPERHUB_THREAD_EXIT_ITERATIONS:-64}"
  if [[ ! $lifecycle_iterations =~ ^[1-9][0-9]*$ || ${#lifecycle_iterations} -gt 4 ]] || ((lifecycle_iterations > 1000)); then
    echo "HYPERHUB_THREAD_EXIT_ITERATIONS must be an integer from 1 to 1000" >&2
    exit 1
  fi
  lifecycle_log="$result_dir/thread-exit-lifecycle.log"
  : > "$lifecycle_log"
  check_lifecycle_exit() {
    local expected_status="$1" expected_output="$2" status=0 output
    shift 2
    output=$("$@") || status=$?
    printf 'status=%s expected=%s output=%s\n' "$status" "$expected_status" "$output" >> "$lifecycle_log"
    if [[ $status != "$expected_status" || $output != "$expected_output" ]]; then
      echo "thread lifecycle regression: expected exit $expected_status and '$expected_output', got exit $status and '$output'" >&2
      return 1
    fi
  }
  check_lifecycle_exit 7 "exit-group-race workers=16 status=7" "$thread_exit_probe" --exit-group-race 16 7
  check_lifecycle_exit 9 "nonleader-exec identity-preserved" "$thread_exit_probe" --nonleader-exec
  for ((lifecycle_index = 0; lifecycle_index < lifecycle_iterations; lifecycle_index++)); do
    check_lifecycle_exit 7 "exit-group-race workers=16 status=7" "$standalone_hyperhub" run -- "$thread_exit_probe" --exit-group-race 16 7
    check_lifecycle_exit 9 "nonleader-exec identity-preserved" "$standalone_hyperhub" run -- "$thread_exit_probe" --nonleader-exec
  done
  "$standalone_hyperhub" run \
    -- "$fixture_dir/linux-static-c" --intent-read /etc/hosts >/dev/null
)
record_check backend.runtime_boundary "dynamic/static default ptrace; explicit Gum reported separately"
record_check backend.thread_exit "native/ptrace late pthread teardown and exit_group and nonleader exec preserve status and identity (iterations=${HYPERHUB_THREAD_EXIT_ITERATIONS:-64})"
(
  cd "$root"
  cargo run -p hyperhub-runtime --example runtime_loader_probe --locked \
    >"$result_dir/engine-loader.log" 2>&1
  cargo test -p hyperhub-agent-core --features gum-agent --locked engine_tests::native_upgrade \
    >"$result_dir/engine-fork-runtime.log" 2>&1
  env -u HYPERHUB_TEST_ENGINE_GUM_AGENT -u HYPERHUB_TEST_ENGINE_EMBEDDED_AGENT \
    HYPERHUB_TEST_ENGINE_HYPERHUB="$standalone_hyperhub" HYPERHUB_TEST_ENGINE_BACKEND=ptrace \
    cargo test -p hyperhub --test engine_host_live --locked -- --nocapture \
    >"$result_dir/engine-ptrace.log" 2>&1
  linux_suite_run_backend gum backend.engine_upgrade_gum "embedded Gum Engine host upgrade" \
    env -u HYPERHUB_TEST_ENGINE_GUM_AGENT \
      HYPERHUB_TEST_ENGINE_HYPERHUB="$standalone_hyperhub" HYPERHUB_TEST_ENGINE_BACKEND=gum \
      HYPERHUB_TEST_ENGINE_EMBEDDED_AGENT=1 \
      cargo test -p hyperhub --test engine_host_live --locked -- --nocapture \
      >"$result_dir/engine-gum.log" 2>&1
)
record_check backend.engine_upgrade "authenticated native Engine switch preserves target identity and existing TCP streams"
record_check backend.engine_fork_runtime "native module cache lock and old leases survive fork and reclaim after rollback"
(
  cd "$root"
  HH_FORWARD_WORKER_FIXTURE="$standalone_hyperhub" \
    cargo test -p hyperhub-core --test forward_workers --locked -- --ignored --nocapture \
    >"$result_dir/forward-workers.log" 2>&1
  HH_FORWARD_WORKER_FIXTURE="$standalone_hyperhub" \
    cargo test -p hyperhub-core --lib --locked durable_release_recovery_status_installation_and_missing_host_boundaries -- --ignored --nocapture \
    >"$result_dir/release-recovery.log" 2>&1
)
record_check backend.forward_workers "real worker processes preserve resident identities and old streams across generation changes"
(
  cd "$root"
  for release_backend in ptrace gum; do
    if [[ $release_backend == gum && $linux_gum_available != 1 ]]; then record_skip backend.release_upgrade_gum; continue; fi
    HH_FORWARD_WORKER_FIXTURE="$standalone_hyperhub" \
      HYPERHUB_TEST_RELEASE_BACKEND="$release_backend" \
      cargo test -p hyperhub --test release_live --locked -- --ignored --nocapture \
      >"$result_dir/release-upgrade-$release_backend.log" 2>&1
    record_check "backend.release_upgrade_${release_backend}" "joint Engine/worker finalization"
  done
)
record_check backend.release_upgrade "executed Engine/worker finalization; see per-backend rows"
(
  cd "$root"
  for restart_backend in ptrace gum; do
    if [[ $restart_backend == gum && $linux_gum_available != 1 ]]; then record_skip backend.serve_restart_gum; continue; fi
    restart_test_args=()
    if [[ $restart_backend == ptrace ]]; then
      restart_test_args+=(--skip gum_unavailable_serve_never_resumes_an_unenrolled_child)
    fi
    HYPERHUB_TEST_RESTART_HYPERHUB="$standalone_hyperhub" \
      HYPERHUB_TEST_RESTART_BACKEND="$restart_backend" \
      cargo test -p hyperhub --test serve_restart_live --locked -- --ignored --nocapture --test-threads=1 "${restart_test_args[@]}" \
      >"$result_dir/serve-restart-$restart_backend.log" 2>&1
    record_check "backend.serve_restart_${restart_backend}" "restarts, root exit, exec and control outage"
  done
  gum_test_filters=()
  if [[ $linux_gum_available != 1 ]]; then
    gum_test_filters+=(--skip gum_)
    record_skip sandbox.executor_scope_gum
    record_skip sandbox.file_alias_gum
  fi
  HYPERHUB_TEST_ENGINE_HYPERHUB="$standalone_hyperhub" \
    cargo test -p hyperhub --test executor_scope_live --locked -- --ignored --nocapture "${gum_test_filters[@]}" \
    >"$result_dir/executor-scope.log" 2>&1
  HYPERHUB_TEST_ALIAS_HYPERHUB="$standalone_hyperhub" \
    cargo test -p hyperhub --test file_alias_live --locked -- --ignored --nocapture --test-threads=1 "${gum_test_filters[@]}" \
    >"$result_dir/file-alias.log" 2>&1
)
record_check backend.serve_restart "executed executor continuity tests; see per-backend rows and Gum skips"
record_check sandbox.executor_scope "managed direct reads are denied; delegation to a pre-existing external IPC executor is outside the registered tree"
record_check sandbox.file_alias "managed protected-source hard links and content symlink aliases are denied; ordinary hard links remain usable; pre-existing external hard links are reported as a scope gap"
(
  cd "$root"
  cargo run --release -p hyperhub-engine --example native_upgrade_bench --locked -- \
    "$result_dir/native-engine-performance" >"$result_dir/native-engine-performance.log" 2>&1
)
record_check backend.engine_switch_budget "real native prepare and commit overlap four active decision threads and meet the 100ms soft switch budget"

pass_audit=$(find "$HOME/.hyperhub/audit" -name security-alerts.jsonl -type f -print -quit)
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
python3 - "$fixture_dir/manifest.json" "$dynamic_probe" "$hot_update_probe" "$thread_exit_probe" <<'PYCODE'
import hashlib
import json
import pathlib
import sys
manifest_path = pathlib.Path(sys.argv[1])
binaries = {
    "dynamic-c": ("dynamic-probe", pathlib.Path(sys.argv[2])),
    "ptrace-hot-update": ("dynamic-probe", pathlib.Path(sys.argv[3])),
    "thread-exit": ("dynamic-probe", pathlib.Path(sys.argv[4])),
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
  -- "$dynamic_probe" 127.0.0.1 "$echo_port" \
  >/dev/null 2>"$temporary/dynamic-ptrace.stderr.log"
record_check dynamic.ptrace_descendants "fork+exec,posix_spawn,posix_spawnp,vfork+exec"
record_check dynamic.unix_nonblocking "socket,fcntl,ioctl"

dynamic_hook_report="$result_dir/dynamic-hooks.json"
if [[ $linux_gum_available == 1 ]]; then
HYPERHUB_AGENT_DEBUG=1 \
HYPERHUB_DYNAMIC_HOOK_REPORT=$dynamic_hook_report \
  "$hyperhub" run \
    --backend gum \
    -- "$dynamic_probe" 127.0.0.1 "$echo_port" \
    >/dev/null 2>"$temporary/dynamic-probe.stderr.log"
if ! grep -Eq 'Linux hooks installed=(40 optional_missing=1|41 optional_missing=0) manifest=41' \
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
set +e
"$hyperhub" run \
  --backend gum \
  -- /bin/sh -c 'exit 7' >/dev/null 2>"$temporary/dynamic-gum-exit.stderr.log"
gum_exit_status=$?
set -e
[[ $gum_exit_status -eq 7 ]] || {
  echo "dynamic Gum exit status was not preserved: $gum_exit_status" >&2
  exit 1
}
record_check dynamic.gum_exit_status "exit=7"
record_check dynamic.gum_descendants "fork+exec,posix_spawn,posix_spawnp,vfork+exec"

else
  record_skip dynamic.gum_manifest
  record_skip dynamic.gum_exit_status
  record_skip dynamic.gum_descendants
fi

hook_report="$result_dir/hooks.json"
HYPERHUB_DNS_PORTS=$dns_port \
HYPERHUB_STATIC_HOOK_REPORT=$hook_report \
HYPERHUB_STATIC_REQUIRE_ALL_HOOKS=1 \
  "$hyperhub" run \
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

# These assertions use operation semantics and destination identity independently
# of the syscall-count manifest, with their own isolated configuration and Serve.
python3 "$root/tests/benchmarks/linux-static/hook_regressions.py" \
  --hyperhub "$hyperhub" --output "$result_dir/hook-regressions"
record_check semantic.hook_regressions "DNS transactions/I/O, Fast Open, shared fd tables, mapping permissions"
hook_coverage=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$result_dir/hook-regressions/coverage.json")
case "$hook_coverage" in
  pass) ;;
  partial) record_skip semantic.gum_hook_regressions "report=$result_dir/hook-regressions/coverage.json; Gum semantic groups were not executed" ;;
  *) echo 'hook regression coverage has an invalid completion state' >&2; exit 1 ;;
esac

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
"$hyperhub" import "$credential_config" --admin-password-file "$admin_password_file" >/dev/null
start_serve "$temporary/credential-serve.stdout.log" "$temporary/credential-serve.stderr.log"
"$hyperhub" run \
  --backend ptrace \
  -- python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  localhost "$credential_port"
wait "$credential_pid"
credential_pid=
credential_audit=$(find "$HOME/.hyperhub/audit" -name security-alerts.jsonl -type f -print -quit)
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
"$hyperhub" import "$hot_config" --admin-password-file "$admin_password_file" >/dev/null
start_serve "$temporary/hot-update-serve.stdout.log" "$temporary/hot-update-serve.stderr.log"
hot_fifo="$temporary/hot-update/commands.fifo"
hot_output="$temporary/hot-update/output.log"
mkfifo "$hot_fifo"
exec 9<>"$hot_fifo"
"$hyperhub" run --backend ptrace -- \
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
python3 - "$hyperhub" "$admin_password_file" "$temporary/hot-update/approve.log" <<'PYCODE'
import os, pathlib, pty, select, subprocess, sys, time
binary, password, log_path = sys.argv[1:]
master, slave = pty.openpty()
process = subprocess.Popen(
    [binary, "approve", "--admin-password-file", password],
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
# The ptrace supervisor refreshes the sandbox snapshot on a bounded polling
# interval. Give the successful live update one refresh interval before
# issuing the first post-update syscall; otherwise this assertion can race
# the supervisor and report a false regression.
sleep 0.5
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
hot_audit=$(find "$HOME/.hyperhub/audit" -name security-alerts.jsonl -type f -print -quit)
[[ $(grep -c '"event":"security_alert"' "$hot_audit" || true) -ge 4 ]] || {
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
"$hyperhub" import "$trust_config" --admin-password-file "$admin_password_file" >/dev/null
start_serve "$temporary/trust-serve.stdout.log" "$temporary/trust-serve.stderr.log"
"$hyperhub" run --backend ptrace -- \
  python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  --tls-client localhost "$trust_tls_port"
wait "$trust_tls_pid"
trust_tls_pid=
python3 "$root/tests/fixtures/linux_http_credential_probe.py" \
  --tls-server "$trust_tls_port_file" placeholder-token "$trust_tls_cert" "$trust_tls_key" &
trust_tls_pid=$!
"$hyperhub" run --backend ptrace -- \
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
"$hyperhub" run --backend ptrace -- \
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
"$hyperhub" run --backend ptrace -- \
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
"$hyperhub" run --backend ptrace -- \
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -p "$trust_ssh_port" nobody@localhost true \
  >/dev/null 2>"$temporary/trust-ssh-rotated.stderr.log"
set -e
kill "$trust_ssh_pid"
wait "$trust_ssh_pid" 2>/dev/null || true
trust_ssh_pid=
trust_audit=$(find "$HOME/.hyperhub/audit" -name security-alerts.jsonl -type f -print -quit)
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
printf 'intent\n' > "$temporary/intents/mprotect-write"
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
id = "deny-create-write"
priority = 100
action = "deny"
operations = ["write"]
patterns = [{ pattern = "^$temporary/intents/create-write$" }]

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

[[sandbox.file.rules]]
enabled = true
id = "deny-mprotect-write"
priority = 100
action = "deny"
operations = ["write"]
patterns = [{ pattern = "^$temporary/intents/mprotect-write$" }]

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
"$hyperhub" import "$sandbox_config" --admin-password-file "$admin_password_file" >/dev/null
start_serve "$temporary/deny-serve.stdout.log" "$temporary/deny-serve.stderr.log"

expect_denied() {
  local name=$1
  shift
  set +e
  "$hyperhub" run \
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
expect_denied create-write --intent-create "$temporary/intents/create-write"
expect_denied delete --intent-delete "$temporary/intents/delete"
expect_denied rename --intent-rename "$temporary/intents/rename-old" "$temporary/intents/rename-new"
expect_denied mprotect-write --intent-mprotect-write "$temporary/intents/mprotect-write"
if [[ $linux_gum_available == 1 ]]; then
printf 'intent\n' > "$temporary/intents/rename-old"
set +e
"$hyperhub" run \
  --backend gum \
  -- "$dynamic_probe" --intent-rename "$temporary/intents/rename-old" "$temporary/intents/rename-new" \
  >/dev/null 2>"$temporary/rename-gum.stderr.log"
rename_gum_status=$?
set -e
[[ $rename_gum_status -ne 0 ]] || { echo 'dynamic Gum rename deny returned success' >&2; exit 1; }
[[ -e $temporary/intents/rename-old && ! -e $temporary/intents/rename-new ]] || {
  echo 'dynamic Gum rename target deny did not preserve the source path' >&2
  exit 1
}
record_check dynamic.gum_rename_target "source=preserved target=denied"
printf 'intent\n' > "$temporary/intents/mprotect-write"
set +e
"$hyperhub" run \
  --backend gum \
  -- "$dynamic_probe" --intent-mprotect-write "$temporary/intents/mprotect-write" \
  >/dev/null 2>"$temporary/mprotect-write-gum.stderr.log"
mprotect_gum_status=$?
set -e
[[ $mprotect_gum_status -ne 0 ]] || { echo 'dynamic Gum mprotect deny returned success' >&2; exit 1; }
python3 - "$temporary/intents/mprotect-write" <<'PYCODE'
import pathlib
import sys
data = pathlib.Path(sys.argv[1]).read_bytes()
if data[:1] == b"x":
    raise SystemExit("dynamic Gum mprotect write deny allowed the mapping mutation")
PYCODE
record_check dynamic.gum_mprotect_upgrade "read-only mapping write upgrade denied"
set +e
"$hyperhub" run \
  --backend gum \
  -- "$dynamic_probe" --intent-create "$temporary/intents/create-write" \
  >/dev/null 2>"$temporary/create-write-gum.stderr.log"
create_gum_status=$?
set -e
[[ $create_gum_status -ne 0 ]] || { echo 'dynamic Gum create/write deny returned success' >&2; exit 1; }
[[ ! -e $temporary/intents/create-write ]] || {
  echo 'dynamic Gum create with write semantics bypassed write deny' >&2
  exit 1
}
record_check dynamic.gum_create_write "O_CREAT|O_WRONLY checks create and write"
else
  record_skip dynamic.gum_rename_target
  record_skip dynamic.gum_mprotect_upgrade
  record_skip dynamic.gum_create_write
fi

expect_denied process-fork --intent-fork
expect_denied process-exec --intent-exec /usr/bin/true
expect_denied process-child-exec --intent-child-exec /usr/bin/true

deny_audit=$(find "$HOME/.hyperhub/audit" -name security-alerts.jsonl -type f -print -quit)
[[ -n $deny_audit ]] || { echo 'sandbox deny audit was not created' >&2; exit 1; }
denied=$(grep -c '"event":"security_alert"' "$deny_audit" || true)
minimum_denies=10
if [[ $linux_gum_available == 1 ]]; then minimum_denies=11; fi
if ((denied < minimum_denies)); then
  echo "expected at least $minimum_denies events for the executed sandbox checks, got $denied" >&2
  exit 1
fi
record_check sandbox.denies "events=$denied; minimum=$minimum_denies; ten ptrace intent checks; gum_positive_tests=$linux_gum_available"
# Exercise the same source target through approved live attach and reversible
# Ordinary memory/thread correctness uses the same source actor as dynamic
# attachment. The native proc cursor oracle does not load HyperHub.
cursor_oracle="$fixture_dir/dynamic-map-cursor-oracle"
cc -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/fixtures/dynamic_attach_target.c" -ldl -o "$cursor_oracle"
"$cursor_oracle" unused 0 --map-cursor-oracle > "$result_dir/native-proc-cursor.json"
record_check memory.proc_cursor_native \
  "report=$result_dir/native-proc-cursor.json; sequentialcursorzeroerrors; sharedpreadcounterexamplecount"
# new-run lifecycle. This runner owns its private gateway and dummy credentials.
# Full 100-cycle/two-hour stress uses this same entrypoint in dedicated CI jobs.
cargo build --locked --manifest-path "$root/tests/fixtures/dynamic-attach-terminal/Cargo.toml" \
  --target-dir "$root/target/terminal-fixture"
terminal_fixture="$root/target/terminal-fixture/debug/dynamic-attach-terminal"
terminal_native_root=$(mktemp -d "$result_dir/dynamic-terminal-native.XXXXXX")
python3 "$root/scripts/test-dynamic-attach-terminal.py" --fixture "$terminal_fixture" \
  --native-only --output "$terminal_native_root/report"
record_check dynamic.terminal_native_keyboard_oracle \
  "report=$terminal_native_root/report/result.json; actualrawkeybytes; termios; foreground"
python3 - "$fixture_dir/manifest.json" "$terminal_fixture" <<'PYTERMINAL'
import hashlib,json,pathlib,sys
path,binary=map(pathlib.Path,sys.argv[1:]);manifest=json.loads(path.read_text())
manifest['fixtures']=[item for item in manifest['fixtures'] if item['workload']!='dynamic-attach-terminal']
manifest['fixtures'].append({'workload':'dynamic-attach-terminal','kind':'dynamic-probe','path':str(binary),'source':'tests/fixtures/dynamic-attach-terminal/src/main.rs','build_manifest':'tests/fixtures/dynamic-attach-terminal/Cargo.toml','bytes':binary.stat().st_size,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
path.write_text(json.dumps(manifest,indent=2)+'\n')
PYTERMINAL
if [[ $linux_gum_available == 1 ]]; then
  cargo build --release --locked -p hyperhub-runtime --example attachment_init_failure
  startup_fixture="$root/target/release/examples/attachment_init_failure"
  startup_agent=${HYPERHUB_TEST_STARTUP_AGENT:-${HYPERHUB_EMBEDDED_AGENT_PATH:-"$root/target/release/libhyperhub_gum_agent.so"}}
  [[ -f $startup_agent ]] || { echo "startup recovery tests require the matching Agent; set HYPERHUB_TEST_STARTUP_AGENT" >&2; exit 1; }
  startup_agent=$(realpath "$startup_agent")
  for startup_mode in engine missing-pin host-bind; do
    "$startup_fixture" "$startup_agent" "$startup_mode" > "$result_dir/startup-${startup_mode}.log" 2>&1
    record_check "dynamic.startup_recovery_${startup_mode}" \
      "source=tests/fixtures/attachment_init_failure.rs; log=$result_dir/startup-${startup_mode}.log; authenticatedfailedstartup; approvedcleanup"
  done
  python3 - "$fixture_dir/manifest.json" "$startup_fixture" <<'PYSTARTUP'
import hashlib,json,pathlib,sys
path,binary=map(pathlib.Path,sys.argv[1:]);manifest=json.loads(path.read_text())
manifest['fixtures']=[item for item in manifest['fixtures'] if item['workload']!='attachment-init-failure']
manifest['fixtures'].append({'workload':'attachment-init-failure','kind':'dynamic-probe','path':str(binary),'source':'tests/fixtures/attachment_init_failure.rs','build_manifest':'crates/hyperhub-runtime/Cargo.toml','bytes':binary.stat().st_size,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
path.write_text(json.dumps(manifest,indent=2)+'\n')
PYSTARTUP
else
  for startup_mode in engine missing-pin host-bind; do
    record_skip "dynamic.startup_recovery_${startup_mode}" "$linux_gum_reason; native Gum startup recovery not executed"
  done
fi
for attachment_backend in ptrace gum; do
  if [[ $attachment_backend == gum && $linux_gum_available != 1 ]]; then
    record_skip dynamic.gum_attachment_matrix "$linux_gum_reason; attach/run/terminal/process/tree/recovery/aliases/memory/legacy positive groups not executed"
    continue
  fi
  for attachment_origin in attach run; do
    if [[ $attachment_backend != gum || $linux_gum_available == 1 ]]; then
      terminal_root=$(mktemp -d "$result_dir/dynamic-terminal-${attachment_backend}-${attachment_origin}.XXXXXX")
      python3 "$root/scripts/test-dynamic-attach-terminal.py" --fixture "$terminal_fixture" \
        --hyperhub "$hyperhub" --backend "$attachment_backend" --origin "$attachment_origin" \
        --cycles 2 --output "$terminal_root/report"
      record_check "dynamic.terminal_${attachment_backend}_${attachment_origin}" \
        "report=$terminal_root/report/result.json; actualrawkeyboard; restart; detach; originalexit37"
    fi
    attachment_root=$(mktemp -d "$result_dir/dynamic-attachment-${attachment_backend}-${attachment_origin}.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" \
      --hyperhub "$hyperhub" --backend "$attachment_backend" \
      --origin "$attachment_origin" --target-pty --cycles 3 \
      --output "$attachment_root/report"
    record_check "dynamic.attachment_${attachment_backend}_${attachment_origin}" \
      "report=$attachment_root/report/result.json; realPTY; threecycles; originalexit37"
    orphan_root=$(mktemp -d "$result_dir/dynamic-attachment-${attachment_backend}-${attachment_origin}-orphan.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" \
      --hyperhub "$hyperhub" --backend "$attachment_backend" \
      --origin "$attachment_origin" --target-pty --root-exit --cycles 1 \
      --output "$orphan_root/report"
    record_check "dynamic.attachment_${attachment_backend}_${attachment_origin}_root_exit" \
      "report=$orphan_root/report/result.json; originalroot37; livechildpolicy; detachbyid"
    exec_root=$(mktemp -d "$result_dir/dynamic-attachment-${attachment_backend}-${attachment_origin}-self-exec.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend "$attachment_backend" --origin "$attachment_origin" --target-pty \
      --root-self-exec --root-exec-methods path path fexecve execveat --cycles 2 --output "$exec_root/report"
    record_check "dynamic.attachment_${attachment_backend}_${attachment_origin}_root_self_exec" \
      "report=$exec_root/report/result.json; nativeoracle; path+path+fexecve+execveat; strictepochincrements; stalegrantrejection; detachandreattach"
    python3 - "$fixture_dir/manifest.json" "$attachment_root/report/dynamic-attach-target" "$attachment_backend" "$attachment_origin" <<'PYATTACH'
import hashlib
import json
import pathlib
import sys
manifest_path,binary=map(pathlib.Path,sys.argv[1:3])
workload="dynamic-attachment-"+"-".join(sys.argv[3:])
manifest=json.loads(manifest_path.read_text())
manifest["fixtures"]=[item for item in manifest["fixtures"] if item["workload"]!=workload]
manifest["fixtures"].append({"workload":workload,"kind":"dynamic-probe","path":str(binary),"source":"tests/fixtures/dynamic_attach_target.c","bytes":binary.stat().st_size,"sha256":hashlib.sha256(binary.read_bytes()).hexdigest()})
manifest_path.write_text(json.dumps(manifest,indent=2)+"\n")
PYATTACH
  done
  for exec_scope in process tree; do
    exec_family_root=$(mktemp -d "$result_dir/dynamic-attachment-${attachment_backend}-${exec_scope}-exec-family.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend "$attachment_backend" --scope "$exec_scope" --origin attach --target-pty \
      --exec-family-regression --cycles 2 --output "$exec_family_root/report"
    record_check "dynamic.attachment_${attachment_backend}_${exec_scope}_exec_family" \
      "report=$exec_family_root/report/result.json; nativeerrno; badpointers; fullstdlibexecfamily; O_PATH; relative; deleted; epoch; stalerequests"
  done
  if [[ $attachment_backend == gum ]]; then
    exec_process_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-process-self-exec.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend gum --scope process --origin attach --target-pty \
      --root-self-exec --root-exec-methods path path fexecve execveat --cycles 2 --output "$exec_process_root/report"
    record_check dynamic.attachment_gum_process_root_self_exec \
      "report=$exec_process_root/report/result.json; scopeprocess; nativeoracle; path+path+fexecve+execveat; strictepochincrements; stalegrantrejection"
    process_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-process.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend gum --scope process --target-pty --cycles 3 --output "$process_root/report"
    record_check dynamic.attachment_gum_process_scope \
      "report=$process_root/report/result.json; unmanagedchildren; nativebadpointeroracle; realPTY"
    process_alias_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-process-issued.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend gum --scope process --issued-fake-ip --inherited-issued --alias-serve-offline \
      --cycles 2 --output "$process_alias_root/report"
    record_check dynamic.attachment_gum_process_inherited_alias \
      "report=$process_alias_root/report/result.json; activeprocessscopechild; inheritednativealiases; collisionalias; restoredepoch"
  fi
  recovery_root=$(mktemp -d "$result_dir/dynamic-attachment-${attachment_backend}-manager.XXXXXX")
  python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
    --backend "$attachment_backend" --manager-loss clean --cycles 1 \
    --output "$recovery_root/report"
  record_check "dynamic.attachment_${attachment_backend}_manager_recovery" \
    "report=$recovery_root/report/result.json; actualSIGKILL; signedrecovery; sameattachment/session"
  restart_root=$(mktemp -d "$result_dir/dynamic-attachment-${attachment_backend}-serve.XXXXXX")
  python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
    --backend "$attachment_backend" --serve-restart --cycles 1 \
    --output "$restart_root/report"
  record_check "dynamic.attachment_${attachment_backend}_serve_restart" \
    "report=$restart_root/report/result.json; cachedpolicy; originaldirectstream; stablesession"
  alias_root=$(mktemp -d "$result_dir/dynamic-attachment-${attachment_backend}-alias.XXXXXX")
  python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
    --backend "$attachment_backend" --fake-ip --cycles 3 \
    --output "$alias_root/report"
  record_check "dynamic.attachment_${attachment_backend}_cached_fake_ip" \
    "report=$alias_root/report/result.json; applicationcache; tightenGatewaydeny; detachednativepeer"
  if [[ $attachment_backend == gum ]]; then
    thread_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-pthread.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend gum --scope process --thread-creation-regression --cycles 1 \
      --output "$thread_root/report"
    record_check memory.attachment_gum_pthread_creation \
      "report=$thread_root/report/result.json; native4active32detached4rounds; concurrentVMAchanges; pthreadreturnandcontents; anonymousmprotectzeroerrors"
    for fork_scope in process tree; do
      fork_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-allocator-fork-${fork_scope}.XXXXXX")
      python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
        --backend gum --scope "$fork_scope" --allocator-fork-regression --cycles 1 \
        --output "$fork_root/report"
      record_check "memory.attachment_gum_allocator_fork_${fork_scope}" \
        "report=$fork_root/report/result.json; repeatedcoldthreads; nativelibc_exit; actualchildreap; activeanddetached; originalrootexit37"
    done
    for mapping_style in plain space newline deleted-literal; do
      mapping_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-mapping-${mapping_style}.XXXXXX")
      python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
        --backend gum --scope process --mapping-regression "$mapping_style" --cycles 1 \
        --output "$mapping_root/report"
      record_check "dynamic.attachment_gum_mapping_${mapping_style}" \
        "report=$mapping_root/report/result.json; coldthreadallocator; closedFDPROT_NONE; fullpathname; FDpressure"
    done
    issued_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-issued-alias.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend gum --issued-fake-ip --inherited-issued --alias-serve-offline --cycles 3 --output "$issued_root/report"
    record_check dynamic.attachment_gum_issued_fake_ip \
      "report=$issued_root/report/result.json; actualSDKsyntheticpublication; unmanagedforkinheritance; stickyDNScollision; Serveoffline; restoredallocator"
    producer_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-cross-producer.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend gum --scope tree --issued-fake-ip --cross-producer-issued \
      --alias-serve-offline --cycles 2 --output "$producer_root/report"
    record_check dynamic.attachment_gum_cross_producer_issued_alias \
      "report=$producer_root/report/result.json; actualchildissuer; sockaddrIPConly; issuerexit; Coreoffline; reattachallocator"
    startup_child_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-child-startup.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend gum --scope tree --child-startup-failure --cycles 1 \
      --output "$startup_child_root/report"
    record_check dynamic.attachment_gum_child_startup_failure \
      "report=$startup_child_root/report/result.json; source=tests/fixtures/attachment_bind_fault.c; actualHostbindfault; heldpasttimeout; newDetachonly; unknownresourcesstayPending"
    for busy_workers in 1 2; do
      busy_root=$(mktemp -d "$result_dir/dynamic-attachment-gum-busy-preparation-${busy_workers}.XXXXXX")
      python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
        --backend gum --scope tree --busy-preparation --busy-fork-workers "$busy_workers" --cycles 2 --target-pty \
        --output "$busy_root/report"
      record_check "dynamic.attachment_gum_busy_preparation_${busy_workers}_workers" \
        "report=$busy_root/report/result.json; everyworkerprogress; postActivepolicy; explicitrefusalandapprovedcleanup"
    done
    record_check dynamic.attachment_gum_busy_preparation \
      "oneandtwoindependentforkworkers; twoapprovedcyclesforeach; perworkercounters"
  fi
  if [[ $attachment_backend == ptrace ]]; then
    dirty_root=$(mktemp -d "$result_dir/dynamic-attachment-ptrace-dirty.XXXXXX")
    python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
      --backend ptrace --manager-loss dirty --cycles 1 --output "$dirty_root/report"
    record_check dynamic.attachment_ptrace_unsafe_recovery_refusal \
      "report=$dirty_root/report/result.json; virtualSOCK_NONBLOCK; actualSIGKILL; unprovenrefused"
  fi
  legacy_root=$(mktemp -d "$result_dir/dynamic-attachment-${attachment_backend}-legacy.XXXXXX")
  python3 "$root/scripts/test-dynamic-attach.py" --hyperhub "$hyperhub" \
    --backend "$attachment_backend" --legacy-negative --output "$legacy_root/report"
  record_check "dynamic.attachment_${attachment_backend}_legacy" \
    "report=$legacy_root/report/result.json; genericexportedABI; refusedbeforemutation"
done
run_restricted_gum_tests
python3 "$root/tests/benchmarks/linux-static/suite_report.py" \
  "$checks_file" \
  "$result_dir/summary.csv" \
  "$fixture_dir/manifest.json" \
  "$result_dir/suite.json" \
  "$result_dir/suite-report.md"
suite_status=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$result_dir/suite.json")
printf 'Linux backend benchmark %s; connections=%d dynamic_hooks=%s static_hooks=%s sandbox_denies=%d\n' \
  "$suite_status" "$connections" "$dynamic_hook_report" "$hook_report" "$denied"
printf 'suite: %s\nreport: %s\nfixtures: %s\n' \
  "$result_dir/suite.json" "$result_dir/suite-report.md" "$fixture_dir/manifest.json"
