#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hyperhub=${1:-"$root/target/debug/hyperhub"}
[[ -x $hyperhub ]] || { echo "HyperHub is not executable: $hyperhub" >&2; exit 1; }
hyperhub=$(realpath "$hyperhub")
mkdir -p "$root/target"
temporary=$(mktemp -d "$root/target/hyperhub-multi-home.XXXXXX")
home_a="$temporary/instance-a"
home_b="$temporary/instance-b"
agent_home="$temporary/agent-home"
admin_password_file="$temporary/admin-password"
mkdir -p "$home_a" "$home_b" "$agent_home"
# Keep isolated CLI regressions independent of GitHub upgrade checks.
python3 - "$home_a" "$home_b" <<'PY'
import json
import pathlib
import sys
import time
for directory in sys.argv[1:]:
    (pathlib.Path(directory) / "upgrade-check.json").write_text(
        json.dumps({"last_check_ms": int(time.time() * 1000)}), encoding="utf-8"
    )
PY
printf '%s\n' 'multi-home-test-password' > "$admin_password_file"
chmod 0600 "$admin_password_file"

stop_instance() {
  local instance=$1
  HOME="$agent_home" HYPERHUB_HOME="$instance" \
    "$hyperhub" stop >/dev/null 2>&1 || true
}
stage=setup
failure_diagnostics() {
  python3 - "$temporary" "$stage" "$1" <<'PY_MULTI_HOME_DIAGNOSTICS'
import json
import os
import pathlib
import stat
import sys
root = pathlib.Path(sys.argv[1])
print(f"MULTI_HOME_FAILURE stage={sys.argv[2]} exit={sys.argv[3]}", file=sys.stderr)
paths = ["instance-a/serve.log", "instance-b/serve.log"]
paths += [name + ".out" for name in ("start-a", "start-b", "restart-a", "migrate-b", "rewrap-b", "repair-a")]
paths += ["status-a.json", "status-b.json"]
for name in paths:
    path = root / name
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as file:
            metadata = os.fstat(file.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                continue
            file.seek(max(0, metadata.st_size - 16384))
            data = file.read(16384)
        if name.endswith(".json"):
            value = json.loads(data)
            text = json.dumps({key: value[key] for key in ("state", "pid", "control_endpoint", "hyperhub_home", "socks_address") if key in value}, ensure_ascii=False)
        else:
            text = "\n".join(data.decode("utf-8", errors="replace").splitlines()[-32:])
        print(f"MULTI_HOME_LOG {name}: {text}", file=sys.stderr)
    except (OSError, ValueError):
        pass
PY_MULTI_HOME_DIAGNOSTICS
}
cleanup() {
  local exit_code=$1
  trap - EXIT INT TERM
  if ((exit_code != 0)); then
    failure_diagnostics "$exit_code" || true
  fi
  stop_instance "$home_a"
  stop_instance "$home_b"
  chmod -R u+w "$temporary" 2>/dev/null || true
  rm -rf "$temporary"
  exit "$exit_code"
}
trap 'cleanup "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stage=start-a
HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" start --admin-password-file "$admin_password_file" > "$temporary/start-a.out"
stage=start-b
HOME="$agent_home" HYPERHUB_HOME="$home_b" \
  "$hyperhub" start --admin-password-file "$admin_password_file" > "$temporary/start-b.out"

stage=status
HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" status --json > "$temporary/status-a.json"
HOME="$agent_home" HYPERHUB_HOME="$home_b" \
  "$hyperhub" status --json > "$temporary/status-b.json"

python3 - "$temporary/status-a.json" "$temporary/status-b.json" "$home_a" "$home_b" <<'PY'
import json
import pathlib
import sys

a = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
b = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
home_a = str(pathlib.Path(sys.argv[3]).resolve())
home_b = str(pathlib.Path(sys.argv[4]).resolve())
assert a["state"] == b["state"] == "running"
assert a["pid"] != b["pid"]
assert a["hyperhub_home"] == home_a
assert b["hyperhub_home"] == home_b
assert a["control_endpoint"] != b["control_endpoint"]
assert a["control_endpoint"] == str(pathlib.Path(home_a) / "runtime" / "control.sock")
assert b["control_endpoint"] == str(pathlib.Path(home_b) / "runtime" / "control.sock")
address_a = a["socks_address"].rsplit(":", 1)
address_b = b["socks_address"].rsplit(":", 1)
assert address_a[0] == address_b[0] == "127.0.0.1"
assert int(address_b[1]) > int(address_a[1]), (a["socks_address"], b["socks_address"])
PY

[[ -f $home_a/config.bin && -f $home_b/config.bin ]]
[[ -S $home_a/runtime/control.sock && -S $home_b/runtime/control.sock ]]
[[ -f $home_a/runtime/api-key && -f $home_b/runtime/api-key ]]
[[ -f $home_a/runtime/config-key.bin && -f $home_b/runtime/config-key.bin ]]

HOME="$agent_home" HYPERHUB_HOME="$home_a" "$hyperhub" stop >/dev/null
stage=restart-a
HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" start > "$temporary/restart-a.out"
HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" validate >/dev/null

stage=runtime-auth
# Run authenticates with this instance's API key without an explicit argument.
test_target=$(command -v true)
HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" run --dry-run -- "$test_target" > "$temporary/run-a.out"
HOME="$agent_home" HYPERHUB_HOME="$home_b" \
  "$hyperhub" run --dry-run -- "$test_target" > "$temporary/run-b.out"
for option in --password-file --api-key-file; do
  if HOME="$agent_home" HYPERHUB_HOME="$home_a" \
    "$hyperhub" run "$option" "$home_a/runtime/api-key" -- "$test_target" > "$temporary/removed-option.out" 2>&1; then
    echo "Run accepted removed option $option" >&2
    exit 1
  fi
  grep -qF 'loaded automatically' "$temporary/removed-option.out"
done

stage=missing-key
# Missing keys must fail without recreating credentials or granting a session.
mv "$home_a/runtime/api-key" "$temporary/saved-api-key"
if HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" run --dry-run -- "$test_target" > "$temporary/missing-api-key.out" 2>&1; then
  echo 'Run accepted a missing API key' >&2
  exit 1
fi
grep -qF 'API key file' "$temporary/missing-api-key.out"
[[ ! -e $home_a/runtime/api-key ]]
mv "$temporary/saved-api-key" "$home_a/runtime/api-key"

HOME="$agent_home" HYPERHUB_HOME="$home_b" "$hyperhub" stop >/dev/null
rm "$home_b/runtime/config-key.bin"
stage=migrate-b
HOME="$agent_home" HYPERHUB_HOME="$home_b" \
  "$hyperhub" start --admin-password-file "$admin_password_file" > "$temporary/migrate-b.out"
[[ -f $home_b/runtime/config-key.bin ]]

stage=wrong-admin
# A wrong administrator password must not replace a valid runtime envelope.
wrong_password_file="$temporary/wrong-password"
printf '%s\n' 'incorrect-test-password' > "$wrong_password_file"
chmod 0600 "$wrong_password_file"
cp "$home_a/runtime/config-key.bin" "$temporary/key-before-wrong-password.bin"
if HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" serve --admin-password-file "$wrong_password_file" > "$temporary/wrong-password.out" 2>&1; then
  echo 'Serve accepted an incorrect administrator password' >&2
  exit 1
fi
cmp "$home_a/runtime/config-key.bin" "$temporary/key-before-wrong-password.bin"
HOME="$agent_home" HYPERHUB_HOME="$home_a" "$hyperhub" validate >/dev/null

stage=wrong-api-key
# Use a valid but unrelated API key to distinguish authentication from stale generation.
python3 - "$temporary/wrong-api-key" <<'PY'
import base64
import os
import sys
with os.fdopen(os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
    file.write("hhk_" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))
PY
cp "$home_a/runtime/api-key" "$temporary/saved-api-key"
cp "$temporary/wrong-api-key" "$home_a/runtime/api-key"
if HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" validate > "$temporary/wrong-api-key.out" 2>&1; then
  echo 'Validation accepted an unrelated API key' >&2
  exit 1
fi
grep -qF 'with the API key' "$temporary/wrong-api-key.out"
if HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" run --dry-run -- "$test_target" > "$temporary/wrong-run-key.out" 2>&1; then
  echo 'Run accepted an unrelated API key' >&2
  exit 1
fi
grep -qF 'rejected session registration' "$temporary/wrong-run-key.out"
cp "$temporary/saved-api-key" "$home_a/runtime/api-key"

stage=stale-generation
# Build a stale-generation envelope encrypted by the same API key, without
# corrupting either encrypted file. Start must reject it before spawning Serve.
stop_instance "$home_b"
cp "$home_a/runtime/api-key" "$home_b/runtime/api-key"
stage=rewrap-b
HOME="$agent_home" HYPERHUB_HOME="$home_b" \
  "$hyperhub" start --admin-password-file "$admin_password_file" > "$temporary/rewrap-b.out"
stop_instance "$home_a"
cp "$home_a/config.bin" "$temporary/config-before-repair.bin"
cp "$home_b/runtime/config-key.bin" "$home_a/runtime/config-key.bin"
log_bytes=$(wc -c < "$home_a/serve.log")
if HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" start > "$temporary/stale-key.out" 2>&1; then
  echo 'Start accepted a stale-generation runtime key' >&2
  exit 1
fi
grep -qF 'out of date' "$temporary/stale-key.out"
[[ $(wc -c < "$home_a/serve.log") -eq $log_bytes ]]
stage=repair-a
HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" start --admin-password-file "$admin_password_file" > "$temporary/repair-a.out"
cmp "$home_a/config.bin" "$temporary/config-before-repair.bin"
HOME="$agent_home" HYPERHUB_HOME="$home_a" "$hyperhub" validate >/dev/null

printf 'HyperHub multi-home isolation passed; a=%s b=%s\n' \
  "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["socks_address"])' "$temporary/status-a.json")" \
  "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["socks_address"])' "$temporary/status-b.json")"
