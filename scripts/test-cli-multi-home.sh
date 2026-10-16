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
printf '%s\n' 'multi-home-test-password' > "$admin_password_file"
chmod 0600 "$admin_password_file"

stop_instance() {
  local instance=$1
  HOME="$agent_home" HYPERHUB_HOME="$instance" \
    "$hyperhub" stop >/dev/null 2>&1 || true
}
cleanup() {
  stop_instance "$home_a"
  stop_instance "$home_b"
  chmod -R u+w "$temporary" 2>/dev/null || true
  rm -rf "$temporary"
}
trap cleanup EXIT INT TERM

HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" start --admin-password-file "$admin_password_file" > "$temporary/start-a.out"
HOME="$agent_home" HYPERHUB_HOME="$home_b" \
  "$hyperhub" start --admin-password-file "$admin_password_file" > "$temporary/start-b.out"

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
HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" start --password-file "$home_a/runtime/api-key" > "$temporary/restart-a.out"
HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" validate --password-file "$home_a/runtime/api-key" >/dev/null

HOME="$agent_home" HYPERHUB_HOME="$home_b" "$hyperhub" stop >/dev/null
rm "$home_b/runtime/config-key.bin"
HOME="$agent_home" HYPERHUB_HOME="$home_b" \
  "$hyperhub" start --admin-password-file "$admin_password_file" > "$temporary/migrate-b.out"
[[ -f $home_b/runtime/config-key.bin ]]

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

# Use a valid but unrelated API key to distinguish authentication from stale generation.
python3 - "$temporary/wrong-api-key" <<'PY'
import base64
import os
import sys
with os.fdopen(os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
    file.write("hhk_" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))
PY
if HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" validate --password-file "$temporary/wrong-api-key" > "$temporary/wrong-api-key.out" 2>&1; then
  echo 'Validation accepted an unrelated API key' >&2
  exit 1
fi
grep -qF 'with the API key' "$temporary/wrong-api-key.out"

# Build a stale-generation envelope encrypted by the same API key, without
# corrupting either encrypted file. Start must reject it before spawning Serve.
stop_instance "$home_b"
cp "$home_a/runtime/api-key" "$home_b/runtime/api-key"
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
HOME="$agent_home" HYPERHUB_HOME="$home_a" \
  "$hyperhub" start --admin-password-file "$admin_password_file" > "$temporary/repair-a.out"
cmp "$home_a/config.bin" "$temporary/config-before-repair.bin"
HOME="$agent_home" HYPERHUB_HOME="$home_a" "$hyperhub" validate >/dev/null

printf 'HyperHub multi-home isolation passed; a=%s b=%s\n' \
  "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["socks_address"])' "$temporary/status-a.json")" \
  "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["socks_address"])' "$temporary/status-b.json")"
