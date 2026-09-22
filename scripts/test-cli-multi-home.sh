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
password_file="$temporary/password"
mkdir -p "$home_a" "$home_b" "$agent_home"
printf '%s\n' 'multi-home-test-password' > "$password_file"
chmod 0600 "$password_file"

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
  "$hyperhub" start --password-file "$password_file" > "$temporary/start-a.out"
HOME="$agent_home" HYPERHUB_HOME="$home_b" \
  "$hyperhub" start --password-file "$password_file" > "$temporary/start-b.out"

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

printf 'HyperHub multi-home isolation passed; a=%s b=%s\n' \
  "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["socks_address"])' "$temporary/status-a.json")" \
  "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["socks_address"])' "$temporary/status-b.json")"
