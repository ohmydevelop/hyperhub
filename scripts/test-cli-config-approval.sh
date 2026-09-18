#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hyperhub=${1:-"$root/target/release/hyperhub"}
[[ -x $hyperhub ]] || { echo "HyperHub is not executable: $hyperhub" >&2; exit 1; }
hyperhub=$(realpath "$hyperhub")

temporary=$(mktemp -d "${TMPDIR:-/tmp}/hyperhub-cli-config.XXXXXX")
serve_pid=
cleanup() {
  [[ -z $serve_pid ]] || { kill "$serve_pid" 2>/dev/null || true; wait "$serve_pid" 2>/dev/null || true; }
  python3 - "$temporary" <<'PY'
import pathlib
import shutil
import sys
shutil.rmtree(pathlib.Path(sys.argv[1]), ignore_errors=True)
PY
}
trap cleanup EXIT INT TERM

export HOME="$temporary/home"
mkdir -p "$HOME"
password_file="$temporary/password"
printf 'llm-test-password\n' > "$password_file"
chmod 0600 "$password_file"
patch_file="$temporary/initial-patch.json"
cat > "$patch_file" <<'JSON'
[
  {"op":"replace","path":"/debug","value":true},
  {"op":"add","path":"/environment/-","value":{"name":"LLM_TEST_SECRET","value":{"value":"top-secret-value"}}},
  {"op":"add","path":"/routes/-","value":{"id":"llm-deny-example","enabled":true,"priority":100,"endpoints":[{"target":"example.com","port":443}],"deny":true,"rewrite_host":null,"rewrite_port":null,"upstream":null,"plugins":[]}}
]
JSON
chmod 0600 "$patch_file"

plan="$temporary/plan.json"
"$hyperhub" config patch "$patch_file" --password-file "$password_file" > "$plan"
if grep -q 'top-secret-value' "$plan"; then
  echo 'planning leaked an inline secret' >&2
  exit 1
fi
[[ ! -e $HOME/.hyperhub/config.bin ]] || { echo 'planning unexpectedly modified config' >&2; exit 1; }
approval=$(python3 - "$plan" <<'PY'
import json
import pathlib
import sys
plan = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert plan["status"] == "approval_required"
assert plan["changes"]
print(plan["approval_token"])
PY
)

if "$hyperhub" config patch "$patch_file" \
  --password-file "$password_file" --approve invalid-token >/dev/null 2>&1; then
  echo 'invalid approval token unexpectedly applied config' >&2
  exit 1
fi
[[ ! -e $HOME/.hyperhub/config.bin ]] || { echo 'invalid approval modified config' >&2; exit 1; }

applied="$temporary/applied.json"
"$hyperhub" config patch "$patch_file" \
  --password-file "$password_file" --approve "$approval" > "$applied"
if grep -q 'top-secret-value' "$applied"; then
  echo 'apply result leaked an inline secret' >&2
  exit 1
fi
python3 - "$applied" <<'PY'
import json
import pathlib
import sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert result["status"] == "applied"
assert result["live_update"] is False
PY

shown="$temporary/show.json"
"$hyperhub" config show --password-file "$password_file" > "$shown"
python3 - "$shown" <<'PY'
import json
import pathlib
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert "top-secret-value" not in text
shown = json.loads(text)
assert shown["initialized"] is True
assert shown["config"]["debug"] is True
assert shown["config"]["environment"][-1]["value"]["value"] == "<redacted>"
assert shown["config"]["routes"][-1]["id"] == "llm-deny-example"
PY
"$hyperhub" validate --password-file "$password_file" >/dev/null

"$hyperhub" serve --password-file "$password_file" \
  >"$temporary/serve.stdout" 2>"$temporary/serve.stderr" &
serve_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  if "$hyperhub" status --json 2>/dev/null | grep -q '"state".*"running"'; then
    break
  fi
  kill -0 "$serve_pid" 2>/dev/null || {
    cat "$temporary/serve.stderr" >&2
    echo 'Serve exited during config approval test' >&2
    exit 1
  }
  sleep 0.05
done
"$hyperhub" status --json | grep -q '"state".*"running"'

live_patch="$temporary/live-patch.json"
printf '[{"op":"replace","path":"/debug","value":false}]\n' > "$live_patch"
live_plan="$temporary/live-plan.json"
"$hyperhub" config patch "$live_patch" --password-file "$password_file" > "$live_plan"
live_approval=$(python3 - "$live_plan" <<'PY'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["approval_token"])
PY
)
live_applied="$temporary/live-applied.json"
"$hyperhub" config patch "$live_patch" \
  --password-file "$password_file" --approve "$live_approval" > "$live_applied"
python3 - "$live_applied" <<'PY'
import json
import pathlib
import sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert result["status"] == "applied"
assert result["live_update"] is True
PY

kill "$serve_pid" 2>/dev/null || true
wait "$serve_pid" 2>/dev/null || true
serve_pid=
printf 'CLI config approval integration passed; plan=%s applied=%s live=%s\n' \
  "$plan" "$applied" "$live_applied"
