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

preexisting_serve=0
if "$hyperhub" status --json 2>/dev/null | grep -q '"state".*"running"'; then
  preexisting_serve=1
fi

export HOME="$temporary/home"
export XDG_RUNTIME_DIR="$temporary/runtime"
mkdir -p "$HOME" "$XDG_RUNTIME_DIR"
chmod 0700 "$XDG_RUNTIME_DIR"
password_file="$temporary/password"
printf 'llm-test-password\n' > "$password_file"
chmod 0600 "$password_file"
patch_file="$temporary/initial-patch.json"
cat > "$patch_file" <<'JSON'
[
  {"op":"replace","path":"/debug","value":true},
  {"op":"add","path":"/environment/-","value":{"name":"LLM_TEST_SECRET","value":{"value":"${APPROVE:github-api-key}"}}},
  {"op":"add","path":"/routes/-","value":{"id":"llm-deny-example","enabled":true,"priority":100,"endpoints":[{"target":"example.com","port":443}],"deny":true,"rewrite_host":null,"rewrite_port":null,"upstream":null,"plugins":[]}}
]
JSON
chmod 0600 "$patch_file"

plan="$temporary/plan.json"
"$hyperhub" config patch "$patch_file" --password-file "$password_file" > "$plan"
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

if "$hyperhub" approve "$patch_file" \
  --password-file "$password_file" --token invalid-token >/dev/null 2>&1; then
  echo 'invalid approval token unexpectedly applied config' >&2
  exit 1
fi
[[ ! -e $HOME/.hyperhub/config.bin ]] || { echo 'invalid approval modified config' >&2; exit 1; }

review_editor="$temporary/review-editor"
cat > "$review_editor" <<'EOF_EDITOR'
#!/usr/bin/env python3
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
patch = json.loads(path.read_text(encoding="utf-8"))
for operation in patch:
    value = operation.get("value")
    if isinstance(value, dict) and value.get("id") == "llm-deny-example":
        value["priority"] = 120
path.write_text(json.dumps(patch, indent=2) + "\n", encoding="utf-8")
EOF_EDITOR
chmod 0700 "$review_editor"

run_approve() {
  local patch=$1 token=$2 editor=$3 secret=$4 decision=$5 transcript=$6
  python3 - "$hyperhub" "$patch" "$password_file" "$token" "$editor" "$secret" "$decision" "$transcript" <<'PY'
import os
import pathlib
import pty
import re
import select
import sys

hyperhub, patch, password, token, editor, secret, decision, transcript = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    environment = os.environ.copy()
    os.execve(
        hyperhub,
        [
            hyperhub,
            "approve",
            patch,
            "--password-file",
            password,
            "--token",
            token,
            "--editor",
            editor,
        ],
        environment,
    )

output = bytearray()
sent_secret = False
sent_confirmation = False
while True:
    ready, _, _ = select.select([fd], [], [], 30)
    if not ready:
        os.kill(pid, 9)
        raise SystemExit("timed out waiting for approve interaction")
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        chunk = b""
    if not chunk:
        break
    output.extend(chunk)
    text = output.decode("utf-8", errors="replace")
    if not sent_secret and "Value for approval placeholder" in text:
        os.write(fd, secret.encode() + b"\n")
        sent_secret = True
    if not sent_confirmation:
        match = re.search(r"Type APPLY ([0-9a-f]{12}) to confirm:", text)
        if match:
            answer = f"APPLY {match.group(1)}" if decision == "apply" else "CANCEL"
            os.write(fd, f"{answer}\n".encode())
            sent_confirmation = True

_, status = os.waitpid(pid, 0)
pathlib.Path(transcript).write_bytes(bytes(output))
exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 255
if decision == "apply" and exit_code != 0:
    sys.stderr.buffer.write(output)
    raise SystemExit("approve command failed")
if decision == "cancel" and exit_code == 0:
    raise SystemExit("cancelled approval unexpectedly succeeded")
if decision == "cancel" and b"configuration approval was cancelled" not in output:
    sys.stderr.buffer.write(output)
    raise SystemExit("cancelled approval did not report cancellation")
if secret.encode() in output:
    raise SystemExit("approve output leaked the manually entered secret")
PY
}

cancelled_transcript="$temporary/cancelled-approve.transcript"
run_approve "$patch_file" "$approval" "$review_editor" 'cancelled-secret' cancel "$cancelled_transcript"
[[ ! -e $HOME/.hyperhub/config.bin ]] || { echo 'cancelled approval modified config' >&2; exit 1; }

transcript="$temporary/approve.transcript"
run_approve "$patch_file" "$approval" "$review_editor" 'real-github-api-key' apply "$transcript"

shown="$temporary/show.json"
"$hyperhub" show > "$shown"
if "$hyperhub" config show >"$temporary/config-show.stdout" 2>"$temporary/config-show.stderr"; then
  echo 'removed config show alias unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'use `hyperhub show`' "$temporary/config-show.stderr"
cmp "$shown" "$HOME/.hyperhub/config.redacted.json"
[[ $(stat -c %a "$HOME/.hyperhub/config.redacted.json") == 600 ]]
python3 - "$shown" <<'PY'
import json
import pathlib
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert "real-github-api-key" not in text
shown = json.loads(text)
assert shown["debug"] is True
assert shown["environment"][-1]["value"]["value"] == "<redacted>"
route = shown["routes"][-1]
assert route["id"] == "llm-deny-example"
assert route["priority"] == 120
PY
"$hyperhub" validate --password-file "$password_file" >/dev/null

redacted_view="$HOME/.hyperhub/config.redacted.json"
rm "$redacted_view"
if "$hyperhub" show >/dev/null 2>"$temporary/missing-view.stderr"; then
  echo 'show unexpectedly decrypted an existing config without its redacted view' >&2
  exit 1
fi
grep -q 'run `hyperhub validate' "$temporary/missing-view.stderr"
"$hyperhub" validate --password-file "$password_file" >/dev/null
migrated_show="$temporary/migrated-show.json"
"$hyperhub" show > "$migrated_show"
cmp "$migrated_show" "$redacted_view"

live_transcript=skipped
run_live_update_test() {
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
  chmod 0600 "$live_patch"
  live_plan="$temporary/live-plan.json"
  "$hyperhub" config patch "$live_patch" --password-file "$password_file" > "$live_plan"
  live_approval=$(python3 - "$live_plan" <<'PYCODE'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["approval_token"])
PYCODE
)
  noop_editor="$temporary/noop-editor"
  cat > "$noop_editor" <<'EOF_EDITOR'
#!/bin/sh
exit 0
EOF_EDITOR
  chmod 0700 "$noop_editor"
  live_transcript="$temporary/live-approve.transcript"
  run_approve "$live_patch" "$live_approval" "$noop_editor" unused apply "$live_transcript"
  grep -q '"live_update": true' "$live_transcript"

  kill "$serve_pid" 2>/dev/null || true
  wait "$serve_pid" 2>/dev/null || true
  serve_pid=
}

if ((preexisting_serve)); then
  printf 'skipping isolated live-update check because another Serve is already running for this user\n'
else
  run_live_update_test
fi
printf 'CLI human approval integration passed; plan=%s review=%s live=%s\n' \
  "$plan" "$transcript" "$live_transcript"
