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
password='llm-test-password'
password_file="$temporary/password"
printf '%s\n' "$password" > "$password_file"
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
queue="$HOME/.hyperhub/config.approval.bin"
[[ -f $queue ]] || { echo 'planning did not persist the approval queue' >&2; exit 1; }
[[ $(stat -c %a "$queue") == 600 ]]
python3 - "$plan" <<'PY'
import json
import pathlib
import sys
plan = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert plan["status"] == "approval_required"
assert plan["request_count"] == 3
assert plan["changes"]
assert len(plan["approval_token"]) == 64
PY

pending="$temporary/pending.json"
"$hyperhub" config patch "$patch_file" --password-file "$password_file" > "$pending"
python3 - "$pending" <<'PY'
import json
import pathlib
import sys
pending = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert pending["status"] == "approval_pending"
assert pending["completed"] == 0
assert pending["remaining"] == 3
PY
other_patch="$temporary/other-patch.json"
printf '[{"op":"replace","path":"/debug","value":false}]\n' > "$other_patch"
chmod 0600 "$other_patch"
if "$hyperhub" config patch "$other_patch" --password-file "$password_file" >/dev/null 2>&1; then
  echo 'a different patch unexpectedly replaced the pending approval queue' >&2
  exit 1
fi

review_editor="$temporary/review-editor"
cat > "$review_editor" <<'EOF_EDITOR'
#!/usr/bin/env python3
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
operation = json.loads(path.read_text(encoding="utf-8"))
operation["value"]["priority"] = 120
path.write_text(json.dumps(operation, indent=2) + "\n", encoding="utf-8")
EOF_EDITOR
chmod 0700 "$review_editor"

drive_approve() {
  local mode=$1 transcript=$2 secret=${3:-unused} editor=${4:-}
  python3 - "$hyperhub" "$password" "$mode" "$transcript" "$secret" "$editor" <<'PY'
import os
import pathlib
import pty
import select
import signal
import sys

hyperhub, password, mode, transcript, secret, editor = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    argv = [hyperhub, "approve"]
    if editor:
        argv.extend(["--editor", editor])
    os.execve(hyperhub, argv, os.environ.copy())

output = bytearray()
password_sent = False
secret_sent = False
decisions_sent = 0
killed = False
while True:
    ready, _, _ = select.select([fd], [], [], 30)
    if not ready:
        os.kill(pid, signal.SIGKILL)
        raise SystemExit("timed out waiting for approve interaction")
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        chunk = b""
    if not chunk:
        break
    output.extend(chunk)
    text = output.decode("utf-8", errors="replace")
    if not password_sent and "HyperHub password:" in text:
        os.write(fd, password.encode() + b"\n")
        password_sent = True
    if not secret_sent and "Enter value (hidden):" in text:
        os.write(fd, secret.encode() + b"\n")
        secret_sent = True
    prompt_count = text.count("Choose [a]pprove") + text.count("Request is invalid; choose")
    while decisions_sent < prompt_count:
        decisions_sent += 1
        if mode == "interrupt":
            if decisions_sent == 1:
                os.write(fd, b"r\n")
            elif decisions_sent == 2:
                os.write(fd, b"a\n")
            elif decisions_sent == 3:
                os.kill(pid, signal.SIGKILL)
                killed = True
                break
        elif mode == "resume":
            os.write(fd, b"e\n" if decisions_sent == 1 else b"a\n")
        elif mode == "apply":
            os.write(fd, b"a\n")
        else:
            raise SystemExit(f"unknown mode {mode}")
    if killed:
        break

_, status = os.waitpid(pid, 0)
pathlib.Path(transcript).write_bytes(bytes(output))
if password.encode() in output or (secret != "unused" and secret.encode() in output):
    raise SystemExit("approve transcript leaked hidden input")
if not password_sent:
    raise SystemExit("approve did not prompt for the configuration password")
if mode == "interrupt":
    if not killed:
        raise SystemExit("approve was expected to be interrupted")
elif not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
    sys.stderr.buffer.write(output)
    raise SystemExit("approve command failed")
PY
}

first_transcript="$temporary/approve-interrupted.transcript"
drive_approve interrupt "$first_transcript" 'real-github-api-key'
grep -q '\[1/3\] configuration request' "$first_transcript"
grep -q '\[1/3\] rejected' "$first_transcript"
grep -q '\[2/3\] configuration request' "$first_transcript"
grep -q '\[2/3\] approved' "$first_transcript"
grep -q '\[3/3\] configuration request' "$first_transcript"
[[ -f $queue ]] || { echo 'interruption removed the pending approval queue' >&2; exit 1; }

partial="$temporary/partial-show.json"
"$hyperhub" show > "$partial"
python3 - "$partial" <<'PY'
import json
import pathlib
import sys
shown = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert shown["debug"] is False
assert shown["environment"][-1]["name"] == "LLM_TEST_SECRET"
assert shown["environment"][-1]["value"]["value"] == "<redacted>"
assert not shown["routes"]
PY

resume_transcript="$temporary/approve-resumed.transcript"
drive_approve resume "$resume_transcript" unused "$review_editor"
grep -q '\[3/3\] configuration request' "$resume_transcript"
! grep -q '\[1/3\] configuration request' "$resume_transcript"
! grep -q '\[2/3\] configuration request' "$resume_transcript"
grep -q '"edited": true' "$resume_transcript"
grep -q '"status": "completed"' "$resume_transcript"
[[ ! -e $queue ]] || { echo 'completed approval queue was not removed' >&2; exit 1; }

shown="$temporary/show.json"
"$hyperhub" show > "$shown"
cmp "$shown" "$HOME/.hyperhub/config.redacted.json"
[[ $(stat -c %a "$HOME/.hyperhub/config.redacted.json") == 600 ]]
python3 - "$shown" <<'PY'
import json
import pathlib
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert "real-github-api-key" not in text
shown = json.loads(text)
assert shown["debug"] is False
assert shown["environment"][-1]["value"]["value"] == "<redacted>"
route = shown["routes"][-1]
assert route["id"] == "llm-deny-example"
assert route["priority"] == 120
PY
"$hyperhub" validate --password-file "$password_file" >/dev/null
if "$hyperhub" approve --password-file "$password_file" >/dev/null 2>&1; then
  echo 'approve unexpectedly succeeded without pending requests' >&2
  exit 1
fi

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
  printf '[{"op":"replace","path":"/debug","value":true}]\n' > "$live_patch"
  chmod 0600 "$live_patch"
  "$hyperhub" config patch "$live_patch" --password-file "$password_file" > "$temporary/live-plan.json"
  live_transcript="$temporary/live-approve.transcript"
  drive_approve apply "$live_transcript"
  grep -q '\[1/1\] approved (live_update=true)' "$live_transcript"

  kill "$serve_pid" 2>/dev/null || true
  wait "$serve_pid" 2>/dev/null || true
  serve_pid=
}

if ((preexisting_serve)); then
  printf 'skipping isolated live-update check because another Serve is already running for this user\n'
else
  run_live_update_test
fi
printf 'CLI sequential approval integration passed; plan=%s interrupted=%s resumed=%s live=%s\n' \
  "$plan" "$first_transcript" "$resume_transcript" "$live_transcript"
