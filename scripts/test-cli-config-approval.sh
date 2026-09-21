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
  {"op":"replace","path":"/gateway/debug","value":true},
  {"op":"add","path":"/environment_variables/-","value":{"name":"LLM_TEST_SECRET","value":{"value":"${APPROVE:github-api-key}"}}},
  {"op":"add","path":"/gateway/routing/routes/-","value":{"id":"llm-deny-example","enabled":true,"priority":100,"endpoints":[{"target":"example.com","port":443}],"decision":{"action":"deny"}}}
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
import re
import pathlib
import sys
plan = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert plan["status"] == "approval_required"
assert plan["request_count"] == 3
assert plan["changes"]
assert len(plan["approval_token"]) == 64
requests = plan["requests"]
assert len(requests) == 3
assert len({request["uuid"] for request in requests}) == 3
assert [request["action"] for request in requests] == ["修改", "新增", "新增"]
assert [request["section"] for request in requests] == ["网关 / 基础", "环境变量", "网关 / 路由"]
assert requests[0]["config_item_uuid"] is None
assert re.fullmatch(r"[0-9a-f-]{36}", requests[1]["config_item_uuid"])
assert re.fullmatch(r"[0-9a-f-]{36}", requests[2]["config_item_uuid"])
assert requests[1]["config_item_uuid"] != requests[2]["config_item_uuid"]
assert requests[1]["details"] == ["变量值=已脱敏"]
assert any("行为=拒绝" in detail for detail in requests[2]["details"])
assert any("example.com" in detail for detail in requests[2]["details"])
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
printf '[{"op":"replace","path":"/gateway/debug","value":false}]\n' > "$other_patch"
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
import time

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
        time.sleep(0.05)
        os.write(fd, password.encode() + b"\n")
        password_sent = True
    if not secret_sent and "Enter value (masked):" in text:
        time.sleep(0.05)
        os.write(fd, secret.encode() + b"\n")
        secret_sent = True
    prompt_count = text.count("选择 [a]批准") + text.count("当前配置项无效；选择")
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
if password.encode() in output:
    raise SystemExit("approve transcript leaked the configuration password")
if secret != "unused" and secret.encode() in output:
    raise SystemExit("approve transcript leaked the sensitive placeholder value")
if secret != "unused" and (b"*" * len(secret.encode())) not in output:
    raise SystemExit("sensitive input did not display masked feedback")
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
grep -q '\[1/3\] 配置审批项' "$first_transcript"
grep -q '\[1/3\] 已拒绝' "$first_transcript"
grep -q '\[2/3\] 配置审批项' "$first_transcript"
grep -q '\[2/3\] 已批准' "$first_transcript"
grep -q '\[3/3\] 配置审批项' "$first_transcript"
python3 - "$plan" "$first_transcript" <<'PY'
import json
import pathlib
import re
import sys
planned = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
text = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
uuids = [request["uuid"] for request in planned["requests"]]
assert len(set(uuids)) == 3
assert all(uuid in text for uuid in uuids)
assert "操作          修改" in text
assert text.count("操作          新增") == 2
assert "位置          网关 / 基础" in text
assert "位置          环境变量" in text
assert "位置          网关 / 路由" in text
PY
[[ -f $queue ]] || { echo 'interruption removed the pending approval queue' >&2; exit 1; }

partial="$temporary/partial-show.json"
"$hyperhub" show > "$partial"
python3 - "$partial" <<'PY'
import json
import pathlib
import sys
shown = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert shown["gateway"]["debug"] is False
assert shown["environment_variables"][-1]["name"] == "LLM_TEST_SECRET"
assert shown["environment_variables"][-1]["value"]["value"] == "<redacted>"
assert not shown["gateway"]["routing"]["routes"]
PY

resume_transcript="$temporary/approve-resumed.transcript"
drive_approve resume "$resume_transcript" unused "$review_editor"
grep -q '\[3/3\] 配置审批项' "$resume_transcript"
! grep -q '\[1/3\] 配置审批项' "$resume_transcript"
! grep -q '\[2/3\] 配置审批项' "$resume_transcript"
grep -q '（已二次编辑）' "$resume_transcript"
grep -q '"status": "completed"' "$resume_transcript"
python3 - "$plan" "$resume_transcript" <<'PY'
import json
import pathlib
import sys
planned = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
text = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
uuids = [request["uuid"] for request in planned["requests"]]
assert uuids[-1] in text
assert all(uuid not in text for uuid in uuids[:-1])
PY
[[ ! -e $queue ]] || { echo 'completed approval queue was not removed' >&2; exit 1; }

shown="$temporary/show.json"
"$hyperhub" show > "$shown"
cmp "$shown" "$HOME/.hyperhub/config.redacted.json"
[[ $(stat -c %a "$HOME/.hyperhub/config.redacted.json") == 600 ]]
python3 - "$shown" "$plan" <<'PY'
import json
import pathlib
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
plan = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
assert "real-github-api-key" not in text
shown = json.loads(text)
assert shown["gateway"]["debug"] is False
assert shown["environment_variables"][-1]["value"]["value"] == "<redacted>"
assert shown["environment_variables"][-1]["uuid"] == plan["requests"][1]["config_item_uuid"]
route = shown["gateway"]["routing"]["routes"][-1]
assert route["uuid"] == plan["requests"][2]["config_item_uuid"]
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
  "$hyperhub" start --password-file "$password_file" \
    >"$temporary/start.stdout" 2>"$temporary/start.stderr"
  skill="$HOME/.agents/skills/hyperhub-cli"
  [[ -f $skill/SKILL.md ]]
  [[ -f $skill/agents/openai.yaml ]]
  python3 - "$skill/.hyperhub-skill.json" <<'PY'
import json
import pathlib
import sys
marker = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert marker["schema_version"] == 1
assert marker["name"] == "hyperhub-cli"
assert len(marker["content_sha256"]) == 64
assert marker["bundle_version"].startswith(marker["cli_version"] + "+sha256.")
PY
  "$hyperhub" start --password-file "$password_file" >"$temporary/start-again.stdout"
  ! grep -q 'Agent Skill installed\|Agent Skill upgraded' "$temporary/start-again.stdout"
  status=$("$hyperhub" status --json)
  grep -q '"state".*"running"' <<<"$status"
  serve_pid=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["pid"])' <<<"$status")

  live_patch="$temporary/live-patch.json"
  printf '[{"op":"replace","path":"/gateway/debug","value":true}]\n' > "$live_patch"
  chmod 0600 "$live_patch"
  "$hyperhub" config patch "$live_patch" --password-file "$password_file" > "$temporary/live-plan.json"
  live_transcript="$temporary/live-approve.transcript"
  drive_approve apply "$live_transcript"
  grep -q '\[1/1\] 已批准（live_update=true）' "$live_transcript"

  "$hyperhub" stop >/dev/null
  serve_pid=
}

if ((preexisting_serve)); then
  printf 'skipping isolated live-update check because another Serve is already running for this user\n'
else
  run_live_update_test
fi
printf 'CLI sequential approval integration passed; plan=%s interrupted=%s resumed=%s live=%s\n' \
  "$plan" "$first_transcript" "$resume_transcript" "$live_transcript"
