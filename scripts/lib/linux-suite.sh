#!/usr/bin/env bash
# Read-only capability classification; sourcing this file performs no IO.
linux_suite_classify_yama() {
  local path=${1:-/proc/sys/kernel/yama/ptrace_scope} value
  linux_gum_available=0
  linux_gum_negative=0
  linux_yama_scope=unknown
  linux_gum_reason='Yama capability could not be established'
  if [[ ! -e $path ]]; then
    linux_gum_available=1
    linux_yama_scope=absent
    linux_gum_reason='Yama is absent; the CLI treats this as unrestricted'
  elif ! value=$(cat -- "$path" 2>/dev/null); then
    linux_gum_reason='Yama scope is unreadable; Gum positive tests cannot run'
  elif [[ $value =~ ^[[:space:]]*([0-3])[[:space:]]*$ ]]; then
    linux_yama_scope=${BASH_REMATCH[1]}
    if [[ $linux_yama_scope == 0 ]]; then
      linux_gum_available=1
      linux_gum_reason='Yama scope 0 permits the Gum test environment'
    else
      linux_gum_negative=1
      linux_gum_reason="Yama scope $linux_yama_scope rejects Gum before target mutation"
    fi
  else
    linux_gum_reason='Yama scope is invalid or unrecognized; Gum positive tests cannot run'
  fi
}

linux_suite_record() {
  local status=$1 name=$2 details=${3:-}
  details=${details//$'\t'/ }
  details=${details//$'\n'/ }
  printf '%s\t%s\t%s\n' "$name" "$status" "$details" >> "$checks_file"
}
record_skip() { linux_suite_record skip "$1" "${2:-$linux_gum_reason}"; }

# Single external commands use this same dispatcher in production and tests.
# Compound groups keep their own if gate so shell errexit remains active.
linux_suite_run_backend() {
  local backend=$1 name=$2 details=$3 status
  shift 3
  case "$backend" in
    gum|ptrace|native|engine) ;;
    *) echo "unknown Suite backend: $backend" >&2; return 2 ;;
  esac
  if [[ $backend == gum && $linux_gum_available != 1 ]]; then
    record_skip "$name" "$linux_gum_reason"
    return 0
  fi
  if "$@"; then
    linux_suite_record pass "$name" "$details"
  else
    status=$?
    linux_suite_record fail "$name" "command exit=$status; $details"
    return "$status"
  fi
}
