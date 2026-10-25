#!/usr/bin/env bash
# Prepare only a disposable GitHub-hosted test VM. This is never a CLI fallback.
set -euo pipefail
if [[ ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted || ${RUNNER_OS:-} != Linux ]]; then
  echo 'Linux Gum test environment changes require a disposable GitHub-hosted Linux runner.' >&2
  exit 2
fi
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
state="$RUNNER_TEMP/hyperhub-yama-before"
case ${1:-} in
  prepare)
    original=$(sysctl -n kernel.yama.ptrace_scope)
    case $original in 0|1|2|3) ;; *) echo 'Unrecognized Yama policy; refusing test setup.' >&2; exit 2;; esac
    (umask 077; set -o noclobber; printf '%s\n' "$original" > "$state")
    sudo sysctl -w kernel.yama.ptrace_scope=0
    [[ $(sysctl -n kernel.yama.ptrace_scope) == 0 ]]
    ;;
  restore)
    if [[ -f $state ]]; then
      read -r original < "$state"
      case $original in 0|1|2|3) ;; *) echo 'Invalid saved Yama policy; refusing restore.' >&2; exit 2;; esac
      sudo sysctl -w "kernel.yama.ptrace_scope=$original"
      [[ $(sysctl -n kernel.yama.ptrace_scope) == "$original" ]]
      rm -- "$state"
    fi
    ;;
  *) echo 'Usage: ci-linux-gum-environment.sh prepare|restore' >&2; exit 2;;
esac
