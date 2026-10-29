#!/usr/bin/env bash
# Standard Linux setup requires the complete, verified source-built patchset.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
arch=${1:-$(uname -m)}
case "$arch" in
  x86_64|x64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo "unsupported Linux architecture: $arch" >&2; exit 2 ;;
esac
options=(--architecture "$arch" --jobs "${HYPERHUB_FRIDA_BUILD_JOBS:-2}")
if [[ -n ${HYPERHUB_FRIDA_CACHE_ROOT:-} ]]; then
  options+=(--cache-root "$HYPERHUB_FRIDA_CACHE_ROOT")
fi
if [[ -n ${HYPERHUB_FRIDA_GUM_ROOT:-} || -n ${HYPERHUB_FRIDA_CORE_ROOT:-} ]]; then
  if [[ -z ${HYPERHUB_FRIDA_GUM_ROOT:-} || -z ${HYPERHUB_FRIDA_CORE_ROOT:-} ]]; then
    echo 'Linux SDK overrides require both HYPERHUB_FRIDA_GUM_ROOT and HYPERHUB_FRIDA_CORE_ROOT' >&2
    exit 2
  fi
  options+=(--gum-root "$HYPERHUB_FRIDA_GUM_ROOT" --core-root "$HYPERHUB_FRIDA_CORE_ROOT")
fi
exec python3 "$root/scripts/frida-native-deps.py" "${options[@]}"
