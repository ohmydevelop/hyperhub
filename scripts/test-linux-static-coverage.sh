#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hyperhub=${1:-"$root/target/release/hyperhub"}
runtime=${2:-"$root/target/release/libhyperhub_gum_agent.so"}
output=${3:-"$root/target/benchmarks/linux-backends"}

exec "$root/scripts/benchmark-linux-backends.sh" \
  --skip-build \
  --hyperhub "$hyperhub" \
  --runtime "$runtime" \
  --output "$output"
