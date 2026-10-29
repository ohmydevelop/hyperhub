#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
: "${CARGO_TARGET_DIR:=$root/target}"
export CARGO_TARGET_DIR
mapfile -t devkits < <("$root/scripts/frida-devkit.sh")
export HYPERHUB_FRIDA_GUM_ROOT=${devkits[0]}
export HYPERHUB_FRIDA_CORE_ROOT=${devkits[1]}
compiler_include=$(cc -print-file-name=include)
export BINDGEN_EXTRA_CLANG_ARGS="-I$HYPERHUB_FRIDA_CORE_ROOT -isystem $compiler_include ${BINDGEN_EXTRA_CLANG_ARGS:-}"
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo build --release --locked -p hyperhub-agent-core --features gum-agent
export HYPERHUB_EMBEDDED_AGENT_PATH="$CARGO_TARGET_DIR/release/libhyperhub_gum_agent.so"
agent_mark_size=$(readelf --dyn-syms --wide "$HYPERHUB_EMBEDDED_AGENT_PATH" | awk '$8 == "hyperhub_fork_listener_mark_armed" { print $3; exit }')
if [[ ! "$agent_mark_size" =~ ^[0-9]+$ ]] || (( agent_mark_size < 5 )); then
  echo "hyperhub_fork_listener_mark_armed is missing or too short for Frida Interceptor: ${agent_mark_size:-missing}" >&2
  exit 1
fi
cargo build --release --locked -p hyperhub-engine
export HYPERHUB_EMBEDDED_ENGINE_PATH="$CARGO_TARGET_DIR/release/libhyperhub_engine.so"
cargo test --locked -p hyperhub --no-default-features --features embedded-agent embedded_
cargo build --release --locked -p hyperhub --no-default-features --features embedded-agent
printf 'Single-file build complete:\n  %s\nAgent embedded from:\n  %s\n' "$CARGO_TARGET_DIR/release/hyperhub" "$HYPERHUB_EMBEDDED_AGENT_PATH"
