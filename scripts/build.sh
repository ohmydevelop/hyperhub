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
cargo test --locked -p hyperhub --no-default-features --features embedded-agent embedded_
cargo build --release --locked -p hyperhub --no-default-features --features embedded-agent
printf 'Single-file build complete:\n  %s\nAgent embedded from:\n  %s\n' "$CARGO_TARGET_DIR/release/hyperhub" "$HYPERHUB_EMBEDDED_AGENT_PATH"
