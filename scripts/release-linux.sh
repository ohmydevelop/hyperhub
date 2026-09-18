#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

arch=${1:-$(uname -m)}
case "$arch" in
  x86_64|x64)
    arch=x86_64
    target=x86_64-unknown-linux-gnu
    linker=cc
    bindgen_args="--target=$target"
    ;;
  aarch64|arm64)
    arch=aarch64
    target=aarch64-unknown-linux-gnu
    linker=aarch64-linux-gnu-gcc
    bindgen_args="--target=$target --sysroot=/usr/aarch64-linux-gnu"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$linker"
    ;;
  *)
    echo "unsupported Linux architecture: $arch" >&2
    exit 2
    ;;
esac

: "${CARGO_TARGET_DIR:=$root/target}"
export CARGO_TARGET_DIR
mapfile -t devkits < <("$root/scripts/frida-devkit.sh" "$arch")
export HYPERHUB_FRIDA_GUM_ROOT=${devkits[0]}
export HYPERHUB_FRIDA_CORE_ROOT=${devkits[1]}

compiler_include=$("$linker" -print-file-name=include)
export BINDGEN_EXTRA_CLANG_ARGS="$bindgen_args -I$HYPERHUB_FRIDA_CORE_ROOT -isystem $compiler_include ${BINDGEN_EXTRA_CLANG_ARGS:-}"

cargo build --release --locked \
  -p hyperhub-agent-core \
  --features gum-agent \
  --target "$target"

export HYPERHUB_EMBEDDED_AGENT_PATH="$CARGO_TARGET_DIR/$target/release/libhyperhub_gum_agent.so"
test -f "$HYPERHUB_EMBEDDED_AGENT_PATH"

cargo build --release --locked \
  -p hyperhub \
  --no-default-features \
  --features embedded-agent \
  --target "$target"

binary="$CARGO_TARGET_DIR/$target/release/hyperhub"
test -x "$binary"
printf 'Linux release binary: %s\nEmbedded Agent: %s\n' "$binary" "$HYPERHUB_EMBEDDED_AGENT_PATH"
