#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
mapfile -t native_devkits < <("$root/scripts/frida-devkit.sh" x86_64)
export HYPERHUB_FRIDA_GUM_ROOT=${native_devkits[0]}
export HYPERHUB_FRIDA_CORE_ROOT=${native_devkits[1]}
native_include=$(cc -print-file-name=include)
export BINDGEN_EXTRA_CLANG_ARGS="-I$HYPERHUB_FRIDA_CORE_ROOT -isystem $native_include"
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo test -p hyperhub-agent-core --features gum-agent --locked
for tuple in "x86_64:x86_64-unknown-linux-gnu" "aarch64:aarch64-unknown-linux-gnu"; do
  arch=${tuple%%:*}; target=${tuple#*:}
  mapfile -t devkits < <(env -u HYPERHUB_FRIDA_GUM_ROOT -u HYPERHUB_FRIDA_CORE_ROOT "$root/scripts/frida-devkit.sh" "$arch")
  export HYPERHUB_FRIDA_GUM_ROOT=${devkits[0]}
  export HYPERHUB_FRIDA_CORE_ROOT=${devkits[1]}
  if [[ $arch == aarch64 ]]; then
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    compiler_include=$(aarch64-linux-gnu-gcc -print-file-name=include)
    export BINDGEN_EXTRA_CLANG_ARGS="--target=$target --sysroot=/usr/aarch64-linux-gnu -I$HYPERHUB_FRIDA_CORE_ROOT -isystem $compiler_include"
  else
    compiler_include=$(cc -print-file-name=include)
    export BINDGEN_EXTRA_CLANG_ARGS="-I$HYPERHUB_FRIDA_CORE_ROOT -isystem $compiler_include"
  fi
  cargo check -p hyperhub-agent-core --features gum-agent --locked --target "$target"
  cargo check -p hyperhub --locked --target "$target"
  cargo build --release -p hyperhub-agent-core --features gum-agent --locked --target "$target"
  export HYPERHUB_EMBEDDED_AGENT_PATH="${CARGO_TARGET_DIR:-$root/target}/$target/release/libhyperhub_gum_agent.so"
  cargo check -p hyperhub --locked --target "$target" --no-default-features --features embedded-agent
done
if command -v cc >/dev/null 2>&1; then
  cc -O2 -Wall -Wextra tests/fixtures/linux_probe.c -o "${TMPDIR:-/tmp}/hyperhub-linux-probe"
  if cc -O2 -Wall -Wextra -static -s -fno-ident -Wl,--build-id=none \
    tests/fixtures/linux_static_probe.c -o "${TMPDIR:-/tmp}/hyperhub-linux-static-probe"; then
    file "${TMPDIR:-/tmp}/hyperhub-linux-static-probe"
    if nm -an "${TMPDIR:-/tmp}/hyperhub-linux-static-probe" | grep -qv '^$'; then
      echo 'static probe still exposes symbols' >&2
      exit 1
    fi
  else
    echo 'static probe build unavailable; skipping static fixture' >&2
  fi
fi

# Run the static syscall supervisor end-to-end with the native release CLI and Agent.
mapfile -t native_devkits < <(env -u HYPERHUB_FRIDA_GUM_ROOT -u HYPERHUB_FRIDA_CORE_ROOT "$root/scripts/frida-devkit.sh" x86_64)
export HYPERHUB_FRIDA_GUM_ROOT=${native_devkits[0]}
export HYPERHUB_FRIDA_CORE_ROOT=${native_devkits[1]}
native_include=$(cc -print-file-name=include)
export BINDGEN_EXTRA_CLANG_ARGS="-I$HYPERHUB_FRIDA_CORE_ROOT -isystem $native_include"
export HYPERHUB_EMBEDDED_AGENT_PATH="${CARGO_TARGET_DIR:-$root/target}/x86_64-unknown-linux-gnu/release/libhyperhub_gum_agent.so"
cargo build --release -p hyperhub --locked --target x86_64-unknown-linux-gnu \
  --no-default-features --features embedded-agent
"$root/scripts/test-cli-config-approval.sh" \
  "$root/target/x86_64-unknown-linux-gnu/release/hyperhub"
"$root/scripts/benchmark-linux-backends.sh" \
  --skip-build \
  --hyperhub "$root/target/x86_64-unknown-linux-gnu/release/hyperhub"
