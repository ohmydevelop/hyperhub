#!/usr/bin/env bash
set -euo pipefail

cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
if [[ -d "$cargo_home/bin" ]]; then
  export PATH="$cargo_home/bin:$PATH"
fi

remote_root=$1
install_path=$2
keep_remote=$3

if [[ ! "$remote_root" =~ ^/tmp/hyperhub-remote-[0-9a-f]{32}$ ]]; then
  echo "unsafe remote staging path: $remote_root" >&2
  exit 2
fi

cleanup() {
  if [[ "$keep_remote" != 1 ]]; then
    rm -rf -- "$remote_root"
  fi
}
trap cleanup EXIT

case "$install_path" in
  /*) ;;
  *) echo "install path must be absolute: $install_path" >&2; exit 2 ;;
esac
if [[ "$install_path" == / || "$install_path" == */ ]]; then
  echo "install path must name a file: $install_path" >&2
  exit 2
fi

for command in bash cargo rustc cc clang tar xz sha256sum install; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required Linux build command is missing: $command" >&2
    exit 2
  }
done

archive="$remote_root/source.tar"
gum_archive="$remote_root/frida-gum.tar.xz"
core_archive="$remote_root/frida-core.tar.xz"
build_root="$remote_root/build"
for input in "$archive" "$gum_archive" "$core_archive"; do
  [[ -f "$input" ]] || {
    echo "remote build input is missing: $input" >&2
    exit 2
  }
done

mkdir -p -- "$build_root"
tar -xf "$archive" -C "$build_root"
devkit_root="$remote_root/devkits"
mkdir -p "$devkit_root/gum" "$devkit_root/core"
tar -xJf "$gum_archive" -C "$devkit_root/gum"
tar -xJf "$core_archive" -C "$devkit_root/core"
export HYPERHUB_FRIDA_GUM_ROOT="$devkit_root/gum"
export HYPERHUB_FRIDA_CORE_ROOT="$devkit_root/core"

cd "$build_root"
chmod +x scripts/*.sh

export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

printf 'Building HyperHub on %s (%s)...\n' "$(uname -s)" "$(uname -m)"
./scripts/build.sh

binary="$build_root/target/release/hyperhub"
[[ -x "$binary" ]] || {
  echo "Linux build did not produce $binary" >&2
  exit 2
}

build_sha=$(sha256sum "$binary" | awk '{print $1}')
install_directory=$(dirname -- "$install_path")
if [[ -w "$install_path" || -w "$install_directory" ]]; then
  install -m 0755 "$binary" "$install_path"
elif [[ $(id -u) -eq 0 ]]; then
  install -m 0755 "$binary" "$install_path"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -m 0755 "$binary" "$install_path"
else
  echo "installing to $install_path requires root or sudo" >&2
  exit 2
fi

installed_sha=$(sha256sum "$install_path" | awk '{print $1}')
if [[ "$build_sha" != "$installed_sha" ]]; then
  echo "installed binary SHA-256 mismatch" >&2
  exit 2
fi

"$install_path" --help >/dev/null
doctor_output=$("$install_path" doctor)
printf '%s\n' "$doctor_output"
grep -q 'agent_runtime=embedded-verified' <<<"$doctor_output" || {
  echo "installed CLI does not report an embedded verified Agent" >&2
  exit 2
}

printf 'Remote installation complete:\n  path=%s\n  sha256=%s\n' "$install_path" "$installed_sha"
