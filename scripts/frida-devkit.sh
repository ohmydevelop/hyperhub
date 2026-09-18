#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=17.17.0
arch=${1:-$(uname -m)}
case "$arch" in
  x86_64|x64)
    platform=linux-x86_64; layout=linux-x64
    gum_sha=0987DD51E9901A6DDDD9D55BC9EF02CD90D95012A4947E29DAB942EC7F5348B7
    core_sha=483E1A25945CEBAA69E61C09D7804692C42D234CAB0C58261A73382163027A2E ;;
  aarch64|arm64)
    platform=linux-arm64; layout=linux-arm64
    gum_sha=A035CB1F9F58F03822FA87D6DD578BBADB7C3452BC1B8C08EE31C1F14E29025F
    core_sha=93ACE484ED610961BA153B176C6363A5AC598A1DB3B245EF785175A8229568B0 ;;
  *) echo "unsupported Linux architecture: $arch" >&2; exit 2 ;;
esac
cache="$root/.cache/frida"
mkdir -p "$cache"
install_devkit() {
  local kind=$1 sha=$2 dest=$3 lib=$4
  local archive="$cache/frida-$kind-devkit-$version-$platform.tar.xz"
  if [[ ! -f "$dest/$lib" ]]; then
    if [[ ! -f "$archive" ]]; then
      curl -fL "https://github.com/frida/frida/releases/download/$version/$(basename "$archive")" -o "$archive"
    fi
    echo "$sha  $archive" | sha256sum -c --status -
    mkdir -p "$dest"
    tar -xJf "$archive" -C "$dest"
  fi
}
gum=${HYPERHUB_FRIDA_GUM_ROOT:-"$root/.deps/frida-gum/$version/$layout"}
core=${HYPERHUB_FRIDA_CORE_ROOT:-"$root/.deps/frida-core/$version/$layout"}
if [[ -n ${HYPERHUB_FRIDA_GUM_ROOT:-} ]]; then
  [[ -f "$gum/libfrida-gum.a" ]] || { echo "invalid HYPERHUB_FRIDA_GUM_ROOT: $gum" >&2; exit 2; }
else
  install_devkit gum "$gum_sha" "$gum" libfrida-gum.a
fi
if [[ -n ${HYPERHUB_FRIDA_CORE_ROOT:-} ]]; then
  [[ -f "$core/libfrida-core.a" ]] || { echo "invalid HYPERHUB_FRIDA_CORE_ROOT: $core" >&2; exit 2; }
else
  install_devkit core "$core_sha" "$core" libfrida-core.a
fi
printf '%s\n%s\n' "$gum" "$core"
