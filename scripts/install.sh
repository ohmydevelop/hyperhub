#!/usr/bin/env sh
set -eu

repo="${HYPERHUB_REPO:-flash-dev-ctrl/hyperhub}"
version="${HYPERHUB_VERSION:-latest}"
install_dir="${HYPERHUB_INSTALL_DIR:-$HOME/.local/bin}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

[ "$(uname -s)" = Linux ] || {
  echo "error: this installer supports Linux only" >&2
  exit 1
}

case "$(uname -m)" in
  x86_64|amd64) asset=hyperhub-linux-x86_64.tar.gz ;;
  aarch64|arm64) asset=hyperhub-linux-aarch64.tar.gz ;;
  *) echo "error: unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac

need tar
need mktemp
if command -v curl >/dev/null 2>&1; then
  downloader=curl
elif command -v wget >/dev/null 2>&1; then
  downloader=wget
else
  echo "error: curl or wget is required" >&2
  exit 1
fi

if [ "$version" = latest ]; then
  url="https://github.com/$repo/releases/latest/download/$asset"
else
  case "$version" in
    v*) tag=$version ;;
    *) tag="v$version" ;;
  esac
  url="https://github.com/$repo/releases/download/$tag/$asset"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
archive="$tmp/$asset"
if [ "$downloader" = curl ]; then
  curl -fsSL "$url" -o "$archive"
else
  wget -qO "$archive" "$url"
fi

mkdir -p "$tmp/extract" "$install_dir"
tar -xzf "$archive" -C "$tmp/extract"
bin=$(find "$tmp/extract" -type f -name hyperhub -perm -u+x 2>/dev/null | head -n 1)
[ -n "$bin" ] || bin=$(find "$tmp/extract" -type f -name hyperhub 2>/dev/null | head -n 1)
[ -n "$bin" ] || {
  echo "error: hyperhub binary not found in $asset" >&2
  exit 1
}

install -m 0755 "$bin" "$install_dir/hyperhub"
"$install_dir/hyperhub" --help >/dev/null

cat > "$install_dir/hsh" <<EOF
#!/usr/bin/env sh
set -eu
shell="\${HYPERHUB_SHELL:-\${SHELL:-bash}}"
shell="\${shell##*/}"
case "\$shell" in
  bash|sh|zsh|fish|ksh|dash) ;;
  *) shell=bash ;;
esac
exec "$install_dir/hyperhub" run "\$shell" "\$@"
EOF
chmod 0755 "$install_dir/hsh"

echo "hyperhub installed to $install_dir/hyperhub"
echo "shortcut installed to $install_dir/hsh"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "add this directory to PATH if needed: $install_dir" ;;
esac
