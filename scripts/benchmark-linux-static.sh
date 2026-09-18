#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
iterations=5
output="$root/target/benchmarks/linux-static"
hyperhub=
runtime=
password_file=
fixtures=
include_large=1
rebuild_fixtures=0
timeout_seconds=120

usage() {
  cat <<'USAGE'
usage: scripts/benchmark-linux-static.sh [options]

Build and benchmark stripped, fully static C, Go, and Rust probes. By default
BusyBox, GitHub CLI, yq, and (on x86_64) ripgrep are included as larger,
commonly used static binaries. Supplying --hyperhub produces native and
HyperHub measurements plus a Markdown overhead report.

options:
  --iterations N       measured launches per workload (default: 5)
  --output DIR         output directory (default: target/benchmarks/linux-static)
  --hyperhub PATH      HyperHub CLI used for native-vs-HyperHub comparison
  --runtime PATH       deprecated compatibility option; ignored for static targets
  --password-file PATH password file passed to HyperHub run
  --fixtures DIR       reusable fixture cache (default: target/benchmarks/linux-fixtures/<arch>)
  --rebuild-fixtures   rebuild cached fixture binaries
  --skip-large         only run the C, Go, and Rust probes
  --timeout SECONDS    timeout for each launch (default: 120)
  -h, --help           show this help
USAGE
}

while (($#)); do
  case "$1" in
    --iterations)
      [[ $# -ge 2 ]] || { echo 'missing value for --iterations' >&2; exit 2; }
      iterations=$2
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || { echo 'missing value for --output' >&2; exit 2; }
      output=$2
      shift 2
      ;;
    --hyperhub)
      [[ $# -ge 2 ]] || { echo 'missing value for --hyperhub' >&2; exit 2; }
      hyperhub=$2
      shift 2
      ;;
    --runtime)
      [[ $# -ge 2 ]] || { echo 'missing value for --runtime' >&2; exit 2; }
      runtime=$2
      shift 2
      ;;
    --password-file)
      [[ $# -ge 2 ]] || { echo 'missing value for --password-file' >&2; exit 2; }
      password_file=$2
      shift 2
      ;;
    --fixtures)
      [[ $# -ge 2 ]] || { echo 'missing value for --fixtures' >&2; exit 2; }
      fixtures=$2
      shift 2
      ;;
    --rebuild-fixtures)
      rebuild_fixtures=1
      shift
      ;;
    --skip-large)
      include_large=0
      shift
      ;;
    --timeout)
      [[ $# -ge 2 ]] || { echo 'missing value for --timeout' >&2; exit 2; }
      timeout_seconds=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ $iterations =~ ^[1-9][0-9]*$ ]] || { echo '--iterations must be a positive integer' >&2; exit 2; }
[[ $timeout_seconds =~ ^[1-9][0-9]*$ ]] || { echo '--timeout must be a positive integer' >&2; exit 2; }
if [[ -n $runtime ]]; then
  echo 'benchmark-linux-static: --runtime is ignored because all workloads use the static ptrace backend' >&2
fi
[[ -z $password_file || -n $hyperhub ]] || { echo '--password-file requires --hyperhub' >&2; exit 2; }

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command is unavailable: $1" >&2
    exit 1
  }
}

for command in cc go rustc readelf nm python3 awk date timeout sha256sum; do
  require_command "$command"
done
if ((include_large)); then
  for command in busybox curl strip tar; do
    require_command "$command"
  done
fi

case "$(uname -m)" in
  x86_64)
    architecture=x86_64
    go_arch=amd64
    rust_target=x86_64-unknown-linux-musl
    release_arch=amd64
    ;;
  aarch64|arm64)
    architecture=aarch64
    go_arch=arm64
    rust_target=aarch64-unknown-linux-musl
    release_arch=arm64
    ;;
  *)
    echo "unsupported Linux architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "$output"
output=$(cd "$output" && pwd)
if [[ -z $fixtures ]]; then
  fixtures="$root/target/benchmarks/linux-fixtures/$architecture"
fi
mkdir -p "$fixtures"
fixtures=$(cd "$fixtures" && pwd)
downloads="$fixtures/downloads"
workload_dir="$fixtures/workload"
mkdir -p "$downloads" "$workload_dir"

c_source="$root/tests/fixtures/linux_static_probe.c"
go_source="$root/tests/benchmarks/linux-static/go/main.go"
rust_source="$root/tests/benchmarks/linux-static/rust/main.rs"
c_binary="$fixtures/linux-static-c"
go_binary="$fixtures/linux-static-go"
rust_binary="$fixtures/linux-static-rust"
fingerprint_file="$fixtures/probes.sha256"
probe_fingerprint=$(
  {
    printf 'architecture=%s\ngo_arch=%s\nrust_target=%s\n' "$architecture" "$go_arch" "$rust_target"
    sha256sum "$c_source" "$go_source" "$rust_source" | awk '{print $1}'
    cc --version
    go version
    rustc -Vv
  } | sha256sum | awk '{print $1}'
)
current_fingerprint=$(cat "$fingerprint_file" 2>/dev/null || true)
if ((rebuild_fixtures)) \
  || [[ $current_fingerprint != "$probe_fingerprint" ]] \
  || [[ ! -x $c_binary || ! -x $go_binary || ! -x $rust_binary ]]; then
  cc -O2 -Wall -Wextra -static -s -fno-ident -Wl,--build-id=none \
    "$c_source" -o "$c_binary"
  CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" \
    go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o "$go_binary" "$go_source"
  rustc --edition=2021 --target "$rust_target" -C opt-level=3 -C panic=abort \
    -C strip=symbols -C link-arg=-Wl,--build-id=none \
    "$rust_source" -o "$rust_binary"
  printf '%s\n' "$probe_fingerprint" > "$fingerprint_file"
else
  printf 'reusing Linux benchmark fixtures from %s\n' "$fixtures"
fi

verify_static_stripped() {
  local binary=$1
  local program_headers dynamic_sections sections symbols
  program_headers=$(readelf -lW "$binary")
  dynamic_sections=$(readelf -dW "$binary" 2>/dev/null || true)
  sections=$(readelf -SW "$binary")
  symbols=$(nm -an "$binary" 2>/dev/null || true)
  if grep -q ' INTERP ' <<<"$program_headers"; then
    echo "$binary contains a program interpreter" >&2
    exit 1
  fi
  if grep -q '(NEEDED)' <<<"$dynamic_sections"; then
    echo "$binary contains dynamic dependencies" >&2
    exit 1
  fi
  if grep -Eq '[[:space:]]\.symtab[[:space:]]|[[:space:]]\.debug_[^[:space:]]*' <<<"$sections"; then
    echo "$binary still contains symbols or debug sections" >&2
    exit 1
  fi
  if [[ -n $symbols ]]; then
    echo "$binary still exposes symbols through nm" >&2
    exit 1
  fi
}

fetch_verified() {
  local url=$1 expected=$2 destination=$3
  if [[ ! -f $destination ]] || ! printf '%s  %s\n' "$expected" "$destination" | sha256sum -c --status -; then
    local temporary="$destination.part"
    curl -fL --retry 3 "$url" -o "$temporary"
    printf '%s  %s\n' "$expected" "$temporary" | sha256sum -c --status - || {
      echo "checksum mismatch for $url" >&2
      exit 1
    }
    mv "$temporary" "$destination"
  fi
}

workloads=(c go rust)
declare -A binaries kinds
binaries[c]=$c_binary
binaries[go]=$go_binary
binaries[rust]=$rust_binary
kinds[c]=probe
kinds[go]=probe
kinds[rust]=probe

if ((include_large)); then
  busybox_source=$(command -v busybox)
  busybox_binary="$downloads/busybox-static"
  busybox_fingerprint=$(sha256sum "$busybox_source" | awk '{print $1}')
  if ((rebuild_fixtures)) \
    || [[ ! -x $busybox_binary ]] \
    || [[ $(cat "$downloads/busybox.sha256" 2>/dev/null || true) != "$busybox_fingerprint" ]]; then
    cp "$busybox_source" "$busybox_binary"
    chmod 0755 "$busybox_binary"
    strip --strip-all --remove-section=.debug_gdb_scripts "$busybox_binary"
    printf '%s\n' "$busybox_fingerprint" > "$downloads/busybox.sha256"
  fi
  verify_static_stripped "$busybox_binary"
  binaries[busybox]=$busybox_binary
  kinds[busybox]=large
  workloads+=(busybox)

  gh_version=2.78.0
  gh_archive="$downloads/gh_${gh_version}_linux_${release_arch}.tar.gz"
  gh_binary="$downloads/gh-${gh_version}"
  if [[ $architecture == x86_64 ]]; then
    gh_sha=ac309f70c5d6b122c82e6138ce82cb65ca5d8595cc09d11751fbc4e3907e1a05
  else
    gh_sha=9e3ca75b227a5503f6ef92c4b8b6dbf94e34bfdd8069ac0f16b8739856ebba7b
  fi
  fetch_verified \
    "https://github.com/cli/cli/releases/download/v${gh_version}/gh_${gh_version}_linux_${release_arch}.tar.gz" \
    "$gh_sha" "$gh_archive"
  if ((rebuild_fixtures)) || [[ ! -x $gh_binary ]]; then
    tar -xOf "$gh_archive" "gh_${gh_version}_linux_${release_arch}/bin/gh" > "$gh_binary"
    chmod 0755 "$gh_binary"
    strip --strip-all --remove-section=.debug_gdb_scripts "$gh_binary"
  fi
  verify_static_stripped "$gh_binary"
  binaries[gh]=$gh_binary
  kinds[gh]=large
  workloads+=(gh)

  yq_version=4.47.2
  if [[ $architecture == x86_64 ]]; then
    yq_asset=yq_linux_amd64
    yq_sha=1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0
  else
    yq_asset=yq_linux_arm64
    yq_sha=05df1f6aed334f223bb3e6a967db259f7185e33650c3b6447625e16fea0ed31f
  fi
  yq_asset_file="$downloads/${yq_asset}-${yq_version}"
  yq_binary="$downloads/yq-${yq_version}"
  fetch_verified \
    "https://github.com/mikefarah/yq/releases/download/v${yq_version}/${yq_asset}" \
    "$yq_sha" "$yq_asset_file"
  if ((rebuild_fixtures)) || [[ ! -x $yq_binary ]]; then
    cp "$yq_asset_file" "$yq_binary"
    chmod 0755 "$yq_binary"
    strip --strip-all --remove-section=.debug_gdb_scripts "$yq_binary"
  fi
  verify_static_stripped "$yq_binary"
  binaries[yq]=$yq_binary
  kinds[yq]=large
  workloads+=(yq)

  if [[ $architecture == x86_64 ]]; then
    rg_version=14.1.1
    rg_archive="$downloads/ripgrep-${rg_version}-x86_64-unknown-linux-musl.tar.gz"
    rg_binary="$downloads/rg-${rg_version}"
    fetch_verified \
      "https://github.com/BurntSushi/ripgrep/releases/download/${rg_version}/ripgrep-${rg_version}-x86_64-unknown-linux-musl.tar.gz" \
      4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e \
      "$rg_archive"
    if ((rebuild_fixtures)) || [[ ! -x $rg_binary ]]; then
      tar -xOf "$rg_archive" "ripgrep-${rg_version}-x86_64-unknown-linux-musl/rg" > "$rg_binary"
      chmod 0755 "$rg_binary"
      strip --strip-all --remove-section=.debug_gdb_scripts "$rg_binary"
    fi
    verify_static_stripped "$rg_binary"
    binaries[ripgrep]=$rg_binary
    kinds[ripgrep]=large
    workloads+=(ripgrep)
  fi
fi

for binary in "$c_binary" "$go_binary" "$rust_binary"; do
  verify_static_stripped "$binary"
done

python3 - "$workload_dir" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
corpus = root / "corpus.txt"
if not corpus.exists() or corpus.stat().st_size < 8_000_000:
    with corpus.open("w", encoding="utf-8") as output:
        for index in range(220_000):
            output.write(f"line {index} hyperhub static benchmark value {index % 97}\n")
yaml = root / "data.yaml"
if not yaml.exists() or yaml.stat().st_size < 250_000:
    with yaml.open("w", encoding="utf-8") as output:
        output.write("items:\n")
        for index in range(8_000):
            output.write(f"  - id: {index}\n    name: item-{index}\n    enabled: {str(index % 2 == 0).lower()}\n")
PY

manifest_tsv="$fixtures/manifest.tsv"
printf 'workload\tkind\tpath\tbytes\tsha256\n' > "$manifest_tsv"
for workload in "${workloads[@]}"; do
  binary=${binaries[$workload]}
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$workload" "${kinds[$workload]}" "$binary" "$(stat -c %s "$binary")" \
    "$(sha256sum "$binary" | awk '{print $1}')" >> "$manifest_tsv"
done
python3 - "$manifest_tsv" "$fixtures/manifest.json" "$architecture" "$probe_fingerprint" <<'PY'
import csv
import json
import pathlib
import sys
source, destination, architecture, fingerprint = sys.argv[1:]
with pathlib.Path(source).open(encoding="utf-8", newline="") as handle:
    fixtures = list(csv.DictReader(handle, delimiter="\t"))
for fixture in fixtures:
    fixture["bytes"] = int(fixture["bytes"])
pathlib.Path(destination).write_text(
    json.dumps(
        {
            "schema_version": 1,
            "architecture": architecture,
            "probe_fingerprint": fingerprint,
            "fixtures": fixtures,
        },
        indent=2,
    ) + "\n",
    encoding="utf-8",
)
PY

port_file="$output/echo-server.port"
: > "$port_file"
python3 "$root/tests/benchmarks/linux-static/echo_server.py" "$port_file" &
server_pid=$!
cleanup() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -s $port_file ]] && break
  kill -0 "$server_pid" 2>/dev/null || {
    echo 'echo server exited before becoming ready' >&2
    exit 1
  }
  sleep 0.05
done
[[ -s $port_file ]] || { echo 'timed out waiting for echo server' >&2; exit 1; }
read -r port dns_port < "$port_file"
export HYPERHUB_DNS_PORTS=$dns_port

if [[ -n $hyperhub ]]; then
  hyperhub=$(realpath "$hyperhub")
  [[ -x $hyperhub ]] || { echo "HyperHub is not executable: $hyperhub" >&2; exit 1; }
  if ! "$hyperhub" status --json 2>/dev/null | grep -Eq '"state"[[:space:]]*:[[:space:]]*"running"'; then
    echo 'HyperHub Serve must be running before comparison' >&2
    exit 1
  fi
fi
if [[ -n $password_file ]]; then
  password_file=$(realpath "$password_file")
fi

run_native() {
  local workload=$1 binary=${binaries[$1]}
  case "$workload" in
    c) "$binary" 127.0.0.1 "$port" "$dns_port" ;;
    go|rust) "$binary" 127.0.0.1 "$port" ;;
    busybox) "$binary" sha256sum "$workload_dir/corpus.txt" ;;
    gh) "$binary" --version ;;
    yq) "$binary" eval '.items | map(select(.enabled)) | length' "$workload_dir/data.yaml" ;;
    ripgrep) "$binary" --threads 1 --count-matches 'hyperhub|static' "$workload_dir/corpus.txt" ;;
    *) echo "unknown workload: $workload" >&2; return 2 ;;
  esac
}

results="$output/results.csv"
printf 'workload,kind,binary_bytes,mode,iteration,elapsed_ms\n' > "$results"
modes=(native)
[[ -z $hyperhub ]] || modes+=(hyperhub)

# Keep the timed command construction outside of subshells so arguments with spaces remain intact.
for workload in "${workloads[@]}"; do
  for mode in "${modes[@]}"; do
    if [[ $mode == hyperhub ]]; then
      hyperhub_command=("$hyperhub" run)
      [[ -z $password_file ]] || hyperhub_command+=(--password-file "$password_file")
      hyperhub_command+=(-- "${binaries[$workload]}")
      case "$workload" in
        c) hyperhub_command+=(127.0.0.1 "$port" "$dns_port") ;;
        go|rust) hyperhub_command+=(127.0.0.1 "$port") ;;
        busybox) hyperhub_command+=(sha256sum "$workload_dir/corpus.txt") ;;
        gh) hyperhub_command+=(--version) ;;
        yq) hyperhub_command+=(eval '.items | map(select(.enabled)) | length' "$workload_dir/data.yaml") ;;
        ripgrep) hyperhub_command+=(--threads 1 --count-matches 'hyperhub|static' "$workload_dir/corpus.txt") ;;
      esac
    else
      hyperhub_command=()
    fi
    # One untimed warm-up keeps download, disk-cache, and first authorization costs out of medians.
    if [[ $mode == native ]]; then
      run_native "$workload" >/dev/null
    else
      timeout "$timeout_seconds" "${hyperhub_command[@]}" >/dev/null
    fi
    size=$(stat -c %s "${binaries[$workload]}")
    for ((iteration = 1; iteration <= iterations; iteration++)); do
      start=$(date +%s%N)
      if [[ $mode == native ]]; then
        run_native "$workload" >/dev/null
      else
        timeout "$timeout_seconds" "${hyperhub_command[@]}" >/dev/null
      fi
      end=$(date +%s%N)
      elapsed=$(awk -v start="$start" -v end="$end" 'BEGIN { printf "%.3f", (end - start) / 1000000 }')
      printf '%s,%s,%s,%s,%d,%s\n' \
        "$workload" "${kinds[$workload]}" "$size" "$mode" "$iteration" "$elapsed" | tee -a "$results"
    done
  done
done

python3 "$root/tests/benchmarks/linux-static/report.py" "$results" "$output"
printf '\nfixtures: %s\nmanifest: %s\nresults:  %s\nsummary:  %s\nreport:   %s\n' \
  "$fixtures" "$fixtures/manifest.json" "$results" "$output/summary.csv" "$output/report.md"
