"""Download fixed public source, SDK bundles and baseline build tools privately."""
import json
import os
import shutil
import subprocess
import tarfile
import time
import urllib.error
import urllib.request

from common import MANIFEST, VENDOR, revision, run, sha256


def fetch(url, path, expected, headers=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if sha256(path) != expected:
            raise ValueError(f"Cached download checksum mismatch: {path}")
        return path
    temporary = path.with_name(path.name + f".download-{os.getpid()}")
    try:
        request = urllib.request.Request(url, headers=headers or {})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
                    shutil.copyfileobj(response, output)
                break
            except (OSError, urllib.error.URLError):
                temporary.unlink(missing_ok=True)
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)
        if sha256(temporary) != expected:
            raise ValueError(f"Download checksum mismatch: {url}")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def checkout(destination, specification, tag=None, recursive=False):
    if not destination.exists():
        if tag is not None:
            command = ["git", "clone", "--depth=1", "--branch", tag]
            if recursive:
                command += ["--recurse-submodules", "--shallow-submodules"]
            run([*command, specification["url"], destination])
        else:
            destination.mkdir(parents=True)
            run(["git", "init", "--quiet"], cwd=destination)
            run(["git", "remote", "add", "origin", specification["url"]], cwd=destination)
            run(["git", "fetch", "--depth=1", "origin", specification["revision"]], cwd=destination)
            run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=destination)
    if revision(destination) != specification["revision"]:
        raise ValueError(f"Unexpected source revision: {destination}")


def apply_patch(source, name):
    patch = VENDOR / "patches" / name
    expected = MANIFEST["patches"][name]
    if sha256(patch) != expected:
        raise ValueError(f"Patch input checksum mismatch: {patch}")
    applied = subprocess.run(["git", "apply", "--reverse", "--check", str(patch)],
                             cwd=source, capture_output=True)
    if applied.returncode:
        run(["git", "apply", "--check", patch], cwd=source)
        run(["git", "apply", patch], cwd=source)
    run(["git", "diff", "--check"], cwd=source)
    for relative, expected_content in MANIFEST["patch_files"][name].items():
        if sha256(source / relative) != expected_content:
            raise ValueError(f"Applied source differs from the reviewed patch: {source / relative}")


def verify_source_changes(source, patch_names, reference="HEAD"):
    expected = {}
    for name in patch_names:
        for relative, expected_content in MANIFEST["patch_files"][name].items():
            if relative in expected and expected[relative] != expected_content:
                raise ValueError(f"Conflicting reviewed patch postimages: {relative}")
            expected[relative] = expected_content
    actual = set(subprocess.check_output(["git", "diff", "--name-only", "--no-ext-diff", reference],
                                         cwd=source, text=True).splitlines())
    if actual != set(expected):
        raise ValueError(f"Unexpected changed source files in {source}: {sorted(actual)}")
    for relative, expected_content in expected.items():
        path = source / relative
        if path.is_symlink() or sha256(path) != expected_content:
            raise ValueError(f"Source patchset postimage mismatch: {path}")
    metadata = subprocess.check_output(["git", "diff", "--raw", "--no-ext-diff", reference], cwd=source, text=True)
    if any(line.split()[0][1:] != line.split()[1] for line in metadata.splitlines()):
        raise ValueError("Reviewed source patches do not permit file type or mode changes")
    if subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=source):
        raise ValueError(f"Unexpected untracked source files: {source}")


def prepare_sources(root):
    source = root / "source"
    checkout(source, MANIFEST["source"]["core"], MANIFEST["version"], recursive=True)
    for path, key in ((source / "releng", "releng"), (source / "releng/meson", "meson")):
        if revision(path) != MANIFEST["source"][key]:
            raise ValueError(f"Unexpected submodule revision: {path}")
        if subprocess.check_output(["git", "status", "--porcelain"], cwd=path):
            raise ValueError(f"Modified source submodule: {path}")
    checkout(source / "subprojects/frida-gum", MANIFEST["source"]["gum"], MANIFEST["version"])
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=source / "subprojects/frida-gum"):
        raise ValueError("Modified Gum checkout")
    core_patches = ("spawn-monitor-linux-safe-metadata.patch", "child-agent-lifetime.patch",
                    "dbus-context-retirement.patch", "linux-helper-artifacts.patch")
    for name in core_patches:
        apply_patch(source, name)
    verify_source_changes(source, core_patches)
    checkout(root / "glib-source", MANIFEST["source"]["glib"])
    glib_patches = ("glib-gwakeup-eventfd.patch", "glib-dbus-connection-retirement.patch")
    for name in glib_patches:
        apply_patch(root / "glib-source", name)
    verify_source_changes(root / "glib-source", glib_patches)


def toolchain(root, architecture):
    spec = MANIFEST["toolchains"][architecture]
    repository = spec["repository"]
    headers = {}
    cached = [root / f"downloads/xtools-{architecture}-manifest.json",
              root / f"downloads/xtools-{architecture}.tar.gz"]
    if not all(path.exists() for path in cached):
        token_url = f"https://ghcr.io/token?service=ghcr.io&scope=repository:{repository}:pull"
        with urllib.request.urlopen(token_url, timeout=30) as response:
            token = json.load(response)["token"]
        headers = {"Authorization": "Bearer " + token,
                   "Accept": "application/vnd.docker.distribution.manifest.v2+json"}
    base = f"https://ghcr.io/v2/{repository}"
    manifest = fetch(base + "/manifests/sha256:" + spec["manifest"],
                     root / f"downloads/xtools-{architecture}-manifest.json", spec["manifest"], headers)
    if not any(layer["digest"] == "sha256:" + spec["layer"] for layer in json.loads(manifest.read_text())["layers"]):
        raise ValueError("Pinned toolchain layer is absent from its OCI manifest")
    archive = fetch(base + "/blobs/sha256:" + spec["layer"],
                    root / f"downloads/xtools-{architecture}.tar.gz", spec["layer"], headers)
    destination = root / f"tools/xtools-{architecture}"
    compiler = destination / "opt/x-tools" / spec["triplet"] / "bin"
    if not compiler.exists():
        destination.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as contents:
            members = [item for item in contents.getmembers() if item.name == "opt" or item.name.startswith("opt/")]
            contents.extractall(destination, members=members, filter="data")
    return compiler


def prepare_tools(root, architecture):
    for name in ("downloads", "tools", "deps", "tmp", "logs"):
        (root / name).mkdir(parents=True, exist_ok=True)
    node_name = "node-v22.20.0-linux-x64.tar.xz"
    archive = fetch("https://nodejs.org/dist/v22.20.0/" + node_name,
                    root / "downloads" / node_name, MANIFEST["archives"][node_name])
    node = root / "tools/node-v22.20.0-linux-x64/bin"
    if not node.exists():
        with tarfile.open(archive) as contents:
            contents.extractall(root / "tools", filter="data")
    go_name = "go" + MANIFEST["go"]["version"] + ".linux-amd64.tar.gz"
    archive = fetch("https://go.dev/dl/" + go_name, root / "downloads" / go_name, MANIFEST["go"]["sha256"])
    go = root / "tools/go/bin"
    if not go.exists():
        with tarfile.open(archive) as contents:
            contents.extractall(root / "tools", filter="data")
    architectures = ["x86_64", "x86"] if architecture == "x86_64" else ["x86_64", "arm64"]
    compilers = {arch: toolchain(root, arch) for arch in architectures}
    bundles = ["toolchain-linux-x86_64.tar.xz", *[f"sdk-linux-{arch}.tar.xz" for arch in architectures]]
    for name in bundles:
        fetch(f"https://build.frida.re/deps/{MANIFEST['dependencies_version']}/{name}",
              root / "deps" / name, MANIFEST["archives"][name])
    # Prime the exact upstream module ZIP through the same public module proxy.
    # Go still verifies the module against the pinned source go.sum when used.
    module = MANIFEST["go_module_prefetch"]
    checksum = f"{module['module']} {module['version']} {module['go_sum']}"
    if checksum not in (root / "source/src/compiler/go.sum").read_text().splitlines():
        raise ValueError("Prefetched Go module differs from the pinned source go.sum")
    name = module["module"] + "/@v/" + module["version"] + ".zip"
    fetch("https://proxy.golang.org/" + name, root / "tools/gopath/pkg/mod/cache/download" / name,
          module["sha256"])
    return node, go, compilers
