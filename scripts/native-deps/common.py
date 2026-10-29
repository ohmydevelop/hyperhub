"""Pinned Frida source-build inputs and verified, path-independent receipts."""
import hashlib
import json
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[2]
VENDOR = REPO / "third_party/frida"
MANIFEST = json.loads((VENDOR / "manifest.json").read_text())


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command, **kwargs):
    kwargs.setdefault("check", True)
    return subprocess.run([str(value) for value in command], **kwargs)


def revision(path):
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


def recipe_identity():
    paths = [VENDOR / "manifest.json", VENDOR / "linux-nolibc.json", VENDOR / "NOTICE.md",
             *sorted(VENDOR.glob("COPYING*")),
             *sorted((VENDOR / "patches").glob("*.patch")),
             *sorted((REPO / "scripts/native-deps").glob("*.py")),
             REPO / "scripts/frida-native-deps.py", REPO / "tests/fixtures/linux_execve_error_probe.c",
             *sorted((REPO / "tests/fixtures/frida-native").glob("*.c"))]
    digest = hashlib.sha256(b"hyperhub-frida-source-recipe-v1\0")
    for path in paths:
        name = path.relative_to(REPO).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(name).to_bytes(8, "little"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def verify_pair(gum, core, architecture, recipe):
    roots = {"gum": Path(gum), "core": Path(core)}
    receipts = [json.loads((root / "hyperhub-frida-sdk.json").read_text()) for root in roots.values()]
    receipt = receipts[0]
    if not isinstance(receipt, dict) or receipts[1] != receipt or receipt.get("schema") != 1:
        raise ValueError("Core/Gum SDK receipts do not match")
    if receipt.get("recipe_sha256") != recipe or receipt.get("architecture") != architecture:
        raise ValueError("SDK receipt does not match the pinned source recipe and architecture")
    required = {"gum/frida-gum.h", "gum/libfrida-gum.a", "core/frida-core.h", "core/libfrida-core.a"}
    artifacts = receipt.get("artifacts", {})
    if not isinstance(artifacts, dict) or not required.issubset(artifacts):
        raise ValueError("SDK receipt is missing required Core/Gum files")
    actual_roles = {f"{role}/{path.name}" for role, root in roots.items() for path in root.iterdir()
                    if path.name != "hyperhub-frida-sdk.json"}
    if set(artifacts) != actual_roles:
        raise ValueError("SDK directory contains unrecorded or missing files")
    for role, expected in artifacts.items():
        if not isinstance(role, str) or not isinstance(expected, str) or len(expected) != 64:
            raise ValueError("Invalid SDK receipt artifact digest")
        parts = role.split("/")
        if len(parts) != 2 or parts[0] not in roots or parts[1] in ("", ".", ".."):
            raise ValueError("Invalid SDK receipt artifact role")
        path = roots[parts[0]] / parts[1]
        if path.is_symlink() or not path.is_file() or sha256(path) != expected:
            raise ValueError(f"SDK file checksum mismatch: {path}")
    return receipt


def write_pair_receipt(gum, core, architecture, recipe):
    artifacts = {}
    for role, root in (("gum", gum), ("core", core)):
        for path in sorted(root.iterdir()):
            if path.is_file() and path.name != "hyperhub-frida-sdk.json":
                artifacts[f"{role}/{path.name}"] = sha256(path)
    receipt = {"schema": 1, "architecture": architecture, "recipe_sha256": recipe,
               "source": MANIFEST["source"], "patches": MANIFEST["patches"],
               "artifacts": artifacts}
    encoded = json.dumps(receipt, indent=2) + "\n"
    for root in (gum, core):
        (root / "hyperhub-frida-sdk.json").write_text(encoded)
    verify_pair(gum, core, architecture, recipe)
