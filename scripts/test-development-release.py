#!/usr/bin/env python3
"""Local installer isolation tests; optional real development CLI checks. No network."""
import argparse
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = None

spec = importlib.util.spec_from_file_location("release_readiness", ROOT / "scripts/check-release-readiness.py")
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


class ReleaseReadiness(unittest.TestCase):
    def fixtures(self, event="push", branch="dev/dynamic-attach", prerelease=True):
        names = ["Test (ubuntu-latest)", "Test (windows-latest)", "Check Linux targets"]
        if prerelease:
            names += ["Attachment soak (Linux ptrace)", "Attachment soak (Linux gum)",
                      "Attachment soak (Windows gum)"]
        run = {"id": 42, "head_sha": "source-sha", "head_branch": branch,
               "event": event, "conclusion": "success"}
        jobs = [{"name": name, "status": "completed", "conclusion": "success"} for name in names]
        return run, jobs

    def verify(self, run, jobs, version="0.3.0-alpha.1", tag=None):
        def api(path):
            if path == "actions/workflows/ci.yml/runs?head_sha=source-sha&status=completed&per_page=100":
                return {"workflow_runs": [run]}
            self.assertEqual(path, f"actions/runs/{run['id']}/jobs?per_page=100")
            return {"jobs": jobs}
        return readiness.verify(tag or "v" + version, version, "source-sha", api)

    def test_development_release_requires_all_native_soaks_and_stays_off_latest(self):
        run, jobs = self.fixtures()
        result = self.verify(run, jobs)
        self.assertTrue(result["prerelease"])
        self.assertFalse(result["make_latest"])
        self.assertEqual(result["required_jobs"], 6)
        for missing in range(len(jobs)):
            with self.subTest(missing=jobs[missing]["name"]):
                with self.assertRaises(ValueError):
                    self.verify(run, jobs[:missing] + jobs[missing + 1:])

    def test_successful_run_with_skipped_or_failed_job_is_rejected(self):
        run, jobs = self.fixtures()
        for conclusion in ["skipped", "failure", "cancelled"]:
            altered = copy.deepcopy(jobs)
            altered[-1]["conclusion"] = conclusion
            with self.subTest(conclusion=conclusion), self.assertRaises(ValueError):
                self.verify(run, altered)

    def test_other_commit_branch_or_pull_request_cannot_satisfy_release(self):
        run, jobs = self.fixtures()
        for field, value in [("head_sha", "other-sha"), ("head_branch", "main"),
                             ("event", "pull_request"), ("conclusion", "failure")]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify({**run, field: value}, jobs)

    def test_explicit_ci_dispatch_for_the_exact_development_commit_is_accepted(self):
        run, jobs = self.fixtures(event="workflow_dispatch")
        self.assertEqual(self.verify(run, jobs)["ci_run_id"], 42)

    def test_stable_build_metadata_does_not_select_the_development_channel(self):
        run, jobs = self.fixtures(branch="main", prerelease=False)
        result = self.verify(run, jobs, version="0.3.0+build-feature")
        self.assertFalse(result["prerelease"])
        self.assertTrue(result["make_latest"])
        self.assertEqual(result["required_jobs"], 3)

    def test_tag_must_match_the_compiled_workspace_version(self):
        run, jobs = self.fixtures()
        for tag in ["0.3.0-alpha.1", "vv0.3.0-alpha.1", "v0.3.0", "v0.3.0-alpha.2"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.verify(run, jobs, tag=tag)


class DevelopmentRelease(unittest.TestCase):
    def test_linux_prerelease_installer_preserves_stable_installation(self):
        if os.name != "posix" or os.uname().sysname != "Linux":
            self.skipTest("Linux installer test")
        for version, relative in [("v0.3.0-alpha.1", ".local/opt/hyperhub-dev/0.3.0-alpha.1"),
                                  ("0.2.15", ".local/bin"),
                                  ("0.2.15+build-feature", ".local/bin")]:
            with self.subTest(version=version), tempfile.TemporaryDirectory(prefix="hh-install-") as temporary:
                base = Path(temporary)
                home = base / "home"
                home.mkdir()
                stable = home / ".local/bin/hyperhub"
                stable.parent.mkdir(parents=True)
                stable.write_bytes(b"stable installation sentinel\n")
                archive = base / "fixture.tar.gz"
                with tarfile.open(archive, "w:gz") as output:
                    data = b"#!/bin/sh\n[ \"$1\" = --help ]\n"
                    entry = tarfile.TarInfo("fixture/hyperhub")
                    entry.mode, entry.size = 0o755, len(data)
                    output.addfile(entry, io.BytesIO(data))
                mock = base / "mock"
                mock.mkdir()
                curl = mock / "curl"
                curl.write_text("#!/usr/bin/env python3\n"
                                "import os,pathlib,shutil,sys\n"
                                "args=sys.argv[1:]\n"
                                "url=next(x for x in args if x.startswith('https://'))\n"
                                "assert '/releases/download/'+os.environ['EXPECTED_TAG']+'/' in url,url\n"
                                "shutil.copyfile(os.environ['FIXTURE_ARCHIVE'],args[args.index('-o')+1])\n")
                curl.chmod(0o700)
                env = {key: value for key, value in os.environ.items() if not key.startswith("HYPERHUB_")}
                env.update(HOME=str(home), TMPDIR=str(base), HYPERHUB_VERSION=version,
                           FIXTURE_ARCHIVE=str(archive), EXPECTED_TAG=version if version.startswith("v") else "v" + version,
                           PATH=str(mock) + os.pathsep + os.environ["PATH"])
                completed = subprocess.run(["sh", str(ROOT / "scripts/install.sh")], env=env,
                                           capture_output=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                self.assertTrue((home / relative / "hyperhub").is_file())
                self.assertTrue((home / relative / "hsh").is_file())
                if "alpha" in version:
                    self.assertEqual(stable.read_bytes(), b"stable installation sentinel\n")
                    self.assertFalse((stable.parent / "hsh").exists())

    def test_real_development_cli_uses_private_default_and_manual_updates(self):
        if CLI is None:
            self.skipTest("provide --hyperhub for built development CLI tests")
        workspace_version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        if "-" not in workspace_version.split("+", 1)[0]:
            self.skipTest("development CLI behavior is only applicable to prerelease builds")
        with tempfile.TemporaryDirectory(prefix="hh-dev-cli-") as temporary:
            home = Path(temporary)
            env = {key: value for key, value in os.environ.items() if not key.startswith("HYPERHUB_")}
            runtime = home / "runtime"
            runtime.mkdir(mode=0o700)
            env.update(HOME=str(home), USERPROFILE=str(home), XDG_RUNTIME_DIR=str(runtime))
            status = subprocess.run([str(CLI), "status", "--json"], env=env,
                                    capture_output=True, timeout=30)
            self.assertEqual(status.returncode, 3, status.stderr.decode())
            value = json.loads(status.stdout)
            self.assertEqual(Path(value["hyperhub_home"]), home / ".hyperhub-dev")
            self.assertEqual(value["state"], "stopped")
            self.assertIn("attachments", value)
            update = subprocess.run([str(CLI), "upgrade"], env=env, capture_output=True, timeout=10)
            self.assertEqual(update.returncode, 0, update.stderr.decode())
            self.assertIn(b"explicit release tag", update.stdout)
            self.assertFalse((home / ".hyperhub").exists())
            self.assertFalse((home / ".agents").exists())
            self.assertFalse((home / ".hyperhub-dev/upgrade-check.json").exists())
            skill = subprocess.run([str(CLI), "skill"], env=env, capture_output=True, timeout=10)
            self.assertEqual(skill.returncode, 0, skill.stderr.decode())
            self.assertIn("运行中进程的附加与卸载审批".encode(), skill.stdout)
            self.assertIn(b"hyperhub approve <request-id>", skill.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hyperhub", type=Path)
    args, remaining = parser.parse_known_args()
    if args.hyperhub:
        CLI = args.hyperhub.resolve(strict=True)
    unittest.main(argv=[__file__] + remaining)
