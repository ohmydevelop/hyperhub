#!/usr/bin/env python3
"""Require successful CI for the exact release source commit before publication."""
import json
import os
from pathlib import Path
import subprocess
import tomllib


def verify(tag, workspace_version, sha, api):
    if not tag.startswith("v") or tag[1:] != workspace_version:
        raise ValueError("release tag must equal the workspace version with one leading v")
    prerelease = "-" in workspace_version.split("+", 1)[0]
    required = {"Test (ubuntu-latest)", "Test (windows-latest)", "Check Linux targets"}
    if prerelease:
        required |= {"Attachment soak (Linux ptrace)", "Attachment soak (Linux gum)",
                     "Attachment soak (Windows gum)"}
    runs = api(f"actions/workflows/ci.yml/runs?head_sha={sha}&status=completed&per_page=100")["workflow_runs"]
    for run in runs:
        if (run["head_sha"] != sha or run["conclusion"] != "success"
                or run["event"] not in {"push", "workflow_dispatch"}):
            continue
        if prerelease and not run["head_branch"].startswith("dev/"):
            continue
        jobs = api(f"actions/runs/{run['id']}/jobs?per_page=100")["jobs"]
        passed = {job["name"] for job in jobs
                  if job["status"] == "completed" and job["conclusion"] == "success"}
        if required <= passed:
            return {"prerelease": prerelease, "make_latest": not prerelease,
                    "ci_run_id": run["id"], "required_jobs": len(required)}
    raise ValueError("exact source commit requires successful platform CI and development soak gates")


def main():
    with Path("Cargo.toml").open("rb") as source:
        version = tomllib.load(source)["workspace"]["package"]["version"]
    repo = os.environ["GITHUB_REPOSITORY"]

    def api(path):
        return json.loads(subprocess.check_output(["gh", "api", f"repos/{repo}/{path}"]))

    result = verify(os.environ["RELEASE_TAG"], version, os.environ["GITHUB_SHA"], api)
    print(f"Verified CI {result['ci_run_id']} at {os.environ['GITHUB_SHA']}; "
          f"required jobs: {result['required_jobs']}")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for name in ["prerelease", "make_latest"]:
            output.write(f"{name}={str(result[name]).lower()}\n")


if __name__ == "__main__":
    main()
