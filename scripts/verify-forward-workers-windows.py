#!/usr/bin/env python3
"""Bind actual native Windows CI evidence to a frozen local worker run.

This does not execute Windows tests or infer Windows success from Linux results.
It checks saved GitHub API run/job metadata, full job output and exact committed
source bytes before replacing the explicitly pending Windows verification record.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "benchmarks/forward-workers"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def evidence(path):
    return {"path": path.resolve().relative_to(REPO).as_posix(), "sha256": digest(path.read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True, help="Existing formal run directory")
    parser.add_argument("--ci-run", type=Path, required=True, help="GitHub REST actions/runs/ID JSON")
    parser.add_argument("--job", type=Path, required=True, help="GitHub REST actions/jobs/ID JSON")
    parser.add_argument("--log", type=Path, required=True, help="Complete unmodified Windows job log")
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--contract-tool", type=Path, default=Path.home()/".agents/skills/benchmark/scripts/benchmark_contract.py")
    args = parser.parse_args()
    assert re.fullmatch("[0-9a-f]{40}", args.expected_commit)
    output = args.run.resolve()
    assert output.is_relative_to(REPO)
    model = json.loads((SPEC/"model.json").read_text())
    plan = json.loads((SPEC/"plan.json").read_text())
    run_path = output/"run.json"
    run = json.loads(run_path.read_text())
    assert run["model_digest"] == canonical(model) and run["plan_digest"] == canonical(plan)
    ci = json.loads(args.ci_run.read_text())
    job = json.loads(args.job.read_text())
    assert ci["head_sha"] == args.expected_commit
    assert ci["status"] == "completed" and ci["conclusion"] == "success"
    assert job["run_id"] == ci["id"]
    assert job["status"] == "completed" and job["conclusion"] == "success"
    assert any("windows" in label.lower() for label in job["labels"])
    steps = {step["name"]: step for step in job["steps"]}
    for name in ["Test workspace", "Test Windows Hook semantics"]:
        assert steps[name]["status"] == "completed" and steps[name]["conclusion"] == "success", name
    log = re.sub(r"\x1b\[[0-9;]*m", "", args.log.read_text())
    tests = [
        "forward::wire::platform::tests::shutdown_cancels_real_child_stdio_overlapped_reads_and_writes",
        "faults::whole_prepare_deadline_covers_a_child_that_never_reads_bootstrap",
        "faults::disconnected_control_drains_granted_streams_and_preserves_central_revocation",
        "faults::health_deadline_closes_control_when_booted_child_stops_consuming_messages",
    ]
    for name in tests:
        assert re.search(r"test " + re.escape(name) + r" \.\.\. ok(?:\s|$)", log), name
    assert "test result: ok. 12 passed; 0 failed; 0 ignored;" in log
    # Measurement metadata can be committed after the product fix. Every bound
    # production, build and fixture byte must still equal the native CI commit.
    committed_sources = []
    for source in model["sources"]:
        path = source["path"]
        if not (path.startswith(("crates/", "tests/", "build_support/")) or path in ["Cargo.toml", "Cargo.lock"]):
            continue
        result = subprocess.run(["git", "show", args.expected_commit+":"+path], cwd=REPO, capture_output=True, timeout=30)
        assert result.returncode == 0 and digest(result.stdout) == source["sha256"], ("native CI source mismatch", path)
        committed_sources.append(source)
    case = next(case for case in plan["cases"] if case["id"] == "C-windows-stdio")
    old = next(record for record in run["records"] if record["case_id"] == case["id"])
    assert old["status"] == "blocked", "Windows evidence was already supplied; preserve the original record"
    destination = output/"windows-ci"
    destination.mkdir(exist_ok=False)
    paths = []
    for source, name in [(args.ci_run, "run-metadata.json"), (args.job, "job-metadata.json"), (args.log, "job.log")]:
        target = destination/name
        shutil.copyfile(source, target)
        paths.append(target)
    binding = destination/"binding.json"
    save(binding, {"ci_run_id": ci["id"], "job_id": job["id"], "commit": args.expected_commit,
                   "observed_passing_tests": tests, "committed_source_count": len(committed_sources),
                   "committed_sources": committed_sources})
    paths.append(binding)
    files = [evidence(path) for path in paths]
    record = {"case_id": case["id"], "status": "completed", "correctness": "passed", "measurement": "not_applicable",
              "acceptance": "not_evaluated", "parameters": case["parameters"], "checks": [], "samples": {},
              "evidence": files, "details": "Actual Windows job passed the real overlapped stdio unit and all 12 worker subprocess cases at the exact bound product source commit.",
              "verifications": [{"id": verification["id"], "trigger": "observed", "status": "passed",
                                  "evidence_paths": [item["path"] for item in files], "details": verification["assertion"]}
                                 for verification in case["verifications"]]}
    shutil.copyfile(run_path, output/"run-linux-only.json")
    shutil.copyfile(output/"exit-codes.json", output/"exit-codes-linux-only.json")
    if (output/"BENCHMARK.valid.md").exists():
        shutil.copyfile(output/"BENCHMARK.valid.md", output/"BENCHMARK.linux-only.md")
    run["records"] = [record if row["case_id"] == case["id"] else row for row in run["records"]]
    save(run_path, run)
    completed_report = output/"BENCHMARK.windows-completed.md"
    checker = [sys.executable, str(args.contract_tool), "check", "--repo", str(REPO), "--model", str(SPEC/"model.json"),
               "--plan", str(SPEC/"plan.json"), "--expected-model-digest", run["model_digest"], "--stage", "valid", "--run", str(run_path),
               "--require-standard", "--format", "markdown", "--output", str(completed_report)]
    result = subprocess.run(checker, cwd=REPO, capture_output=True)
    (output/"windows-completed-valid-check.log").write_bytes(result.stdout+result.stderr)
    if completed_report.exists():
        shutil.copyfile(completed_report, output/"BENCHMARK.valid.md")
    codes = json.loads((output/"exit-codes.json").read_text())
    codes.update(checker=result.returncode, windows_ci_completed=True, windows_ci_run=ci["id"], windows_job=job["id"])
    save(output/"exit-codes.json", codes)
    print(json.dumps({"checker": result.returncode, "ci_run": ci["id"], "job": job["id"], "commit": args.expected_commit}))
    return 1 if result.returncode or codes["preflight"] or codes["measurement"] or codes["acceptance_failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
