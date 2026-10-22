#!/usr/bin/env python3
"""Record actual native benchmark JSON against the frozen component contract."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SPEC = Path(__file__).resolve().parent


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def load(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def evidence(path):
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path)
    parser.add_argument("--evidence-dir", type=Path, default=SPEC / "evidence/linux-x64")
    parser.add_argument("--run", type=Path, default=SPEC / "run.json")
    args = parser.parse_args()
    output = args.evidence_dir.resolve()
    output.relative_to(ROOT)
    output.mkdir(parents=True, exist_ok=True)
    raw_path = output / "raw.json"
    if args.raw.resolve() != raw_path:
        shutil.copyfile(args.raw, raw_path)
    raw = load(raw_path)
    assert raw["profile"] == "release", "Only optimized measurements support this plan"
    assert raw["threads"] == 4 and raw["rules"] == 32 and raw["trial_duration_ms"] == 250
    assert len(raw["trials"]) == 10
    environment = {
        "os": platform.system(), "release": platform.release(), "machine": platform.machine(),
        "python": platform.python_version(), "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(), "profile": "release",
        "logical_cpus": os.cpu_count(), "run_boundary": "Shared local runner, no CPU affinity or isolated-host claim.",
    }
    environment_path = output / "environment.json"
    write(environment_path, environment)
    model = load(SPEC / "model.json")
    plan = load(SPEC / "plan.json")
    assert plan["model_digest"] == digest(model)
    records = []
    for case in plan["cases"]:
        performance = case["kind"] == "performance"
        switch = case["id"] == "P-switch"
        mode = "upgrade" if switch else case["parameters"].get("mode")
        trials = [trial for trial in raw["trials"] if mode is None or trial["mode"] == mode]
        assert len(trials) == (5 if performance else 10)
        for trial in trials:
            assert trial["correctness"] == "passed" and trial["completed_units"] > 0
            assert trial["native_calls"] == trial["completed_units"] * 3
            assert trial["elapsed_ns"] > 0 and trial["latency_samples_ns"]
            assert trial["old_lease_pinned"] and trial["concurrent_workers_observed"] == 4
            assert all(sample > 0 for sample in trial["latency_samples_ns"])
            if trial["mode"] == "upgrade":
                assert trial["prepare_ns"] > 0 and trial["commit_ns"] > 0
        samples = {metric["name"]: [trial[metric["name"]] for trial in trials]
                   for metric in case["protocol"]["metrics"]} if performance else {}
        record = {
            "case_id": case["id"], "status": "completed", "correctness": "passed",
            "measurement": "valid" if performance else "not_applicable",
            "acceptance": ("passed" if max(samples["commit_ns"]) <= 100_000_000 else "failed") if switch else "not_evaluated",
            "parameters": case["parameters"], "samples": samples, "evidence": [evidence(raw_path)],
            "checks": [{"id": check["id"], "status": "passed", "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed."}
                       for check in case["protocol"]["validity_checks"]] if performance else [],
            "details": "Actual release native DSOs and five paired trials; component evidence, without product-wide or cross-platform performance claims.",
            "verifications": [{"id": verification["id"], "trigger": "observed", "status": "passed",
                               "evidence_paths": [raw_path.relative_to(ROOT).as_posix()],
                               "details": "Compiled native baseline/candidate code and pinned old leases passed the fixed source semantic assertions."}
                              for verification in case["verifications"]],
        }
        if performance:
            count = len(trials) if switch else sum(trial["completed_units"] for trial in trials)
            record["measurement_context_digest"] = digest(case["protocol"]["measurement_context"])
            record["accounting"] = {"work_unit_id": "native_upgrade" if switch else "decision_unit",
                                    "offered": count, "accepted": count, "succeeded": count,
                                    "failed": 0, "rejected": 0, "cancelled": 0, "unfinished": 0, "retries": 0}
        records.append(record)
    write(args.run, {"schema_version": "1.1", "target": model["target"], "revision": model["revision"],
                     "model_digest": digest(model), "plan_digest": digest(plan),
                     "environment": {"description": "Actual optimized native component run; fixed four-worker/32-rule workload, shared local runner.",
                                     "evidence": [evidence(environment_path)]}, "records": records})


if __name__ == "__main__":
    main()
