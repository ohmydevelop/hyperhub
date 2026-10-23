#!/usr/bin/env python3
"""Run native forwarding preflight and a frozen component performance plan."""
import argparse
import datetime
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "benchmarks" / "forward-workers"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def file_evidence(path):
    return {"path": path.resolve().relative_to(REPO).as_posix(), "sha256": digest(path)}


def command(argv, log, env=None):
    with log.open("wb") as output:
        output.write((json.dumps(argv) + "\n").encode())
        output.flush()
        process = subprocess.Popen(argv, cwd=REPO, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert process.stdout is not None
        # Read to EOF, including inherited child stderr. Waiting only for Cargo
        # can hash a log before a draining worker writes its final error.
        with process.stdout:
            while chunk := process.stdout.read1(65536):
                output.write(chunk)
                output.flush()
        return process.wait()


def version(argv):
    result = subprocess.run(argv, cwd=REPO, capture_output=True, text=True, check=False)
    return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def environment(worker, profile, tool):
    data = {"platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
            "python": sys.version, "rustc": version(["rustc", "-Vv"]), "cargo": version(["cargo", "--version"]),
            "git": version(["git", "rev-parse", "HEAD"]), "dirty": version(["git", "status", "--porcelain"]),
            "worker": {"path": str(worker), "sha256": digest(worker), "bytes": worker.stat().st_size}, "profile": profile, "cargo_incremental": "0 (runner override)",
            "worker_runtime": {"threads": "min(available_parallelism,4)", "max_blocking_threads": 32},
            "controller_runtime": {"threads": 4, "max_blocking_threads": "Tokio default"},
            "sampling": "Observed process resources at nominal 1ms intervals; short-lived peaks can be missed"}
    for path in ["/proc/loadavg", "/proc/meminfo", "/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/memory.max"]:
        try:
            data[path] = Path(path).read_text()
        except OSError:
            pass
    # Fingerprint the complete local checker module and schema package. This
    # superset includes every actual local import without maintaining an old
    # hand-written module list. Third-party validator version is explicit.
    tool_files = sorted(tool.parent.glob("*.py")) + sorted((tool.parent.parent / "references").glob("*.json"))
    data["checker_files"] = {str(path): digest(path) for path in tool_files}
    data["jsonschema_version"] = importlib.metadata.version("jsonschema")
    if hasattr(os, "sched_getaffinity"):
        data["cpu_affinity"] = sorted(os.sched_getaffinity(0))
    try:
        data["cpu_model"] = next(line for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name"))
    except (OSError, StopIteration):
        pass
    return data


def resource_peaks(trial):
    readings = trial["resource_samples"]
    assert readings and all(row["processes"] for row in readings)
    return {
        "parent_threads_peak": max(row["processes"][0]["threads"] for row in readings),
        "parent_rss_peak": max(row["processes"][0]["rss_bytes"] for row in readings),
        "worker_threads_peak": max(sum(p["threads"] for p in row["processes"][1:]) for row in readings),
        "worker_rss_peak": max(sum(p["rss_bytes"] for p in row["processes"][1:]) for row in readings),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True, help="Built candidate CLI or source worker probe")
    parser.add_argument("--profile", choices=["dev", "release"], default="release")
    parser.add_argument("--contract-tool", type=Path, default=Path.home()/".agents/skills/benchmark/scripts/benchmark_contract.py")
    parser.add_argument("--output", type=Path, required=True, help="New directory inside the repository, normally target/benchmarks/...")
    args = parser.parse_args()
    worker = args.worker.resolve()
    if not worker.is_file() or not args.contract_tool.is_file():
        parser.error("worker executable and benchmark contract checker must exist")
    output = args.output.resolve()
    if not output.is_relative_to(REPO):
        parser.error("output must be inside the repository for evidence references")
    output.mkdir(parents=True, exist_ok=False)
    expected_worker = digest(worker)
    original_worker = worker
    worker = output / ("candidate-worker" + (".exe" if os.name == "nt" else ""))
    shutil.copyfile(original_worker, worker)
    if digest(worker) != expected_worker or digest(original_worker) != expected_worker:
        raise RuntimeError("candidate executable changed while making its benchmark snapshot")
    worker.chmod(stat.S_IRUSR | stat.S_IXUSR)
    model = json.loads((SPEC/"model.json").read_text())
    plan = json.loads((SPEC/"plan.json").read_text())
    pinned = re.search(r"Model digest: `([0-9a-f]{64})`", (SPEC/"FROZEN.md").read_text()).group(1)
    checker = [sys.executable, str(args.contract_tool), "check", "--repo", str(REPO), "--model", str(SPEC/"model.json"), "--plan", str(SPEC/"plan.json"), "--expected-model-digest", pinned, "--require-standard"]
    if command(checker+["--stage", "implemented"], output/"implemented-check.log"):
        print(f"Frozen implementation check failed: {output}", file=sys.stderr)
        return 1
    env_path = output/"environment.json"
    save(env_path, environment(worker, args.profile, args.contract_tool.resolve()))
    env = os.environ.copy()
    env["CARGO_INCREMENTAL"] = "0"
    temporary = output / "tmp"
    temporary.mkdir(mode=0o700)
    for name in ("TMPDIR", "TMP", "TEMP"):
        env[name] = str(temporary)
    env["HH_FORWARD_WORKER_FIXTURE"] = str(worker)
    raw_path = output/"raw.json"
    env["HH_FORWARD_BENCHMARK_OUTPUT"] = str(raw_path)
    cargo = ["cargo", "test", "-p", "hyperhub-core", "--offline"]
    if args.profile == "release":
        cargo.append("--release")
    unit_log = output/"unit-preflight.log"
    unit_preflight = command(cargo+["--lib", "forward::", "--", "--nocapture"], unit_log, env)
    preflight_log = output/"preflight.log"
    preflight = unit_preflight or command(cargo+["--test", "forward_workers", "--", "--ignored", "--nocapture"], preflight_log, env)
    cases = {case["id"]: case for case in plan["cases"]}
    records = []

    def record(case_id, passed, evidence, samples=None, accounting=None, acceptance="not_evaluated"):
        case = cases[case_id]
        perf = case["kind"] == "performance"
        result = {"case_id": case_id, "status": "completed" if passed else "failed", "correctness": "passed" if passed else "failed",
                  "measurement": ("valid" if passed else "invalid") if perf else "not_applicable", "acceptance": acceptance,
                  "parameters": case["parameters"], "checks": [], "samples": samples or {}, "evidence": [file_evidence(path) for path in evidence],
                  "details": "Native assertions and raw accounting checked" if passed else "Native execution or raw validation failed",
                  "verifications": [{"id": v["id"], "trigger": "observed" if passed else "not_observed", "status": "passed" if passed else "failed", "evidence_paths": [file_evidence(path)["path"] for path in evidence], "details": v["assertion"]} for v in case["verifications"]]}
        if perf:
            result["measurement_context_digest"] = canonical(case["protocol"]["measurement_context"])
            result["accounting"] = accounting
            result["checks"] = [{"id": check["id"], "status": "passed" if passed else "failed", "details": check["condition"]} for check in case["protocol"]["validity_checks"]]
        if os.name == "nt":
            for verification in result["verifications"]:
                if verification["id"] == "V-B-probe-exhaustion":
                    verification.update(trigger="not_observed", status="not_checked", details="The real RLIMIT_NOFILE exhaustion subprocess is Unix-only; no Windows fault execution is claimed.")
        records.append(result)

    record("C-native-suite", preflight == 0, [unit_log]+([preflight_log] if preflight_log.exists() else []))
    if os.name == "nt":
        record("C-windows-stdio", preflight == 0, [unit_log]+([preflight_log] if preflight_log.exists() else []))
    else:
        case = cases["C-windows-stdio"]
        records.append({"case_id": case["id"], "status": "blocked", "correctness": "not_checked", "measurement": "not_applicable",
                        "acceptance": "not_evaluated", "parameters": case["parameters"], "checks": [], "samples": {}, "evidence": [],
                        "details": "Native Windows overlapped stdio is not exercised by this platform. Supply actual exact-source Windows CI evidence before final valid acceptance.",
                        "verifications": [{"id": item["id"], "trigger": "not_observed", "status": "not_checked", "evidence_paths": [],
                                           "details": "Pending actual Windows stdio and worker subprocess execution; Unix IO does not establish this boundary."}
                                          for item in case["verifications"]]})
    execution = preflight
    if preflight == 0:
        measurement_log = output/"measurement.log"
        execution = command(cargo+["--test", "forward_worker_benchmark", "--", "--ignored", "--nocapture"], measurement_log, env)
        good = execution == 0
        try:
            trials = json.loads(raw_path.read_text())["trials"]
            assert len(trials) == 20
            for state in ["baseline", "upgrade-0", "upgrade-1", "upgrade-4"]:
                rows = [row for row in trials if row["state"] == state]
                assert sorted(row["trial"] for row in rows) == list(range(5))
                for row in rows:
                    assert len(row["echo_us"]) == 1024 and len(row["admission_ms"]) == 32
                    assert row["accounting"] == {"offered":1024,"accepted":1024,"succeeded":1024,"failed":0,"rejected":0,"cancelled":0,"unfinished":0,"retries":0}
                    resource_peaks(row)
        except (OSError, KeyError, ValueError, AssertionError) as error:
            good = False
            (output/"raw-validation-error.txt").write_text(repr(error)+"\n")
        evidence = [measurement_log]+([raw_path] if raw_path.exists() else [])
        record("C-payload-oracle", good, evidence)
        if good:
            for state in ["baseline", "upgrade-0", "upgrade-1", "upgrade-4"]:
                rows = [row for row in trials if row["state"] == state]
                ledger = {"work_unit_id":"echo","offered":5120,"accepted":5120,"succeeded":5120,"failed":0,"rejected":0,"cancelled":0,"unfinished":0,"retries":0}
                record(f"P-echo-{state}", True, evidence, {"echo_us":[v for row in rows for v in row["echo_us"]], "echo_rate":[row["echo_per_second"] for row in rows]}, ledger)
                resource = {name:[resource_peaks(row)[name] for row in rows] for name in resource_peaks(rows[0])}
                resource["admission_ms"] = [v for row in rows for v in row["admission_ms"]]
                record(f"P-admission-{state}", True, evidence, resource, {**ledger,"work_unit_id":"admission","offered":160,"accepted":160,"succeeded":160})
                if state != "baseline":
                    samples = {name:[row["control"][name] for row in rows] for name in ["prepare_ms","commit_ms"]}
                    acceptance = "passed" if max(samples["prepare_ms"]) <= 30000 and max(samples["commit_ms"]) <= 100 else "failed"
                    record(f"P-control-{state}", True, evidence, samples, {**ledger,"work_unit_id":"upgrade","offered":5,"accepted":5,"succeeded":5}, acceptance)
        if not good:
            execution = 1
    run_path = output/"run.json"
    save(run_path, {"schema_version":"1.1","target":model["target"],"revision":model["revision"],"model_digest":pinned,"plan_digest":canonical(plan),
                   "environment":{"description":"Native local component measurement; see full environment and raw observations", "evidence":[file_evidence(env_path)]}, "records":records})
    check = command(checker+["--stage","valid","--run",str(run_path),"--format","markdown","--output",str(output/"BENCHMARK.valid.md")], output/"valid-check.log")
    acceptance_failed = any(record["acceptance"] == "failed" for record in records)
    save(output/"exit-codes.json", {"unit_preflight":unit_preflight,"preflight":preflight,"measurement":execution,"checker":check,"acceptance_failed":acceptance_failed,"finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat()})
    print(f"Evidence: {output}; preflight={preflight}, measurement={execution}, checker={check}; acceptance_failed={acceptance_failed}")
    return 1 if preflight or execution or check or acceptance_failed else 0


if __name__ == "__main__":
    sys.exit(main())
