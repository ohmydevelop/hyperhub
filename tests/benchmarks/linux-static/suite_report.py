#!/usr/bin/env python3
import csv
import json
import pathlib
import sys
from typing import Any


def load_checks(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def load_performance(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", newline="") as source:
        for row in csv.DictReader(source):
            converted: dict[str, Any] = dict(row)
            converted["binary_bytes"] = int(row["binary_bytes"])
            for key in (
                "native_median_ms",
                "hyperhub_median_ms",
                "overhead_ms",
                "overhead_ratio",
            ):
                converted[key] = float(row[key]) if row[key] else None
            rows.append(converted)
    return rows


def display(value: float | None, suffix: str = "") -> str:
    return "-" if value is None else f"{value:.3f}{suffix}"


def main() -> None:
    if len(sys.argv) != 6:
        raise SystemExit(
            f"usage: {sys.argv[0]} checks.tsv summary.csv fixtures.json suite.json report.md"
        )
    checks_path, summary_path, fixtures_path, suite_path, report_path = map(
        pathlib.Path, sys.argv[1:]
    )
    checks = load_checks(checks_path)
    performance = load_performance(summary_path)
    fixtures = json.loads(fixtures_path.read_text(encoding="utf-8"))
    passed = all(check["status"] == "pass" for check in checks)
    suite = {
        "schema_version": 1,
        "status": "pass" if passed else "fail",
        "checks": checks,
        "performance": performance,
        "fixtures": fixtures,
    }
    suite_path.write_text(json.dumps(suite, indent=2) + "\n", encoding="utf-8")

    with report_path.open("w", encoding="utf-8") as report:
        report.write("# Linux backend reusable benchmark\n\n")
        report.write(f"**Result: {'PASS' if passed else 'FAIL'}**\n\n")
        report.write("## Functional checks\n\n")
        report.write("| Check | Status | Details |\n")
        report.write("| --- | --- | --- |\n")
        for check in checks:
            report.write(
                f"| {check['check']} | {check['status']} | {check['details']} |\n"
            )
        report.write("\n## Performance\n\n")
        report.write(
            "| Workload | Kind | Binary MiB | Native ms | HyperHub ms | Added ms | Ratio |\n"
        )
        report.write("| --- | --- | ---: | ---: | ---: | ---: | ---: |\n")
        for row in performance:
            ratio = row["overhead_ratio"]
            report.write(
                f"| {row['workload']} | {row['kind']} | "
                f"{row['binary_bytes'] / 1024 / 1024:.2f} | "
                f"{display(row['native_median_ms'])} | "
                f"{display(row['hyperhub_median_ms'])} | "
                f"{display(row['overhead_ms'])} | "
                f"{display(ratio, 'x')} |\n"
            )
        report.write("\n## Fixture identity\n\n")
        report.write(f"- Architecture: `{fixtures['architecture']}`\n")
        report.write(f"- Probe fingerprint: `{fixtures['probe_fingerprint']}`\n")
        report.write(f"- Fixture count: {len(fixtures['fixtures'])}\n")

    if not passed:
        raise SystemExit("Linux backend suite contains failed checks")


if __name__ == "__main__":
    main()
