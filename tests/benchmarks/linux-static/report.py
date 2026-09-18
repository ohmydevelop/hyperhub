#!/usr/bin/env python3
import csv
import pathlib
import statistics
import sys


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} results.csv output-dir")
    results_path = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    groups: dict[tuple[str, str], list[float]] = {}
    metadata: dict[str, tuple[str, int]] = {}
    with results_path.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            workload = row["workload"]
            mode = row["mode"]
            groups.setdefault((workload, mode), []).append(float(row["elapsed_ms"]))
            metadata[workload] = (row["kind"], int(row["binary_bytes"]))

    rows = []
    for workload in metadata:
        native_values = groups.get((workload, "native"), [])
        hyperhub_values = groups.get((workload, "hyperhub"), [])
        native = statistics.median(native_values) if native_values else None
        hyperhub = statistics.median(hyperhub_values) if hyperhub_values else None
        delta = hyperhub - native if native is not None and hyperhub is not None else None
        ratio = hyperhub / native if native and hyperhub is not None else None
        kind, size = metadata[workload]
        rows.append((workload, kind, size, native, hyperhub, delta, ratio))

    summary_path = output / "summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.writer(destination)
        writer.writerow(
            [
                "workload",
                "kind",
                "binary_bytes",
                "native_median_ms",
                "hyperhub_median_ms",
                "overhead_ms",
                "overhead_ratio",
            ]
        )
        for workload, kind, size, native, hyperhub, delta, ratio in rows:
            writer.writerow(
                [
                    workload,
                    kind,
                    size,
                    format_value(native),
                    format_value(hyperhub),
                    format_value(delta),
                    format_value(ratio),
                ]
            )

    report_path = output / "report.md"
    with report_path.open("w", encoding="utf-8") as report:
        report.write("# Linux static stripped benchmark\n\n")
        report.write("| Workload | Kind | Binary MiB | Native median ms | HyperHub median ms | Added ms | Ratio |\n")
        report.write("| --- | --- | ---: | ---: | ---: | ---: | ---: |\n")
        for workload, kind, size, native, hyperhub, delta, ratio in rows:
            report.write(
                f"| {workload} | {kind} | {size / 1024 / 1024:.2f} | "
                f"{display(native)} | {display(hyperhub)} | {display(delta)} | "
                f"{display_ratio(ratio)} |\n"
            )
        report.write("\nHyperHub measurements include CLI session setup and the portable ptrace syscall supervisor. ")
        report.write("Kernel-assisted backends may reduce this overhead later without changing policy semantics.\n")

    print_table(rows)


def format_value(value: float | None) -> str:
    return "" if value is None else f"{value:.3f}"


def display(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def display_ratio(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}x"


def print_table(rows: list[tuple[str, str, int, float | None, float | None, float | None, float | None]]) -> None:
    print()
    print(f"{'workload':<12} {'native_ms':>12} {'hyperhub_ms':>14} {'added_ms':>12} {'ratio':>9}")
    for workload, _kind, _size, native, hyperhub, delta, ratio in rows:
        print(
            f"{workload:<12} {display(native):>12} {display(hyperhub):>14} "
            f"{display(delta):>12} {display_ratio(ratio):>9}"
        )


if __name__ == "__main__":
    main()
