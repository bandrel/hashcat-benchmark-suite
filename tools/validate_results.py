#!/usr/bin/env python3
"""Validate benchmark results, correctness reports, and system info.

Quality gates: trial count, coefficient of variation, PII detection,
required field checks.  Used by submit_results.py and CI pipelines.
"""

import argparse
import json
import math
import os
import re
import statistics
import sys


# ── PII fields that must never appear in submitted data ─────────────────────

PII_FIELDS: frozenset = frozenset(
    {
        "hostname",
        "username",
        "serial_number",
        "hardware_uuid",
        "mac_address",
        "ip_address",
        "gpu_uuid",
        "pci_bus_id",
    }
)

_PATH_RE = re.compile(r"(?:/Users/|/home/)")

# ── Required system_info fields ─────────────────────────────────────────────

REQUIRED_SYSTEM_FIELDS: list[str] = [
    "gpu_model",
    "os_name",
    "os_version",
    "hashcat_version",
    "hashcat_binary_sha256",
    "device_id",
    "timestamp",
]


# ── Validation functions ────────────────────────────────────────────────────


def validate_benchmark_quality(data: dict, min_trials: int = 30) -> list[str]:
    """Validate benchmark result quality.

    Checks each mode/vec combo in ``data["results"]`` for:
    - Speeds array length >= *min_trials*
    - No all-zero speed arrays
    - No NaN values in speeds
    - Coefficient of variation <= 5%

    Returns a list of error strings (empty means valid).
    """
    errors: list[str] = []
    results = data.get("results", {})

    for mode, mode_data in results.items():
        vec_results = mode_data.get("vec_results", {})
        for vec, vec_data in vec_results.items():
            prefix = f"mode {mode} vec {vec}"
            speeds = vec_data.get("speeds", [])

            # Check for NaN values first
            if any(isinstance(s, float) and math.isnan(s) for s in speeds):
                errors.append(f"{prefix}: speeds contain NaN values")
                continue  # skip further checks on corrupt data

            # Check trial count
            if len(speeds) < min_trials:
                errors.append(
                    f"{prefix}: too few speed samples ({len(speeds)} < {min_trials})"
                )
                continue  # CV check meaningless with too few samples

            # Check all zeros
            if all(s == 0 for s in speeds):
                errors.append(f"{prefix}: all speeds are zero")
                continue

            # Check CV
            mean = statistics.mean(speeds)
            if mean != 0 and len(speeds) >= 2:
                stdev = statistics.stdev(speeds)
                cv = stdev / abs(mean)
                if cv > 0.05:
                    errors.append(
                        f"{prefix}: CV too high ({cv:.4f} > 0.05)"
                    )

    return errors


def validate_correctness(data: dict) -> list[str]:
    """Validate correctness test results.

    Errors if:
    - ``failed`` > 0
    - ``total_tested`` == 0

    Returns a list of error strings (empty means valid).
    """
    errors: list[str] = []

    total = data.get("total_tested", 0)
    failed = data.get("failed", 0)

    if total == 0:
        errors.append("total_tested is 0 — no tests were run")

    if failed > 0:
        errors.append(f"correctness failures: {failed} of {total} tests failed")

    return errors


def validate_system_info(data: dict) -> list[str]:
    """Validate system info for required fields, PII, and file paths.

    Checks:
    - All required fields are present
    - No PII fields (hostname, username, serial_number, etc.)
    - No file paths containing ``/Users/`` or ``/home/`` in values

    Returns a list of error strings (empty means valid).
    """
    errors: list[str] = []

    # Check required fields
    for field in REQUIRED_SYSTEM_FIELDS:
        if field not in data:
            errors.append(f"missing required field: {field}")

    # Check for PII fields
    for field in PII_FIELDS:
        if field in data:
            errors.append(f"PII field present: {field}")

    # Check for file paths in values
    for key, value in data.items():
        if isinstance(value, str) and _PATH_RE.search(value):
            errors.append(
                f"file path detected in field '{key}': value contains /Users/ or /home/"
            )

    return errors


def validate_results_dir(results_dir: str, min_trials: int = 30) -> list[str]:
    """Validate all result files in a results directory.

    Looks for:
    - ``system_info.json``
    - ``benchmark_summary.json``
    - ``correctness/*.json`` or ``correctness*.json``

    Returns combined error list from all validations.
    """
    errors: list[str] = []

    # Validate system_info.json
    sys_info_path = os.path.join(results_dir, "system_info.json")
    if os.path.isfile(sys_info_path):
        with open(sys_info_path) as f:
            sys_data = json.load(f)
        for err in validate_system_info(sys_data):
            errors.append(f"system_info.json: {err}")
    else:
        errors.append("system_info.json not found")

    # Validate benchmark_summary.json
    bench_path = os.path.join(results_dir, "benchmark_summary.json")
    if os.path.isfile(bench_path):
        with open(bench_path) as f:
            bench_data = json.load(f)
        for err in validate_benchmark_quality(bench_data, min_trials=min_trials):
            errors.append(f"benchmark_summary.json: {err}")
    else:
        errors.append("benchmark_summary.json not found")

    # Validate correctness files
    correctness_dir = os.path.join(results_dir, "correctness")
    correctness_files: list[str] = []

    if os.path.isdir(correctness_dir):
        correctness_files = [
            os.path.join(correctness_dir, f)
            for f in sorted(os.listdir(correctness_dir))
            if f.endswith(".json")
        ]
    else:
        # Check for correctness*.json in the results dir itself
        correctness_files = [
            os.path.join(results_dir, f)
            for f in sorted(os.listdir(results_dir))
            if f.startswith("correctness") and f.endswith(".json")
        ]

    if not correctness_files:
        errors.append("no correctness result files found")
    else:
        for cpath in correctness_files:
            fname = os.path.basename(cpath)
            with open(cpath) as f:
                cdata = json.load(f)
            for err in validate_correctness(cdata):
                errors.append(f"{fname}: {err}")

    return errors


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate benchmark result files for quality and PII."
    )
    parser.add_argument(
        "results_dir",
        help="Path to the results directory to validate",
    )
    parser.add_argument(
        "--min-trials",
        type=int,
        default=30,
        help="Minimum number of speed samples per mode/vec (default: 30)",
    )
    args = parser.parse_args()

    errors = validate_results_dir(args.results_dir, min_trials=args.min_trials)

    if errors:
        print("VALIDATION FAILED")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("VALIDATION PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
