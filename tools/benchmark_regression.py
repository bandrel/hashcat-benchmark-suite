#!/usr/bin/env python3
"""Synthetic benchmark regression suite.

Runs ``hashcat -b`` across multiple hash modes and Vec widths, collecting
30-trial statistics with quality gates and cross-Vec t-test comparisons.

Usage:
    # Full run (30 trials, all default modes)
    python3 tools/benchmark_regression.py --trials 30

    # Quick smoke test
    python3 tools/benchmark_regression.py --trials 3

    # Specific modes and device
    python3 tools/benchmark_regression.py --modes 0,1000,900 --trials 10 --device 1

    # Compare against a baseline
    python3 tools/benchmark_regression.py --trials 30 --baseline results/baseline.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from detect_system import detect_system
from stats import check_quality, compute_summary, welch_t_test

# ── Constants ───────────────────────────────────────────────────────────────

DEFAULT_MODES = [0, 10, 11, 20, 22, 30, 40, 60, 70, 900, 1000, 1100, 2600]

VEC_WIDTHS = [1, 2, 4]

# Speed unit -> MH/s multiplier
_UNIT_MULTIPLIERS = {
    "H/s": 1e-6,
    "kH/s": 1e-3,
    "MH/s": 1.0,
    "GH/s": 1e3,
    "TH/s": 1e6,
}

_SPEED_RE = re.compile(r"Speed[^:]*:\s*([\d.]+)\s*([kMGT]?H/s)")
_NAME_RE = re.compile(r"Name\.+:\s*(.*)")


# ── Helper functions ────────────────────────────────────────────────────────


def get_gpu_temp() -> float | None:
    """Best-effort GPU temperature reading.

    Tries nvidia-smi on Linux.  Returns None if unavailable (macOS without
    sudo cannot read GPU temperature).
    """
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return float(result.stdout.strip().splitlines()[0])
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        pass
    return None


def run_benchmark(
    hashcat_bin: str,
    mode: int,
    vec_width: int,
    device: int | None = None,
) -> float | None:
    """Run a single ``hashcat -b`` invocation and return speed in MH/s.

    Returns ``None`` on timeout or if the speed line cannot be parsed.
    """
    cmd = [hashcat_bin, "-b", "-m", str(mode), f"--backend-vector-width={vec_width}"]
    if device is not None:
        cmd.extend(["-d", str(device), "--force"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        combined = result.stdout + result.stderr

        match = _SPEED_RE.search(combined)
        if not match:
            return None

        value = float(match.group(1))
        unit = match.group(2)
        return value * _UNIT_MULTIPLIERS.get(unit, 1.0)

    except subprocess.TimeoutExpired:
        return None


def get_mode_name(hashcat_bin: str, mode: int) -> str:
    """Return the human-readable algorithm name for *mode*.

    Falls back to ``"Mode {mode}"`` on failure.
    """
    try:
        result = subprocess.run(
            [hashcat_bin, "--hash-info", "-m", str(mode)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        match = _NAME_RE.search(result.stdout)
        if match:
            return match.group(1).strip()
    except subprocess.TimeoutExpired:
        pass
    return f"Mode {mode}"


# ── Core benchmark suite ────────────────────────────────────────────────────


def run_benchmark_suite(
    hashcat_bin: str,
    modes: list[int],
    trials: int,
    device: int | None = None,
    verbose: bool = True,
) -> dict:
    """Run benchmarks across all modes and Vec widths.

    Returns a structured results dict keyed by mode (str) with per-Vec
    statistics, quality checks, cross-Vec comparisons, and optimal Vec
    determination.
    """
    results: dict = {}

    for mode in modes:
        name = get_mode_name(hashcat_bin, mode)
        if verbose:
            print(f"\n--- Mode {mode}: {name} ---")

        mode_data: dict = {
            "name": name,
            "vec_results": {},
            "comparisons": {},
            "optimal_vec": None,
        }

        # Collect speeds for each Vec width.
        raw_speeds: dict[int, list[float]] = {}

        for vec in VEC_WIDTHS:
            speeds: list[float] = []
            temps: list[float] = []

            for i in range(trials):
                # Record temperature before each trial (best effort).
                temp = get_gpu_temp()
                if temp is not None:
                    temps.append(temp)

                speed = run_benchmark(hashcat_bin, mode, vec, device)
                if speed is not None:
                    speeds.append(speed)

                if verbose:
                    status = f"{speed:.1f} MH/s" if speed is not None else "FAILED"
                    temp_str = f" (GPU {temp:.0f}C)" if temp is not None else ""
                    print(
                        f"  Vec:{vec} trial {i + 1}/{trials}: {status}{temp_str}"
                    )

            raw_speeds[vec] = speeds

            if speeds:
                summary = compute_summary(speeds)
                passed, reason = check_quality(speeds, min_trials=trials)
                vec_entry: dict = {
                    **summary,
                    "speeds": speeds,
                    "quality_passed": passed,
                    "quality_reason": reason,
                }
                if temps:
                    vec_entry["gpu_temps"] = temps
                mode_data["vec_results"][str(vec)] = vec_entry

        # Cross-Vec comparisons using Welch's t-test (Vec N vs Vec 1).
        vec1_speeds = raw_speeds.get(1, [])
        for vec in VEC_WIDTHS:
            if vec == 1:
                continue
            vec_speeds = raw_speeds.get(vec, [])
            if len(vec1_speeds) >= 2 and len(vec_speeds) >= 2:
                t_stat, df, significant = welch_t_test(vec_speeds, vec1_speeds)
                # Note: welch_t_test computes (a - b), so positive t means
                # vec_speeds > vec1_speeds (vec N faster than vec 1).
                vec1_mean = compute_summary(vec1_speeds)["mean"]
                vecN_mean = compute_summary(vec_speeds)["mean"]
                pct_change = (
                    (vecN_mean - vec1_mean) / vec1_mean * 100 if vec1_mean else 0.0
                )
                mode_data["comparisons"][f"vec{vec}_vs_vec1"] = {
                    "t_stat": t_stat,
                    "df": df,
                    "significant": significant,
                    "pct_change": pct_change,
                }

        # Determine optimal Vec (highest mean speed among completed configs).
        best_vec = None
        best_mean = -1.0
        for vec in VEC_WIDTHS:
            entry = mode_data["vec_results"].get(str(vec))
            if entry and entry["mean"] > best_mean:
                best_mean = entry["mean"]
                best_vec = vec
        mode_data["optimal_vec"] = best_vec

        results[str(mode)] = mode_data

    return results


# ── Display ─────────────────────────────────────────────────────────────────


def print_summary(results: dict, system_info: dict) -> None:
    """Print a formatted summary table of benchmark results."""
    print("\n" + "=" * 115)
    print(f"BENCHMARK RESULTS - {system_info.get('hashcat_version', 'unknown')}")
    print(f"GPU: {system_info.get('gpu_model', 'unknown')}")
    print(f"Backend: {system_info.get('backend', 'unknown')}")
    print(f"Timestamp: {system_info.get('timestamp', 'unknown')}")
    print("=" * 115)

    header = (
        f"{'Mode':<7} {'Name':<35} "
        f"{'Vec1 MH/s':>12} {'Vec2 MH/s':>12} {'V2vs1%':>8} "
        f"{'Vec4 MH/s':>12} {'V4vs1%':>8} {'Best':>5}"
    )
    print(f"\n{header}")
    print("-" * 115)

    for mode_str, data in sorted(results.items(), key=lambda x: int(x[0])):
        name = data["name"][:35]
        v1 = data["vec_results"].get("1", {})
        v2 = data["vec_results"].get("2", {})
        v4 = data["vec_results"].get("4", {})

        v1_mean = v1.get("mean", 0.0)
        v2_mean = v2.get("mean", 0.0)
        v4_mean = v4.get("mean", 0.0)

        v2_pct = (v2_mean - v1_mean) / v1_mean * 100 if v1_mean else 0.0
        v4_pct = (v4_mean - v1_mean) / v1_mean * 100 if v1_mean else 0.0

        v1_str = f"{v1_mean:>9.1f}" if v1 else "      N/A"
        v2_str = f"{v2_mean:>9.1f}" if v2 else "      N/A"
        v4_str = f"{v4_mean:>9.1f}" if v4 else "      N/A"

        best = data.get("optimal_vec")
        best_str = f"Vec:{best}" if best else "N/A"

        print(
            f"{mode_str:<7} {name:<35} "
            f"{v1_str:>12} {v2_str:>12} {v2_pct:>+7.1f}% "
            f"{v4_str:>12} {v4_pct:>+7.1f}% {best_str:>5}"
        )

    print()


# ── Baseline comparison ─────────────────────────────────────────────────────


def compare_baseline(results: dict, baseline: dict) -> list[dict]:
    """Compare results against a baseline, returning a list of regressions.

    A regression is flagged when: speed drops > 2% AND the difference is
    statistically significant (Welch's t-test at p < 0.01).
    """
    regressions: list[dict] = []

    for mode_str, data in results.items():
        if mode_str not in baseline:
            continue
        base_mode = baseline[mode_str]

        for vec_str, current in data["vec_results"].items():
            base_vec = base_mode.get("vec_results", {}).get(vec_str)
            if not base_vec or "speeds" not in base_vec:
                continue

            cur_mean = current["mean"]
            base_mean = base_vec["mean"]
            pct_change = (
                (cur_mean - base_mean) / base_mean * 100 if base_mean else 0.0
            )

            t_stat, df, significant = welch_t_test(
                base_vec["speeds"], current["speeds"]
            )

            if pct_change < -2.0 and significant:
                regressions.append(
                    {
                        "mode": mode_str,
                        "name": data["name"],
                        "vec": vec_str,
                        "baseline_mean": base_mean,
                        "current_mean": cur_mean,
                        "pct_change": pct_change,
                        "t_stat": t_stat,
                        "df": df,
                    }
                )

    return regressions


# ── CLI entry point ─────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Synthetic benchmark regression suite for hashcat"
    )
    parser.add_argument(
        "--hashcat-bin",
        default="./hashcat",
        help="Path to hashcat binary (default: ./hashcat)",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=30,
        help="Number of trials per configuration (default: 30)",
    )
    parser.add_argument(
        "--modes",
        type=str,
        default=None,
        help="Comma-separated hash modes to test (default: all 13 default modes)",
    )
    parser.add_argument(
        "--device",
        type=int,
        default=None,
        help="Specific device ID to test",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results",
        help="Output directory (default: results)",
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default=None,
        help="Path to baseline JSON for regression comparison",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-trial output",
    )
    args = parser.parse_args()

    # Parse modes.
    modes = (
        [int(m.strip()) for m in args.modes.split(",")]
        if args.modes
        else DEFAULT_MODES
    )

    # Detect system.
    system_info = detect_system(args.hashcat_bin)

    device_id = system_info.get("device_id", "unknown")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    total_runs = len(modes) * len(VEC_WIDTHS) * args.trials
    est_minutes = total_runs * 10 // 60  # ~10s per benchmark run

    if not args.quiet:
        print(f"Hashcat synthetic benchmark suite")
        print(f"  Modes:    {len(modes)}")
        print(f"  Vec widths: {VEC_WIDTHS}")
        print(f"  Trials:   {args.trials}")
        print(f"  Total runs: {total_runs}")
        print(f"  Est. time:  ~{est_minutes} minutes")
        print(f"  GPU:      {system_info.get('gpu_model', 'unknown')}")
        print(f"  Backend:  {system_info.get('backend', 'unknown')}")
        print(f"  Hashcat:  {system_info.get('hashcat_version', 'unknown')}")
        print()

    # Run the benchmark suite.
    results = run_benchmark_suite(
        args.hashcat_bin, modes, args.trials, args.device, verbose=not args.quiet
    )

    # Print summary table.
    print_summary(results, system_info)

    # Build output directory: {output}/{device_id}/{timestamp}/
    out_dir = Path(args.output) / device_id / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    # Save system_info.json.
    with open(out_dir / "system_info.json", "w") as f:
        json.dump(system_info, f, indent=2)
        f.write("\n")

    # Save per-Vec benchmark files.
    for vec in VEC_WIDTHS:
        vec_data: dict = {}
        for mode_str, data in results.items():
            vec_entry = data["vec_results"].get(str(vec))
            if vec_entry:
                vec_data[mode_str] = {
                    "name": data["name"],
                    **{k: v for k, v in vec_entry.items() if k != "speeds"},
                    "speeds": vec_entry.get("speeds", []),
                }
        with open(out_dir / f"benchmark_vec{vec}.json", "w") as f:
            json.dump(vec_data, f, indent=2)
            f.write("\n")

    # Save benchmark_summary.json (full results without raw speed arrays for
    # compactness, plus comparisons and optimal_vec).
    summary: dict = {
        "system_info": system_info,
        "modes": {},
    }
    for mode_str, data in results.items():
        mode_summary: dict = {
            "name": data["name"],
            "optimal_vec": data["optimal_vec"],
            "comparisons": data["comparisons"],
            "vec_results": {},
        }
        for vec_str, vec_entry in data["vec_results"].items():
            mode_summary["vec_results"][vec_str] = {
                k: v for k, v in vec_entry.items() if k != "speeds"
            }
        summary["modes"][mode_str] = mode_summary

    with open(out_dir / "benchmark_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    if not args.quiet:
        print(f"Results saved to: {out_dir}/")

    # Baseline regression comparison.
    if args.baseline:
        with open(args.baseline) as f:
            baseline_data = json.load(f)

        # Support both flat results and nested {"results": ...} format.
        if "results" in baseline_data:
            baseline_results = baseline_data["results"]
        elif "modes" in baseline_data:
            baseline_results = baseline_data["modes"]
        else:
            baseline_results = baseline_data

        regressions = compare_baseline(results, baseline_results)

        if regressions:
            print(f"\n{'!' * 60}")
            print(f"REGRESSIONS DETECTED ({len(regressions)}):")
            print(f"{'!' * 60}")
            for r in regressions:
                print(
                    f"  Mode {r['mode']} ({r['name']}) Vec:{r['vec']}: "
                    f"{r['baseline_mean']:.1f} -> {r['current_mean']:.1f} MH/s "
                    f"({r['pct_change']:+.1f}%, t={r['t_stat']:.2f})"
                )
            sys.exit(1)
        else:
            print("\nNo regressions detected.")


if __name__ == "__main__":
    main()
