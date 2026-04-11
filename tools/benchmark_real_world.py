#!/usr/bin/env python3
"""Real-world benchmark harness using wordlists and rules.

Runs hashcat in attack mode 0 (straight), 1 (combinator), and 3 (brute-force)
with realistic workloads: wordlists, rule files, multi-hash targets.

Six full scenarios and one quick scenario provide coverage of common cracking
workflows while measuring throughput, recovery rates, and per-Vec performance.

Usage:
    # Quick smoke test (single scenario, few trials)
    python3 tools/benchmark_real_world.py \\
        --hashcat-bin ../hashcat/hashcat \\
        --wordlist ~/wordlists/rockyou.txt \\
        --hashcat-src ../hashcat \\
        --scenarios quick --trials 3

    # Full run (all 6 scenarios, 30 trials)
    python3 tools/benchmark_real_world.py \\
        --hashcat-bin ../hashcat/hashcat \\
        --wordlist ~/wordlists/rockyou.txt \\
        --hashcat-src ../hashcat \\
        --scenarios all --trials 30
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from benchmark_regression import VEC_WIDTHS, get_gpu_temp
from detect_system import detect_system
from stats import check_quality, compute_summary


# ── Scenario definitions ────────────────────────────────────────────────────

SCENARIOS_FULL = [
    {
        "name": "wordlist_norules_single",
        "description": "Wordlist attack, no rules, single hash target",
        "attack_mode": 0,
        "wordlist_key": "rockyou",
        "rules": None,
        "hash_target": "single",
    },
    {
        "name": "wordlist_norules_multi1k",
        "description": "Wordlist attack, no rules, 1K hash targets",
        "attack_mode": 0,
        "wordlist_key": "rockyou",
        "rules": None,
        "hash_target": "hashes_1k",
    },
    {
        "name": "wordlist_best64_single",
        "description": "Wordlist + best64 rules, single hash target",
        "attack_mode": 0,
        "wordlist_key": "rockyou",
        "rules": "best64.rule",
        "hash_target": "single",
    },
    {
        "name": "wordlist_dive_single",
        "description": "Wordlist + dive rules, single hash target",
        "attack_mode": 0,
        "wordlist_key": "rockyou",
        "rules": "dive.rule",
        "hash_target": "single",
    },
    {
        "name": "combinator_top1k",
        "description": "Combinator attack (top1k x top1k), 1K hash targets",
        "attack_mode": 1,
        "wordlist_key": "top1k",
        "wordlist2_key": "top1k",
        "rules": None,
        "hash_target": "hashes_1k",
    },
    {
        "name": "bruteforce_7char",
        "description": "Brute-force 7-char all-printable, single hash target",
        "attack_mode": 3,
        "mask": "?a?a?a?a?a?a?a",
        "rules": None,
        "hash_target": "single",
    },
]

SCENARIOS_QUICK = [
    {
        "name": "wordlist_best64_single_quick",
        "description": "Wordlist + best64 rules, single hash (quick)",
        "attack_mode": 0,
        "wordlist_key": "top10k",
        "rules": "best64.rule",
        "hash_target": "single",
    },
]


# ── Speed parsing ───────────────────────────────────────────────────────────

_UNIT_MULTIPLIERS = {
    "H/s": 1e-6,
    "kH/s": 1e-3,
    "MH/s": 1.0,
    "GH/s": 1e3,
    "TH/s": 1e6,
}

_SPEED_RE = re.compile(r"Speed[^:]*:\s*([\d.]+)\s*([kMGT]?H/s)")
_MACHINE_SPEED_RE = re.compile(r"SPEED\s+[\d.]+\s+([\d.]+)\s*([kMGT]?H/s)")


def _parse_speed(output: str) -> float | None:
    """Extract speed in MH/s from hashcat output."""
    # Try machine-readable format first.
    match = _MACHINE_SPEED_RE.search(output)
    if not match:
        match = _SPEED_RE.search(output)
    if not match:
        return None
    value = float(match.group(1))
    unit = match.group(2)
    return value * _UNIT_MULTIPLIERS.get(unit, 1.0)


def _count_recovered(potfile_path: str) -> int:
    """Count lines in a potfile to determine recovered passwords."""
    if not os.path.exists(potfile_path):
        return 0
    with open(potfile_path) as f:
        return sum(1 for _ in f)


# ── Resolve scenario paths ──────────────────────────────────────────────────


def _resolve_paths(
    scenario: dict,
    wordlist_path: str,
    hashcat_src: str,
    corpus_dir: str,
) -> dict:
    """Build a resolved copy of a scenario with absolute file paths.

    Adds keys: hash_file, wordlist_file, wordlist2_file (optional),
    rules_file (optional), mask (pass-through).
    """
    resolved = dict(scenario)

    # Hash target file.
    target = scenario["hash_target"]
    if target == "single":
        resolved["hash_file"] = os.path.join(corpus_dir, "single.hash")
    elif target == "hashes_1k":
        resolved["hash_file"] = os.path.join(corpus_dir, "hashes_1k.txt")
    elif target == "hashes_100k":
        resolved["hash_file"] = os.path.join(corpus_dir, "hashes_100k.txt")
    else:
        resolved["hash_file"] = os.path.join(corpus_dir, target)

    # Wordlist files (attack modes 0 and 1).
    wl_map = {
        "rockyou": wordlist_path,
        "top1k": os.path.join(corpus_dir, "rockyou-top1k.txt"),
        "top10k": os.path.join(corpus_dir, "rockyou-top10k.txt"),
        "ascii_only": os.path.join(corpus_dir, "rockyou-ascii-only.txt"),
    }

    wl_key = scenario.get("wordlist_key")
    if wl_key:
        resolved["wordlist_file"] = wl_map.get(wl_key, wl_key)

    wl2_key = scenario.get("wordlist2_key")
    if wl2_key:
        resolved["wordlist2_file"] = wl_map.get(wl2_key, wl2_key)

    # Rules file.
    rules = scenario.get("rules")
    if rules:
        resolved["rules_file"] = os.path.join(hashcat_src, "rules", rules)

    return resolved


# ── Single benchmark run ────────────────────────────────────────────────────


def run_real_world_benchmark(
    hashcat_bin: str,
    scenario: dict,
    vec_width: int,
    timeout: int = 600,
) -> dict | None:
    """Run hashcat with the given scenario config and return metrics.

    Executes in a temporary directory to isolate potfiles and session data.

    Parameters
    ----------
    hashcat_bin : str
        Path to hashcat binary.
    scenario : dict
        Resolved scenario dict (from _resolve_paths).
    vec_width : int
        Backend vector width (1, 2, or 4).
    timeout : int
        Maximum seconds to allow the run.

    Returns
    -------
    dict or None
        ``{hashes_per_second, total_time_seconds, passwords_recovered}``
        or ``None`` on failure/timeout.
    """
    with tempfile.TemporaryDirectory(prefix="hashcat_rw_") as tmpdir:
        potfile = os.path.join(tmpdir, "hashcat.potfile")

        cmd = [
            hashcat_bin,
            "-m", "1000",                          # NTLM
            "-a", str(scenario["attack_mode"]),
            f"--backend-vector-width={vec_width}",
            "--machine-readable",
            "--potfile-path", potfile,
            "--outfile", os.path.join(tmpdir, "out.txt"),
            "--session", "rw_bench",
            "-o", os.path.join(tmpdir, "found.txt"),
            "--quiet",
        ]

        attack_mode = scenario["attack_mode"]

        if attack_mode == 0:
            # Straight / wordlist
            cmd.append(scenario["hash_file"])
            cmd.append(scenario["wordlist_file"])
            if scenario.get("rules_file"):
                cmd.extend(["-r", scenario["rules_file"]])

        elif attack_mode == 1:
            # Combinator
            cmd.append(scenario["hash_file"])
            cmd.append(scenario["wordlist_file"])
            cmd.append(scenario["wordlist2_file"])

        elif attack_mode == 3:
            # Brute-force / mask
            cmd.append(scenario["hash_file"])
            cmd.append(scenario["mask"])

        try:
            start = datetime.now(timezone.utc)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmpdir,
            )
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()

            combined = result.stdout + result.stderr
            speed = _parse_speed(combined)

            recovered = _count_recovered(potfile)

            if speed is None:
                # Try to salvage: if it completed but speed wasn't parseable,
                # still return timing info.
                return None

            return {
                "hashes_per_second": speed,
                "total_time_seconds": elapsed,
                "passwords_recovered": recovered,
            }

        except subprocess.TimeoutExpired:
            return None


# ── Multi-trial runner ──────────────────────────────────────────────────────


def run_scenario_trials(
    hashcat_bin: str,
    scenario: dict,
    trials: int,
    verbose: bool = True,
) -> dict:
    """Run a scenario across all Vec widths for multiple trials.

    Parameters
    ----------
    hashcat_bin : str
        Path to hashcat binary.
    scenario : dict
        Resolved scenario dict.
    trials : int
        Number of repetitions per Vec width.
    verbose : bool
        Print per-trial progress.

    Returns
    -------
    dict
        Structured results with per-Vec statistics, quality checks,
        and optimal Vec determination.
    """
    scenario_result: dict = {
        "name": scenario["name"],
        "description": scenario["description"],
        "attack_mode": scenario["attack_mode"],
        "vec_results": {},
        "optimal_vec": None,
    }

    best_vec = None
    best_mean = -1.0

    for vec in VEC_WIDTHS:
        speeds: list[float] = []
        times: list[float] = []
        recovered_counts: list[int] = []
        temps: list[float] = []

        for i in range(trials):
            temp = get_gpu_temp()
            if temp is not None:
                temps.append(temp)

            result = run_real_world_benchmark(hashcat_bin, scenario, vec)

            if result is not None:
                speeds.append(result["hashes_per_second"])
                times.append(result["total_time_seconds"])
                recovered_counts.append(result["passwords_recovered"])

            if verbose:
                if result is not None:
                    speed_str = f"{result['hashes_per_second']:.1f} MH/s"
                    time_str = f"{result['total_time_seconds']:.1f}s"
                    rec_str = f"{result['passwords_recovered']} recovered"
                else:
                    speed_str = "FAILED"
                    time_str = "N/A"
                    rec_str = "N/A"
                temp_str = f" (GPU {temp:.0f}C)" if temp is not None else ""
                print(
                    f"  Vec:{vec} trial {i + 1}/{trials}: "
                    f"{speed_str}, {time_str}, {rec_str}{temp_str}"
                )

        if speeds:
            summary = compute_summary(speeds)
            passed, reason = check_quality(speeds, min_trials=trials)
            vec_entry: dict = {
                **summary,
                "speeds": speeds,
                "total_times": times,
                "passwords_recovered": recovered_counts,
                "quality_passed": passed,
                "quality_reason": reason,
            }
            if temps:
                vec_entry["gpu_temps"] = temps

            scenario_result["vec_results"][str(vec)] = vec_entry

            if summary["mean"] > best_mean:
                best_mean = summary["mean"]
                best_vec = vec

    scenario_result["optimal_vec"] = best_vec
    return scenario_result


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Real-world benchmark harness for hashcat NTLM cracking."
    )
    parser.add_argument(
        "--hashcat-bin",
        required=True,
        help="Path to hashcat binary",
    )
    parser.add_argument(
        "--wordlist",
        required=True,
        help="Path to rockyou.txt (or similar full wordlist)",
    )
    parser.add_argument(
        "--hashcat-src",
        default=None,
        help="Path to hashcat source tree (for rules/). "
        "Defaults to parent directory of hashcat-bin.",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=30,
        help="Number of trials per Vec width per scenario (default: 30)",
    )
    parser.add_argument(
        "--scenarios",
        choices=["quick", "all"],
        default="all",
        help="Scenario set to run (default: all)",
    )
    parser.add_argument(
        "--output",
        default="results",
        help="Output directory (default: results)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-trial output",
    )
    args = parser.parse_args()

    # Resolve hashcat source tree.
    hashcat_src = args.hashcat_src
    if hashcat_src is None:
        hashcat_src = os.path.dirname(os.path.abspath(args.hashcat_bin))

    # Detect system info.
    system_info = detect_system(args.hashcat_bin)
    device_id = system_info.get("device_id", "unknown")

    if not args.quiet:
        print("Real-world benchmark harness")
        print(f"  GPU:      {system_info.get('gpu_model', 'unknown')}")
        print(f"  Backend:  {system_info.get('backend', 'unknown')}")
        print(f"  Hashcat:  {system_info.get('hashcat_version', 'unknown')}")
        print(f"  Wordlist: {args.wordlist}")
        print(f"  Hashcat source: {hashcat_src}")
        print()

    # Generate real-world hash targets if not already present.
    corpus_dir = "corpus/real_world"
    required_files = [
        "single.hash",
        "hashes_1k.txt",
        "hashes_100k.txt",
        "rockyou-top1k.txt",
        "rockyou-top10k.txt",
        "rockyou-ascii-only.txt",
    ]
    missing = [
        f for f in required_files if not os.path.exists(os.path.join(corpus_dir, f))
    ]
    if missing:
        if not args.quiet:
            print(f"Generating real-world hash targets ({len(missing)} files missing)...")
        from generate_real_world_hashes import load_wordlist, generate_hash_targets, main as gen_main

        # Run the generator via subprocess to keep isolation clean.
        subprocess.run(
            [sys.executable, "-m", "generate_real_world_hashes",
             "--wordlist", args.wordlist, "--output-dir", corpus_dir],
            check=True,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        if not args.quiet:
            print()

    # Select scenarios.
    if args.scenarios == "quick":
        scenarios = SCENARIOS_QUICK
    else:
        scenarios = SCENARIOS_FULL

    total_runs = len(scenarios) * len(VEC_WIDTHS) * args.trials
    if not args.quiet:
        print(f"Scenarios:  {len(scenarios)}")
        print(f"Vec widths: {VEC_WIDTHS}")
        print(f"Trials:     {args.trials}")
        print(f"Total runs: {total_runs}")
        print()

    # Run all scenarios.
    all_results: dict = {}

    for scenario in scenarios:
        resolved = _resolve_paths(
            scenario, args.wordlist, hashcat_src, corpus_dir
        )

        if not args.quiet:
            print(f"\n--- {resolved['name']}: {resolved['description']} ---")

        result = run_scenario_trials(
            args.hashcat_bin,
            resolved,
            args.trials,
            verbose=not args.quiet,
        )
        all_results[resolved["name"]] = result

    # Save results.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.output) / device_id / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    output_data = {
        "system_info": system_info,
        "scenario_set": args.scenarios,
        "trials": args.trials,
        "scenarios": {},
    }

    for name, result in all_results.items():
        # Strip raw speed arrays for the summary file.
        scenario_summary: dict = {
            "name": result["name"],
            "description": result["description"],
            "attack_mode": result["attack_mode"],
            "optimal_vec": result["optimal_vec"],
            "vec_results": {},
        }
        for vec_str, vec_entry in result["vec_results"].items():
            scenario_summary["vec_results"][vec_str] = {
                k: v
                for k, v in vec_entry.items()
                if k != "speeds"
            }
        output_data["scenarios"][name] = scenario_summary

    out_path = out_dir / "real_world_benchmarks.json"
    with open(out_path, "w") as f:
        json.dump(output_data, f, indent=2)
        f.write("\n")

    if not args.quiet:
        print(f"\nResults saved to: {out_path}")

    # Print summary table.
    if not args.quiet:
        print()
        print("=" * 100)
        print("REAL-WORLD BENCHMARK RESULTS")
        print("=" * 100)

        header = (
            f"{'Scenario':<35} "
            f"{'Vec1 MH/s':>12} {'Vec2 MH/s':>12} {'Vec4 MH/s':>12} "
            f"{'Best':>5}"
        )
        print(f"\n{header}")
        print("-" * 100)

        for name, result in all_results.items():
            v1 = result["vec_results"].get("1", {})
            v2 = result["vec_results"].get("2", {})
            v4 = result["vec_results"].get("4", {})

            v1_str = f"{v1['mean']:>9.1f}" if v1 else "      N/A"
            v2_str = f"{v2['mean']:>9.1f}" if v2 else "      N/A"
            v4_str = f"{v4['mean']:>9.1f}" if v4 else "      N/A"

            best = result.get("optimal_vec")
            best_str = f"Vec:{best}" if best else "N/A"

            print(
                f"{name:<35} "
                f"{v1_str:>12} {v2_str:>12} {v4_str:>12} "
                f"{best_str:>5}"
            )

        print()


if __name__ == "__main__":
    main()
