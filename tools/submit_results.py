#!/usr/bin/env python3
"""Package benchmark results and open a GitHub pull request.

Finds the latest results directory, validates quality, shows system_info
for PII review, generates a PR summary with benchmark tables, creates a
git branch, and opens a PR via ``gh`` CLI.

Usage:
    python3 tools/submit_results.py --results-dir results
    python3 tools/submit_results.py --results-dir results --dry-run
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

from validate_results import validate_results_dir


# ── Find latest results ──────────────────────────────────────────────────────


def find_latest_results(results_dir: str) -> str | None:
    """Find the most recent results directory.

    Results live at ``results/<device-id>/<timestamp>/``.  Iterates device
    directories, finds the most recent timestamp subdirectory (lexicographic
    sort of ISO-style timestamps), and returns the full path.

    Returns ``None`` if no valid results directory exists.
    """
    if not os.path.isdir(results_dir):
        return None

    latest_path: str | None = None
    latest_timestamp: str = ""

    for device_id in sorted(os.listdir(results_dir)):
        device_dir = os.path.join(results_dir, device_id)
        if not os.path.isdir(device_dir):
            continue

        for timestamp in sorted(os.listdir(device_dir)):
            ts_dir = os.path.join(device_dir, timestamp)
            if not os.path.isdir(ts_dir):
                continue

            # Timestamps are ISO-style (e.g. 20240101T120000Z) so
            # lexicographic comparison gives chronological order.
            if timestamp > latest_timestamp:
                latest_timestamp = timestamp
                latest_path = ts_dir

    return latest_path


# ── PR summary generation ────────────────────────────────────────────────────


def _fmt_speed(value: float) -> str:
    """Format a speed value in MH/s with one decimal place."""
    return f"{value:.1f}"


def generate_pr_summary(results_dir: str) -> str:
    """Generate a Markdown PR summary from benchmark results.

    Reads system_info.json, benchmark_summary.json, correctness files,
    and optionally real_world_benchmarks.json to produce a formatted
    Markdown string suitable for a pull request body.
    """
    sections: list[str] = []

    # ── System info ──────────────────────────────────────────────────────
    sys_info_path = os.path.join(results_dir, "system_info.json")
    sys_info: dict = {}
    if os.path.isfile(sys_info_path):
        with open(sys_info_path) as f:
            sys_info = json.load(f)

    device = sys_info.get("gpu_model", "Unknown device")
    backend = sys_info.get("backend", "Unknown")
    os_name = sys_info.get("os_name", "Unknown")
    os_version = sys_info.get("os_version", "")
    hashcat_version = sys_info.get("hashcat_version", "Unknown")
    device_id = sys_info.get("device_id", "unknown")
    timestamp = sys_info.get("timestamp", "unknown")

    sections.append("## System Information\n")
    sections.append(f"- **Device:** {device}")
    sections.append(f"- **Backend:** {backend}")
    sections.append(f"- **OS:** {os_name} {os_version}".rstrip())
    sections.append(f"- **Hashcat:** {hashcat_version}")
    sections.append(f"- **Device ID:** {device_id}")
    sections.append(f"- **Timestamp:** {timestamp}")

    # ── Benchmark summary table ──────────────────────────────────────────
    bench_path = os.path.join(results_dir, "benchmark_summary.json")
    tiers_completed: list[str] = []

    if os.path.isfile(bench_path):
        with open(bench_path) as f:
            bench_data = json.load(f)

        modes = bench_data.get("modes", {})
        if modes:
            tiers_completed.append("synthetic benchmarks")
            sections.append("\n## Synthetic Benchmark Results\n")
            sections.append(
                "| Mode | Name | Vec:1 (MH/s) | Vec:2 (MH/s) "
                "| Vec:4 (MH/s) | Best |"
            )
            sections.append(
                "|------|------|---------------|---------------|"
                "---------------|------|"
            )

            for mode_str in sorted(modes.keys(), key=lambda x: int(x)):
                mode_data = modes[mode_str]
                name = mode_data.get("name", f"Mode {mode_str}")
                vec_results = mode_data.get("vec_results", {})
                optimal = mode_data.get("optimal_vec")

                cells: list[str] = [mode_str, name]

                for vec in ["1", "2", "4"]:
                    entry = vec_results.get(vec, {})
                    mean = entry.get("mean")
                    stdev = entry.get("stdev")
                    if mean is not None and stdev is not None:
                        cells.append(f"{_fmt_speed(mean)} +/- {_fmt_speed(stdev)}")
                    elif mean is not None:
                        cells.append(_fmt_speed(mean))
                    else:
                        cells.append("N/A")

                best_str = f"Vec:{optimal}" if optimal else "N/A"
                cells.append(best_str)

                sections.append("| " + " | ".join(cells) + " |")

    # ── Correctness results ──────────────────────────────────────────────
    correctness_dir = os.path.join(results_dir, "correctness")
    correctness_files: list[str] = []

    if os.path.isdir(correctness_dir):
        correctness_files = [
            os.path.join(correctness_dir, f)
            for f in sorted(os.listdir(correctness_dir))
            if f.endswith(".json")
        ]
    else:
        correctness_files = [
            os.path.join(results_dir, f)
            for f in sorted(os.listdir(results_dir))
            if f.startswith("correctness") and f.endswith(".json")
        ]

    if correctness_files:
        tiers_completed.append("correctness tests")
        total_passed = 0
        total_failed = 0
        total_tested = 0

        for cpath in correctness_files:
            with open(cpath) as f:
                cdata = json.load(f)
            total_passed += cdata.get("passed", 0)
            total_failed += cdata.get("failed", 0)
            total_tested += cdata.get("total_tested", 0)

        status = "PASS" if total_failed == 0 else "FAIL"
        sections.append("\n## Correctness Results\n")
        sections.append(f"- **Status:** {status}")
        sections.append(f"- **Total tested:** {total_tested}")
        sections.append(f"- **Passed:** {total_passed}")
        sections.append(f"- **Failed:** {total_failed}")
        sections.append(f"- **Files:** {len(correctness_files)}")

    # ── Real-world benchmarks ────────────────────────────────────────────
    rw_path = os.path.join(results_dir, "real_world_benchmarks.json")
    if os.path.isfile(rw_path):
        tiers_completed.append("real-world benchmarks")
        with open(rw_path) as f:
            rw_data = json.load(f)

        scenarios = rw_data.get("scenarios", {})
        if scenarios:
            sections.append("\n## Real-World Benchmark Results\n")
            sections.append(
                "| Scenario | Vec:1 (MH/s) | Vec:2 (MH/s) "
                "| Vec:4 (MH/s) | Best |"
            )
            sections.append(
                "|----------|---------------|---------------|"
                "---------------|------|"
            )

            for scenario_name, scenario_data in scenarios.items():
                vec_results = scenario_data.get("vec_results", {})
                optimal = scenario_data.get("optimal_vec")
                cells: list[str] = [scenario_name]

                for vec in ["1", "2", "4"]:
                    entry = vec_results.get(vec, {})
                    mean = entry.get("mean")
                    stdev = entry.get("stdev")
                    if mean is not None and stdev is not None:
                        cells.append(f"{_fmt_speed(mean)} +/- {_fmt_speed(stdev)}")
                    elif mean is not None:
                        cells.append(_fmt_speed(mean))
                    else:
                        cells.append("N/A")

                best_str = f"Vec:{optimal}" if optimal else "N/A"
                cells.append(best_str)

                sections.append("| " + " | ".join(cells) + " |")

    # ── Tiers completed ──────────────────────────────────────────────────
    if tiers_completed:
        sections.append("\n## Tiers Completed\n")
        for tier in tiers_completed:
            sections.append(f"- {tier}")

    return "\n".join(sections) + "\n"


# ── Git / PR helpers ─────────────────────────────────────────────────────────


def _run_git(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a git command and return the result."""
    cmd = ["git"] + args
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _run_gh(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a gh CLI command and return the result."""
    cmd = ["gh"] + args
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _resolve_push_remote() -> str:
    """Determine which git remote to push to.

    If the authenticated ``gh`` user owns the origin repo, pushes directly
    to ``origin``.  Otherwise, ensures a fork exists (via ``gh repo fork``)
    and returns the remote name pointing to the fork.
    """
    # Who owns origin?
    result = _run_gh(
        ["repo", "view", "--json", "owner", "-q", ".owner.login"], check=False
    )
    repo_owner = result.stdout.strip() if result.returncode == 0 else ""

    # Who is the authenticated user?
    result = _run_gh(["api", "user", "-q", ".login"], check=False)
    gh_user = result.stdout.strip() if result.returncode == 0 else ""

    if not repo_owner or not gh_user:
        print("WARNING: Could not determine repo owner or GitHub user.")
        print("  Falling back to 'origin'. Push may fail if you lack write access.")
        return "origin"

    if repo_owner == gh_user:
        return "origin"

    # External contributor — ensure a fork exists.
    print(f"You ({gh_user}) don't own the upstream repo ({repo_owner}).")
    print("Ensuring your fork exists...")

    # Check if a remote already points to the user's fork.
    result = _run_git(["remote", "-v"], check=False)
    remotes = result.stdout if result.returncode == 0 else ""
    for line in remotes.splitlines():
        if gh_user.lower() in line.lower() and "(push)" in line:
            remote_name = line.split()[0]
            print(f"  Found existing fork remote: {remote_name}")
            return remote_name

    # No fork remote found — create one via gh.
    result = _run_gh(
        ["repo", "fork", "--remote", "--remote-name", "fork", "--clone=false"],
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        # gh prints to stderr even on success ("already exists" etc.)
        if "already exists" in stderr.lower():
            print("  Fork already exists.")
        else:
            print(f"  gh repo fork output: {stderr}")

    # Verify the fork remote is present.
    result = _run_git(["remote", "get-url", "fork"], check=False)
    if result.returncode == 0:
        print(f"  Fork remote URL: {result.stdout.strip()}")
        return "fork"

    # Last resort: try adding manually.
    result = _run_gh(
        ["repo", "view", f"{gh_user}/hashcat-benchmark-suite", "--json", "sshUrl", "-q", ".sshUrl"],
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        fork_url = result.stdout.strip()
        _run_git(["remote", "add", "fork", fork_url], check=False)
        print(f"  Added fork remote: {fork_url}")
        return "fork"

    print("WARNING: Could not set up fork remote. Falling back to 'origin'.")
    return "origin"


# ── Manual submission (no gh CLI) ────────────────────────────────────────────


def _manual_submit(
    results_dir: str, device_id: str, timestamp_dir: str, summary: str
) -> None:
    """Write a Markdown file with PR contents and manual submission instructions."""
    pr_title = f"results: {device_id} ({timestamp_dir})"
    md_path = os.path.join(results_dir, "SUBMIT_PR.md")

    content = f"""\
# Benchmark Results — Manual Submission

The `gh` CLI was not found, so results could not be submitted automatically.
Follow the steps below to create a pull request manually.

## PR Title

```
{pr_title}
```

## PR Body

Paste everything between the `---` lines into the PR description:

---

{summary}
---

## Steps

1. Fork this repo on GitHub:
   https://github.com/bandrel/hashcat-benchmark-suite

2. Create a branch and commit your results:
   ```bash
   git checkout -b results/{device_id}/{timestamp_dir}
   git add {results_dir}
   git commit -m "data: add benchmark results for {device_id}"
   git remote add fork https://github.com/<YOUR_USERNAME>/hashcat-benchmark-suite.git
   git push -u fork results/{device_id}/{timestamp_dir}
   ```

3. Open a pull request:
   - Go to https://github.com/bandrel/hashcat-benchmark-suite/pulls
   - Click "New pull request" → "compare across forks"
   - Select your fork and branch
   - Use the PR title and body above

Alternatively, install the GitHub CLI (https://cli.github.com/) and re-run:
```bash
./bench submit
```
"""

    with open(md_path, "w") as f:
        f.write(content)

    print(f"\ngh CLI not found — wrote manual submission instructions to:")
    print(f"  {md_path}")
    print(f"\nFollow the steps in that file to create your PR.")


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Package benchmark results and open a GitHub pull request."
    )
    parser.add_argument(
        "--results-dir",
        default="results",
        help="Top-level results directory (default: results)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be submitted without creating a PR",
    )
    args = parser.parse_args()

    # (a) Find latest results directory.
    latest = find_latest_results(args.results_dir)
    if latest is None:
        print("ERROR: No results found in", args.results_dir)
        sys.exit(1)

    print(f"Latest results: {latest}")

    # (b) Validate results — warn but allow override.
    errors = validate_results_dir(latest)
    if errors:
        print(f"\nValidation warnings ({len(errors)}):")
        for err in errors:
            print(f"  - {err}")
        print()
        try:
            answer = input("Continue despite validation warnings? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "y":
            print("Aborted.")
            sys.exit(1)
    else:
        print("Validation passed.")

    # (c) Show system_info.json for PII review.
    sys_info_path = os.path.join(latest, "system_info.json")
    if os.path.isfile(sys_info_path):
        with open(sys_info_path) as f:
            sys_info = json.load(f)
        print("\n--- system_info.json (review for PII) ---")
        print(json.dumps(sys_info, indent=2))
        print("---")
        print()
        try:
            answer = input(
                "Does this look correct and free of personal info? [y/N] "
            ).strip().lower()
        except EOFError:
            answer = ""
        if answer != "y":
            print("Aborted. Edit system_info.json and re-run.")
            sys.exit(1)
    else:
        print("WARNING: system_info.json not found in results directory.")

    # Extract device_id and timestamp from directory path.
    # Path is: results/<device-id>/<timestamp>/
    parts = os.path.normpath(latest).split(os.sep)
    if len(parts) >= 2:
        timestamp_dir = parts[-1]
        device_id = parts[-2]
    else:
        device_id = "unknown"
        timestamp_dir = "unknown"

    # (d) Generate PR summary.
    summary = generate_pr_summary(latest)

    # (e) Dry run — print summary and exit.
    if args.dry_run:
        print("\n=== DRY RUN — PR Summary ===\n")
        print(summary)
        print(f"Branch: results/{device_id}/{timestamp_dir}")
        print(f"Results dir: {latest}")
        print("\nNo changes made.")
        sys.exit(0)

    # (f) Check for gh CLI — fall back to manual submission if missing.
    if not shutil.which("gh"):
        _manual_submit(latest, device_id, timestamp_dir, summary)
        sys.exit(0)

    # (g) Determine push remote (origin for owners, fork for contributors).
    push_remote = _resolve_push_remote()

    # (h) Create git branch.
    branch_name = f"results/{device_id}/{timestamp_dir}"
    print(f"\nCreating branch: {branch_name}")
    result = _run_git(["checkout", "-b", branch_name], check=False)
    if result.returncode != 0:
        print(f"ERROR: Failed to create branch: {result.stderr.strip()}")
        sys.exit(1)

    # (i) git add the results directory.
    print(f"Adding results: {latest}")
    result = _run_git(["add", latest], check=False)
    if result.returncode != 0:
        print(f"ERROR: git add failed: {result.stderr.strip()}")
        sys.exit(1)

    # (j) git commit.
    device_name = sys_info.get("gpu_model", device_id) if os.path.isfile(sys_info_path) else device_id
    commit_msg = f"data: add benchmark results for {device_name}\n\nDevice: {device_id}\nTimestamp: {timestamp_dir}"
    print("Committing...")
    result = _run_git(["commit", "-m", commit_msg], check=False)
    if result.returncode != 0:
        print(f"ERROR: git commit failed: {result.stderr.strip()}")
        sys.exit(1)

    # (k) git push to the resolved remote.
    print(f"Pushing branch to {push_remote}: {branch_name}")
    result = _run_git(["push", "-u", push_remote, branch_name], check=False)
    if result.returncode != 0:
        print(f"ERROR: git push failed: {result.stderr.strip()}")
        sys.exit(1)

    # (l) gh pr create — targets upstream automatically for forks.
    pr_title = f"results: {device_id} ({timestamp_dir})"
    print("Creating pull request...")
    result = _run_gh(
        [
            "pr",
            "create",
            "--title",
            pr_title,
            "--body",
            summary,
        ],
        check=False,
    )
    if result.returncode != 0:
        print(f"ERROR: gh pr create failed: {result.stderr.strip()}")
        sys.exit(1)

    pr_url = result.stdout.strip()

    # (m) git checkout main.
    _run_git(["checkout", "main"], check=False)

    # (n) Done!
    print(f"\nDone! PR created: {pr_url}")


if __name__ == "__main__":
    main()
