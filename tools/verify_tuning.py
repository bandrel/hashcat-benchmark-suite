#!/usr/bin/env python3
"""Verify hashcat tuning entries for Apple Silicon.

Two checks:
1. Alias verification — confirm that the device name reported by ``hashcat -I``
   has a matching entry in ``Alias.hctune`` that maps to ``ALIAS_Apple_M``.
2. Vec default verification — confirm that modes WITHOUT tuning entries still
   default to Vec:1, while tuned modes pick up Vec:2.

Usage:
    python3 tools/verify_tuning.py --hashcat-src ../hashcat

    # Just run alias check
    python3 tools/verify_tuning.py --hashcat-src ../hashcat --check alias

    # Just run vec-default check
    python3 tools/verify_tuning.py --hashcat-src ../hashcat --check vec-default
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


# ── Helpers ────────────────────────────────────────────────────────────────────


def _run(cmd: list[str], **kwargs) -> str:
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, **kwargs
        ).decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def get_device_name(hashcat_bin: str) -> str | None:
    """Extract the device Name from ``hashcat -I`` output."""
    output = _run([hashcat_bin, "-I"])
    if not output:
        return None
    for line in output.splitlines():
        match = re.match(r"\s*Name\.+:\s*(.*)", line)
        if match:
            return match.group(1).strip()
    return None


def parse_alias_entries(hctune_path: Path) -> dict[str, str]:
    """Parse Alias.hctune, returning {device_name: alias_name}."""
    entries: dict[str, str] = {}
    if not hctune_path.is_file():
        return entries
    for line in hctune_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            entries[parts[0]] = parts[1]
    return entries


def parse_tuned_modes(hctune_path: Path, alias: str) -> list[int]:
    """Parse Modules_default.hctune for modes tuned under *alias*."""
    modes: list[int] = []
    if not hctune_path.is_file():
        return modes
    for line in hctune_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0] == alias:
            try:
                modes.append(int(parts[2]))
            except ValueError:
                pass
    return modes


def get_benchmark_vec(hashcat_bin: str, mode: int) -> int | None:
    """Run ``hashcat -b -m <mode>`` and parse the Vec width from output.

    Returns the Vec width as an int, or None if parsing fails.
    """
    try:
        result = subprocess.run(
            [hashcat_bin, "-b", "-m", str(mode)],
            capture_output=True, text=True, timeout=120,
        )
        combined = result.stdout + result.stderr
        match = re.search(r"Vec:(\d+)", combined)
        if match:
            return int(match.group(1))
    except subprocess.TimeoutExpired:
        pass
    return None


# ── Checks ─────────────────────────────────────────────────────────────────────


def check_alias(hashcat_bin: str, hashcat_src: str) -> bool:
    """Verify the current device maps to ALIAS_Apple_M in Alias.hctune."""
    device_name = get_device_name(hashcat_bin)
    if device_name is None:
        print("FAIL: Could not detect device name from hashcat -I")
        return False

    print(f"Device name from hashcat -I: {device_name!r}")

    # hashcat normalizes spaces to underscores for hctune matching
    device_key = device_name.replace(" ", "_")
    print(f"Normalized device key:       {device_key!r}")

    alias_path = Path(hashcat_src) / "tunings" / "Alias.hctune"
    if not alias_path.is_file():
        print(f"FAIL: Alias.hctune not found at {alias_path}")
        return False

    entries = parse_alias_entries(alias_path)
    alias = entries.get(device_key)

    if alias is None:
        print(f"FAIL: No alias entry for {device_key!r} in Alias.hctune")
        # Show what Apple entries exist for debugging
        apple_entries = {k: v for k, v in entries.items() if "Apple" in k}
        if apple_entries:
            print(f"  Apple entries found: {list(apple_entries.keys())}")
        return False

    if alias != "ALIAS_Apple_M":
        print(f"FAIL: {device_key!r} maps to {alias!r}, expected ALIAS_Apple_M")
        return False

    print(f"PASS: {device_key!r} -> {alias}")
    return True


def check_vec_defaults(
    hashcat_bin: str,
    hashcat_src: str,
    unlisted_modes: list[int] | None = None,
) -> bool:
    """Verify unlisted modes default to Vec:1 and tuned modes use Vec:2."""
    tuned_path = Path(hashcat_src) / "tunings" / "Modules_default.hctune"
    tuned_modes = parse_tuned_modes(tuned_path, "ALIAS_Apple_M")

    if not tuned_modes:
        print("WARN: No ALIAS_Apple_M entries found in Modules_default.hctune")

    # Default unlisted modes to check — common fast modes not in the tuning list
    if unlisted_modes is None:
        unlisted_modes = [100, 1400, 1700]

    all_passed = True

    # Check unlisted modes default to Vec:1
    print(f"\n--- Unlisted modes (expect Vec:1) ---")
    for mode in unlisted_modes:
        if mode in tuned_modes:
            print(f"  SKIP: mode {mode} is tuned, not unlisted")
            continue
        vec = get_benchmark_vec(hashcat_bin, mode)
        if vec is None:
            print(f"  FAIL: mode {mode} — could not parse Vec width")
            all_passed = False
        elif vec != 1:
            print(f"  FAIL: mode {mode} — Vec:{vec}, expected Vec:1")
            all_passed = False
        else:
            print(f"  PASS: mode {mode} — Vec:{vec}")

    # Spot-check tuned modes use Vec:2
    print(f"\n--- Tuned modes (expect Vec:2) ---")
    spot_check = tuned_modes[:3] if len(tuned_modes) > 3 else tuned_modes
    for mode in spot_check:
        vec = get_benchmark_vec(hashcat_bin, mode)
        if vec is None:
            print(f"  FAIL: mode {mode} — could not parse Vec width")
            all_passed = False
        elif vec != 2:
            print(f"  FAIL: mode {mode} — Vec:{vec}, expected Vec:2")
            all_passed = False
        else:
            print(f"  PASS: mode {mode} — Vec:{vec}")

    return all_passed


# ── CLI ────────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify hashcat tuning entries for Apple Silicon"
    )
    parser.add_argument(
        "--hashcat-src",
        default="../hashcat",
        help="Path to hashcat source tree (default: ../hashcat)",
    )
    parser.add_argument(
        "--check",
        choices=["alias", "vec-default", "all"],
        default="all",
        help="Which check to run (default: all)",
    )
    parser.add_argument(
        "--unlisted-modes",
        type=str,
        default=None,
        help="Comma-separated modes expected to be Vec:1 (default: 100,1400,1700)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output results as JSON",
    )
    args = parser.parse_args()

    hashcat_bin = str(Path(args.hashcat_src) / "hashcat")
    unlisted = (
        [int(m.strip()) for m in args.unlisted_modes.split(",")]
        if args.unlisted_modes
        else None
    )

    results: dict = {}
    all_passed = True

    if args.check in ("alias", "all"):
        print("=== Alias Verification ===")
        passed = check_alias(hashcat_bin, args.hashcat_src)
        results["alias"] = "PASS" if passed else "FAIL"
        all_passed = all_passed and passed
        print()

    if args.check in ("vec-default", "all"):
        print("=== Vec Default Verification ===")
        passed = check_vec_defaults(hashcat_bin, args.hashcat_src, unlisted)
        results["vec_default"] = "PASS" if passed else "FAIL"
        all_passed = all_passed and passed
        print()

    if args.as_json:
        print(json.dumps(results, indent=2))

    if all_passed:
        print("All checks passed.")
    else:
        print("Some checks FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
