#!/usr/bin/env python3
"""Correctness test harness for hashcat NTLM cracking.

Validates that hashcat produces correct NTLM output by running it
against the reference corpus and comparing recovered passwords to
the expected set.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


# ── Hashcat runner ──────────────────────────────────────────────────────────


def run_hashcat_crack(
    hashcat_bin: str,
    hash_file: str,
    wordlist: str,
    attack_mode: int = 0,
    timeout: int = 300,
) -> set[str]:
    """Run hashcat in cracking mode and return the set of recovered passwords.

    Uses a temporary directory for the potfile and outfile.  For combinator
    attack (mode 1) the wordlist is passed twice.  Returns an empty set on
    timeout.
    """
    with tempfile.TemporaryDirectory(prefix="hc_correctness_") as tmpdir:
        potfile = os.path.join(tmpdir, "potfile")
        outfile = os.path.join(tmpdir, "outfile")

        cmd = [
            hashcat_bin,
            "-m", "1000",
            "-a", str(attack_mode),
            "--potfile-path", potfile,
            "--outfile", outfile,
            "--outfile-format", "2",
            "--quiet",
            "--self-test-disable",
            hash_file,
        ]

        # Combinator attack uses wordlist as both left and right dict
        if attack_mode == 1:
            cmd.extend([wordlist, wordlist])
        else:
            cmd.append(wordlist)

        try:
            subprocess.run(
                cmd,
                timeout=timeout,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return set()

        # Parse recovered passwords from outfile
        recovered: set[str] = set()
        if os.path.isfile(outfile):
            with open(outfile, "r") as f:
                for line in f:
                    pw = line.rstrip("\n")
                    recovered.add(pw)

        return recovered


# ── Per-corpus correctness test ─────────────────────────────────────────────


def run_correctness_test(
    hashcat_bin: str,
    corpus_dir: str,
    attack_mode: int = 0,
    verbose: bool = True,
) -> dict:
    """Run correctness tests against all corpus files in *corpus_dir*.

    For each ``.hashes`` file found, locates the companion ``.hashes.passwords``
    file, runs hashcat, and compares recovered passwords against expected.

    Returns a result dict with keys: attack_mode, corpus_dir, total_tested,
    passed, failed, failures (capped at 100 entries), timestamp.
    """
    total_tested = 0
    passed = 0
    failed = 0
    failures: list[dict] = []

    # Find all .hashes files in corpus_dir
    if not os.path.isdir(corpus_dir):
        if verbose:
            print(f"  WARNING: corpus directory not found: {corpus_dir}")
        return {
            "attack_mode": attack_mode,
            "corpus_dir": corpus_dir,
            "total_tested": 0,
            "passed": 0,
            "failed": 0,
            "failures": [],
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    for entry in sorted(os.listdir(corpus_dir)):
        if not entry.endswith(".hashes"):
            continue

        hash_file = os.path.join(corpus_dir, entry)
        pw_file = hash_file + ".passwords"

        if not os.path.isfile(pw_file):
            if verbose:
                print(f"  WARNING: no companion .passwords file for {hash_file}")
            continue

        # Load expected passwords and hashes (same line order)
        with open(pw_file, "r") as f:
            expected_passwords = [line.rstrip("\n") for line in f]
        with open(hash_file, "r") as f:
            expected_hashes = [line.rstrip("\n") for line in f]

        corpus_name = os.path.splitext(entry)[0]

        if verbose:
            print(f"  Testing corpus: {corpus_name} ({len(expected_passwords)} vectors)")

        recovered = run_hashcat_crack(
            hashcat_bin, hash_file, pw_file, attack_mode=attack_mode,
        )

        # Compare recovered set against expected
        total_tested += len(expected_passwords)

        for i, pw in enumerate(expected_passwords):
            if pw in recovered:
                passed += 1
            else:
                failed += 1
                if len(failures) < 100:
                    failures.append({
                        "password": pw,
                        "expected_hash": expected_hashes[i] if i < len(expected_hashes) else "unknown",
                        "corpus": corpus_name,
                    })

    return {
        "attack_mode": attack_mode,
        "corpus_dir": corpus_dir,
        "total_tested": total_tested,
        "passed": passed,
        "failed": failed,
        "failures": failures,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate hashcat NTLM output against the reference corpus."
    )
    parser.add_argument(
        "--hashcat-bin",
        default="./hashcat",
        help="Path to hashcat binary (default: ./hashcat)",
    )
    parser.add_argument(
        "--corpus-dir",
        default="corpus",
        help="Root directory for corpus files (default: corpus)",
    )
    parser.add_argument(
        "--attack-mode",
        type=int,
        choices=[0, 1, 3],
        default=0,
        help="Hashcat attack mode: 0=straight, 1=combinator, 3=brute-force (default: 0)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save JSON results to FILE",
    )
    parser.add_argument(
        "--tier",
        choices=["deterministic", "random", "adversarial", "all"],
        default="all",
        help="Which corpus tier to test (default: all)",
    )
    args = parser.parse_args()

    # ── Self-test gate ──────────────────────────────────────────────────────
    # hashcat runs self-test automatically on startup (no --self-test flag).
    # Verify by running a quick benchmark — if self-test fails, hashcat exits
    # with a non-zero code before producing benchmark output.
    print("Running hashcat self-test (mode 1000 benchmark)...")
    try:
        result = subprocess.run(
            [args.hashcat_bin, "-b", "-m", "1000", "--quiet"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            print(f"ERROR: hashcat self-test failed (exit {result.returncode})",
                  file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            sys.exit(1)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"ERROR: hashcat self-test failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print("Self-test passed.")

    # ── Per-tier tests ──────────────────────────────────────────────────────
    tiers = (
        ["deterministic", "random", "adversarial"]
        if args.tier == "all"
        else [args.tier]
    )

    all_results: list[dict] = []
    total_passed = 0
    total_failed = 0

    for tier in tiers:
        print(f"\n{'='*60}")
        print(f"Tier: {tier}  (attack mode {args.attack_mode})")
        print(f"{'='*60}")

        # Each tier has a single .hashes file: ntlm_{tier}.hashes
        hash_file = os.path.join(args.corpus_dir, f"ntlm_{tier}.hashes")
        pw_file = hash_file + ".passwords"

        if not os.path.isfile(hash_file):
            print(f"  WARNING: corpus file not found: {hash_file}")
            all_results.append({
                "tier": tier,
                "attack_mode": args.attack_mode,
                "total_tested": 0,
                "passed": 0,
                "failed": 0,
                "failures": [],
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            continue

        if not os.path.isfile(pw_file):
            print(f"  WARNING: no companion .passwords file: {pw_file}")
            all_results.append({
                "tier": tier,
                "attack_mode": args.attack_mode,
                "total_tested": 0,
                "passed": 0,
                "failed": 0,
                "failures": [],
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            continue

        # Load expected passwords and hashes
        with open(pw_file, "r") as f:
            expected_passwords = [line.rstrip("\n") for line in f]
        with open(hash_file, "r") as f:
            expected_hashes = [line.rstrip("\n") for line in f]

        corpus_name = f"ntlm_{tier}"
        print(f"  Testing corpus: {corpus_name} ({len(expected_passwords)} vectors)")

        recovered = run_hashcat_crack(
            hashcat_bin=args.hashcat_bin,
            hash_file=hash_file,
            wordlist=pw_file,
            attack_mode=args.attack_mode,
        )

        tier_passed = 0
        tier_failed = 0
        failures: list[dict] = []

        for i, pw in enumerate(expected_passwords):
            if pw in recovered:
                tier_passed += 1
            else:
                tier_failed += 1
                if len(failures) < 100:
                    failures.append({
                        "password": pw,
                        "expected_hash": expected_hashes[i] if i < len(expected_hashes) else "unknown",
                        "corpus": corpus_name,
                    })

        total_passed += tier_passed
        total_failed += tier_failed

        tier_result = {
            "tier": tier,
            "attack_mode": args.attack_mode,
            "total_tested": len(expected_passwords),
            "passed": tier_passed,
            "failed": tier_failed,
            "failures": failures,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        all_results.append(tier_result)

        print(f"  Passed: {tier_passed}/{len(expected_passwords)}")
        if tier_failed > 0:
            print(f"  FAILED: {tier_failed}")

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"SUMMARY: {total_passed} passed, {total_failed} failed")
    print(f"{'='*60}")

    if total_failed > 0:
        print("\nFailing vectors:")
        for result in all_results:
            for fail in result["failures"]:
                print(f"  [{fail['corpus']}] pw={fail['password']!r}  hash={fail['expected_hash']}")

    # ── JSON output ─────────────────────────────────────────────────────────
    if args.output:
        output_data = {
            "total_passed": total_passed,
            "total_failed": total_failed,
            "tiers": all_results,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
            f.write("\n")
        print(f"\nResults saved to {args.output}")

    if total_failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
