#!/usr/bin/env python3
"""Generate NTLM target hashes from a wordlist for real-world benchmarks.

Produces hash files and filtered wordlists in corpus/real_world/:
  - single.hash           — NTLM of "password" (single-target scenario)
  - hashes_1k.txt         — 1,000 unique NTLM hashes
  - hashes_100k.txt       — 100,000 unique NTLM hashes
  - rockyou-top1k.txt     — first 1,000 unique passwords
  - rockyou-top10k.txt    — first 10,000 unique passwords
  - rockyou-ascii-only.txt — passwords filtered to printable ASCII only
"""

import argparse
import os
import random
import string

from ntlm_reference import ntlm_hash


def load_wordlist(path: str, max_lines: int | None = None) -> list[str]:
    """Load passwords from a wordlist file.

    Reads with latin-1 encoding (rockyou.txt is not valid UTF-8).
    Strips trailing newlines from each line.

    Parameters
    ----------
    path : str
        Path to the wordlist file.
    max_lines : int or None
        Maximum number of lines to read.  None means read all.

    Returns
    -------
    list[str]
        List of password strings.
    """
    passwords: list[str] = []
    with open(path, encoding="latin-1") as f:
        for line in f:
            passwords.append(line.rstrip("\n\r"))
            if max_lines is not None and len(passwords) >= max_lines:
                break
    return passwords


def generate_hash_targets(
    passwords: list[str], count: int
) -> list[tuple[str, str]]:
    """Generate NTLM hashes for a random subset of passwords.

    Deduplicates by hash value so that each hash in the returned list
    is unique.  Uses a fixed seed for reproducibility.

    Parameters
    ----------
    passwords : list[str]
        Pool of passwords to sample from.
    count : int
        Number of unique hash targets to produce.

    Returns
    -------
    list[tuple[str, str]]
        List of (password, hash_hex) pairs, deduplicated by hash.
    """
    rng = random.Random(42)
    seen_hashes: set[str] = set()
    targets: list[tuple[str, str]] = []

    # Shuffle a copy so we get a reproducible random subset.
    pool = list(passwords)
    rng.shuffle(pool)

    for pw in pool:
        if len(targets) >= count:
            break
        h = ntlm_hash(pw)
        if h not in seen_hashes:
            seen_hashes.add(h)
            targets.append((pw, h))

    return targets


def _write_hashes(targets: list[tuple[str, str]], path: str) -> None:
    """Write hash values (one per line) to *path*."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        for _, h in targets:
            f.write(h + "\n")


def _write_passwords(passwords: list[str], path: str) -> None:
    """Write passwords (one per line) to *path*."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        for pw in passwords:
            f.write(pw + "\n")


def _is_printable_ascii(s: str) -> bool:
    """Return True if every character in *s* is printable ASCII (0x20-0x7E)."""
    return all(0x20 <= ord(c) <= 0x7E for c in s)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate NTLM hash targets and filtered wordlists from rockyou.txt."
    )
    parser.add_argument(
        "--wordlist",
        required=True,
        help="Path to rockyou.txt (or similar wordlist)",
    )
    parser.add_argument(
        "--output-dir",
        default="corpus/real_world",
        help="Output directory (default: corpus/real_world)",
    )
    args = parser.parse_args()

    print(f"Loading wordlist: {args.wordlist}")
    passwords = load_wordlist(args.wordlist)
    print(f"  Loaded {len(passwords):,} passwords")

    out = args.output_dir
    os.makedirs(out, exist_ok=True)

    # 1. Single hash target: NTLM of "password"
    single_hash = ntlm_hash("password")
    single_path = os.path.join(out, "single.hash")
    with open(single_path, "w") as f:
        f.write(single_hash + "\n")
    print(f"  single.hash -> {single_path}")

    # 2. 1K hash targets
    targets_1k = generate_hash_targets(passwords, 1000)
    path_1k = os.path.join(out, "hashes_1k.txt")
    _write_hashes(targets_1k, path_1k)
    print(f"  hashes_1k.txt -> {len(targets_1k)} hashes")

    # 3. 100K hash targets
    targets_100k = generate_hash_targets(passwords, 100_000)
    path_100k = os.path.join(out, "hashes_100k.txt")
    _write_hashes(targets_100k, path_100k)
    print(f"  hashes_100k.txt -> {len(targets_100k)} hashes")

    # 4. rockyou-top1k.txt (first 1000 unique passwords)
    seen: set[str] = set()
    top1k: list[str] = []
    for pw in passwords:
        if pw not in seen:
            seen.add(pw)
            top1k.append(pw)
            if len(top1k) >= 1000:
                break
    _write_passwords(top1k, os.path.join(out, "rockyou-top1k.txt"))
    print(f"  rockyou-top1k.txt -> {len(top1k)} passwords")

    # 5. rockyou-top10k.txt (first 10000 unique passwords)
    seen.clear()
    top10k: list[str] = []
    for pw in passwords:
        if pw not in seen:
            seen.add(pw)
            top10k.append(pw)
            if len(top10k) >= 10_000:
                break
    _write_passwords(top10k, os.path.join(out, "rockyou-top10k.txt"))
    print(f"  rockyou-top10k.txt -> {len(top10k)} passwords")

    # 6. rockyou-ascii-only.txt (filtered to printable ASCII)
    ascii_only: list[str] = []
    for pw in passwords:
        if pw and _is_printable_ascii(pw):
            ascii_only.append(pw)
    _write_passwords(ascii_only, os.path.join(out, "rockyou-ascii-only.txt"))
    print(f"  rockyou-ascii-only.txt -> {len(ascii_only)} passwords")

    print("Done.")


if __name__ == "__main__":
    main()
