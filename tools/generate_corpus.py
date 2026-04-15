#!/usr/bin/env python3
"""Three-tier NTLM corpus generation for correctness testing.

Tiers:
  - deterministic: ~10,000 structured edge case vectors
  - random: ~10,000 seeded random printable ASCII vectors
  - adversarial: ~1,000 vectors targeting bitselect edge cases
"""

import argparse
import os
import random
import string
import struct

from ntlm_reference import ntlm_hash


# ---------------------------------------------------------------------------
# Tier 1 — Deterministic corpus
# ---------------------------------------------------------------------------

def generate_deterministic_corpus() -> list[tuple[str, str]]:
    """Generate ~10,000 structured edge case password/hash pairs.

    Includes: empty password, single printable ASCII, boundary lengths,
    hashcat self-test vector, common passwords, single-bit differences,
    and numeric strings 0-9999.  No duplicate passwords.
    """
    seen: set[str] = set()
    corpus: list[tuple[str, str]] = []

    def _add(pw: str) -> None:
        if pw not in seen:
            seen.add(pw)
            corpus.append((pw, ntlm_hash(pw)))

    # Empty password
    _add("")

    # Single printable ASCII characters
    for c in string.printable:
        _add(c)

    # Boundary lengths using repeated character
    for length in (0, 1, 2, 13, 14, 27):
        _add("A" * length)
        _add("z" * length)
        _add("9" * length)

    # hashcat self-test vector
    _add("hashcat")

    # Common passwords
    common = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "passw0rd", "shadow", "123123", "654321",
    ]
    for pw in common:
        _add(pw)

    # Single-bit differences from a fixed base password.
    # Only keep ASCII results — multi-byte Unicode has encoding ambiguity
    # between our reference (proper UTF-16LE) and hashcat's optimized kernel
    # (byte-by-byte UTF-16LE expansion).
    base = "hashcat"
    base_bytes = base.encode("utf-16-le")
    for byte_idx in range(len(base_bytes)):
        for bit in range(8):
            mutated = bytearray(base_bytes)
            mutated[byte_idx] ^= (1 << bit)
            try:
                pw = mutated.decode("utf-16-le")
                if pw.isascii():
                    _add(pw)
            except (UnicodeDecodeError, ValueError):
                pass

    # Numbers 0-9999
    for n in range(10000):
        _add(str(n))

    return corpus


# ---------------------------------------------------------------------------
# Tier 2 — Random corpus
# ---------------------------------------------------------------------------

def generate_random_corpus(count: int = 10000, seed: int = 42) -> list[tuple[str, str]]:
    """Generate *count* random printable ASCII password/hash pairs.

    Passwords have lengths 1-27.  Same seed always produces the same output.
    """
    rng = random.Random(seed)
    charset = string.printable.strip()  # exclude trailing whitespace chars
    corpus: list[tuple[str, str]] = []
    for _ in range(count):
        length = rng.randint(1, 27)
        pw = "".join(rng.choices(charset, k=length))
        corpus.append((pw, ntlm_hash(pw)))
    return corpus


# ---------------------------------------------------------------------------
# Tier 3 — Adversarial corpus (targeting bitselect patterns)
# ---------------------------------------------------------------------------

_INTERESTING_BYTES = {0x00, 0xFF, 0x55, 0xAA, 0x0F, 0xF0}


def _is_adversarial(hash_hex: str) -> bool:
    """Check if a hash contains patterns that stress bitselect operations."""
    raw = bytes.fromhex(hash_hex)

    # Check for interesting byte values
    for b in raw:
        if b in _INTERESTING_BYTES:
            return True

    # Check for adjacent 32-bit words being equal
    words = struct.unpack("<4I", raw)
    for i in range(len(words) - 1):
        if words[i] == words[i + 1]:
            return True

    # Check for XOR edge cases between adjacent words
    for i in range(len(words) - 1):
        xor = words[i] ^ words[i + 1]
        if xor == 0 or xor == 0xFFFFFFFF:
            return True

    return False


def generate_adversarial_corpus(count: int = 1000) -> list[tuple[str, str]]:
    """Generate up to *count* passwords whose hashes stress bitselect ops.

    Searches random passwords for adversarial hash patterns; falls back to
    plain random if not enough adversarial candidates are found.
    """
    rng = random.Random(0xADCE)
    charset = string.printable.strip()
    adversarial: list[tuple[str, str]] = []
    fallback: list[tuple[str, str]] = []
    attempts = 0
    max_attempts = count * 200  # generous search budget

    while len(adversarial) < count and attempts < max_attempts:
        attempts += 1
        length = rng.randint(1, 27)
        pw = "".join(rng.choices(charset, k=length))
        h = ntlm_hash(pw)
        if _is_adversarial(h):
            adversarial.append((pw, h))
        elif len(fallback) < count:
            fallback.append((pw, h))

    # Fill remaining slots from fallback if needed
    if len(adversarial) < count:
        need = count - len(adversarial)
        adversarial.extend(fallback[:need])

    return adversarial[:count]


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------

def write_hashfile(
    corpus: list[tuple[str, str]],
    path: str,
    include_passwords: bool = False,
) -> None:
    """Write corpus hashes to *path*, one per line.

    If *include_passwords* is True, also write a companion .passwords file.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        for _, h in corpus:
            f.write(h + "\n")
    if include_passwords:
        pw_path = path + ".passwords"
        with open(pw_path, "w") as f:
            for pw, _ in corpus:
                f.write(pw + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate NTLM test corpus for hashcat correctness testing."
    )
    parser.add_argument(
        "--output-dir",
        default="corpus",
        help="Directory for output files (default: corpus)",
    )
    parser.add_argument(
        "--tier",
        choices=["deterministic", "random", "adversarial", "all"],
        default="all",
        help="Which corpus tier to generate (default: all)",
    )
    args = parser.parse_args()

    tiers = (
        ["deterministic", "random", "adversarial"]
        if args.tier == "all"
        else [args.tier]
    )

    for tier in tiers:
        print(f"Generating {tier} corpus...")
        if tier == "deterministic":
            corpus = generate_deterministic_corpus()
        elif tier == "random":
            corpus = generate_random_corpus()
        else:
            corpus = generate_adversarial_corpus()

        path = os.path.join(args.output_dir, f"ntlm_{tier}.hashes")
        write_hashfile(corpus, path, include_passwords=True)
        print(f"  {len(corpus)} vectors -> {path}")

    print("Done.")


if __name__ == "__main__":
    main()
