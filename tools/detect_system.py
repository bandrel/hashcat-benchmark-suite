#!/usr/bin/env python3
"""Hardware detection and PII-sanitized system info collection.

Allowlist-based filtering ensures only approved fields are collected.
Strips hostnames, UUIDs, serial numbers, file paths, PCI bus IDs,
and other PII.  Timestamps normalized to UTC.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone

# ── Allowlist ────────────────────────────────────────────────────────────────

ALLOWED_FIELDS: frozenset = frozenset(
    {
        "gpu_model",
        "gpu_core_count",
        "gpu_memory_mb",
        "backend",
        "driver_version",
        "os_name",
        "os_version",
        "hashcat_version",
        "hashcat_commit",
        "hashcat_binary",
        "suite_commit",
        "hashcat_binary_sha256",
        "timestamp",
        "device_id",
    }
)

# ── Sanitization ─────────────────────────────────────────────────────────────

_PATH_RE = re.compile(r"(?:/Users/|/home/)")


def _sanitize_value(value: str) -> str:
    """Strip PII from a single string value (e.g. file paths)."""
    if isinstance(value, str) and _PATH_RE.search(value):
        return os.path.basename(value)
    return value


def sanitize_system_info(raw: dict, *, return_dropped: bool = False):
    """Return a copy of *raw* containing only ALLOWED_FIELDS keys.

    File-path values containing ``/Users/`` or ``/home/`` are reduced to
    their basename.

    Parameters
    ----------
    raw : dict
        Raw system info dictionary.
    return_dropped : bool
        If ``True`` return ``(sanitized, dropped_keys)`` instead of just
        the sanitized dict.
    """
    sanitized = {}
    dropped: list[str] = []

    for key, value in raw.items():
        if key in ALLOWED_FIELDS:
            sanitized[key] = _sanitize_value(value)
        else:
            dropped.append(key)

    if return_dropped:
        return sanitized, dropped
    return sanitized


# ── Timestamp helpers ────────────────────────────────────────────────────────


def normalize_timestamp(ts_str: str) -> str:
    """Normalize *ts_str* to an ISO-8601 UTC string ending with ``Z``.

    * Timezone-aware strings are converted to UTC.
    * Naive strings (no offset) are assumed UTC.
    * Already-UTC strings ending in ``Z`` pass through.
    """
    # Python's fromisoformat doesn't handle trailing Z in older versions,
    # but 3.11+ does.  Normalise it before parsing anyway for safety.
    cleaned = ts_str.replace("Z", "+00:00") if ts_str.endswith("Z") else ts_str

    dt = datetime.fromisoformat(cleaned)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)

    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Device ID ────────────────────────────────────────────────────────────────

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def generate_device_id(info: dict) -> str:
    """Derive a slug-style device ID from ``info['gpu_model']``.

    ``"Apple M3 Max"`` → ``"apple-m3-max"``
    """
    model = info.get("gpu_model", "unknown")
    slug = _NON_ALNUM.sub("-", model.lower())
    slug = slug.strip("-")
    return slug


# ── Detection helpers (macOS / Linux) ────────────────────────────────────────


def _run(cmd: list[str], **kwargs) -> str:
    """Run a subprocess and return stripped stdout, or empty string on error."""
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, **kwargs).decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def _detect_gpu_macos() -> dict:
    """Use system_profiler to detect GPU on macOS."""
    raw = _run(["system_profiler", "SPDisplaysDataType", "-json"])
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}

    displays = data.get("SPDisplaysDataType", [])
    if not displays:
        return {}
    gpu = displays[0]

    result: dict = {}
    # Model name
    name = gpu.get("sppci_model") or gpu.get("_name", "")
    if name:
        result["gpu_model"] = name
    # Core count (Apple-specific key)
    cores = gpu.get("sppci_cores")
    if cores:
        result["gpu_core_count"] = cores
    # VRAM
    vram_str = gpu.get("sppci_vram") or gpu.get("spdisplays_vram") or ""
    if vram_str:
        # e.g. "36864 MB" or "36 GB"
        match = re.search(r"(\d+)\s*(MB|GB)", vram_str, re.IGNORECASE)
        if match:
            val, unit = int(match.group(1)), match.group(2).upper()
            result["gpu_memory_mb"] = val if unit == "MB" else val * 1024

    return result


def _detect_gpu_linux() -> dict:
    """Use nvidia-smi to detect GPU on Linux."""
    name = _run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader,nounits"])
    if not name:
        return {}
    result: dict = {"gpu_model": name.splitlines()[0].strip()}

    mem = _run(["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"])
    if mem:
        try:
            result["gpu_memory_mb"] = int(mem.splitlines()[0].strip())
        except ValueError:
            pass

    driver = _run(["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader,nounits"])
    if driver:
        result["driver_version"] = driver.splitlines()[0].strip()

    return result


def _detect_backend(hashcat_bin: str) -> str:
    """Detect compute backend from ``hashcat -I``."""
    output = _run([hashcat_bin, "-I"])
    if not output:
        return "unknown"
    lower = output.lower()
    if "metal" in lower:
        return "Metal"
    if "cuda" in lower:
        return "CUDA"
    if "opencl" in lower:
        return "OpenCL"
    return "unknown"


def _hashcat_version(hashcat_bin: str) -> str:
    output = _run([hashcat_bin, "--version"])
    return output or "unknown"


def _sha256_file(path: str) -> str:
    """Return hex SHA-256 of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
    except OSError:
        return "unknown"
    return h.hexdigest()


def _suite_commit() -> str:
    """Return the short commit hash of this benchmark-suite repo."""
    return _run(["git", "rev-parse", "--short", "HEAD"]) or "unknown"


def _os_info() -> tuple[str, str]:
    """Return (os_name, os_version) — marketing version only."""
    os_name = platform.system()  # "Darwin", "Linux", "Windows"
    if os_name == "Darwin":
        os_name = "macOS"
        ver = platform.mac_ver()[0]  # e.g. "15.5"
    else:
        ver = platform.release()
    return os_name, ver


# ── Main detection entry point ───────────────────────────────────────────────


def detect_system(hashcat_bin: str = "./hashcat") -> dict:
    """Collect hardware/software info about the current system.

    The returned dictionary is already sanitized through the allowlist.
    """
    os_name, os_ver = _os_info()

    info: dict = {
        "os_name": os_name,
        "os_version": os_ver,
        "hashcat_version": _hashcat_version(hashcat_bin),
        "hashcat_binary": hashcat_bin,
        "hashcat_binary_sha256": _sha256_file(hashcat_bin),
        "hashcat_commit": _run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=os.path.dirname(os.path.abspath(hashcat_bin)) or ".",
        )
        or "unknown",
        "suite_commit": _suite_commit(),
        "backend": _detect_backend(hashcat_bin),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    # GPU detection — platform-specific
    if platform.system() == "Darwin":
        info.update(_detect_gpu_macos())
    else:
        info.update(_detect_gpu_linux())

    # Derive device_id
    info["device_id"] = generate_device_id(info)

    return sanitize_system_info(info)


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect system hardware and software for benchmark context."
    )
    parser.add_argument(
        "--hashcat-bin",
        default="./hashcat",
        help="Path to hashcat binary (default: ./hashcat)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save JSON output to FILE",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print JSON to stdout",
    )
    args = parser.parse_args()

    info = detect_system(args.hashcat_bin)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(info, f, indent=2)
            f.write("\n")
        print(f"Wrote {args.output}")

    elif args.as_json:
        print(json.dumps(info, indent=2))

    else:
        # Formatted table
        max_key = max(len(k) for k in info) if info else 0
        for key in sorted(info):
            print(f"  {key:<{max_key}}  {info[key]}")


if __name__ == "__main__":
    main()
