"""Tests for tools/detect_system.py — PII sanitization and system detection helpers."""

import os
import sys

# Allow importing from tools/ without package structure.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import unittest
from detect_system import (
    ALLOWED_FIELDS,
    generate_device_id,
    normalize_timestamp,
    sanitize_system_info,
)


# ---------------------------------------------------------------------------
# sanitize_system_info
# ---------------------------------------------------------------------------
class TestSanitizeSystemInfo(unittest.TestCase):
    """Allowlist-based filtering must block PII and pass approved fields."""

    def test_allows_gpu_model(self):
        raw = {"gpu_model": "Apple M3 Max"}
        self.assertEqual(sanitize_system_info(raw), {"gpu_model": "Apple M3 Max"})

    def test_strips_hostname(self):
        raw = {"gpu_model": "Apple M3 Max", "hostname": "justins-mbp.local"}
        result = sanitize_system_info(raw)
        self.assertNotIn("hostname", result)
        self.assertIn("gpu_model", result)

    def test_strips_username(self):
        raw = {"username": "jbollinger", "gpu_model": "M3"}
        self.assertNotIn("username", sanitize_system_info(raw))

    def test_strips_serial_number(self):
        raw = {"serial_number": "C02XG1KDLVCF", "gpu_model": "M3"}
        self.assertNotIn("serial_number", sanitize_system_info(raw))

    def test_strips_uuid(self):
        raw = {"system_uuid": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"}
        self.assertEqual(sanitize_system_info(raw), {})

    def test_strips_mac_address(self):
        raw = {"mac_address": "00:1A:2B:3C:4D:5E"}
        self.assertEqual(sanitize_system_info(raw), {})

    def test_strips_ip_address_field(self):
        raw = {"ip_address": "192.168.1.42"}
        self.assertEqual(sanitize_system_info(raw), {})

    def test_strips_file_paths(self):
        """Full paths containing /Users/ or /home/ are reduced to basename."""
        raw = {"hashcat_binary": "/Users/jbollinger/projects/hashcat/hashcat"}
        result = sanitize_system_info(raw)
        self.assertEqual(result["hashcat_binary"], "hashcat")

    def test_strips_linux_home_paths(self):
        raw = {"hashcat_binary": "/home/user/hashcat/hashcat"}
        result = sanitize_system_info(raw)
        self.assertEqual(result["hashcat_binary"], "hashcat")

    def test_strips_pci_bus_id(self):
        raw = {"pci_bus_id": "0000:01:00.0"}
        self.assertEqual(sanitize_system_info(raw), {})

    def test_strips_gpu_uuid(self):
        raw = {"gpu_uuid": "GPU-12345678-abcd-efgh-ijkl-123456789012"}
        self.assertEqual(sanitize_system_info(raw), {})

    def test_strips_os_build(self):
        raw = {"os_build": "24F74"}
        self.assertEqual(sanitize_system_info(raw), {})

    def test_allows_all_allowed_fields(self):
        raw = {field: f"value-{field}" for field in ALLOWED_FIELDS}
        result = sanitize_system_info(raw)
        self.assertEqual(set(result.keys()), ALLOWED_FIELDS)

    def test_return_dropped_fields(self):
        raw = {"gpu_model": "M3", "hostname": "evil", "serial_number": "SN123"}
        sanitized, dropped = sanitize_system_info(raw, return_dropped=True)
        self.assertIn("gpu_model", sanitized)
        self.assertIn("hostname", dropped)
        self.assertIn("serial_number", dropped)

    def test_sanitizes_paths_in_values(self):
        """Even allowed fields have path values scrubbed."""
        raw = {"hashcat_binary": "/Users/alice/bin/hashcat"}
        result = sanitize_system_info(raw)
        self.assertEqual(result["hashcat_binary"], "hashcat")


# ---------------------------------------------------------------------------
# normalize_timestamp
# ---------------------------------------------------------------------------
class TestNormalizeTimestamp(unittest.TestCase):
    """Timestamps must be normalized to UTC with Z suffix."""

    def test_timezone_aware_conversion(self):
        result = normalize_timestamp("2026-04-11T14:30:00-07:00")
        self.assertEqual(result, "2026-04-11T21:30:00Z")

    def test_already_utc_passthrough(self):
        result = normalize_timestamp("2026-04-11T21:30:00Z")
        self.assertEqual(result, "2026-04-11T21:30:00Z")

    def test_naive_treated_as_utc(self):
        result = normalize_timestamp("2026-04-11T21:30:00")
        self.assertEqual(result, "2026-04-11T21:30:00Z")

    def test_positive_offset(self):
        result = normalize_timestamp("2026-04-12T03:30:00+06:00")
        self.assertEqual(result, "2026-04-11T21:30:00Z")


# ---------------------------------------------------------------------------
# generate_device_id
# ---------------------------------------------------------------------------
class TestGenerateDeviceId(unittest.TestCase):
    """Device IDs must be lowercase, hyphenated, deterministic."""

    def test_apple_silicon(self):
        info = {"gpu_model": "Apple M3 Max"}
        self.assertEqual(generate_device_id(info), "apple-m3-max")

    def test_nvidia(self):
        info = {"gpu_model": "NVIDIA GeForce RTX 3080 Ti"}
        self.assertEqual(generate_device_id(info), "nvidia-rtx-3080-ti")

    def test_amd(self):
        info = {"gpu_model": "AMD Radeon RX 7900 XTX"}
        self.assertEqual(generate_device_id(info), "amd-rx-7900-xtx")

    def test_special_characters(self):
        info = {"gpu_model": "NVIDIA (TM) RTX™ 4090 -- Special!"}
        result = generate_device_id(info)
        # Should be lowercase, only alphanumeric and hyphens, no leading/trailing hyphens
        self.assertRegex(result, r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
        self.assertNotIn("--", result)


if __name__ == "__main__":
    unittest.main()
