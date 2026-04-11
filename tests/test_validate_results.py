"""Tests for tools/validate_results.py — result validation and quality gates."""

import os
import sys

# Allow importing from tools/ without package structure.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import unittest

from validate_results import (
    validate_benchmark_quality,
    validate_correctness,
    validate_system_info,
)


# ---------------------------------------------------------------------------
# Benchmark quality validation
# ---------------------------------------------------------------------------
class TestBenchmarkQuality(unittest.TestCase):
    """Benchmark results must meet trial count, CV, and sanity requirements."""

    def _make_valid_data(self, n_speeds=30):
        """Return benchmark data with reasonable speeds."""
        # Speeds around 1_000_000 with small variance
        speeds = [1_000_000 + i * 100 for i in range(n_speeds)]
        return {
            "results": {
                "1000": {
                    "name": "NTLM",
                    "vec_results": {
                        "1": {"speeds": speeds},
                    },
                }
            }
        }

    def test_valid_data_passes(self):
        data = self._make_valid_data(30)
        errors = validate_benchmark_quality(data, min_trials=30)
        self.assertEqual(errors, [])

    def test_too_few_trials_flagged(self):
        data = self._make_valid_data(10)
        errors = validate_benchmark_quality(data, min_trials=30)
        self.assertTrue(any("trial" in e.lower() or "speed" in e.lower() for e in errors))

    def test_zero_speeds_flagged(self):
        data = {
            "results": {
                "1000": {
                    "name": "NTLM",
                    "vec_results": {
                        "1": {"speeds": [0] * 30},
                    },
                }
            }
        }
        errors = validate_benchmark_quality(data, min_trials=30)
        self.assertTrue(any("zero" in e.lower() for e in errors))

    def test_nan_speeds_flagged(self):
        speeds = [1_000_000] * 29 + [float("nan")]
        data = {
            "results": {
                "1000": {
                    "name": "NTLM",
                    "vec_results": {
                        "1": {"speeds": speeds},
                    },
                }
            }
        }
        errors = validate_benchmark_quality(data, min_trials=30)
        self.assertTrue(any("nan" in e.lower() for e in errors))

    def test_high_cv_flagged(self):
        """A CV > 5% should be flagged."""
        # Create speeds with high variance: mean ~500k, stdev ~300k => CV ~60%
        speeds = [100_000] * 15 + [900_000] * 15
        data = {
            "results": {
                "1000": {
                    "name": "NTLM",
                    "vec_results": {
                        "1": {"speeds": speeds},
                    },
                }
            }
        }
        errors = validate_benchmark_quality(data, min_trials=30)
        self.assertTrue(any("cv" in e.lower() or "coefficient" in e.lower() for e in errors))

    def test_multiple_modes_validated(self):
        """All mode/vec combos are checked independently."""
        data = {
            "results": {
                "1000": {
                    "name": "NTLM",
                    "vec_results": {
                        "1": {"speeds": [1_000_000 + i for i in range(30)]},
                        "2": {"speeds": [0] * 30},
                    },
                },
            }
        }
        errors = validate_benchmark_quality(data, min_trials=30)
        # Vec 1 should pass, vec 2 should fail (all zeros)
        self.assertTrue(len(errors) >= 1)
        self.assertTrue(any("zero" in e.lower() for e in errors))


# ---------------------------------------------------------------------------
# Correctness validation
# ---------------------------------------------------------------------------
class TestCorrectnessValidation(unittest.TestCase):
    """Correctness results must have zero failures."""

    def test_all_passed_no_errors(self):
        data = {
            "attack_mode": 0,
            "total_tested": 100,
            "passed": 100,
            "failed": 0,
            "all_passed": True,
        }
        errors = validate_correctness(data)
        self.assertEqual(errors, [])

    def test_failures_flagged(self):
        data = {
            "attack_mode": 0,
            "total_tested": 100,
            "passed": 97,
            "failed": 3,
            "all_passed": False,
        }
        errors = validate_correctness(data)
        self.assertTrue(len(errors) >= 1)
        self.assertTrue(any("fail" in e.lower() for e in errors))

    def test_zero_tested_flagged(self):
        data = {
            "attack_mode": 0,
            "total_tested": 0,
            "passed": 0,
            "failed": 0,
            "all_passed": True,
        }
        errors = validate_correctness(data)
        self.assertTrue(len(errors) >= 1)


# ---------------------------------------------------------------------------
# System info validation
# ---------------------------------------------------------------------------
class TestSystemInfoValidation(unittest.TestCase):
    """System info must have required fields and no PII."""

    def _make_valid_system_info(self):
        return {
            "gpu_model": "Apple M3 Max",
            "os_name": "macOS",
            "os_version": "15.5",
            "hashcat_version": "v6.2.6",
            "hashcat_binary_sha256": "a" * 64,
            "device_id": "apple-m3-max",
            "timestamp": "2026-04-11T21:30:00Z",
        }

    def test_valid_system_info_passes(self):
        data = self._make_valid_system_info()
        errors = validate_system_info(data)
        self.assertEqual(errors, [])

    def test_missing_required_field_flagged(self):
        data = self._make_valid_system_info()
        del data["gpu_model"]
        errors = validate_system_info(data)
        self.assertTrue(any("gpu_model" in e for e in errors))

    def test_pii_hostname_flagged(self):
        data = self._make_valid_system_info()
        data["hostname"] = "justins-mbp.local"
        errors = validate_system_info(data)
        self.assertTrue(any("hostname" in e.lower() for e in errors))

    def test_pii_username_flagged(self):
        data = self._make_valid_system_info()
        data["username"] = "jbollinger"
        errors = validate_system_info(data)
        self.assertTrue(any("username" in e.lower() for e in errors))

    def test_file_path_in_value_flagged(self):
        data = self._make_valid_system_info()
        data["hashcat_binary"] = "/Users/jbollinger/hashcat/hashcat"
        errors = validate_system_info(data)
        self.assertTrue(any("path" in e.lower() or "/users/" in e.lower() for e in errors))

    def test_pii_serial_number_flagged(self):
        data = self._make_valid_system_info()
        data["serial_number"] = "C02XG1KDLVCF"
        errors = validate_system_info(data)
        self.assertTrue(any("serial_number" in e.lower() for e in errors))

    def test_pii_hardware_uuid_flagged(self):
        data = self._make_valid_system_info()
        data["hardware_uuid"] = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
        errors = validate_system_info(data)
        self.assertTrue(any("hardware_uuid" in e.lower() for e in errors))

    def test_pii_mac_address_flagged(self):
        data = self._make_valid_system_info()
        data["mac_address"] = "00:1A:2B:3C:4D:5E"
        errors = validate_system_info(data)
        self.assertTrue(any("mac_address" in e.lower() for e in errors))

    def test_pii_ip_address_flagged(self):
        data = self._make_valid_system_info()
        data["ip_address"] = "192.168.1.42"
        errors = validate_system_info(data)
        self.assertTrue(any("ip_address" in e.lower() for e in errors))

    def test_pii_gpu_uuid_flagged(self):
        data = self._make_valid_system_info()
        data["gpu_uuid"] = "GPU-12345678-abcd-efgh-ijkl-123456789012"
        errors = validate_system_info(data)
        self.assertTrue(any("gpu_uuid" in e.lower() for e in errors))

    def test_pii_pci_bus_id_flagged(self):
        data = self._make_valid_system_info()
        data["pci_bus_id"] = "0000:01:00.0"
        errors = validate_system_info(data)
        self.assertTrue(any("pci_bus_id" in e.lower() for e in errors))


if __name__ == "__main__":
    unittest.main()
