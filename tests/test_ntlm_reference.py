"""Tests for tools/ntlm_reference.py — NTLM hash reference implementation."""

import os
import sys

# Allow importing from tools/ without package structure.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import unittest
from ntlm_reference import ntlm_hash


class TestNtlmKnownVectors(unittest.TestCase):
    """Known NTLM test vectors must match expected hashes."""

    def test_hashcat_password(self):
        self.assertEqual(ntlm_hash("hashcat"), "b4b9b02e6f09a9bd760f388b67351e2b")

    def test_empty_password(self):
        self.assertEqual(ntlm_hash(""), "31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_password_literal(self):
        self.assertEqual(ntlm_hash("password"), "8846f7eaee8fb117ad06bdd830b7586c")

    def test_single_char_a(self):
        self.assertEqual(ntlm_hash("a"), "186cb09181e2c2ecaac768c47c729904")


class TestNtlmProperties(unittest.TestCase):
    """General properties of the NTLM hash function."""

    def test_max_length_27_produces_valid_hex(self):
        result = ntlm_hash("a" * 27)
        self.assertEqual(len(result), 32)
        # Must be valid lowercase hex
        int(result, 16)

    def test_unicode_characters(self):
        result = ntlm_hash("\u00e9\u00fc\u00f1")
        self.assertEqual(len(result), 32)
        int(result, 16)

    def test_deterministic_output(self):
        self.assertEqual(ntlm_hash("test123"), ntlm_hash("test123"))

    def test_lowercase_hex(self):
        result = ntlm_hash("anything")
        self.assertEqual(result, result.lower())


if __name__ == "__main__":
    unittest.main()
