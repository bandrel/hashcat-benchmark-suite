"""Tests for tools/generate_corpus.py — Three-tier corpus generation."""

import os
import sys
import tempfile

# Allow importing from tools/ without package structure.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import unittest
from generate_corpus import (
    generate_adversarial_corpus,
    generate_deterministic_corpus,
    generate_random_corpus,
    write_hashfile,
)


class TestDeterministicCorpus(unittest.TestCase):
    """Deterministic corpus must include structured edge cases."""

    def setUp(self):
        self.corpus = generate_deterministic_corpus()

    def test_returns_list_of_tuples(self):
        self.assertIsInstance(self.corpus, list)
        for item in self.corpus[:10]:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)

    def test_includes_empty_password(self):
        passwords = [p for p, h in self.corpus]
        self.assertIn("", passwords)

    def test_includes_boundary_lengths(self):
        passwords = [p for p, h in self.corpus]
        lengths = {len(p) for p in passwords}
        for boundary in (0, 1, 2, 13, 14, 27):
            self.assertIn(boundary, lengths, f"Missing boundary length {boundary}")

    def test_approximate_size(self):
        # Should be roughly 10k vectors
        self.assertGreater(len(self.corpus), 8000)
        self.assertLess(len(self.corpus), 15000)

    def test_no_duplicate_passwords(self):
        passwords = [p for p, h in self.corpus]
        self.assertEqual(len(passwords), len(set(passwords)))

    def test_all_hashes_valid_hex(self):
        for pw, h in self.corpus[:100]:
            self.assertEqual(len(h), 32, f"Bad hash length for password {pw!r}")
            int(h, 16)


class TestRandomCorpus(unittest.TestCase):
    """Random corpus must be seeded and reproducible."""

    def test_seeded_reproducibility(self):
        c1 = generate_random_corpus(count=100, seed=42)
        c2 = generate_random_corpus(count=100, seed=42)
        self.assertEqual(c1, c2)

    def test_different_seeds_differ(self):
        c1 = generate_random_corpus(count=100, seed=42)
        c2 = generate_random_corpus(count=100, seed=99)
        self.assertNotEqual(c1, c2)

    def test_correct_size(self):
        corpus = generate_random_corpus(count=500, seed=42)
        self.assertEqual(len(corpus), 500)

    def test_length_range(self):
        corpus = generate_random_corpus(count=1000, seed=42)
        for pw, h in corpus:
            self.assertGreaterEqual(len(pw), 1)
            self.assertLessEqual(len(pw), 27)


class TestAdversarialCorpus(unittest.TestCase):
    """Adversarial corpus targets bitselect edge cases."""

    def test_returns_nonempty(self):
        corpus = generate_adversarial_corpus(count=50)
        self.assertGreater(len(corpus), 0)

    def test_all_valid_hashes(self):
        corpus = generate_adversarial_corpus(count=50)
        for pw, h in corpus:
            self.assertEqual(len(h), 32)
            int(h, 16)


class TestWriteHashfile(unittest.TestCase):
    """write_hashfile must produce correct format."""

    def test_writes_hash_file(self):
        corpus = [("abc", "aabbccdd" * 4), ("def", "11223344" * 4)]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.hashes")
            write_hashfile(corpus, path)
            with open(path) as f:
                lines = f.read().strip().split("\n")
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0], "aabbccdd" * 4)

    def test_writes_password_companion(self):
        corpus = [("abc", "aabbccdd" * 4), ("def", "11223344" * 4)]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.hashes")
            write_hashfile(corpus, path, include_passwords=True)
            pw_path = path + ".passwords"
            self.assertTrue(os.path.exists(pw_path))
            with open(pw_path) as f:
                lines = f.read().strip().split("\n")
            self.assertEqual(lines[0], "abc")
            self.assertEqual(lines[1], "def")


if __name__ == "__main__":
    unittest.main()
