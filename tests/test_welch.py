"""Tests for tools/stats.py — Welch's t-test, summary stats, and quality gate."""

import os
import sys

# Allow importing from tools/ without package structure.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import math
import unittest
from stats import check_quality, compute_summary, welch_t_test


# ---------------------------------------------------------------------------
# welch_t_test
# ---------------------------------------------------------------------------
class TestWelchTTest(unittest.TestCase):
    """Welch's t-test for unequal variances."""

    def test_identical_samples_not_significant(self):
        a = [100.0] * 30
        b = [100.0] * 30
        t_stat, df, sig = welch_t_test(a, b)
        self.assertFalse(sig)

    def test_clearly_different_samples_significant(self):
        a = [100.0 + i * 0.1 for i in range(30)]
        b = [200.0 + i * 0.1 for i in range(30)]
        t_stat, df, sig = welch_t_test(a, b)
        self.assertTrue(sig)
        self.assertGreater(abs(t_stat), 2.66)
        self.assertGreater(df, 20)

    def test_small_sample_not_significant(self):
        """Samples with < 2 values should return the sentinel tuple."""
        t_stat, df, sig = welch_t_test([1.0], [2.0])
        self.assertEqual(t_stat, 0.0)
        self.assertEqual(df, 0.0)
        self.assertFalse(sig)

    def test_correct_return_types(self):
        a = [100.0 + i for i in range(30)]
        b = [200.0 + i for i in range(30)]
        t_stat, df, sig = welch_t_test(a, b)
        self.assertIsInstance(t_stat, float)
        self.assertIsInstance(df, float)
        self.assertIsInstance(sig, bool)

    def test_zero_variance_equal_means(self):
        """Both samples constant and equal -> not significant."""
        a = [50.0] * 30
        b = [50.0] * 30
        t_stat, df, sig = welch_t_test(a, b)
        self.assertFalse(sig)

    def test_zero_variance_different_means(self):
        """Both samples constant but different -> significant (inf t-stat)."""
        a = [50.0] * 30
        b = [60.0] * 30
        t_stat, df, sig = welch_t_test(a, b)
        self.assertTrue(sig)
        self.assertTrue(math.isinf(t_stat))


# ---------------------------------------------------------------------------
# compute_summary
# ---------------------------------------------------------------------------
class TestComputeSummary(unittest.TestCase):
    """Summary statistics with 95% confidence intervals."""

    def test_basic_stats(self):
        data = [10.0, 20.0, 30.0, 40.0, 50.0]
        result = compute_summary(data)
        self.assertAlmostEqual(result["mean"], 30.0)
        self.assertEqual(result["min"], 10.0)
        self.assertEqual(result["max"], 50.0)
        self.assertEqual(result["n"], 5)
        self.assertGreater(result["stdev"], 0)
        self.assertIn("ci_95", result)
        self.assertEqual(len(result["ci_95"]), 2)

    def test_single_value(self):
        result = compute_summary([42.0])
        self.assertAlmostEqual(result["mean"], 42.0)
        self.assertEqual(result["stdev"], 0.0)
        self.assertEqual(result["n"], 1)

    def test_ci_contains_mean(self):
        data = [10.0, 20.0, 30.0, 40.0, 50.0]
        result = compute_summary(data)
        lower, upper = result["ci_95"]
        self.assertLessEqual(lower, result["mean"])
        self.assertGreaterEqual(upper, result["mean"])

    def test_empty_raises_value_error(self):
        with self.assertRaises(ValueError):
            compute_summary([])


# ---------------------------------------------------------------------------
# check_quality
# ---------------------------------------------------------------------------
class TestCheckQuality(unittest.TestCase):
    """Coefficient-of-variation quality gate."""

    def test_low_cv_passes(self):
        # Mean ~100, stdev ~1 -> CV ~0.01
        data = [100.0 + (i % 3 - 1) * 0.5 for i in range(30)]
        passed, reason = check_quality(data)
        self.assertTrue(passed)
        self.assertEqual(reason, "")

    def test_high_cv_fails(self):
        # Wide spread -> high CV
        data = [1.0, 100.0] * 15
        passed, reason = check_quality(data)
        self.assertFalse(passed)
        self.assertIn("coefficient of variation", reason.lower())

    def test_too_few_trials_fails(self):
        data = [100.0] * 10
        passed, reason = check_quality(data, min_trials=30)
        self.assertFalse(passed)
        self.assertIn("trial", reason.lower())


if __name__ == "__main__":
    unittest.main()
