"""Statistical analysis utilities for benchmark data.

Provides Welch's t-test, summary statistics with confidence intervals,
and a coefficient-of-variation quality gate.  Uses only Python stdlib.
"""

import math
import statistics


def welch_t_test(a: list, b: list) -> tuple:
    """Welch's t-test for unequal variances.

    Returns (t_statistic, degrees_of_freedom, significant_at_p001).
    Returns (0.0, 0.0, False) if either sample has fewer than 2 values.

    Significance criterion: abs(t) > 2.66 AND df > 20 (approx p < 0.01).
    """
    if len(a) < 2 or len(b) < 2:
        return (0.0, 0.0, False)

    n_a, n_b = len(a), len(b)
    mean_a, mean_b = statistics.mean(a), statistics.mean(b)
    var_a, var_b = statistics.variance(a), statistics.variance(b)

    # Handle zero variance.
    if var_a == 0.0 and var_b == 0.0:
        if mean_a == mean_b:
            return (0.0, float(n_a + n_b - 2), False)
        else:
            return (float("inf"), float(n_a + n_b - 2), True)

    se_sq = var_a / n_a + var_b / n_b

    if se_sq == 0.0:
        # Shouldn't reach here given the checks above, but guard anyway.
        return (0.0, float(n_a + n_b - 2), False)

    t_stat = (mean_a - mean_b) / math.sqrt(se_sq)

    # Welch-Satterthwaite degrees of freedom.
    num = se_sq ** 2
    denom = ((var_a / n_a) ** 2) / (n_a - 1) + ((var_b / n_b) ** 2) / (n_b - 1)

    if denom == 0.0:
        df = float(n_a + n_b - 2)
    else:
        df = num / denom

    significant = abs(t_stat) > 2.66 and df > 20

    return (float(t_stat), float(df), bool(significant))


def compute_summary(data: list) -> dict:
    """Compute summary statistics for a list of numeric values.

    Returns dict with keys: mean, stdev, min, max, n, ci_95 (as [lower, upper]).
    Raises ValueError if data is empty.
    """
    if not data:
        raise ValueError("data must not be empty")

    n = len(data)
    mean = statistics.mean(data)

    if n == 1:
        stdev = 0.0
    else:
        stdev = statistics.stdev(data)

    # 95% CI: use t_crit = 2.045 for n <= 30, 1.96 for n > 30.
    t_crit = 2.045 if n <= 30 else 1.96

    if n >= 2:
        margin = t_crit * stdev / math.sqrt(n)
    else:
        margin = 0.0

    return {
        "mean": mean,
        "stdev": stdev,
        "min": min(data),
        "max": max(data),
        "n": n,
        "ci_95": [mean - margin, mean + margin],
    }


def check_quality(data: list, min_trials: int = 30, max_cv: float = 0.05) -> tuple:
    """Quality gate based on trial count and coefficient of variation.

    Returns (passed: bool, reason: str).  If passed, reason is empty string.
    """
    if len(data) < min_trials:
        return (False, f"Too few trials: {len(data)} < {min_trials}")

    mean = statistics.mean(data)

    if mean == 0.0:
        return (False, "Mean is zero; coefficient of variation is undefined")

    if len(data) >= 2:
        stdev = statistics.stdev(data)
    else:
        stdev = 0.0

    cv = stdev / abs(mean)

    if cv > max_cv:
        return (False, f"Coefficient of variation too high: {cv:.4f} > {max_cv}")

    return (True, "")
