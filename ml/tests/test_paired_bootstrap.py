"""Unit tests for paired bootstrap."""

from __future__ import annotations

import numpy as np

from packagegate_ml.evaluation.paired_bootstrap import (
    paired_bootstrap_metric,
    paired_bootstrap_pr_auc,
)


def test_paired_bootstrap_uses_same_rows() -> None:
    y = np.array([0, 1, 0, 1, 0, 1, 0, 1] * 4)
    # Perfect ranking for A; chance-like for B
    scores_a = y.astype(float)
    scores_b = np.full(len(y), 0.5)
    out = paired_bootstrap_pr_auc(y, scores_a, scores_b, n_boot=500, seed=1)
    assert out["nBootValid"] == 500
    assert out["pointDelta"] is not None and out["pointDelta"] > 0.2
    assert out["ci95Low"] is not None and out["ci95High"] is not None
    assert out["ci95Low"] <= out["ci95High"]
    assert out["fracDeltaPositive"] > 0.9


def test_paired_bootstrap_skips_one_class_draws() -> None:
    y = np.array([1, 1, 1, 0])  # rare negative — some draws may be all-positive
    a = np.array([0.9, 0.8, 0.7, 0.2])
    b = np.array([0.6, 0.5, 0.4, 0.3])
    out = paired_bootstrap_pr_auc(y, a, b, n_boot=200, seed=2)
    assert out["nBootValid"] == 200
    assert out["nAttempts"] >= 200


def test_identical_scores_delta_near_zero() -> None:
    y = np.array([0, 1, 0, 1, 0, 1, 0, 1] * 5)
    s = np.linspace(0.1, 0.9, len(y))
    out = paired_bootstrap_pr_auc(y, s, s, n_boot=300, seed=3)
    assert abs(out["pointDelta"]) < 1e-12
    assert abs(out["meanDelta"]) < 1e-9
    assert out["fracDeltaPositive"] == 0.0


def test_threshold_metric_bootstrap() -> None:
    y = np.array([0, 1, 0, 1, 0, 1, 0, 1] * 5)
    a = y.astype(float) * 0.8 + 0.1
    b = y.astype(float) * 0.5 + 0.2
    out = paired_bootstrap_metric(
        y, a, b, metric="f1", threshold_a=0.5, threshold_b=0.5, n_boot=200, seed=4
    )
    assert out["nBootValid"] == 200
    assert out["pointDelta"] is not None
