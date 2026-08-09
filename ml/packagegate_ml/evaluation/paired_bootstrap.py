"""Paired bootstrap comparison of two score vectors on the same rows."""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score


def _safe_pr_auc(y: np.ndarray, p: np.ndarray) -> float | None:
    if len(y) < 2 or len(set(y.tolist())) < 2:
        return None
    return float(average_precision_score(y, p))


def paired_bootstrap_pr_auc(
    y_true: np.ndarray,
    scores_a: np.ndarray,
    scores_b: np.ndarray,
    *,
    n_boot: int = 10_000,
    seed: int = 0,
) -> dict[str, Any]:
    """
    Resample the SAME row indices for both models each replicate.

    Returns delta = PR-AUC(A) - PR-AUC(B). Invalid one-class draws are skipped.
    """
    y = np.asarray(y_true, dtype=np.int64)
    a = np.asarray(scores_a, dtype=np.float64)
    b = np.asarray(scores_b, dtype=np.float64)
    if not (len(y) == len(a) == len(b)):
        raise ValueError("y/scores length mismatch")
    if len(y) == 0:
        raise ValueError("empty inputs")

    point_a = _safe_pr_auc(y, a)
    point_b = _safe_pr_auc(y, b)
    point_delta = (
        None if point_a is None or point_b is None else float(point_a - point_b)
    )

    rng = np.random.default_rng(seed)
    deltas: list[float] = []
    a_scores: list[float] = []
    b_scores: list[float] = []
    attempts = 0
    max_attempts = n_boot * 20
    while len(deltas) < n_boot and attempts < max_attempts:
        attempts += 1
        idx = rng.integers(0, len(y), len(y))
        yy = y[idx]
        if len(set(yy.tolist())) < 2:
            continue
        pa = _safe_pr_auc(yy, a[idx])
        pb = _safe_pr_auc(yy, b[idx])
        if pa is None or pb is None:
            continue
        a_scores.append(pa)
        b_scores.append(pb)
        deltas.append(pa - pb)

    arr = np.array(deltas, dtype=np.float64) if deltas else np.array([])
    out: dict[str, Any] = {
        "n": int(len(y)),
        "nBootRequested": n_boot,
        "nBootValid": int(len(deltas)),
        "nAttempts": attempts,
        "pointPrAucA": point_a,
        "pointPrAucB": point_b,
        "pointDelta": point_delta,
        "meanDelta": float(arr.mean()) if len(arr) else None,
        "medianDelta": float(np.median(arr)) if len(arr) else None,
        "ci95Low": float(np.percentile(arr, 2.5)) if len(arr) else None,
        "ci95High": float(np.percentile(arr, 97.5)) if len(arr) else None,
        "fracDeltaPositive": float((arr > 0).mean()) if len(arr) else None,
        "meanPrAucA": float(np.mean(a_scores)) if a_scores else None,
        "meanPrAucB": float(np.mean(b_scores)) if b_scores else None,
    }
    return out


def paired_bootstrap_metric(
    y_true: np.ndarray,
    scores_a: np.ndarray,
    scores_b: np.ndarray,
    *,
    metric: str,
    threshold_a: float,
    threshold_b: float,
    n_boot: int = 10_000,
    seed: int = 0,
) -> dict[str, Any]:
    """
    Paired bootstrap for thresholded metrics.

    Thresholds must be pre-selected (validation); not re-fit on bootstrap draws.
    metric in {f1, recall, brier}.
    """
    y = np.asarray(y_true, dtype=np.int64)
    a = np.asarray(scores_a, dtype=np.float64)
    b = np.asarray(scores_b, dtype=np.float64)

    def compute(yy, sa, sb) -> tuple[float | None, float | None, float | None]:
        if metric == "brier":
            return (
                float(brier_score_loss(yy, sa)),
                float(brier_score_loss(yy, sb)),
                float(brier_score_loss(yy, sa) - brier_score_loss(yy, sb)),
            )
        if len(set(yy.tolist())) < 2 and metric != "brier":
            return None, None, None
        pred_a = (sa >= threshold_a).astype(np.int64)
        pred_b = (sb >= threshold_b).astype(np.int64)
        if metric == "f1":
            va = float(f1_score(yy, pred_a, zero_division=0))
            vb = float(f1_score(yy, pred_b, zero_division=0))
        elif metric == "recall":
            # positive-class recall
            pos = yy == 1
            if not pos.any():
                return None, None, None
            va = float(((pred_a == 1) & pos).sum() / pos.sum())
            vb = float(((pred_b == 1) & pos).sum() / pos.sum())
        else:
            raise ValueError(metric)
        return va, vb, va - vb

    point = compute(y, a, b)
    rng = np.random.default_rng(seed)
    deltas: list[float] = []
    attempts = 0
    max_attempts = n_boot * 20
    while len(deltas) < n_boot and attempts < max_attempts:
        attempts += 1
        idx = rng.integers(0, len(y), len(y))
        _, _, d = compute(y[idx], a[idx], b[idx])
        if d is None:
            continue
        deltas.append(d)
    arr = np.array(deltas) if deltas else np.array([])
    return {
        "metric": metric,
        "thresholdA": threshold_a,
        "thresholdB": threshold_b,
        "pointA": point[0],
        "pointB": point[1],
        "pointDelta": point[2],
        "nBootValid": int(len(deltas)),
        "meanDelta": float(arr.mean()) if len(arr) else None,
        "medianDelta": float(np.median(arr)) if len(arr) else None,
        "ci95Low": float(np.percentile(arr, 2.5)) if len(arr) else None,
        "ci95High": float(np.percentile(arr, 97.5)) if len(arr) else None,
        "fracDeltaPositive": float((arr > 0).mean()) if len(arr) else None,
        # For Brier, lower is better — also report frac where A better
        "fracABetter": (
            float((arr < 0).mean())
            if metric == "brier" and len(arr)
            else float((arr > 0).mean())
            if len(arr)
            else None
        ),
    }
