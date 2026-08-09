"""Run paired bootstrap on frozen Exp1 V4 matched predictions."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from packagegate_ml.evaluation.paired_bootstrap import (
    paired_bootstrap_metric,
    paired_bootstrap_pr_auc,
)

REPO = Path(__file__).resolve().parents[3]
EXP = REPO / "ml" / "experiments" / "pg-neural-exp1"
PRED = EXP / "v4_matched_test_predictions.jsonl"
FREEZE = EXP / "freeze.json"


def main() -> None:
    rows = [
        json.loads(line)
        for line in PRED.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    y = np.array([r["y"] for r in rows], dtype=np.int64)
    embed = np.array([r["embed_mean_proba"] for r in rows], dtype=np.float64)
    structured = np.array([r["structured_proba"] for r in rows], dtype=np.float64)
    mil = np.array(
        [r["mil_code_proba"] if r["mil_code_proba"] is not None else np.nan for r in rows],
        dtype=np.float64,
    )

    pr = paired_bootstrap_pr_auc(y, embed, structured, n_boot=10_000, seed=0)
    thr_e = (freeze["selectedPackageModel"].get("recallAt5pctFpr") or {}).get(
        "threshold"
    )
    thr_s = (freeze["structuredBaseline"].get("recallAt5pctFpr") or {}).get("threshold")
    # Fall back to stored decision thresholds if operating points missing
    if thr_e is None:
        thr_e = freeze["selectedPackageModel"]["threshold"]
    if thr_s is None:
        thr_s = freeze["structuredBaseline"]["threshold"]
    # Prefer validation ~5% FPR operating points for recall/F1 uncertainty
    pkg = json.loads(
        (REPO / "ml" / "runs" / "20260809T193015Z-pg-package-mil-v1" / "metadata.json").read_text(
            encoding="utf-8"
        )
    )
    thr_e_op = (
        (pkg["full"]["EMBED_MEAN_ONLY"].get("recallAt5pctFpr") or {}).get("threshold")
        or thr_e
    )
    thr_s_op = (
        (pkg["full"]["STRUCTURED_BEHAVIOUR_LOGISTIC"].get("recallAt5pctFpr") or {}).get(
            "threshold"
        )
        or thr_s
    )
    f1 = paired_bootstrap_metric(
        y,
        embed,
        structured,
        metric="f1",
        threshold_a=float(thr_e_op),
        threshold_b=float(thr_s_op),
        n_boot=10_000,
        seed=1,
    )
    recall = paired_bootstrap_metric(
        y,
        embed,
        structured,
        metric="recall",
        threshold_a=float(thr_e_op),
        threshold_b=float(thr_s_op),
        n_boot=10_000,
        seed=2,
    )
    brier = paired_bootstrap_metric(
        y,
        embed,
        structured,
        metric="brier",
        threshold_a=float(thr_e_op),
        threshold_b=float(thr_s_op),
        n_boot=10_000,
        seed=3,
    )

    # Also compare vs MIL if available
    mil_pr = None
    if not np.isnan(mil).any():
        mil_pr = paired_bootstrap_pr_auc(y, embed, mil, n_boot=10_000, seed=4)

    report = {
        "experimentId": "pg-neural-exp1",
        "n": len(rows),
        "embedVsStructuredPrAuc": pr,
        "embedVsStructuredF1": f1,
        "embedVsStructuredRecallAtFrozenThreshold": recall,
        "embedVsStructuredBrier": brier,
        "embedVsMilCodePrAuc": mil_pr,
        "interpretationNote": (
            "CI containing 0 ⇒ statistically inconclusive at 95% bootstrap level; "
            "do not claim significance without support."
        ),
    }
    out = EXP / "paired_bootstrap.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["embedVsStructuredPrAuc"], indent=2))


if __name__ == "__main__":
    main()
