"""Experiment 0 — structured classical ML baseline (no transformers)."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from packagegate_ml.features.structured import align_feature_matrix

ROOT = Path(__file__).resolve().parents[2]
FEATURES = ROOT / "data" / "features" / "smoke_features.jsonl"
RUNS = ROOT / "runs"


def _git_commit() -> str | None:
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=ROOT.parent,
                text=True,
            ).strip()
        )
    except (OSError, subprocess.CalledProcessError):
        return None


def load_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def label_to_binary(label: str) -> int:
    return 1 if label in {"MALICIOUS", "SYNTHETIC_SUSPICIOUS"} else 0


def train_and_eval(rows: list[dict], seed: int = 42) -> dict:
    feature_rows = [r["features"] for r in rows]
    keys, x = align_feature_matrix(feature_rows)
    y = np.array([label_to_binary(r["label"]) for r in rows], dtype=np.int64)

    # Tiny smoke set: stratified-ish holdout by simple index split after shuffle.
    rng = np.random.default_rng(seed)
    idx = np.arange(len(rows))
    rng.shuffle(idx)
    if len(idx) < 4:
        raise SystemExit("Need at least 4 labelled rows for structured smoke training")
    split = max(1, len(idx) // 5)
    test_idx = idx[:split]
    train_idx = idx[split:]
    # Ensure both classes in train when possible.
    if len(set(y[train_idx].tolist())) < 2:
        train_idx, test_idx = idx[split:], idx[:split]
        if len(set(y[train_idx].tolist())) < 2:
            # Fall back: train on all, evaluate on all (document as smoke-only).
            train_idx = idx
            test_idx = idx

    x_train, y_train = x[train_idx], y[train_idx]
    x_test, y_test = x[test_idx], y[test_idx]

    models = {
        "logistic_regression": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=2000,
                        class_weight="balanced",
                        random_state=seed,
                    ),
                ),
            ]
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_depth=3,
            learning_rate=0.1,
            max_iter=100,
            random_state=seed,
        ),
    }

    results: dict = {"featureKeys": keys, "nTrain": int(len(train_idx)), "nTest": int(len(test_idx))}
    for name, model in models.items():
        model.fit(x_train, y_train)
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(x_test)[:, 1]
        else:
            proba = model.decision_function(x_test)
            proba = 1 / (1 + np.exp(-proba))
        pred = (proba >= 0.5).astype(int)
        metrics = {
            "precision": float(
                precision_recall_fscore_support(
                    y_test, pred, average="binary", zero_division=0
                )[0]
            ),
            "recall": float(
                precision_recall_fscore_support(
                    y_test, pred, average="binary", zero_division=0
                )[1]
            ),
            "f1": float(f1_score(y_test, pred, zero_division=0)),
        }
        if len(set(y_test.tolist())) > 1:
            metrics["pr_auc"] = float(average_precision_score(y_test, proba))
            metrics["roc_auc"] = float(roc_auc_score(y_test, proba))
            metrics["brier"] = float(brier_score_loss(y_test, proba))
        else:
            metrics["pr_auc"] = None
            metrics["roc_auc"] = None
            metrics["brier"] = None
            metrics["note"] = "single-class test fold — metrics limited (smoke)"

        # Validation calibration wrapper (smoke: calibrate on train).
        try:
            calib = CalibratedClassifierCV(model, method="sigmoid", cv=2)
            calib.fit(x_train, y_train)
            cprob = calib.predict_proba(x_test)[:, 1]
            metrics["brier_calibrated"] = (
                float(brier_score_loss(y_test, cprob))
                if len(set(y_test.tolist())) > 1
                else None
            )
        except Exception as exc:  # noqa: BLE001
            metrics["calibration_error"] = str(exc)

        results[name] = metrics

    results["warning"] = (
        "Smoke metrics on tiny synthetic fixture exports are NOT statistically meaningful."
    )
    return results


def main() -> None:
    if not FEATURES.exists():
        raise SystemExit(
            f"Missing {FEATURES}. Export fixtures then build features first."
        )
    rows = load_rows(FEATURES)
    metrics = train_and_eval(rows)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-structured")
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "runId": run_id,
        "task": "structured_baseline",
        "gitCommit": _git_commit(),
        "featureSchemaVersion": 1,
        "seed": 42,
        "metrics": metrics,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    (run_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
