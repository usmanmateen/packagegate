"""Dataset V1 structured baselines with honest holdout evaluation."""

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
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from packagegate_ml.datasets.splits import load_records
from packagegate_ml.features.structured import align_feature_matrix
from packagegate_ml.utils.system_info import collect_system_info

REPO = Path(__file__).resolve().parents[3]
FEATURES = Path("/tmp/packagegate-ml-data/exports/v1/features.jsonl")
SPLIT = REPO / "ml" / "data-manifests" / "v1" / "split.json"
RECORDS = Path("/tmp/packagegate-ml-data/manifests/dataset_v1_full.private.json")
RUNS = REPO / "ml" / "runs"


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def load_feature_rows(path: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        rows[row["sample_id"]] = row
    return rows


def binary_label(label: str) -> int:
    return 1 if label in {"MALICIOUS", "COMPROMISED", "SYNTHETIC_SUSPICIOUS"} else 0


def metrics_at_threshold(y_true: np.ndarray, proba: np.ndarray, threshold: float) -> dict:
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, pred, average="binary", zero_division=0
    )
    total_neg = max(tn + fp, 1)
    total_pos = max(tp + fn, 1)
    out = {
        "threshold": float(threshold),
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fp / total_neg),
        "fnr": float(fn / total_pos),
    }
    if len(set(y_true.tolist())) > 1:
        out["pr_auc"] = float(average_precision_score(y_true, proba))
        out["roc_auc"] = float(roc_auc_score(y_true, proba))
        out["brier"] = float(brier_score_loss(y_true, proba))
    else:
        out["pr_auc"] = None
        out["roc_auc"] = None
        out["brier"] = None
    return out


def recall_at_fpr(y_true: np.ndarray, proba: np.ndarray, target_fpr: float) -> dict:
    # Choose highest threshold on this set with FPR <= target (for reporting only).
    thresholds = np.unique(np.concatenate(([0.0], proba, [1.0])))
    thresholds = np.sort(thresholds)[::-1]
    best = {"threshold": 1.0, "recall": 0.0, "fpr": 0.0}
    for thr in thresholds:
        m = metrics_at_threshold(y_true, proba, float(thr))
        if m["fpr"] <= target_fpr + 1e-12:
            if m["recall"] >= best["recall"]:
                best = {
                    "threshold": float(thr),
                    "recall": m["recall"],
                    "fpr": m["fpr"],
                }
    return best


def select_threshold_for_fpr(
    y_val: np.ndarray, proba_val: np.ndarray, target_fpr: float = 0.05
) -> float:
    thresholds = np.unique(np.concatenate(([0.0], proba_val, [1.0])))
    thresholds = np.sort(thresholds)[::-1]
    chosen = 0.5
    best_recall = -1.0
    for thr in thresholds:
        m = metrics_at_threshold(y_val, proba_val, float(thr))
        if m["fpr"] <= target_fpr + 1e-12 and m["recall"] >= best_recall:
            best_recall = m["recall"]
            chosen = float(thr)
    return chosen


def matrix_for(
    ids: list[str],
    feature_rows: dict[str, dict],
    *,
    feature_mode: str = "structured",
    shuffle_labels: bool = False,
    seed: int = 42,
    feature_keys: list[str] | None = None,
) -> tuple[list[str], np.ndarray, np.ndarray, list[str]]:
    used_ids: list[str] = []
    feature_dicts: list[dict[str, float]] = []
    labels: list[int] = []
    for sid in ids:
        row = feature_rows.get(sid)
        if row is None:
            continue
        used_ids.append(sid)
        if feature_mode == "structured":
            feature_dicts.append(row["features"])
        elif feature_mode == "name_hash":
            # Deliberately weak shortcut baseline from sample_id token lengths.
            feature_dicts.append(
                {
                    "name_len": float(len(sid.split("@")[0])),
                    "version_len": float(len(sid.split("@")[-1])),
                    "at_count": float(sid.count("@")),
                    "digit_count": float(sum(ch.isdigit() for ch in sid)),
                }
            )
        elif feature_mode == "metadata":
            feats = row["features"]
            feature_dicts.append(
                {
                    "fileCount": float(feats.get("fileCount", 0)),
                    "findingCount": float(feats.get("findingCount", 0)),
                    "analysedExecutableBytes": float(
                        feats.get("analysedExecutableBytes", 0)
                    ),
                    "coverageRatio": float(feats.get("coverageRatio", 0)),
                }
            )
        else:
            raise ValueError(feature_mode)
        labels.append(binary_label(row["label"]))

    if shuffle_labels:
        rng = np.random.default_rng(seed)
        labels = list(rng.permutation(np.array(labels)))

    if feature_keys is None:
        keys, x = align_feature_matrix(feature_dicts)
    else:
        keys = feature_keys
        x = np.zeros((len(feature_dicts), len(keys)), dtype=np.float64)
        for i, row in enumerate(feature_dicts):
            for j, key in enumerate(keys):
                x[i, j] = float(row.get(key, 0.0))
    y = np.array(labels, dtype=np.int64)
    return keys, x, y, used_ids


def fit_predict(model_name: str, x_train, y_train, x_eval, seed: int = 42):
    if model_name == "logistic_regression":
        model = Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=4000,
                        class_weight="balanced",
                        random_state=seed,
                    ),
                ),
            ]
        )
    elif model_name == "hist_gradient_boosting":
        model = HistGradientBoostingClassifier(
            max_depth=4,
            learning_rate=0.08,
            max_iter=200,
            random_state=seed,
        )
    else:
        raise ValueError(model_name)
    model.fit(x_train, y_train)
    proba = model.predict_proba(x_eval)[:, 1]
    return model, proba


def top_errors(
    ids: list[str],
    y_true: np.ndarray,
    proba: np.ndarray,
    *,
    positive: bool,
    limit: int = 10,
) -> list[dict]:
    rows = []
    for sid, yt, p in zip(ids, y_true, proba, strict=True):
        if positive and yt == 1:
            rows.append({"sample_id": sid, "probability": float(p), "label": int(yt)})
        if not positive and yt == 0:
            rows.append({"sample_id": sid, "probability": float(p), "label": int(yt)})
    if positive:
        # false negatives: positives with lowest score
        rows.sort(key=lambda r: r["probability"])
    else:
        # false positives: negatives with highest score
        rows.sort(key=lambda r: r["probability"], reverse=True)
    return rows[:limit]


def main() -> None:
    if not FEATURES.exists() or not SPLIT.exists() or not RECORDS.exists():
        raise SystemExit("Missing features/split/records — export pilot first")

    feature_rows = load_feature_rows(FEATURES)
    split = json.loads(SPLIT.read_text(encoding="utf-8"))
    records = {r.sample_id: r for r in load_records(RECORDS)}

    # Build a global feature vocabulary from all available rows in the split.
    all_split_ids = split["train"] + split["validation"] + split["test"]
    keys, _, _, _ = matrix_for(all_split_ids, feature_rows)
    _, x_train, y_train, train_ids = matrix_for(
        split["train"], feature_rows, feature_keys=keys
    )
    _, x_val, y_val, val_ids = matrix_for(
        split["validation"], feature_rows, feature_keys=keys
    )
    _, x_test, y_test, test_ids = matrix_for(
        split["test"], feature_rows, feature_keys=keys
    )

    if len(set(y_train.tolist())) < 2:
        raise SystemExit("Training set lacks both classes")

    results: dict = {
        "nFeatures": len(keys),
        "distribution": {
            "train": {
                "n": int(len(y_train)),
                "positives": int(y_train.sum()),
                "negatives": int(len(y_train) - y_train.sum()),
            },
            "validation": {
                "n": int(len(y_val)),
                "positives": int(y_val.sum()),
                "negatives": int(len(y_val) - y_val.sum()),
            },
            "test": {
                "n": int(len(y_test)),
                "positives": int(y_test.sum()),
                "negatives": int(len(y_test) - y_test.sum()),
            },
        },
        "models": {},
    }

    for model_name in ("logistic_regression", "hist_gradient_boosting"):
        model, proba_val = fit_predict(model_name, x_train, y_train, x_val)
        thr = select_threshold_for_fpr(y_val, proba_val, target_fpr=0.05)
        _, proba_test = fit_predict(model_name, x_train, y_train, x_test)
        # Refit once for calibrated probabilities on validation folds.
        try:
            calib = CalibratedClassifierCV(model, method="sigmoid", cv=3)
            calib.fit(x_train, y_train)
            cprob_test = calib.predict_proba(x_test)[:, 1]
            cprob_val = calib.predict_proba(x_val)[:, 1]
        except Exception as exc:  # noqa: BLE001
            cprob_test = proba_test
            cprob_val = proba_val
            results.setdefault("calibrationWarnings", []).append(
                f"{model_name}:{exc}"
            )

        test_metrics = metrics_at_threshold(y_test, cprob_test, thr)
        results["models"][model_name] = {
            "validationThresholdFor5pctFpr": thr,
            "validation": metrics_at_threshold(y_val, cprob_val, thr),
            "test": test_metrics,
            "testRecallAt5pctFprOperatingPoint": recall_at_fpr(
                y_test, cprob_test, 0.05
            ),
            "testRecallAt1pctFprOperatingPoint": recall_at_fpr(
                y_test, cprob_test, 0.01
            ),
            "topFalsePositives": top_errors(
                test_ids, y_test, cprob_test, positive=False
            ),
            "topFalseNegatives": top_errors(
                test_ids, y_test, cprob_test, positive=True
            ),
        }

    # Sanity: shuffled labels
    _, x_tr_s, y_tr_s, _ = matrix_for(
        split["train"],
        feature_rows,
        shuffle_labels=True,
        seed=7,
        feature_keys=keys,
    )
    _, x_te_s, y_te_s, _ = matrix_for(
        split["test"],
        feature_rows,
        feature_keys=keys,
    )
    if len(set(y_tr_s.tolist())) > 1 and len(y_te_s) > 0:
        _, proba_s = fit_predict("logistic_regression", x_tr_s, y_tr_s, x_te_s, seed=7)
        results["shuffledLabelLogistic"] = {
            "pr_auc": float(average_precision_score(y_te_s, proba_s))
            if len(set(y_te_s.tolist())) > 1
            else None,
            "note": "Should collapse toward chance / low PR-AUC",
        }

    # Name-only and metadata-only shortcuts
    for mode in ("name_hash", "metadata"):
        k, xtr, ytr, _ = matrix_for(split["train"], feature_rows, feature_mode=mode)
        _, xte, yte, _ = matrix_for(split["test"], feature_rows, feature_mode=mode)
        if len(set(ytr.tolist())) < 2:
            continue
        _, proba = fit_predict("logistic_regression", xtr, ytr, xte)
        results[f"shortcut_{mode}"] = metrics_at_threshold(
            yte, proba, 0.5
        ) | {"nFeatures": len(k)}

    # Deterministic rules-only baseline on same test IDs
    det_y = []
    det_pred = []
    for sid in test_ids:
        row = feature_rows[sid]
        det_y.append(binary_label(row["label"]))
        rec = row.get("deterministicRecommendation") or "ALLOW"
        det_pred.append(1 if rec in {"REVIEW", "BLOCK"} else 0)
    det_y_a = np.array(det_y)
    det_pred_a = np.array(det_pred)
    # Use deterministic score as a crude score if present
    det_scores = np.array(
        [
            float(feature_rows[sid].get("deterministicScore") or 0) / 100.0
            for sid in test_ids
        ]
    )
    results["rulesOnlyDeterministic"] = metrics_at_threshold(det_y_a, det_scores, 0.25)
    results["rulesOnlyDeterministic"]["interventionConfusion"] = {
        "tp": int(((det_y_a == 1) & (det_pred_a == 1)).sum()),
        "tn": int(((det_y_a == 0) & (det_pred_a == 0)).sum()),
        "fp": int(((det_y_a == 0) & (det_pred_a == 1)).sum()),
        "fn": int(((det_y_a == 1) & (det_pred_a == 0)).sum()),
    }

    # Enrich FP/FN with categories from private records
    for model_name, model_res in results["models"].items():
        for bucket in ("topFalsePositives", "topFalseNegatives"):
            for item in model_res[bucket]:
                rec = records.get(item["sample_id"])
                if rec is None:
                    continue
                item["hardNegativeCategory"] = rec.hard_negative_category
                item["datasetSource"] = rec.dataset_source
                item["packageName"] = rec.package_name

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-structured-v1")
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "runId": run_id,
        "task": "structured_baseline_v1",
        "gitCommit": _git_commit(),
        "featureSchemaVersion": 1,
        "datasetVersion": "v1",
        "seed": 42,
        "hardware": collect_system_info(),
        "metrics": results,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "policyMode": "shadow",
        "neuralTrainingGate": None,
    }

    # Gate decision
    logistic = results["models"]["logistic_regression"]["test"]
    shuffled = results.get("shuffledLabelLogistic", {})
    name_shortcut = results.get("shortcut_name_hash", {})
    gate_pass = True
    gate_reasons = []
    if results["distribution"]["train"]["n"] < 50:
        gate_pass = False
        gate_reasons.append("train_too_small")
    if results["distribution"]["test"]["positives"] < 5:
        gate_pass = False
        gate_reasons.append("test_positives_too_few")
    if shuffled.get("pr_auc") is not None and shuffled["pr_auc"] > 0.75:
        gate_pass = False
        gate_reasons.append("shuffled_label_pr_auc_too_high")
    if logistic.get("pr_auc") is None:
        gate_pass = False
        gate_reasons.append("missing_pr_auc")
    # Package-name shortcuts must not solve the task — that is memorisation/bias.
    if name_shortcut.get("pr_auc") is not None and name_shortcut["pr_auc"] >= 0.85:
        gate_pass = False
        gate_reasons.append("package_name_shortcut_pr_auc_too_high")

    metadata["neuralTrainingGate"] = {
        "passed": gate_pass,
        "reasons": gate_reasons,
        "note": (
            "PASS requires split integrity plus absence of obvious shortcut bias. "
            "High name-only PR-AUC means the pilot corpus is not yet trustworthy "
            "for neural claims even if structured metrics look strong."
        ),
    }

    (run_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
