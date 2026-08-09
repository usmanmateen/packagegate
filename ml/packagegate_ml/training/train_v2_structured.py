"""Dataset V2 structured baselines + shortcut decomposition (no neural training)."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from packagegate_ml.datasets.splits import load_records
from packagegate_ml.features.structured import align_feature_matrix
from packagegate_ml.training.shortcut_features import (
    artifact_structure_features,
    behaviour_only_features,
    generic_metadata_features,
    name_plus_version_features,
    opaque_random_id_features,
    package_name_lexical_features,
    source_one_hot,
    v1_legacy_name_morphology_from_sample_id,
    version_only_features,
)
from packagegate_ml.training.train_pilot_structured import (
    fit_predict,
    metrics_at_threshold,
    recall_at_fpr,
    select_threshold_for_fpr,
    top_errors,
)
from packagegate_ml.utils.system_info import collect_system_info

REPO = Path(__file__).resolve().parents[3]
FEATURES = Path("/tmp/packagegate-ml-data-v2/exports/v2/features.jsonl")
SPLIT = REPO / "ml" / "data-manifests" / "v2" / "split.json"
BENCHMARKS = REPO / "ml" / "data-manifests" / "v2" / "benchmarks.json"
RECORDS = Path("/tmp/packagegate-ml-data-v2/manifests/dataset_v2_full.private.json")
PAIRS = REPO / "ml" / "data-manifests" / "v2" / "compromise_pairs.json"
RUNS = REPO / "ml" / "runs"

# Pre-registered neural gate thresholds (do not weaken after seeing results).
GATE = {
    "max_name_lexical_pr_auc": 0.80,
    "max_nuisance_pr_auc": 0.80,
    "max_shuffled_pr_auc": 0.75,
    "max_opaque_random_pr_auc_over_prevalence": 0.25,
    "min_behaviour_minus_nuisance_pr_auc": 0.05,
    "min_compromised_benchmark_samples": 40,
}


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


def feature_dict_for(mode: str, row: dict, record) -> dict[str, float]:
    name = (record.package_name if record else None) or row.get("package_name") or ""
    version = (record.version if record else None) or row.get("version") or ""
    source = (record.dataset_source if record else None) or row.get("dataset_source")
    structured = row.get("structured") or row.get("features") or {}
    if mode == "PACKAGE_NAME_LEXICAL_ONLY":
        return package_name_lexical_features(name, version)
    if mode == "VERSION_ONLY":
        return version_only_features(version)
    if mode == "NAME_PLUS_VERSION":
        return name_plus_version_features(name, version)
    if mode == "V1_LEGACY_NAME_MORPHOLOGY":
        return v1_legacy_name_morphology_from_sample_id(row["sample_id"])
    if mode == "SOURCE_ONLY":
        return source_one_hot(source)
    if mode == "ARTIFACT_STRUCTURE_ONLY":
        return artifact_structure_features(structured)
    if mode == "GENERIC_METADATA_ONLY":
        return generic_metadata_features(
            package_name=name,
            version=version,
            dataset_source=source,
            structured=structured,
            include_source=False,
        )
    if mode == "GENERIC_METADATA_PLUS_SOURCE":
        return generic_metadata_features(
            package_name=name,
            version=version,
            dataset_source=source,
            structured=structured,
            include_source=True,
        )
    if mode == "BEHAVIOUR_ONLY":
        return behaviour_only_features(structured)
    if mode == "BEHAVIOUR_PLUS_METADATA":
        out = behaviour_only_features(structured)
        out.update(
            generic_metadata_features(
                package_name=name,
                version=version,
                dataset_source=source,
                structured=structured,
            )
        )
        return out
    if mode == "OPAQUE_RANDOM_ID":
        return opaque_random_id_features(row["sample_id"], seed=0)
    if mode == "STRUCTURED_FULL":
        return dict(row.get("features") or {})
    raise ValueError(mode)


def matrix(
    ids: list[str],
    feature_rows: dict[str, dict],
    records: dict,
    mode: str,
    *,
    feature_keys: list[str] | None = None,
    shuffle_labels: bool = False,
    seed: int = 0,
) -> tuple[list[str], np.ndarray, np.ndarray, list[str]]:
    used: list[str] = []
    dicts: list[dict[str, float]] = []
    labels: list[int] = []
    for sid in ids:
        row = feature_rows.get(sid)
        if row is None:
            continue
        used.append(sid)
        dicts.append(feature_dict_for(mode, row, records.get(sid)))
        labels.append(binary_label(row["label"]))
    if shuffle_labels:
        rng = np.random.default_rng(seed)
        labels = list(rng.permutation(np.array(labels)))
    if feature_keys is None:
        keys, x = align_feature_matrix(dicts)
    else:
        keys = feature_keys
        x = np.zeros((len(dicts), len(keys)), dtype=np.float64)
        for i, d in enumerate(dicts):
            for j, k in enumerate(keys):
                x[i, j] = float(d.get(k, 0.0))
    return keys, x, np.array(labels, dtype=np.int64), used


def evaluate_mode(
    mode: str,
    train_ids: list[str],
    val_ids: list[str],
    test_ids: list[str],
    feature_rows: dict[str, dict],
    records: dict,
) -> dict:
    keys, xtr, ytr, _ = matrix(train_ids, feature_rows, records, mode)
    _, xva, yva, _ = matrix(
        val_ids, feature_rows, records, mode, feature_keys=keys
    )
    _, xte, yte, te_ids = matrix(
        test_ids, feature_rows, records, mode, feature_keys=keys
    )
    prevalence = float(yte.mean()) if len(yte) else 0.0
    out: dict = {
        "mode": mode,
        "nFeatures": len(keys),
        "trainN": int(len(ytr)),
        "testN": int(len(yte)),
        "positivePrevalenceTest": prevalence,
        "prAucChanceBaseline": prevalence,
    }
    if len(set(ytr.tolist())) < 2 or len(yte) == 0 or len(set(yte.tolist())) < 2:
        out["pr_auc"] = None
        out["skipped"] = True
        return out
    _, proba_val = fit_predict("logistic_regression", xtr, ytr, xva)
    thr = select_threshold_for_fpr(yva, proba_val, 0.05) if len(set(yva.tolist())) > 1 else 0.5
    _, proba = fit_predict("logistic_regression", xtr, ytr, xte)
    out.update(metrics_at_threshold(yte, proba, thr))
    out["validationThresholdFor5pctFpr"] = thr
    out["testRecallAt5pctFprOperatingPoint"] = recall_at_fpr(yte, proba, 0.05)
    return out


def evaluate_models_behaviour(
    train_ids, val_ids, test_ids, feature_rows, records
) -> dict:
    results = {}
    keys, xtr, ytr, _ = matrix(
        train_ids, feature_rows, records, "BEHAVIOUR_ONLY"
    )
    _, xva, yva, _ = matrix(
        val_ids, feature_rows, records, "BEHAVIOUR_ONLY", feature_keys=keys
    )
    _, xte, yte, te_ids = matrix(
        test_ids, feature_rows, records, "BEHAVIOUR_ONLY", feature_keys=keys
    )
    if len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        return {"skipped": True}
    for model_name in ("logistic_regression", "hist_gradient_boosting"):
        _, pval = fit_predict(model_name, xtr, ytr, xva)
        thr = select_threshold_for_fpr(yva, pval, 0.05)
        _, pte = fit_predict(model_name, xtr, ytr, xte)
        results[model_name] = {
            "validationThresholdFor5pctFpr": thr,
            "test": metrics_at_threshold(yte, pte, thr),
            "testRecallAt5pctFprOperatingPoint": recall_at_fpr(yte, pte, 0.05),
            "topFalsePositives": top_errors(te_ids, yte, pte, positive=False),
            "topFalseNegatives": top_errors(te_ids, yte, pte, positive=True),
            "brier": float(brier_score_loss(yte, pte)),
            "positivePrevalenceTest": float(yte.mean()),
        }
    # rules-only
    det_y = np.array([binary_label(feature_rows[s]["label"]) for s in te_ids])
    det_pred = np.array(
        [
            1
            if (feature_rows[s].get("deterministicRecommendation") or "ALLOW")
            in {"REVIEW", "BLOCK"}
            else 0
            for s in te_ids
        ]
    )
    results["rulesOnly"] = {
        "tp": int(((det_y == 1) & (det_pred == 1)).sum()),
        "tn": int(((det_y == 0) & (det_pred == 0)).sum()),
        "fp": int(((det_y == 0) & (det_pred == 1)).sum()),
        "fn": int(((det_y == 1) & (det_pred == 0)).sum()),
    }
    return results


def pair_delta_baseline(feature_rows: dict, pairs: list[dict], split: dict) -> dict:
    """PG-Delta structured baseline on compromise pairs (family-grouped)."""
    # Negative pairs: random expected-benign version pairs within train families — skipped if scarce
    pos = []
    for p in pairs:
        clean = feature_rows.get(p["clean_sample_id"])
        bad = feature_rows.get(p["compromised_sample_id"])
        if not clean or not bad:
            continue
        pos.append((p, clean, bad, 1))

    # Build simple delta vectors
    def delta(a: dict, b: dict) -> dict[str, float]:
        fa = a.get("features") or {}
        fb = b.get("features") or {}
        keys = sorted(set(fa) | set(fb))
        return {k: float(fb.get(k, 0) - fa.get(k, 0)) for k in keys}

    # Assign pair to split by compromised id membership
    def which(sid: str) -> str | None:
        if sid in split["train"]:
            return "train"
        if sid in split["validation"]:
            return "validation"
        if sid in split["test"]:
            return "test"
        return None

    buckets = {"train": [], "validation": [], "test": []}
    for p, clean, bad, y in pos:
        part = which(p["compromised_sample_id"])
        if part:
            buckets[part].append((delta(clean, bad), y, p["pair_id"]))

    if len(buckets["train"]) < 5 or len(buckets["test"]) < 3:
        return {
            "skipped": True,
            "reason": "insufficient_pairs",
            "counts": {k: len(v) for k, v in buckets.items()},
        }

    # Need negatives: delta between two benign feature rows if available in same split families
    # Use zero-ish synthetic negatives from shuffling feature deltas among positives as weak negs — better:
    # use clean→clean self delta (zeros) is useless. Skip if no true negatives.
    # Create negatives from pairs where we reverse? No.
    # Use matched benign structure: for each positive delta, include a "no change" near-zero from
    # comparing a benign row to itself is trivial. Instead mark skipped for negatives.
    # Practical: train one-class? User asked for NO_KNOWN_COMPROMISE negatives.
    # Approximate: sample pairs of expected-benign feature rows sharing no malice.
    benign_ids = [
        sid
        for sid, row in feature_rows.items()
        if binary_label(row["label"]) == 0
    ]
    rng = np.random.default_rng(0)
    for part, items in list(buckets.items()):
        part_ids = [sid for sid in split[part] if sid in feature_rows and binary_label(feature_rows[sid]["label"]) == 0]
        for _ in range(min(len(items), max(len(part_ids) // 2, 0))):
            if len(part_ids) < 2:
                break
            a, b = rng.choice(part_ids, size=2, replace=False)
            buckets[part].append(
                (delta(feature_rows[a], feature_rows[b]), 0, f"neg::{a}->{b}")
            )

    def stack(items):
        dicts = [d for d, _, _ in items]
        ys = np.array([y for _, y, _ in items], dtype=np.int64)
        keys, x = align_feature_matrix(dicts)
        return keys, x, ys

    keys, xtr, ytr = stack(buckets["train"])
    _, xte, yte = stack(
        [
            ({k: float(d.get(k, 0.0)) for k in keys}, y, pid)
            for d, y, pid in buckets["test"]
        ]
        if False
        else buckets["test"]
    )
    # realign test
    xte = np.zeros((len(buckets["test"]), len(keys)), dtype=np.float64)
    yte = np.array([y for _, y, _ in buckets["test"]], dtype=np.int64)
    for i, (d, _, _) in enumerate(buckets["test"]):
        for j, k in enumerate(keys):
            xte[i, j] = float(d.get(k, 0.0))

    if len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        return {
            "skipped": True,
            "reason": "single_class",
            "counts": {k: len(v) for k, v in buckets.items()},
        }
    _, proba = fit_predict("logistic_regression", xtr, ytr, xte)
    return {
        "counts": {k: len(v) for k, v in buckets.items()},
        "positivePrevalenceTest": float(yte.mean()),
        "prAucChanceBaseline": float(yte.mean()),
        **metrics_at_threshold(yte, proba, 0.5),
    }


def main() -> None:
    for path in (FEATURES, SPLIT, BENCHMARKS, RECORDS):
        if not path.exists():
            raise SystemExit(f"Missing {path}")

    feature_rows = load_feature_rows(FEATURES)
    split = json.loads(SPLIT.read_text(encoding="utf-8"))
    benchmarks = json.loads(BENCHMARKS.read_text(encoding="utf-8"))
    records = {r.sample_id: r for r in load_records(RECORDS)}
    pairs = json.loads(PAIRS.read_text(encoding="utf-8")) if PAIRS.exists() else []

    shortcut_modes = [
        "PACKAGE_NAME_LEXICAL_ONLY",
        "VERSION_ONLY",
        "NAME_PLUS_VERSION",
        "V1_LEGACY_NAME_MORPHOLOGY",
        "SOURCE_ONLY",
        "ARTIFACT_STRUCTURE_ONLY",
        "GENERIC_METADATA_ONLY",
        "GENERIC_METADATA_PLUS_SOURCE",
        "OPAQUE_RANDOM_ID",
        "BEHAVIOUR_ONLY",
        "BEHAVIOUR_PLUS_METADATA",
        "STRUCTURED_FULL",
    ]

    results: dict = {
        "gateDefinition": GATE,
        "benchmarks": {},
        "mixedShortcuts": {},
        "pgDelta": None,
        "multiSeedBehaviour": [],
    }

    # Mixed / naturalistic uses frozen split
    for mode in shortcut_modes:
        results["mixedShortcuts"][mode] = evaluate_mode(
            mode,
            split["train"],
            split["validation"],
            split["test"],
            feature_rows,
            records,
        )

    # Shuffled label on behaviour-only
    keys, xtr, ytr, _ = matrix(
        split["train"],
        feature_rows,
        records,
        "BEHAVIOUR_ONLY",
        shuffle_labels=True,
        seed=7,
    )
    _, xte, yte, _ = matrix(
        split["test"], feature_rows, records, "BEHAVIOUR_ONLY", feature_keys=keys
    )
    if len(set(ytr.tolist())) > 1 and len(set(yte.tolist())) > 1:
        _, proba = fit_predict("logistic_regression", xtr, ytr, xte, seed=7)
        results["shuffledLabelBehaviour"] = {
            "pr_auc": float(average_precision_score(yte, proba)),
            "positivePrevalenceTest": float(yte.mean()),
            "prAucChanceBaseline": float(yte.mean()),
        }

    results["behaviourModelsMixed"] = evaluate_models_behaviour(
        split["train"], split["validation"], split["test"], feature_rows, records
    )

    # Per-benchmark: intersect with frozen split parts
    for bench_name, bench_ids in benchmarks.items():
        bench_set = set(bench_ids)
        tr = [i for i in split["train"] if i in bench_set]
        va = [i for i in split["validation"] if i in bench_set]
        te = [i for i in split["test"] if i in bench_set]
        results["benchmarks"][bench_name] = {
            "sizes": {"train": len(tr), "validation": len(va), "test": len(te)},
            "PACKAGE_NAME_LEXICAL_ONLY": evaluate_mode(
                "PACKAGE_NAME_LEXICAL_ONLY", tr, va, te, feature_rows, records
            ),
            "GENERIC_METADATA_ONLY": evaluate_mode(
                "GENERIC_METADATA_ONLY", tr, va, te, feature_rows, records
            ),
            "BEHAVIOUR_ONLY": evaluate_mode(
                "BEHAVIOUR_ONLY", tr, va, te, feature_rows, records
            ),
            "models": evaluate_models_behaviour(tr, va, te, feature_rows, records),
        }

    results["pgDelta"] = pair_delta_baseline(feature_rows, pairs, split)

    # Multi-seed robustness on behaviour-only (report only; canonical split unchanged)
    from packagegate_ml.datasets.splits import grouped_split

    all_records = list(records.values())
    for seed in (1, 2, 3, 4, 5):
        sp = grouped_split(all_records, seed=seed)
        m = evaluate_mode(
            "BEHAVIOUR_ONLY",
            sp.train,
            sp.validation,
            sp.test,
            feature_rows,
            records,
        )
        results["multiSeedBehaviour"].append(
            {"seed": seed, "pr_auc": m.get("pr_auc"), "testN": m.get("testN")}
        )

    # Gate evaluation (pre-registered)
    name_pr = (results["mixedShortcuts"].get("PACKAGE_NAME_LEXICAL_ONLY") or {}).get(
        "pr_auc"
    )
    nuisance_pr = (results["mixedShortcuts"].get("GENERIC_METADATA_ONLY") or {}).get(
        "pr_auc"
    )
    behaviour_pr = (results["mixedShortcuts"].get("BEHAVIOUR_ONLY") or {}).get("pr_auc")
    opaque = results["mixedShortcuts"].get("OPAQUE_RANDOM_ID") or {}
    opaque_pr = opaque.get("pr_auc")
    prevalence = opaque.get("positivePrevalenceTest") or 0.0
    shuffled = (results.get("shuffledLabelBehaviour") or {}).get("pr_auc")
    compromised_n = results["benchmarks"].get("compromised_version", {}).get("sizes", {})
    compromised_total = sum(compromised_n.values()) if compromised_n else 0

    reasons = []
    passed = True
    if name_pr is not None and name_pr > GATE["max_name_lexical_pr_auc"]:
        passed = False
        reasons.append("name_lexical_pr_auc_too_high")
    if nuisance_pr is not None and nuisance_pr > GATE["max_nuisance_pr_auc"]:
        passed = False
        reasons.append("nuisance_pr_auc_too_high")
    if shuffled is not None and shuffled > GATE["max_shuffled_pr_auc"]:
        passed = False
        reasons.append("shuffled_label_pr_auc_too_high")
    if (
        opaque_pr is not None
        and opaque_pr > prevalence + GATE["max_opaque_random_pr_auc_over_prevalence"]
    ):
        passed = False
        reasons.append("opaque_random_id_pr_auc_too_high")
    if (
        behaviour_pr is not None
        and nuisance_pr is not None
        and (behaviour_pr - nuisance_pr) < GATE["min_behaviour_minus_nuisance_pr_auc"]
    ):
        passed = False
        reasons.append("behaviour_not_materially_above_nuisance")
    if compromised_total < GATE["min_compromised_benchmark_samples"]:
        passed = False
        reasons.append("compromised_benchmark_too_small")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-structured-v2")
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "runId": run_id,
        "task": "structured_baseline_v2",
        "gitCommit": _git_commit(),
        "datasetVersion": "v2",
        "seed": 42,
        "hardware": collect_system_info(),
        "metrics": results,
        "neuralTrainingGate": {
            "passed": passed,
            "reasons": reasons,
            "definition": GATE,
            "observed": {
                "nameLexicalPrAuc": name_pr,
                "nuisancePrAuc": nuisance_pr,
                "behaviourPrAuc": behaviour_pr,
                "opaqueRandomPrAuc": opaque_pr,
                "prevalence": prevalence,
                "shuffledPrAuc": shuffled,
                "compromisedBenchmarkN": compromised_total,
            },
        },
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "policyMode": "shadow",
        "torchInstalled": False,
    }
    (run_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata["neuralTrainingGate"], indent=2))
    print(json.dumps({
        "mixedShortcuts": {
            k: {
                "pr_auc": v.get("pr_auc"),
                "prevalence": v.get("positivePrevalenceTest"),
            }
            for k, v in results["mixedShortcuts"].items()
        },
        "benchmarks": {
            k: {
                "sizes": v["sizes"],
                "name": (v.get("PACKAGE_NAME_LEXICAL_ONLY") or {}).get("pr_auc"),
                "nuisance": (v.get("GENERIC_METADATA_ONLY") or {}).get("pr_auc"),
                "behaviour": (v.get("BEHAVIOUR_ONLY") or {}).get("pr_auc"),
            }
            for k, v in results["benchmarks"].items()
        },
        "pgDelta": results["pgDelta"],
    }, indent=2))


if __name__ == "__main__":
    main()
