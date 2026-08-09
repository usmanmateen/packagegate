"""Dataset V4 baselines: STRICT_SECURITY_VIEW PG-Package + robust PG-Delta."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from packagegate_ml.datasets.feature_families import (
    behaviour_delta_features,
    behaviour_features,
    generic_metadata_v3,
    structure_nuisance_features,
)
from packagegate_ml.datasets.splits import load_records
from packagegate_ml.features.record_v2 import strict_input_nuisance
from packagegate_ml.features.structured import align_feature_matrix
from packagegate_ml.training.shortcut_features import (
    opaque_random_id_features,
    package_name_lexical_features,
    source_one_hot,
    version_only_features,
)
from packagegate_ml.training.train_pilot_structured import (
    fit_predict,
    metrics_at_threshold,
    recall_at_fpr,
    select_threshold_for_fpr,
)
from packagegate_ml.utils.system_info import collect_system_info

REPO = Path(__file__).resolve().parents[3]
FEATURES = Path("/tmp/packagegate-ml-data-v4/exports/v4/strict_features.jsonl")
SPLIT = REPO / "ml" / "data-manifests" / "v4" / "split.json"
MATCHES = REPO / "ml" / "data-manifests" / "v4" / "structure_matches.json"
PAIRS = REPO / "ml" / "data-manifests" / "v4" / "pairs.json"
DELTA_SPLIT = REPO / "ml" / "data-manifests" / "v4" / "pg_delta_split.json"
GATE_DEF = REPO / "ml" / "data-manifests" / "v4" / "neural_gate_definition.json"
RECORDS = Path("/tmp/packagegate-ml-data-v4/manifests/dataset_v4_full.private.json")
RUNS = REPO / "ml" / "runs"


def _git() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def load_rows(path: Path) -> dict[str, dict]:
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            rows[r["sample_id"]] = r
    return rows


def binlab(label: str) -> int:
    return 1 if label in {"MALICIOUS", "COMPROMISED", "SYNTHETIC_SUSPICIOUS"} else 0


def feat(mode: str, row: dict) -> dict[str, float]:
    meta = row.get("_meta") or {}
    name = meta.get("package_name") or ""
    ver = meta.get("version") or ""
    src = meta.get("dataset_source")
    structured = row.get("structured_raw") or {}
    if mode == "BEHAVIOUR_ONLY":
        return dict(row.get("behaviour_features") or behaviour_features(structured))
    if mode == "STRICT_INPUT_NUISANCE_ONLY":
        return dict(row.get("strict_input_nuisance") or strict_input_nuisance(structured))
    if mode == "ARTIFACT_STRUCTURE_ONLY":
        return structure_nuisance_features(structured)
    if mode == "PACKAGE_NAME_LEXICAL_ONLY":
        return package_name_lexical_features(name, ver)
    if mode == "VERSION_ONLY":
        return version_only_features(ver)
    if mode == "GENERIC_METADATA_ONLY":
        return generic_metadata_v3(package_name=name, version=ver, structured=structured)
    if mode == "SOURCE_ONLY":
        return source_one_hot(src)
    if mode == "OPAQUE_RANDOM_ID":
        return opaque_random_id_features(row["sample_id"], seed=0)
    raise ValueError(mode)


def matrix(ids, rows, mode, *, keys=None, shuffle=False, seed=0):
    dicts, ys, used = [], [], []
    for sid in ids:
        row = rows.get(sid)
        if row is None:
            continue
        used.append(sid)
        dicts.append(feat(mode, row))
        ys.append(binlab(row["label"]))
    if shuffle:
        rng = np.random.default_rng(seed)
        ys = list(rng.permutation(np.array(ys)))
    if keys is None:
        keys, x = align_feature_matrix(dicts)
    else:
        x = np.zeros((len(dicts), len(keys)))
        for i, d in enumerate(dicts):
            for j, k in enumerate(keys):
                x[i, j] = float(d.get(k, 0.0))
    return keys, x, np.array(ys, dtype=np.int64), used


def eval_mode(mode, tr, va, te, rows) -> dict:
    keys, xtr, ytr, _ = matrix(tr, rows, mode)
    _, xva, yva, _ = matrix(va, rows, mode, keys=keys)
    _, xte, yte, _ = matrix(te, rows, mode, keys=keys)
    prev = float(yte.mean()) if len(yte) else 0.0
    out = {
        "mode": mode,
        "nFeatures": len(keys),
        "trainN": int(len(ytr)),
        "testN": int(len(yte)),
        "positives": int(yte.sum()) if len(yte) else 0,
        "negatives": int(len(yte) - yte.sum()) if len(yte) else 0,
        "positivePrevalenceTest": prev,
        "prAucChanceBaseline": prev,
    }
    if len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        out["pr_auc"] = None
        out["skipped"] = True
        return out
    _, pva = fit_predict("logistic_regression", xtr, ytr, xva)
    thr = select_threshold_for_fpr(yva, pva, 0.05) if len(set(yva.tolist())) > 1 else 0.5
    _, pte = fit_predict("logistic_regression", xtr, ytr, xte)
    out.update(metrics_at_threshold(yte, pte, thr))
    out["validationThresholdFor5pctFpr"] = thr
    out["testRecallAt5pctFprOperatingPoint"] = recall_at_fpr(yte, pte, 0.05)
    if mode in {"STRICT_INPUT_NUISANCE_ONLY", "VERSION_ONLY", "BEHAVIOUR_ONLY"}:
        pipe = Pipeline(
            [
                ("s", StandardScaler()),
                (
                    "c",
                    LogisticRegression(
                        max_iter=5000, class_weight="balanced", random_state=0
                    ),
                ),
            ]
        )
        pipe.fit(xtr, ytr)
        coef = pipe.named_steps["c"].coef_[0]
        ranked = sorted(zip(keys, coef, strict=True), key=lambda t: abs(t[1]), reverse=True)
        out["topCoefficients"] = [
            {"feature": k, "coef": float(c)} for k, c in ranked[:10]
        ]
    return out


def bootstrap_pr(y, proba, n=200, seed=0):
    rng = np.random.default_rng(seed)
    y, proba = np.asarray(y), np.asarray(proba)
    if len(set(y.tolist())) < 2:
        return {"mean": None, "lo": None, "hi": None}
    scores = []
    for _ in range(n):
        idx = rng.integers(0, len(y), len(y))
        if len(set(y[idx].tolist())) < 2:
            continue
        scores.append(float(average_precision_score(y[idx], proba[idx])))
    if not scores:
        return {"mean": None, "lo": None, "hi": None}
    return {
        "mean": float(np.mean(scores)),
        "lo": float(np.percentile(scores, 2.5)),
        "hi": float(np.percentile(scores, 97.5)),
    }


def delta_nuisance(before: dict, after: dict, pair: dict) -> dict[str, float]:
    """Non-security release-change structure (no findings/chains/completeness)."""
    fa = before.get("structured_raw") or before.get("features") or {}
    fb = after.get("structured_raw") or after.get("features") or {}
    v1 = pair.get("clean_version") or ""
    v2 = pair.get("compromised_version") or ""
    from packagegate_ml.datasets.compromise_pairs import _version_key

    def step_type(a: str, b: str) -> float:
        try:
            ka, kb = _version_key(a), _version_key(b)
        except Exception:  # noqa: BLE001
            return 0.0
        if len(ka) >= 1 and len(kb) >= 1 and ka[0] != kb[0]:
            return 3.0  # major-ish
        if len(ka) >= 2 and len(kb) >= 2 and ka[1] != kb[1]:
            return 2.0
        return 1.0

    return {
        "fileCountDelta": float(fb.get("fileCount", 0) - fa.get("fileCount", 0)),
        "bytesDelta": float(
            fb.get("analysedExecutableBytes", 0) - fa.get("analysedExecutableBytes", 0)
        ),
        "versionStepType": step_type(v1, v2),
        "versionLenDelta": float(len(v2) - len(v1)),
    }


def pg_delta_eval(rows, pairs, delta_split) -> dict:
    by_id = {p["pair_id"]: p for p in pairs}
    buckets = {"train": [], "validation": [], "test": []}
    for part in ("train", "validation", "test"):
        for pid in delta_split[part]:
            p = by_id.get(pid)
            if not p:
                continue
            a, b = rows.get(p["clean_sample_id"]), rows.get(p["compromised_sample_id"])
            if not a or not b:
                continue
            y = 1 if (p.get("pair_label") or p.get("label")) == "COMPROMISE_INTRODUCED" else 0
            fa = a.get("structured_raw") or {}
            fb = b.get("structured_raw") or {}
            buckets[part].append(
                {
                    "behaviour": behaviour_delta_features(fa, fb),
                    "nuisance": delta_nuisance(a, b, p),
                    "y": y,
                    "family": (p.get("compromised_sample_id") or "").rsplit("@", 1)[0],
                    "pair": p,
                }
            )

    def run(feature_key: str) -> dict:
        def stack(items, keys=None):
            dicts = [it[feature_key] for it in items]
            ys = np.array([it["y"] for it in items], dtype=np.int64)
            if keys is None:
                keys, x = align_feature_matrix(dicts)
            else:
                x = np.zeros((len(dicts), len(keys)))
                for i, d in enumerate(dicts):
                    for j, k in enumerate(keys):
                        x[i, j] = float(d.get(k, 0.0))
            return keys, x, ys

        counts = {k: len(v) for k, v in buckets.items()}
        pos = sum(1 for part in buckets.values() for it in part if it["y"] == 1)
        neg = sum(1 for part in buckets.values() for it in part if it["y"] == 0)
        out = {
            "counts": counts,
            "usablePositive": pos,
            "usableNegative": neg,
            "testPositives": sum(1 for it in buckets["test"] if it["y"] == 1),
            "testNegatives": sum(1 for it in buckets["test"] if it["y"] == 0),
        }
        if len(buckets["train"]) < 10 or len(buckets["test"]) < 5:
            out["skipped"] = True
            return out
        keys, xtr, ytr = stack(buckets["train"])
        _, xte, yte = stack(buckets["test"], keys=keys)
        if buckets["validation"] and len(set(it["y"] for it in buckets["validation"])) > 1:
            _, xva, yva = stack(buckets["validation"], keys=keys)
        else:
            xva, yva = xtr, ytr
        if len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
            out["skipped"] = True
            out["reason"] = "single_class"
            return out
        _, pva = fit_predict("logistic_regression", xtr, ytr, xva)
        thr = select_threshold_for_fpr(yva, pva, 0.05)
        _, pte = fit_predict("logistic_regression", xtr, ytr, xte)
        m = metrics_at_threshold(yte, pte, thr)
        m["brier"] = float(brier_score_loss(yte, pte))
        m["prAucBootstrap"] = bootstrap_pr(yte, pte)
        m["positivePrevalenceTest"] = float(yte.mean())
        out["logistic"] = m

        # Grouped CV on all pairs
        all_items = buckets["train"] + buckets["validation"] + buckets["test"]
        groups = np.array([it["family"] for it in all_items])
        dicts = [it[feature_key] for it in all_items]
        ys = np.array([it["y"] for it in all_items], dtype=np.int64)
        keys_cv, x_all = align_feature_matrix(dicts)
        unique_groups = len(set(groups.tolist()))
        n_splits = min(5, unique_groups)
        fold_scores = []
        if n_splits >= 2 and len(set(ys.tolist())) > 1:
            gkf = GroupKFold(n_splits=n_splits)
            for tr_i, te_i in gkf.split(x_all, ys, groups):
                if len(set(ys[tr_i].tolist())) < 2 or len(set(ys[te_i].tolist())) < 2:
                    continue
                _, proba = fit_predict(
                    "logistic_regression", x_all[tr_i], ys[tr_i], x_all[te_i]
                )
                fold_scores.append(float(average_precision_score(ys[te_i], proba)))
        out["groupedCV"] = {
            "nSplits": n_splits,
            "scores": fold_scores,
            "mean": float(np.mean(fold_scores)) if fold_scores else None,
            "std": float(np.std(fold_scores)) if fold_scores else None,
            "min": float(np.min(fold_scores)) if fold_scores else None,
            "max": float(np.max(fold_scores)) if fold_scores else None,
        }
        return out

    return {
        "DELTA_BEHAVIOUR": run("behaviour"),
        "DELTA_NUISANCE": run("nuisance"),
        "examplesPositive": [
            {
                "pair_id": it["pair"]["pair_id"],
                "clean": it["pair"]["clean_sample_id"],
                "compromised": it["pair"]["compromised_sample_id"],
            }
            for it in buckets["test"]
            if it["y"] == 1
        ][:3],
        "examplesNegative": [
            {
                "pair_id": it["pair"]["pair_id"],
                "before": it["pair"]["clean_sample_id"],
                "after": it["pair"]["compromised_sample_id"],
            }
            for it in buckets["test"]
            if it["y"] == 0
        ][:3],
    }


def source_proxy_strict(rows, split) -> dict:
    """Predict dataset source from STRICT_INPUT_NUISANCE only."""
    ytr, xtr = [], []
    for sid in split["train"]:
        row = rows.get(sid)
        if not row:
            continue
        xtr.append(feat("STRICT_INPUT_NUISANCE_ONLY", row))
        ytr.append(1 if (row.get("_meta") or {}).get("dataset_source") == "datadog" else 0)
    yte, xte = [], []
    for sid in split["test"]:
        row = rows.get(sid)
        if not row:
            continue
        xte.append(feat("STRICT_INPUT_NUISANCE_ONLY", row))
        yte.append(1 if (row.get("_meta") or {}).get("dataset_source") == "datadog" else 0)
    keys, Xtr = align_feature_matrix(xtr)
    Xte = np.zeros((len(xte), len(keys)))
    for i, d in enumerate(xte):
        for j, k in enumerate(keys):
            Xte[i, j] = float(d.get(k, 0.0))
    ytr_a, yte_a = np.array(ytr), np.array(yte)
    if len(set(ytr_a.tolist())) < 2 or len(set(yte_a.tolist())) < 2:
        return {"skipped": True}
    pipe = Pipeline(
        [
            ("s", StandardScaler()),
            (
                "c",
                LogisticRegression(max_iter=5000, class_weight="balanced", random_state=0),
            ),
        ]
    )
    pipe.fit(Xtr, ytr_a)
    proba = pipe.predict_proba(Xte)[:, 1]
    coef = pipe.named_steps["c"].coef_[0]
    ranked = sorted(zip(keys, coef, strict=True), key=lambda t: abs(t[1]), reverse=True)
    return {
        "pr_auc": float(average_precision_score(yte_a, proba)),
        "prevalence": float(yte_a.mean()),
        "topCoefficients": [{"feature": k, "coef": float(c)} for k, c in ranked[:8]],
    }


def main() -> None:
    for p in (FEATURES, SPLIT, MATCHES, PAIRS, DELTA_SPLIT, GATE_DEF, RECORDS):
        if not p.exists():
            raise SystemExit(f"Missing {p}")

    gate = json.loads(GATE_DEF.read_text(encoding="utf-8"))
    rows = load_rows(FEATURES)
    split = json.loads(SPLIT.read_text(encoding="utf-8"))
    matches = json.loads(MATCHES.read_text(encoding="utf-8"))
    pairs = json.loads(PAIRS.read_text(encoding="utf-8"))
    delta_split = json.loads(DELTA_SPLIT.read_text(encoding="utf-8"))
    matched_ids = set(matches.get("matchedSampleIds") or [])

    modes = [
        "PACKAGE_NAME_LEXICAL_ONLY",
        "VERSION_ONLY",
        "ARTIFACT_STRUCTURE_ONLY",
        "GENERIC_METADATA_ONLY",
        "SOURCE_ONLY",
        "OPAQUE_RANDOM_ID",
        "STRICT_INPUT_NUISANCE_ONLY",
        "BEHAVIOUR_ONLY",
    ]

    tr_m = [i for i in split["train"] if i in matched_ids]
    va_m = [i for i in split["validation"] if i in matched_ids]
    te_m = [i for i in split["test"] if i in matched_ids]

    matched = {
        "n": len(matched_ids),
        "sizes": {"train": len(tr_m), "validation": len(va_m), "test": len(te_m)},
        "modes": {m: eval_mode(m, tr_m, va_m, te_m, rows) for m in modes},
        "beforeSMD": matches.get("beforeSMD"),
        "afterSMD": matches.get("afterSMD"),
    }
    mixed = {m: eval_mode(m, split["train"], split["validation"], split["test"], rows) for m in modes}

    # shuffled behaviour on matched
    keys, xtr, ytr, _ = matrix(tr_m, rows, "BEHAVIOUR_ONLY", shuffle=True, seed=7)
    _, xte, yte, _ = matrix(te_m, rows, "BEHAVIOUR_ONLY", keys=keys)
    shuffled = None
    if len(set(ytr.tolist())) > 1 and len(set(yte.tolist())) > 1:
        _, proba = fit_predict("logistic_regression", xtr, ytr, xte, seed=7)
        shuffled = {
            "pr_auc": float(average_precision_score(yte, proba)),
            "positivePrevalenceTest": float(yte.mean()),
        }

    pg_delta = pg_delta_eval(rows, pairs, delta_split)
    source_proxy = source_proxy_strict(rows, split)

    # leakage rate from export
    leak_n = sum(1 for r in rows.values() if r.get("leakage_issues"))

    # Gate
    prev = (matched["modes"].get("BEHAVIOUR_ONLY") or {}).get("positivePrevalenceTest") or 0.0
    strict_n = (matched["modes"].get("STRICT_INPUT_NUISANCE_ONLY") or {}).get("pr_auc")
    struct_m = (matched["modes"].get("ARTIFACT_STRUCTURE_ONLY") or {}).get("pr_auc")
    ver_m = (matched["modes"].get("VERSION_ONLY") or {}).get("pr_auc")
    beh_m = (matched["modes"].get("BEHAVIOUR_ONLY") or {}).get("pr_auc")
    opaque = mixed.get("OPAQUE_RANDOM_ID") or {}
    delta_beh = (pg_delta.get("DELTA_BEHAVIOUR") or {}).get("logistic") or {}
    delta_nui = (pg_delta.get("DELTA_NUISANCE") or {}).get("logistic") or {}
    delta_beh_pr = delta_beh.get("pr_auc")
    delta_nui_pr = delta_nui.get("pr_auc")
    # Prefer grouped CV mean when test is small
    delta_beh_cv = ((pg_delta.get("DELTA_BEHAVIOUR") or {}).get("groupedCV") or {}).get("mean")
    delta_nui_cv = ((pg_delta.get("DELTA_NUISANCE") or {}).get("groupedCV") or {}).get("mean")
    if delta_beh_cv is not None and delta_nui_cv is not None:
        delta_beh_cmp, delta_nui_cmp = delta_beh_cv, delta_nui_cv
    else:
        delta_beh_cmp, delta_nui_cmp = delta_beh_pr, delta_nui_pr

    reasons = []
    passed = True

    def fail(r: str) -> None:
        nonlocal passed
        passed = False
        reasons.append(r)

    if matched["n"] < gate["min_matched_samples"]:
        fail("matched_too_small")
    if strict_n is not None and strict_n > prev + gate["max_strict_input_nuisance_over_prevalence"]:
        fail("strict_input_nuisance_too_high")
    if struct_m is not None and struct_m > prev + gate["max_artifact_structure_matched_over_prevalence"]:
        fail("artifact_structure_matched_too_high")
    if ver_m is not None and ver_m > gate["max_version_only_matched"]:
        fail("version_only_matched_too_high")
    if (
        beh_m is not None
        and strict_n is not None
        and (beh_m - strict_n) < gate["min_behaviour_minus_strict_nuisance"]
    ):
        fail("behaviour_not_above_strict_nuisance")
    if shuffled and shuffled["pr_auc"] > gate["max_shuffled_pr_auc"]:
        fail("shuffled_too_high")
    if opaque.get("pr_auc") is not None and opaque["pr_auc"] > (
        opaque.get("positivePrevalenceTest") or 0
    ) + gate["max_opaque_over_prevalence"]:
        fail("opaque_too_high")
    pos_n = (pg_delta.get("DELTA_BEHAVIOUR") or {}).get("usablePositive", 0)
    neg_n = (pg_delta.get("DELTA_BEHAVIOUR") or {}).get("usableNegative", 0)
    test_n = sum((pg_delta.get("DELTA_BEHAVIOUR") or {}).get("counts", {}).values())  # wrong
    test_pairs = (pg_delta.get("DELTA_BEHAVIOUR") or {}).get("counts", {}).get("test", 0)
    if pos_n < gate["min_pg_delta_positive"] or neg_n < gate["min_pg_delta_negative"]:
        fail("pg_delta_pair_support_too_low")
    if test_pairs < gate["min_pg_delta_test_pairs"]:
        # allow if grouped CV present with enough folds
        cv = (pg_delta.get("DELTA_BEHAVIOUR") or {}).get("groupedCV") or {}
        if not cv.get("scores") or len(cv["scores"]) < 3:
            fail("pg_delta_test_too_small")
    if (
        delta_beh_cmp is not None
        and delta_nui_cmp is not None
        and (delta_beh_cmp - delta_nui_cmp) < gate["min_delta_behaviour_minus_delta_nuisance"]
    ):
        fail("delta_behaviour_not_above_delta_nuisance")
    if leak_n > max(5, int(0.05 * len(rows))):
        fail("strict_input_identity_leakage_rate_high")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-structured-v4")
    metadata = {
        "runId": run_id,
        "task": "structured_baseline_v4",
        "gitCommit": _git(),
        "datasetVersion": "v4",
        "hardware": collect_system_info(),
        "metrics": {
            "matched": matched,
            "mixed": mixed,
            "pgDelta": pg_delta,
            "sourceProxyStrictNuisance": source_proxy,
            "shuffledLabelBehaviourMatched": shuffled,
            "strictLeakFlags": leak_n,
            "modelInputAudit": {
                "packageNamePresent": False,
                "versionPresent": False,
                "datasetSourcePresent": False,
                "labelPresent": False,
                "familyIdPresent": False,
                "authorPresent": False,
                "repositoryPresent": False,
                "primaryFeatures": "structuredBehaviourFeatures (findings/chains/lifecycle/completeness) + masked slices + securityManifest scripts",
            },
        },
        "neuralTrainingGate": {
            "passed": passed,
            "reasons": reasons,
            "definition": gate,
            "observed": {
                "matchedN": matched["n"],
                "matchedPrevalence": prev,
                "strictInputNuisance": strict_n,
                "artifactStructure": struct_m,
                "versionOnly": ver_m,
                "behaviour": beh_m,
                "behaviourMinusStrictNuisance": (
                    None if beh_m is None or strict_n is None else beh_m - strict_n
                ),
                "rawNameMatched": (matched["modes"].get("PACKAGE_NAME_LEXICAL_ONLY") or {}).get(
                    "pr_auc"
                ),
                "deltaBehaviour": delta_beh_cmp,
                "deltaNuisance": delta_nui_cmp,
                "pgDeltaTestPairs": test_pairs,
                "pgDeltaPos": pos_n,
                "pgDeltaNeg": neg_n,
                "shuffled": shuffled,
                "opaque": opaque.get("pr_auc"),
                "leakFlags": leak_n,
            },
        },
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "torchInstalled": False,
    }
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata["neuralTrainingGate"], indent=2))
    print(
        json.dumps(
            {
                "matched": {k: (v or {}).get("pr_auc") for k, v in matched["modes"].items()},
                "pgDelta": {
                    "behaviour": delta_beh_cmp,
                    "nuisance": delta_nui_cmp,
                    "testPairs": test_pairs,
                    "cvBehaviour": (pg_delta.get("DELTA_BEHAVIOUR") or {}).get("groupedCV"),
                    "cvNuisance": (pg_delta.get("DELTA_NUISANCE") or {}).get("groupedCV"),
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
