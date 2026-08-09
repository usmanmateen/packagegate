"""Dataset V3 structured baselines, PG-Delta, matched benchmark, neural gate."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from packagegate_ml.datasets.feature_families import (
    behaviour_delta_features,
    behaviour_features,
    generic_metadata_v3,
    structure_nuisance_features,
)
from packagegate_ml.datasets.splits import grouped_split, load_records
from packagegate_ml.datasets.structure_matching import structure_match
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
    top_errors,
)
from packagegate_ml.utils.system_info import collect_system_info

REPO = Path(__file__).resolve().parents[3]
FEATURES = Path("/tmp/packagegate-ml-data-v3/exports/v3/features.jsonl")
SPLIT = REPO / "ml" / "data-manifests" / "v3" / "split.json"
RECORDS = Path("/tmp/packagegate-ml-data-v3/manifests/dataset_v3_full.private.json")
PAIRS = REPO / "ml" / "data-manifests" / "v3" / "pairs.json"
GATE_DEF = REPO / "ml" / "data-manifests" / "v3" / "neural_gate_definition.json"
RUNS = REPO / "ml" / "runs"
FROZEN = REPO / "ml" / "data-manifests" / "v3"


def _git() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def load_rows(path: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            rows[r["sample_id"]] = r
    return rows


def binlab(label: str) -> int:
    return 1 if label in {"MALICIOUS", "COMPROMISED", "SYNTHETIC_SUSPICIOUS"} else 0


def feat_mode(mode: str, row: dict, rec) -> dict[str, float]:
    name = (rec.package_name if rec else None) or row.get("package_name") or ""
    ver = (rec.version if rec else None) or row.get("version") or ""
    src = (rec.dataset_source if rec else None) or row.get("dataset_source")
    structured = row.get("structured") or row.get("features") or {}
    if mode == "PACKAGE_NAME_LEXICAL_ONLY":
        return package_name_lexical_features(name, ver)
    if mode == "VERSION_ONLY":
        return version_only_features(ver)
    if mode == "ARTIFACT_STRUCTURE_ONLY":
        return structure_nuisance_features(structured)
    if mode == "GENERIC_METADATA_ONLY":
        return generic_metadata_v3(package_name=name, version=ver, structured=structured)
    if mode == "SOURCE_ONLY":
        return source_one_hot(src)
    if mode == "OPAQUE_RANDOM_ID":
        return opaque_random_id_features(row["sample_id"], seed=0)
    if mode == "BEHAVIOUR_ONLY":
        return behaviour_features(structured)
    raise ValueError(mode)


def matrix(ids, rows, records, mode, *, keys=None, shuffle=False, seed=0):
    dicts = []
    ys = []
    used = []
    for sid in ids:
        row = rows.get(sid)
        if row is None:
            continue
        used.append(sid)
        dicts.append(feat_mode(mode, row, records.get(sid)))
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


def eval_mode(mode, tr, va, te, rows, records) -> dict:
    keys, xtr, ytr, _ = matrix(tr, rows, records, mode)
    _, xva, yva, _ = matrix(va, rows, records, mode, keys=keys)
    _, xte, yte, te_ids = matrix(te, rows, records, mode, keys=keys)
    prev = float(yte.mean()) if len(yte) else 0.0
    out = {
        "mode": mode,
        "nFeatures": len(keys),
        "trainN": int(len(ytr)),
        "testN": int(len(yte)),
        "positivePrevalenceTest": prev,
        "prAucChanceBaseline": prev,
    }
    if len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        out["pr_auc"] = None
        out["skipped"] = True
        return out
    _, pva = fit_predict("logistic_regression", xtr, ytr, xva)
    thr = (
        select_threshold_for_fpr(yva, pva, 0.05)
        if len(set(yva.tolist())) > 1
        else 0.5
    )
    model, pte = fit_predict("logistic_regression", xtr, ytr, xte)
    out.update(metrics_at_threshold(yte, pte, thr))
    out["validationThresholdFor5pctFpr"] = thr
    out["testRecallAt5pctFprOperatingPoint"] = recall_at_fpr(yte, pte, 0.05)
    # coefficients for nuisance modes
    if mode in {"ARTIFACT_STRUCTURE_ONLY", "GENERIC_METADATA_ONLY", "PACKAGE_NAME_LEXICAL_ONLY"}:
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
            {"feature": k, "coef": float(c)} for k, c in ranked[:12]
        ]
    out["topFalsePositives"] = top_errors(te_ids, yte, pte, positive=False, limit=5)
    out["topFalseNegatives"] = top_errors(te_ids, yte, pte, positive=True, limit=5)
    return out


def bootstrap_pr_auc(y, proba, n=200, seed=0) -> dict:
    rng = np.random.default_rng(seed)
    y = np.asarray(y)
    proba = np.asarray(proba)
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
        "nBoot": len(scores),
    }


def pg_delta_eval(rows, pairs, split) -> dict:
    def part(sid: str) -> str | None:
        if sid in split["train"]:
            return "train"
        if sid in split["validation"]:
            return "validation"
        if sid in split["test"]:
            return "test"
        return None

    buckets = {"train": [], "validation": [], "test": []}
    usable_pos = 0
    usable_neg = 0
    examples_pos = []
    examples_neg = []
    for p in pairs:
        a = rows.get(p["clean_sample_id"])
        b = rows.get(p["compromised_sample_id"])
        if not a or not b:
            continue
        label = p.get("pair_label") or p.get("label") or "COMPROMISE_INTRODUCED"
        y = 1 if label == "COMPROMISE_INTRODUCED" else 0
        if y == 1:
            usable_pos += 1
        else:
            usable_neg += 1
        fa = a.get("structured") or a.get("features") or {}
        fb = b.get("structured") or b.get("features") or {}
        delta = behaviour_delta_features(fa, fb)
        # Assign by family of either member
        which = part(p["compromised_sample_id"]) or part(p["clean_sample_id"])
        if which is None:
            continue
        buckets[which].append((delta, y, p))
        if y == 1 and len(examples_pos) < 3:
            examples_pos.append(
                {
                    "pair_id": p.get("pair_id"),
                    "clean": p["clean_sample_id"],
                    "compromised": p["compromised_sample_id"],
                    "deltaHighlights": {
                        k: delta[k]
                        for k in sorted(delta)
                        if k.startswith("new:") and delta[k] > 0
                    },
                }
            )
        if y == 0 and len(examples_neg) < 3:
            examples_neg.append(
                {
                    "pair_id": p.get("pair_id"),
                    "before": p["clean_sample_id"],
                    "after": p["compromised_sample_id"],
                }
            )

    def stack(items, keys=None):
        dicts = [d for d, _, _ in items]
        ys = np.array([y for _, y, _ in items], dtype=np.int64)
        if keys is None:
            keys, x = align_feature_matrix(dicts)
        else:
            x = np.zeros((len(dicts), len(keys)))
            for i, d in enumerate(dicts):
                for j, k in enumerate(keys):
                    x[i, j] = float(d.get(k, 0.0))
        return keys, x, ys

    counts = {k: len(v) for k, v in buckets.items()}
    if len(buckets["train"]) < 10 or len(buckets["test"]) < 5:
        return {
            "skipped": True,
            "reason": "insufficient_pairs_in_split",
            "counts": counts,
            "usablePositivePairsWithFeatures": usable_pos,
            "usableNegativePairsWithFeatures": usable_neg,
            "examplesPositive": examples_pos,
            "examplesNegative": examples_neg,
        }
    keys, xtr, ytr = stack(buckets["train"])
    _, xte, yte = stack(buckets["test"], keys=keys)
    if len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        return {
            "skipped": True,
            "reason": "single_class",
            "counts": counts,
            "usablePositivePairsWithFeatures": usable_pos,
            "usableNegativePairsWithFeatures": usable_neg,
        }
    results = {
        "counts": counts,
        "usablePositivePairsWithFeatures": usable_pos,
        "usableNegativePairsWithFeatures": usable_neg,
    }
    if buckets["validation"] and len(set(y for _, y, _ in buckets["validation"])) > 1:
        _, xva, yva = stack(buckets["validation"], keys=keys)
    else:
        xva, yva = xtr, ytr
    for model_name in ("logistic_regression", "hist_gradient_boosting"):
        _, pva = fit_predict(model_name, xtr, ytr, xva)
        thr = select_threshold_for_fpr(yva, pva, 0.05)
        _, pte = fit_predict(model_name, xtr, ytr, xte)
        m = metrics_at_threshold(yte, pte, thr)
        m["brier"] = float(brier_score_loss(yte, pte))
        m["prAucBootstrap"] = bootstrap_pr_auc(yte, pte)
        m["positivePrevalenceTest"] = float(yte.mean())
        results[model_name] = m
    results["examplesPositive"] = examples_pos
    results["examplesNegative"] = examples_neg
    return results


def source_proxy_analysis(rows, records, split) -> dict:
    """Predict dataset_source from feature families (diagnostic only)."""
    out = {}
    for mode in ("ARTIFACT_STRUCTURE_ONLY", "GENERIC_METADATA_ONLY", "BEHAVIOUR_ONLY"):
        keys, xtr, _, _ = matrix(split["train"], rows, records, mode)
        # rebuild y as source
        ytr = []
        xtr_list = []
        for sid in split["train"]:
            row = rows.get(sid)
            rec = records.get(sid)
            if not row or not rec:
                continue
            xtr_list.append(feat_mode(mode, row, rec))
            ytr.append(1 if rec.dataset_source == "datadog" else 0)
        yte = []
        xte_list = []
        for sid in split["test"]:
            row = rows.get(sid)
            rec = records.get(sid)
            if not row or not rec:
                continue
            xte_list.append(feat_mode(mode, row, rec))
            yte.append(1 if rec.dataset_source == "datadog" else 0)
        keys, xtr = align_feature_matrix(xtr_list)
        xte = np.zeros((len(xte_list), len(keys)))
        for i, d in enumerate(xte_list):
            for j, k in enumerate(keys):
                xte[i, j] = float(d.get(k, 0.0))
        ytr_a = np.array(ytr)
        yte_a = np.array(yte)
        if len(set(ytr_a.tolist())) < 2 or len(set(yte_a.tolist())) < 2:
            out[mode] = {"skipped": True}
            continue
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
        pipe.fit(xtr, ytr_a)
        proba = pipe.predict_proba(xte)[:, 1]
        coef = pipe.named_steps["c"].coef_[0]
        ranked = sorted(zip(keys, coef, strict=True), key=lambda t: abs(t[1]), reverse=True)
        out[mode] = {
            "target": "dataset_source==datadog",
            "pr_auc": float(average_precision_score(yte_a, proba)),
            "prevalence": float(yte_a.mean()),
            "topCoefficients": [
                {"feature": k, "coef": float(c)} for k, c in ranked[:10]
            ],
        }
    return out


def main() -> None:
    for p in (FEATURES, SPLIT, RECORDS, PAIRS, GATE_DEF):
        if not p.exists():
            raise SystemExit(f"Missing {p}")

    gate = json.loads(GATE_DEF.read_text(encoding="utf-8"))
    rows = load_rows(FEATURES)
    split = json.loads(SPLIT.read_text(encoding="utf-8"))
    records = {r.sample_id: r for r in load_records(RECORDS)}
    pairs = json.loads(PAIRS.read_text(encoding="utf-8"))

    modes = [
        "PACKAGE_NAME_LEXICAL_ONLY",
        "VERSION_ONLY",
        "ARTIFACT_STRUCTURE_ONLY",
        "GENERIC_METADATA_ONLY",
        "SOURCE_ONLY",
        "OPAQUE_RANDOM_ID",
        "BEHAVIOUR_ONLY",
    ]
    mixed = {
        m: eval_mode(m, split["train"], split["validation"], split["test"], rows, records)
        for m in modes
    }

    # shuffled
    keys, xtr, ytr, _ = matrix(
        split["train"], rows, records, "BEHAVIOUR_ONLY", shuffle=True, seed=7
    )
    _, xte, yte, _ = matrix(split["test"], rows, records, "BEHAVIOUR_ONLY", keys=keys)
    shuffled = None
    if len(set(ytr.tolist())) > 1 and len(set(yte.tolist())) > 1:
        _, proba = fit_predict("logistic_regression", xtr, ytr, xte, seed=7)
        shuffled = {
            "pr_auc": float(average_precision_score(yte, proba)),
            "positivePrevalenceTest": float(yte.mean()),
        }

    # structure match
    match_report = structure_match(list(records.values()), rows, max_matches=2, max_distance=3.5)
    (FROZEN / "structure_matches.json").write_text(
        json.dumps(
            {
                "matches": [m.to_dict() for m in match_report.matches],
                "unmatched": match_report.unmatched_malicious,
                "beforeSMD": match_report.before_smd,
                "afterSMD": match_report.after_smd,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    matched_ids = set()
    for m in match_report.matches:
        matched_ids.add(m.malicious_sample_id)
        matched_ids.update(m.matched_benign_sample_ids)
    tr_m = [i for i in split["train"] if i in matched_ids]
    va_m = [i for i in split["validation"] if i in matched_ids]
    te_m = [i for i in split["test"] if i in matched_ids]
    matched = {
        "nMatches": len(match_report.matches),
        "nMatchedSamples": len(matched_ids),
        "unmatchedMalicious": len(match_report.unmatched_malicious),
        "sizes": {"train": len(tr_m), "validation": len(va_m), "test": len(te_m)},
        "beforeSMD": match_report.before_smd,
        "afterSMD": match_report.after_smd,
        "modes": {
            m: eval_mode(m, tr_m, va_m, te_m, rows, records)
            for m in modes
            if m != "SOURCE_ONLY"
        },
    }

    # same-package compromised classification (available compromised + adjacent controls)
    same_pkg_ids = [
        r.sample_id
        for r in records.values()
        if r.available
        and r.sample_id in rows
        and (
            r.attack_category == "compromised_lib"
            or r.hard_negative_category == "compromised_version_control"
        )
    ]
    same_pkg = {
        "n": len(same_pkg_ids),
        "modes": {
            m: eval_mode(
                m,
                [i for i in split["train"] if i in set(same_pkg_ids)],
                [i for i in split["validation"] if i in set(same_pkg_ids)],
                [i for i in split["test"] if i in set(same_pkg_ids)],
                rows,
                records,
            )
            for m in ("BEHAVIOUR_ONLY", "ARTIFACT_STRUCTURE_ONLY", "PACKAGE_NAME_LEXICAL_ONLY")
        },
    }

    pg_delta = pg_delta_eval(rows, pairs, split)
    source_proxy = source_proxy_analysis(rows, records, split)

    # multi-seed behaviour on matched if possible else mixed
    multi = []
    all_recs = list(records.values())
    for seed in (1, 2, 3, 4, 5):
        sp = grouped_split(all_recs, seed=seed)
        ids = matched_ids if len(matched_ids) >= 80 else None
        if ids:
            tr = [i for i in sp.train if i in ids]
            va = [i for i in sp.validation if i in ids]
            te = [i for i in sp.test if i in ids]
        else:
            tr, va, te = sp.train, sp.validation, sp.test
        m = eval_mode("BEHAVIOUR_ONLY", tr, va, te, rows, records)
        multi.append({"seed": seed, "pr_auc": m.get("pr_auc"), "testN": m.get("testN")})

    # Gate
    name_m = (matched["modes"].get("PACKAGE_NAME_LEXICAL_ONLY") or {}).get("pr_auc")
    struct_m = (matched["modes"].get("ARTIFACT_STRUCTURE_ONLY") or {}).get("pr_auc")
    meta_m = (matched["modes"].get("GENERIC_METADATA_ONLY") or {}).get("pr_auc")
    beh_m = (matched["modes"].get("BEHAVIOUR_ONLY") or {}).get("pr_auc")
    prev_m = (matched["modes"].get("BEHAVIOUR_ONLY") or {}).get("positivePrevalenceTest") or 0.0
    opaque = mixed.get("OPAQUE_RANDOM_ID") or {}
    reasons = []
    passed = True

    def fail(r: str) -> None:
        nonlocal passed
        passed = False
        reasons.append(r)

    if matched["nMatchedSamples"] < gate["min_matched_samples"]:
        fail("matched_benchmark_too_small")
    if name_m is not None and name_m > gate["max_name_lexical_matched"]:
        fail("name_lexical_matched_too_high")
    if struct_m is not None and struct_m > prev_m + gate["max_artifact_structure_matched_over_prevalence"]:
        fail("artifact_structure_matched_too_high")
    if meta_m is not None and meta_m > gate["max_generic_metadata_matched"]:
        fail("generic_metadata_matched_too_high")
    if (
        beh_m is not None
        and meta_m is not None
        and (beh_m - meta_m) < gate["min_behaviour_minus_nuisance_matched"]
    ):
        fail("behaviour_not_above_nuisance_matched")
    if shuffled and shuffled["pr_auc"] > gate["max_shuffled_pr_auc"]:
        fail("shuffled_too_high")
    if opaque.get("pr_auc") is not None and opaque["pr_auc"] > (
        opaque.get("positivePrevalenceTest") or 0
    ) + gate["max_opaque_over_prevalence"]:
        fail("opaque_random_too_high")
    if pg_delta.get("usablePositivePairsWithFeatures", 0) < gate[
        "min_pg_delta_positive_pairs_with_features"
    ]:
        fail("pg_delta_positives_too_few")
    if pg_delta.get("usableNegativePairsWithFeatures", 0) < gate[
        "min_pg_delta_negative_pairs_with_features"
    ]:
        fail("pg_delta_negatives_too_few")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-structured-v3")
    metadata = {
        "runId": run_id,
        "task": "structured_baseline_v3",
        "gitCommit": _git(),
        "datasetVersion": "v3",
        "hardware": collect_system_info(),
        "metrics": {
            "mixed": mixed,
            "matched": matched,
            "samePackageCompromised": same_pkg,
            "pgDelta": pg_delta,
            "sourceProxy": source_proxy,
            "shuffledLabelBehaviour": shuffled,
            "multiSeedBehaviour": multi,
            "v2NuisanceAuditNote": {
                "dominantStructureFeature": "hasPreinstall",
                "correction": "V3 ARTIFACT_STRUCTURE_ONLY excludes lifecycle hooks",
            },
        },
        "neuralTrainingGate": {
            "passed": passed,
            "reasons": reasons,
            "definition": gate,
            "observed": {
                "matchedN": matched["nMatchedSamples"],
                "nameLexicalMatched": name_m,
                "artifactStructureMatched": struct_m,
                "genericMetadataMatched": meta_m,
                "behaviourMatched": beh_m,
                "matchedPrevalence": prev_m,
                "shuffled": shuffled,
                "opaque": opaque.get("pr_auc"),
                "pgDeltaPos": pg_delta.get("usablePositivePairsWithFeatures"),
                "pgDeltaNeg": pg_delta.get("usableNegativePairsWithFeatures"),
                "sourceOnlyMixed": (mixed.get("SOURCE_ONLY") or {}).get("pr_auc"),
            },
        },
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "torchInstalled": False,
    }
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata["neuralTrainingGate"], indent=2))
    print(
        json.dumps(
            {
                "mixed": {k: v.get("pr_auc") for k, v in mixed.items()},
                "matched": {
                    k: (v or {}).get("pr_auc") for k, v in matched["modes"].items()
                },
                "matchedN": matched["nMatchedSamples"],
                "pgDelta": {
                    "pos": pg_delta.get("usablePositivePairsWithFeatures"),
                    "neg": pg_delta.get("usableNegativePairsWithFeatures"),
                    "counts": pg_delta.get("counts"),
                    "logistic": (pg_delta.get("logistic_regression") or {}).get("pr_auc"),
                },
                "sourceProxy": {
                    k: (v or {}).get("pr_auc") for k, v in source_proxy.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
