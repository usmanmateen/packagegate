"""Build Dataset V4 manifests: identity-masked views, rematch, PG-Delta pair split."""

from __future__ import annotations

import json
import os
import random
from collections import Counter, defaultdict
from pathlib import Path

os.environ.setdefault("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data-v4")

from packagegate_ml.datasets.audit_splits import audit_splits
from packagegate_ml.datasets.feature_families import matching_nuisance_vector
from packagegate_ml.datasets.paths import data_root, external_manifests_root, scratch_root
from packagegate_ml.datasets.schema import (
    MALWARE_QUALITATIVE_HOLDOUT_IDS,
    DatasetRecord,
    SampleLabel,
)
from packagegate_ml.datasets.splits import (
    grouped_split,
    load_records,
    write_frozen_split_files,
    write_manifest,
)
from packagegate_ml.datasets.structure_matching import MatchBalanceReport, StructureMatch
from packagegate_ml.training.shortcut_features import version_only_features
import numpy as np

REPO = Path(__file__).resolve().parents[3]
FROZEN = REPO / "ml" / "data-manifests" / "v4"
V3_PRIVATE = Path("/tmp/packagegate-ml-data-v3/manifests/dataset_v3_full.private.json")
V3_PAIRS = REPO / "ml" / "data-manifests" / "v3" / "pairs.json"
V3_FEATURES = Path("/tmp/packagegate-ml-data-v3/exports/v3/features.jsonl")
V3_EXCLUDED = REPO / "ml" / "data-manifests" / "v3" / "excluded_cross_label_v2.json"


def load_feature_rows(path: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            rows[r["sample_id"]] = r
    return rows


MATCH_KEYS_V4 = [
    "fileCount",
    "analysedExecutableBytes",
    "coverageRatio",
    "hasPreinstall",
    "hasInstall",
    "hasPostinstall",
    "lifecycleHookCount",
    "name_len",
    "scoped",
    "digit_fraction_name",
    "segment_count",
    "separator_count",
    "version_len",
    "version_component_count",
    "version_unusual_large",
    "version_is_zeroish",
    "version_has_prerelease",
    "version_major_bucket",
    "version_minor_bucket",
    "version_patch_bucket",
]


def _version_buckets(version: str) -> dict[str, float]:
    v = version_only_features(version)

    def bucket(x: float) -> float:
        if x <= 0:
            return 0.0
        if x == 1:
            return 1.0
        if x < 10:
            return 2.0
        if x < 100:
            return 3.0
        return 4.0

    return {
        **{k: v[k] for k in (
            "version_len",
            "version_component_count",
            "version_unusual_large",
            "version_is_zeroish",
            "version_has_prerelease",
        )},
        "version_major_bucket": bucket(v["version_major"]),
        "version_minor_bucket": bucket(v["version_minor"]),
        "version_patch_bucket": bucket(v["version_patch"]),
    }


def match_vector(rec: DatasetRecord, row: dict) -> np.ndarray:
    structured = row.get("structured") or row.get("features") or {}
    base = matching_nuisance_vector(
        package_name=rec.package_name or "",
        version=rec.version or "",
        structured=structured,
    )
    base.update(_version_buckets(rec.version or ""))
    return np.array([float(base.get(k, 0.0)) for k in MATCH_KEYS_V4], dtype=np.float64)


def structure_match_v4(
    records: list[DatasetRecord],
    feature_rows: dict[str, dict],
    *,
    max_matches: int = 2,
    # V4 distance space adds version-shape buckets vs V3; 4.5 recovers ≥250
    # matched samples while keeping version_unusual_large SMD near zero.
    max_distance: float = 4.5,
) -> MatchBalanceReport:
    malicious = [
        r
        for r in records
        if r.available
        and r.label in {SampleLabel.MALICIOUS, SampleLabel.COMPROMISED}
        and r.sample_id in feature_rows
        and "EXCLUDED_CROSS_LABEL" not in (r.notes or "")
    ]
    benign = [
        r
        for r in records
        if r.available
        and r.label == SampleLabel.EXPECTED_BENIGN
        and r.sample_id in feature_rows
        and r.hard_negative_category
        not in {"compromised_version_control", "negative_version_pair"}
    ]
    mal_recs, mal_x = [], []
    for r in malicious:
        mal_recs.append(r)
        mal_x.append(match_vector(r, feature_rows[r.sample_id]))
    ben_recs, ben_x = [], []
    for r in benign:
        ben_recs.append(r)
        ben_x.append(match_vector(r, feature_rows[r.sample_id]))
    if not mal_x or not ben_x:
        return MatchBalanceReport([], [r.sample_id for r in malicious], {}, {})
    mal_x_a = np.vstack(mal_x)
    ben_x_a = np.vstack(ben_x)
    all_x = np.vstack([mal_x_a, ben_x_a])
    mean, std = all_x.mean(0), all_x.std(0)
    std = np.where(std < 1e-8, 1.0, std)
    mal_s = (mal_x_a - mean) / std
    ben_s = (ben_x_a - mean) / std

    def smd(a, b):
        pooled = float(np.sqrt((a.var() + b.var()) / 2) or 1.0)
        return float((a.mean() - b.mean()) / pooled)

    before = {MATCH_KEYS_V4[i]: smd(mal_x_a[:, i], ben_x_a[:, i]) for i in range(len(MATCH_KEYS_V4))}
    used: set[int] = set()
    matches: list[StructureMatch] = []
    unmatched: list[str] = []
    for mi in sorted(range(len(mal_recs)), key=lambda i: mal_recs[i].sample_id):
        distances = [
            (float(np.linalg.norm(mal_s[mi] - ben_s[bi])), bi)
            for bi in range(len(ben_recs))
            if bi not in used
        ]
        distances.sort(key=lambda t: (t[0], ben_recs[t[1]].sample_id))
        chosen = []
        best = float("inf")
        for dist, bi in distances:
            if dist > max_distance or len(chosen) >= max_matches:
                break
            chosen.append(ben_recs[bi].sample_id)
            used.add(bi)
            best = min(best, dist)
        if not chosen:
            unmatched.append(mal_recs[mi].sample_id)
            continue
        matches.append(
            StructureMatch(
                malicious_sample_id=mal_recs[mi].sample_id,
                matched_benign_sample_ids=tuple(chosen),
                matching_distance=float(best),
                matching_features={
                    MATCH_KEYS_V4[i]: float(mal_x_a[mi, i]) for i in range(len(MATCH_KEYS_V4))
                },
            )
        )
    if matches:
        m_idx = [
            i
            for i, r in enumerate(mal_recs)
            if any(m.malicious_sample_id == r.sample_id for m in matches)
        ]
        b_ids = {sid for m in matches for sid in m.matched_benign_sample_ids}
        b_idx = [i for i, r in enumerate(ben_recs) if r.sample_id in b_ids]
        after = {
            MATCH_KEYS_V4[i]: smd(mal_x_a[m_idx, i], ben_x_a[b_idx, i])
            for i in range(len(MATCH_KEYS_V4))
        }
    else:
        after = {}
    return MatchBalanceReport(matches, unmatched, before, after)


def pair_family_split(
    pairs: list[dict],
    *,
    seed: int = 42,
    train_ratio: float = 0.6,
    val_ratio: float = 0.2,
) -> dict:
    """Family-grouped split over unique package families appearing in pairs."""
    by_family: dict[str, list[dict]] = defaultdict(list)
    for p in pairs:
        fam = p.get("family_group") or "unknown"
        # Prefer npm package identity from sample ids when family is fam::root
        if fam.startswith("fam::"):
            sid = p.get("compromised_sample_id") or p.get("clean_sample_id") or ""
            fam = sid.rsplit("@", 1)[0].lower() if sid else fam
        by_family[fam].append(p)
    families = sorted(by_family.keys())
    rng = random.Random(seed)
    rng.shuffle(families)
    n = len(families)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    train_f = set(families[:n_train])
    val_f = set(families[n_train : n_train + n_val])
    split = {"train": [], "validation": [], "test": [], "strategy": "pair_family_grouped", "seed": seed}
    for fam, members in by_family.items():
        ids = [m["pair_id"] for m in members]
        if fam in train_f:
            split["train"].extend(ids)
        elif fam in val_f:
            split["validation"].extend(ids)
        else:
            split["test"].extend(ids)
    for k in ("train", "validation", "test"):
        split[k] = sorted(split[k])
    split["familyCounts"] = {
        "total": n,
        "train": len(train_f),
        "validation": len(val_f),
        "test": n - len(train_f) - len(val_f),
    }
    return split


def main() -> None:
    print(json.dumps({"data_root": str(data_root()), "phase": "seed_v3"}))
    if not V3_PRIVATE.exists() or not V3_FEATURES.exists():
        raise SystemExit("Missing V3 private manifest or features — build V3 first")

    records = load_records(V3_PRIVATE)
    excluded = set()
    if V3_EXCLUDED.exists():
        excluded = set(json.loads(V3_EXCLUDED.read_text(encoding="utf-8")))
    # Also exclude notes-marked
    cleaned = []
    for r in records:
        if r.sample_id in excluded or "EXCLUDED_CROSS_LABEL" in (r.notes or ""):
            cleaned.append(
                DatasetRecord(
                    **{
                        **r.__dict__,
                        "available": False,
                        "notes": r.notes + "; V4_EXCLUDED_AMBIGUOUS",
                    }
                )
            )
        else:
            cleaned.append(r)
    records = cleaned
    feature_rows = load_feature_rows(V3_FEATURES)

    pairs = json.loads(V3_PAIRS.read_text(encoding="utf-8"))
    # Keep only pairs where both sides have features
    usable_pairs = [
        p
        for p in pairs
        if p["clean_sample_id"] in feature_rows
        and p["compromised_sample_id"] in feature_rows
    ]
    delta_split = pair_family_split(usable_pairs, seed=42)

    # Package-level split (reuse grouped)
    pkg_split = grouped_split(records, seed=42)
    assert "02-echo@0.0.7" not in pkg_split.train
    assert "02-echo@0.0.7" not in pkg_split.validation
    audit = audit_splits(records, pkg_split)
    if not audit.get("passed"):
        raise SystemExit(f"Leakage audit failed: {audit}")

    match_report = structure_match_v4(records, feature_rows)
    matched_ids = set()
    for m in match_report.matches:
        matched_ids.add(m.malicious_sample_id)
        matched_ids.update(m.matched_benign_sample_ids)

    FROZEN.mkdir(parents=True, exist_ok=True)
    write_manifest(
        external_manifests_root() / "dataset_v4_full.private.json",
        records,
        include_package_name=True,
    )
    write_manifest(
        external_manifests_root() / "dataset_v4_full.json",
        records,
        include_package_name=False,
    )
    hashes = write_frozen_split_files(FROZEN, records, pkg_split)

    (FROZEN / "pairs.json").write_text(
        json.dumps(usable_pairs, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (FROZEN / "pg_delta_split.json").write_text(
        json.dumps(delta_split, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (FROZEN / "structure_matches.json").write_text(
        json.dumps(
            {
                "matches": [m.to_dict() for m in match_report.matches],
                "unmatched": match_report.unmatched_malicious,
                "beforeSMD": match_report.before_smd,
                "afterSMD": match_report.after_smd,
                "matchedSampleIds": sorted(matched_ids),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # Pre-register gate BEFORE evaluation
    gate = {
        "max_strict_input_nuisance_over_prevalence": 0.20,
        "max_artifact_structure_matched_over_prevalence": 0.15,
        "max_version_only_matched": 0.75,
        "min_behaviour_minus_strict_nuisance": 0.05,
        "min_delta_behaviour_minus_delta_nuisance": 0.05,
        "max_shuffled_pr_auc": 0.75,
        "max_opaque_over_prevalence": 0.25,
        "min_matched_samples": 250,
        "min_pg_delta_positive": 100,
        "min_pg_delta_negative": 100,
        "min_pg_delta_test_pairs": 40,
        "require_strict_input_no_identity": True,
        "require_canonical_processing": True,
        "raw_name_lexical_not_a_gate": True,
        "source_only_not_a_gate": True,
        "note": (
            "Raw PACKAGE_NAME_LEXICAL may remain high as dataset bias. "
            "Gate requires identity absent from STRICT_SECURITY_VIEW and "
            "STRICT_INPUT_NUISANCE / DELTA_NUISANCE controlled."
        ),
    }
    (FROZEN / "neural_gate_definition.json").write_text(
        json.dumps(gate, indent=2) + "\n", encoding="utf-8"
    )

    pos = sum(1 for p in usable_pairs if (p.get("pair_label") or p.get("label")) == "COMPROMISE_INTRODUCED")
    neg = len(usable_pairs) - pos
    summary = {
        "seededFrom": "v3",
        "total": len(records),
        "available": sum(1 for r in records if r.available),
        "available_labels": dict(
            Counter(r.label.value for r in records if r.available)
        ),
        "matched_samples": len(matched_ids),
        "matched_pairs_malicious": len(match_report.matches),
        "unmatched_malicious": len(match_report.unmatched_malicious),
        "pg_delta_usable_pairs": len(usable_pairs),
        "pg_delta_positive": pos,
        "pg_delta_negative": neg,
        "pg_delta_split_counts": {
            k: len(delta_split[k]) for k in ("train", "validation", "test")
        },
        "pg_delta_family_counts": delta_split["familyCounts"],
        "package_split": {
            "train": len(pkg_split.train),
            "validation": len(pkg_split.validation),
            "test": len(pkg_split.test),
            "holdout": len(pkg_split.holdout),
        },
        "hashes": hashes,
        "audit_passed": audit.get("passed"),
        "02_echo_holdout": "02-echo@0.0.7" in MALWARE_QUALITATIVE_HOLDOUT_IDS,
    }
    (FROZEN / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (external_manifests_root() / "dataset_v4_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    print(json.dumps({"gate_definition_frozen": gate}, indent=2))


if __name__ == "__main__":
    main()
