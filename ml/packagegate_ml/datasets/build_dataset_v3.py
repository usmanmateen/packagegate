"""Build Dataset V3: canonical artefacts, expanded pairs, frozen manifests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections import Counter
from pathlib import Path

os.environ.setdefault("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data-v3")

from packagegate_ml.datasets.audit_splits import audit_splits
from packagegate_ml.datasets.canonical import canonicalise_artifact
from packagegate_ml.datasets.dedup import (
    apply_duplicate_groups,
    cluster_duplicates,
    write_duplicate_report,
)
from packagegate_ml.datasets.pair_expansion import (
    build_negative_version_pairs,
    expand_positive_pairs,
)
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

REPO = Path(__file__).resolve().parents[3]
FROZEN = REPO / "ml" / "data-manifests" / "v3"
V2_PRIVATE = Path("/tmp/packagegate-ml-data-v2/manifests/dataset_v2_full.private.json")
V2_CROSS = REPO / "ml" / "data-manifests" / "v2" / "cross_label_duplicates.json"


def _canonical_root() -> Path:
    path = data_root() / "canonical"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_name(sample_id: str) -> str:
    return sample_id.replace("/", "_").replace(":", "_")


def load_v2_seed() -> list[DatasetRecord]:
    if not V2_PRIVATE.exists():
        raise SystemExit(f"Missing V2 private manifest: {V2_PRIVATE}")
    return load_records(V2_PRIVATE)


def ambiguous_sample_ids() -> set[str]:
    if not V2_CROSS.exists():
        return set()
    rows = json.loads(V2_CROSS.read_text(encoding="utf-8"))
    out: set[str] = set()
    for row in rows:
        out.update(row.get("sample_ids") or [])
    return out


def canonicalise_records(records: list[DatasetRecord]) -> list[DatasetRecord]:
    out: list[DatasetRecord] = []
    failures: list[dict] = []
    canon_dir = _canonical_root()
    for rec in records:
        if not rec.available:
            out.append(rec)
            continue
        src = Path(rec.artifact_path or rec.artifact_path_external or "")
        if not src.exists():
            failures.append({"sample_id": rec.sample_id, "reason": "missing_source"})
            out.append(
                DatasetRecord(**{**rec.__dict__, "available": False, "notes": rec.notes + "; V3 missing source"})
            )
            continue
        dest = canon_dir / f"{_safe_name(rec.sample_id)}.tgz"
        try:
            if not dest.exists():
                sha = canonicalise_artifact(src, dest, work_dir=scratch_root() / "canon" / _safe_name(rec.sample_id))
            else:
                sha = hashlib.sha256(dest.read_bytes()).hexdigest()
        except Exception as exc:  # noqa: BLE001
            failures.append({"sample_id": rec.sample_id, "reason": f"canon:{exc}"})
            out.append(
                DatasetRecord(**{**rec.__dict__, "available": False, "notes": rec.notes + f"; canon_fail:{exc}"})
            )
            continue
        out.append(
            DatasetRecord(
                **{
                    **rec.__dict__,
                    "artifact_path": str(dest),
                    "artifact_path_external": str(dest),
                    "artifact_sha256": sha,
                    "notes": (rec.notes + "; canonical_v3").strip("; "),
                }
            )
        )
        if len(out) % 50 == 0:
            print(json.dumps({"canonicalised": sum(1 for r in out if r.available)}))
    (scratch_root() / "canonical_failures.json").write_text(
        json.dumps(failures, indent=2), encoding="utf-8"
    )
    return out


def main() -> None:
    print(json.dumps({"data_root": str(data_root()), "phase": "seed_v2"}))
    # Copy V2 datadog index into V3 scratch for pair expansion helpers
    v2_idx = Path("/tmp/packagegate-ml-data-v2/scratch/datadog_npm_zip_index.json")
    if v2_idx.exists():
        shutil.copy(v2_idx, scratch_root() / "datadog_npm_zip_index.json")

    records = load_v2_seed()
    amb = ambiguous_sample_ids()
    # Mark ambiguous cross-label near-dups unavailable for automatic training
    cleaned: list[DatasetRecord] = []
    for rec in records:
        if rec.sample_id in amb:
            cleaned.append(
                DatasetRecord(
                    **{
                        **rec.__dict__,
                        "available": False,
                        "notes": rec.notes + "; EXCLUDED_CROSS_LABEL_NEAR_DUP",
                        "benchmark_tags": tuple(
                            t for t in rec.benchmark_tags if t != "compromised_version"
                        ),
                    }
                )
            )
        else:
            cleaned.append(rec)
    records = cleaned

    print(json.dumps({"phase": "canonicalise", "n": len(records)}))
    records = canonicalise_records(records)

    print(json.dumps({"phase": "expand_positive_pairs"}))
    pos_pairs, pos_new = expand_positive_pairs(records, max_pairs=160)
    # Canonicalise newly downloaded adjacent cleans
    if pos_new:
        pos_new = canonicalise_records(pos_new)
    records = [*records, *pos_new]

    print(json.dumps({"phase": "negative_pairs", "positives": len(pos_pairs)}))
    neg_pairs, neg_new = build_negative_version_pairs(
        records, pos_pairs, max_negatives=120
    )
    if neg_new:
        neg_new = canonicalise_records(neg_new)
    records = [*records, *neg_new]

    # Dedup + family unify
    report = cluster_duplicates(records)
    records = apply_duplicate_groups(records, report)
    write_duplicate_report(scratch_root() / "duplicates_v3.json", report)

    # Recompute cross-label after dedup
    by_dup: dict[str, list] = {}
    for rec in records:
        if rec.duplicate_group_id:
            by_dup.setdefault(rec.duplicate_group_id, []).append(rec)
    ambiguous = []
    for gid, members in by_dup.items():
        labels = {m.label for m in members}
        if SampleLabel.EXPECTED_BENIGN in labels and labels & {
            SampleLabel.MALICIOUS,
            SampleLabel.COMPROMISED,
        }:
            ambiguous.append(
                {
                    "duplicate_group_id": gid,
                    "sample_ids": [m.sample_id for m in members],
                    "labels": [m.label.value for m in members],
                }
            )

    split = grouped_split(records, seed=42)
    # Ensure 02-echo holdout
    assert "02-echo@0.0.7" not in split.train
    assert "02-echo@0.0.7" not in split.validation
    audit = audit_splits(records, split)
    if not audit.get("passed"):
        raise SystemExit(f"Leakage audit failed: {audit}")

    write_manifest(
        external_manifests_root() / "dataset_v3_full.private.json",
        records,
        include_package_name=True,
    )
    write_manifest(
        external_manifests_root() / "dataset_v3_full.json",
        records,
        include_package_name=False,
    )
    hashes = write_frozen_split_files(FROZEN, records, split)

    all_pairs = [
        {**p.to_dict(), "pair_label": p.label} for p in [*pos_pairs, *neg_pairs]
    ]
    (FROZEN / "pairs.json").write_text(
        json.dumps(all_pairs, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (FROZEN / "cross_label_duplicates.json").write_text(
        json.dumps(ambiguous, indent=2) + "\n", encoding="utf-8"
    )
    (FROZEN / "excluded_cross_label_v2.json").write_text(
        json.dumps(sorted(amb), indent=2) + "\n", encoding="utf-8"
    )

    available = [r for r in records if r.available]
    summary = {
        "total": len(records),
        "available": len(available),
        "labels": dict(Counter(r.label.value for r in records)),
        "available_labels": dict(Counter(r.label.value for r in available)),
        "attack_categories": dict(
            Counter(r.attack_category for r in available if r.attack_category)
        ),
        "positive_compromise_pairs": len(pos_pairs),
        "negative_version_pairs": len(neg_pairs),
        "exact_dup_groups": len(report.exact_artifact_groups),
        "near_dup_groups": len(report.near_duplicate_groups),
        "cross_label_duplicate_groups": len(ambiguous),
        "excluded_cross_label_samples": len(amb),
        "split": {
            "train": len(split.train),
            "validation": len(split.validation),
            "test": len(split.test),
            "holdout": len(split.holdout),
        },
        "hashes": hashes,
        "audit_passed": audit.get("passed"),
        "canonical": True,
        "note_02_echo": "02-echo@0.0.7" in MALWARE_QUALITATIVE_HOLDOUT_IDS,
    }
    (external_manifests_root() / "dataset_v3_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    (FROZEN / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    # Pre-registered gate (numeric thresholds fixed before evaluation)
    gate_def = {
        "max_name_lexical_matched": 0.80,
        "max_artifact_structure_matched_over_prevalence": 0.20,
        "max_generic_metadata_matched": 0.80,
        "min_behaviour_minus_nuisance_matched": 0.05,
        "max_shuffled_pr_auc": 0.75,
        "max_opaque_over_prevalence": 0.25,
        "min_matched_samples": 80,
        "min_pg_delta_positive_pairs_with_features": 60,
        "min_pg_delta_negative_pairs_with_features": 40,
        "require_canonical_processing": True,
        "source_only_not_a_gate": True,
        "source_only_note": (
            "SOURCE_ONLY may be ~1.0 by construction; gate uses matched "
            "structure/metadata/name proxies instead."
        ),
    }
    (FROZEN / "neural_gate_definition.json").write_text(
        json.dumps(gate_def, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    print(json.dumps({"gate_definition_frozen": gate_def}, indent=2))


if __name__ == "__main__":
    main()
