"""Build Dataset V2 under an external data root (default /tmp/packagegate-ml-data-v2)."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

# Force V2 data root before importing path helpers.
os.environ.setdefault("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data-v2")

from packagegate_ml.datasets.audit_splits import audit_splits
from packagegate_ml.datasets.benign_adapter import acquire_benign_pilot
from packagegate_ml.datasets.compromise_pairs import build_compromise_pairs
from packagegate_ml.datasets.datadog_adapter import acquire_datadog_pilot
from packagegate_ml.datasets.dedup import (
    apply_duplicate_groups,
    cluster_duplicates,
    write_duplicate_report,
)
from packagegate_ml.datasets.matching import match_malicious_to_benign
from packagegate_ml.datasets.openssf_adapter import fetch_openssf_npm_metadata_sample
from packagegate_ml.datasets.paths import external_manifests_root, scratch_root
from packagegate_ml.datasets.schema import SampleLabel
from packagegate_ml.datasets.splits import (
    grouped_split,
    write_frozen_split_files,
    write_manifest,
)

REPO = Path(__file__).resolve().parents[3]
FROZEN = REPO / "ml" / "data-manifests" / "v2"


def _parse_category_from_notes(notes: str) -> str | None:
    if "category=compromised_lib" in notes:
        return "compromised_lib"
    if "category=malicious_intent" in notes:
        return "malicious_intent"
    return None


def main() -> None:
    print(json.dumps({"data_root": os.environ["PACKAGEGATE_ML_DATA_ROOT"]}))

    # Balanced malicious mix: compromised_lib + malicious_intent
    datadog = acquire_datadog_pilot(
        max_samples=280,
        max_per_family=1,
        seed=42,
        category_quotas={"compromised_lib": 140, "malicious_intent": 140},
    )

    benign = acquire_benign_pilot(max_samples=900)
    openssf = fetch_openssf_npm_metadata_sample(limit=40)

    records = [*datadog, *benign, *openssf]

    pairs, adjacent = build_compromise_pairs(records, max_pairs=100, max_clean_per_compromised=2)
    records.extend(adjacent)

    report = cluster_duplicates(records)
    records = apply_duplicate_groups(records, report)
    write_duplicate_report(scratch_root() / "duplicates_v2.json", report)

    # Cross-label duplicate flag
    by_dup: dict[str, list] = {}
    for rec in records:
        if rec.duplicate_group_id:
            by_dup.setdefault(rec.duplicate_group_id, []).append(rec)
    ambiguous = []
    for gid, members in by_dup.items():
        labels = {m.label for m in members}
        if SampleLabel.EXPECTED_BENIGN in labels and (
            SampleLabel.MALICIOUS in labels or SampleLabel.COMPROMISED in labels
        ):
            ambiguous.append(
                {
                    "duplicate_group_id": gid,
                    "sample_ids": [m.sample_id for m in members],
                    "labels": [m.label.value for m in members],
                }
            )
            for m in members:
                # Keep out of automatic training via holdout-like unavailability? Flag only.
                object.__setattr__(
                    m,
                    "notes",
                    (m.notes + "; CROSS_LABEL_DUPLICATE").strip("; "),
                )

    match_report = match_malicious_to_benign(records, max_matches_per_malicious=2)
    matches_path = external_manifests_root() / "dataset_v2_matches.json"
    matches_path.write_text(
        json.dumps(
            {
                "matches": [m.to_dict() for m in match_report.matches],
                "unmatched_malicious": match_report.unmatched_malicious,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    pairs_path = external_manifests_root() / "dataset_v2_compromise_pairs.json"
    pairs_path.write_text(
        json.dumps([p.to_dict() for p in pairs], indent=2) + "\n", encoding="utf-8"
    )

    # Benchmark membership manifests (sample IDs only)
    compromised_ids = [
        r.sample_id
        for r in records
        if r.available
        and (
            r.attack_category == "compromised_lib"
            or "compromised_version" in r.benchmark_tags
            or r.hard_negative_category == "compromised_version_control"
        )
    ]
    # Include pair members
    for p in pairs:
        compromised_ids.extend([p.clean_sample_id, p.compromised_sample_id])
    compromised_ids = sorted(set(compromised_ids))

    matched_ids: list[str] = []
    for m in match_report.matches:
        matched_ids.append(m.malicious_sample_id)
        matched_ids.extend(m.matched_benign_sample_ids)
    matched_ids = sorted(set(matched_ids))

    mixed_ids = sorted({r.sample_id for r in records if r.available})

    benchmarks = {
        "compromised_version": compromised_ids,
        "matched_malicious_intent": matched_ids,
        "mixed_naturalistic": mixed_ids,
    }
    (external_manifests_root() / "dataset_v2_benchmarks.json").write_text(
        json.dumps(benchmarks, indent=2) + "\n", encoding="utf-8"
    )

    split = grouped_split(records, seed=42)
    audit = audit_splits(records, split)
    (scratch_root() / "audit_v2.json").write_text(
        json.dumps(audit, indent=2) + "\n", encoding="utf-8"
    )
    if not audit.get("passed"):
        raise SystemExit(f"Leakage audit failed: {audit}")

    private = external_manifests_root() / "dataset_v2_full.private.json"
    public = external_manifests_root() / "dataset_v2_full.json"
    write_manifest(private, records, include_package_name=True)
    write_manifest(public, records, include_package_name=False)

    hashes = write_frozen_split_files(FROZEN, records, split)
    (FROZEN / "benchmarks.json").write_text(
        json.dumps(benchmarks, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (FROZEN / "compromise_pairs.json").write_text(
        json.dumps([p.to_dict() for p in pairs], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (FROZEN / "matches.json").write_text(
        json.dumps(
            {
                "matches": [m.to_dict() for m in match_report.matches],
                "unmatched_malicious": match_report.unmatched_malicious,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (FROZEN / "cross_label_duplicates.json").write_text(
        json.dumps(ambiguous, indent=2) + "\n", encoding="utf-8"
    )

    labels = Counter(r.label.value for r in records)
    available = [r for r in records if r.available]
    summary = {
        "total": len(records),
        "available": len(available),
        "labels": dict(labels),
        "available_labels": dict(Counter(r.label.value for r in available)),
        "attack_categories": dict(
            Counter(r.attack_category for r in available if r.attack_category)
        ),
        "hard_negative_categories": dict(
            Counter(
                r.hard_negative_category for r in available if r.hard_negative_category
            )
        ),
        "exact_dup_groups": len(report.exact_artifact_groups),
        "near_dup_groups": len(report.near_duplicate_groups),
        "cross_label_duplicate_groups": len(ambiguous),
        "compromise_pairs": len(pairs),
        "morphology_matches": len(match_report.matches),
        "unmatched_malicious_intent": len(match_report.unmatched_malicious),
        "split": {
            "train": len(split.train),
            "validation": len(split.validation),
            "test": len(split.test),
            "holdout": len(split.holdout),
        },
        "benchmark_sizes": {k: len(v) for k, v in benchmarks.items()},
        "hashes": hashes,
        "audit_passed": audit.get("passed"),
    }
    (external_manifests_root() / "dataset_v2_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    (FROZEN / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
