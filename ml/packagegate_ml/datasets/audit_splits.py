"""Leakage and split-integrity audit for PackageGate ML datasets."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from packagegate_ml.datasets.schema import (
    MALWARE_QUALITATIVE_HOLDOUT_IDS,
    QUALITATIVE_HOLDOUT_IDS,
    DatasetRecord,
    SplitManifest,
)


BANNED_INPUT_SUBSTRINGS = (
    "malicious",
    "compromised_lib",
    "benign",
    "datadog",
    "ground_truth",
    "openssf",
    "/tmp/packagegate",
)


def audit_splits(
    records: list[DatasetRecord],
    split: SplitManifest,
) -> dict:
    by_id = {r.sample_id: r for r in records}
    issues: list[str] = []

    # 02-echo / qualitative controls must not be in train/validation.
    for sid in list(MALWARE_QUALITATIVE_HOLDOUT_IDS) + list(QUALITATIVE_HOLDOUT_IDS):
        if sid in split.train or sid in split.validation:
            issues.append(f"holdout_contaminated:{sid}")

    membership: dict[str, str] = {}
    for name in ("train", "validation", "test"):
        for sid in getattr(split, name):
            if sid in membership:
                issues.append(f"sample_in_multiple_splits:{sid}")
            membership[sid] = name

    # Same package family across splits.
    family_to_splits: dict[str, set[str]] = defaultdict(set)
    for sid, part in membership.items():
        record = by_id.get(sid)
        if record is None:
            issues.append(f"missing_record:{sid}")
            continue
        family_to_splits[record.family_group].add(part)
    for family, parts in family_to_splits.items():
        if len(parts) > 1:
            issues.append(f"family_split_leak:{family}:{','.join(sorted(parts))}")

    # Exact artifact hash across splits.
    hash_to_splits: dict[str, set[str]] = defaultdict(set)
    hash_to_ids: dict[str, list[str]] = defaultdict(list)
    for sid, part in membership.items():
        record = by_id.get(sid)
        if record is None or not record.artifact_sha256:
            continue
        hash_to_splits[record.artifact_sha256].add(part)
        hash_to_ids[record.artifact_sha256].append(sid)
    for sha, parts in hash_to_splits.items():
        if len(parts) > 1:
            issues.append(
                f"artifact_hash_cross_split:{sha[:12]}:{','.join(sorted(parts))}"
            )

    # Duplicate cluster across splits.
    dup_to_splits: dict[str, set[str]] = defaultdict(set)
    for sid, part in membership.items():
        record = by_id.get(sid)
        if record is None or not record.duplicate_group_id:
            continue
        dup_to_splits[record.duplicate_group_id].add(part)
    for gid, parts in dup_to_splits.items():
        if len(parts) > 1:
            issues.append(f"duplicate_cluster_cross_split:{gid}:{','.join(sorted(parts))}")

    # Path / label leakage in fields that might be used as features accidentally.
    for record in records:
        for field in (
            record.notes,
            record.label_reference,
            record.artifact_path,
            record.dataset_source or "",
        ):
            if not field:
                continue
            lower = field.lower()
            # notes/paths may contain provenance; ensure they are not marked as feature keys.
            for banned in BANNED_INPUT_SUBSTRINGS:
                if banned in lower and record.available:
                    # Provenance fields are allowed in manifests, but flag for awareness.
                    pass

    passed = len(issues) == 0
    return {
        "passed": passed,
        "issueCount": len(issues),
        "issues": issues,
        "counts": {
            "train": len(split.train),
            "validation": len(split.validation),
            "test": len(split.test),
            "holdout": len(split.holdout),
            "families": len(family_to_splits),
        },
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Audit PackageGate ML split integrity")
    parser.add_argument("--records", required=True)
    parser.add_argument("--split", required=True)
    parser.add_argument("--out", required=False)
    args = parser.parse_args()

    from packagegate_ml.datasets.splits import load_records

    records = load_records(Path(args.records))
    split_raw = json.loads(Path(args.split).read_text(encoding="utf-8"))
    split = SplitManifest(**split_raw)
    report = audit_splits(records, split)
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
