"""Build a smoke dataset manifest from inert PackageGate fixtures.

This does NOT download malware. Real malicious samples must be supplied via an
external quarantine root and marked available=false until present.
"""

from __future__ import annotations

import json
from pathlib import Path

from packagegate_ml.datasets.schema import (
    DatasetRecord,
    SampleLabel,
    family_group_for,
    hash_package_name,
)
from packagegate_ml.datasets.splits import grouped_split, write_manifest, write_split

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = ROOT / "manifests"


def smoke_records() -> list[DatasetRecord]:
    fixtures = [
        ("inert-normal-installer", SampleLabel.EXPECTED_BENIGN, "fixture"),
        ("inert-shell-cooccurrence-negative", SampleLabel.EXPECTED_BENIGN, "fixture"),
        ("version-diff-benign-v1", SampleLabel.EXPECTED_BENIGN, "fixture"),
        ("version-diff-line-shift-v1", SampleLabel.EXPECTED_BENIGN, "fixture"),
        ("version-diff-line-shift-v2", SampleLabel.EXPECTED_BENIGN, "fixture"),
        ("inert-env-exfil", SampleLabel.SYNTHETIC_SUSPICIOUS, "fixture"),
        ("inert-install-curl-bash", SampleLabel.SYNTHETIC_SUSPICIOUS, "fixture"),
        ("inert-powershell-irm-iex", SampleLabel.SYNTHETIC_SUSPICIOUS, "fixture"),
        ("version-diff-remote-v2", SampleLabel.SYNTHETIC_SUSPICIOUS, "fixture"),
        # Distinct synthetic families for split diversity (duplicate labels OK).
        ("smoke-benign-a", SampleLabel.EXPECTED_BENIGN, "synthetic-placeholder"),
        ("smoke-benign-b", SampleLabel.EXPECTED_BENIGN, "synthetic-placeholder"),
        ("smoke-mal-a", SampleLabel.MALICIOUS, "synthetic-placeholder"),
        ("smoke-mal-b", SampleLabel.MALICIOUS, "synthetic-placeholder"),
        ("smoke-mal-c", SampleLabel.MALICIOUS, "synthetic-placeholder"),
    ]

    records: list[DatasetRecord] = []
    for sample_id, label, source in fixtures:
        available = source == "fixture"
        records.append(
            DatasetRecord(
                sample_id=sample_id,
                label=label,
                label_source=source,
                family_group=family_group_for(sample_id),
                available=available,
                package_name_hash=hash_package_name(sample_id),
                notes="Inert fixture or placeholder; no malware bytes in-repo.",
            )
        )

    # Qualitative holdouts — unavailable until external quarantine provides them.
    for sample_id in (
        "02-echo@0.0.7",
        "lodash@4.17.21",
        "express@4.21.2",
        "debug@4.3.4",
        "JSONStream@1.3.5",
    ):
        records.append(
            DatasetRecord(
                sample_id=sample_id,
                label=(
                    SampleLabel.MALICIOUS
                    if sample_id.startswith("02-echo")
                    else SampleLabel.EXPECTED_BENIGN
                ),
                label_source=(
                    "datadog-malicious-software-packages-dataset"
                    if sample_id.startswith("02-echo")
                    else "npm-expected-benign-control"
                ),
                family_group=family_group_for(sample_id.split("@", 1)[0]),
                available=False,
                package_name_hash=hash_package_name(sample_id.split("@", 1)[0]),
                version=sample_id.split("@", 1)[1] if "@" in sample_id else None,
                notes="Qualitative holdout; excluded from train/validation.",
            )
        )
    return records


def main() -> None:
    records = smoke_records()
    manifest_path = MANIFESTS / "smoke_manifest.json"
    split_path = MANIFESTS / "smoke_split.json"
    mh = write_manifest(manifest_path, records)
    split = grouped_split(records, seed=42)
    sh = write_split(split_path, split)
    summary = {
        "manifestPath": str(manifest_path),
        "manifestHash": mh,
        "splitPath": str(split_path),
        "splitHash": sh,
        "counts": {
            "total": len(records),
            "available": sum(1 for r in records if r.available),
            "train": len(split.train),
            "validation": len(split.validation),
            "test": len(split.test),
            "holdout": len(split.holdout),
        },
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
