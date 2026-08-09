"""Build PackageGate ML Dataset V1 pilot manifest from external sources."""

from __future__ import annotations

import json
from pathlib import Path

from packagegate_ml.datasets.benign_adapter import acquire_benign_pilot
from packagegate_ml.datasets.datadog_adapter import acquire_datadog_pilot
from packagegate_ml.datasets.dedup import (
    apply_duplicate_groups,
    cluster_duplicates,
    write_duplicate_report,
)
from packagegate_ml.datasets.openssf_adapter import fetch_openssf_npm_metadata_sample
from packagegate_ml.datasets.paths import data_root, external_manifests_root
from packagegate_ml.datasets.schema import (
    DatasetRecord,
    SampleLabel,
    family_group_for,
    hash_package_name,
)
from packagegate_ml.datasets.splits import (
    grouped_split,
    write_frozen_split_files,
    write_manifest,
    write_split,
)
from packagegate_ml.datasets.audit_splits import audit_splits

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "fixtures"
MANIFESTS_REPO = REPO / "ml" / "data-manifests" / "v1"


def synthetic_fixture_records() -> list[DatasetRecord]:
    mapping = {
        "inert-env-exfil": SampleLabel.SYNTHETIC_SUSPICIOUS,
        "inert-install-curl-bash": SampleLabel.SYNTHETIC_SUSPICIOUS,
        "inert-powershell-irm-iex": SampleLabel.SYNTHETIC_SUSPICIOUS,
        "version-diff-remote-v2": SampleLabel.SYNTHETIC_SUSPICIOUS,
        "inert-shell-cooccurrence-negative": SampleLabel.EXPECTED_BENIGN,
        "inert-normal-installer": SampleLabel.EXPECTED_BENIGN,
        "version-diff-benign-v1": SampleLabel.EXPECTED_BENIGN,
    }
    records: list[DatasetRecord] = []
    for name, label in mapping.items():
        root = FIXTURES / name
        if not root.exists():
            continue
        # Fixtures are source dirs; export pipeline handles them specially.
        records.append(
            DatasetRecord(
                sample_id=f"fixture:{name}",
                package_name=name,
                version="fixture",
                label=label,
                label_source="packagegate-inert-fixture",
                family_group=family_group_for(f"fixture-{name}"),
                available=True,
                artifact_path=str(root),
                artifact_path_external=str(root),
                package_name_hash=hash_package_name(name),
                dataset_source="fixture",
                notes="Inert synthetic fixture (never executed)",
            )
        )
    return records


def main() -> None:
    print(json.dumps({"phase": "acquire_datadog", "dataRoot": str(data_root())}))
    malicious = acquire_datadog_pilot(max_samples=150, max_per_family=1, seed=42)
    print(json.dumps({"phase": "acquire_benign"}))
    benign = acquire_benign_pilot(max_samples=250)
    print(json.dumps({"phase": "openssf_metadata"}))
    openssf = fetch_openssf_npm_metadata_sample(limit=40)
    synthetic = synthetic_fixture_records()

    records = malicious + benign + openssf + synthetic
    print(json.dumps({"phase": "dedup", "rawCount": len(records)}))
    dup_report = cluster_duplicates(records)
    records = apply_duplicate_groups(records, dup_report)
    write_duplicate_report(external_manifests_root() / "duplicate_report.json", dup_report)

    split = grouped_split(records, seed=42)
    audit = audit_splits(records, split)

    # Write external + repo metadata manifests (no malware bytes).
    full_path = external_manifests_root() / "dataset_v1_full.json"
    mh = write_manifest(full_path, records, include_package_name=False)
    # Private mapping with names kept outside repo for operator use only.
    private_path = external_manifests_root() / "dataset_v1_full.private.json"
    write_manifest(private_path, records, include_package_name=True)
    sh = write_split(external_manifests_root() / "dataset_v1_split.json", split)
    frozen_hashes = write_frozen_split_files(MANIFESTS_REPO, records, split)

    summary = {
        "datasetVersion": "v1",
        "dataRoot": str(data_root()),
        "counts": {
            "totalRecords": len(records),
            "available": sum(1 for r in records if r.available),
            "maliciousAvailable": sum(
                1
                for r in records
                if r.available and r.label.value in {"MALICIOUS", "COMPROMISED"}
            ),
            "benignAvailable": sum(
                1
                for r in records
                if r.available and r.label.value == "EXPECTED_BENIGN"
            ),
            "syntheticAvailable": sum(
                1
                for r in records
                if r.available and r.label.value == "SYNTHETIC_SUSPICIOUS"
            ),
            "openssfMetadataOnly": sum(
                1 for r in records if r.dataset_source == "openssf"
            ),
            "exactDuplicateGroups": len(dup_report.exact_artifact_groups),
            "nearDuplicateGroups": len(dup_report.near_duplicate_groups),
            "train": len(split.train),
            "validation": len(split.validation),
            "test": len(split.test),
            "holdout": len(split.holdout),
        },
        "manifestHash": mh,
        "splitHash": sh,
        "frozenHashes": frozen_hashes,
        "leakageAudit": audit,
        "02echoHoldout": "02-echo@0.0.7" in split.holdout
        and "02-echo@0.0.7" not in split.train
        and "02-echo@0.0.7" not in split.validation,
    }
    (external_manifests_root() / "dataset_v1_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    if not audit["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
