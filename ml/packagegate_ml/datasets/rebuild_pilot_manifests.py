"""Rebuild Dataset V1 manifests from already-acquired external artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from packagegate_ml.datasets.audit_splits import audit_splits
from packagegate_ml.datasets.benign_catalogue import benign_catalogue
from packagegate_ml.datasets.build_pilot_dataset import synthetic_fixture_records
from packagegate_ml.datasets.dedup import (
    apply_duplicate_groups,
    cluster_duplicates,
    write_duplicate_report,
)
from packagegate_ml.datasets.openssf_adapter import fetch_openssf_npm_metadata_sample
from packagegate_ml.datasets.paths import (
    benign_root,
    data_root,
    external_manifests_root,
    malware_root,
)
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

REPO = Path(__file__).resolve().parents[3]
MANIFESTS_REPO = REPO / "ml" / "data-manifests" / "v1"


def _parse_safe_id(name: str) -> tuple[str, str] | None:
    # Files look like package@version.tgz with @ preserved, or scoped @scope_name@ver
    stem = name[: -len(".tgz")] if name.endswith(".tgz") else name
    if "@" not in stem:
        return None
    # last @ separates version for unscoped; scoped may have multiple @
    # Our _safe_id kept @ in package names.
    package, version = stem.rsplit("@", 1)
    return package, version


def records_from_disk() -> list[DatasetRecord]:
    records: list[DatasetRecord] = []

    # Holdout metadata
    records.append(
        DatasetRecord(
            sample_id="02-echo@0.0.7",
            package_name="02-echo",
            version="0.0.7",
            label=SampleLabel.MALICIOUS,
            label_source="datadog-malicious-software-packages-dataset",
            family_group=family_group_for("02-echo"),
            available=False,
            package_name_hash=hash_package_name("02-echo"),
            dataset_source="datadog",
            notes="Qualitative malware holdout",
        )
    )
    for control in (
        "lodash@4.17.21",
        "express@4.21.2",
        "debug@4.3.4",
        "JSONStream@1.3.5",
    ):
        name, version = control.split("@", 1)
        records.append(
            DatasetRecord(
                sample_id=control,
                package_name=name,
                version=version,
                label=SampleLabel.EXPECTED_BENIGN,
                label_source="npm-expected-benign-control",
                family_group=family_group_for(name),
                available=False,
                package_name_hash=hash_package_name(name),
                dataset_source="npm-registry",
                notes="Qualitative control",
            )
        )

    for path in sorted((malware_root() / "datadog").glob("*.tgz")):
        parsed = _parse_safe_id(path.name)
        if parsed is None:
            continue
        package, version = parsed
        sid = f"{package}@{version}"
        if sid == "02-echo@0.0.7":
            continue
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        records.append(
            DatasetRecord(
                sample_id=sid,
                package_name=package,
                version=version,
                label=SampleLabel.MALICIOUS,
                label_source="datadog-malicious-software-packages-dataset",
                family_group=family_group_for(package),
                available=True,
                artifact_sha256=sha,
                artifact_path=str(path),
                artifact_path_external=str(path),
                package_name_hash=hash_package_name(package),
                dataset_source="datadog",
                notes="static tgz rebuilt from Datadog zip",
            )
        )

    cat = {
        f"{r['package_name']}@{r['version']}": r for r in benign_catalogue()
    }
    for path in sorted((benign_root() / "npm").glob("*.tgz")):
        parsed = _parse_safe_id(path.name)
        if parsed is None:
            continue
        package, version = parsed
        sid = f"{package}@{version}"
        meta = cat.get(sid, {})
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        records.append(
            DatasetRecord(
                sample_id=sid,
                package_name=package,
                version=version,
                label=SampleLabel.EXPECTED_BENIGN,
                label_source="npm-expected-benign-catalogue",
                family_group=family_group_for(package),
                available=True,
                artifact_sha256=sha,
                artifact_path=str(path),
                artifact_path_external=str(path),
                package_name_hash=hash_package_name(package),
                dataset_source="npm-registry",
                hard_negative_category=meta.get("hard_negative_category"),
                notes=meta.get("notes", ""),
            )
        )

    records.extend(synthetic_fixture_records())
    records.extend(fetch_openssf_npm_metadata_sample(limit=40))
    return records


def main() -> None:
    records = records_from_disk()
    print(json.dumps({"phase": "dedup", "rawCount": len(records)}))
    dup_report = cluster_duplicates(records)
    records = apply_duplicate_groups(records, dup_report)
    write_duplicate_report(external_manifests_root() / "duplicate_report.json", dup_report)

    split = grouped_split(records, seed=42)
    audit = audit_splits(records, split)

    mh = write_manifest(
        external_manifests_root() / "dataset_v1_full.json",
        records,
        include_package_name=False,
    )
    write_manifest(
        external_manifests_root() / "dataset_v1_full.private.json",
        records,
        include_package_name=True,
    )
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
