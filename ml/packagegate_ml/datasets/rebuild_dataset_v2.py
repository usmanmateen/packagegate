"""Rebuild Dataset V2 manifests from already-downloaded external artefacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

os.environ.setdefault("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data-v2")

from packagegate_ml.datasets.audit_splits import audit_splits
from packagegate_ml.datasets.benign_catalogue import benign_catalogue
from packagegate_ml.datasets.compromise_pairs import build_compromise_pairs
from packagegate_ml.datasets.datadog_adapter import list_npm_zip_paths
from packagegate_ml.datasets.dedup import (
    apply_duplicate_groups,
    cluster_duplicates,
    write_duplicate_report,
)
from packagegate_ml.datasets.matching import match_malicious_to_benign
from packagegate_ml.datasets.openssf_adapter import fetch_openssf_npm_metadata_sample
from packagegate_ml.datasets.paths import (
    benign_root,
    external_manifests_root,
    malware_root,
    scratch_root,
)
from packagegate_ml.datasets.schema import (
    MALWARE_QUALITATIVE_HOLDOUT_IDS,
    QUALITATIVE_HOLDOUT_IDS,
    DatasetRecord,
    SampleLabel,
    family_group_for,
    hash_package_name,
    sample_id_for,
)
from packagegate_ml.datasets.splits import (
    grouped_split,
    write_frozen_split_files,
    write_manifest,
)
from packagegate_ml.datasets.compromise_pairs import datadog_name_to_npm

REPO = Path(__file__).resolve().parents[3]
FROZEN = REPO / "ml" / "data-manifests" / "v2"


def _safe_id(sample_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9@._+-]+", "_", sample_id)


def records_from_disk() -> list[DatasetRecord]:
    records: list[DatasetRecord] = []

    # Index Datadog paths by npm sample id for category recovery
    by_sid: dict[str, dict] = {}
    try:
        for entry in list_npm_zip_paths():
            npm_name = datadog_name_to_npm(entry["package_name"])
            sid = sample_id_for(npm_name, entry["version"])
            by_sid[sid] = entry
            by_sid[sample_id_for(entry["package_name"], entry["version"])] = entry
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"datadog_index_warning": str(exc)}))

    records.append(
        DatasetRecord(
            sample_id="02-echo@0.0.7",
            package_name="02-echo",
            version="0.0.7",
            label=SampleLabel.MALICIOUS,
            label_source="datadog-malicious-software-packages-dataset",
            label_reference="samples/npm/compromised_lib/02-echo/0.0.7",
            family_group=family_group_for("02-echo"),
            available=False,
            package_name_hash=hash_package_name("02-echo"),
            dataset_source="datadog",
            attack_category="compromised_lib",
            notes="Qualitative malware holdout — excluded from train/validation",
        )
    )

    for path in sorted((malware_root() / "datadog").glob("*.tgz")):
        # Reverse safe_id is lossy; recover from index by matching filename stem
        stem = path.name[: -len(".tgz")]
        entry = None
        for sid, ent in by_sid.items():
            if _safe_id(sid) == stem:
                entry = ent
                break
        if entry is None:
            # Fallback parse: last @ separates version
            if "@" not in stem:
                continue
            name_part, version = stem.rsplit("@", 1)
            npm_name = name_part.replace("_", "/", 1) if name_part.startswith("@") else name_part
            category = "uncategorised"
            package_name = npm_name
            label_reference = None
        else:
            package_name = datadog_name_to_npm(entry["package_name"])
            version = entry["version"]
            category = entry["category"]
            label_reference = entry["path"]

        sid = sample_id_for(package_name, version)
        if sid in MALWARE_QUALITATIVE_HOLDOUT_IDS:
            continue
        label = (
            SampleLabel.COMPROMISED
            if category == "compromised_lib"
            else SampleLabel.MALICIOUS
        )
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        records.append(
            DatasetRecord(
                sample_id=sid,
                package_name=package_name,
                version=version,
                label=label,
                label_source="datadog-malicious-software-packages-dataset",
                label_reference=label_reference,
                family_group=family_group_for(package_name),
                available=True,
                artifact_sha256=sha,
                artifact_path=str(path),
                artifact_path_external=str(path),
                package_name_hash=hash_package_name(package_name),
                dataset_source="datadog",
                attack_category=category,
                benchmark_tags=(
                    ("compromised_version",)
                    if category == "compromised_lib"
                    else ("malicious_intent",)
                ),
                notes=f"category={category}; static tgz rebuilt from Datadog zip",
            )
        )

    for control in sorted(QUALITATIVE_HOLDOUT_IDS):
        if control.startswith("02-echo"):
            continue
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
                notes="Qualitative control — excluded from train/validation",
            )
        )

    catalogue = {
        (row["package_name"], row["version"]): row for row in benign_catalogue()
    }
    for directory, tag in (
        (benign_root() / "npm", None),
        (benign_root() / "npm-adjacent", "compromised_version_control"),
    ):
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.tgz")):
            stem = path.name[: -len(".tgz")]
            if "@" not in stem:
                continue
            name_part, version = stem.rsplit("@", 1)
            package_name = (
                name_part.replace("_", "/", 1) if name_part.startswith("@") else name_part
            )
            # Prefer catalogue metadata when present
            meta = catalogue.get((package_name, version))
            # Also try with underscore form
            if meta is None:
                for (n, v), row in catalogue.items():
                    if _safe_id(sample_id_for(n, v)) == stem:
                        meta = row
                        package_name = n
                        version = v
                        break
            sid = sample_id_for(package_name, version)
            if sid in QUALITATIVE_HOLDOUT_IDS:
                continue
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            hn = tag or (meta["hard_negative_category"] if meta else "unspecified")
            notes = meta["notes"] if meta else "expected-benign from disk"
            records.append(
                DatasetRecord(
                    sample_id=sid,
                    package_name=package_name,
                    version=version,
                    label=SampleLabel.EXPECTED_BENIGN,
                    label_source=(
                        "npm-adjacent-to-compromised"
                        if tag
                        else "npm-expected-benign-catalogue"
                    ),
                    family_group=family_group_for(package_name),
                    available=True,
                    artifact_sha256=sha,
                    artifact_path=str(path),
                    artifact_path_external=str(path),
                    package_name_hash=hash_package_name(package_name),
                    dataset_source="npm-registry",
                    hard_negative_category=hn,
                    benchmark_tags=(("compromised_version", "matched_clean"),)
                    if tag
                    else (),
                    notes=notes,
                )
            )

    records.extend(fetch_openssf_npm_metadata_sample(limit=40))
    return records


def finalise(records: list[DatasetRecord]) -> dict:
    pairs, adjacent = build_compromise_pairs(
        records, max_pairs=100, max_clean_per_compromised=2
    )
    records = [*records, *adjacent]

    report = cluster_duplicates(records)
    records = apply_duplicate_groups(records, report)
    write_duplicate_report(scratch_root() / "duplicates_v2.json", report)

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

    match_report = match_malicious_to_benign(records, max_matches_per_malicious=2)

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

    split = grouped_split(records, seed=42)
    audit = audit_splits(records, split)
    (scratch_root() / "audit_v2.json").write_text(
        json.dumps(audit, indent=2) + "\n", encoding="utf-8"
    )
    if not audit.get("passed"):
        raise SystemExit(f"Leakage audit failed: {audit}")

    write_manifest(
        external_manifests_root() / "dataset_v2_full.private.json",
        records,
        include_package_name=True,
    )
    write_manifest(
        external_manifests_root() / "dataset_v2_full.json",
        records,
        include_package_name=False,
    )
    hashes = write_frozen_split_files(FROZEN, records, split)
    FROZEN.mkdir(parents=True, exist_ok=True)
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

    available = [r for r in records if r.available]
    summary = {
        "total": len(records),
        "available": len(available),
        "labels": dict(Counter(r.label.value for r in records)),
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
    (FROZEN / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def main() -> None:
    print(json.dumps({"phase": "records_from_disk"}))
    records = records_from_disk()
    print(json.dumps({"records": len(records)}))
    summary = finalise(records)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
