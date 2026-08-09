"""Grouped package/family splits with qualitative holdouts and duplicate clusters."""

from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

from packagegate_ml.datasets.schema import (
    MALWARE_QUALITATIVE_HOLDOUT_IDS,
    QUALITATIVE_HOLDOUT_IDS,
    DatasetRecord,
    SampleLabel,
    SplitManifest,
)


def grouped_split(
    records: list[DatasetRecord],
    *,
    seed: int = 42,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
) -> SplitManifest:
    """
    Assign entire family_groups to a single split.
    Qualitative holdouts are forced into holdout and excluded from train/val/test.
    """
    by_family: dict[str, list[DatasetRecord]] = defaultdict(list)
    holdout: list[str] = []
    for record in records:
        if (
            record.sample_id in QUALITATIVE_HOLDOUT_IDS
            or record.sample_id in MALWARE_QUALITATIVE_HOLDOUT_IDS
            or not record.available
        ):
            holdout.append(record.sample_id)
            continue
        by_family[record.family_group].append(record)

    families = sorted(by_family.keys())
    rng = random.Random(seed)
    rng.shuffle(families)

    n = len(families)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    train_f = set(families[:n_train])
    val_f = set(families[n_train : n_train + n_val])

    train: list[str] = []
    validation: list[str] = []
    test: list[str] = []
    for family, members in by_family.items():
        ids = [m.sample_id for m in members]
        if family in train_f:
            train.extend(ids)
        elif family in val_f:
            validation.extend(ids)
        else:
            test.extend(ids)

    return SplitManifest(
        strategy="grouped_package_family+duplicate_cluster",
        seed=seed,
        train=sorted(train),
        validation=sorted(validation),
        test=sorted(test),
        holdout=sorted(set(holdout)),
    )


def write_manifest(
    path: Path,
    records: list[DatasetRecord],
    *,
    include_package_name: bool = False,
) -> str:
    payload = {
        "schemaVersion": 1,
        "records": [
            r.to_public_dict(include_package_name=include_package_name) for r in records
        ],
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_split(path: Path, split: SplitManifest) -> str:
    text = json.dumps(split.to_dict(), indent=2, sort_keys=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_frozen_split_files(
    out_dir: Path,
    records: list[DatasetRecord],
    split: SplitManifest,
) -> dict[str, str]:
    """Write train/validation/test/qualitative-holdouts manifests with hashes."""
    by_id = {r.sample_id: r for r in records}
    out_dir.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}

    def dump(name: str, ids: list[str]) -> None:
        subset = [by_id[i] for i in ids if i in by_id]
        hashes[name] = write_manifest(out_dir / f"{name}.json", subset)

    dump("train", split.train)
    dump("validation", split.validation)
    dump("test", split.test)
    dump("qualitative-holdouts", split.holdout)
    hashes["split"] = write_split(out_dir / "split.json", split)
    (out_dir / "hashes.json").write_text(
        json.dumps(hashes, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return hashes


def load_records(path: Path) -> list[DatasetRecord]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: list[DatasetRecord] = []
    for item in raw["records"]:
        out.append(
            DatasetRecord(
                sample_id=item["sample_id"],
                label=SampleLabel(item["label"])
                if not isinstance(item["label"], SampleLabel)
                else item["label"],
                label_source=item["label_source"],
                family_group=item["family_group"],
                available=bool(item["available"]),
                package_name=item.get("package_name"),
                version=item.get("version"),
                label_reference=item.get("label_reference"),
                observed_date=item.get("observed_date"),
                artifact_sha256=item.get("artifact_sha256"),
                artifact_path=item.get("artifact_path")
                or item.get("artifact_path_external"),
                artifact_path_external=item.get("artifact_path_external"),
                package_name_hash=item.get("package_name_hash"),
                dataset_source=item.get("dataset_source"),
                hard_negative_category=item.get("hard_negative_category"),
                duplicate_group_id=item.get("duplicate_group_id"),
                notes=item.get("notes", ""),
            )
        )
    return out
