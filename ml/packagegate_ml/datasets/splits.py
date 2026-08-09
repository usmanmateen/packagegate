"""Grouped package/family splits with qualitative holdouts."""

from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

from packagegate_ml.datasets.schema import (
    QUALITATIVE_HOLDOUT_IDS,
    DatasetRecord,
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
        if record.sample_id in QUALITATIVE_HOLDOUT_IDS or not record.available:
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
    test_f = set(families[n_train + n_val :])

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
        strategy="grouped_package_family",
        seed=seed,
        train=sorted(train),
        validation=sorted(validation),
        test=sorted(test),
        holdout=sorted(set(holdout)),
    )


def write_manifest(path: Path, records: list[DatasetRecord]) -> str:
    payload = {
        "schemaVersion": 1,
        "records": [r.to_public_dict() for r in records],
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


def load_records(path: Path) -> list[DatasetRecord]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: list[DatasetRecord] = []
    for item in raw["records"]:
        out.append(
            DatasetRecord(
                sample_id=item["sample_id"],
                label=item["label"],
                label_source=item["label_source"],
                family_group=item["family_group"],
                available=bool(item["available"]),
                artifact_sha256=item.get("artifact_sha256"),
                artifact_path_external=item.get("artifact_path_external"),
                package_name_hash=item.get("package_name_hash"),
                version=item.get("version"),
                observed_date=item.get("observed_date"),
                notes=item.get("notes", ""),
            )
        )
    return out
