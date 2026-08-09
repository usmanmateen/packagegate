"""Tests for Dataset V1 split integrity, dedup, and holdouts."""

from __future__ import annotations

from pathlib import Path

from packagegate_ml.datasets.audit_splits import audit_splits
from packagegate_ml.datasets.dedup import cluster_duplicates
from packagegate_ml.datasets.schema import (
    MALWARE_QUALITATIVE_HOLDOUT_IDS,
    DatasetRecord,
    SampleLabel,
)
from packagegate_ml.datasets.splits import grouped_split


def test_02_echo_excluded_from_train_validation() -> None:
    records = [
        DatasetRecord(
            sample_id="02-echo@0.0.7",
            label=SampleLabel.MALICIOUS,
            label_source="datadog",
            family_group="02-echo",
            available=False,
            package_name="02-echo",
            version="0.0.7",
        ),
        DatasetRecord(
            sample_id="alpha@1.0.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="test",
            family_group="alpha",
            available=True,
        ),
        DatasetRecord(
            sample_id="beta@1.0.0",
            label=SampleLabel.MALICIOUS,
            label_source="test",
            family_group="beta",
            available=True,
        ),
        DatasetRecord(
            sample_id="gamma@1.0.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="test",
            family_group="gamma",
            available=True,
        ),
    ]
    split = grouped_split(records, seed=1)
    assert "02-echo@0.0.7" in MALWARE_QUALITATIVE_HOLDOUT_IDS
    assert "02-echo@0.0.7" in split.holdout
    assert "02-echo@0.0.7" not in split.train
    assert "02-echo@0.0.7" not in split.validation
    report = audit_splits(records, split)
    assert report["passed"] is True


def test_family_versions_stay_together() -> None:
    records = [
        DatasetRecord(
            sample_id="foo@1.0.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="t",
            family_group="foo",
            available=True,
        ),
        DatasetRecord(
            sample_id="foo@1.0.1",
            label=SampleLabel.MALICIOUS,
            label_source="t",
            family_group="foo",
            available=True,
        ),
        DatasetRecord(
            sample_id="bar@1.0.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="t",
            family_group="bar",
            available=True,
        ),
        DatasetRecord(
            sample_id="baz@1.0.0",
            label=SampleLabel.MALICIOUS,
            label_source="t",
            family_group="baz",
            available=True,
        ),
        DatasetRecord(
            sample_id="qux@1.0.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="t",
            family_group="qux",
            available=True,
        ),
    ]
    split = grouped_split(records, seed=0, train_ratio=0.4, val_ratio=0.2)
    membership = {}
    for part in ("train", "validation", "test"):
        for sid in getattr(split, part):
            membership[sid] = part
    assert membership["foo@1.0.0"] == membership["foo@1.0.1"]
    assert audit_splits(records, split)["passed"] is True


def test_exact_artifact_duplicate_clusters(tmp_path: Path) -> None:
    a = tmp_path / "a.tgz"
    b = tmp_path / "b.tgz"
    # Minimal gzip tar-like bytes (same payload) — fingerprint falls back to file hash
    payload = b"hello-packagegate-dup"
    a.write_bytes(payload)
    b.write_bytes(payload)
    records = [
        DatasetRecord(
            sample_id="pkg-a@1.0.0",
            label=SampleLabel.MALICIOUS,
            label_source="t",
            family_group="pkg-a",
            available=True,
            artifact_sha256="abc123",
            artifact_path=str(a),
        ),
        DatasetRecord(
            sample_id="pkg-b@1.0.0",
            label=SampleLabel.MALICIOUS,
            label_source="t",
            family_group="pkg-b",
            available=True,
            artifact_sha256="abc123",
            artifact_path=str(b),
        ),
    ]
    report = cluster_duplicates(records)
    assert "abc123" in report.exact_artifact_groups
    assert len(report.exact_artifact_groups["abc123"]) == 2
