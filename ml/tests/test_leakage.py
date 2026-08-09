"""Leakage and split integrity tests for PackageGate ML."""

from __future__ import annotations

from packagegate_ml.datasets.schema import (
    QUALITATIVE_HOLDOUT_IDS,
    DatasetRecord,
    SampleLabel,
)
from packagegate_ml.datasets.splits import grouped_split
from packagegate_ml.features.structured import flatten_structured_features


def test_grouped_split_keeps_family_together() -> None:
    records = [
        DatasetRecord(
            sample_id="foo@1.0.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="test",
            family_group="foo",
            available=True,
        ),
        DatasetRecord(
            sample_id="foo@1.0.1",
            label=SampleLabel.MALICIOUS,
            label_source="test",
            family_group="foo",
            available=True,
        ),
        DatasetRecord(
            sample_id="bar@1.0.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="test",
            family_group="bar",
            available=True,
        ),
        DatasetRecord(
            sample_id="baz@1.0.0",
            label=SampleLabel.MALICIOUS,
            label_source="test",
            family_group="baz",
            available=True,
        ),
        DatasetRecord(
            sample_id="qux@1.0.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="test",
            family_group="qux",
            available=True,
        ),
    ]
    split = grouped_split(records, seed=0, train_ratio=0.4, val_ratio=0.2)
    membership = {}
    for name in ("train", "validation", "test"):
        for sample_id in getattr(split, name):
            membership[sample_id] = name
    assert membership["foo@1.0.0"] == membership["foo@1.0.1"]


def test_qualitative_holdouts_excluded_from_train() -> None:
    records = [
        DatasetRecord(
            sample_id="02-echo@0.0.7",
            label=SampleLabel.MALICIOUS,
            label_source="datadog",
            family_group="02-echo",
            available=False,
        ),
        DatasetRecord(
            sample_id="other@1.0.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="test",
            family_group="other",
            available=True,
        ),
    ]
    split = grouped_split(records, seed=1)
    assert "02-echo@0.0.7" in split.holdout
    assert "02-echo@0.0.7" not in split.train
    assert "02-echo@0.0.7" not in split.validation
    assert "02-echo@0.0.7" not in split.test
    assert "02-echo@0.0.7" in QUALITATIVE_HOLDOUT_IDS


def test_structured_features_omit_policy_fields() -> None:
    structured = {
        "findingCount": 1,
        "chainCount": 0,
        "lifecycleHookCount": 0,
        "hasPreinstall": 0,
        "hasInstall": 0,
        "hasPostinstall": 0,
        "networkDestinationCount": 0,
        "environmentAccessCount": 1,
        "processExecutionCount": 0,
        "remoteDownloadCount": 0,
        "sensitiveFileCount": 0,
        "shellCommandCount": 0,
        "opaqueSourceCount": 0,
        "largeSourceCount": 0,
        "completenessStatusComplete": 1,
        "completenessStatusDegraded": 0,
        "completenessStatusInsufficient": 0,
        "coverageRatio": 1.0,
        "fileCount": 2,
        "analysedExecutableBytes": 100,
        "familyBreadth": 1,
        "findingsByCategory": {"ENVIRONMENT_ACCESS": 1},
        "findingsBySeverity": {"LOW": 1},
        "findingsByConfidence": {"HIGH": 1},
        "chainsByType": {},
    }
    keys, _values = flatten_structured_features(structured)
    joined = " ".join(keys).lower()
    assert "finalaction" not in joined
    assert "policy" not in joined
    assert "malicious" not in joined
