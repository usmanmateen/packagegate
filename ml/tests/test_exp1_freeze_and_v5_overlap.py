"""Tests for V4/V5 overlap exclusion and Exp1 freeze metadata."""

from __future__ import annotations

import json
from pathlib import Path

from packagegate_ml.datasets.dedup import DuplicateReport, cluster_duplicates
from packagegate_ml.datasets.schema import DatasetRecord, SampleLabel, family_group_for

ML_ROOT = Path(__file__).resolve().parents[1]
FREEZE = ML_ROOT / "experiments" / "pg-neural-exp1" / "freeze.json"
PREDS = ML_ROOT / "experiments" / "pg-neural-exp1" / "v4_matched_test_predictions.jsonl"


def test_freeze_record_exists_and_frozen() -> None:
    assert FREEZE.exists()
    data = json.loads(FREEZE.read_text(encoding="utf-8"))
    assert data["EXPERIMENT_STATUS"] == "FROZEN"
    assert data["experimentId"] == "pg-neural-exp1"
    assert data["baseModelId"] == "microsoft/graphcodebert-base"
    assert data["baseModelRevision"] == "2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d"
    assert data["maxSeqLength"] == 512
    assert data["weightsCommitted"] is False
    assert len(data["sliceCheckpointSha256"]) == 64


def test_preserved_predictions_cover_matched_test() -> None:
    assert PREDS.exists()
    rows = [json.loads(l) for l in PREDS.read_text().splitlines() if l.strip()]
    assert len(rows) == 58
    for r in rows:
        assert "sample_id" in r
        assert "y" in r or "ground_truth" in r or "label" in r
        assert "structured_proba" in r or "structuredProba" in r
        assert "embed_mean_proba" in r or "embedMeanProba" in r


def test_family_disjoint_helper() -> None:
    v4_families = {"lodash", "express", family_group_for("@scope/foo")}
    assert family_group_for("lodash") in v4_families
    assert family_group_for("brand-new-pkg-xyz") not in v4_families


def test_cluster_duplicates_reports_exact_artifact_groups() -> None:
    a = DatasetRecord(
        sample_id="a@1",
        label=SampleLabel.EXPECTED_BENIGN,
        label_source="test",
        family_group="a",
        available=True,
        package_name="a",
        version="1",
        artifact_sha256="abc",
        dataset_source="test",
    )
    b = DatasetRecord(
        sample_id="b@1",
        label=SampleLabel.EXPECTED_BENIGN,
        label_source="test",
        family_group="b",
        available=True,
        package_name="b",
        version="1",
        artifact_sha256="abc",
        dataset_source="test",
    )
    report = cluster_duplicates([a, b])
    assert isinstance(report, DuplicateReport)
    assert "abc" in report.exact_artifact_groups
    assert set(report.exact_artifact_groups["abc"]) == {"a@1", "b@1"}


def test_v5_builder_overlap_audit_attr_names() -> None:
    """Guard against DuplicateReport attribute drift in V5 builder."""
    from packagegate_ml.datasets import build_dataset_v5 as v5

    src = Path(v5.__file__).read_text(encoding="utf-8")
    assert "exact_artifact_groups" in src
    assert "exact_duplicate_groups" not in src
