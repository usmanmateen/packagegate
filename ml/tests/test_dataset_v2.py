"""Tests for Dataset V2 matching and name-morphology helpers."""

from __future__ import annotations

from packagegate_ml.datasets.compromise_pairs import datadog_name_to_npm
from packagegate_ml.datasets.matching import match_malicious_to_benign
from packagegate_ml.datasets.schema import DatasetRecord, SampleLabel


def test_datadog_scoped_name_normalisation() -> None:
    assert datadog_name_to_npm("@scope@pkg") == "@scope/pkg"
    assert datadog_name_to_npm("lodash") == "lodash"
    assert datadog_name_to_npm("@scope/pkg") == "@scope/pkg"


def test_matching_uses_morphology_not_labels() -> None:
    records = [
        DatasetRecord(
            sample_id="@x@weird@9.9.9",
            label=SampleLabel.MALICIOUS,
            label_source="t",
            family_group="weird",
            available=True,
            package_name="@x/weird",
            version="9.9.9",
            attack_category="malicious_intent",
        ),
        DatasetRecord(
            sample_id="@y@alike@9.8.8",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="t",
            family_group="alike",
            available=True,
            package_name="@y/alike",
            version="9.8.8",
            hard_negative_category="cli_tools",
        ),
        DatasetRecord(
            sample_id="express@4.21.0",
            label=SampleLabel.EXPECTED_BENIGN,
            label_source="t",
            family_group="express",
            available=True,
            package_name="express",
            version="4.21.0",
            hard_negative_category="frameworks",
        ),
    ]
    report = match_malicious_to_benign(records, max_matches_per_malicious=1, max_distance=10)
    assert len(report.matches) == 1
    assert report.matches[0].malicious_sample_id == "@x@weird@9.9.9"
    # Prefer morphologically closer scoped/digit-heavy name over express
    assert report.matches[0].matched_benign_sample_ids[0] == "@y@alike@9.8.8"
