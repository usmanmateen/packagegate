"""Canonical PackageGate ML dataset records and holdout constants."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Any


class SampleLabel(str, Enum):
    EXPECTED_BENIGN = "EXPECTED_BENIGN"
    MALICIOUS = "MALICIOUS"
    SYNTHETIC_SUSPICIOUS = "SYNTHETIC_SUSPICIOUS"
    UNKNOWN = "UNKNOWN"
    COMPROMISED = "COMPROMISED"


class SplitName(str, Enum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    HOLDOUT = "holdout"


# Samples reserved from training/validation for qualitative PackageGate reports.
QUALITATIVE_HOLDOUT_IDS = frozenset(
    {
        "02-echo@0.0.7",
        "lodash@4.17.21",
        "express@4.21.2",
        "debug@4.3.4",
        "JSONStream@1.3.5",
    }
)

# Must never appear in train/validation for ML V1 pilot.
MALWARE_QUALITATIVE_HOLDOUT_IDS = frozenset({"02-echo@0.0.7"})


@dataclass(frozen=True)
class DatasetRecord:
    sample_id: str
    label: SampleLabel
    label_source: str
    family_group: str
    available: bool
    package_name: str | None = None
    version: str | None = None
    label_reference: str | None = None
    observed_date: str | None = None
    artifact_sha256: str | None = None
    artifact_path: str | None = None
    artifact_path_external: str | None = None
    package_name_hash: str | None = None
    dataset_source: str | None = None
    hard_negative_category: str | None = None
    duplicate_group_id: str | None = None
    # Datadog / analysis metadata — NEVER use as model input features.
    attack_category: str | None = None
    benchmark_tags: tuple[str, ...] = ()
    notes: str = ""

    def to_public_dict(self, *, include_package_name: bool = False) -> dict[str, Any]:
        """Serialize for manifests. Package names omitted by default (leakage control)."""
        data = asdict(self)
        if not include_package_name:
            data.pop("package_name", None)
        if data.get("artifact_path") is None and data.get("artifact_path_external"):
            data["artifact_path"] = data["artifact_path_external"]
        data["label"] = self.label.value
        data["benchmark_tags"] = list(self.benchmark_tags)
        return data

    def binary_positive(self) -> bool | None:
        if self.label in {
            SampleLabel.MALICIOUS,
            SampleLabel.COMPROMISED,
            SampleLabel.SYNTHETIC_SUSPICIOUS,
        }:
            return True
        if self.label == SampleLabel.EXPECTED_BENIGN:
            return False
        return None


@dataclass(frozen=True)
class CompromisePair:
    """Paired clean vs compromised versions of the same package family."""

    pair_id: str
    family_group: str
    clean_sample_id: str
    compromised_sample_id: str
    clean_version: str
    compromised_version: str
    clean_artifact_sha256: str | None
    compromised_artifact_sha256: str | None
    label: str = "COMPROMISE_INTRODUCED"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MatchRecord:
    """Malicious-intent sample matched to expected-benign hard negatives."""

    malicious_sample_id: str
    matched_benign_sample_ids: tuple[str, ...]
    matching_distance: float
    matching_features: dict[str, float]
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["matched_benign_sample_ids"] = list(self.matched_benign_sample_ids)
        return data


@dataclass
class SplitManifest:
    strategy: str
    seed: int
    train: list[str] = field(default_factory=list)
    validation: list[str] = field(default_factory=list)
    test: list[str] = field(default_factory=list)
    holdout: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def hash_package_name(name: str) -> str:
    return sha256(name.encode("utf-8")).hexdigest()[:16]


def family_group_for(package_name: str) -> str:
    """Group all versions of a package into one split family."""
    return package_name.strip().lower()


def sample_id_for(package_name: str, version: str) -> str:
    return f"{package_name}@{version}"


def assert_no_path_leakage(feature_keys: list[str]) -> None:
    banned = ("malicious", "benign", "/tmp/", "quarantine", "label", "policy", "datadog")
    for key in feature_keys:
        lower = key.lower()
        for token in banned:
            if token in lower and token not in {"label_support_count"}:
                raise ValueError(f"Potential leakage feature key: {key}")
