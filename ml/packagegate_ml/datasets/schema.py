"""Dataset record schemas and leakage-safe helpers."""

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


@dataclass(frozen=True)
class DatasetRecord:
    sample_id: str
    label: SampleLabel
    label_source: str
    family_group: str
    available: bool
    artifact_sha256: str | None = None
    artifact_path_external: str | None = None
    package_name_hash: str | None = None
    version: str | None = None
    observed_date: str | None = None
    notes: str = ""
    # Training metadata only — never fed as model input text.
    package_label_private: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize without private package names when present."""
        data = asdict(self)
        data.pop("package_label_private", None)
        data["label"] = self.label.value
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


def assert_no_path_leakage(feature_keys: list[str]) -> None:
    banned = ("malicious", "benign", "/tmp/", "quarantine", "label", "policy")
    for key in feature_keys:
        lower = key.lower()
        for token in banned:
            if token in lower and token not in {"label_support_count"}:
                raise ValueError(f"Potential leakage feature key: {key}")
