"""Paths for external PackageGate ML data (never under the git repo)."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_DATA_ROOT = Path(
    os.environ.get("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data")
)


def data_root() -> Path:
    root = Path(os.environ.get("PACKAGEGATE_ML_DATA_ROOT", str(DEFAULT_DATA_ROOT)))
    root.mkdir(parents=True, exist_ok=True)
    return root


def malware_root() -> Path:
    path = data_root() / "malware"
    path.mkdir(parents=True, exist_ok=True)
    return path


def benign_root() -> Path:
    path = data_root() / "benign"
    path.mkdir(parents=True, exist_ok=True)
    return path


def exports_root() -> Path:
    path = data_root() / "exports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def scratch_root() -> Path:
    path = data_root() / "scratch"
    path.mkdir(parents=True, exist_ok=True)
    return path


def external_manifests_root() -> Path:
    path = data_root() / "manifests"
    path.mkdir(parents=True, exist_ok=True)
    return path
