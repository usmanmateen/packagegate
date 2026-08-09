"""Flatten PackageGate ML export JSON into classical feature matrices."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

# Stable scalar keys used when exports use nested category maps.
SCALAR_KEYS = [
    "findingCount",
    "chainCount",
    "lifecycleHookCount",
    "hasPreinstall",
    "hasInstall",
    "hasPostinstall",
    "networkDestinationCount",
    "environmentAccessCount",
    "processExecutionCount",
    "remoteDownloadCount",
    "sensitiveFileCount",
    "shellCommandCount",
    "opaqueSourceCount",
    "largeSourceCount",
    "completenessStatusComplete",
    "completenessStatusDegraded",
    "completenessStatusInsufficient",
    "coverageRatio",
    "fileCount",
    "analysedExecutableBytes",
    "familyBreadth",
]


def flatten_structured_features(
    structured: dict[str, Any],
    *,
    include_behavioural_score: bool = False,
) -> tuple[list[str], list[float]]:
    keys: list[str] = []
    values: list[float] = []

    def push(key: str, value: float) -> None:
        keys.append(key)
        values.append(float(value))

    for key in SCALAR_KEYS:
        push(key, float(structured.get(key, 0)))

    by_cat = structured.get("findingsByCategory") or {}
    for cat, count in sorted(by_cat.items()):
        push(f"cat:{cat}", float(count))

    by_sev = structured.get("findingsBySeverity") or {}
    for sev, count in sorted(by_sev.items()):
        push(f"sev:{sev}", float(count))

    by_conf = structured.get("findingsByConfidence") or {}
    for conf, count in sorted(by_conf.items()):
        push(f"conf:{conf}", float(count))

    by_chain = structured.get("chainsByType") or {}
    for ctype, count in sorted(by_chain.items()):
        push(f"chainType:{ctype}", float(count))

    if include_behavioural_score and "behaviouralScore" in structured:
        push("behaviouralScore", float(structured["behaviouralScore"]))

    return keys, values


def align_feature_matrix(
    rows: list[dict[str, float]],
) -> tuple[list[str], np.ndarray]:
    key_set: set[str] = set()
    for row in rows:
        key_set.update(row.keys())
    keys = sorted(key_set)
    matrix = np.zeros((len(rows), len(keys)), dtype=np.float64)
    for i, row in enumerate(rows):
        for j, key in enumerate(keys):
            matrix[i, j] = float(row.get(key, 0.0))
    return keys, matrix


def load_export(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def export_to_feature_row(
    export: dict[str, Any],
    *,
    include_behavioural_score: bool = False,
) -> dict[str, float]:
    structured = export["structuredFeatures"]
    keys, values = flatten_structured_features(
        structured,
        include_behavioural_score=include_behavioural_score,
    )
    return dict(zip(keys, values, strict=True))
