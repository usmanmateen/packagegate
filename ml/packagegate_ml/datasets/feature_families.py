"""Feature family definitions for Dataset V3 (behaviour vs completeness vs nuisance)."""

from __future__ import annotations

from typing import Any

from packagegate_ml.training.shortcut_features import (
    name_plus_version_features,
    package_name_lexical_features,
    version_only_features,
)


# Pure packaging / size — NOT security behaviour. Used for matching + nuisance baselines.
STRUCTURE_NUISANCE_KEYS = [
    "fileCount",
    "analysedExecutableBytes",
    "coverageRatio",
]

# Lifecycle hook presence is security-relevant composition context (often payload entry).
# It must NOT dominate "artifact structure" nuisance baselines (V2 confound).
LIFECYCLE_KEYS = [
    "lifecycleHookCount",
    "hasPreinstall",
    "hasInstall",
    "hasPostinstall",
]

BEHAVIOUR_SCALAR_KEYS = [
    "findingCount",
    "chainCount",
    "networkDestinationCount",
    "environmentAccessCount",
    "processExecutionCount",
    "remoteDownloadCount",
    "sensitiveFileCount",
    "shellCommandCount",
    "opaqueSourceCount",
    "largeSourceCount",
    "familyBreadth",
    *LIFECYCLE_KEYS,
]

COMPLETENESS_KEYS = [
    "completenessStatusComplete",
    "completenessStatusDegraded",
    "completenessStatusInsufficient",
]


def structure_nuisance_features(structured: dict[str, Any]) -> dict[str, float]:
    """ARTIFACT_STRUCTURE nuisance without lifecycle hooks (V3 correction)."""
    return {k: float(structured.get(k, 0)) for k in STRUCTURE_NUISANCE_KEYS}


def completeness_features(structured: dict[str, Any]) -> dict[str, float]:
    return {k: float(structured.get(k, 0)) for k in COMPLETENESS_KEYS}


def behaviour_features(structured: dict[str, Any]) -> dict[str, float]:
    """Primary behaviour + security-relevant completeness."""
    out = {k: float(structured.get(k, 0)) for k in BEHAVIOUR_SCALAR_KEYS}
    out.update(completeness_features(structured))
    for prefix, field in (
        ("cat", "findingsByCategory"),
        ("sev", "findingsBySeverity"),
        ("conf", "findingsByConfidence"),
        ("chainType", "chainsByType"),
    ):
        mapping = structured.get(field) or {}
        for name, count in sorted(mapping.items()):
            out[f"{prefix}:{name}"] = float(count)
    return out


def behaviour_delta_features(before: dict[str, Any], after: dict[str, Any]) -> dict[str, float]:
    """PG-Delta: after − before on behaviour/completeness only (no identity/source)."""
    b = behaviour_features(before)
    a = behaviour_features(after)
    keys = sorted(set(b) | set(a))
    out = {f"delta:{k}": float(a.get(k, 0.0) - b.get(k, 0.0)) for k in keys}
    # Absolute post-state for a few high-signal behaviours
    for k in (
        "hasPreinstall",
        "hasInstall",
        "hasPostinstall",
        "processExecutionCount",
        "remoteDownloadCount",
        "shellCommandCount",
        "chainCount",
        "opaqueSourceCount",
    ):
        out[f"after:{k}"] = float(a.get(k, 0.0))
        out[f"new:{k}"] = float(1.0 if a.get(k, 0.0) > b.get(k, 0.0) else 0.0)
    return out


def matching_nuisance_vector(
    *,
    package_name: str,
    version: str,
    structured: dict[str, Any],
) -> dict[str, float]:
    """Nuisance variables for structure matching (no findings/chains/risk)."""
    out = structure_nuisance_features(structured)
    # Lifecycle presence is allowed as a matching dimension (balance installers),
    # but matching must not use finding/chain counts.
    out["hasPreinstall"] = float(structured.get("hasPreinstall", 0))
    out["hasInstall"] = float(structured.get("hasInstall", 0))
    out["hasPostinstall"] = float(structured.get("hasPostinstall", 0))
    out["lifecycleHookCount"] = float(structured.get("lifecycleHookCount", 0))
    out.update(package_name_lexical_features(package_name, version))
    out.update(version_only_features(version))
    return out


def generic_metadata_v3(
    *,
    package_name: str,
    version: str,
    structured: dict[str, Any],
) -> dict[str, float]:
    """Name/version morphology + pure structure nuisance (no source, no findings)."""
    out = name_plus_version_features(package_name, version)
    out.update(structure_nuisance_features(structured))
    return out
