"""Nuisance / shortcut feature extractors for dataset quality audits.

IMPORTANT naming:
- PACKAGE_NAME_LEXICAL — morphology derived from package name / sample_id text
- NOT a cryptographic hash, HashingVectorizer, or opaque package ID

Dataset V1 incorrectly labelled this baseline ``name_hash`` in run metadata.
That baseline used sample_id morphology only:
  name_len, version_len, at_count, digit_count
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


def parse_sample_id(sample_id: str) -> tuple[str, str]:
    """Split ``name@version`` allowing scoped names that contain ``@``."""
    if "@" not in sample_id:
        return sample_id, ""
    name, version = sample_id.rsplit("@", 1)
    return name, version


def package_name_lexical_features(package_name: str, version: str = "") -> dict[str, float]:
    """PACKAGE_NAME_LEXICAL_ONLY morphology (no security behaviour)."""
    name = package_name or ""
    scoped = 1.0 if name.startswith("@") else 0.0
    segments = [s for s in re.split(r"[/@._-]+", name) if s]
    digits = sum(ch.isdigit() for ch in name)
    separators = sum(ch in "/@._-" for ch in name)
    return {
        "name_len": float(len(name)),
        "scoped": scoped,
        "at_count_in_name": float(name.count("@")),
        "slash_count": float(name.count("/")),
        "hyphen_count": float(name.count("-")),
        "underscore_count": float(name.count("_")),
        "digit_count_name": float(digits),
        "digit_fraction_name": float(digits) / max(len(name), 1),
        "separator_count": float(separators),
        "segment_count": float(len(segments)),
        "avg_segment_len": float(sum(len(s) for s in segments) / max(len(segments), 1)),
        "has_digit_token": float(any(any(c.isdigit() for c in s) for s in segments)),
    }


def version_only_features(version: str) -> dict[str, float]:
    """VERSION_ONLY nuisance features."""
    v = version or ""
    parts = re.split(r"[.+-]", v)
    nums = []
    for part in parts:
        if part.isdigit():
            nums.append(int(part))
        else:
            m = re.match(r"(\d+)", part)
            nums.append(int(m.group(1)) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return {
        "version_len": float(len(v)),
        "version_component_count": float(len([p for p in parts if p])),
        "version_major": float(nums[0]),
        "version_minor": float(nums[1]),
        "version_patch": float(nums[2]),
        "version_has_prerelease": float("-" in v or any(c.isalpha() for c in v)),
        "version_digit_count": float(sum(ch.isdigit() for ch in v)),
        "version_unusual_large": float(1.0 if nums[0] >= 100 or nums[1] >= 100 else 0.0),
        "version_is_zeroish": float(1.0 if nums[0] == 0 else 0.0),
    }


def name_plus_version_features(package_name: str, version: str) -> dict[str, float]:
    """NAME_PLUS_VERSION — lexical name + version nuisance features."""
    out = package_name_lexical_features(package_name, version)
    out.update(version_only_features(version))
    # Dataset V1 compatibility features derived from full sample_id string.
    sid = f"{package_name}@{version}" if version else package_name
    out["sample_id_len"] = float(len(sid))
    out["sample_id_at_count"] = float(sid.count("@"))
    out["sample_id_digit_count"] = float(sum(ch.isdigit() for ch in sid))
    return out


def v1_legacy_name_morphology_from_sample_id(sample_id: str) -> dict[str, float]:
    """Exact Dataset V1 ``shortcut_name_hash`` feature set (misnamed historically)."""
    return {
        "name_len": float(len(sample_id.split("@")[0])),
        "version_len": float(len(sample_id.split("@")[-1])),
        "at_count": float(sample_id.count("@")),
        "digit_count": float(sum(ch.isdigit() for ch in sample_id)),
    }


def opaque_random_id_features(sample_id: str, *, seed: int = 0, dims: int = 4) -> dict[str, float]:
    """Opaque pseudo-random features from sample_id (should be near chance).

    Uses a cryptographic hash of (seed, sample_id) mapped to floats in [0,1).
    Labels must never influence the mapping.
    """
    out: dict[str, float] = {}
    for i in range(dims):
        digest = hashlib.sha256(f"{seed}:{i}:{sample_id}".encode("utf-8")).digest()
        # Interpret first 8 bytes as uint64 fraction
        value = int.from_bytes(digest[:8], "big") / float(2**64)
        out[f"opaque_{i}"] = float(value)
    return out


def source_one_hot(dataset_source: str | None) -> dict[str, float]:
    sources = ("datadog", "npm-registry", "openssf", "fixture", "other")
    src = (dataset_source or "other").lower()
    if src not in sources:
        src = "other"
    return {f"source_{s}": float(1.0 if s == src else 0.0) for s in sources}


def artifact_structure_features(structured: dict[str, Any]) -> dict[str, float]:
    """ARTIFACT_STRUCTURE_ONLY — size/file counts, no finding/chain signals."""
    return {
        "fileCount": float(structured.get("fileCount", 0)),
        "analysedExecutableBytes": float(structured.get("analysedExecutableBytes", 0)),
        "coverageRatio": float(structured.get("coverageRatio", 0)),
        "lifecycleHookCount": float(structured.get("lifecycleHookCount", 0)),
        "hasPreinstall": float(structured.get("hasPreinstall", 0)),
        "hasInstall": float(structured.get("hasInstall", 0)),
        "hasPostinstall": float(structured.get("hasPostinstall", 0)),
    }


def behaviour_only_features(structured: dict[str, Any]) -> dict[str, float]:
    """BEHAVIOUR_ONLY — security evidence; excludes package identity/metadata shortcuts."""
    banned_prefixes = ()
    keys = [
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
        "completenessStatusComplete",
        "completenessStatusDegraded",
        "completenessStatusInsufficient",
        "familyBreadth",
        "lifecycleHookCount",
        "hasPreinstall",
        "hasInstall",
        "hasPostinstall",
    ]
    out = {k: float(structured.get(k, 0)) for k in keys}
    for prefix, field in (
        ("cat", "findingsByCategory"),
        ("sev", "findingsBySeverity"),
        ("conf", "findingsByConfidence"),
        ("chainType", "chainsByType"),
    ):
        mapping = structured.get(field) or {}
        for name, count in sorted(mapping.items()):
            out[f"{prefix}:{name}"] = float(count)
    # Explicitly drop pure structure if we want stricter behaviour — keep hooks
    # because install-time reachability is behavioural composition context.
    _ = banned_prefixes
    return out


def generic_metadata_features(
    *,
    package_name: str,
    version: str,
    dataset_source: str | None,
    structured: dict[str, Any] | None = None,
    include_source: bool = False,
) -> dict[str, float]:
    """GENERIC_METADATA_ONLY — morphology + optional structure; source off by default.

    Dataset source is a perfect label proxy on Datadog-vs-npm pilots (PR-AUC→1.0).
    Keep source in an explicit SOURCE_ONLY bias detector, not in generic nuisance.
    """
    out = name_plus_version_features(package_name, version)
    if include_source:
        out.update(source_one_hot(dataset_source))
    if structured:
        out.update(artifact_structure_features(structured))
        for k in list(out):
            if k.startswith(("cat:", "sev:", "conf:", "chainType:")):
                out.pop(k)
            if k in {
                "findingCount",
                "chainCount",
                "processExecutionCount",
                "remoteDownloadCount",
                "shellCommandCount",
                "sensitiveFileCount",
                "environmentAccessCount",
                "networkDestinationCount",
                "opaqueSourceCount",
            }:
                out.pop(k, None)
    return out
