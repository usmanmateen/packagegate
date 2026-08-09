"""Name-morphology / nuisance nearest-neighbour matching for Dataset V2."""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from packagegate_ml.datasets.schema import DatasetRecord, MatchRecord, SampleLabel
from packagegate_ml.training.shortcut_features import name_plus_version_features


MATCH_FEATURE_KEYS = [
    "name_len",
    "scoped",
    "at_count_in_name",
    "hyphen_count",
    "underscore_count",
    "digit_count_name",
    "digit_fraction_name",
    "segment_count",
    "avg_segment_len",
    "version_len",
    "version_component_count",
    "version_unusual_large",
    "version_is_zeroish",
]


def morphology_vector(record: DatasetRecord) -> np.ndarray:
    name = record.package_name or ""
    version = record.version or ""
    feats = name_plus_version_features(name, version)
    return np.array([float(feats.get(k, 0.0)) for k in MATCH_FEATURE_KEYS], dtype=np.float64)


def _standardise(matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    mean = matrix.mean(axis=0)
    std = matrix.std(axis=0)
    std = np.where(std < 1e-8, 1.0, std)
    return (matrix - mean) / std, mean, std


@dataclass
class MatchReport:
    matches: list[MatchRecord]
    unmatched_malicious: list[str]


def match_malicious_to_benign(
    records: list[DatasetRecord],
    *,
    max_matches_per_malicious: int = 2,
    max_distance: float = 4.0,
) -> MatchReport:
    """
    Greedy nearest-neighbour matching on nuisance morphology only.

    Never uses PackageGate findings, chains, risk, or threat intel.
    """
    malicious = [
        r
        for r in records
        if r.available
        and r.label in {SampleLabel.MALICIOUS, SampleLabel.COMPROMISED}
        and (r.attack_category == "malicious_intent" or "malicious_intent" in (r.notes or ""))
    ]
    # Fall back: any malicious without compromised_lib tag
    if not malicious:
        malicious = [
            r
            for r in records
            if r.available
            and r.label in {SampleLabel.MALICIOUS, SampleLabel.COMPROMISED}
            and r.attack_category != "compromised_lib"
        ]
    benign = [
        r
        for r in records
        if r.available and r.label == SampleLabel.EXPECTED_BENIGN
    ]
    if not malicious or not benign:
        return MatchReport(matches=[], unmatched_malicious=[r.sample_id for r in malicious])

    mal_ids = [r.sample_id for r in malicious]
    ben_ids = [r.sample_id for r in benign]
    mal_x = np.vstack([morphology_vector(r) for r in malicious])
    ben_x = np.vstack([morphology_vector(r) for r in benign])
    all_x = np.vstack([mal_x, ben_x])
    all_std, _, _ = _standardise(all_x)
    mal_s = all_std[: len(malicious)]
    ben_s = all_std[len(malicious) :]

    used_benign: set[int] = set()
    matches: list[MatchRecord] = []
    unmatched: list[str] = []

    # Process malicious in deterministic order by sample_id
    order = sorted(range(len(malicious)), key=lambda i: mal_ids[i])
    for mi in order:
        distances = []
        for bi in range(len(benign)):
            if bi in used_benign:
                continue
            dist = float(np.linalg.norm(mal_s[mi] - ben_s[bi]))
            distances.append((dist, bi))
        distances.sort(key=lambda t: (t[0], ben_ids[t[1]]))
        chosen: list[str] = []
        best_dist = math.inf
        for dist, bi in distances:
            if dist > max_distance:
                break
            if len(chosen) >= max_matches_per_malicious:
                break
            chosen.append(ben_ids[bi])
            used_benign.add(bi)
            best_dist = min(best_dist, dist)
        if not chosen:
            unmatched.append(mal_ids[mi])
            continue
        feat = {
            k: float(morphology_vector(malicious[mi])[i])
            for i, k in enumerate(MATCH_FEATURE_KEYS)
        }
        matches.append(
            MatchRecord(
                malicious_sample_id=mal_ids[mi],
                matched_benign_sample_ids=tuple(chosen),
                matching_distance=float(best_dist if best_dist < math.inf else -1),
                matching_features=feat,
            )
        )
    return MatchReport(matches=matches, unmatched_malicious=unmatched)
