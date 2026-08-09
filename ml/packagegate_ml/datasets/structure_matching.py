"""Strict nuisance-structure matching for Dataset V3."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass

import numpy as np

from packagegate_ml.datasets.feature_families import matching_nuisance_vector
from packagegate_ml.datasets.schema import DatasetRecord, SampleLabel


MATCH_KEYS = [
    "fileCount",
    "analysedExecutableBytes",
    "coverageRatio",
    "hasPreinstall",
    "hasInstall",
    "hasPostinstall",
    "lifecycleHookCount",
    "name_len",
    "scoped",
    "digit_fraction_name",
    "segment_count",
    "version_len",
    "version_unusual_large",
    "version_is_zeroish",
]


@dataclass
class StructureMatch:
    malicious_sample_id: str
    matched_benign_sample_ids: tuple[str, ...]
    matching_distance: float
    matching_features: dict[str, float]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["matched_benign_sample_ids"] = list(self.matched_benign_sample_ids)
        return d


@dataclass
class MatchBalanceReport:
    matches: list[StructureMatch]
    unmatched_malicious: list[str]
    before_smd: dict[str, float]
    after_smd: dict[str, float]


def _vector(rec: DatasetRecord, feature_rows: dict[str, dict]) -> np.ndarray | None:
    row = feature_rows.get(rec.sample_id)
    if row is None or not rec.package_name:
        return None
    structured = row.get("structured") or row.get("features") or {}
    feats = matching_nuisance_vector(
        package_name=rec.package_name,
        version=rec.version or "",
        structured=structured,
    )
    return np.array([float(feats.get(k, 0.0)) for k in MATCH_KEYS], dtype=np.float64)


def _smd(a: np.ndarray, b: np.ndarray) -> float:
    """Standardised mean difference."""
    pooled = math.sqrt((a.var() + b.var()) / 2.0) or 1.0
    return float((a.mean() - b.mean()) / pooled)


def structure_match(
    records: list[DatasetRecord],
    feature_rows: dict[str, dict],
    *,
    max_matches: int = 2,
    max_distance: float = 3.5,
) -> MatchBalanceReport:
    malicious = [
        r
        for r in records
        if r.available
        and r.label in {SampleLabel.MALICIOUS, SampleLabel.COMPROMISED}
        and r.sample_id in feature_rows
    ]
    benign = [
        r
        for r in records
        if r.available
        and r.label == SampleLabel.EXPECTED_BENIGN
        and r.sample_id in feature_rows
        and r.hard_negative_category != "compromised_version_control"
    ]
    mal_vecs = []
    mal_recs = []
    for r in malicious:
        v = _vector(r, feature_rows)
        if v is not None:
            mal_vecs.append(v)
            mal_recs.append(r)
    ben_vecs = []
    ben_recs = []
    for r in benign:
        v = _vector(r, feature_rows)
        if v is not None:
            ben_vecs.append(v)
            ben_recs.append(r)
    if not mal_vecs or not ben_vecs:
        return MatchBalanceReport([], [r.sample_id for r in malicious], {}, {})

    mal_x = np.vstack(mal_vecs)
    ben_x = np.vstack(ben_vecs)
    all_x = np.vstack([mal_x, ben_x])
    mean = all_x.mean(axis=0)
    std = all_x.std(axis=0)
    std = np.where(std < 1e-8, 1.0, std)
    mal_s = (mal_x - mean) / std
    ben_s = (ben_x - mean) / std

    before = {
        MATCH_KEYS[i]: _smd(mal_x[:, i], ben_x[:, i]) for i in range(len(MATCH_KEYS))
    }

    used: set[int] = set()
    matches: list[StructureMatch] = []
    unmatched: list[str] = []
    order = sorted(range(len(mal_recs)), key=lambda i: mal_recs[i].sample_id)
    for mi in order:
        distances = []
        for bi in range(len(ben_recs)):
            if bi in used:
                continue
            dist = float(np.linalg.norm(mal_s[mi] - ben_s[bi]))
            distances.append((dist, bi))
        distances.sort(key=lambda t: (t[0], ben_recs[t[1]].sample_id))
        chosen: list[str] = []
        best = math.inf
        for dist, bi in distances:
            if dist > max_distance:
                break
            if len(chosen) >= max_matches:
                break
            chosen.append(ben_recs[bi].sample_id)
            used.add(bi)
            best = min(best, dist)
        if not chosen:
            unmatched.append(mal_recs[mi].sample_id)
            continue
        feat = {
            MATCH_KEYS[i]: float(mal_x[mi, i]) for i in range(len(MATCH_KEYS))
        }
        matches.append(
            StructureMatch(
                malicious_sample_id=mal_recs[mi].sample_id,
                matched_benign_sample_ids=tuple(chosen),
                matching_distance=float(best),
                matching_features=feat,
            )
        )

    # After matching SMD
    if matches:
        m_idx = [i for i, r in enumerate(mal_recs) if any(m.malicious_sample_id == r.sample_id for m in matches)]
        b_ids = {sid for m in matches for sid in m.matched_benign_sample_ids}
        b_idx = [i for i, r in enumerate(ben_recs) if r.sample_id in b_ids]
        after = {
            MATCH_KEYS[i]: _smd(mal_x[m_idx, i], ben_x[b_idx, i])
            for i in range(len(MATCH_KEYS))
        }
    else:
        after = {}

    return MatchBalanceReport(matches, unmatched, before, after)
