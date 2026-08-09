"""Exact and near-duplicate clustering for PackageGate ML samples."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from packagegate_ml.datasets.schema import DatasetRecord, family_group_for


@dataclass
class DuplicateReport:
    exact_artifact_groups: dict[str, list[str]]
    near_duplicate_groups: dict[str, list[str]]
    sample_to_duplicate_group: dict[str, str]


def _normalise_js(text: str) -> str:
    # Comment strip (best-effort) + whitespace collapse for fingerprinting only.
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(^|[^:])//.*?$", "", text, flags=re.M)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def _shingles(text: str, k: int = 5) -> set[str]:
    if len(text) < k:
        return {text} if text else set()
    return {text[i : i + k] for i in range(len(text) - k + 1)}


def _simhash(tokens: set[str], bits: int = 64) -> int:
    v = [0] * bits
    for token in tokens:
        h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
        for i in range(bits):
            bit = (h >> i) & 1
            v[i] += 1 if bit else -1
    out = 0
    for i, weight in enumerate(v):
        if weight > 0:
            out |= 1 << i
    return out


def _hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def content_fingerprint_from_tgz(path: Path, max_files: int = 40) -> tuple[str, int]:
    """
    Return (sha256_of_normalised_concat, simhash) from JS/TS files in a tarball.
    Never executes content.
    """
    parts: list[str] = []
    try:
        with tarfile.open(path, "r:*") as tar:
            members = [
                m
                for m in tar.getmembers()
                if m.isfile()
                and re.search(r"\.(?:[cm]?js|jsx|[cm]?ts|tsx)$", m.name, re.I)
            ]
            members = members[:max_files]
            for member in members:
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                raw = extracted.read(200_000)
                try:
                    text = raw.decode("utf-8", errors="ignore")
                except Exception:  # noqa: BLE001
                    continue
                parts.append(_normalise_js(text))
    except tarfile.TarError:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return digest, _simhash({digest})

    joined = "\n".join(parts)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
    shingles = _shingles(joined[:50_000])
    return digest, _simhash(shingles)


def cluster_duplicates(records: list[DatasetRecord]) -> DuplicateReport:
    by_artifact: dict[str, list[str]] = defaultdict(list)
    fingerprints: dict[str, tuple[str, int]] = {}

    for record in records:
        if not record.available:
            continue
        path = record.artifact_path or record.artifact_path_external
        if record.artifact_sha256:
            by_artifact[record.artifact_sha256].append(record.sample_id)
        if not path:
            continue
        p = Path(path)
        if not p.exists() or not p.is_file():
            # Fixture source directories are handled by export, not tar fingerprinting.
            continue
        fingerprints[record.sample_id] = content_fingerprint_from_tgz(p)

    exact_groups = {
        sha: ids for sha, ids in by_artifact.items() if len(ids) > 1
    }

    # Near-duplicate: same normalised content hash OR close simhash.
    # Ignore empty fingerprints (packages with no JS/TS source).
    empty_sha = hashlib.sha256(b"").hexdigest()
    by_content: dict[str, list[str]] = defaultdict(list)
    for sample_id, (content_hash, _sim) in fingerprints.items():
        if content_hash == empty_sha:
            continue
        by_content[content_hash].append(sample_id)
    near_groups: dict[str, list[str]] = {
        f"content:{h}": ids for h, ids in by_content.items() if len(ids) > 1
    }

    ids = [
        sid
        for sid, (content_hash, _) in fingerprints.items()
        if content_hash != empty_sha
    ]
    assigned: dict[str, str] = {}
    cluster_idx = 0
    for i, a in enumerate(ids):
        if a in assigned:
            continue
        _, sim_a = fingerprints[a]
        members = [a]
        for b in ids[i + 1 :]:
            if b in assigned:
                continue
            _, sim_b = fingerprints[b]
            if _hamming(sim_a, sim_b) <= 3:
                members.append(b)
        if len(members) > 1:
            gid = f"near:{cluster_idx}"
            cluster_idx += 1
            near_groups[gid] = members
            for m in members:
                assigned[m] = gid

    sample_to_group: dict[str, str] = {}
    for sha, ids in exact_groups.items():
        gid = f"exact:{sha[:12]}"
        for sample_id in ids:
            sample_to_group[sample_id] = gid
    for gid, ids in near_groups.items():
        for sample_id in ids:
            sample_to_group.setdefault(sample_id, gid)

    return DuplicateReport(
        exact_artifact_groups=exact_groups,
        near_duplicate_groups=near_groups,
        sample_to_duplicate_group=sample_to_group,
    )


def apply_duplicate_groups(
    records: list[DatasetRecord],
    report: DuplicateReport,
) -> list[DatasetRecord]:
    """
    Attach duplicate IDs and unify split families.

    All versions of a package plus any near/exact duplicate cluster members
    must share one family_group so they never cross train/test.
    """
    # Union-find over package identity + duplicate clusters
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    pkg_family: dict[str, str] = {}
    for record in records:
        if record.package_name:
            pkg_family[record.sample_id] = family_group_for(record.package_name)
        else:
            pkg_family[record.sample_id] = record.family_group

    for sid, fam in pkg_family.items():
        union(sid, f"pkg::{fam}")

    for sid, gid in report.sample_to_duplicate_group.items():
        union(sid, f"dup::{gid}")
        for other, og in report.sample_to_duplicate_group.items():
            if og == gid:
                union(sid, other)

    updated: list[DatasetRecord] = []
    for record in records:
        gid = report.sample_to_duplicate_group.get(record.sample_id)
        root = find(record.sample_id)
        updated.append(
            DatasetRecord(
                **{
                    **record.__dict__,
                    "duplicate_group_id": gid,
                    "family_group": f"fam::{root}",
                }
            )
        )
    return updated


def write_duplicate_report(path: Path, report: DuplicateReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "exactArtifactGroups": report.exact_artifact_groups,
                "nearDuplicateGroups": report.near_duplicate_groups,
                "sampleToDuplicateGroup": report.sample_to_duplicate_group,
                "exactGroupCount": len(report.exact_artifact_groups),
                "nearGroupCount": len(report.near_duplicate_groups),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
