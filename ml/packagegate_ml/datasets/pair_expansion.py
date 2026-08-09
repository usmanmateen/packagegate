"""Expand compromise pairs + negative NO_KNOWN_COMPROMISE pairs for Dataset V3."""

from __future__ import annotations

import json
from pathlib import Path

from packagegate_ml.datasets.compromise_pairs import (
    build_compromise_pairs,
    datadog_name_to_npm,
    download_npm_tarball,
    list_npm_versions,
    pick_adjacent_clean_versions,
)
from packagegate_ml.datasets.paths import benign_root, scratch_root
from packagegate_ml.datasets.schema import (
    CompromisePair,
    DatasetRecord,
    SampleLabel,
    family_group_for,
    hash_package_name,
    sample_id_for,
)


def build_negative_version_pairs(
    records: list[DatasetRecord],
    positive_pairs: list[CompromisePair],
    *,
    max_negatives: int = 120,
) -> tuple[list[CompromisePair], list[DatasetRecord]]:
    """
    Build NO_KNOWN_COMPROMISE version pairs.

    Prefer same families as positives (earlier clean→clean), else benign catalogue upgrades.
    """
    malicious_versions: dict[str, set[str]] = {}
    by_pkg: dict[str, list[DatasetRecord]] = {}
    for rec in records:
        if not rec.package_name or not rec.version:
            continue
        by_pkg.setdefault(rec.package_name, []).append(rec)
        if rec.label in {SampleLabel.MALICIOUS, SampleLabel.COMPROMISED}:
            malicious_versions.setdefault(rec.package_name, set()).add(rec.version)

    positive_families = {p.family_group for p in positive_pairs}
    existing_ids = {r.sample_id for r in records}
    new_records: list[DatasetRecord] = []
    negatives: list[CompromisePair] = []
    skipped: list[dict[str, str]] = []

    # 1) Within positive families: two clean versions if available
    for fam in sorted(positive_families):
        if len(negatives) >= max_negatives:
            break
        # find package name from any member
        pkgs = [
            r.package_name
            for r in records
            if r.package_name
            and (
                r.family_group == fam
                or family_group_for(r.package_name) == fam
            )
        ]
        if not pkgs:
            # family may be fam::root — fall back via pair
            continue
        # Use package names from positive pairs in this family
        pair_pkgs = [p for p in positive_pairs if p.family_group == fam]
        for pp in pair_pkgs:
            if len(negatives) >= max_negatives:
                break
            # clean version already known; try another clean adjacent to clean
            pkg = None
            for r in records:
                if r.sample_id == pp.clean_sample_id and r.package_name:
                    pkg = r.package_name
                    break
            if not pkg:
                continue
            mal = malicious_versions.get(pkg, set()) | malicious_versions.get(
                next(
                    (
                        r.package_name
                        for r in records
                        if r.sample_id == pp.compromised_sample_id and r.package_name
                    ),
                    pkg,
                ),
                set(),
            )
            try:
                versions = list_npm_versions(pkg)
            except Exception as exc:  # noqa: BLE001
                skipped.append({"pkg": pkg, "reason": f"versions:{exc}"})
                continue
            cleans = [v for v in versions if v not in mal]
            # pick two cleans around the known clean version
            if pp.clean_version not in cleans:
                cleans.append(pp.clean_version)
            ordered = pick_adjacent_clean_versions(
                cleans, pp.clean_version, mal, max_clean=3
            )
            # Need a version different from clean that is also not malicious
            candidates = [v for v in ordered if v != pp.clean_version]
            if not candidates:
                # try any two cleans
                cleans_sorted = sorted(set(cleans))
                if len(cleans_sorted) < 2:
                    continue
                idx = cleans_sorted.index(pp.clean_version) if pp.clean_version in cleans_sorted else 0
                other = cleans_sorted[idx - 1] if idx > 0 else cleans_sorted[min(1, len(cleans_sorted)-1)]
                if other == pp.clean_version:
                    continue
                candidates = [other]
            other = candidates[0]
            npm_name = datadog_name_to_npm(pkg)
            a_sid = sample_id_for(npm_name, pp.clean_version)
            b_sid = sample_id_for(npm_name, other)
            # ensure both available
            for sid, ver in ((a_sid, pp.clean_version), (b_sid, other)):
                if sid in existing_ids:
                    continue
                out = benign_root() / "npm-pair-neg" / f"{sid.replace('/', '_')}.tgz"
                sha = download_npm_tarball(npm_name, ver, out)
                if sha is None:
                    skipped.append({"sample": sid, "reason": "download_failed"})
                    continue
                new_records.append(
                    DatasetRecord(
                        sample_id=sid,
                        package_name=npm_name,
                        version=ver,
                        label=SampleLabel.EXPECTED_BENIGN,
                        label_source="npm-negative-pair-version",
                        family_group=family_group_for(npm_name),
                        available=True,
                        artifact_sha256=sha,
                        artifact_path=str(out),
                        artifact_path_external=str(out),
                        package_name_hash=hash_package_name(npm_name),
                        dataset_source="npm-registry",
                        hard_negative_category="negative_version_pair",
                        benchmark_tags=("pg_delta_negative",),
                        notes=f"NO_KNOWN_COMPROMISE pair member for {npm_name}",
                    )
                )
                existing_ids.add(sid)
            if a_sid not in existing_ids or b_sid not in existing_ids:
                continue
            # order by version string compare loosely using pick order: older→newer
            from packagegate_ml.datasets.compromise_pairs import _version_key

            v1, v2 = pp.clean_version, other
            if _version_key(v1) > _version_key(v2):
                v1, v2 = v2, v1
                a_sid, b_sid = b_sid, a_sid
            sha1 = next((r.artifact_sha256 for r in [*records, *new_records] if r.sample_id == a_sid), None)
            sha2 = next((r.artifact_sha256 for r in [*records, *new_records] if r.sample_id == b_sid), None)
            negatives.append(
                CompromisePair(
                    pair_id=f"{family_group_for(npm_name)}::{v1}->{v2}::NEG",
                    family_group=family_group_for(npm_name),
                    clean_sample_id=a_sid,
                    compromised_sample_id=b_sid,  # "after" version (not compromised)
                    clean_version=v1,
                    compromised_version=v2,
                    clean_artifact_sha256=sha1,
                    compromised_artifact_sha256=sha2,
                    label="NO_KNOWN_COMPROMISE",
                    notes="benign version upgrade; neither version Datadog-labelled malicious",
                )
            )

    # 2) Unrelated expected-benign packages with ≥2 acquired versions (rare) — skip if enough

    (scratch_root() / "negative_pairs_skipped.json").write_text(
        json.dumps(skipped, indent=2), encoding="utf-8"
    )
    return negatives[:max_negatives], new_records


def expand_positive_pairs(
    records: list[DatasetRecord],
    *,
    max_pairs: int = 160,
) -> tuple[list[CompromisePair], list[DatasetRecord]]:
    """Acquire additional adjacent cleans for compromised_lib samples."""
    return build_compromise_pairs(
        records,
        max_pairs=max_pairs,
        max_clean_per_compromised=3,
    )
