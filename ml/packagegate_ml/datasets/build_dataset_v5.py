"""Build Dataset V5 external/temporal holdout — inference only for Exp1."""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import urllib.error
from collections import Counter
from dataclasses import replace
from pathlib import Path

os.environ.setdefault("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data-v5")

from packagegate_ml.datasets.benign_adapter import resolve_tarball, _http_bytes
from packagegate_ml.datasets.benign_catalogue import benign_catalogue
from packagegate_ml.datasets.canonical import canonicalise_artifact
from packagegate_ml.datasets.compromise_pairs import datadog_name_to_npm
from packagegate_ml.datasets.datadog_adapter import (
    list_npm_zip_paths,
    zip_to_npm_tgz,
    _http_bytes as dd_http_bytes,
    _safe_id,
)
from packagegate_ml.datasets.dedup import cluster_duplicates
from packagegate_ml.datasets.paths import data_root, external_manifests_root, malware_root, benign_root
from packagegate_ml.datasets.schema import (
    DatasetRecord,
    SampleLabel,
    family_group_for,
    hash_package_name,
    sample_id_for,
)
from packagegate_ml.datasets.splits import write_manifest

REPO = Path(__file__).resolve().parents[3]
V4_PRIVATE = Path("/tmp/packagegate-ml-data-v4/manifests/dataset_v4_full.private.json")
FROZEN = REPO / "ml" / "data-manifests" / "v5"
TRAINING_CUTOFF = "2026-06-10"  # from Exp1 freeze / V4-linked Datadog dates


def load_v4_exclusion() -> dict:
    records = json.loads(V4_PRIVATE.read_text(encoding="utf-8"))["records"]
    names = set()
    families = set()
    sample_ids = set()
    shas = set()
    for r in records:
        if r.get("package_name"):
            names.add(r["package_name"].lower())
        if r.get("family_group"):
            families.add(r["family_group"])
        sample_ids.add(r["sample_id"])
        if r.get("artifact_sha256"):
            shas.add(r["artifact_sha256"])
    return {
        "names": names,
        "families": families,
        "sample_ids": sample_ids,
        "shas": shas,
    }


def select_temporal_malicious(*, max_packages: int = 80, seed: int = 7) -> list[dict]:
    excl = load_v4_exclusion()
    entries = list_npm_zip_paths(
        cache=Path("/tmp/packagegate-ml-data-v2/scratch/datadog_npm_zip_index.json")
    )
    rng = random.Random(seed)
    by_family: dict[str, list[dict]] = {}
    for e in entries:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", e["zip_name"])
        if not m or m.group(1) <= TRAINING_CUTOFF:
            continue
        npm = datadog_name_to_npm(e["package_name"])
        if npm.lower() in excl["names"] or e["package_name"].lower() in excl["names"]:
            continue
        fam = family_group_for(npm)
        if fam in excl["families"]:
            continue
        sid = sample_id_for(npm, e["version"])
        if sid in excl["sample_ids"]:
            continue
        e = dict(e)
        e["npm_name"] = npm
        e["observed_date"] = m.group(1)
        e["family"] = fam
        e["sample_id"] = sid
        by_family.setdefault(fam, []).append(e)

    families = sorted(by_family.keys())
    rng.shuffle(families)
    # diversify categories: prefer mix of compromised_lib and malicious_intent
    selected: list[dict] = []
    cat_counts: Counter[str] = Counter()
    for fam in families:
        if len(selected) >= max_packages:
            break
        cands = by_family[fam]
        # one per family
        cands.sort(key=lambda x: (0 if x["category"] == "compromised_lib" else 1, x["observed_date"]))
        pick = cands[0]
        # soft category balance
        if cat_counts[pick["category"]] >= max_packages * 0.65 and pick["category"] == "malicious_intent":
            alt = next((c for c in cands if c["category"] == "compromised_lib"), None)
            if alt:
                pick = alt
        selected.append(pick)
        cat_counts[pick["category"]] += 1
    return selected


def select_benign(*, max_packages: int = 160, seed: int = 7) -> list[dict]:
    excl = load_v4_exclusion()
    rng = random.Random(seed)
    rows = list(benign_catalogue())
    rng.shuffle(rows)
    # Prefer hard-negative categories
    prefer = {
        "native_installers",
        "binary_downloaders",
        "network_libraries",
        "build_tools",
        "package_managers",
        "cloud_sdks",
        "cli_tools",
    }
    rows.sort(key=lambda r: (0 if r["hard_negative_category"] in prefer else 1, r["package_name"]))
    out = []
    seen_fam = set()
    for row in rows:
        if len(out) >= max_packages:
            break
        name = row["package_name"]
        ver = row["version"]
        sid = sample_id_for(name, ver)
        fam = family_group_for(name)
        if name.lower() in excl["names"] or sid in excl["sample_ids"] or fam in excl["families"]:
            continue
        if fam in seen_fam:
            continue
        seen_fam.add(fam)
        out.append(
            {
                "package_name": name,
                "version": ver,
                "sample_id": sid,
                "family": fam,
                "hard_negative_category": row["hard_negative_category"],
                "notes": row.get("notes"),
            }
        )
    return out


def acquire_malicious(entries: list[dict]) -> list[DatasetRecord]:
    out_dir = malware_root() / "datadog-v5"
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[DatasetRecord] = []
    for e in entries:
        sid = e["sample_id"]
        tgz = out_dir / f"{_safe_id(sid)}.tgz"
        try:
            if not tgz.exists():
                raw = dd_http_bytes(e["download_url"])
                sha = zip_to_npm_tgz(raw, tgz)
            else:
                sha = hashlib.sha256(tgz.read_bytes()).hexdigest()
            # canonicalise
            canon = data_root() / "canonical" / f"{_safe_id(sid)}.tgz"
            if not canon.exists():
                canonicalise_artifact(tgz, canon)
            sha = hashlib.sha256(canon.read_bytes()).hexdigest()
            label = (
                SampleLabel.COMPROMISED
                if e["category"] == "compromised_lib"
                else SampleLabel.MALICIOUS
            )
            records.append(
                DatasetRecord(
                    sample_id=sid,
                    package_name=e["npm_name"],
                    version=e["version"],
                    label=label,
                    label_source="datadog-malicious-software-packages-dataset",
                    label_reference=e["path"],
                    family_group=e["family"],
                    available=True,
                    package_name_hash=hash_package_name(e["npm_name"]),
                    artifact_path=str(canon),
                    artifact_path_external=str(canon),
                    artifact_sha256=sha,
                    dataset_source="datadog",
                    attack_category=e["category"],
                    notes=f"V5_TEMPORAL_UNSEEN observed={e['observed_date']} cutoff={TRAINING_CUTOFF}",
                    hard_negative_category=None,
                    benchmark_tags=["v5", "temporal_unseen", e["category"]],
                )
            )
        except (urllib.error.URLError, OSError, FileNotFoundError, ValueError) as exc:
            records.append(
                DatasetRecord(
                    sample_id=sid,
                    package_name=e["npm_name"],
                    version=e["version"],
                    label=SampleLabel.MALICIOUS,
                    label_source="datadog-malicious-software-packages-dataset",
                    label_reference=e["path"],
                    family_group=e["family"],
                    available=False,
                    package_name_hash=hash_package_name(e["npm_name"]),
                    dataset_source="datadog",
                    notes=f"V5_ACQUIRE_FAIL:{exc}",
                    benchmark_tags=["v5"],
                )
            )
    return records


def acquire_benign(entries: list[dict]) -> list[DatasetRecord]:
    out_dir = benign_root() / "v5"
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[DatasetRecord] = []
    for e in entries:
        sid = e["sample_id"]
        tgz = out_dir / f"{_safe_id(sid)}.tgz"
        try:
            if not tgz.exists():
                url = resolve_tarball(e["package_name"], e["version"])
                if not url:
                    raise FileNotFoundError("registry 404")
                tgz.write_bytes(_http_bytes(url))
            canon = data_root() / "canonical" / f"{_safe_id(sid)}.tgz"
            if not canon.exists():
                canonicalise_artifact(tgz, canon)
            sha = hashlib.sha256(canon.read_bytes()).hexdigest()
            records.append(
                DatasetRecord(
                    sample_id=sid,
                    package_name=e["package_name"],
                    version=e["version"],
                    label=SampleLabel.EXPECTED_BENIGN,
                    label_source="npm-expected-benign-hard-negative",
                    family_group=e["family"],
                    available=True,
                    package_name_hash=hash_package_name(e["package_name"]),
                    artifact_path=str(canon),
                    artifact_path_external=str(canon),
                    artifact_sha256=sha,
                    dataset_source="npm-registry",
                    notes="V5_HARD_NEGATIVE",
                    hard_negative_category=e.get("hard_negative_category"),
                    benchmark_tags=["v5", "hard_negative"],
                )
            )
        except Exception as exc:  # noqa: BLE001
            records.append(
                DatasetRecord(
                    sample_id=sid,
                    package_name=e["package_name"],
                    version=e["version"],
                    label=SampleLabel.EXPECTED_BENIGN,
                    label_source="npm-expected-benign-hard-negative",
                    family_group=e["family"],
                    available=False,
                    package_name_hash=hash_package_name(e["package_name"]),
                    dataset_source="npm-registry",
                    notes=f"V5_ACQUIRE_FAIL:{exc}",
                    hard_negative_category=e.get("hard_negative_category"),
                    benchmark_tags=["v5"],
                )
            )
    return records


def overlap_audit(records: list[DatasetRecord]) -> dict:
    excl = load_v4_exclusion()
    name_hit = []
    fam_hit = []
    sid_hit = []
    sha_hit = []
    for r in records:
        if not r.available:
            continue
        if (r.package_name or "").lower() in excl["names"]:
            name_hit.append(r.sample_id)
        if r.family_group in excl["families"]:
            fam_hit.append(r.sample_id)
        if r.sample_id in excl["sample_ids"]:
            sid_hit.append(r.sample_id)
        if r.artifact_sha256 and r.artifact_sha256 in excl["shas"]:
            sha_hit.append(r.sample_id)
    # near-dup via content fingerprint vs V4 available artifacts would be expensive;
    # use within-V5 dedup + sha overlap for now, plus family/name.
    report = cluster_duplicates([r for r in records if r.available])
    return {
        "nameOverlap": name_hit,
        "familyOverlap": fam_hit,
        "sampleIdOverlap": sid_hit,
        "shaOverlap": sha_hit,
        "exactDupGroups": len(report.exact_artifact_groups),
        "nearDupGroups": len(report.near_duplicate_groups),
        "nearDupGroupsDetail": {
            k: v for k, v in list(report.near_duplicate_groups.items())[:20]
        },
        "passed": not (name_hit or fam_hit or sid_hit or sha_hit),
    }


def main() -> None:
    print(json.dumps({"data_root": str(data_root()), "cutoff": TRAINING_CUTOFF}))
    mal_sel = select_temporal_malicious(max_packages=80, seed=7)
    ben_sel = select_benign(max_packages=160, seed=7)
    print(
        json.dumps(
            {
                "selected_malicious": len(mal_sel),
                "selected_benign": len(ben_sel),
                "mal_cats": dict(Counter(e["category"] for e in mal_sel)),
            }
        )
    )
    mal = acquire_malicious(mal_sel)
    ben = acquire_benign(ben_sel)
    records = [*mal, *ben]
    audit = overlap_audit(records)
    # Mark overlapping as unavailable
    bad = set(
        audit["nameOverlap"]
        + audit["familyOverlap"]
        + audit["sampleIdOverlap"]
        + audit["shaOverlap"]
    )
    cleaned = []
    for r in records:
        if r.sample_id in bad:
            cleaned.append(
                replace(
                    r,
                    available=False,
                    notes=(r.notes or "") + "; V5_EXCLUDED_V4_OVERLAP",
                )
            )
        else:
            cleaned.append(r)
    records = cleaned
    audit = overlap_audit([r for r in records if r.available])

    FROZEN.mkdir(parents=True, exist_ok=True)
    write_manifest(
        external_manifests_root() / "dataset_v5_full.private.json",
        records,
        include_package_name=True,
    )
    write_manifest(
        external_manifests_root() / "dataset_v5_full.json",
        records,
        include_package_name=False,
    )
    avail = [r for r in records if r.available]
    summary = {
        "datasetVersion": "v5",
        "purpose": "external_temporal_holdout_inference_only",
        "trainingDataCutoff": TRAINING_CUTOFF,
        "total": len(records),
        "available": len(avail),
        "labels": dict(Counter(r.label.value for r in avail)),
        "temporalUnseen": sum(1 for r in avail if "TEMPORAL_UNSEEN" in (r.notes or "")),
        "hardNegatives": sum(1 for r in avail if r.label == SampleLabel.EXPECTED_BENIGN),
        "overlapAudit": {
            k: v
            for k, v in audit.items()
            if k != "nearDupGroupsDetail"
        },
        "categories": dict(Counter(r.attack_category or "benign" for r in avail)),
    }
    (FROZEN / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (FROZEN / "overlap_audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    (FROZEN / "sample_ids.json").write_text(
        json.dumps(sorted(r.sample_id for r in avail), indent=2) + "\n"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
