"""Acquire expected-benign npm tarballs via registry HTTP (never npm install)."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from packagegate_ml.datasets.benign_catalogue import benign_catalogue
from packagegate_ml.datasets.paths import benign_root, scratch_root
from packagegate_ml.datasets.schema import (
    QUALITATIVE_HOLDOUT_IDS,
    DatasetRecord,
    SampleLabel,
    family_group_for,
    hash_package_name,
    sample_id_for,
)

REGISTRY = "https://registry.npmjs.org"
USER_AGENT = "PackageGate-ML-Pilot/1.0 (research; static-analysis-only)"


def _http_json(url: str) -> object:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def resolve_tarball(package_name: str, version: str) -> str | None:
    encoded = urllib.request.quote(package_name, safe="@/")
    # scoped: @scope/name -> registry.npmjs.org/@scope%2fname/version
    if package_name.startswith("@"):
        scope, name = package_name.split("/", 1)
        url = f"{REGISTRY}/{scope}%2f{name}/{version}"
    else:
        url = f"{REGISTRY}/{package_name}/{version}"
    try:
        meta = _http_json(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    if not isinstance(meta, dict):
        return None
    dist = meta.get("dist")
    if not isinstance(dist, dict):
        return None
    tarball = dist.get("tarball")
    return tarball if isinstance(tarball, str) else None


def acquire_benign_pilot(*, max_samples: int = 400) -> list[DatasetRecord]:
    records: list[DatasetRecord] = []
    skipped: list[dict[str, str]] = []
    acquired = 0

    # Qualitative controls metadata only (available=false for training).
    for control in sorted(QUALITATIVE_HOLDOUT_IDS):
        if control.startswith("02-echo"):
            continue
        name, version = control.split("@", 1)
        records.append(
            DatasetRecord(
                sample_id=control,
                package_name=name,
                version=version,
                label=SampleLabel.EXPECTED_BENIGN,
                label_source="npm-expected-benign-control",
                family_group=family_group_for(name),
                available=False,
                package_name_hash=hash_package_name(name),
                dataset_source="npm-registry",
                notes="Qualitative control — excluded from train/validation",
            )
        )

    for row in benign_catalogue():
        if acquired >= max_samples:
            break
        name = row["package_name"]
        version = row["version"]
        sid = sample_id_for(name, version)
        if sid in QUALITATIVE_HOLDOUT_IDS:
            continue
        try:
            tarball_url = resolve_tarball(name, version)
        except Exception as exc:  # noqa: BLE001
            skipped.append({"sample": sid, "reason": f"resolve:{exc}"})
            continue
        if tarball_url is None:
            skipped.append({"sample": sid, "reason": "not_found"})
            continue
        out = benign_root() / "npm" / f"{_safe_id(sid)}.tgz"
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            if not out.exists():
                data = _http_bytes(tarball_url)
                out.write_bytes(data)
            sha = hashlib.sha256(out.read_bytes()).hexdigest()
        except Exception as exc:  # noqa: BLE001
            skipped.append({"sample": sid, "reason": f"download:{exc}"})
            if out.exists():
                out.unlink()
            continue

        records.append(
            DatasetRecord(
                sample_id=sid,
                package_name=name,
                version=version,
                label=SampleLabel.EXPECTED_BENIGN,
                label_source="npm-expected-benign-catalogue",
                family_group=family_group_for(name),
                available=True,
                artifact_sha256=sha,
                artifact_path=str(out),
                artifact_path_external=str(out),
                package_name_hash=hash_package_name(name),
                dataset_source="npm-registry",
                hard_negative_category=row["hard_negative_category"],
                notes=row["notes"],
            )
        )
        acquired += 1
        if acquired % 25 == 0:
            print(json.dumps({"benign_progress": acquired, "latest": sid}))

    (scratch_root() / "benign_skipped.json").write_text(
        json.dumps(skipped, indent=2), encoding="utf-8"
    )
    return records


def _safe_id(sample_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9@._+-]+", "_", sample_id)
