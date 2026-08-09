"""Build compromised-version pairs and fetch adjacent expected-benign versions."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from packagegate_ml.datasets.benign_adapter import resolve_tarball
from packagegate_ml.datasets.paths import benign_root, scratch_root
from packagegate_ml.datasets.schema import (
    CompromisePair,
    DatasetRecord,
    SampleLabel,
    family_group_for,
    hash_package_name,
    sample_id_for,
)

USER_AGENT = "PackageGate-ML-V2/1.0 (research; static-analysis-only)"
REGISTRY = "https://registry.npmjs.org"


def datadog_name_to_npm(package_name: str) -> str:
    """Convert Datadog ``@scope@pkg`` path encoding to npm ``@scope/pkg``."""
    if package_name.startswith("@") and "/" not in package_name and package_name.count("@") >= 2:
        rest = package_name[1:]
        scope, name = rest.split("@", 1)
        return f"@{scope}/{name}"
    return package_name


def _safe_id(sample_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9@._+-]+", "_", sample_id)


def _http_json(url: str) -> object:
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def list_npm_versions(package_name: str) -> list[str]:
    npm_name = datadog_name_to_npm(package_name)
    encoded = urllib.request.quote(npm_name, safe="@/")
    if npm_name.startswith("@"):
        scope, name = npm_name.split("/", 1)
        url = f"{REGISTRY}/{scope}%2f{name}"
    else:
        url = f"{REGISTRY}/{encoded}"
    try:
        meta = _http_json(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise
    if not isinstance(meta, dict):
        return []
    versions = meta.get("versions")
    if not isinstance(versions, dict):
        return []
    return sorted(versions.keys())


def _version_key(version: str) -> tuple:
    parts = re.split(r"[.+-]", version)
    key = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part))
    return tuple(key)


def pick_adjacent_clean_versions(
    all_versions: list[str],
    compromised_version: str,
    malicious_versions: set[str],
    *,
    max_clean: int = 2,
) -> list[str]:
    """Pick nearby versions not independently labelled malicious."""
    ordered = sorted(all_versions, key=_version_key)
    if compromised_version not in ordered:
        ordered = sorted([*ordered, compromised_version], key=_version_key)
    idx = ordered.index(compromised_version)
    candidates: list[str] = []
    # Prefer immediate previous, then next, then farther previous.
    for j in range(idx - 1, -1, -1):
        v = ordered[j]
        if v not in malicious_versions:
            candidates.append(v)
            break
    for j in range(idx + 1, len(ordered)):
        v = ordered[j]
        if v not in malicious_versions and v not in candidates:
            candidates.append(v)
            break
    for j in range(idx - 2, -1, -1):
        if len(candidates) >= max_clean:
            break
        v = ordered[j]
        if v not in malicious_versions and v not in candidates:
            candidates.append(v)
    return candidates[:max_clean]


def download_npm_tarball(package_name: str, version: str, out: Path) -> str | None:
    npm_name = datadog_name_to_npm(package_name)
    try:
        url = resolve_tarball(npm_name, version)
    except Exception:  # noqa: BLE001
        return None
    if url is None:
        return None
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        if not out.exists():
            out.write_bytes(_http_bytes(url))
        return hashlib.sha256(out.read_bytes()).hexdigest()
    except Exception:  # noqa: BLE001
        out.unlink(missing_ok=True)
        return None


def build_compromise_pairs(
    records: list[DatasetRecord],
    *,
    max_pairs: int = 80,
    max_clean_per_compromised: int = 2,
) -> tuple[list[CompromisePair], list[DatasetRecord]]:
    """
    For compromised_lib samples, fetch adjacent npm versions not in malicious set.

    Returns (pairs, newly_acquired_expected_benign_records).
    """
    malicious_versions_by_pkg: dict[str, set[str]] = {}
    compromised: list[DatasetRecord] = []
    for rec in records:
        if not rec.package_name or not rec.version:
            continue
        if rec.label not in {SampleLabel.MALICIOUS, SampleLabel.COMPROMISED}:
            continue
        malicious_versions_by_pkg.setdefault(rec.package_name, set()).add(rec.version)
        if rec.attack_category == "compromised_lib" or "compromised_lib" in (rec.notes or ""):
            if rec.available:
                compromised.append(rec)

    # Also mark known malicious sample_ids across sources
    all_malicious_sids = {
        r.sample_id
        for r in records
        if r.label in {SampleLabel.MALICIOUS, SampleLabel.COMPROMISED}
    }

    existing_ids = {r.sample_id for r in records}
    new_records: list[DatasetRecord] = []
    pairs: list[CompromisePair] = []
    skipped: list[dict[str, str]] = []

    compromised = sorted(compromised, key=lambda r: r.sample_id)
    for rec in compromised:
        if len(pairs) >= max_pairs:
            break
        assert rec.package_name and rec.version
        try:
            versions = list_npm_versions(rec.package_name)
        except Exception as exc:  # noqa: BLE001
            skipped.append({"sample": rec.sample_id, "reason": f"versions:{exc}"})
            continue
        if not versions:
            skipped.append({"sample": rec.sample_id, "reason": "no_npm_versions"})
            continue
        mal_vers = malicious_versions_by_pkg.get(rec.package_name, set())
        # Expand malicious set with npm-name-normalized IDs already present
        clean_versions = pick_adjacent_clean_versions(
            versions,
            rec.version,
            mal_vers,
            max_clean=max_clean_per_compromised,
        )
        for clean_ver in clean_versions:
            if len(pairs) >= max_pairs:
                break
            npm_name = datadog_name_to_npm(rec.package_name)
            clean_sid = sample_id_for(npm_name, clean_ver)
            # Also accept datadog-encoded id form
            alt_sid = sample_id_for(rec.package_name, clean_ver)
            if clean_sid in all_malicious_sids or alt_sid in all_malicious_sids:
                skipped.append({"sample": clean_sid, "reason": "labelled_malicious"})
                continue

            out = benign_root() / "npm-adjacent" / f"{_safe_id(clean_sid)}.tgz"
            sha = None
            if clean_sid not in existing_ids and alt_sid not in existing_ids:
                sha = download_npm_tarball(rec.package_name, clean_ver, out)
                if sha is None:
                    skipped.append({"sample": clean_sid, "reason": "download_failed"})
                    continue
                new_rec = DatasetRecord(
                    sample_id=clean_sid,
                    package_name=npm_name,
                    version=clean_ver,
                    label=SampleLabel.EXPECTED_BENIGN,
                    label_source="npm-adjacent-to-compromised",
                    label_reference=f"adjacent_to:{rec.sample_id}",
                    family_group=family_group_for(npm_name),
                    available=True,
                    artifact_sha256=sha,
                    artifact_path=str(out),
                    artifact_path_external=str(out),
                    package_name_hash=hash_package_name(npm_name),
                    dataset_source="npm-registry",
                    hard_negative_category="compromised_version_control",
                    attack_category=None,
                    benchmark_tags=("compromised_version", "matched_clean"),
                    notes=(
                        f"EXPECTED_BENIGN adjacent control for {rec.sample_id}; "
                        "not independently labelled malicious in Datadog set"
                    ),
                )
                new_records.append(new_rec)
                existing_ids.add(clean_sid)
            else:
                # Already present — still form pair if available path known
                sha = next(
                    (
                        r.artifact_sha256
                        for r in [*records, *new_records]
                        if r.sample_id in {clean_sid, alt_sid}
                    ),
                    None,
                )
                clean_sid = clean_sid if clean_sid in existing_ids else alt_sid

            pairs.append(
                CompromisePair(
                    pair_id=f"{family_group_for(npm_name)}::{clean_ver}->{rec.version}",
                    family_group=family_group_for(npm_name),
                    clean_sample_id=clean_sid,
                    compromised_sample_id=rec.sample_id,
                    clean_version=clean_ver,
                    compromised_version=rec.version,
                    clean_artifact_sha256=sha,
                    compromised_artifact_sha256=rec.artifact_sha256,
                    notes="both artefacts required for pair training; family stays in one split",
                )
            )

    (scratch_root() / "compromise_pair_skipped.json").write_text(
        json.dumps(skipped, indent=2), encoding="utf-8"
    )
    return pairs, new_records
