"""OpenSSF malicious-packages metadata adapter (labels only; no auto malware fetch)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from packagegate_ml.datasets.paths import scratch_root
from packagegate_ml.datasets.schema import (
    DatasetRecord,
    SampleLabel,
    family_group_for,
    hash_package_name,
    sample_id_for,
)

# OSMF advisory index (metadata). Artifacts are NOT downloaded by this adapter.
OSV_MALICIOUS_QUERY = (
    "https://api.osv.dev/v1/query"
)
USER_AGENT = "PackageGate-ML-Pilot/1.0 (research; metadata-only)"


def fetch_openssf_npm_metadata_sample(limit: int = 50) -> list[DatasetRecord]:
    """
    Record OpenSSF/OSV malicious npm advisories as unavailable metadata samples.

    This diversifies label provenance without downloading malware. Physical
    artifacts remain Datadog-quarantined or caller-provided.
    """
    # Use a small fixed set of known OSV malicious package IDs via query by ecosystem
    # is awkward; instead cache a lightweight GH raw index if available.
    records: list[DatasetRecord] = []
    cache = scratch_root() / "openssf_npm_metadata.json"
    url = (
        "https://raw.githubusercontent.com/ossf/malicious-packages/main/"
        "osv/malicious/npm/MAL-2024-0001.json"
    )
    # Prefer listing via GitHub API directory (capped).
    api = (
        "https://api.github.com/repos/ossf/malicious-packages/contents/"
        "osv/malicious/npm?per_page=100"
    )
    try:
        req = urllib.request.Request(api, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=60) as resp:
            listing = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        cache.write_text(json.dumps({"error": str(exc), "url": url}), encoding="utf-8")
        return records

    if not isinstance(listing, list):
        return records

    count = 0
    for item in listing:
        if count >= limit:
            break
        if item.get("type") != "dir":
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            continue
        # Directory is package name; versions require another lookup — keep metadata-only.
        sid = sample_id_for(name, "osv-meta")
        records.append(
            DatasetRecord(
                sample_id=sid,
                package_name=name,
                version=None,
                label=SampleLabel.MALICIOUS,
                label_source="openssf-malicious-packages",
                label_reference=item.get("html_url"),
                family_group=family_group_for(name),
                available=False,
                package_name_hash=hash_package_name(name),
                dataset_source="openssf",
                notes="Metadata-only OpenSSF/OSV label; artifact not auto-downloaded",
            )
        )
        count += 1

    cache.write_text(
        json.dumps([r.to_public_dict(include_package_name=True) for r in records], indent=2),
        encoding="utf-8",
    )
    return records
