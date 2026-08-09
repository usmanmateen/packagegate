"""Datadog malicious-software-packages-dataset adapter (metadata + capped download)."""

from __future__ import annotations

import hashlib
import io
import json
import random
import re
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from zipfile import ZipFile

from packagegate_ml.datasets.paths import malware_root, scratch_root
from packagegate_ml.datasets.schema import (
    MALWARE_QUALITATIVE_HOLDOUT_IDS,
    DatasetRecord,
    SampleLabel,
    family_group_for,
    hash_package_name,
    sample_id_for,
)

REPO_API = "https://api.github.com/repos/DataDog/malicious-software-packages-dataset"
RAW_BASE = (
    "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main"
)
ZIP_PASSWORD = b"infected"
USER_AGENT = "PackageGate-ML-Pilot/1.0 (research; static-analysis-only)"


def _http_json(url: str) -> Any:
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=180) as resp:
        return resp.read()


def list_npm_zip_paths(*, cache: Path | None = None) -> list[dict[str, str]]:
    """
    One recursive git tree call → npm sample zip paths.
    Path shape: samples/npm/<category>/<package>/<version>/<date>-....zip
    For malicious_intent, category may nest differently; handle both.
    """
    cache_path = cache or (scratch_root() / "datadog_npm_zip_index.json")
    if cache_path.exists():
        return json.loads(cache_path.read_text(encoding="utf-8"))

    # Resolve main commit SHA then recursive tree.
    repo = _http_json(REPO_API)
    default_branch = repo.get("default_branch", "main")
    ref = _http_json(f"{REPO_API}/git/ref/heads/{default_branch}")
    commit_sha = ref["object"]["sha"]
    commit = _http_json(f"{REPO_API}/git/commits/{commit_sha}")
    tree_sha = commit["tree"]["sha"]
    tree = _http_json(f"{REPO_API}/git/trees/{tree_sha}?recursive=1")

    entries: list[dict[str, str]] = []
    for item in tree.get("tree", []):
        path = item.get("path", "")
        if item.get("type") != "blob":
            continue
        if not path.startswith("samples/npm/"):
            continue
        if not path.endswith(".zip"):
            continue
        parts = path.split("/")
        # samples/npm/<pkg>/<ver>/<zip> OR samples/npm/<cat>/<pkg>/<ver>/<zip>
        if len(parts) == 5:
            category = "uncategorised"
            package_name = parts[2]
            version = parts[3]
            zip_name = parts[4]
        elif len(parts) == 6:
            category = parts[2]
            package_name = parts[3]
            version = parts[4]
            zip_name = parts[5]
        else:
            continue
        entries.append(
            {
                "path": path,
                "category": category,
                "package_name": package_name,
                "version": version,
                "zip_name": zip_name,
                "download_url": f"{RAW_BASE}/{path}",
            }
        )

    cache_path.write_text(json.dumps(entries), encoding="utf-8")
    return entries


def zip_to_npm_tgz(zip_bytes: bytes, out_tgz: Path) -> str:
    """Extract Datadog password-protected zip and rebuild npm-style .tgz (data only)."""
    out_tgz.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch_root()) as tmp:
        tmp_path = Path(tmp)
        with ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(tmp_path, pwd=ZIP_PASSWORD)

        candidates = list(tmp_path.rglob("package.json"))
        if not candidates:
            raise FileNotFoundError("No package.json in Datadog sample zip")
        candidates.sort(
            key=lambda p: (0 if p.parent.name == "package" else 1, -len(p.parts))
        )
        pkg_root = candidates[0].parent

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for path in sorted(pkg_root.rglob("*")):
                if not path.is_file() or path.is_symlink():
                    continue
                rel = path.relative_to(pkg_root).as_posix()
                info = tarfile.TarInfo(name=f"package/{rel}")
                data = path.read_bytes()
                info.size = len(data)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(data))
        out_tgz.write_bytes(buf.getvalue())
    return hashlib.sha256(out_tgz.read_bytes()).hexdigest()


def acquire_datadog_pilot(
    *,
    max_samples: int = 150,
    max_per_family: int = 1,
    seed: int = 42,
    prefer_categories: tuple[str, ...] = ("compromised_lib", "malicious_intent"),
) -> list[DatasetRecord]:
    rng = random.Random(seed)
    records: list[DatasetRecord] = []
    seen_families: dict[str, int] = {}

    records.append(
        DatasetRecord(
            sample_id="02-echo@0.0.7",
            package_name="02-echo",
            version="0.0.7",
            label=SampleLabel.MALICIOUS,
            label_source="datadog-malicious-software-packages-dataset",
            label_reference="samples/npm/compromised_lib/02-echo/0.0.7",
            family_group=family_group_for("02-echo"),
            available=False,
            package_name_hash=hash_package_name("02-echo"),
            dataset_source="datadog",
            notes="Qualitative malware holdout — excluded from train/validation",
        )
    )

    try:
        entries = list_npm_zip_paths()
    except (urllib.error.URLError, KeyError, TimeoutError) as exc:
        (scratch_root() / "datadog_index_error.json").write_text(
            json.dumps({"error": str(exc)}), encoding="utf-8"
        )
        return records

    # Prefer one zip per package@version; prefer preferred categories.
    by_sample: dict[str, dict[str, str]] = {}
    for entry in entries:
        sid = sample_id_for(entry["package_name"], entry["version"])
        prev = by_sample.get(sid)
        if prev is None:
            by_sample[sid] = entry
            continue
        # Prefer preferred categories
        if entry["category"] in prefer_categories and prev["category"] not in prefer_categories:
            by_sample[sid] = entry

    candidates = list(by_sample.values())
    rng.shuffle(candidates)

    # Stable priority: preferred categories first
    candidates.sort(
        key=lambda e: (0 if e["category"] in prefer_categories else 1, e["package_name"])
    )

    acquired = 0
    skipped: list[dict[str, str]] = []
    for entry in candidates:
        if acquired >= max_samples:
            break
        package_name = entry["package_name"]
        version = entry["version"]
        sid = sample_id_for(package_name, version)
        if sid in MALWARE_QUALITATIVE_HOLDOUT_IDS:
            continue
        family = family_group_for(package_name)
        if seen_families.get(family, 0) >= max_per_family:
            continue

        out_tgz = malware_root() / "datadog" / f"{_safe_id(sid)}.tgz"
        try:
            if not out_tgz.exists():
                zip_bytes = _http_bytes(entry["download_url"])
                sha = zip_to_npm_tgz(zip_bytes, out_tgz)
            else:
                sha = hashlib.sha256(out_tgz.read_bytes()).hexdigest()
        except Exception as exc:  # noqa: BLE001
            skipped.append({"sample": sid, "reason": f"acquire:{exc}"})
            if out_tgz.exists():
                out_tgz.unlink(missing_ok=True)
            continue

        observed = None
        m = re.match(r"(\d{4}-\d{2}-\d{2})", entry["zip_name"])
        if m:
            observed = m.group(1)

        records.append(
            DatasetRecord(
                sample_id=sid,
                package_name=package_name,
                version=version,
                label=SampleLabel.MALICIOUS,
                label_source="datadog-malicious-software-packages-dataset",
                label_reference=entry["path"],
                family_group=family,
                available=True,
                artifact_sha256=sha,
                artifact_path=str(out_tgz),
                artifact_path_external=str(out_tgz),
                package_name_hash=hash_package_name(package_name),
                dataset_source="datadog",
                observed_date=observed,
                notes=f"category={entry['category']}; static tgz rebuilt from Datadog zip",
            )
        )
        seen_families[family] = seen_families.get(family, 0) + 1
        acquired += 1
        if acquired % 10 == 0:
            print(json.dumps({"datadog_progress": acquired, "latest": sid}))

    (scratch_root() / "datadog_skipped.json").write_text(
        json.dumps(skipped, indent=2), encoding="utf-8"
    )
    return records


def _safe_id(sample_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9@._+-]+", "_", sample_id)
