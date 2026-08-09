"""Build STRICT_SECURITY_VIEW PackageGateMlRecordV2 rows from V3 exports (no re-scan)."""

from __future__ import annotations

import json
import os
import tarfile
from pathlib import Path

os.environ.setdefault("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data-v4")

from packagegate_ml.datasets.paths import exports_root
from packagegate_ml.datasets.splits import load_records
from packagegate_ml.features.record_v2 import (
    audit_strict_record_leakage,
    behaviour_only_from_structured,
    build_package_gate_ml_record_v2,
    strict_input_nuisance,
)

V3_PRIVATE = Path("/tmp/packagegate-ml-data-v3/manifests/dataset_v3_full.private.json")
V3_EXPORT_DIR = Path("/tmp/packagegate-ml-data-v3/exports/v3")


def _safe(sid: str) -> str:
    return sid.replace("/", "_").replace("@", "_").replace(":", "_")


def _read_package_json(tgz: Path) -> dict | None:
    try:
        with tarfile.open(tgz, "r:*") as tar:
            for name in ("package/package.json", "package.json"):
                try:
                    member = tar.getmember(name)
                except KeyError:
                    continue
                f = tar.extractfile(member)
                if f is None:
                    continue
                return json.loads(f.read().decode("utf-8", errors="ignore"))
    except (tarfile.TarError, OSError, json.JSONDecodeError):
        return None
    return None


def main() -> None:
    records = {r.sample_id: r for r in load_records(V3_PRIVATE)}
    out_dir = exports_root() / "v4"
    out_dir.mkdir(parents=True, exist_ok=True)
    feats_path = out_dir / "strict_features.jsonl"
    natural_path = out_dir / "natural_features.jsonl"
    audit_path = out_dir / "leakage_audit.jsonl"
    n_ok = 0
    n_fail = 0
    n_leak = 0

    with feats_path.open("w", encoding="utf-8") as feats, natural_path.open(
        "w", encoding="utf-8"
    ) as natural_feats, audit_path.open("w", encoding="utf-8") as audits:
        for sid, rec in records.items():
            if not rec.available:
                continue
            export_file = V3_EXPORT_DIR / f"{_safe(sid)}.json"
            if not export_file.exists():
                export_file = next(
                    (p for p in V3_EXPORT_DIR.iterdir() if p.is_file() and _safe(sid) == p.stem),
                    None,
                )
            if export_file is None or not Path(export_file).exists():
                n_fail += 1
                continue
            try:
                v1 = json.loads(Path(export_file).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                n_fail += 1
                continue

            pkg_json = None
            art = Path(rec.artifact_path or "")
            if art.exists():
                pkg_json = _read_package_json(art)

            v1 = dict(v1)
            v1.pop("package", None)

            strict = build_package_gate_ml_record_v2(
                v1_or_export=v1,
                package_name=rec.package_name,
                version=rec.version,
                package_json=pkg_json,
                view="STRICT_SECURITY_VIEW",
            )
            natural_rec = build_package_gate_ml_record_v2(
                v1_or_export=v1,
                package_name=rec.package_name,
                version=rec.version,
                package_json=pkg_json,
                view="NATURAL_CODE_VIEW",
            )
            issues = audit_strict_record_leakage(
                strict, package_name=rec.package_name, version=rec.version
            )
            if issues:
                n_leak += 1
                audits.write(
                    json.dumps({"sample_id": sid, "issues": issues}) + "\n"
                )

            structured = v1.get("structuredFeatures") or {}
            behaviour = behaviour_only_from_structured(structured)
            nuisance = strict_input_nuisance(structured)

            out_path = out_dir / f"{_safe(sid)}.strict.json"
            out_path.write_text(json.dumps(strict), encoding="utf-8")
            (out_dir / f"{_safe(sid)}.natural.json").write_text(
                json.dumps(natural_rec), encoding="utf-8"
            )

            row = {
                "sample_id": sid,
                "label": rec.label.value,
                "_meta": {
                    "package_name": rec.package_name,
                    "version": rec.version,
                    "dataset_source": rec.dataset_source,
                    "family_group": rec.family_group,
                    "attack_category": rec.attack_category,
                },
                "behaviour_features": behaviour,
                "strict_input_nuisance": nuisance,
                "structured_raw": structured,
                "leakage_issues": issues,
                "deterministicRecommendation": (
                    (v1.get("behaviouralRisk") or {}).get("recommendation")
                ),
                "deterministicScore": (v1.get("behaviouralRisk") or {}).get("score"),
            }
            feats.write(json.dumps(row) + "\n")
            natural_feats.write(
                json.dumps(
                    {
                        "sample_id": sid,
                        "label": rec.label.value,
                        "view": "NATURAL_CODE_VIEW",
                        "behaviour_features": behaviour,
                    }
                )
                + "\n"
            )
            n_ok += 1
            if n_ok % 50 == 0:
                print(json.dumps({"exported": n_ok, "leak_flags": n_leak, "failed": n_fail}))

    summary = {
        "exported": n_ok,
        "failed": n_fail,
        "leakFlags": n_leak,
        "strictFeaturesPath": str(feats_path),
        "auditPath": str(audit_path),
    }
    (out_dir / "export_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
