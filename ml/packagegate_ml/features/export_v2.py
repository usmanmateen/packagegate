"""Export PackageGate features for Dataset V2 (static scans only)."""

from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data-v2")

from packagegate_ml.datasets.paths import exports_root
from packagegate_ml.datasets.splits import load_records
from packagegate_ml.features.export_pilot import (
    _run_fixture,
    _run_scan_tarball,
    investigation_to_mle_export,
)
from packagegate_ml.features.structured import export_to_feature_row

EXTERNAL_MANIFEST = Path(
    os.environ.get(
        "PACKAGEGATE_ML_V2_MANIFEST",
        "/tmp/packagegate-ml-data-v2/manifests/dataset_v2_full.private.json",
    )
)


def main() -> None:
    if not EXTERNAL_MANIFEST.exists():
        raise SystemExit(f"Missing manifest {EXTERNAL_MANIFEST}")
    records = load_records(EXTERNAL_MANIFEST)
    out_dir = exports_root() / "v2"
    out_dir.mkdir(parents=True, exist_ok=True)
    feature_rows_path = out_dir / "features.jsonl"
    failures_path = out_dir / "export_failures.jsonl"

    n_ok = 0
    n_fail = 0
    fail_by_label: dict[str, int] = {}

    with feature_rows_path.open("w", encoding="utf-8") as feats, failures_path.open(
        "w", encoding="utf-8"
    ) as fails:
        for record in records:
            if not record.available:
                continue
            sample_id = record.sample_id
            safe = (
                sample_id.replace("/", "_").replace("@", "_").replace(":", "_")
            )
            export_path = out_dir / f"{safe}.json"
            tmp_json = out_dir / f".tmp_{safe}.json"

            if sample_id.startswith("fixture:"):
                fixture_name = sample_id.split(":", 1)[1]
                result = _run_fixture(fixture_name, tmp_json)
            else:
                path = Path(record.artifact_path or "")
                if not path.exists():
                    fails.write(
                        json.dumps(
                            {
                                "sample_id": sample_id,
                                "label": record.label.value,
                                "status": "OTHER",
                                "failure": "missing_artifact",
                            }
                        )
                        + "\n"
                    )
                    n_fail += 1
                    fail_by_label[record.label.value] = (
                        fail_by_label.get(record.label.value, 0) + 1
                    )
                    continue
                result = _run_scan_tarball(path, tmp_json)

            if result["status"] != "SCAN_SUCCESS":
                fails.write(
                    json.dumps(
                        {
                            "sample_id": sample_id,
                            "label": record.label.value,
                            "status": result["status"],
                            "failure": result.get("failure"),
                        }
                    )
                    + "\n"
                )
                n_fail += 1
                fail_by_label[record.label.value] = (
                    fail_by_label.get(record.label.value, 0) + 1
                )
                tmp_json.unlink(missing_ok=True)
                continue

            if "mlExport" in result:
                mle = result["mlExport"]
            else:
                mle = investigation_to_mle_export(result["investigation"])
            tmp_json.unlink(missing_ok=True)
            mle.pop("finalPolicy", None)
            mle.pop("threatIntelligence", None)
            export_path.write_text(json.dumps(mle), encoding="utf-8")
            features = export_to_feature_row(mle, include_behavioural_score=False)
            feats.write(
                json.dumps(
                    {
                        "sample_id": sample_id,
                        "label": record.label.value,
                        "family_group": record.family_group,
                        "dataset_source": record.dataset_source,
                        "attack_category": record.attack_category,
                        "package_name": record.package_name,
                        "version": record.version,
                        "features": features,
                        "structured": mle.get("structuredFeatures") or features,
                        "deterministicRecommendation": (
                            (mle.get("behaviouralRisk") or {}).get("recommendation")
                        ),
                        "deterministicScore": (mle.get("behaviouralRisk") or {}).get(
                            "score"
                        ),
                    }
                )
                + "\n"
            )
            n_ok += 1
            if n_ok % 25 == 0:
                print(json.dumps({"exported": n_ok, "failed": n_fail}))

    summary = {
        "exported": n_ok,
        "failed": n_fail,
        "failuresByLabel": fail_by_label,
        "featuresPath": str(feature_rows_path),
        "failuresPath": str(failures_path),
    }
    (out_dir / "export_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
