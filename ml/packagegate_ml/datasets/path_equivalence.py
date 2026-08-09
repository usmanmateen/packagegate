"""Compare registry-path vs canonical-repack PackageGate exports for benign samples."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

os.environ.setdefault("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data-v3")

from packagegate_ml.datasets.canonical import behaviour_feature_delta, canonicalise_artifact
from packagegate_ml.datasets.paths import scratch_root
from packagegate_ml.features.export_pilot import _run_scan_tarball, investigation_to_mle_export
from packagegate_ml.features.structured import export_to_feature_row
from packagegate_ml.datasets.feature_families import behaviour_features

REPO = Path(__file__).resolve().parents[3]


def scan_features(tgz: Path, tmp: Path) -> dict[str, float]:
    out = tmp / f"{tgz.stem}.json"
    result = _run_scan_tarball(tgz, out)
    if result["status"] != "SCAN_SUCCESS":
        raise RuntimeError(result.get("failure"))
    mle = investigation_to_mle_export(result["investigation"])
    row = export_to_feature_row(mle, include_behavioural_score=False)
    structured = mle.get("structuredFeatures") or row
    return behaviour_features(structured)


def main() -> None:
    # Use a few already-downloaded benign npm tarballs from V2
    benign_dir = Path("/tmp/packagegate-ml-data-v2/benign/npm")
    samples = sorted(benign_dir.glob("*.tgz"))[:8]
    if not samples:
        raise SystemExit("No benign samples available for path equivalence")

    report = []
    work = scratch_root() / "path_equivalence"
    work.mkdir(parents=True, exist_ok=True)
    for src in samples:
        canon = work / f"canon_{src.name}"
        try:
            canonicalise_artifact(src, canon, work_dir=work / f"w_{src.stem}")
            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                a = scan_features(src, tmp)
                b = scan_features(canon, tmp)
            delta = behaviour_feature_delta(a, b)
            nonzero = {k: v for k, v in delta.items() if abs(v) > 1e-9}
            report.append(
                {
                    "sample": src.name,
                    "behaviourFeatureDeltaNonZero": len(nonzero),
                    "maxAbsDelta": max((abs(v) for v in delta.values()), default=0.0),
                    "changedKeys": sorted(nonzero)[:20],
                }
            )
            print(json.dumps(report[-1]))
        except Exception as exc:  # noqa: BLE001
            report.append({"sample": src.name, "error": str(exc)})
            print(json.dumps(report[-1]))

    out = scratch_root() / "path_equivalence_report.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # Soft assertion target for docs: most samples should have zero behaviour delta
    ok = sum(1 for r in report if r.get("behaviourFeatureDeltaNonZero") == 0)
    print(json.dumps({"n": len(report), "zeroBehaviourDelta": ok}))


if __name__ == "__main__":
    main()
