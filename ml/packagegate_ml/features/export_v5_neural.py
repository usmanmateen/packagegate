"""Export Dataset V5 with frozen V4 STRICT_SECURITY_VIEW + SliceSchemaV2.

Inference-only artefacts — never used for training/threshold selection.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

os.environ.setdefault("PACKAGEGATE_ML_DATA_ROOT", "/tmp/packagegate-ml-data-v5")

from packagegate_ml.datasets.paths import exports_root
from packagegate_ml.datasets.splits import load_records
from packagegate_ml.features.export_pilot import CLI, _run_scan_tarball, investigation_to_mle_export
from packagegate_ml.features.record_v2 import (
    audit_strict_record_leakage,
    behaviour_only_from_structured,
    build_package_gate_ml_record_v2,
    strict_input_nuisance,
)
from packagegate_ml.features.slice_schema_v2 import (
    SLICE_SCHEMA_VERSION,
    SliceGenConfig,
    generate_slices_for_package,
    load_tarball_sources,
)

REPO = Path(__file__).resolve().parents[3]
MANIFEST = Path("/tmp/packagegate-ml-data-v5/manifests/dataset_v5_full.private.json")
FROZEN = REPO / "ml" / "data-manifests" / "v5"


def _safe(sid: str) -> str:
    return sid.replace("/", "_").replace("@", "_").replace(":", "_")


def main() -> None:
    if not MANIFEST.exists():
        raise SystemExit(f"Missing {MANIFEST}; run build_dataset_v5 first")
    if not CLI.exists():
        raise SystemExit("CLI not built; run pnpm --filter @packagegate/cli build")

    records = [r for r in load_records(MANIFEST) if r.available]
    out_dir = exports_root() / "v5-neural"
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = SliceGenConfig(max_slices=32, context_lines=12, max_per_category=6)

    index_path = out_dir / "index.jsonl"
    feats_path = out_dir / "strict_features.jsonl"
    audit_path = out_dir / "leakage_audit.jsonl"
    fails_path = out_dir / "export_failures.jsonl"

    n_ok = 0
    n_fail = 0
    n_leak = 0
    slice_counts: list[int] = []
    zero_reasons: Counter[str] = Counter()

    with index_path.open("w", encoding="utf-8") as index_f, feats_path.open(
        "w", encoding="utf-8"
    ) as feats_f, audit_path.open("w", encoding="utf-8") as audit_f, fails_path.open(
        "w", encoding="utf-8"
    ) as fails_f:
        for rec in records:
            sid = rec.sample_id
            art = Path(rec.artifact_path or "")
            tmp = out_dir / f".tmp_{_safe(sid)}.json"
            if not art.exists():
                fails_f.write(
                    json.dumps(
                        {
                            "sample_id": sid,
                            "status": "OTHER",
                            "failure": "missing_artifact",
                        }
                    )
                    + "\n"
                )
                n_fail += 1
                continue
            result = _run_scan_tarball(art, tmp)
            if result["status"] != "SCAN_SUCCESS":
                fails_f.write(
                    json.dumps(
                        {
                            "sample_id": sid,
                            "label": rec.label.value,
                            "status": result["status"],
                            "failure": result.get("failure"),
                        }
                    )
                    + "\n"
                )
                n_fail += 1
                tmp.unlink(missing_ok=True)
                continue
            v1 = result.get("mlExport") or investigation_to_mle_export(
                result["investigation"]
            )
            tmp.unlink(missing_ok=True)
            v1 = dict(v1)
            v1.pop("finalPolicy", None)
            v1.pop("threatIntelligence", None)
            v1.pop("package", None)

            sources = load_tarball_sources(art)
            gen = generate_slices_for_package(
                findings=list(v1.get("findings") or []),
                chains=list(v1.get("chains") or []),
                lifecycle=list(v1.get("lifecycle") or []),
                sources=sources,
                package_name=rec.package_name,
                version=rec.version,
                config=cfg,
            )
            if gen.zero_slice_reason:
                zero_reasons[gen.zero_slice_reason] += 1

            v1["slices"] = [
                {
                    "sliceId": s.slice_id,
                    "filePath": s.file_path,
                    "startLine": s.start_line,
                    "endLine": s.end_line,
                    "sourceText": s.source_text,
                    "lifecycleReachable": s.lifecycle_reachable,
                    **({"lifecycleHook": s.lifecycle_hook} if s.lifecycle_hook else {}),
                    "deterministicFindings": s.deterministic_findings,
                    "behaviourLabels": s.behaviour_labels,
                    "behaviourChainMembership": s.behaviour_chain_membership,
                    "priority": s.priority,
                }
                for s in gen.slices
            ]
            v1["mlInputCompleteness"] = {
                **gen.summary(),
                "slicesAvailable": gen.candidate_slices,
                "slicesUsed": gen.selected_slices,
                "sliceSchemaVersion": SLICE_SCHEMA_VERSION,
            }

            strict = build_package_gate_ml_record_v2(
                v1_or_export=v1,
                package_name=None,
                version=None,
                package_json=None,
                view="STRICT_SECURITY_VIEW",
            )
            if "package.json" in sources:
                try:
                    from packagegate_ml.features.identity_mask import security_manifest_view

                    pkg = json.loads(sources["package.json"])
                    strict["securityManifest"] = security_manifest_view(pkg)
                except (json.JSONDecodeError, TypeError):
                    pass
            strict["slices"] = [s.to_model_dict() for s in gen.slices]
            strict["mlInputCompleteness"] = v1["mlInputCompleteness"]
            strict["codeViewAvailable"] = gen.code_view_available

            issues = audit_strict_record_leakage(
                strict, package_name=rec.package_name, version=rec.version
            )
            if issues:
                n_leak += 1
                audit_f.write(json.dumps({"sample_id": sid, "issues": issues}) + "\n")

            out_path = out_dir / f"{_safe(sid)}.strict.json"
            out_path.write_text(json.dumps(strict), encoding="utf-8")
            (out_dir / f"{_safe(sid)}.json").write_text(json.dumps(v1), encoding="utf-8")

            structured = v1.get("structuredFeatures") or {}
            row = {
                "sample_id": sid,
                "label": rec.label.value,
                "family_group": rec.family_group,
                "code_view_available": gen.code_view_available,
                "n_slices": gen.selected_slices,
                "slice_meta": gen.summary(),
                "behaviour_features": behaviour_only_from_structured(structured),
                "strict_input_nuisance": strict_input_nuisance(structured),
                "structured_raw": structured,
                "deterministicScore": (v1.get("behaviouralRisk") or {}).get("score"),
                "deterministicRecommendation": (v1.get("behaviouralRisk") or {}).get(
                    "recommendation"
                ),
                "leakage_issues": issues,
                "benchmark_tags": list(rec.benchmark_tags or []),
                "notes": rec.notes,
                "attack_category": rec.attack_category,
                "_meta": {
                    "package_name": rec.package_name,
                    "version": rec.version,
                    "dataset_source": rec.dataset_source,
                    "slice_schema_version": SLICE_SCHEMA_VERSION,
                },
            }
            feats_f.write(json.dumps(row) + "\n")
            index_f.write(
                json.dumps(
                    {
                        "sample_id": sid,
                        "label": rec.label.value,
                        "n_slices": gen.selected_slices,
                        "code_view_available": gen.code_view_available,
                        "zero_slice_reason": gen.zero_slice_reason,
                        "path": str(out_path),
                    }
                )
                + "\n"
            )
            n_ok += 1
            slice_counts.append(gen.selected_slices)
            if n_ok % 20 == 0:
                print(json.dumps({"exported": n_ok, "failed": n_fail, "leak": n_leak}))

    summary = {
        "datasetVersion": "v5",
        "exported": n_ok,
        "failed": n_fail,
        "leakageFailures": n_leak,
        "leakagePass": n_leak == 0,
        "sliceSchemaVersion": SLICE_SCHEMA_VERSION,
        "meanSlices": float(sum(slice_counts) / len(slice_counts)) if slice_counts else 0.0,
        "ge1": float(sum(1 for c in slice_counts if c >= 1) / len(slice_counts))
        if slice_counts
        else 0.0,
        "ge2": float(sum(1 for c in slice_counts if c >= 2) / len(slice_counts))
        if slice_counts
        else 0.0,
        "zeroReasons": dict(zero_reasons),
    }
    (out_dir / "export_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    FROZEN.mkdir(parents=True, exist_ok=True)
    (FROZEN / "neural_export_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
