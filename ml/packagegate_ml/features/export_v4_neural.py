"""Re-export frozen V4 packages with SliceSchemaV2 STRICT neural records.

Does NOT change train/validation/test/holdout membership.
"""

from __future__ import annotations

import json
import os
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
from packagegate_ml.features.slice_schema_v2 import (
    SLICE_SCHEMA_VERSION,
    SliceGenConfig,
    generate_slices_for_package,
    load_tarball_sources,
)

V4_PRIVATE = Path("/tmp/packagegate-ml-data-v4/manifests/dataset_v4_full.private.json")
V3_EXPORT_DIR = Path("/tmp/packagegate-ml-data-v3/exports/v3")
MATCHED = Path(
    Path(__file__).resolve().parents[3]
    / "ml"
    / "data-manifests"
    / "v4"
    / "structure_matches.json"
)

# Pre-registered neural coverage gate (before export finalisation).
NEURAL_COVERAGE_GATE = {
    "min_matched_ge1": 0.95,
    "min_matched_ge2": 0.80,
    "note": (
        "Zero-slice packages remain in evaluation with codeViewAvailable=false; "
        "they are not excluded."
    ),
}


def _safe(sid: str) -> str:
    return sid.replace("/", "_").replace("@", "_").replace(":", "_")


def main() -> None:
    records = {r.sample_id: r for r in load_records(V4_PRIVATE)}
    matched_ids = set(
        json.loads(MATCHED.read_text(encoding="utf-8")).get("matchedSampleIds") or []
    )
    out_dir = exports_root() / "v4-neural"
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = SliceGenConfig(max_slices=32, context_lines=12, max_per_category=6)

    index_path = out_dir / "index.jsonl"
    feats_path = out_dir / "strict_features.jsonl"
    audit_path = out_dir / "leakage_audit.jsonl"
    coverage_path = out_dir / "coverage_report.json"
    gate_path = out_dir / "coverage_gate_definition.json"
    gate_path.write_text(json.dumps(NEURAL_COVERAGE_GATE, indent=2) + "\n", encoding="utf-8")

    n_ok = 0
    n_fail = 0
    n_leak = 0
    slice_counts: list[int] = []
    matched_counts: list[int] = []
    zero_reasons: dict[str, int] = {}

    with index_path.open("w", encoding="utf-8") as index_f, feats_path.open(
        "w", encoding="utf-8"
    ) as feats_f, audit_path.open("w", encoding="utf-8") as audit_f:
        for sid, rec in records.items():
            if not rec.available:
                continue
            export_file = V3_EXPORT_DIR / f"{_safe(sid)}.json"
            if not export_file.exists():
                n_fail += 1
                continue
            try:
                v1 = json.loads(export_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                n_fail += 1
                continue

            art = Path(rec.artifact_path or "")
            sources = load_tarball_sources(art) if art.exists() else {}
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
                zero_reasons[gen.zero_slice_reason] = (
                    zero_reasons.get(gen.zero_slice_reason, 0) + 1
                )

            # Inject generated slices into V1-shaped export for record_v2 builder
            v1 = dict(v1)
            v1.pop("package", None)
            v1["slices"] = [
                {
                    "sliceId": s.slice_id,
                    "filePath": s.file_path,
                    "startLine": s.start_line,
                    "endLine": s.end_line,
                    "sourceText": s.source_text,  # already masked
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

            # Avoid double-masking: prepare_strict_source already applied.
            # build_package_gate_ml_record_v2 will mask again — idempotent for imports/
            # comments mostly; pass empty package_name for second pass on slices? Better:
            # build record manually for slices already strict.
            strict = build_package_gate_ml_record_v2(
                v1_or_export=v1,
                package_name=None,  # slices already masked; avoid over-masking builtins
                version=None,
                package_json=None,
                view="STRICT_SECURITY_VIEW",
            )
            # Re-attach security manifest from sources if available
            if "package.json" in sources:
                try:
                    from packagegate_ml.features.identity_mask import security_manifest_view

                    pkg = json.loads(sources["package.json"])
                    strict["securityManifest"] = security_manifest_view(pkg)
                except (json.JSONDecodeError, TypeError):
                    pass

            # Prefer already-masked slice dicts with full SliceSchemaV2 fields
            strict["slices"] = [s.to_model_dict() for s in gen.slices]
            strict["mlInputCompleteness"] = v1["mlInputCompleteness"]
            strict["codeViewAvailable"] = gen.code_view_available

            issues = audit_strict_record_leakage(
                strict, package_name=rec.package_name, version=rec.version
            )
            if issues:
                n_leak += 1
                audit_f.write(
                    json.dumps({"sample_id": sid, "issues": issues}) + "\n"
                )

            out_path = out_dir / f"{_safe(sid)}.strict.json"
            out_path.write_text(json.dumps(strict), encoding="utf-8")

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
            if sid in matched_ids:
                matched_counts.append(gen.selected_slices)
            if n_ok % 50 == 0:
                print(
                    json.dumps(
                        {
                            "exported": n_ok,
                            "leak_flags": n_leak,
                            "failed": n_fail,
                            "mean_slices": (
                                sum(slice_counts) / len(slice_counts) if slice_counts else 0
                            ),
                        }
                    ),
                    flush=True,
                )

    def dist(counts: list[int]) -> dict:
        if not counts:
            return {}
        s = sorted(counts)

        def pct(p: float) -> int:
            i = min(len(s) - 1, int(round((p / 100) * (len(s) - 1))))
            return s[i]

        def bucket(n: int) -> str:
            if n == 0:
                return "0"
            if n == 1:
                return "1"
            if n <= 4:
                return "2-4"
            if n <= 8:
                return "5-8"
            if n <= 16:
                return "9-16"
            if n <= 32:
                return "17-32"
            return ">32"

        from collections import Counter

        return {
            "n": len(counts),
            "total_slices": sum(counts),
            "mean": sum(counts) / len(counts),
            "median": sorted(counts)[len(counts) // 2],
            "p90": pct(90),
            "p95": pct(95),
            "max": max(counts),
            "ge1": sum(1 for c in counts if c >= 1) / len(counts),
            "ge2": sum(1 for c in counts if c >= 2) / len(counts),
            "buckets": dict(Counter(bucket(c) for c in counts)),
        }

    matched_ge1 = (
        sum(1 for c in matched_counts if c >= 1) / len(matched_counts)
        if matched_counts
        else 0.0
    )
    matched_ge2 = (
        sum(1 for c in matched_counts if c >= 2) / len(matched_counts)
        if matched_counts
        else 0.0
    )
    coverage_pass = matched_ge1 >= NEURAL_COVERAGE_GATE[
        "min_matched_ge1"
    ] and matched_ge2 >= NEURAL_COVERAGE_GATE["min_matched_ge2"]
    # Allow documented justification path if behavioural-free packages dominate zeros —
    # still fail hard if ge1 < 0.95 unless explicitly reviewed.
    report = {
        "exported": n_ok,
        "failed": n_fail,
        "leakFlags": n_leak,
        "sliceSchemaVersion": SLICE_SCHEMA_VERSION,
        "config": {
            "max_slices": cfg.max_slices,
            "context_lines": cfg.context_lines,
            "max_per_category": cfg.max_per_category,
        },
        "all": dist(slice_counts),
        "matched": dist(matched_counts),
        "zeroReasons": zero_reasons,
        "coverageGate": {
            **NEURAL_COVERAGE_GATE,
            "observed_matched_ge1": matched_ge1,
            "observed_matched_ge2": matched_ge2,
            "passed": coverage_pass and n_leak == 0,
            "leakPass": n_leak == 0,
        },
    }
    coverage_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not report["coverageGate"]["passed"]:
        raise SystemExit("NEURAL COVERAGE/LEAKAGE GATE FAILED — do not install PyTorch")


if __name__ == "__main__":
    main()
