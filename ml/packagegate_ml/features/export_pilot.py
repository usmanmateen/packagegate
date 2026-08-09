"""Export PackageGate ML records for Dataset V1 via static CLI scans only."""

from __future__ import annotations

import json
import subprocess
import hashlib
from pathlib import Path

from packagegate_ml.datasets.paths import exports_root
from packagegate_ml.datasets.splits import load_records
from packagegate_ml.features.structured import export_to_feature_row

REPO = Path(__file__).resolve().parents[3]
CLI = REPO / "packages" / "cli" / "dist" / "bin.js"
EXTERNAL_MANIFEST = Path("/tmp/packagegate-ml-data/manifests/dataset_v1_full.private.json")


def _run_scan_tarball(path: Path, out_json: Path) -> dict:
    proc = subprocess.run(
        ["node", str(CLI), "scan-tarball", str(path), "--json"],
        cwd=str(REPO),
        stdout=out_json.open("w", encoding="utf-8"),
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
        check=False,
    )
    if proc.returncode != 0:
        return {
            "status": "ERROR",
            "failure": (proc.stderr or "")[-500:],
        }
    try:
        return {
            "status": "SCAN_SUCCESS",
            "investigation": json.loads(out_json.read_text(encoding="utf-8")),
        }
    except json.JSONDecodeError as exc:
        return {"status": "OTHER", "failure": f"json:{exc}"}


def _run_fixture(name: str, out_json: Path) -> dict:
    proc = subprocess.run(
        ["node", str(CLI), "ml-export", name],
        cwd=str(REPO),
        stdout=out_json.open("w", encoding="utf-8"),
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        return {"status": "ERROR", "failure": (proc.stderr or "")[-500:]}
    try:
        return {
            "status": "SCAN_SUCCESS",
            "mlExport": json.loads(out_json.read_text(encoding="utf-8")),
        }
    except json.JSONDecodeError as exc:
        return {"status": "OTHER", "failure": f"json:{exc}"}


def investigation_to_mle_export(inv: dict) -> dict:
    """Build a PackageGateMlRecordV1-compatible object from investigation JSON."""
    findings = inv.get("findings") or []
    chains = inv.get("behaviourChains") or []
    lifecycle = inv.get("lifecycleScripts") or []
    completeness = inv.get("analysisCompleteness") or {}
    files = inv.get("files") or []

    by_cat: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    by_conf: dict[str, int] = {}
    for f in findings:
        by_cat[f.get("category", "?")] = by_cat.get(f.get("category", "?"), 0) + 1
        by_sev[f.get("severity", "?")] = by_sev.get(f.get("severity", "?"), 0) + 1
        by_conf[f.get("confidence", "?")] = by_conf.get(f.get("confidence", "?"), 0) + 1

    chains_by_type: dict[str, int] = {}
    for c in chains:
        meta = c.get("metadata") or {}
        key = meta.get("chainType") or f"{c.get('source')}->{c.get('sink')}"
        chains_by_type[str(key)] = chains_by_type.get(str(key), 0) + 1

    hooks = {s.get("name") for s in lifecycle}
    structured = {
        "schemaVersion": 1,
        "findingCount": len(findings),
        "findingsByCategory": by_cat,
        "findingsBySeverity": by_sev,
        "findingsByConfidence": by_conf,
        "chainCount": len(chains),
        "chainsByType": chains_by_type,
        "chainsByConfidence": {},
        "lifecycleHookCount": len(lifecycle),
        "hasPreinstall": 1 if "preinstall" in hooks else 0,
        "hasInstall": 1 if "install" in hooks else 0,
        "hasPostinstall": 1 if "postinstall" in hooks else 0,
        "networkDestinationCount": by_cat.get("NETWORK_DESTINATION", 0),
        "environmentAccessCount": by_cat.get("ENVIRONMENT_ACCESS", 0),
        "processExecutionCount": by_cat.get("PROCESS_EXECUTION", 0),
        "remoteDownloadCount": by_cat.get("REMOTE_CODE_FETCH", 0)
        + by_cat.get("DOWNLOAD_BEHAVIOUR", 0),
        "sensitiveFileCount": by_cat.get("SENSITIVE_FILE_ACCESS", 0),
        "shellCommandCount": by_cat.get("SHELL_COMMAND", 0),
        "opaqueSourceCount": by_cat.get("OBFUSCATION_SIGNAL", 0)
        + by_cat.get("HIGH_ENTROPY_PAYLOAD", 0),
        "largeSourceCount": 0,
        "completenessStatusComplete": 1
        if completeness.get("status") == "COMPLETE"
        else 0,
        "completenessStatusDegraded": 1
        if completeness.get("status") == "DEGRADED"
        else 0,
        "completenessStatusInsufficient": 1
        if completeness.get("status") == "INSUFFICIENT"
        else 0,
        "coverageRatio": float(completeness.get("coverageRatio") or 0),
        "fileCount": len(files),
        "analysedExecutableBytes": sum(
            int(f.get("sizeBytes") or 0)
            for f in files
            if f.get("analysed")
            and f.get("kind") in {"JAVASCRIPT", "TYPESCRIPT"}
        ),
        "familyBreadth": sum(1 for v in by_cat.values() if v > 0),
    }

    resolved = inv.get("resolved") or {}
    name = resolved.get("name") or "unknown"
    name_hash = hashlib.sha256(name.encode()).hexdigest()[:16]
    return {
        "schemaVersion": 1,
        "featureSchemaVersion": 1,
        "package": {"nameHash": name_hash, "version": resolved.get("version")},
        "artifact": {"sha256": (inv.get("artifact") or {}).get("sha256")},
        "lifecycle": [
            {"name": s.get("name"), "command": s.get("command")} for s in lifecycle
        ],
        "findings": findings,
        "chains": chains,
        "completeness": {
            "status": completeness.get("status"),
            "coverageRatio": completeness.get("coverageRatio"),
        },
        "structuredFeatures": structured,
        "slices": [],
        "mlInputCompleteness": {
            "slicesAvailable": 0,
            "slicesUsed": 0,
            "truncationOccurred": False,
        },
        "behaviouralRisk": {
            "score": (inv.get("risk") or {}).get("score"),
            "recommendation": (inv.get("risk") or {}).get("recommendation"),
        },
        "finalPolicy": (inv.get("policy") or {}).get("finalAction"),
    }


def main() -> None:
    if not EXTERNAL_MANIFEST.exists():
        raise SystemExit(f"Missing {EXTERNAL_MANIFEST}; run build_pilot_dataset first")
    if not CLI.exists():
        raise SystemExit("CLI not built; run pnpm --filter @packagegate/cli build")

    records = load_records(EXTERNAL_MANIFEST)
    out_dir = exports_root() / "v1"
    out_dir.mkdir(parents=True, exist_ok=True)
    feature_rows_path = out_dir / "features.jsonl"
    failures_path = out_dir / "export_failures.jsonl"

    n_ok = 0
    n_fail = 0
    with feature_rows_path.open("w", encoding="utf-8") as feats, failures_path.open(
        "w", encoding="utf-8"
    ) as fails:
        for record in records:
            if not record.available:
                continue
            sample_id = record.sample_id
            safe = sample_id.replace("/", "_").replace("@", "_").replace(":", "_")
            export_path = out_dir / f"{safe}.json"

            tmp_json = out_dir / f".tmp_{safe}.json"
            if sample_id.startswith("fixture:"):
                fixture_name = sample_id.split(":", 1)[1]
                result = _run_fixture(fixture_name, tmp_json)
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
                    tmp_json.unlink(missing_ok=True)
                    continue
                mle = result["mlExport"]
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
                    tmp_json.unlink(missing_ok=True)
                    continue
                mle = investigation_to_mle_export(result["investigation"])
            tmp_json.unlink(missing_ok=True)

            # Strip policy/threat intel from training export copy.
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
                        "features": features,
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
        "featuresPath": str(feature_rows_path),
        "failuresPath": str(failures_path),
    }
    (out_dir / "export_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
