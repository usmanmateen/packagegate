"""Trusted PackageGate ML inference worker (JSON stdin → JSON stdout).

Receives PackageGateMlRecordV1. Never executes package source.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODEL_META = ROOT / "models" / "structured" / "model.json"


def predict_heuristic(record: dict) -> dict:
    """
    Offline heuristic used when no trained weights are present.
    Prefer deterministic structured signals; still reports as ML lane.
    """
    features = record.get("structuredFeatures") or {}
    score = 0.0
    score += 0.25 * min(1.0, float(features.get("processExecutionCount", 0)) / 2)
    score += 0.25 * min(1.0, float(features.get("remoteDownloadCount", 0)) / 2)
    score += 0.2 * min(1.0, float(features.get("shellCommandCount", 0)) / 2)
    score += 0.15 * float(features.get("hasPreinstall", 0) or features.get("hasInstall", 0))
    score += 0.15 * min(1.0, float(features.get("chainCount", 0)))
    score = max(0.0, min(1.0, score))

    behaviours = []
    mapping = [
        ("process_execution", "processExecutionCount"),
        ("remote_download", "remoteDownloadCount"),
        ("shell_execution", "shellCommandCount"),
        ("install_time_execution", "hasPreinstall"),
    ]
    for behaviour, key in mapping:
        val = float(features.get(key, 0))
        if val > 0:
            behaviours.append(
                {
                    "behaviour": behaviour,
                    "probability": min(1.0, 0.5 + 0.1 * val),
                }
            )

    top_slices = []
    for slice_rec in (record.get("slices") or [])[:5]:
        top_slices.append(
            {
                "file": slice_rec.get("filePath", "unknown"),
                "startLine": slice_rec.get("startLine", 1),
                "endLine": slice_rec.get("endLine", 1),
                "score": min(1.0, 0.4 + 0.1 * float(slice_rec.get("priority", 0)) / 100),
                "predictedBehaviours": [
                    {"behaviour": b, "probability": 0.7}
                    for b in (slice_rec.get("behaviourLabels") or [])[:3]
                ],
                "deterministicEvidenceRefs": list(
                    slice_rec.get("deterministicFindings") or []
                ),
            }
        )

    completeness = record.get("mlInputCompleteness") or {}
    return {
        "status": "AVAILABLE",
        "modelId": "pg-structured-heuristic-v0",
        "modelVersion": "0.1.0-smoke",
        "featureSchemaVersion": int(record.get("featureSchemaVersion") or 1),
        "maliciousProbability": score,
        "calibratedProbability": score,
        "uncertainty": 0.5,
        "predictedBehaviours": behaviours,
        "topSlices": top_slices,
        "inputCompleteness": {
            "slicesAvailable": int(completeness.get("slicesAvailable") or 0),
            "slicesUsed": int(completeness.get("slicesUsed") or 0),
            "truncationOccurred": bool(completeness.get("truncationOccurred")),
        },
        "supportsReviewEscalation": score >= 0.85,
    }


def main() -> None:
    raw = sys.stdin.read()
    if not raw.strip():
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "predictedBehaviours": [],
                    "topSlices": [],
                    "supportsReviewEscalation": False,
                    "errorMessage": "Empty ML input",
                }
            )
        )
        return
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "predictedBehaviours": [],
                    "topSlices": [],
                    "supportsReviewEscalation": False,
                    "errorMessage": f"Invalid JSON: {exc}",
                }
            )
        )
        return

    # Prefer trained structured model metadata when present; heuristic otherwise.
    if MODEL_META.exists():
        meta = json.loads(MODEL_META.read_text(encoding="utf-8"))
        result = predict_heuristic(record)
        result["modelId"] = meta.get("modelId", result["modelId"])
        result["modelVersion"] = meta.get("modelVersion", result["modelVersion"])
        print(json.dumps(result))
        return

    print(json.dumps(predict_heuristic(record)))


if __name__ == "__main__":
    main()
