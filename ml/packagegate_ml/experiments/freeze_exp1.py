"""Freeze PackageGate Neural Experiment 1 metadata and V4 matched predictions."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
EXP = REPO / "ml" / "experiments" / "pg-neural-exp1"
PKG_RUN = REPO / "ml" / "runs" / "20260809T193015Z-pg-package-mil-v1" / "metadata.json"
SLICE_META = Path("/home/usman/packagegate-ml-models/20260809T191708Z-pg-slice-v1/metadata.json")
SLICE_CKPT = Path("/home/usman/packagegate-ml-models/20260809T191708Z-pg-slice-v1/best.pt")
FEATURES = Path("/tmp/packagegate-ml-data-v4/exports/v4-neural/strict_features.jsonl")
V4_HASHES = REPO / "ml" / "data-manifests" / "v4" / "hashes.json"
NEURAL_HASHES = REPO / "ml" / "data-manifests" / "v4" / "neural" / "hashes.json"
MATCHED = REPO / "ml" / "data-manifests" / "v4" / "structure_matches.json"
SPLIT = REPO / "ml" / "data-manifests" / "v4" / "neural" / "split.json"


def _git() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    EXP.mkdir(parents=True, exist_ok=True)
    pkg = json.loads(PKG_RUN.read_text(encoding="utf-8"))
    slice_meta = json.loads(SLICE_META.read_text(encoding="utf-8"))
    full = pkg["full"]
    structured = full["STRUCTURED_BEHAVIOUR_LOGISTIC"]
    embed = full["EMBED_MEAN_ONLY"]
    mil = full.get("MIL_CODE_ONLY") or {}

    ids = embed["testIds"]
    assert ids == structured["testIds"]
    features = {}
    for line in FEATURES.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            features[r["sample_id"]] = r

    rows = []
    for i, sid in enumerate(ids):
        lab = features[sid]["label"]
        y = 1 if lab in {"MALICIOUS", "COMPROMISED"} else 0
        rows.append(
            {
                "sample_id": sid,
                "label": lab,
                "y": y,
                "structured_proba": structured["proba"][i],
                "embed_mean_proba": embed["proba"][i],
                "mil_code_proba": (mil.get("proba") or [None] * len(ids))[i],
            }
        )

    pred_path = EXP / "v4_matched_test_predictions.jsonl"
    with pred_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    pred_hash = _sha(pred_path)

    # validation predictions: recompute not stored — record thresholds only
    freeze = {
        "experimentId": "pg-neural-exp1",
        "EXPERIMENT_STATUS": "FROZEN",
        "frozenAt": datetime.now(timezone.utc).isoformat(),
        "gitCommit": _git(),
        "datasetVersion": "v4",
        "datasetHashes": json.loads(V4_HASHES.read_text(encoding="utf-8")),
        "neuralManifestHashes": json.loads(NEURAL_HASHES.read_text(encoding="utf-8")),
        "split": json.loads(SPLIT.read_text(encoding="utf-8")),
        "matchedSampleIds": json.loads(MATCHED.read_text(encoding="utf-8")).get(
            "matchedSampleIds"
        ),
        "sliceSchemaVersion": 2,
        "featureSchemaVersion": 2,
        "baseModelId": "microsoft/graphcodebert-base",
        "baseModelRevision": "2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d",
        "tokenizerRevision": "2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d",
        "maxSeqLength": 512,
        "sliceCheckpoint": str(SLICE_CKPT),
        "sliceCheckpointSha256": _sha(SLICE_CKPT),
        "embeddingDir": pkg["embeddingDir"],
        "packageRunId": pkg["runId"],
        "sliceRunId": slice_meta.get("runId"),
        "trainingHyperparameters": {
            "batchSize": slice_meta.get("batchSize"),
            "gradAccum": slice_meta.get("gradAccum"),
            "epochs": slice_meta.get("epochs"),
            "lr": slice_meta.get("lr"),
            "bf16": slice_meta.get("bf16"),
            "seed": slice_meta.get("seed"),
            "selectedEpochMetric": "validation_micro_f1",
            "bestValMicroF1": slice_meta.get("bestValMicroF1"),
        },
        "selectedPackageModel": {
            "mode": "EMBED_MEAN_ONLY",
            "threshold": embed.get("threshold"),
            "pr_auc": embed.get("pr_auc"),
            "recallAt5pctFpr": embed.get("recallAt5pctFpr"),
            "selectionRationale": "Highest PR-AUC on frozen V4 matched test among Exp1 package ablations; MIL not selected.",
        },
        "structuredBaseline": {
            "mode": "STRUCTURED_BEHAVIOUR_LOGISTIC",
            "model": "logistic_regression",
            "threshold": structured.get("threshold"),
            "pr_auc": structured.get("pr_auc"),
            "recallAt5pctFpr": structured.get("recallAt5pctFpr"),
        },
        "testMetrics": {
            "n": embed.get("testN"),
            "positives": embed.get("positives"),
            "negatives": embed.get("negatives"),
            "prevalence": embed.get("prevalence"),
            "structuredPrAuc": structured.get("pr_auc"),
            "embedMeanPrAuc": embed.get("pr_auc"),
            "absoluteDeltaPrAuc": (
                None
                if structured.get("pr_auc") is None or embed.get("pr_auc") is None
                else embed["pr_auc"] - structured["pr_auc"]
            ),
            "milCodePrAuc": mil.get("pr_auc"),
            "milHybridPrAuc": (full.get("MIL_PLUS_STRUCTURED") or {}).get("pr_auc"),
        },
        "predictionsPath": str(pred_path.relative_to(REPO)),
        "predictionsSha256": pred_hash,
        "hardware": {
            "gpu": slice_meta.get("gpu"),
            "torch": slice_meta.get("torch"),
            "cuda": slice_meta.get("cuda"),
            "transformers": slice_meta.get("transformers"),
        },
        "trainingDataCutoff": "2026-06-10",
        "trainingDataCutoffNote": (
            "Latest Datadog observation date among V4-linked samples (zip_name date). "
            "V5 TEMPORAL_UNSEEN prefers samples with observation date > this cutoff."
        ),
        "policy": "EXPERIMENTAL_SHADOW",
        "weightsCommitted": False,
    }
    (EXP / "freeze.json").write_text(json.dumps(freeze, indent=2) + "\n", encoding="utf-8")
    (EXP / "README.md").write_text(
        "# pg-neural-exp1 (FROZEN)\n\n"
        "Metadata-only freeze of the first GraphCodeBERT + mean-pooling package experiment.\n"
        "Weights live under `/home/usman/packagegate-ml-models/` and are not committed.\n",
        encoding="utf-8",
    )
    print(json.dumps({"frozen": True, "experimentId": freeze["experimentId"], "predictionsSha256": pred_hash, "delta": freeze["testMetrics"]["absoluteDeltaPrAuc"]}, indent=2))


if __name__ == "__main__":
    main()
