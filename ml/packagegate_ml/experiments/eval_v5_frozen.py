"""Evaluate frozen Exp1 models once on Dataset V5 (inference only).

Refits V4 train logistics with frozen Exp1 embeddings (reproducible), then
scores V5 using V4 validation-selected operating thresholds from freeze.json.
Never uses V5 for threshold selection, calibration, or model selection.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    roc_auc_score,
)
from transformers import AutoTokenizer

from packagegate_ml.evaluation.paired_bootstrap import paired_bootstrap_pr_auc
from packagegate_ml.neural import (
    BASE_MODEL_ID,
    BASE_MODEL_REVISION,
    BEHAVIOUR_LABELS_V1,
    MAX_SEQ_LENGTH,
)
from packagegate_ml.neural.datasets import SliceDataset, load_index, load_strict_features
from packagegate_ml.neural.train_package import (
    binlab,
    mean_emb,
    package_matrix,
    set_seed,
)
from packagegate_ml.neural.train_slice_encoder import SliceEncoder
from packagegate_ml.training.train_pilot_structured import (
    fit_predict,
    metrics_at_threshold,
)

REPO = Path(__file__).resolve().parents[3]
EXP = REPO / "ml" / "experiments" / "pg-neural-exp1"
FREEZE = EXP / "freeze.json"
V4_SPLIT = REPO / "ml" / "data-manifests" / "v4" / "neural" / "split.json"
V4_MATCHED = REPO / "ml" / "data-manifests" / "v4" / "structure_matches.json"
V4_FEATURES = Path("/tmp/packagegate-ml-data-v4/exports/v4-neural/strict_features.jsonl")
V4_INDEX = Path("/tmp/packagegate-ml-data-v4/exports/v4-neural/index.jsonl")
V5_FEATURES = Path("/tmp/packagegate-ml-data-v5/exports/v5-neural/strict_features.jsonl")
V5_INDEX = Path("/tmp/packagegate-ml-data-v5/exports/v5-neural/index.jsonl")
MODELS = Path(os.environ.get("PACKAGEGATE_ML_MODELS", "${PACKAGEGATE_ML_MODELS}"))
OUT = EXP / "v5_eval"


def _safe(sid: str) -> str:
    return sid.replace("/", "_").replace("@", "_").replace(":", "_")


@torch.no_grad()
def export_v5_embeddings(ckpt_path: Path, emb_dir: Path) -> None:
    """Encode V5 packages with frozen slice encoder into emb_dir."""
    emb_dir.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    model = SliceEncoder(BASE_MODEL_ID, BASE_MODEL_REVISION, len(BEHAVIOUR_LABELS_V1))
    model.load_state_dict(ckpt["model_state"], strict=False)
    model.to(device)
    model.eval()
    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL_ID, revision=BASE_MODEL_REVISION, trust_remote_code=False
    )
    index = load_index(V5_INDEX)
    ids = sorted(index.keys())
    ds = SliceDataset(ids, index, tokenizer=tokenizer, max_length=MAX_SEQ_LENGTH)
    from torch.utils.data import DataLoader

    loader = DataLoader(ds, batch_size=16, shuffle=False)
    ranks: dict[str, list[tuple[float, str, torch.Tensor]]] = {}
    for batch in loader:
        out = model(batch["input_ids"].to(device), batch["attention_mask"].to(device))
        cls = out["cls"].cpu()
        logits = out["logits"].cpu()
        for i in range(cls.size(0)):
            sid = batch["sample_id"][i]
            slice_id = batch["slice_id"][i]
            score = float(torch.sigmoid(logits[i]).max())
            ranks.setdefault(sid, []).append((score, slice_id, cls[i]))
    for sid, items in ranks.items():
        items.sort(key=lambda x: -x[0])
        embeddings = torch.stack([t[2] for t in items]) if items else torch.zeros(0, 768)
        torch.save(
            {
                "sample_id": sid,
                "embeddings": embeddings,
                "slice_ids": [t[1] for t in items],
                "scores": [t[0] for t in items],
                "code_view_available": True,
            },
            emb_dir / f"{_safe(sid)}.pt",
        )
    # also write empty tensors for zero-slice packages present in features
    feats = load_strict_features(V5_FEATURES)
    for sid, row in feats.items():
        path = emb_dir / f"{_safe(sid)}.pt"
        if path.exists():
            continue
        torch.save(
            {
                "sample_id": sid,
                "embeddings": torch.zeros(0, 768),
                "slice_ids": [],
                "scores": [],
            },
            path,
        )


def score_mode(mode: str, tr, features_v4, features_v5, emb_v4, emb_v5, thr: float):
    keys, xtr, ytr, _ = package_matrix(tr, features_v4, emb_v4, mode)
    v5_ids = sorted(features_v5.keys())
    _, xv5, yv5, used = package_matrix(v5_ids, features_v5, emb_v5, mode, keys=keys)
    if len(set(ytr.tolist())) < 2 or len(set(yv5.tolist())) < 2:
        return {"skipped": True, "mode": mode}
    _, pv5 = fit_predict("logistic_regression", xtr, ytr, xv5)
    m = metrics_at_threshold(yv5, pv5, thr)
    m["brier"] = float(brier_score_loss(yv5, pv5))
    try:
        m["roc_auc"] = float(roc_auc_score(yv5, pv5))
    except ValueError:
        m["roc_auc"] = None
    try:
        m["pr_auc"] = float(average_precision_score(yv5, pv5))
    except ValueError:
        m["pr_auc"] = None
    return {
        "mode": mode,
        "threshold": thr,
        "n": int(len(yv5)),
        "positives": int(yv5.sum()),
        "negatives": int(len(yv5) - yv5.sum()),
        "prevalence": float(yv5.mean()),
        "testIds": used,
        "y": yv5.tolist(),
        "proba": pv5.tolist(),
        **m,
    }


def error_rows(features_v5, ids, y, p_struct, p_embed, thr_s, thr_e, top_n=10):
    rows = []
    for i, sid in enumerate(ids):
        gt = int(y[i])
        ps, pe = float(p_struct[i]), float(p_embed[i])
        pred_s = int(ps >= thr_s)
        pred_e = int(pe >= thr_e)
        feat = features_v5.get(sid) or {}
        rows.append(
            {
                "sample_id": sid,
                "label": feat.get("label"),
                "y": gt,
                "structuredProba": ps,
                "embedMeanProba": pe,
                "structuredPred": pred_s,
                "embedPred": pred_e,
                "deterministicScore": feat.get("deterministicScore"),
                "deterministicRecommendation": feat.get("deterministicRecommendation"),
                "n_slices": feat.get("n_slices"),
                "attack_category": feat.get("attack_category"),
                "notes": feat.get("notes"),
                "package_name": (feat.get("_meta") or {}).get("package_name"),
            }
        )
    fps = sorted(
        [r for r in rows if r["y"] == 0 and r["embedPred"] == 1],
        key=lambda r: -r["embedMeanProba"],
    )[:top_n]
    fns = sorted(
        [r for r in rows if r["y"] == 1 and r["embedPred"] == 0],
        key=lambda r: r["embedMeanProba"],
    )[:top_n]
    return fps, fns


def main() -> None:
    set_seed(42)
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    thr_s = float(freeze["structuredBaseline"]["recallAt5pctFpr"]["threshold"])
    thr_e = float(freeze["selectedPackageModel"]["recallAt5pctFpr"]["threshold"])
    ckpt = Path(freeze["sliceCheckpoint"])
    emb_v4 = Path(freeze["embeddingDir"])

    if not V5_FEATURES.exists() or not V5_INDEX.exists():
        raise SystemExit("V5 neural export missing; run export_v5_neural first")

    emb_v5 = MODELS / "embeddings" / f"v5-slice-{freeze['sliceCheckpointSha256'][:16]}"
    if not any(emb_v5.glob("*.pt")):
        print(json.dumps({"stage": "export_v5_embeddings", "dir": str(emb_v5)}))
        export_v5_embeddings(ckpt, emb_v5)

    split = json.loads(V4_SPLIT.read_text(encoding="utf-8"))
    matched = set(json.loads(V4_MATCHED.read_text(encoding="utf-8"))["matchedSampleIds"])
    tr = [i for i in split["train"] if i in matched]
    features_v4 = load_strict_features(V4_FEATURES)
    features_v5_all = load_strict_features(V5_FEATURES)
    primary_path = REPO / "ml" / "data-manifests" / "v5" / "primary_eval_ids.json"
    if primary_path.exists():
        primary_ids = set(json.loads(primary_path.read_text(encoding="utf-8")))
        features_v5 = {k: v for k, v in features_v5_all.items() if k in primary_ids}
    else:
        features_v5 = features_v5_all

    structured = score_mode(
        "STRUCTURED_BEHAVIOUR",
        tr,
        features_v4,
        features_v5,
        emb_v4,
        emb_v5,
        thr_s,
    )
    embed = score_mode(
        "EMBED_MEAN_ONLY",
        tr,
        features_v4,
        features_v5,
        emb_v4,
        emb_v5,
        thr_e,
    )

    y = np.array(structured["y"])
    boot = paired_bootstrap_pr_auc(
        y,
        np.array(embed["proba"]),
        np.array(structured["proba"]),
        n_boot=10000,
        seed=7,
    )
    fps, fns = error_rows(
        features_v5,
        structured["testIds"],
        structured["y"],
        structured["proba"],
        embed["proba"],
        thr_s,
        thr_e,
    )

    # distribution shift vs V4 matched test
    v4_test = set(split["test"]) & matched
    v4_slices = [int((features_v4.get(i) or {}).get("n_slices") or 0) for i in v4_test]
    v5_slices = [int(r.get("n_slices") or 0) for r in features_v5.values()]

    preds_path = OUT / "v5_predictions.jsonl"
    OUT.mkdir(parents=True, exist_ok=True)
    with preds_path.open("w", encoding="utf-8") as f:
        for i, sid in enumerate(structured["testIds"]):
            f.write(
                json.dumps(
                    {
                        "sample_id": sid,
                        "y": structured["y"][i],
                        "structured_proba": structured["proba"][i],
                        "embed_mean_proba": embed["proba"][i],
                        "label": (features_v5.get(sid) or {}).get("label"),
                    }
                )
                + "\n"
            )

    summary = {
        "experimentId": "pg-neural-exp1",
        "datasetVersion": "v5",
        "inferenceOnly": True,
        "n": structured["n"],
        "positives": structured["positives"],
        "negatives": structured["negatives"],
        "prevalence": structured["prevalence"],
        "labels": dict(Counter((features_v5[s]["label"] for s in structured["testIds"]))),
        "structured": {
            k: structured[k]
            for k in (
                "pr_auc",
                "roc_auc",
                "precision",
                "recall",
                "f1",
                "fpr",
                "fnr",
                "brier",
                "threshold",
            )
            if k in structured
        },
        "embedMean": {
            k: embed[k]
            for k in (
                "pr_auc",
                "roc_auc",
                "precision",
                "recall",
                "f1",
                "fpr",
                "fnr",
                "brier",
                "threshold",
            )
            if k in embed
        },
        "deltaPrAuc": (embed.get("pr_auc") or 0) - (structured.get("pr_auc") or 0),
        "pairedBootstrapPrAuc": boot,
        "v4DeltaPrAuc": freeze["testMetrics"]["absoluteDeltaPrAuc"],
        "falsePositivesTop": fps,
        "falseNegativesTop": fns,
        "distributionShift": {
            "v4MatchedTestSliceMean": float(np.mean(v4_slices)) if v4_slices else None,
            "v5SliceMean": float(np.mean(v5_slices)) if v5_slices else None,
            "v4MatchedTestGe1": float(np.mean([c >= 1 for c in v4_slices]))
            if v4_slices
            else None,
            "v5Ge1": float(np.mean([c >= 1 for c in v5_slices])) if v5_slices else None,
        },
        "predictionsPath": str(preds_path),
        "embeddingDir": str(emb_v5),
        "sliceCheckpointSha256": freeze["sliceCheckpointSha256"],
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k not in {"falsePositivesTop", "falseNegativesTop"}}, indent=2))


if __name__ == "__main__":
    main()
