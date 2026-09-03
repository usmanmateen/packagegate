"""Multi-seed robustness for PG-SLICE-V1 + package embed-mean (Exp1 config frozen)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SEEDS = [11, 22, 33, 44, 55]
EXP = REPO / "ml" / "experiments" / "pg-neural-exp1"
MODELS = Path(os.environ.get("PACKAGEGATE_ML_MODELS", "${PACKAGEGATE_ML_MODELS}"))


def run(cmd: list[str], env: dict) -> None:
    print(json.dumps({"cmd": cmd, "seed": env.get("PG_SLICE_SEED")}), flush=True)
    subprocess.run(cmd, cwd=str(REPO / "ml"), env=env, check=True)


def main() -> None:
    base_env = os.environ.copy()
    base_env.update(
        {
            "HF_HOME": "${PACKAGEGATE_ML_CACHE}/huggingface",
            "TRANSFORMERS_CACHE": "${PACKAGEGATE_ML_CACHE}/huggingface",
            "PACKAGEGATE_ML_MODELS": str(MODELS),
            "PACKAGEGATE_ML_DATA_ROOT": "/tmp/packagegate-ml-data-v4",
            "PYTHONUNBUFFERED": "1",
        }
    )
    results = []
    py = [sys.executable, "-m"]
    for seed in SEEDS:
        env = dict(base_env)
        env["PG_SLICE_SEED"] = str(seed)
        # 1) train encoder (reuse existing seed checkpoint if present)
        ckpts = sorted(MODELS.glob(f"*-pg-slice-v1-seed{seed}/best.pt"))
        if not ckpts:
            run([*py, "packagegate_ml.neural.train_slice_encoder"], env)
            ckpts = sorted(MODELS.glob(f"*-pg-slice-v1-seed{seed}/best.pt"))
        if not ckpts:
            raise SystemExit(f"missing checkpoint for seed {seed}")
        ckpt = ckpts[-1]
        env["PG_SLICE_CKPT"] = str(ckpt)
        # 2) export embeddings
        run([*py, "packagegate_ml.neural.export_embeddings"], env)
        emb_dirs = sorted((MODELS / "embeddings").glob("slice-*"), key=lambda p: p.stat().st_mtime)
        env["PG_EMBED_DIR"] = str(emb_dirs[-1])
        # 3) package eval (writes run under ml/runs)
        run([*py, "packagegate_ml.neural.train_package"], env)
        # read latest package run
        runs = sorted((REPO / "ml" / "runs").glob("*-pg-package-mil-v1"))
        meta = json.loads((runs[-1] / "metadata.json").read_text(encoding="utf-8"))
        full = meta["full"]
        results.append(
            {
                "seed": seed,
                "sliceCheckpoint": str(ckpt),
                "embeddingDir": env["PG_EMBED_DIR"],
                "packageRunId": meta["runId"],
                "structuredPrAuc": full["STRUCTURED_BEHAVIOUR_LOGISTIC"]["pr_auc"],
                "embedMeanPrAuc": full["EMBED_MEAN_ONLY"]["pr_auc"],
                "embedMeanRecallAt5": (
                    full["EMBED_MEAN_ONLY"].get("recallAt5pctFpr") or {}
                ).get("recall"),
                "embedMeanF1": full["EMBED_MEAN_ONLY"].get("f1"),
                "embedMeanBrier": full["EMBED_MEAN_ONLY"].get("brier"),
                "deltaVsStructured": full["EMBED_MEAN_ONLY"]["pr_auc"]
                - full["STRUCTURED_BEHAVIOUR_LOGISTIC"]["pr_auc"],
            }
        )
        (EXP / "seed_robustness_partial.json").write_text(
            json.dumps(results, indent=2) + "\n", encoding="utf-8"
        )

    import numpy as np

    prs = [r["embedMeanPrAuc"] for r in results]
    deltas = [r["deltaVsStructured"] for r in results]
    recalls = [r["embedMeanRecallAt5"] for r in results if r["embedMeanRecallAt5"] is not None]
    summary = {
        "seeds": SEEDS,
        "results": results,
        "embedMeanPrAuc": {
            "values": prs,
            "mean": float(np.mean(prs)),
            "std": float(np.std(prs)),
            "min": float(np.min(prs)),
            "max": float(np.max(prs)),
        },
        "deltaVsStructured": {
            "values": deltas,
            "mean": float(np.mean(deltas)),
            "std": float(np.std(deltas)),
            "min": float(np.min(deltas)),
            "max": float(np.max(deltas)),
        },
        "embedMeanRecallAt5": {
            "values": recalls,
            "mean": float(np.mean(recalls)) if recalls else None,
            "std": float(np.std(recalls)) if recalls else None,
        },
        "originalExp1EmbedPrAuc": 0.8974494768667705,
        "originalRepresentative": None,
    }
    # Is original within mean±1std?
    m, s = summary["embedMeanPrAuc"]["mean"], summary["embedMeanPrAuc"]["std"]
    summary["originalRepresentative"] = bool(
        abs(0.8974494768667705 - m) <= max(s, 0.02)
    )
    (EXP / "seed_robustness.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
