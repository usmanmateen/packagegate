"""Cache PG-SLICE-V1 CLS embeddings per package (outside git)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import torch
from torch.utils.data import DataLoader
from transformers import AutoTokenizer

from packagegate_ml.neural import (
    BASE_MODEL_ID,
    BASE_MODEL_REVISION,
    BEHAVIOUR_LABELS_V1,
    MAX_SEQ_LENGTH,
    SLICE_SCHEMA_VERSION,
)
from packagegate_ml.neural.datasets import SliceDataset, load_index, load_split
from packagegate_ml.neural.train_slice_encoder import SliceEncoder, HOLDOUT_IDS

REPO = Path(__file__).resolve().parents[3]
SPLIT = REPO / "ml" / "data-manifests" / "v4" / "neural" / "split.json"
INDEX = Path("/tmp/packagegate-ml-data-v4/exports/v4-neural/index.jsonl")
MODELS = Path(os.environ.get("PACKAGEGATE_ML_MODELS", "/home/usman/packagegate-ml-models"))


@torch.no_grad()
def main() -> None:
    ckpt_path = Path(
        os.environ.get(
            "PG_SLICE_CKPT",
            str(sorted(MODELS.glob("*-pg-slice-v1/best.pt"))[-1]),
        )
    )
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    ckpt_hash = hashlib.sha256(ckpt_path.read_bytes()).hexdigest()[:16]
    out_root = MODELS / "embeddings" / f"slice-{ckpt_hash}"
    out_root.mkdir(parents=True, exist_ok=True)

    model = SliceEncoder(BASE_MODEL_ID, BASE_MODEL_REVISION, len(BEHAVIOUR_LABELS_V1))
    model.load_state_dict(ckpt["model_state"], strict=False)
    model.to(device)
    model.eval()
    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL_ID, revision=BASE_MODEL_REVISION, trust_remote_code=False
    )

    split = load_split(SPLIT)
    index = load_index(INDEX)
    all_ids = [
        i
        for part in ("train", "validation", "test")
        for i in split[part]
        if i not in HOLDOUT_IDS
    ]
    # also qualitative holdouts separately later
    holdouts = json.loads(
        (REPO / "ml" / "data-manifests" / "v4" / "neural" / "holdouts.json").read_text()
    )
    if isinstance(holdouts, dict):
        holdout_ids = holdouts.get("sampleIds") or holdouts.get("ids") or []
        if not holdout_ids and "records" not in holdouts:
            # file may be list of ids or split-like
            holdout_ids = holdouts if isinstance(holdouts, list) else list(holdouts.values())[0] if holdouts else []
    elif isinstance(holdouts, list):
        holdout_ids = holdouts
    else:
        holdout_ids = []

    ds = SliceDataset(all_ids, index, tokenizer=tokenizer, max_length=MAX_SEQ_LENGTH)
    loader = DataLoader(ds, batch_size=16, shuffle=False)

    # accumulate per package
    buckets: dict[str, list[torch.Tensor]] = {}
    ranks: dict[str, list[tuple[float, str, torch.Tensor]]] = {}
    for batch in loader:
        out = model(batch["input_ids"].to(device), batch["attention_mask"].to(device))
        cls = out["cls"].cpu()
        logits = out["logits"].cpu()
        for i in range(cls.size(0)):
            sid = batch["sample_id"][i]
            slice_id = batch["slice_id"][i]
            buckets.setdefault(sid, []).append(cls[i])
            # rank by max sigmoid behaviour score
            score = float(torch.sigmoid(logits[i]).max())
            ranks.setdefault(sid, []).append((score, slice_id, cls[i]))

    meta = {
        "checkpoint": str(ckpt_path),
        "checkpointSha16": ckpt_hash,
        "baseModel": BASE_MODEL_ID,
        "revision": BASE_MODEL_REVISION,
        "sliceSchemaVersion": SLICE_SCHEMA_VERSION,
        "packages": 0,
        "zeroSlicePackages": 0,
    }
    for sid in all_ids:
        safe = sid.replace("/", "_").replace("@", "_").replace(":", "_")
        path = out_root / f"{safe}.pt"
        if sid not in buckets:
            torch.save(
                {
                    "sample_id": sid,
                    "embeddings": torch.zeros(0, model.encoder.config.hidden_size),
                    "slice_ids": [],
                    "scores": [],
                    "code_view_available": False,
                },
                path,
            )
            meta["zeroSlicePackages"] += 1
        else:
            ordered = sorted(ranks[sid], key=lambda t: -t[0])
            emb = torch.stack([t[2] for t in ordered], dim=0)
            torch.save(
                {
                    "sample_id": sid,
                    "embeddings": emb,
                    "slice_ids": [t[1] for t in ordered],
                    "scores": [t[0] for t in ordered],
                    "code_view_available": True,
                },
                path,
            )
        meta["packages"] += 1

    (out_root / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(json.dumps({"embeddingDir": str(out_root), **meta}, indent=2))


if __name__ == "__main__":
    main()
