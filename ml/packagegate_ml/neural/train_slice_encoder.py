"""Train PG-SLICE-V1: GraphCodeBERT multi-label behaviour encoder."""

from __future__ import annotations

import hashlib
import json
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import average_precision_score, f1_score
from torch.utils.data import DataLoader
from transformers import AutoModel, AutoTokenizer, get_linear_schedule_with_warmup

from packagegate_ml.neural import (
    BASE_MODEL_ID,
    BASE_MODEL_REVISION,
    BEHAVIOUR_LABELS_V1,
    MAX_SEQ_LENGTH,
)
from packagegate_ml.neural.datasets import SliceDataset, load_index, load_split

REPO = Path(__file__).resolve().parents[3]
SPLIT = REPO / "ml" / "data-manifests" / "v4" / "neural" / "split.json"
INDEX = Path("/tmp/packagegate-ml-data-v4/exports/v4-neural/index.jsonl")
MODELS = Path(os.environ.get("PACKAGEGATE_ML_MODELS", "${PACKAGEGATE_ML_MODELS}"))
RUNS = REPO / "ml" / "runs"

HOLDOUT_IDS = {"02-echo@0.0.7"}


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


class SliceEncoder(nn.Module):
    def __init__(self, model_id: str, revision: str, n_labels: int) -> None:
        super().__init__()
        self.encoder = AutoModel.from_pretrained(
            model_id, revision=revision, trust_remote_code=False
        )
        hidden = self.encoder.config.hidden_size
        self.classifier = nn.Linear(hidden, n_labels)

    def forward(self, input_ids, attention_mask, labels=None):
        out = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        cls = out.last_hidden_state[:, 0]
        logits = self.classifier(cls)
        loss = None
        if labels is not None:
            # pos_weight set externally via criterion
            loss = self.criterion(logits, labels)
        return {"loss": loss, "logits": logits, "cls": cls}

    def set_criterion(self, pos_weight: torch.Tensor) -> None:
        self.criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)


@torch.no_grad()
def evaluate(model, loader, device, labels) -> dict:
    model.eval()
    ys, ps = [], []
    for batch in loader:
        logits = model(
            batch["input_ids"].to(device),
            batch["attention_mask"].to(device),
        )["logits"]
        prob = torch.sigmoid(logits).cpu().numpy()
        y = batch["labels"].numpy()
        ys.append(y)
        ps.append(prob)
    if not ys:
        return {"skipped": True}
    y = np.vstack(ys)
    p = np.vstack(ps)
    pred = (p >= 0.5).astype(np.float32)
    per = {}
    for i, lab in enumerate(labels):
        support = int(y[:, i].sum())
        if support == 0 or y[:, i].min() == y[:, i].max():
            per[lab] = {"support": support, "f1": None, "pr_auc": None}
            continue
        per[lab] = {
            "support": support,
            "f1": float(f1_score(y[:, i], pred[:, i], zero_division=0)),
            "pr_auc": float(average_precision_score(y[:, i], p[:, i])),
            "precision": float(
                ((pred[:, i] == 1) & (y[:, i] == 1)).sum() / max(1, (pred[:, i] == 1).sum())
            ),
            "recall": float(
                ((pred[:, i] == 1) & (y[:, i] == 1)).sum() / max(1, support)
            ),
        }
    return {
        "micro_f1": float(f1_score(y, pred, average="micro", zero_division=0)),
        "macro_f1": float(f1_score(y, pred, average="macro", zero_division=0)),
        "micro_pr_auc": float(average_precision_score(y, p, average="micro")),
        "macro_pr_auc": float(average_precision_score(y, p, average="macro")),
        "per_label": per,
        "n": int(len(y)),
    }


def main() -> None:
    if not torch.cuda.is_available():
        raise SystemExit("CUDA unavailable — stop GPU training")
    seed = int(os.environ.get("PG_SLICE_SEED", "42"))
    set_seed(seed)
    device = torch.device("cuda")
    smoke = os.environ.get("PG_SLICE_SMOKE", "0") == "1"

    split = load_split(SPLIT)
    index = load_index(INDEX)
    train_ids = [i for i in split["train"] if i not in HOLDOUT_IDS]
    val_ids = [i for i in split["validation"] if i not in HOLDOUT_IDS]
    test_ids = [i for i in split["test"] if i not in HOLDOUT_IDS]
    assert "02-echo@0.0.7" not in train_ids + val_ids

    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL_ID, revision=BASE_MODEL_REVISION, trust_remote_code=False
    )
    train_ds = SliceDataset(train_ids, index, tokenizer=tokenizer, max_length=MAX_SEQ_LENGTH)
    val_ds = SliceDataset(val_ids, index, tokenizer=tokenizer, max_length=MAX_SEQ_LENGTH)
    test_ds = SliceDataset(test_ids, index, tokenizer=tokenizer, max_length=MAX_SEQ_LENGTH)

    # class imbalance pos_weight
    y_all = np.array([it["y"] for it in train_ds.items], dtype=np.float32)
    pos = y_all.sum(0)
    neg = len(y_all) - pos
    pos_weight = torch.tensor(np.where(pos > 0, neg / np.maximum(pos, 1), 1.0), dtype=torch.float32)

    batch_size = 8 if not smoke else 4
    accum = 2
    epochs = 1 if smoke else 3
    lr = 2e-5
    max_train = 400 if smoke else None

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False)

    model = SliceEncoder(BASE_MODEL_ID, BASE_MODEL_REVISION, len(BEHAVIOUR_LABELS_V1))
    model.set_criterion(pos_weight.to(device))
    model.to(device)

    optim = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    # estimate steps
    n_batches = len(train_loader) if max_train is None else min(len(train_loader), max_train)
    total_steps = max(1, (n_batches // accum) * epochs)
    sched = get_linear_schedule_with_warmup(
        optim, num_warmup_steps=max(1, total_steps // 10), num_training_steps=total_steps
    )
    use_bf16 = torch.cuda.is_bf16_supported()
    scaler = torch.amp.GradScaler("cuda", enabled=not use_bf16)

    run_id = datetime.now(timezone.utc).strftime(f"%Y%m%dT%H%M%SZ-pg-slice-v1-seed{seed}")
    out_dir = MODELS / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    best_path = out_dir / "best.pt"
    best_metric = -1.0
    history = []
    t0 = time.time()

    for epoch in range(epochs):
        model.train()
        optim.zero_grad(set_to_none=True)
        running = 0.0
        n_seen = 0
        for step, batch in enumerate(train_loader):
            if max_train is not None and step >= max_train:
                break
            with torch.amp.autocast("cuda", dtype=torch.bfloat16 if use_bf16 else torch.float16):
                out = model(
                    batch["input_ids"].to(device),
                    batch["attention_mask"].to(device),
                    batch["labels"].to(device),
                )
                loss = out["loss"] / accum
            if use_bf16:
                loss.backward()
            else:
                scaler.scale(loss).backward()
            if (step + 1) % accum == 0:
                if use_bf16:
                    torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                    optim.step()
                else:
                    scaler.unscale_(optim)
                    torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                    scaler.step(optim)
                    scaler.update()
                sched.step()
                optim.zero_grad(set_to_none=True)
            running += float(out["loss"].detach()) * batch["labels"].size(0)
            n_seen += batch["labels"].size(0)
        val_metrics = evaluate(model, val_loader, device, BEHAVIOUR_LABELS_V1)
        score = val_metrics.get("micro_f1") or 0.0
        history.append(
            {
                "epoch": epoch,
                "train_loss": running / max(1, n_seen),
                "val": val_metrics,
            }
        )
        print(json.dumps({"epoch": epoch, "train_loss": history[-1]["train_loss"], "val_micro_f1": score, "val_macro_f1": val_metrics.get("macro_f1")}), flush=True)
        if score >= best_metric:
            best_metric = score
            torch.save(
                {
                    "model_state": {
                        k: v
                        for k, v in model.state_dict().items()
                        if not k.startswith("criterion.")
                    },
                    "labels": BEHAVIOUR_LABELS_V1,
                    "base_model": BASE_MODEL_ID,
                    "revision": BASE_MODEL_REVISION,
                    "max_length": MAX_SEQ_LENGTH,
                    "val_metrics": val_metrics,
                },
                best_path,
            )

    # Load best for test (once). Criterion buffers are not checkpointed.
    ckpt = torch.load(best_path, map_location=device, weights_only=False)
    model.load_state_dict(ckpt["model_state"], strict=False)
    test_metrics = evaluate(model, test_loader, device, BEHAVIOUR_LABELS_V1)
    duration = time.time() - t0
    ckpt_hash = hashlib.sha256(best_path.read_bytes()).hexdigest()

    meta = {
        "runId": run_id,
        "task": "pg-slice-v1",
        "smoke": smoke,
        "baseModel": BASE_MODEL_ID,
        "baseRevision": BASE_MODEL_REVISION,
        "maxLength": MAX_SEQ_LENGTH,
        "labels": list(BEHAVIOUR_LABELS_V1),
        "trainSlices": len(train_ds),
        "valSlices": len(val_ds),
        "testSlices": len(test_ds),
        "batchSize": batch_size,
        "gradAccum": accum,
        "epochs": epochs,
        "lr": lr,
        "bf16": use_bf16,
        "posWeight": pos_weight.cpu().tolist(),
        "labelSupportTrain": {lab: int(pos[i]) for i, lab in enumerate(BEHAVIOUR_LABELS_V1)},
        "history": history,
        "bestValMicroF1": best_metric,
        "testMetrics": test_metrics,
        "durationSec": duration,
        "checkpoint": str(best_path),
        "checkpointSha256": ckpt_hash,
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "gpu": torch.cuda.get_device_name(0),
        "transformers": __import__("transformers").__version__,
        "seed": seed,
        "02echoExcluded": True,
    }
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"runId": run_id, "bestValMicroF1": best_metric, "testMicroF1": test_metrics.get("micro_f1"), "testMacroF1": test_metrics.get("macro_f1"), "checkpoint": str(best_path)}, indent=2))


if __name__ == "__main__":
    main()
