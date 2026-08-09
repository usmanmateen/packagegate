"""Slice and package datasets for neural V1 (family-split inherited)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import torch
from torch.utils.data import Dataset

from packagegate_ml.neural import BEHAVIOUR_LABELS_V1


def load_split(path: Path) -> dict[str, list[str]]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_index(path: Path) -> dict[str, dict]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            out[r["sample_id"]] = r
    return out


def load_strict_features(path: Path) -> dict[str, dict]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            out[r["sample_id"]] = r
    return out


def label_vector_fixed(behaviour_labels: list[str], vocab: tuple[str, ...] = BEHAVIOUR_LABELS_V1) -> list[float]:
    s = set(behaviour_labels or [])
    return [1.0 if lab in s else 0.0 for lab in vocab]


class SliceDataset(Dataset):
    """One item per security slice; inherits package family split."""

    def __init__(
        self,
        sample_ids: list[str],
        index: dict[str, dict],
        *,
        tokenizer,
        max_length: int = 512,
        labels: tuple[str, ...] = BEHAVIOUR_LABELS_V1,
    ) -> None:
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.labels = labels
        self.items: list[dict[str, Any]] = []
        for sid in sample_ids:
            meta = index.get(sid)
            if not meta:
                continue
            path = Path(meta["path"])
            if not path.exists():
                continue
            rec = json.loads(path.read_text(encoding="utf-8"))
            for sl in rec.get("slices") or []:
                text = sl.get("sourceText") or ""
                if not text.strip():
                    continue
                self.items.append(
                    {
                        "sample_id": sid,
                        "slice_id": sl.get("sliceId"),
                        "text": text,
                        "y": label_vector_fixed(list(sl.get("behaviourLabels") or []), labels),
                    }
                )

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, idx: int) -> dict[str, Any]:
        item = self.items[idx]
        enc = self.tokenizer(
            item["text"],
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "labels": torch.tensor(item["y"], dtype=torch.float32),
            "sample_id": item["sample_id"],
            "slice_id": item["slice_id"] or "",
        }


class PackageDataset(Dataset):
    """Package-level rows with optional precomputed slice embedding paths."""

    def __init__(
        self,
        sample_ids: list[str],
        features: dict[str, dict],
        *,
        embedding_dir: Path | None = None,
        exclude_fixtures: bool = True,
    ) -> None:
        self.rows: list[dict[str, Any]] = []
        for sid in sample_ids:
            if exclude_fixtures and sid.startswith("fixture:"):
                continue
            row = features.get(sid)
            if not row:
                continue
            label = row.get("label")
            if label not in {"MALICIOUS", "COMPROMISED", "EXPECTED_BENIGN"}:
                continue
            y = 1 if label in {"MALICIOUS", "COMPROMISED"} else 0
            emb = None
            if embedding_dir is not None:
                p = embedding_dir / f"{sid.replace('/', '_').replace('@', '_').replace(':', '_')}.pt"
                if p.exists():
                    emb = torch.load(p, map_location="cpu", weights_only=True)
            self.rows.append(
                {
                    "sample_id": sid,
                    "y": y,
                    "behaviour": row.get("behaviour_features") or {},
                    "code_view_available": bool(row.get("code_view_available")),
                    "n_slices": int(row.get("n_slices") or 0),
                    "embedding": emb,
                }
            )

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int) -> dict[str, Any]:
        return self.rows[idx]
