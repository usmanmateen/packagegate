"""Package-level baselines + MIL hybrid for neural V1."""

from __future__ import annotations

import json
import os
import random
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from packagegate_ml.features.structured import align_feature_matrix
from packagegate_ml.neural.datasets import load_split, load_strict_features
from packagegate_ml.training.train_pilot_structured import (
    fit_predict,
    metrics_at_threshold,
    recall_at_fpr,
    select_threshold_for_fpr,
)

REPO = Path(__file__).resolve().parents[3]
SPLIT = REPO / "ml" / "data-manifests" / "v4" / "neural" / "split.json"
MATCHED = REPO / "ml" / "data-manifests" / "v4" / "structure_matches.json"
FEATURES = Path("/tmp/packagegate-ml-data-v4/exports/v4-neural/strict_features.jsonl")
MODELS = Path(os.environ.get("PACKAGEGATE_ML_MODELS", "/home/usman/packagegate-ml-models"))
RUNS = REPO / "ml" / "runs"
HOLDOUT = "02-echo@0.0.7"


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def binlab(label: str) -> int:
    return 1 if label in {"MALICIOUS", "COMPROMISED"} else 0


def mean_emb(path: Path, dim: int = 768) -> np.ndarray:
    if not path.exists():
        return np.zeros(dim, dtype=np.float32)
    obj = torch.load(path, map_location="cpu", weights_only=True)
    emb = obj.get("embeddings")
    if emb is None or emb.numel() == 0:
        return np.zeros(dim, dtype=np.float32)
    return emb.mean(0).numpy().astype(np.float32)


def package_matrix(ids, features, emb_dir: Path | None, mode: str, keys=None):
    dicts, ys, used = [], [], []
    for sid in ids:
        if sid == HOLDOUT or sid.startswith("fixture:"):
            continue
        row = features.get(sid)
        if not row or row.get("label") not in {
            "MALICIOUS",
            "COMPROMISED",
            "EXPECTED_BENIGN",
        }:
            continue
        used.append(sid)
        ys.append(binlab(row["label"]))
        beh = dict(row.get("behaviour_features") or {})
        safe = sid.replace("/", "_").replace("@", "_").replace(":", "_")
        emb = (
            mean_emb(emb_dir / f"{safe}.pt")
            if emb_dir is not None
            else np.zeros(768, dtype=np.float32)
        )
        code_flag = 1.0 if row.get("code_view_available") else 0.0
        if mode == "STRUCTURED_BEHAVIOUR":
            dicts.append(beh)
        elif mode == "EMBED_MEAN_ONLY":
            d = {f"e{i}": float(emb[i]) for i in range(len(emb))}
            d["codeViewAvailable"] = code_flag
            dicts.append(d)
        elif mode == "EMBED_MEAN_PLUS_STRUCTURED":
            d = dict(beh)
            for i, v in enumerate(emb):
                d[f"e{i}"] = float(v)
            d["codeViewAvailable"] = code_flag
            dicts.append(d)
        else:
            raise ValueError(mode)
    if keys is None:
        keys, x = align_feature_matrix(dicts)
    else:
        x = np.zeros((len(dicts), len(keys)), dtype=np.float64)
        for i, d in enumerate(dicts):
            for j, k in enumerate(keys):
                x[i, j] = float(d.get(k, 0.0))
    return keys, x, np.array(ys, dtype=np.int64), used


def eval_sklearn(mode, tr, va, te, features, emb_dir, model_kind="logistic"):
    keys, xtr, ytr, _ = package_matrix(tr, features, emb_dir, mode)
    _, xva, yva, _ = package_matrix(va, features, emb_dir, mode, keys=keys)
    _, xte, yte, used_te = package_matrix(te, features, emb_dir, mode, keys=keys)
    out = {
        "mode": mode,
        "model": model_kind,
        "testN": int(len(yte)),
        "positives": int(yte.sum()),
        "negatives": int(len(yte) - yte.sum()),
        "prevalence": float(yte.mean()) if len(yte) else 0.0,
    }
    if len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        out["skipped"] = True
        return out
    if model_kind == "tree":
        clf = HistGradientBoostingClassifier(max_depth=4, random_state=0)
        clf.fit(xtr, ytr)
        pva = clf.predict_proba(xva)[:, 1]
        pte = clf.predict_proba(xte)[:, 1]
    else:
        _, pva = fit_predict("logistic_regression", xtr, ytr, xva)
        _, pte = fit_predict("logistic_regression", xtr, ytr, xte)
    thr = select_threshold_for_fpr(yva, pva, 0.05)
    m = metrics_at_threshold(yte, pte, thr)
    m["brier"] = float(brier_score_loss(yte, pte))
    try:
        m["roc_auc"] = float(roc_auc_score(yte, pte))
    except ValueError:
        m["roc_auc"] = None
    m["recallAt5pctFpr"] = recall_at_fpr(yte, pte, 0.05)
    out.update(m)
    out["threshold"] = thr
    out["testIds"] = used_te
    out["proba"] = pte.tolist()
    return out


class GatedAttentionMIL(nn.Module):
    def __init__(self, emb_dim=768, structured_dim=0, hidden=128) -> None:
        super().__init__()
        self.proj = nn.Sequential(nn.Linear(emb_dim, hidden), nn.ReLU())
        self.attn_v = nn.Linear(hidden, hidden)
        self.attn_u = nn.Linear(hidden, hidden)
        self.attn_w = nn.Linear(hidden, 1)
        self.structured_dim = structured_dim
        in_dim = hidden + structured_dim + 1  # + codeViewAvailable
        self.head = nn.Sequential(
            nn.Linear(in_dim, hidden),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden, 1),
        )

    def forward(self, embeddings, structured, code_flag):
        """
        embeddings: (N, D) or (0, D)
        structured: (S,)
        code_flag: ()
        """
        if embeddings.numel() == 0:
            bag = torch.zeros(self.proj[0].out_features, device=structured.device)
            weights = embeddings.new_zeros(0)
        else:
            h = self.proj(embeddings)
            a = torch.tanh(self.attn_v(h)) * torch.sigmoid(self.attn_u(h))
            logits = self.attn_w(a).squeeze(-1)
            weights = torch.softmax(logits, dim=0)
            bag = (weights.unsqueeze(-1) * h).sum(0)
        x = torch.cat([bag, structured, code_flag.view(1)], dim=0)
        return self.head(x).squeeze(-1), weights


def bootstrap_pr(y, p, n=200, seed=0):
    rng = np.random.default_rng(seed)
    scores = []
    y = np.asarray(y)
    p = np.asarray(p)
    for _ in range(n):
        idx = rng.integers(0, len(y), len(y))
        if len(set(y[idx].tolist())) < 2:
            continue
        scores.append(float(average_precision_score(y[idx], p[idx])))
    if not scores:
        return None
    return {
        "mean": float(np.mean(scores)),
        "lo": float(np.percentile(scores, 2.5)),
        "hi": float(np.percentile(scores, 97.5)),
    }


def train_mil(tr_ids, va_ids, features, emb_dir, structured_keys, *, code_only=False, epochs=8):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    def pack(ids):
        items = []
        for sid in ids:
            if sid == HOLDOUT or sid.startswith("fixture:"):
                continue
            row = features.get(sid)
            if not row or row.get("label") not in {
                "MALICIOUS",
                "COMPROMISED",
                "EXPECTED_BENIGN",
            }:
                continue
            safe = sid.replace("/", "_").replace("@", "_").replace(":", "_")
            obj = torch.load(emb_dir / f"{safe}.pt", map_location="cpu", weights_only=True)
            emb = obj["embeddings"]
            beh = row.get("behaviour_features") or {}
            struct = torch.tensor(
                [float(beh.get(k, 0.0)) for k in structured_keys], dtype=torch.float32
            )
            if code_only:
                struct = torch.zeros_like(struct)
            items.append(
                {
                    "sid": sid,
                    "emb": emb,
                    "struct": struct,
                    "code": torch.tensor(
                        1.0 if row.get("code_view_available") else 0.0
                    ),
                    "y": torch.tensor(float(binlab(row["label"]))),
                }
            )
        return items

    train_items = pack(tr_ids)
    val_items = pack(va_ids)
    model = GatedAttentionMIL(
        emb_dim=768,
        structured_dim=len(structured_keys),
        hidden=128,
    ).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    # class weight
    pos = sum(1 for it in train_items if it["y"] > 0.5)
    neg = len(train_items) - pos
    pos_weight = torch.tensor([neg / max(1, pos)], device=device)
    crit = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    best_state = None
    best_pr = -1.0
    for _ in range(epochs):
        model.train()
        random.shuffle(train_items)
        for it in train_items:
            opt.zero_grad(set_to_none=True)
            logit, _ = model(
                it["emb"].to(device), it["struct"].to(device), it["code"].to(device)
            )
            loss = crit(logit.view(1), it["y"].to(device).view(1))
            loss.backward()
            opt.step()
        # val
        model.eval()
        ys, ps = [], []
        with torch.no_grad():
            for it in val_items:
                logit, _ = model(
                    it["emb"].to(device), it["struct"].to(device), it["code"].to(device)
                )
                ps.append(float(torch.sigmoid(logit).cpu()))
                ys.append(float(it["y"]))
        if len(set(ys)) > 1:
            pr = float(average_precision_score(ys, ps))
            if pr >= best_pr:
                best_pr = pr
                best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
    if best_state:
        model.load_state_dict(best_state)
    return model, best_pr, structured_keys


@torch.no_grad()
def predict_mil(model, ids, features, emb_dir, structured_keys, *, code_only=False):
    device = next(model.parameters()).device
    model.eval()
    ys, ps, used, weights_map = [], [], [], {}
    for sid in ids:
        if sid == HOLDOUT or sid.startswith("fixture:"):
            continue
        row = features.get(sid)
        if not row or row.get("label") not in {
            "MALICIOUS",
            "COMPROMISED",
            "EXPECTED_BENIGN",
        }:
            continue
        safe = sid.replace("/", "_").replace("@", "_").replace(":", "_")
        obj = torch.load(emb_dir / f"{safe}.pt", map_location="cpu", weights_only=True)
        beh = row.get("behaviour_features") or {}
        struct = torch.tensor(
            [float(beh.get(k, 0.0)) for k in structured_keys], dtype=torch.float32
        )
        if code_only:
            struct = torch.zeros_like(struct)
        logit, w = model(
            obj["embeddings"].to(device),
            struct.to(device),
            torch.tensor(1.0 if row.get("code_view_available") else 0.0, device=device),
        )
        used.append(sid)
        ys.append(binlab(row["label"]))
        ps.append(float(torch.sigmoid(logit).cpu()))
        weights_map[sid] = {
            "slice_ids": obj.get("slice_ids") or [],
            "weights": w.detach().cpu().tolist() if w.numel() else [],
            "scores": obj.get("scores") or [],
        }
    return used, np.array(ys), np.array(ps), weights_map


def main() -> None:
    set_seed(42)
    emb_dir = Path(
        os.environ.get(
            "PG_EMBED_DIR",
            str(sorted((MODELS / "embeddings").glob("slice-*"))[-1]),
        )
    )
    split = load_split(SPLIT)
    features = load_strict_features(FEATURES)
    matched = set(json.loads(MATCHED.read_text())["matchedSampleIds"])
    tr = [i for i in split["train"] if i in matched]
    va = [i for i in split["validation"] if i in matched]
    te = [i for i in split["test"] if i in matched]

    results = {
        "STRUCTURED_BEHAVIOUR_LOGISTIC": eval_sklearn(
            "STRUCTURED_BEHAVIOUR", tr, va, te, features, emb_dir, "logistic"
        ),
        "STRUCTURED_BEHAVIOUR_TREE": eval_sklearn(
            "STRUCTURED_BEHAVIOUR", tr, va, te, features, emb_dir, "tree"
        ),
        "EMBED_MEAN_ONLY": eval_sklearn(
            "EMBED_MEAN_ONLY", tr, va, te, features, emb_dir, "logistic"
        ),
        "EMBED_MEAN_PLUS_STRUCTURED": eval_sklearn(
            "EMBED_MEAN_PLUS_STRUCTURED", tr, va, te, features, emb_dir, "logistic"
        ),
    }

    # structured keys from behaviour features
    keys, _, _, _ = package_matrix(tr, features, emb_dir, "STRUCTURED_BEHAVIOUR")

    mil_code, mil_code_val, _ = train_mil(
        tr, va, features, emb_dir, keys, code_only=True, epochs=10
    )
    mil_hyb, mil_hyb_val, _ = train_mil(
        tr, va, features, emb_dir, keys, code_only=False, epochs=10
    )

    def mil_eval(model, code_only, name):
        # threshold on val
        _, yva, pva, _ = predict_mil(
            model, va, features, emb_dir, keys, code_only=code_only
        )
        thr = select_threshold_for_fpr(yva, pva, 0.05) if len(set(yva.tolist())) > 1 else 0.5
        used, yte, pte, wmap = predict_mil(
            model, te, features, emb_dir, keys, code_only=code_only
        )
        m = metrics_at_threshold(yte, pte, thr)
        m["brier"] = float(brier_score_loss(yte, pte))
        try:
            m["roc_auc"] = float(roc_auc_score(yte, pte))
        except ValueError:
            m["roc_auc"] = None
        m["recallAt5pctFpr"] = recall_at_fpr(yte, pte, 0.05)
        m["prAucBootstrap"] = bootstrap_pr(yte, pte)
        # simple calibration on val via logistic on scores
        if len(set(yva.tolist())) > 1:
            cal = LogisticRegression(max_iter=1000)
            cal.fit(np.asarray(pva).reshape(-1, 1), yva)
            pte_cal = cal.predict_proba(pte.reshape(-1, 1))[:, 1]
            m["brierCalibrated"] = float(brier_score_loss(yte, pte_cal))
        else:
            pte_cal = pte
            m["brierCalibrated"] = m["brier"]
        return {
            "mode": name,
            "valPrAuc": None,
            "threshold": thr,
            "testN": int(len(yte)),
            "positives": int(yte.sum()),
            "negatives": int(len(yte) - yte.sum()),
            "prevalence": float(yte.mean()),
            **m,
            "testIds": used,
            "proba": pte.tolist(),
            "probaCalibrated": pte_cal.tolist(),
            "topSlices": {
                sid: {
                    "ranked": sorted(
                        [
                            {
                                "sliceId": (wmap[sid]["slice_ids"][i] if i < len(wmap[sid]["slice_ids"]) else None),
                                "attention": wmap[sid]["weights"][i],
                            }
                            for i in range(len(wmap[sid]["weights"]))
                        ],
                        key=lambda x: -x["attention"],
                    )[:5]
                }
                for sid in used[:20]
            },
        }

    results["MIL_CODE_ONLY"] = mil_eval(mil_code, True, "MIL_CODE_ONLY")
    results["MIL_CODE_ONLY"]["valPrAuc"] = mil_code_val
    results["MIL_PLUS_STRUCTURED"] = mil_eval(mil_hyb, False, "MIL_PLUS_STRUCTURED")
    results["MIL_PLUS_STRUCTURED"]["valPrAuc"] = mil_hyb_val

    # Save MIL hybrid checkpoint
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-pg-package-mil-v1")
    out = MODELS / run_id
    out.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": mil_hyb.state_dict(),
            "structured_keys": keys,
            "code_only": False,
        },
        out / "mil_hybrid.pt",
    )
    torch.save(
        {
            "state_dict": mil_code.state_dict(),
            "structured_keys": keys,
            "code_only": True,
        },
        out / "mil_code.pt",
    )

    base_pr = results["STRUCTURED_BEHAVIOUR_LOGISTIC"].get("pr_auc")
    hyb_pr = results["MIL_PLUS_STRUCTURED"].get("pr_auc")
    mean_pr = results["EMBED_MEAN_PLUS_STRUCTURED"].get("pr_auc")
    verdict = "INCONCLUSIVE"
    if base_pr is not None and hyb_pr is not None:
        if hyb_pr > base_pr + 0.01 or (
            mean_pr is not None and mean_pr > base_pr + 0.01
        ):
            verdict = "YES"
        elif hyb_pr < base_pr - 0.01 and (mean_pr is None or mean_pr < base_pr - 0.01):
            verdict = "NO"
        else:
            verdict = "INCONCLUSIVE"

    summary = {
        "runId": run_id,
        "embeddingDir": str(emb_dir),
        "matchedSizes": {"train": len(tr), "validation": len(va), "test": len(te)},
        "metrics": {
            k: {
                kk: vv
                for kk, vv in v.items()
                if kk
                not in {"testIds", "proba", "probaCalibrated", "topSlices"}
            }
            for k, v in results.items()
        },
        "neuralBeatsStructuredBaseline": verdict,
        "comparison": {
            "structuredLogistic": base_pr,
            "embedMeanPlusStructured": mean_pr,
            "milHybrid": hyb_pr,
            "milCodeOnly": results["MIL_CODE_ONLY"].get("pr_auc"),
        },
    }
    # keep full results for error analysis
    full = {**summary, "full": results}
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metadata.json").write_text(json.dumps(full, indent=2) + "\n")
    (out / "metadata.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
