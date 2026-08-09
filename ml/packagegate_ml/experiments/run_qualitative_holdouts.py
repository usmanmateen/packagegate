"""Qualitative holdout scoring for frozen Exp1 (02-echo + benign controls).

Not part of aggregate V4/V5 metrics. Inference only; ML remains SHADOW.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import numpy as np
import torch
from transformers import AutoTokenizer

from packagegate_ml.features.export_pilot import CLI, _run_scan_tarball, investigation_to_mle_export
from packagegate_ml.features.record_v2 import (
    behaviour_only_from_structured,
    build_package_gate_ml_record_v2,
)
from packagegate_ml.features.slice_schema_v2 import (
    SliceGenConfig,
    generate_slices_for_package,
    load_tarball_sources,
)
from packagegate_ml.features.structured import align_feature_matrix
from packagegate_ml.neural import (
    BASE_MODEL_ID,
    BASE_MODEL_REVISION,
    BEHAVIOUR_LABELS_V1,
    MAX_SEQ_LENGTH,
)
from packagegate_ml.neural.datasets import load_split, load_strict_features
from packagegate_ml.neural.train_package import (
    binlab,
    mean_emb,
    package_matrix,
    set_seed,
)
from packagegate_ml.neural.train_slice_encoder import SliceEncoder
from packagegate_ml.training.train_pilot_structured import fit_predict


def score_one(
    mode: str,
    sample_id: str,
    feat_row: dict,
    emb_dir: Path,
    tr_ids: list[str],
    features_v4: dict,
    emb_v4: Path,
) -> float:
    """Score a single qualitative sample without HOLDOUT exclusion."""
    keys, xtr, ytr, _ = package_matrix(tr_ids, features_v4, emb_v4, mode)
    beh = dict(feat_row.get("behaviour_features") or {})
    emb = mean_emb(emb_dir / f"{sample_id.replace('/', '_').replace('@', '_').replace(':', '_')}.pt")
    code_flag = 1.0 if feat_row.get("code_view_available") else 0.0
    if mode == "STRUCTURED_BEHAVIOUR":
        d = beh
    elif mode == "EMBED_MEAN_ONLY":
        d = {f"e{i}": float(emb[i]) for i in range(len(emb))}
        d["codeViewAvailable"] = code_flag
    else:
        raise ValueError(mode)
    xq = np.zeros((1, len(keys)), dtype=np.float64)
    for j, k in enumerate(keys):
        xq[0, j] = float(d.get(k, 0.0))
    _, p = fit_predict("logistic_regression", xtr, ytr, xq)
    return float(p[0])

REPO = Path(__file__).resolve().parents[3]
EXP = REPO / "ml" / "experiments" / "pg-neural-exp1"
FREEZE = EXP / "freeze.json"
V4_SPLIT = REPO / "ml" / "data-manifests" / "v4" / "neural" / "split.json"
V4_MATCHED = REPO / "ml" / "data-manifests" / "v4" / "structure_matches.json"
V4_FEATURES = Path("/tmp/packagegate-ml-data-v4/exports/v4-neural/strict_features.jsonl")
MODELS = Path(os.environ.get("PACKAGEGATE_ML_MODELS", "/home/usman/packagegate-ml-models"))

QUAL_DIR = Path("/tmp/packagegate-ml-data-v5/qualitative")


def resolve_control_tarball(sample_id: str) -> Path | None:
    direct = QUAL_DIR / f"{sample_id}.canonical.tgz"
    if direct.exists():
        return direct
    for manifest in (
        Path("/tmp/packagegate-ml-data-v4/manifests/dataset_v4_full.private.json"),
        Path("/tmp/packagegate-ml-data-v3/manifests/dataset_v3_full.private.json"),
    ):
        if not manifest.exists():
            continue
        for r in json.loads(manifest.read_text())["records"]:
            if r.get("sample_id") == sample_id and r.get("artifact_path"):
                p = Path(r["artifact_path"])
                if p.exists():
                    return p
    return None


@torch.no_grad()
def encode_package(model, tokenizer, device, strict_path: Path) -> Path:
    rec = json.loads(strict_path.read_text(encoding="utf-8"))
    slices = rec.get("slices") or []
    emb_dir = MODELS / "embeddings" / "qualitative-exp1"
    emb_dir.mkdir(parents=True, exist_ok=True)
    sid = strict_path.stem.replace(".strict", "")
    # recover sample id from parent naming
    sample_id = strict_path.name.replace(".strict.json", "").replace("_", "@", 1)
    # Prefer metadata
    items = []
    for sl in slices:
        text = sl.get("sourceText") or ""
        if not text.strip():
            continue
        enc = tokenizer(
            text,
            truncation=True,
            max_length=MAX_SEQ_LENGTH,
            padding="max_length",
            return_tensors="pt",
        )
        out = model(
            enc["input_ids"].to(device),
            enc["attention_mask"].to(device),
        )
        cls = out["cls"][0].cpu()
        score = float(torch.sigmoid(out["logits"][0]).max())
        items.append((score, sl.get("sliceId") or "", cls, text[:200]))
    items.sort(key=lambda t: -t[0])
    emb = torch.stack([t[2] for t in items]) if items else torch.zeros(0, 768)
    out_path = emb_dir / f"{strict_path.stem.replace('.strict','')}.pt"
    torch.save(
        {
            "embeddings": emb,
            "slice_ids": [t[1] for t in items],
            "scores": [t[0] for t in items],
            "top_slice_previews": [
                {"sliceId": t[1], "score": t[0], "preview": t[3]} for t in items[:5]
            ],
        },
        out_path,
    )
    return out_path, items


def scan_and_strict(sample_id: str, art: Path, out_dir: Path) -> dict:
    safe = sample_id.replace("/", "_").replace("@", "_").replace(":", "_")
    tmp = out_dir / f".tmp_{safe}.json"
    result = _run_scan_tarball(art, tmp)
    if result["status"] != "SCAN_SUCCESS":
        return {"sample_id": sample_id, "error": result}
    v1 = result.get("mlExport") or investigation_to_mle_export(result["investigation"])
    tmp.unlink(missing_ok=True)
    v1 = dict(v1)
    v1.pop("finalPolicy", None)
    v1.pop("threatIntelligence", None)
    pkg_name, version = sample_id.rsplit("@", 1) if "@" in sample_id else (sample_id, None)
    # scoped packages: @scope/name@version
    if sample_id.startswith("@"):
        pkg_name, version = sample_id.rsplit("@", 1)
    sources = load_tarball_sources(art)
    gen = generate_slices_for_package(
        findings=list(v1.get("findings") or []),
        chains=list(v1.get("chains") or []),
        lifecycle=list(v1.get("lifecycle") or []),
        sources=sources,
        package_name=pkg_name,
        version=version,
        config=SliceGenConfig(max_slices=32, context_lines=12, max_per_category=6),
    )
    v1["slices"] = [
        {
            "sliceId": s.slice_id,
            "filePath": s.file_path,
            "startLine": s.start_line,
            "endLine": s.end_line,
            "sourceText": s.source_text,
            "lifecycleReachable": s.lifecycle_reachable,
            "behaviourLabels": s.behaviour_labels,
            "priority": s.priority,
        }
        for s in gen.slices
    ]
    strict = build_package_gate_ml_record_v2(
        v1_or_export=v1,
        package_name=None,
        version=None,
        package_json=None,
        view="STRICT_SECURITY_VIEW",
    )
    strict["slices"] = [s.to_model_dict() for s in gen.slices]
    strict["codeViewAvailable"] = gen.code_view_available
    path = out_dir / f"{safe}.strict.json"
    path.write_text(json.dumps(strict), encoding="utf-8")
    return {
        "sample_id": sample_id,
        "path": str(path),
        "deterministicScore": (v1.get("behaviouralRisk") or {}).get("score"),
        "deterministicRecommendation": (v1.get("behaviouralRisk") or {}).get(
            "recommendation"
        ),
        "n_slices": gen.selected_slices,
        "behaviour_features": behaviour_only_from_structured(
            v1.get("structuredFeatures") or {}
        ),
        "code_view_available": gen.code_view_available,
        "label": "UNKNOWN",
    }


def main() -> None:
    if not CLI.exists():
        raise SystemExit("CLI not built")
    set_seed(42)
    freeze = json.loads(FREEZE.read_text())
    thr_s = float(freeze["structuredBaseline"]["recallAt5pctFpr"]["threshold"])
    thr_e = float(freeze["selectedPackageModel"]["recallAt5pctFpr"]["threshold"])
    ckpt_path = Path(freeze["sliceCheckpoint"])
    emb_v4 = Path(freeze["embeddingDir"])

    out_dir = EXP / "qualitative"
    out_dir.mkdir(parents=True, exist_ok=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    # Wait — if seed training holds GPU, fall back to CPU for qualitative
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    model = SliceEncoder(BASE_MODEL_ID, BASE_MODEL_REVISION, len(BEHAVIOUR_LABELS_V1))
    model.load_state_dict(ckpt["model_state"], strict=False)
    model.to(device)
    model.eval()
    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL_ID, revision=BASE_MODEL_REVISION, trust_remote_code=False
    )

    # Fit heads on V4 train
    split = json.loads(V4_SPLIT.read_text())
    matched = set(json.loads(V4_MATCHED.read_text())["matchedSampleIds"])
    tr = [i for i in split["train"] if i in matched]
    features_v4 = load_strict_features(V4_FEATURES)

    rows = []
    for sample_id in ("02-echo@0.0.7", "lodash@4.17.21", "express@4.21.2", "debug@4.3.4", "JSONStream@1.3.5"):
        art = resolve_control_tarball(sample_id)
        if art is None or not art.exists():
            rows.append({"sample_id": sample_id, "error": "artifact_missing"})
            continue
        scanned = scan_and_strict(sample_id, art, out_dir)
        if "error" in scanned:
            rows.append(scanned)
            continue
        emb_path, items = encode_package(
            model, tokenizer, device, Path(scanned["path"])
        )
        feat_row = {
            "label": "EXPECTED_BENIGN" if sample_id != "02-echo@0.0.7" else "MALICIOUS",
            "behaviour_features": scanned["behaviour_features"],
            "code_view_available": scanned["code_view_available"],
        }
        safe = sample_id.replace("/", "_").replace("@", "_").replace(":", "_")
        emb_dir = emb_path.parent
        target = emb_dir / f"{safe}.pt"
        if emb_path != target:
            target.write_bytes(emb_path.read_bytes())

        p_s = score_one(
            "STRUCTURED_BEHAVIOUR", sample_id, feat_row, emb_dir, tr, features_v4, emb_v4
        )
        p_e = score_one(
            "EMBED_MEAN_ONLY", sample_id, feat_row, emb_dir, tr, features_v4, emb_v4
        )

        rows.append(
            {
                "sample_id": sample_id,
                "deterministicScore": scanned["deterministicScore"],
                "deterministicRecommendation": scanned["deterministicRecommendation"],
                "structuredProba": p_s,
                "embedMeanProba": p_e,
                "structuredDecision": bool(p_s >= thr_s),
                "embedDecision": bool(p_e >= thr_e),
                "thresholdStructured": thr_s,
                "thresholdEmbed": thr_e,
                "n_slices": scanned["n_slices"],
                "topSlices": [
                    {"sliceId": t[1], "score": t[0], "preview": t[3]} for t in items[:5]
                ],
                "policy": "SHADOW",
            }
        )
        print(json.dumps(rows[-1], indent=2))

    (out_dir / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(json.dumps({"qualitative": rows}, indent=2))


if __name__ == "__main__":
    main()
