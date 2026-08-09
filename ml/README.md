# PackageGate ML

Hybrid **structured features + optional code encoders** for PackageGate.

## Current status (Dataset V1 pilot)

- External pilot corpus acquired under `/tmp/packagegate-ml-data`
- Family-grouped frozen splits in `data-manifests/v1/`
- Structured logistic + tree baselines trained
- **Neural training gate: FAIL** (package-name shortcut bias)

See `../docs/ML_EVALUATION.md`.

## Safety

- Never execute investigated packages.
- Never commit malware or model weights.
- External data root only (`PACKAGEGATE_ML_DATA_ROOT`, default `/tmp/packagegate-ml-data`).
- Default product path: `PACKAGEGATE_ML=disabled`.

## Setup

```bash
cd ml
uv sync --extra dev
uv run python -m packagegate_ml.utils.system_info
```

## Dataset V1 commands

```bash
# Acquire (downloads into external root; never into git):
uv run python -m packagegate_ml.datasets.build_pilot_dataset

# Or rebuild manifests from already-downloaded artefacts:
uv run python -m packagegate_ml.datasets.rebuild_pilot_manifests

# Leakage audit:
uv run python -m packagegate_ml.datasets.audit_splits \
  --records /tmp/packagegate-ml-data/manifests/dataset_v1_full.json \
  --split /tmp/packagegate-ml-data/manifests/dataset_v1_split.json

# Export PackageGate features (requires built CLI):
uv run python -m packagegate_ml.features.export_pilot

# Structured baselines:
uv run python -m packagegate_ml.training.train_pilot_structured
```

## Model candidates (not downloaded)

| Candidate | HF ID | Notes |
| --- | --- | --- |
| GraphCodeBERT | `microsoft/graphcodebert-base` | Blocked until neural gate passes |
| CodeT5+ embedding | `Salesforce/codet5p-110m-embedding` | Blocked until neural gate passes |

Do **not** start with multi-billion-parameter coder LLMs.
