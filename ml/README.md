# PackageGate ML

Hybrid **structured features + optional code encoders** for PackageGate.

## Current status (Dataset V2)

- Dataset V1 frozen (`data-manifests/v1/`) — neural gate failed on name shortcuts
- Dataset V2 built (`data-manifests/v2/`) — deconfounding benchmarks + shortcut
  decomposition; **neural gate still FAIL** (structure/source confounds remain)
- Do **not** install PyTorch / download GraphCodeBERT until the gate passes

See `../docs/ML_EVALUATION.md`, `../docs/ML_DATASET_V1.md`, `../docs/ML_DATASET_V2.md`.


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

## Dataset V2 commands

```bash
export PACKAGEGATE_ML_DATA_ROOT=/tmp/packagegate-ml-data-v2
uv run python -m packagegate_ml.datasets.build_dataset_v2
# or rebuild from downloaded artefacts:
uv run python -m packagegate_ml.datasets.rebuild_dataset_v2
uv run python -m packagegate_ml.features.export_v2
uv run python -m packagegate_ml.training.train_v2_structured
```

## Model candidates (not downloaded)

| Candidate | HF ID | Notes |
| --- | --- | --- |
| GraphCodeBERT | `microsoft/graphcodebert-base` | Blocked until neural gate passes |
| CodeT5+ embedding | `Salesforce/codet5p-110m-embedding` | Blocked until neural gate passes |

Do **not** start with multi-billion-parameter coder LLMs.
