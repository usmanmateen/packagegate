# PackageGate ML

Hybrid **structured features + optional code encoders** for PackageGate.

Deterministic PackageGate answers: *what behaviour can we prove?*  
ML answers: *does the package composition resemble malicious supply-chain patterns?*  
Threat intel answers: *is this exact artifact independently known bad?*

These lanes stay separate. ML **must not** invent URLs, dataflow edges, or
deterministic findings. ML **must not** independently BLOCK in v1
(ALLOW→REVIEW escalation only, when calibrated).

## Safety

- Never execute investigated packages.
- Never commit malware or model weights.
- External malware roots only (e.g. `/tmp/packagegate-ml-malware/`).
- Default product path: `PACKAGEGATE_ML=disabled`.

## Setup

```bash
cd ml
uv sync --extra dev
# Optional neural stack (large download):
# uv sync --extra dev --extra torch
```

## Hardware snapshot

```bash
uv run python -m packagegate_ml.utils.system_info
```

## Structured baseline (Experiment 0)

```bash
# Export fixture ML records via PackageGate CLI, then:
uv run python -m packagegate_ml.datasets.build_smoke_manifest
uv run python -m packagegate_ml.features.build_from_exports
uv run python -m packagegate_ml.training.train_structured
uv run python -m packagegate_ml.evaluation.evaluate_structured
```

## Model candidates (verified IDs — do not download until ready)

| Candidate | HF ID | Notes |
| --- | --- | --- |
| GraphCodeBERT | `microsoft/graphcodebert-base` | RoBERTa/code; HF card lacks explicit licence metadata — review before production use |
| CodeT5+ embedding | `Salesforce/codet5p-110m-embedding` | Smaller embedding encoder; permissive training subset |
| CodeT5+ 220M | `Salesforce/codet5p-220m` | Encoder–decoder; prefer embedding/bimodal for classification heads |

Do **not** start with multi-billion-parameter coder LLMs.

## Layout

See `packagegate_ml/` for datasets, features, slicing, training, inference,
calibration, and evaluation modules.
