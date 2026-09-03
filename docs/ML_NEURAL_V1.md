# PackageGate — Neural Experiment V1

**Status:** first neural experiment complete (shadow)  
**Gate prerequisite:** Dataset V4 neural gate **PASS** (frozen)  
**Data freeze:** `ml/data-manifests/v4/neural/` + SliceSchemaV2 export  

## Slice coverage (required before PyTorch)

| | Before | After SliceSchemaV2 |
| --- | ---: | ---: |
| Packages with ≥1 slice (all) | 0% | **99.4%** |
| Matched ≥1 / ≥2 | 0% / 0% | **99.0% / 92.1%** |
| Total slices (980 pkgs) | 0 | **11034** |
| Leak flags | — | **0** |

Root cause of empty slices: Python `investigation_to_mle_export` hard-coded
`slices: []` despite findings having `location.filePath`.

## Environment

| | |
| --- | --- |
| GPU | NVIDIA GeForce RTX 5060 Ti (sm_120), ~16 GB |
| Driver | 596.49 (CUDA 13.2 reported by nvidia-smi) |
| PyTorch | **2.11.0+cu128** (`torch.cuda.is_available()=True`) |
| Transformers | 5.14.1 |
| Install | `uv pip install torch --index-url https://download.pytorch.org/whl/cu128` (ml venv only) |
| Weights cache | `${PACKAGEGATE_ML_MODELS}/` (not git; avoid `/tmp` tmpfs) |

## Encoder — PG-SLICE-V1

| | |
| --- | --- |
| Base | `microsoft/graphcodebert-base` @ `2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d` |
| Max length | 512 (~16% truncation) |
| Train/val/test slices | 7508 / 2085 / 1441 |
| Val micro-F1 | 0.868 |
| Test micro-F1 / macro-F1 | **0.853 / 0.788** |
| Test micro/macro PR-AUC | 0.907 / 0.851 |
| Train time | ~9.4 min |

## Package models (matched test n=58)

| Model | PR-AUC | Recall@~5% FPR |
| --- | ---: | ---: |
| Structured behaviour logistic | 0.843 | 0.667 |
| **Embedding mean only** | **0.897** | **0.714** |
| Embedding + structured | 0.878 | 0.714 |
| MIL code only | 0.852 | 0.667 |
| MIL + structured | 0.775 | 0.571 |

## Verdict

**YES** — mean-pooled GraphCodeBERT slice embeddings improve PR-AUC and
recall@~5%FPR over the behaviour-only structured baseline on the frozen matched
test. Attention MIL did **not** beat the structured baseline in this run.

Policy: **shadow only**. No ML-only BLOCK. No detector rule changes.

## Holdouts

| Package | Result |
| --- | --- |
| 02-echo@0.0.7 | Artifact unavailable (npm 404 / missing archive); never in train/val |
| lodash / express / debug / JSONStream | Embed-mean proba ≪ 0.01; deterministic ALLOW |

## Next (not this milestone)

- Neural PG-Delta
- CodeT5+ comparison
- Richer GraphCodeBERT data-flow inputs
