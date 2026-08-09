# PackageGate — ML Evaluation

**Status:** scaffolding + structured smoke baseline (Experiment 0)  
**Last updated:** 2026-08-09  

## Scientific question

Can a fine-tuned code model learn malicious composition that hand-written rules
miss, while PackageGate retains explainable deterministic evidence?

This document records **honest** progress. Incomplete training is not success.

## Baseline (product, no ML)

| Sample | Behavioural | Final |
| --- | --- | --- |
| lodash@4.17.21 | 3 ALLOW | ALLOW |
| express@4.21.2 | 2 ALLOW | ALLOW |
| debug@4.3.4 | 0 ALLOW | ALLOW |
| JSONStream@1.3.5 | 4 ALLOW | ALLOW |
| inert-install-curl-bash | ~49 REVIEW | REVIEW |
| 02-echo@0.0.7 (holdout) | 58 REVIEW | REVIEW |

## Hardware snapshot (dev machine)

- GPU: NVIDIA GeForce RTX 5060 Ti (~16 GiB)
- Driver reports CUDA 13.x capability; PyTorch CUDA must be verified via
  `python -m packagegate_ml.utils.system_info` after optional torch install
- RAM: ~16 GiB
- Python ML env: 3.12 via `uv` (system Python 3.14 not used for torch)

## Dataset (smoke)

| Item | Value |
| --- | --- |
| Sources | Inert fixtures + placeholders; Datadog label provenance recorded for 02-echo holdout |
| Malware in git | **None** |
| Split | Grouped package/family |
| Holdouts | `02-echo@0.0.7`, lodash, express, debug, JSONStream |
| Auto-download malware | **Disabled** |

## Model candidates (verified IDs — not downloaded in this milestone)

| Candidate | ID | Status |
| --- | --- | --- |
| GraphCodeBERT | `microsoft/graphcodebert-base` | Config only; licence metadata sparse on HF card — review before use |
| CodeT5+ embedding | `Salesforce/codet5p-110m-embedding` | Config only |
| CodeT5+ 220M | `Salesforce/codet5p-220m` | Config only |

## Experiments completed

| Experiment | Result |
| --- | --- |
| 0 Structured baseline | Runnable on fixture exports; metrics **not** statistically meaningful |
| 1 GraphCodeBERT fine-tune | **Not started** — gated on dataset quality |
| 2 CodeT5+ fine-tune | **Not started** |
| Package MIL | **Not started** |

## Product integration

- `MlAssessment` lane separate from behavioural risk
- `PACKAGEGATE_ML=disabled` by default
- `--ml` enables local Python worker
- Policy: ML may escalate **ALLOW → REVIEW** only; never independent **BLOCK**

## Does ML help yet?

**Not yet measurable.** The infrastructure (export, manifests, splits, leakage
tests, structured trainer, inference adapter, policy wiring) is in place. A
credible answer requires an external curated corpus with hard negatives,
deduplication, and untouched family/temporal holdouts — including frozen
evaluation of `02-echo@0.0.7` after training excludes it.

## Next steps

1. Populate external malware + diverse benign hard negatives
2. Run PackageGate static export over the corpus
3. Train structured baseline at pilot scale
4. Only then fine-tune GraphCodeBERT / CodeT5+ under identical splits
5. Package MIL + calibration + recall@FPR operating points
