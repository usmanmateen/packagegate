# PackageGate — ML Evaluation

**Status:** Neural Experiment V1 complete (shadow) — Dataset V4 gate **PASS**  
**Last updated:** 2026-08-09  

See `ML_DATASET_V1.md` … `ML_DATASET_V4.md`, `ML_NEURAL_V1.md`.

## Question

Can learning from identity-masked code slices add information beyond PackageGate
behavioural features on the frozen V4 matched benchmark?

## Progress

| Stage | Gate / result |
| --- | --- |
| Dataset V1–V3 | FAIL (identity/structure confounds) |
| Dataset V4 | **PASS** (strict input; PG-Delta robust) |
| SliceSchemaV2 coverage | **PASS** (matched ge1 99%, ge2 92%, 0 leaks) |
| PG-SLICE-V1 (GraphCodeBERT) | Trained; test micro-F1 ≈ 0.85 |
| Package embed-mean vs structured | **YES** — PR-AUC 0.897 vs 0.843 |

## Policy

ML remains **optional/shadow**. Deterministic policy authoritative.  
No ML-only BLOCK. No auto weight download into production CLI for this experiment.
