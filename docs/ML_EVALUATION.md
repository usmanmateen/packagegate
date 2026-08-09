# PackageGate — ML Evaluation

**Status:** Dataset V4 complete — neural gate **PASS**  
**Last updated:** 2026-08-09  

See `ML_DATASET_V1.md` … `ML_DATASET_V4.md`.

## Question

Can ML improve PackageGate under honest holdouts **after** the model is forbidden
from seeing package identity, and after security-change (PG-Delta) is evaluated
with meaningful support?

## Progress across datasets

| Diagnostic | V1 | V2 | V3 matched | V4 |
| --- | ---: | ---: | ---: | ---: |
| Raw name | 0.97‡ | 0.83 | 0.87 | 0.89 (diagnostic) |
| Artifact structure | — | 0.94† | **0.43** | **0.42** |
| Metadata / strict-input nuisance | ~0.87 | 0.97 | 0.82 | **0.33** strict-input |
| Random ID | chance | 0.29 | 0.21 | 0.29 / 0.21 |
| Shuffled labels | 0.32 | 0.35 | 0.50 | 0.59 |
| Behaviour only | 0.95‡ | 0.91 | 0.85 | **0.84** |
| Delta behaviour | — | — | 1.0 tiny‡ | **0.98** CV |
| Delta nuisance | — | — | — | 0.89 CV |
| Neural gate | FAIL | FAIL | **FAIL** | **PASS** |

†V2 structure included lifecycle. ‡Confounded / tiny-n.

## V4 gate (pre-registered, then frozen)

**PASS.** Key observations:

- STRICT_INPUT_NUISANCE ≈ prevalence (0.33 vs 0.36)
- BEHAVIOUR − STRICT_INPUT_NUISANCE ≈ **+0.51**
- VERSION_ONLY matched 0.50 ≤ 0.75
- PG-Delta test n=65 (was 21); family split 60/20/20
- DELTA_BEHAVIOUR − DELTA_NUISANCE ≈ **+0.09** (grouped CV)
- Strict model-input identity audit: 0 leak flags / 980

Raw name and SOURCE_ONLY remain high as **dataset bias diagnostics** — not gate conditions (philosophy change in V4).

## Policy

Unchanged: ML optional/shadow; never independent BLOCK; no auto weight download.  
**Neural training is now scientifically justified pending human review of the frozen V4 gate.**  
Do not install PyTorch until that review; then fine-tune one encoder on STRICT_SECURITY_VIEW only.
