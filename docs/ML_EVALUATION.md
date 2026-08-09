# PackageGate — ML Evaluation

**Status:** Dataset V3 complete — neural gate **FAIL**  
**Last updated:** 2026-08-09  

See `ML_DATASET_V1.md`, `ML_DATASET_V2.md`, `ML_DATASET_V3.md`.

## Question

Can ML improve PackageGate under honest holdouts **after** controlling source,
identity, and structure confounds?

## Progress across datasets

| Diagnostic | V1 | V2 | V3 mixed | V3 matched |
| --- | ---: | ---: | ---: | ---: |
| Name lexical PR-AUC | 0.97 | 0.83 | 0.83 | 0.87 |
| Artifact structure | — | 0.94† | **0.68** | **0.43** |
| Generic metadata | ~0.87 | 0.97 | 0.81 | 0.82 |
| Random ID | chance | 0.29 | 0.21 | — |
| Shuffled labels | 0.32 | 0.35 | 0.50 | — |
| Behaviour only | 0.95‡ | 0.91 | 0.89 | 0.85 |
| Neural gate | FAIL | FAIL | — | **FAIL** |

†V2 structure included lifecycle hooks (`hasPreinstall`).  
‡V1 confounded — not semantic evidence.

## V2 → V3 key audit finding

GENERIC_METADATA / ARTIFACT_STRUCTURE shortcuts were driven primarily by
**`hasPreinstall`** (malicious ~66% vs benign ~0.5%), plus name digits / scope
and unusual version numbers. Lifecycle presence is security-relevant — V3 moves
it into **BEHAVIOUR**, leaving structure nuisance as size/file/coverage only.

## V3 gate (pre-registered)

FAIL reasons:

- name lexical on matched **0.87 > 0.80**
- generic metadata on matched **0.82 > 0.80**
- behaviour − metadata on matched **0.03 < 0.05**

PASS: leakage, opaque ID, shuffled, canonicalisation, matched n=270,
structure nuisance on matched (≈ prevalence), PG-Delta pair counts.

SOURCE_ONLY remains 1.0 by construction — **not a gate condition**.

## PG-Delta

160 positive + 120 negative pairs with features. Test n=21 under family splits —
perfect scores are **not** interpretable. Same-package behaviour classification
looks strong on small n (treat cautiously).

## Policy

Unchanged: ML optional/shadow; never independent BLOCK; no auto weight download.
**Neural training is not scientifically justified yet.**
