# Model card — PG-PACKAGE (embedding mean + structured)

## Intended use

**Shadow-mode** package malignancy score on the frozen V4 matched benchmark,
using PG-SLICE-V1 CLS embeddings (mean pool) and/or structured behaviour
features.

**Not** proof that a package is safe. Deterministic PackageGate policy remains
authoritative. ML must not independently BLOCK.

## Primary package result (matched test, n=58, prevalence≈0.36)

| Model | PR-AUC | Recall @ ~5% FPR |
| --- | ---: | ---: |
| Structured behaviour logistic | 0.843 | 0.667 |
| Embedding mean only | **0.897** | **0.714** |
| Embedding mean + structured | 0.878 | 0.714 |
| MIL code only | 0.852 | 0.667 |
| MIL + structured | 0.775 | 0.571 |

Selected representation for qualitative scoring: **embedding mean** (best
PR-AUC on frozen test after validation-only training).

## Calibration

Reported Brier for embed-mean ≈ 0.126 (raw). Operating thresholds for F1 were
unstable on this small n when forcing ≤5% FPR — prefer PR-AUC / recall@FPR.

## Holdouts / controls

- `02-echo@0.0.7`: artifact unavailable (npm 404 / missing local archive)
- Benign controls scored low under embed-mean (lodash/express/debug/JSONStream ≪ 0.01)

## Limitations

- Matched test n=58 — intervals wide
- MIL attention ranks slices; **not** causal explanations
- Zero-slice packages use structured path + `codeViewAvailable=false`
