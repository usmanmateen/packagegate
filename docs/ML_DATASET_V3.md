# PackageGate — ML Dataset V3

**Status:** COMPLETE — neural gate **FAIL** (improved, not cleared)  
**Manifests:** `ml/data-manifests/v3/`  
**External:** `/tmp/packagegate-ml-data-v3`  
**Preserves:** V1 + V2 frozen manifests

## Why V3

V2 failed because structure/metadata shortcuts remained stronger than behaviour.
V3 audit showed V2 “ARTIFACT_STRUCTURE” was dominated by **`hasPreinstall`**
(security-relevant), not pure packaging path.

## Counts

| Item | Count |
| --- | ---: |
| Available / exported | 992 / 980 |
| Malicious-intent / compromised_lib | 140 / 138 |
| Expected-benign | 714 |
| Positive compromise pairs | 160 |
| Negative version pairs | 120 |
| Structure-matched samples | 270 |
| Train / Val / Test / Holdout | 665 / 196 / 131 / 51 |
| Export failures | 12 (5/1/6 by label) |
| Cross-label near-dup groups | 28 — **all same-package** (expected) |
| Path equivalence (8 benign) | **8/8 zero behaviour delta** |

## Canonical processing

Both Datadog-rebuilt and npm-registry tarballs → safe extract → deterministic
`package/*.tgz` → scan-tarball. Product acquisition unchanged.

## Pre-registered gate vs observed

| Condition | Threshold | Observed | |
| --- | --- | --- | --- |
| Leakage / 02-echo / canonical | PASS | PASS | ✓ |
| Opaque random | ≤ prev+0.25 | 0.21 | ✓ |
| Shuffled | ≤ 0.75 | 0.50 | ✓ |
| Matched n | ≥ 80 | 270 | ✓ |
| PG-Delta pos/neg | ≥60 / ≥40 | 160 / 120 | ✓ |
| Structure nuisance (matched) | ≤ prev+0.20 | **0.43** (prev 0.40) | ✓ |
| Name lexical (matched) | ≤ 0.80 | **0.87** | ✗ |
| Generic metadata (matched) | ≤ 0.80 | **0.82** | ✗ |
| Behaviour − nuisance (matched) | ≥ 0.05 | 0.85−0.82=0.03 | ✗ |

**SOURCE_ONLY = 1.0** is documented composition bias — **not a gate condition**.

**Neural gate: FAIL.** No PyTorch / no pretrained models.

## Headline diagnostics

| Diagnostic | V1 | V2 | V3 mixed | V3 matched |
| --- | ---: | ---: | ---: | ---: |
| Name lexical | 0.97 | 0.83 | 0.83 | 0.87 |
| Artifact structure* | — | 0.94† | **0.68** | **0.43** |
| Generic metadata | ~0.87 | 0.97 | 0.81 | 0.82 |
| Random ID | chance | 0.29 | 0.21 | 0.37 |
| Shuffled | 0.32 | 0.35 | 0.50 | — |
| Behaviour only | 0.95‡ | 0.91 | 0.89 | 0.85 |

\*V3 structure excludes lifecycle hooks.  
†V2 structure included `hasPreinstall` (confound).  
‡V1 confounded.

## PG-Delta

Usable pairs with features: 160 positive + 120 negative.  
Split counts: train 186 / val 73 / **test 21** (family-grouped).  
Logistic test PR-AUC 1.0 on n=21 — **not meaningful**; infrastructure works.
Example positive: `@accordproject/concerto-linter-default-ruleset@3.24.0→3.24.1`
adds preinstall + process/remote/shell/opaque chains.

## Remaining confounds

1. Name morphology still separates matched set (scoped / digit tokens)
2. Version morphology in generic metadata (`version_major` / `version_patch`)
3. `hasPreinstall` remains the top **behaviour** and source-proxy signal (legitimate malware pattern, but also Datadog-heavy)
4. PG-Delta test slice still small under family splits

## Next (V4 candidates)

- Name-masked primary evaluation
- Version-morphology ablation / matching on version buckets
- More held-out compromise families for PG-Delta test power
- Optional second malicious source only if same canonical path
