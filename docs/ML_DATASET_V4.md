# PackageGate — ML Dataset V4

**Status:** frozen — neural gate **PASS**  
**Manifests:** `ml/data-manifests/v4/`  
**External data:** `/tmp/packagegate-ml-data-v4`  
**Structured run:** `ml/runs/20260809T185950Z-structured-v4/`  
**Preserves:** V1–V3 unchanged  

**Torch / GraphCodeBERT / CodeT5+:** not installed. Gate result frozen before neural weights.

## Why earlier datasets failed

| Dataset | Root cause |
| --- | --- |
| V1 | “Hash” features were sample-id morphology (~0.97 PR-AUC) |
| V2 | Source one-hot = 1.0; artifact structure dominated by `hasPreinstall` |
| V3 | Structure confound fixed (~0.43 matched); **name/version morphology** still gated neural work; PG-Delta test n≈21 |

V3 correctly failed its pre-registered gate. V4 does **not** collect another random batch. It redefines the **actual model input** so package identity cannot be used as a shortcut, and strengthens PG-Delta evaluation.

## Gating philosophy change

Raw `PACKAGE_NAME_LEXICAL` may remain high — malicious npm campaigns often have distinctive names. That is a **dataset-bias diagnostic**, not a permanent blocker.

V4’s neural gate asks:

> Can the **STRICT_SECURITY_VIEW** still recover identity/source bias, and does **behaviour** beat the nuisance that actually reaches the model?

## PackageGateMlRecordV2 — STRICT_SECURITY_VIEW

Primary model input **must not** contain: package name, version, scope, dataset source, label, family group, sample ID, artifact path, author, repository, homepage, description, keywords, attack category, threat intel, final policy, `nameHash`.

These may remain in **training metadata** for splits/evaluation only.

Allowed model fields:

- `structuredBehaviourFeatures` (findings, chains, lifecycle, completeness)
- `securityManifest` (lifecycle scripts / main / bin / engines; identity stripped)
- identity-masked `slices` (comments removed; external imports → `<EXTERNAL_MODULE>`)
- normalised paths (preserve `scripts/`, `lib/`, `bin/`, …)
- `NATURAL_CODE_VIEW` exists as an ablation (bounded code; still no label/source injection)

Implementation: `ml/packagegate_ml/features/record_v2.py`, `identity_mask.py`.

### Model-input audit (STRICT)

| Field | Present in primary input? |
| --- | --- |
| package name | **NO** |
| version | **NO** |
| dataset source | **NO** |
| label / label source | **NO** |
| author / repository | **NO** |
| family ID | **NO** |
| What remains | Behaviour + completeness + masked code/manifest security view |

Export audit on 980 records: **0** identity-leak flags.

## Identity-masking methodology

1. **Paths:** strip `package/` and self `name-version/` roots; keep security layout.
2. **Manifest:** drop name/version/description/author/repo/keywords; keep lifecycle command text.
3. **Imports:** preserve Node built-ins + local `./` modules; external → `<EXTERNAL_MODULE>` (import sites only — not shell/URLs).
4. **Self-identity:** narrow `name:` / `version:` assignment masking only (no global rename; protects packages named e.g. `request`).
5. **Comments:** stripped in STRICT view; strings/URLs/shell preserved.

## PG-Package benchmark (matched)

Seeded from V3 corpus (no blind resampling):

| Count | Value |
| --- | ---: |
| Malicious-intent available | 140 |
| Compromised available | 138 |
| Expected-benign available | 714 |
| Exported | 980 |
| Failures | 12 |
| Matched samples (V4) | **305** |
| Matched prevalence (test) | **~0.36** |

Matching adds **version-shape buckets** (major/minor/patch buckets, prerelease, unusual-large, …) plus V3 name/structure/lifecycle balance. Distance threshold **4.5** (expanded feature space vs V3’s 3.5).

### Matched diagnostics (logistic PR-AUC)

| Mode | PR-AUC |
| --- | ---: |
| PACKAGE_NAME_LEXICAL (raw diagnostic) | 0.89 |
| VERSION_ONLY (raw) | 0.50 |
| GENERIC_METADATA (raw) | 0.87 |
| ARTIFACT_STRUCTURE | 0.42 |
| SOURCE_ONLY (raw) | 1.00 |
| OPAQUE_RANDOM_ID | 0.29 |
| **STRICT_INPUT_NUISANCE_ONLY** | **0.33** |
| **BEHAVIOUR_ONLY** | **0.84** |
| Behaviour − strict nuisance | **+0.51** |
| Shuffled labels (behaviour) | 0.59 |

Source-proxy on strict nuisance only: PR-AUC **0.69** (prevalence ~0.29) — residual size proxies exist but are weak vs behaviour.

## Why V3 PG-Delta test n was ~21

Pairs inherited the **package** train/val/test split. Only pairs with **both** endpoints in the same partition counted. Co-location:

| Clean ∩ Compromised split | Pairs |
| --- | ---: |
| train ∩ train | 186 |
| validation ∩ validation | 73 |
| **test ∩ test** | **21** |

V4 uses a **pair-family grouped** split (~60/20/20 of families): train 162 / val 53 / **test 65**.

## PG-Delta (co-primary)

| | Value |
| --- | ---: |
| Positive pairs | 160 |
| Negative pairs | 120 |
| Test pairs | 65 |
| Grouped CV | 5 folds |

| Mode | Metric | Value |
| --- | --- | ---: |
| DELTA_BEHAVIOUR | Grouped-CV mean PR-AUC | **0.982** ± 0.033 |
| DELTA_NUISANCE | Grouped-CV mean PR-AUC | **0.891** ± 0.046 |
| Margin | behaviour − nuisance | **+0.091** |

Delta nuisance uses version-step / size / file-count / version-length deltas only. Analysis **coverage** change is treated as security completeness (behaviour), not release structure — aligning with the pre-registered feature families.

## Headline history

| Diagnostic | V1 | V2 | V3 matched | V4 matched / delta |
| --- | ---: | ---: | ---: | ---: |
| Raw name | 0.97‡ | 0.83 | 0.87 | 0.89 (diagnostic only) |
| Artifact structure | — | 0.94† | 0.43 | 0.42 |
| Metadata | ~0.87 | 0.97 | 0.82 | 0.87 raw / **0.33 strict-input** |
| Behaviour | 0.95‡ | 0.91 | 0.85 | **0.84** |
| Delta nuisance | — | — | — | **0.89** CV |
| Delta behaviour | — | — | 1.0 tiny (n≈21)‡ | **0.98** CV (n_test=65) |
| Neural gate | FAIL | FAIL | FAIL | **PASS** |

†Lifecycle in structure. ‡Confounded or tiny-n — not semantic proof.

## Pre-registered gate → result

All conditions evaluated against `ml/data-manifests/v4/neural_gate_definition.json` (frozen before metrics).

**NEURAL GATE = PASS** (`neural_gate_result.json`).

Remaining cautions (not gate failures):

- Raw name / SOURCE_ONLY still show corpus composition bias.
- Delta nuisance remains strong (~0.89); security change wins, but release-structure still predicts compromise introductions — monitor in V5 if needed.
- Matched test n=58 is modest; bootstrap CIs live in the run metadata.

## 02-echo / controls

- `02-echo@0.0.7` — **QUALITATIVE_HOLDOUT** (not train/val).
- Controls: lodash@4.17.21, express@4.21.2, debug@4.3.4, JSONStream@1.3.5 — qualitative only.

## Policy

No detector/rule/weight/threshold changes for ML metrics.  
No PyTorch until this gate freeze is reviewed.  
If proceeding: install torch once, fine-tune **one** encoder on STRICT_SECURITY_VIEW only.

## Limitations

- Slices in V3 exports are often empty — strict code view coverage is incomplete until a slice-rich re-export.
- Hard-negative / FP feedback from V3 not exhaustively re-reviewed for every benign.
- Natural-code ablation not scored in the primary gate run.
