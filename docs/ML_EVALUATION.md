# PackageGate — ML Evaluation

**Status:** Dataset V2 deconfounding complete — neural gate **FAIL**  
**Last updated:** 2026-08-09  

See also: `ML_DATASET_V1.md`, `ML_DATASET_V2.md`.

## Scientific question

Can learned models improve PackageGate over the deterministic engine under
honest package-family holdout conditions?

## A. Name-baseline audit (Dataset V1 “~0.97”)

The V1 run key `shortcut_name_hash` was **misnamed**.

It was **PACKAGE_NAME_LEXICAL / sample_id morphology**, not a cryptographic hash:

| Feature | Definition |
| --- | --- |
| `name_len` | `len(sample_id.split("@")[0])` (broken on scoped IDs) |
| `version_len` | `len(sample_id.split("@")[-1])` |
| `at_count` | `sample_id.count("@")` |
| `digit_count` | digits in full `sample_id` |

**Verdict:** real **corpus identity bias** (Datadog scoped / digit-heavy names vs
established benign controls), **not** opaque-ID leakage.

Regression tests: `ml/tests/test_name_shortcut_audit.py`  
Opaque random-ID baselines stay near prevalence; lexical morphology separates.

## Dataset V1 (frozen historical failure)

| Item | Value |
| --- | ---: |
| Malicious / expected-benign available | 150 / 227 |
| Feature rows | 373 |
| Lexical name shortcut PR-AUC | **~0.97** |
| Neural gate | **FAIL** |

Do not overwrite `ml/data-manifests/v1/`.

## Dataset V2

External root: `/tmp/packagegate-ml-data-v2`

| Item | Count |
| --- | ---: |
| Total metadata / available | 947 / 902 |
| Malicious-intent available | 140 |
| Compromised_lib available | 140 |
| Expected-benign available | 622 |
| Compromised-version controls (adjacent) | 100 |
| Compromise pairs | 100 |
| Morphology matches (malicious-intent) | 73 |
| Near-dup groups | 75 |
| Cross-label near-dup groups | 2 (`@antv/g*`) |
| Train / Val / Test / Holdout | 603 / 174 / 125 / 45 |
| Feature-exported / failures | 892 / 10 |
| Leakage audit | **PASS** |
| 02-echo | HOLDOUT ✓ |

Export failures: mostly `LIMIT_EXCEEDED` (large native artefacts); not strongly
label-skewed (5 MALICIOUS / 1 COMPROMISED / 4 EXPECTED_BENIGN).

### Pre-registered V2 neural gate

| Condition | Threshold | Observed | Result |
| --- | --- | --- | --- |
| Leakage audit | PASS | PASS | ✓ |
| Opaque random-ID PR-AUC | ≤ prev+0.25 | 0.29 ≈ 0.31 | ✓ |
| Shuffled-label PR-AUC | ≤ 0.75 | 0.35 | ✓ |
| PACKAGE_NAME_LEXICAL | ≤ 0.80 | **0.83** | ✗ |
| GENERIC_METADATA (no source) | ≤ 0.80 | **0.97** | ✗ |
| BEHAVIOUR − nuisance | ≥ 0.05 | 0.91 − 0.97 | ✗ |
| Compromised benchmark size | ≥ 40 | 240 | ✓ |
| 02-echo holdout | excluded | yes | ✓ |

**Neural training gate: FAIL** — no PyTorch / no pretrained downloads.

### Shortcut decomposition (mixed test; prevalence ≈ 0.31)

| Mode | PR-AUC |
| --- | ---: |
| PACKAGE_NAME_LEXICAL_ONLY | 0.83 |
| V1_LEGACY_NAME_MORPHOLOGY | **0.75** (was ~0.97 on V1) |
| VERSION_ONLY | 0.46 |
| SOURCE_ONLY | **1.00** (Datadog vs npm — composition bias) |
| ARTIFACT_STRUCTURE_ONLY | 0.94 |
| GENERIC_METADATA_ONLY (no source) | 0.97 |
| OPAQUE_RANDOM_ID | 0.29 |
| BEHAVIOUR_ONLY | 0.91 |
| Shuffled labels | 0.35 |

### Benchmarks (behaviour-only logistic)

| Benchmark | Name PR-AUC | Nuisance | Behaviour | Rules TP/FN |
| --- | ---: | ---: | ---: | --- |
| Compromised-version | 0.71 | ~1.0* | 1.0* | 10 / 4 |
| Matched malicious-intent | **0.78** | 0.93 | 0.91 | 3 / 15 |
| Mixed naturalistic | 0.83 | 0.97 | 0.91 | 14 / 24 |

\*Small test slices / structure shortcuts — treat perfect scores as unreliable.

### PG-Delta (security feature deltas on pairs)

Test n=16 (8 pos / 8 neg): PR-AUC 1.0 — **too small to claim**; infrastructure only.

## What improved vs V1

- Legacy name morphology **0.97 → 0.75**
- Opaque-ID / shuffled sanity checks pass
- Compromised-version + matched-intent benchmarks exist
- Source bias is now **explicit** (SOURCE_ONLY = 1.0)

## What still blocks neural work

1. Artifact-structure / metadata still separates classes too easily  
2. Name lexical still slightly above the 0.80 gate on mixed  
3. Behaviour does **not** beat source-free nuisance on mixed  
4. All malware still comes from one distributor lane (Datadog) vs npm controls  

## Next (Dataset V3 candidates)

- Same-source or source-blind acquisition for both classes  
- Stronger structure-matched hard negatives  
- More compromised pairs with larger held-out families  
- Exclude / specially handle cross-label near-dup clusters  

## Product policy

Unchanged: ML shadow / optional; never independent BLOCK; no auto weight download.
