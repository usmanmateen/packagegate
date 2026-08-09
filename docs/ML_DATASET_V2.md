# PackageGate — ML Dataset V2

**Status:** deconfounding experiment (neural gate evaluated after structured baselines)  
**Manifests:** `ml/data-manifests/v2/`  
**External artefacts:** `/tmp/packagegate-ml-data-v2` (not in git)  
**Does not overwrite:** Dataset V1 (`ml/data-manifests/v1/`)

## Why V2 exists

Dataset V1 proved the pipeline works but failed the neural gate because
**PACKAGE_NAME_LEXICAL** morphology (mislabelled `name_hash` in V1) reached
PR-AUC ≈ 0.97. Models could identify “Datadog-looking” package identities
instead of malicious behaviour.

V2 attacks that confound with:

1. **Compromised-version benchmark** — clean adjacent npm versions vs Datadog
   `compromised_lib` versions (same package identity)
2. **Matched malicious-intent benchmark** — morphology nearest-neighbour
   matching to hard negatives (no security features in the matcher)
3. **Mixed / naturalistic benchmark** — broader population, reported separately
4. **Expanded hard negatives** — installers, native binaries, network clients, CLIs
5. **Stronger family unification** across package identity + duplicate clusters
6. **Shortcut decomposition** — name / version / source / structure / behaviour

## Pre-registered neural gate (Dataset V2)

Defined **before** looking at V2 metrics. Do not weaken after the fact.

PASS only if all hold:

| # | Condition | Threshold |
| --- | --- | --- |
| 1 | Split leakage audit | PASS |
| 2 | Opaque random-ID PR-AUC | ≤ prevalence + 0.25 |
| 3 | Shuffled-label PR-AUC | ≤ 0.75 |
| 4 | PACKAGE_NAME_LEXICAL PR-AUC (mixed) | ≤ 0.80 |
| 5 | GENERIC_METADATA_ONLY PR-AUC (mixed) | ≤ 0.80 |
| 6 | BEHAVIOUR_ONLY − nuisance PR-AUC | ≥ 0.05 |
| 7 | Compromised-version benchmark size | ≥ 40 samples with features |
| 8 | Hard negatives represented | catalogue categories present |
| 9 | 02-echo | not in train/validation |
| 10 | Duplicate clusters | unified into split families |

## Labels

- `EXPECTED_BENIGN` — not proven safe; selected as historically normal / adjacent controls
- `MALICIOUS` / `COMPROMISED` — Datadog curated; `attack_category` is metadata only (**never model input**)
- OpenSSF — metadata-only (`available=false`)

## Hard negatives / matching

Catalogue expanded (`BENIGN_HARD_NEGATIVES` + `BENIGN_HARD_NEGATIVES_V2`).
Malicious-intent samples matched via standardised name/version morphology
nearest neighbours (no PackageGate findings in the matcher).

## Compromised pairs

Datadog `compromised_lib` artefacts paired with adjacent npm versions that are
**not** independently labelled malicious in the Datadog index → `EXPECTED_BENIGN`
controls. Cross-label near-duplicate clusters (e.g. `@antv/g*`) are recorded in
`cross_label_duplicates.json` for manual review.

## Limitations (observed after V2 run)

- `SOURCE_ONLY` PR-AUC = 1.0 on mixed: all malware from Datadog, controls from npm.
- Artifact-structure nuisance remains strong (~0.94 PR-AUC).
- Name lexical improved vs V1 but still ~0.83 on mixed (gate ≤0.80).
- Behaviour-only does not yet beat source-free nuisance on mixed.

Neural gate: **FAIL**. No transformer training.

