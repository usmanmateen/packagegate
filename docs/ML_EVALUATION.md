# PackageGate — ML Evaluation

**Status:** Dataset V1 pilot + structured baselines (neural gate **FAIL**)  
**Last updated:** 2026-08-09  

## Scientific question

Can learned models improve PackageGate over the deterministic engine under
honest package-family holdout conditions?

## Baseline (product, no ML)

| Sample | Behavioural | Final |
| --- | --- | --- |
| lodash@4.17.21 | 3 ALLOW | ALLOW |
| express@4.21.2 | 2 ALLOW | ALLOW |
| debug@4.3.4 | 0 ALLOW | ALLOW |
| JSONStream@1.3.5 | 4 ALLOW | ALLOW |
| inert-install-curl-bash | ~49 REVIEW | REVIEW |
| 02-echo@0.0.7 (holdout) | 58 REVIEW | REVIEW |

## Dataset V1 (pilot)

External root: `/tmp/packagegate-ml-data` (never committed).

| Item | Count |
| --- | ---: |
| Total metadata records | 426 |
| Available artefacts | 381 |
| Malicious available (Datadog) | 150 |
| Expected-benign available | 227 |
| Synthetic suspicious fixtures | 4 |
| OpenSSF metadata-only | 40 |
| Exact duplicate groups | 0 |
| Near-duplicate clusters | 17 |
| Train / Val / Test (split IDs) | 275 / 52 / 54 |
| Feature-exported rows | 373 |
| Export failures (final) | 8 |
| 02-echo in train/val | **No** (holdout ✓) |
| Leakage audit | **PASS** |

### Sources

- **Malicious:** Datadog `malicious-software-packages-dataset` (Apache-2.0). ZIPs
  downloaded to quarantine, password `infected`, rebuilt to npm-style `.tgz`,
  scanned statically only.
- **Expected-benign:** curated hard-negative catalogue via npm registry tarball
  HTTP download (never `npm install`).
- **OpenSSF:** metadata-only labels (no auto malware download).
- **Synthetic:** PackageGate inert fixtures.

### Hard-negative categories

`network_libraries`, `build_tools`, `native_installers`, `binary_downloaders`,
`frameworks`, `cli_tools`, `bundlers`, `package_managers`, `database_clients`,
`cloud_sdks`, `test_tools`.

### Split / dedup

- Grouped by package family + duplicate cluster
- Exact artifact SHA-256 clustering
- Near-duplicate via normalised JS/TS content hash + SimHash (empty sources ignored)
- Frozen manifests under `ml/data-manifests/v1/` (metadata only)

## Structured baseline (run `20260809T171903Z-structured-v1`)

Feature-covered evaluation sets:

| Split | n | positives | negatives |
| --- | ---: | ---: | ---: |
| Train | 271 | 117 | 154 |
| Validation | 50 | 12 | 38 |
| Test | 52 | 20 | 32 |

| System | PR-AUC | Recall (val thr) | FPR | Recall@~5% FPR | Brier |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rules-only (intervention) | — | 5/20 TP | 3 FP | — | — |
| Logistic regression | **0.945** | 0.55 | 0.031 | **0.95** | 0.096 |
| HistGradientBoosting | **0.952** | 0.00* | 0.00* | **0.90** | 0.035 |

\*HGB validation threshold chosen for ≤5% FPR landed near 0.996 (over-conservative
at that single operating point). PR-AUC / recall@5% FPR remain informative.

### Sanity / leakage

| Check | Result |
| --- | --- |
| Shuffled-label logistic PR-AUC | **0.32** (chance-like ✓) |
| Package-name shortcut PR-AUC | **0.97** (**FAIL** — severe name/version bias) |
| Trivial metadata shortcut PR-AUC | **0.87** (warning — size/count shortcuts) |
| Split leakage audit | PASS |
| 02-echo holdout exclusion | PASS |

### False positives (logistic, highest scores on expected-benign test IDs)

Examples: `turbo` (build_tools), `vue` (frameworks), small CLI colour packages
(`has-flag`, `wrap-ansi`, `boxen`). These are hard-negative candidates for v2.

### False negatives

Several Datadog samples score mid/high but below the chosen REVIEW threshold;
rules-only also misses most of this pilot malware set (15/20 FN at intervention),
suggesting many labelled samples lack strong install-time behavioural composition
visible to current deterministic rules.

## Neural training gate

**FAIL** — reason: `package_name_shortcut_pr_auc_too_high`.

Datadog malicious package identities (weird scopes, `999.9.9` versions, etc.)
are too separable from established benign names. Structured metrics look strong
but are **not trustworthy** for claiming semantic malware detection yet.

**No PyTorch install. No pretrained weight download. No GraphCodeBERT/CodeT5+
fine-tune in this milestone.**

## Product integration (unchanged policy)

- ML remains optional / shadow-capable
- Heuristic smoke worker ≠ trained model
- ML must not independently BLOCK
- No automatic model download in normal CLI

## Does ML currently demonstrate measurable value?

**Not yet — not honestly.**

The pilot proves the *experiment infrastructure* works (external corpus, family
splits, dedup, leakage audits, PackageGate exports, structured baselines).

It does **not** yet prove that learned representations beat PackageGate under
conditions free of identity shortcuts. Next dataset iteration must:

1. Name-mask / identity-ablate more aggressively in evaluation
2. Diversify malicious samples beyond easy naming tells
3. Expand hard negatives that look “scary” but are legitimate
4. Re-run structured baselines before any neural work

## Next steps

1. Dataset V2 with stronger identity controls
2. Re-evaluate structured baselines under name-masked protocols
3. Only then revisit neural training gate
