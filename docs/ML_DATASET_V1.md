# PackageGate — ML Dataset V1 (historical)

**Status:** FROZEN — neural training gate **FAILED**  
**Manifests:** `ml/data-manifests/v1/`  
**External artefacts:** `/tmp/packagegate-ml-data` (not in git)

## Purpose

Prove the PackageGate ML experimental pipeline end-to-end:

external artefacts → adapters → grouped splits → PackageGate export →
structured baselines → leakage / shortcut audits.

## Why the neural gate failed

| Shortcut | PR-AUC | Verdict |
| --- | ---: | --- |
| PACKAGE_NAME_LEXICAL (mislabelled `name_hash` in V1 runs) | **~0.97** | Severe confound |
| Trivial metadata (polluted: included `findingCount`) | **~0.72–0.87** | Confound / warning |
| Shuffled labels | **~0.32** | Chance-like PASS |
| Opaque random ID (post-audit) | near prevalence | Expected PASS |

### Exact V1 “name_hash” construction

Not a cryptographic hash. Not HashingVectorizer. Not one-hot package IDs.

Features from `sample_id` string only:

- `name_len` = `len(sample_id.split("@")[0])`  (broken on scoped IDs)
- `version_len` = `len(sample_id.split("@")[-1])`
- `at_count` = `sample_id.count("@")`
- `digit_count` = digits in full `sample_id`

Coefficients on the pilot test set were dominated by **`at_count`** and
**digit / length morphology**. Datadog malicious IDs are disproportionately
scoped / digit-heavy / oddly versioned versus established benign controls.

**Conclusion:** real **corpus identity bias**, not implementation leakage from
opaque IDs. Opaque random-ID baselines collapse toward prevalence; lexical
morphology does not.

## Authoritative counts

| Item | Count |
| --- | ---: |
| Metadata records | 426 |
| Available artefacts | 381 |
| Malicious available | 150 |
| Expected-benign available | 227 |
| Synthetic suspicious | 4 |
| OpenSSF metadata-only | 40 |
| Exact dup groups / members | 12 / 57 |
| Near-dup `dupcluster::*` families | 12 |
| Train / Val / Test / Holdout IDs | 275 / 52 / 54 / 45 |
| Feature rows | 373 |
| Export failures | 8 |

## Structured results (informative only)

Logistic PR-AUC ≈ 0.945; HGB ≈ 0.952 — **not interpretable as behavioural
learning** while lexical shortcuts solve the task.

## Do not overwrite

Dataset V1 remains the historical failed-gate experiment. Dataset V2 lives
under `ml/data-manifests/v2/` and a separate external data root.
