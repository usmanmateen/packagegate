# Experiment 1 robustness + Dataset V5

## Freeze

- Experiment ID: `pg-neural-exp1`
- Status: `FROZEN`
- Record: `ml/experiments/pg-neural-exp1/freeze.json`
- Predictions: `ml/experiments/pg-neural-exp1/v4_matched_test_predictions.jsonl`
- Checkpoint SHA-256: `cec6d3f5f737d1c6cbc83942c0cbf9dd5cac638ddc51a43eae800d2c71474442`
- Base revision: `2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d`

## Paired bootstrap (V4 matched test, n=58)

GraphCodeBERT mean PR-AUC **0.897** vs structured **0.843** → absolute Δ **+0.054**.

10,000 paired bootstrap replicates:

| | |
|--|--|
| mean Δ | 0.055 |
| median Δ | 0.050 |
| 95% CI | **[-0.030, +0.164]** |
| P(Δ>0) | 0.8775 |

**Verdict on V4 Δ alone: INCONCLUSIVE** (CI contains 0).

## Seed robustness (same config, seeds 11/22/33/44/55)

GraphCodeBERT mean PR-AUC on frozen V4 matched test:

| Seed | PR-AUC | Δ vs structured (0.843) |
|------|--------|-------------------------|
| 11 | 0.859 | +0.016 |
| 22 | 0.908 | +0.065 |
| 33 | 0.889 | +0.045 |
| 44 | 0.863 | +0.020 |
| 55 | 0.851 | +0.008 |

- mean **0.874**, std **0.021**, range **[0.851, 0.908]**
- recall@~5% FPR mean **0.667** (std 0.043)
- All five seeds beat the fixed structured baseline
- Original Exp1 0.897 sits toward the high end of the seed distribution (slightly lucky, not an outlier relative to the observed range)

## Dataset V5 (inference only)

- Available n=217 (80 TEMPORAL_UNSEEN malicious + 137 hard-negative benign); 2 scan LIMIT_EXCEEDED failures
- Primary near-dup-collapsed eval n=209 (pos 73 / neg 136 / prev≈0.35)
- Family/name/sha overlap with V4: **0** (audit PASS)
- Leakage: **PASS** (0 failures)
- Cross-source subset: 0
- Frozen V4 thresholds unchanged

### V5 performance

| System | PR-AUC | ROC-AUC | Recall@frozen thr | FPR | Brier |
|--------|--------|---------|-------------------|-----|-------|
| Structured | 0.434 | 0.555 | 0.164 | 0.044 | 0.267 |
| GraphCodeBERT mean | **0.583** | 0.644 | 0.342 | 0.154 | 0.268 |

- Absolute Δ PR-AUC = **+0.149**
- Paired bootstrap 95% CI **[+0.052, +0.228]**; P(Δ>0)=0.9989
- Outcome class **B**: both degrade vs V4, but ML advantage persists (and is stronger on V5)

### Error patterns

- FPs: hard negatives (native/binary/network/process managers)
- FNs: many `@mastra/*` compromised_lib with deterministic ALLOW / near-zero risk → `NO_STATIC_SIGNAL` / `NEW_ATTACK_PATTERN`

## Qualitative holdouts (not in aggregates)

| Sample | Deterministic | Structured p | Embed-mean p |
|--------|---------------|--------------|--------------|
| 02-echo@0.0.7 | REVIEW (58) | 0.9999 | 0.9989 |
| lodash@4.17.21 | ALLOW | 0.088 | 0.005 |
| express@4.21.2 | ALLOW | 0.205 | 0.0005 |
| debug@4.3.4 | ALLOW | 0.105 | 0.002 |
| JSONStream@1.3.5 | ALLOW | 0.052 | ≪0.001 |

Policy: **SHADOW**.

## Final verdicts

48. Is the V4 neural improvement statistically robust? **INCONCLUSIVE** on bootstrap alone; **directionally robust** across seeds (all > structured).
49. Does the neural advantage generalise to V5? **YES** (CI excludes 0; outcome B).
50. Is a second encoder experiment now justified? **YES** — advantage survived external holdout; CodeT5+ remains the next *new* experiment, not a V5 re-tune.

## Stop rules honoured

No CodeT5+ training in this milestone · No MIL retuning · No V4 mutation · No V5 tuning · Deterministic PackageGate unchanged · ML remains SHADOW.
