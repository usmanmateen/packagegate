# pg-package-embed-mean-v1

Status: **EXPERIMENTAL_SHADOW**

## Intended use

Optional local shadow inference beside deterministic PackageGate risk.

ML must **not** change final allow/review/block policy.

**NOT PROOF THAT A PACKAGE IS SAFE.**

## Why this model was selected

Experiment `pg-neural-exp1` compared package heads on frozen Dataset V4 matched test (n=58):

| Head | PR-AUC |
|------|--------|
| Structured behaviour logistic | 0.843 |
| GraphCodeBERT mean embeddings | **0.897** |
| Embed + structured | 0.878 |
| MIL code | 0.852 |
| MIL hybrid | 0.775 |

Mean pooling won. MIL was **not** selected; leave MIL alone pending a future experiment.

## Slice encoder

- Base: `microsoft/graphcodebert-base`
- Revision: `2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d`
- max_length: 512
- SliceSchemaV2, identity-masked `STRICT_SECURITY_VIEW`
- Checkpoint SHA-256: `cec6d3f5f737d1c6cbc83942c0cbf9dd5cac638ddc51a43eae800d2c71474442`

## V4 matched test (frozen)

- n=58, prevalence≈0.36
- Absolute Δ PR-AUC (mean − structured) = **+0.054**
- Paired bootstrap 95% CI for Δ: **[-0.030, +0.164]**; P(Δ>0)=0.8775
- Statistical robustness of the V4 Δ alone: **INCONCLUSIVE** at 95%

## Seed robustness

Seeds 11/22/33/44/55 on frozen V4 matched test (embed-mean PR-AUC):

0.859, 0.908, 0.889, 0.863, 0.851 → mean **0.874**, std **0.021**, range **[0.851, 0.908]**.

All seeds beat structured 0.843. Do **not** pick the best seed for deployment.

## Dataset V5 external/temporal holdout (inference only)

- Family-disjoint from all V4; training cutoff 2026-06-10; TEMPORAL_UNSEEN malicious preferred
- Primary near-dup-collapsed n=209; leakage PASS; V4 overlap 0
- Structured PR-AUC **0.434** vs GraphCodeBERT mean **0.583** (Δ **+0.149**; 95% CI [+0.052, +0.228])
- Absolute scores degrade vs V4; relative ML advantage persists
- Details: `ml/experiments/pg-neural-exp1/v5_eval/`

## Known limitations

- Small V4 matched test (n=58)
- Hard negatives (native installs, downloaders, process managers) drive false positives
- Compromised libraries with weak static signal drive false negatives
- Representation shift can collapse absolute PR-AUC even when relative ML advantage persists
- Shadow only — deterministic PackageGate remains authoritative

## Training-data cutoff

2026-06-10 (latest Datadog observation date among V4-linked samples)

## Policy

`EXPERIMENTAL_SHADOW` — never sole evidence of safety.
