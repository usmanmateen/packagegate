# PackageGate — Evaluation Notes

**Status:** qualitative + harnessed evaluation  
**Last updated:** 2026-08-09  

## Grounding rules

- Static analysis only. Investigated packages are never executed.
- Datadog labels are ground truth for evaluation, not scanner input.
- Behavioural risk, analysis completeness, threat intelligence, and final policy remain separate lanes.

## Detection Engine history (02-echo@0.0.7)

| Engine | Findings | Chains | Completeness | Behavioural | Final |
| --- | --- | --- | --- | --- | --- |
| v1 | 22 | 0 | scalar ~85% | **19 ALLOW** | ALLOW |
| v2 | 30 | 1 HIGH install-time remote execution | **DEGRADED** | **58 REVIEW** | **REVIEW** |

V2 improved because PackageGate evidenced composition (shell semantics + lifecycle reachability + opaque completeness), **not** because thresholds were lowered.

Threat intelligence was `NONE` in both runs. If a trusted exact malware match later produces `BLOCK`, report:

- Behavioural: 58 REVIEW  
- Threat intel: KNOWN_MALICIOUS  
- Final: BLOCK  

Do not rewrite history to claim behavioural analysis alone returned BLOCK.

## Analyst Engine v3 additions

- **Security version diff** (`packagegate diff`) — semantic capability delta between versions
- **Threat-intel provider lane** — offline `none` by default; memory provider for tests; malware exact match → BLOCK without rewriting behavioural score
- **Evaluation harness** (`packagegate evaluate`) — intervention-level TP/TN/FP/FN; real malware never auto-downloaded
- **Decision explanation** — why final policy was chosen, with lanes kept separate

## ML V1 scaffolding / Dataset V1 pilot

See `docs/ML_EVALUATION.md`. Optional `--ml` lane is separate from behavioural
risk. ML may escalate ALLOW→REVIEW only; never independent BLOCK.

Dataset V1 failed the neural gate on package-name lexical shortcuts (~0.97).
Dataset V2 adds compromised-version pairs, matched malicious-intent controls,
and shortcut decomposition — gate still **FAIL** (structure/source confounds).
Do not treat strong structured PR-AUC as behavioural learning yet.

## Controls (post-v3)

| Sample | Score | Final |
| --- | --- | --- |
| lodash@4.17.21 | 3 | ALLOW |
| express@4.21.2 | 2 | ALLOW |
| inert-env-exfil | 32 | REVIEW |
| inert-install-curl-bash | ~49 | REVIEW |
| version-diff demo 1.0.0→1.0.1 | 0→49 CRITICAL | ALLOW→REVIEW |

## Safety

Malware artifacts stay under an explicit quarantine path. Nothing malicious is committed.
