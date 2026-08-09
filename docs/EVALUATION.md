# PackageGate — Detection Engine v2 Evaluation

**Status:** qualitative validation after Detection Engine v2  
**Date:** 2026-08-09  
**Scope:** independently labelled malicious sample + controls + synthetic fixtures  
**Not a detection-rate benchmark.**

## Grounding rules

- PackageGate performed **static analysis only**. No package code was executed.
- The Datadog label is **ground truth for evaluation**, not scanner input.
- Behavioural risk, analysis completeness, threat intelligence, and final policy remain separate lanes.

## Independent malicious sample (same as v1)

| Field | Value |
| --- | --- |
| Dataset | [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) |
| Package | `02-echo@0.0.7` |
| Evaluation artifact | Locally repacked npm-style `.tgz` (not original registry tarball) |

## BEFORE vs AFTER

| Metric | v1 (unchanged engine) | v2 (Detection Engine) |
| --- | --- | --- |
| Findings | 22 | 30 |
| Behaviour chains | **0** | **1** (`INSTALL_TIME_REMOTE_EXECUTION`, HIGH) |
| Analysis coverage | 85% (opaque file invisible) | ~67% (opaque file counted in denominator) |
| Analysis completeness | *(scalar only)* | **DEGRADED** (`bun_environment.js` retention + opaque triage) |
| Behavioural score | **19** | **58** |
| Behavioural recommendation | **ALLOW** | **REVIEW** |
| Final policy | *(same as behavioural)* | **REVIEW** |
| vs Datadog label | False negative | True positive at intervention level (REVIEW) |

### Why the result changed (evidence, not threshold tuning)

1. **Shell semantics** — recoverable command strings at `child_process.execSync`, including binding-assigned constants (`command = "curl … \| bash"; execSync(command)`), are parsed as data. That produced `REMOTE_CODE_FETCH` / remote-content-to-shell evidence.
2. **Lifecycle reachability** — `preinstall → node setup_bun.js` links the shell pipeline into an install-time chain with `LIFECYCLE_INVOCATION` + `ARGUMENT_FLOW` + `SHELL_PIPELINE` evidence.
3. **Risk model** — the new evidenced `REMOTE_DOWNLOAD → PROCESS_EXECUTION` chain maps to existing pattern J3 (with install-time multiplier). Score rose because composition was evidenced, not because ALLOW/REVIEW thresholds were lowered.
4. **Analysis completeness / policy** — `bun_environment.js` (~10 MiB) exceeds retention; opaque triage records `DEGRADED`. Final policy stays REVIEW for both behavioural REVIEW and degraded executable visibility. Behavioural score is not inflated with “incomplete analysis points.”

Threat intelligence remained `NONE` (offline provider). No Datadog label was fed into the scanner.

## Control scans (v2)

| Sample | Findings | Chains | Score | Completeness | Final |
| --- | --- | --- | --- | --- | --- |
| `lodash@4.17.21` | 9 | 0 | 3 | COMPLETE | ALLOW |
| `express@4.21.2` | 6 | 0 | 2 | COMPLETE | ALLOW |
| `debug@4.3.4` | — | 0 | 0 | COMPLETE | ALLOW |
| `JSONStream@1.3.5` | — | 0 | 4 | COMPLETE | ALLOW |
| `inert-env-exfil` | 2 | 1 | 32 | COMPLETE | REVIEW |
| `inert-install-curl-bash` | 7 | 1 | 49 | COMPLETE | REVIEW |
| `inert-shell-cooccurrence-negative` | 2 | 0 | 5 | COMPLETE | ALLOW |
| `02-echo@0.0.7` | 30 | 1 | 58 | DEGRADED | **REVIEW** |

## Remaining limitations (still true)

- The large Bun payload is still not fully AST-analysed (by design: bounded retention + opaque triage).
- Cross-file dataflow remains a small conservative subset.
- Threat-intel providers are wired but offline-default; exact malware matching is a separate lane.
- Absence of findings is still not proof of safety.

## Safety notes

- Malware lived only under `/tmp/packagegate-malware-eval/`.
- Nothing malicious was committed to the PackageGate repository.
- No lifecycle/script/binary execution of investigated packages occurred.
