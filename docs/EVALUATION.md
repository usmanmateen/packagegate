# PackageGate — Initial Qualitative Evaluation

**Status:** qualitative validation note · **Date:** 2026-08-09  
**Scope:** one independently labelled malicious npm sample + existing controls  
**Not a detection-rate benchmark.**

## Grounding rules

- PackageGate performed **static analysis only**. No package code was executed.
- The Datadog label is **ground truth for evaluation**, not scanner input.
- Behavioural risk and threat intelligence remain separate evidence lanes.

## Independent malicious sample

| Field | Value |
| --- | --- |
| Dataset | [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) |
| Category | `samples/npm/compromised_lib` |
| Package | `02-echo@0.0.7` |
| Dataset path | `samples/npm/compromised_lib/02-echo/0.0.7/2025-11-24-02-echo-v0.0.7.zip` |
| Dataset password | `infected` (documented by Datadog) |
| Manifest entry | `02-echo => ["0.0.7"]` (compromised versions list) |
| ZIP layout | Expanded package files (no original registry `.tgz`) |
| Evaluation artifact | Locally repacked npm-style `.tgz` (byte container only; **not** the original published tarball) |

### Artifact hashes (local identification only)

| Artifact | SHA-256 |
| --- | --- |
| Datadog ZIP | `a3fb60c049272535735cde0df929c982e36b46c494d3e44809f7b4fae3b7059a` |
| Repacked evaluation `.tgz` | `1d873542d27dd6f66525f61c1ba2d18f07bc396bf37bf4398eb4f32caf141975` |

These hashes identify the local evaluation containers. They do **not** establish npm registry provenance. PackageGate correctly reported registry integrity as not verified.

## First PackageGate result (engine unchanged)

| Metric | Value |
| --- | --- |
| Files extracted | 6 |
| Files analysed | 2 (`setup_bun.js`, `lib/echo.js`) |
| Analysis coverage | 85% (content retention truncated for one large JS file) |
| Lifecycle | `preinstall` → `node setup_bun.js` (**reported, not executed**) |
| Findings | 22 |
| Behaviour chains | **0** |
| Breadth (B) | 18.67 |
| Chains (X) | 0.00 |
| Final score | **19 / 100** |
| Recommendation | **ALLOW** |
| Classification | **LOW_RISK** |

### Finding categories observed

| Category | Count (approx.) | Notes |
| --- | --- | --- |
| `ENVIRONMENT_ACCESS` | 8 | Named env reads + whole-env enumeration |
| `PROCESS_EXECUTION` | 5 | `child_process.execSync` / runtime shell commands |
| `SYSTEM_INFORMATION_ACCESS` | 4 | `process.platform` |
| `HOME_DIRECTORY_ACCESS` | 2 | `os.homedir()` |
| `INSTALL_SCRIPT` | 1 | `preinstall` |
| `SHELL_COMMAND` | 1 | Shell operators in command strings |
| `NETWORK_DESTINATION` | 1 | `bun.sh` URL literal |

### What this means vs ground truth

Datadog labels `02-echo@0.0.7` malicious. PackageGate independently recommended **ALLOW**.

At the intervention level this is a **false negative** for the current model on this sample.

That does **not** mean PackageGate saw nothing. It saw substantial install-time capability evidence (process execution, environment access, home-directory access, a network destination literal). It did **not** establish an evidenced behaviour chain, and under the published risk model breadth without chains remains below the `REVIEW` band.

## Why the score landed at 19

Observed malware shape (static reading of source as text only):

1. `preinstall` runs a Node installer helper.
2. That helper downloads/installs a third-party runtime via shell (`curl … | bash` / PowerShell).
3. It then launches that runtime against a large obfuscated payload file.

PackageGate’s current strengths matched step 1 and much of step 2’s Node-side API surface. The decisive gaps for this sample were:

1. **No evidenced chain** — capabilities co-occur, but conservative linkage did not produce a source→sink chain the risk engine can amplify.
2. **Shell-mediated download/execute** — the remote fetch is a string passed to `execSync`, not an AST `https.request` / `fetch` call, so network *capability* is under-represented relative to destination literal + process execution.
3. **Large obfuscated payload not analysed** — a ~10 MiB single-line obfuscated JS file exceeded the default per-file content retention budget (4 MiB). Bytes were extracted and hashed, but content was not retained for AST analysis, so obfuscation/payload rules never ran on it.
4. **Cross-runtime payload** — the interesting payload is intended to run under a downloaded `bun` binary, outside PackageGate’s Node/TS AST path even if retention had succeeded.
5. **Risk-model posture** — by design, install scripts and isolated API presence are cheap; `BLOCK`/`REVIEW` are driven primarily by evidenced composition. This sample’s dangerous composition is partly outside current linkage/file-budget reach.

These are **documented capability boundaries**, not evidence that “ALLOW means safe.”

## Control scans (same session)

| Sample | Independent label | Findings (summary) | Chains | Score | PackageGate |
| --- | --- | --- | --- | --- | --- |
| `lodash@4.17.21` | expected-benign control | low-severity / info signals | 0 | 3 | ALLOW |
| `express@4.21.2` | expected-benign control | env + network inventory, no chain | 0 | 2 | ALLOW |
| `inert-env-exfil` | synthetic suspicious | env enumeration + network | 1 | 32 | REVIEW |
| `02-echo@0.0.7` | **Datadog malicious** | install + exec + env + home + dest | 0 | 19 | **ALLOW** |

Controls were unchanged in meaning after this evaluation. No scanner weights were tuned against the malicious sample.

## Improvement backlog (not implemented in this evaluation)

Generalizable follow-ups suggested by this sample, without hard-coding package names:

1. Surface retention-dropped files explicitly in investigation file lists / findings (coverage honesty).
2. Detect install-time `curl|bash` / `wget|sh` / `irm|iex` command strings at process-execution sinks as download-and-execute evidence.
3. Optional higher retention / streaming AST for very large single-line JS when obfuscation signals are present.
4. Future Lane I intelligence: exact `name@version` malware records remain a separate lane from behavioural score.

No commit was made for this evaluation: PackageGate code was not changed.

## Safety notes

- Malware lived only under `/tmp/packagegate-malware-eval/`.
- Nothing malicious was copied into `/home/usman/projects/packagegate/`.
- No `npm install` / `node` / `bun` / lifecycle execution of the sample occurred.
- The evaluation `.tgz` was built with a non-executing archive writer (not `npm pack`).
