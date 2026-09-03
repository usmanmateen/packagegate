# PackageGate

**An npm supply-chain Trust & Safety investigation platform.**

PackageGate answers one question about a published npm package:

> What evidence exists that this package/version should be trusted, reviewed, escalated, or blocked?

It is an evidence-gathering tool for human analysts — not a verdict machine, not a
vulnerability lookup, and not an LLM wrapper. The organising principle is
**evidence before verdict**: every point of every score traces back to a file, a
line, and a rule you can check against the real artifact.

**Package code is never installed, executed, imported, or run through its
lifecycle scripts.** Analysis is static, by design.

---

## What it looks like

```
$ packagegate scan lodash@4.17.21

PACKAGEGATE INVESTIGATION
=========================

Package:          lodash@4.17.21
Duration:         1282ms

Artifact
--------
  ✓ Registry integrity verified
  SHA-256: 6a087ac9e5702a0c9d60fbcd48696012646ec8df1491dea472b150e79fcaf804
  Files extracted: 1054
  Files analysed:  1048
  Analysis coverage: 100.0%

Findings (9)
--------
  By category: DYNAMIC_CODE_EXECUTION=6, NETWORK_DESTINATION=3

  [LOW severity · HIGH confidence] DYNAMIC_CODE_EXECUTION — Dynamic code execution via Function
    template.js:259  (js/dynamic-execution/dynamic-code)

Behaviour chains (0)
----------------
  None with evidenced dataflow.
  (No evidenced chain was established — this is not proof the package is safe.)

Behavioural risk
----------------
  • Final action: ALLOW
  • Behavioural recommendation ALLOW at score 3 with no evidenced behaviour chain.

Risk breakdown
--------------
  Breadth (B):          10.87
  Chains (X):           0.00
  Modifiers (M):        -8.00
  Structural cap:       74
  Raw total:            2.87
  Final score:          3
```

Every number in that breakdown is inspectable. Nothing is a black box.

---

## The problem this solves

Most supply-chain scanners fail in one of two directions.

**They flag everything.** `postinstall` is present, so it's suspicious. The package
reads `process.env`, so it's suspicious. It makes a network request, so it's
suspicious. Every build tool in the ecosystem trips all three. Analysts learn to
ignore the tool, and an ignored scanner protects nobody.

**Or they only know what's already reported.** They query an advisory feed and
report a hit. That is useful but it is a lookup, not an investigation — and the
window that matters most is the one *before* a malicious package is reported.

PackageGate takes a third position: isolated capabilities are cheap, and
**evidenced combinations are expensive**. Reading environment variables is
unremarkable. Making an HTTP request is unremarkable. Reading environment
variables, serialising them, and posting them to a remote host — with the
dataflow between those steps demonstrated and cited — is the thing worth an
analyst's time.

---

## Does it actually discriminate?

That claim is only worth anything if the tool separates real behaviour from
lookalikes. Measured on the bundled fixtures and real packages:

| Subject | Score | Action | Behaviour chain |
|---|---|---|---|
| `lodash@4.17.21` (real, benign) | 3 | ALLOW | none |
| `inert-normal-installer` (legitimate installer shape) | 7 | ALLOW | none |
| `inert-shell-cooccurrence-negative` (**negative control**) | 5 | ALLOW | **none** |
| `inert-env-exfil` | 32 | REVIEW | `ENVIRONMENT_ACCESS → JSON_SERIALIZATION → NETWORK_REQUEST` (HIGH) |
| `inert-install-curl-bash` | 49 | REVIEW | `REMOTE_DOWNLOAD → PROCESS_EXECUTION` (HIGH) |

The third row is the one that matters. `inert-shell-cooccurrence-negative`
contains both a source and a sink in the same package — the exact shape a naive
scanner reports as exfiltration — with **no dataflow between them**. PackageGate
emits **zero chains** and scores it 5.

A chain is never emitted because a source and a sink both exist somewhere. It
requires a demonstrated relationship, and each chain records *how* its steps were
linked (`SHARED_BINDING`, `ARGUMENT_FLOW`, `PROPERTY_ACCESS`, `RETURN_VALUE`, or
the deliberately weak `SEQUENTIAL_IN_SCOPE`). A chain's confidence is capped by
its weakest link, so one resting only on statement proximity can never be
reported above `LOW` — and can never unlock `BLOCK`.

---

## False positives, measured

The discrimination table above is fixtures. This is 131 real, widely used npm
packages — build tooling, test frameworks, HTTP clients, database drivers,
loggers, auth libraries, frameworks — each resolved, downloaded, extracted and
analysed. Reproducible with
`./packages/evaluation/corpus/run-control-corpus.sh`.

| Metric | Value |
|---|---|
| Successfully analysed | **131 / 131** |
| `ALLOW` | 128 (97.7%) |
| `REVIEW` | 3 (2.3%) |
| `BLOCK` | **0** |
| Median behavioural score | **0** |
| **Packages emitting any behaviour chain** | **0** |

**Zero of 131 produced a behaviour chain.** Chains are what drive escalation, and
across the whole corpus the engine inferred none — while still producing a
HIGH-confidence chain on the exfiltration fixture. That gap is the product.

The three remaining escalations are honest ones: `next` at 27% analysis
coverage, and `astro` and `playwright` where source that *can actually run*
failed to parse. None has a behaviour chain, and the report says so.

### The corpus changed the product

An earlier run flagged six packages, and five turned out to be the scanner's
fault rather than the packages'. `pino` was escalated at **99.4% coverage**
because of one file — `test/fixtures/syntax-error-esm.mjs`, a deliberately
invalid 33-byte fixture — and `zustand` scored **0** and was escalated for the
same reason.

The fix was not to ignore `test/`; a path heuristic is trivially defeated and
tells an attacker where to hide. PackageGate now computes **install
reachability** from declared entrypoints, install lifecycle targets and the
static import graph, and only weighs a parse failure when the file can actually
run. Flag rate fell from 4.6% to 2.3% with **no score changes and no chains
gained or lost**. Unreachable files are still fully analysed and still scored;
only the completeness verdict changes, and any dynamic import we cannot resolve
disables the optimisation entirely. See
[`docs/REACHABILITY.md`](docs/REACHABILITY.md).

The corpus also caught that `fs-extra` and `socket.io` **could not be scanned at
all**, both failing on historical registry field shapes the npm documentation
does not describe.

## Real malware: what we can and cannot show

We do **not** publish a malware detection rate, because the denominator does not
exist.

Of 24 npm package versions labelled malicious by OSV — including
`eslint-scope@3.7.2`, `event-stream@3.3.6`, `flatmap-stream@0.1.1`,
`ua-parser-js@0.7.29`, `coa@2.0.3` and `rc@1.2.9` — **0 are still retrievable.**
All 24 have been unpublished. The packages survive with dozens of clean
versions; the malicious versions are gone.

> Static-analysis recall against real npm malware cannot be measured from the
> public registry. Any tool reporting one either holds a private artifact
> archive, is measuring advisory lookups, or is measuring synthetic samples.

What *is* measurable is the advisory lane, which identified all 24 — 18 as
`KNOWN_MALICIOUS`, 6 as `KNOWN_VULNERABLE`. That is a database lookup, not
detection, and it is reported in its own column for exactly that reason.

The 18/6 split is itself informative: the most famous npm compromises are
carried as GHSA advisories rather than OSV `MAL-` records, so a tool that
equates "malware" with "has a MAL- record" under-classifies them.

Full method, per-sample results and ranked gaps:
[`docs/MALWARE_EVALUATION.md`](docs/MALWARE_EVALUATION.md).

## Why isolated signals stay cheap

From `docs/RISK_MODEL.md`, and enforced by tests rather than asserted in prose:

| Signal | Maximum contribution |
|---|---|
| `postinstall` present | ~2.8 points |
| Network access | ~1.9 points |
| **200 separate `process.env` reads** | ~3.5 points |
| Missing provenance | 2 points |
| Minified / obfuscated code | **0** |

Per-rule and per-family saturation means volume cannot substitute for evidence.
A package doing one suspicious-looking thing two hundred times does not
accumulate its way to a high score. `BLOCK` on behaviour alone requires multiple
independently evidenced chains.

Obfuscation is weighted zero deliberately. Minification is ubiquitous and
legitimate. What obfuscation *does* do is reduce analysis coverage — and
PackageGate reports coverage separately, because low coverage removes our right
to say `ALLOW`, without being evidence of malice.

---

## Version comparison

The product question is not "what text changed" — that's what `diff` is for. It
is **what can this version do that the previous one could not**.

```
$ packagegate diff express@4.18.2 express@4.22.2

Findings
--------
  + NETWORK_DESTINATION — Network destination: dub.sh

Network destinations added
  + dub.sh

Risk delta
----------
  Before: 1 ALLOW
  After:  2 ALLOW
  Delta:  +1
```

A release that reformats 40,000 lines but adds no capability is uninteresting. A
release that adds four lines and a `postinstall` is not.

---

## Quick start

Requires Node 22.12+ (developed on 24) and pnpm.

```bash
git clone <your-fork-url> packagegate
cd packagegate
pnpm install
pnpm build

pnpm packagegate scan lodash@4.17.21
pnpm packagegate diff express@4.20.0 express@4.21.2
pnpm packagegate fixture inert-env-exfil
pnpm eval
```

Add `--json` to any command for stable, automation-suitable output. When piping
JSON through the pnpm script, use `pnpm --silent` so pnpm's own banner does not
precede the document:

```bash
pnpm --silent packagegate scan lodash@4.17.21 --json | jq .risk
```

There is no database, API or web interface in this release. The CLI is
stateless — each scan is computed fresh and printed. A `docker-compose.yml`
providing PostgreSQL is present for future persistence work, but nothing
currently connects to it.

---

## Evaluation

Evaluation is part of the product, not a marketing exercise. `pnpm eval` runs a
labelled corpus and reports intervention-level metrics:

```
Intervention matrix
  TP=2 TN=5 FP=0 FN=0 (n=7)
  precision=1.00 recall=1.00

Metrics are intervention-level (REVIEW/BLOCK = positive).
Tiny corpora are not statistically meaningful.
```

**That caveat is printed by the tool itself.** n=7 is a smoke test, not a
benchmark, and a perfect score on seven samples means very little. The larger
false-positive measurement lives in
[`docs/CONTROL_CORPUS.md`](docs/CONTROL_CORPUS.md) — 131 packages, 2.3% flag
rate, zero chains — and expanding both corpora is the most valuable open
contribution to this project.

Real malicious samples are **never auto-downloaded**. They require an explicit
`--malware-root` pointing at a quarantine directory you populated deliberately.
Even then they are only ever statically inspected.

Evaluation is also structurally split, because the two halves rest on different
denominators: advisory-matching recall works from labels alone, while
static-analysis precision needs artifacts — and npm unpublishes malicious
versions after takedown, so many labelled positives have no tarball left to
analyse. The harness reports how many samples were attempted versus obtained.

---

## We tried machine learning. It did not earn its place.

PackageGate contains an optional ML lane. It is **disabled by default**, and it
**cannot independently produce `BLOCK`** — at most it escalates `ALLOW → REVIEW`.

That restraint is empirical, not philosophical. The work is documented in
`docs/ML_DATASET_V1..V4.md`, `docs/ML_NEURAL_V1.md` and
`docs/ML_ROBUSTNESS_V5.md`, with pre-registered gates set *before* each run:

- **Dataset V1, V2, V3 — gate FAILED.** Early results were traced to shortcuts,
  including package-name lexical morphology rather than behaviour.
- **Dataset V4 — INCONCLUSIVE** on paired bootstrap (the confidence interval
  contained zero), though directionally consistent across five seeds.
- **Dataset V5 external holdout — advantage generalised** (CI excludes 0).

Three documented failures are in this repository because they happened. A
security tool that reports its own negative results is easier to trust than one
that reports only wins.

The deterministic engine remains authoritative. No ML output can alter a score,
create a finding, or change an advisory state.

---

## What PackageGate does not do

Stated plainly, because a security tool that oversells itself is worse than none.
The full accounting is in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

- **It cannot establish that a package is safe.** Zero findings means our rules
  recognised nothing in the code we could parse. No screen, field or score in
  this product says "safe".
- **It is static.** Runtime-gated payloads, computed member access, and
  `require` targets built from strings are invisible to it.
- **It analyses the package you asked about, not its dependency tree.**
- **Chains are conservative relationship inference, not whole-program taint
  analysis**, and are never described as such.
- **Provenance proves origin, not behaviour.** There is deliberately no
  `VERIFIED` provenance state, because Sigstore verification is not implemented —
  the strongest honest claim is `ATTESTATION_PUBLISHED`.
- **Advisory feeds lag attacks**, and a malware record is not automatically a
  critical compromise: the npm malicious-package corpus is heavily padded by
  low-effort token-farming spam.

---

## Design commitments

These are enforced structurally, not by convention:

| Commitment | Enforcement |
|---|---|
| Analysed code is never executed | No execution path exists. A guardrail test greps the source and fails on `child_process`, `vm`, `eval`, `symlink` or `link` in the scanner |
| Artifacts are hostile input | Extraction runs under byte, count, ratio and time budgets, enforced *during* streaming; `O_CREAT\|O_EXCL` at 0600 so a planted symlink cannot be followed |
| Scores are deterministic | Pure code. Contributions must reconcile to the total or the assessment is rejected |
| `KNOWN_MALWARE` needs authority | Schema-refined to require an authoritative feed hit — heuristics cannot reach that label by any path |
| Machine ≠ human judgement | Machine recommendation and analyst decision are separate fields that never overwrite each other |
| Malware ≠ vulnerability | Distinct advisory kinds, never merged into an "advisory count" |

---

## Architecture

```
packages/
  shared/            Domain model (Zod schemas + inferred types). No I/O, no Node types.
  npm-registry/      Packuments, version resolution, spec parsing. Read-only, no credentials.
  artifact-fetcher/  Streaming download + hostile-input-safe extraction
  static-analyser/   Babel AST + binding-based alias resolution → Finding[]
  shell-analyser/    Lifecycle command strings parsed as data, never executed
  behaviour-engine/  Findings + AST relationships → BehaviourChain[]
  risk-engine/       Deterministic six-stage scoring with family saturation
  threat-intel/      Advisory lookups, malware and vulnerability kept separate
  version-diff/      Security-relevant capability delta between two scans
  policy-engine/     Final action, keeping ML and behavioural lanes distinct
  cli/               scan · diff · fixture · evaluate
  evaluation/        Metrics harness
```

`shared` compiles without Node type definitions on purpose, so the same domain
model is importable by a network-disabled scanner process and by browser code
without divergence. `static-analyser` takes file *contents* as arguments rather
than a directory path, so it can move into a network-isolated container without
refactoring.

439 tests. `pnpm lint`, `pnpm typecheck`, `pnpm test` and `pnpm build` are all
green on `main`.

---

## Contributing

The highest-value contributions, in order:

1. **Benign control packages.** False positives are the central product risk. A
   legitimate package that PackageGate scores badly is a bug report worth more
   than a feature.
2. **Rules with negative tests.** Any rule PR should include the case where it
   must *not* fire.
3. **Behaviour-chain linkage cases** the engine currently misses — or chains it
   emits that a human would reject.

See [`docs/MODULE_OWNERSHIP.md`](docs/MODULE_OWNERSHIP.md) for module
boundaries and the standards each area is held to, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the trust boundaries.

## Security

To report a vulnerability in PackageGate itself, see [`SECURITY.md`](SECURITY.md).

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
