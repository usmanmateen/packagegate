# Control corpus: measuring the false-positive rate

False positives are PackageGate's central product risk. A scanner that escalates
packages the ecosystem already depends on will be switched off, and a switched-off
scanner protects nobody.

This document records what the scanner actually does against widely used npm
packages. Everything here is reproducible from the repository.

## Method

```bash
pnpm build
./packages/evaluation/corpus/run-control-corpus.sh
python3 packages/evaluation/corpus/summarise.py
```

The corpus is `packages/evaluation/corpus/control-packages.txt`: 131 widely used
npm packages spanning build tooling, test frameworks, HTTP clients, database
drivers, loggers, CLI utilities, crypto/auth libraries and frameworks. Each is
resolved to its current published version, downloaded, extracted and analysed.
Raw per-package output is committed as `results.jsonl`.

**These packages are labelled expected-benign because the ecosystem depends on
them, not because anyone has proven them clean.** That is a weaker claim than it
looks, and it is the honest one — see [`LIMITATIONS.md`](LIMITATIONS.md). What
the corpus measures is *how often PackageGate interrupts an engineer who did
nothing wrong*.

## Results

Run of 2026-08-10, scanner `packagegate-cli/0.2.0`, rules
`static-analyser/2.0.0 + behaviour-engine/2.0.0 + risk-weights/1.0.0 + policy-engine/1.0.0`.

| Metric | Value |
| --- | --- |
| Packages in corpus | 131 |
| Successfully analysed | **131** (0 errors) |
| Final action `ALLOW` | 125 (95.4%) |
| Final action `REVIEW` | 6 (4.6%) |
| Final action `BLOCK` | **0** |
| **Flag rate** | **4.6%** |
| Median behavioural score | **0** |
| Mean behavioural score | 3.7 |
| p95 / max score | 18 / 27 |
| **Packages emitting any behaviour chain** | **0** |

### The number that matters most

**Zero of 131 packages produced a behaviour chain.**

Behaviour chains are the signal that drives escalation, and the engine emitted
none across the entire corpus. Combined with the fixtures — where
`inert-env-exfil` produces a HIGH-confidence
`ENVIRONMENT_ACCESS → JSON_SERIALIZATION → NETWORK_REQUEST` chain and the
co-occurrence negative control produces none — this is the evidence that chain
inference is not manufacturing relationships out of proximity.

A median score of **0** across 131 real packages says the same thing from the
other direction: ordinary code is not accumulating incidental risk.

### The six escalations, and why they are not behavioural

| Package | Score | Coverage | Driver |
| --- | --- | --- | --- |
| `next` | 27 | 0.277 | behavioural score at 27% coverage |
| `astro` | 20 | 0.971 | analysis completeness |
| `pino` | 19 | 0.994 | analysis completeness |
| `playwright` | 18 | 0.974 | analysis completeness |
| `graphql` | 2 | 0.999 | analysis completeness |
| `zustand` | 0 | 0.980 | analysis completeness |

**Five of the six carry a behavioural recommendation of `ALLOW` and zero
chains.** They are escalated by the completeness policy, not by anything the
rules found: some executable source failed to parse, so the scanner declines to
say `ALLOW` about code it did not read. `zustand` scores **0** and is still
escalated for exactly this reason.

That is the intended conservative behaviour — coverage gaps remove our right to
say `ALLOW` — but the trigger is often trivial. `pino`'s escalation comes from
a single file:

```
test/fixtures/syntax-error-esm.mjs — Unexpected token, expected "{" (3:0)
```

A deliberately invalid test fixture, 33 bytes, shipped in the tarball. Coverage
0.994. This is a **known false positive** and the clearest tuning target in the
project: a parse failure in a path that is obviously test material should not
degrade the completeness verdict for the whole package. It is recorded here
rather than quietly fixed by weakening the policy, because the conservative
default is correct and the fix belongs in reachability analysis, not in lowering
the bar.

`next` is the one genuine behavioural escalation: 6,936 findings at 27%
coverage. A `REVIEW` on a package we could only partially parse is a defensible
outcome, not a bug.

## What this run also found

The corpus caught two real defects that no unit test had:

- **`fs-extra` and `socket.io` could not be scanned at all.** Both failed
  packument validation on historical field shapes — `homepage` as an array of
  strings, and the `licenses[]` array carried under the `license` key. Fixed,
  with regression tests. Before the fix the corpus was 129/131.
- Earlier, the same approach surfaced `engines` as an array and absent
  dependency keys, which had made `lodash` unscannable.

Every one of these was found by running against the real registry rather than by
reading its documentation, which describes none of these shapes.

## Limits of this measurement

- 131 packages is a smoke corpus, not a benchmark. It is not weighted by
  download count, and it over-represents build tooling.
- Expected-benign is an assumption about widely used packages, not a proof.
- A flag rate is not a precision figure. Precision needs true positives, and
  measuring those requires malicious artifacts — which npm unpublishes after
  takedown. See [`EVALUATION.md`](EVALUATION.md) for why the two halves rest on
  different denominators.
- The corpus resolves to current versions, so results drift as packages publish.
  Re-run it rather than trusting the numbers above indefinitely.

Expanding this corpus is the single most valuable contribution to the project.
A legitimate package PackageGate escalates is a bug report worth more than a
feature.
