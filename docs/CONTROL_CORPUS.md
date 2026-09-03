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

Scanner `packagegate-cli/0.2.0`. Re-run the harness rather than citing these
figures indefinitely — the corpus resolves to current versions and will drift.

| Metric | Value |
| --- | --- |
| Packages in corpus | 131 |
| Successfully analysed | **131** (0 errors) |
| Final action `ALLOW` | 128 (97.7%) |
| Final action `REVIEW` | 3 (2.3%) |
| Final action `BLOCK` | **0** |
| **Flag rate** | **2.3%** |
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

### The three remaining escalations

| Package | Score | Coverage | Driver |
| --- | --- | --- | --- |
| `next` | 27 | 0.277 | behavioural score below the coverage floor |
| `astro` | 20 | 0.971 | 3 *reachable* executable parse failures |
| `playwright` | 18 | 0.974 | 1 *reachable* executable parse failure |

None has a behaviour chain. `astro` and `playwright` are escalated because source
that can actually run failed to parse, which is the conservative behaviour we
want: coverage gaps in reachable code remove our right to say `ALLOW`. `next` is
analysed at 27% coverage, and a `REVIEW` on a package we could only partly parse
is a defensible outcome rather than a bug.

### What this corpus changed

An earlier run of the same corpus flagged **six** packages at a 4.6% flag rate.
Five of those were the scanner's fault, not the packages':

| Package | Then | Now | Why |
| --- | --- | --- | --- |
| `pino` | REVIEW | ALLOW | only gap was an unreachable invalid test fixture |
| `zustand` | REVIEW | ALLOW | scored **0**, escalated purely on an unreachable gap |
| `graphql` | REVIEW | ALLOW | single unreachable gap at 99.9% coverage |

`pino` was escalated at 99.4% coverage because of
`test/fixtures/syntax-error-esm.mjs` — a deliberately invalid 33-byte file whose
entire purpose is to be unparseable.

The fix was **not** to ignore `test/`. A path heuristic is trivially defeated and
functions as an instruction manual for hiding. PackageGate now computes install
reachability from declared entrypoints, install lifecycle targets and the static
import graph, and weighs a parse failure only when the file can actually run.
Unreachable files are still fully analysed and still scored; only the
completeness verdict changes. See [`REACHABILITY.md`](REACHABILITY.md) for the
security tradeoff and the four properties that bound it.

No score changed, and no behaviour chain appeared or disappeared.

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
