# Contributing to PackageGate

PackageGate is a security tool. The bar for a change is not "does it work" but
"can a reviewer verify it is correct". This document explains what that means in
practice.

## Setup

```bash
pnpm install
pnpm build
pnpm test
```

Node 22.12+ (developed on 24.19) and pnpm are required. Nothing else — there is
no database, service or API key needed to run the scanner or its tests.

## The contributions that matter most

In order of value:

1. **Benign packages that PackageGate wrongly escalates.** False positives are
   the central product risk. A legitimate package the scanner flags is a bug
   report worth more than a feature. Add it to
   `packages/evaluation/corpus/control-packages.txt` with the output you saw.
2. **Malicious behaviour PackageGate misses.** Describe the shape of the
   behaviour and, where possible, add an *inert* fixture reproducing it.
3. **Detection rules, with negative tests.** See below.
4. **Behaviour-chain linkages** the engine misses, or chains it emits that a
   human reviewer would reject.

## Rules for changing detection

**Every rule needs a negative test.** A rule PR without the case where the rule
must *not* fire will be asked for one. Detection is easy; not firing on the
thousands of legitimate packages that look similar is the hard part.

**Severity and confidence are separate axes.** Severity asks how bad this would
be if malicious. Confidence asks how sure we are the detection is real and
correctly attributed. A perfectly detected `process.env.NODE_ENV` read is HIGH
confidence and LOW severity. If you find yourself raising severity to make
something stand out, the answer is usually a chain, not a louder rule.

**Never emit a behaviour chain from co-occurrence.** A source and a sink
appearing in the same file is not dataflow. Chains carry a `ChainLinkKind`
recording how two steps were connected, and confidence is capped by the weakest
link.

## Rules for changing scoring

Scoring changes need more than passing tests:

- State the false-positive scenario the change risks.
- Re-run the control corpus and report before/after:
  ```bash
  ./packages/evaluation/corpus/run-control-corpus.sh
  python3 packages/evaluation/corpus/summarise.py
  ```
- **Do not tune weights to make a benchmark number improve.** If a documented
  figure and the code disagree, report the discrepancy rather than adjusting
  either to match.

## Security constraints that are not negotiable

These are enforced by tests that grep the source. A PR that violates one will
fail CI, and that is intentional:

- **Analysed package code is never executed.** No `require`, `import`, `eval`,
  `vm`, `child_process` or shell invocation on artifact content — including in
  tests.
- **No `fs.symlink` or `fs.link` in the extraction path.**
- **No host filesystem path** may reach a finding, an error message, a log field
  or JSON output.
- **The optional ML lane cannot reach `BLOCK`** and cannot alter a score.

## Fixtures

Test fixtures may *look* malicious. They must never *be* malicious: no real
credential paths read, no real network destinations, no working payload. They
exist to exercise the parser.

Never commit a real malicious sample. Real-malware evaluation reads from a
quarantine directory you supply with `--malware-root`; samples are never
auto-downloaded and never committed.

## Before you open a PR

```bash
pnpm lint && pnpm typecheck && pnpm test && pnpm build && pnpm format:check
```

Commits should read like ordinary engineering history — one understandable piece
of work each, leaving the repository in a working state. Prefer
`fix(scanner): …`, `test(reachability): …`, `docs: …`.

## Reporting security issues

Do not open a public issue for a vulnerability in PackageGate itself. See
[SECURITY.md](SECURITY.md). Missed detections and false positives are ordinary
issues, not security reports — both are very welcome.
