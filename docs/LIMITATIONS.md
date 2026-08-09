# Limitations

PackageGate is an evidence-gathering tool for human analysts. It is not an
oracle. This document states plainly what it cannot do, because a security tool
that oversells itself is worse than no tool at all — it converts an unknown into
a false sense of resolution.

If you are evaluating PackageGate, read this before the README.

---

## 1. The central limitation

**PackageGate can never establish that a package is safe.**

A scan that completes with zero findings means exactly one thing: *the rules we
have did not recognise anything in the code we could parse*. It does not mean
the package is benign. No screen, API field, report section or score in this
product is permitted to say "safe", and the vocabulary is deliberately
constrained to `ALLOW` / `REVIEW` / `BLOCK` and `LOW_RISK` /
`INSUFFICIENT_EVIDENCE` for that reason.

Absence of evidence is not evidence of absence.

---

## 2. Static analysis misses dynamic behaviour

The first release performs **static analysis only**. Package code is never
installed, executed, imported, required, or run through its lifecycle scripts.
That is a deliberate safety property, and it has a direct cost: anything that
only becomes apparent at runtime is invisible to us.

Concretely, we will miss:

- payloads assembled at runtime from fragments that look innocuous individually
- behaviour gated on environment — code that only activates on a CI runner, on a
  particular OS, after a date, or when a specific environment variable is set
- capability reached through computed member access: `obj[key](payload)` where
  `key` is only known at runtime
- `require` targets built from strings: `require("child" + "_process")`
- code fetched from the network at install time and executed immediately, where
  the fetched content is the actual payload
- native code behaviour. We can detect that a `.node` addon or platform binary
  is present; we do not analyse compiled machine code.
- anything inside a dependency. **We analyse the package you asked about, not its
  dependency tree.** A clean direct package can install a malicious transitive
  one.

Docker isolation does not change this. Containerisation is defence-in-depth for
*our* pipeline, never a licence to detonate unknown code.

---

## 3. Behaviour chains are not taint analysis

The behaviour-chain engine performs **conservative relationship inference**,
mostly within a single file. It is not whole-program dataflow analysis and must
never be described as such.

Each chain records *how* its steps were connected, via a `ChainLinkKind`, and a
chain's confidence is capped at its weakest link. A chain built only on
`SEQUENTIAL_IN_SCOPE` — two operations in the same function with no proven
dataflow between them — can never be reported above `LOW`.

We will miss real chains that cross function boundaries in complex ways, pass
through class instance state, flow through callbacks and promise pipelines, or
are reassembled after being split across modules. **A missing chain is not
evidence that data does not flow.**

We will also occasionally infer a relationship that a human would reject. That
is why every chain cites the exact lines it rests on.

---

## 4. Heuristics carry false positives and false negatives

The risk engine is deterministic and explainable, but its weights are judgement
calls, not measurements of ground truth.

Legitimate packages routinely do things that look alarming in isolation:

- build tools spawn child processes and compile native modules
- installers download platform-specific binaries during installation
- almost everything reads `process.env`
- CLI tools read and write files across the user's home directory
- telemetry makes outbound requests
- bundled `dist/` output is minified to the point of unreadability

None of these is evidence of malice, and PackageGate is tuned so that none of
them alone produces a high score. The consequence of that tuning is the
opposite error: **a sufficiently careful attacker doing only one suspicious
thing may score low.** We accept that trade because a scanner that flags
everything is ignored, and an ignored scanner protects nobody.

Where the evaluation harness has measured precision and recall, the real numbers
are published in `docs/EVALUATION.md` alongside the sample sizes they rest on.
Any figure without a reproducible dataset behind it should be treated as
marketing, including ours.

---

## 5. Intelligence feeds lag attacks, and their content is uneven

Known-malware and vulnerability data comes from external feeds. Those feeds are
authoritative but not instantaneous.

- A malicious package is typically published *before* it is reported. During
  that window — often the window that matters most — the feeds say nothing.
- **A malware advisory is not automatically a critical compromise.** The npm
  malicious-package corpus is heavily padded by mass low-effort campaigns,
  notably token-farming spam. A `MAL-` record may describe a serious credential
  stealer or a worthless spam package, and the record alone does not distinguish
  them. PackageGate surfaces the record and its source rather than converting it
  into a severity we cannot justify.
- Coverage differs by source. Most malicious-package records carry no GitHub
  advisory alias, so consulting a single feed produces a large blind spot. We
  query more than one and record which were consulted.
- A failed lookup is reported as a failed lookup, never as "no advisories
  found". Those are different facts and the UI keeps them different.
- Advisory version ranges are taken verbatim from the feed. A record covering a
  *different* version of the same package is shown as context, not as a hit.

---

## 6. Provenance proves origin, not behaviour

Where npm publishes attestation data, PackageGate surfaces it. Two honest
statements bound what that means:

**Provenance does not make a package safe.** A malicious package built
transparently in a public CI pipeline has perfect provenance. Attestation
describes *where and how* an artifact was built, never what the code does.

**Missing provenance does not make a package suspicious.** Most of the registry
predates the feature. Absence is unremarkable and is not scored.

There is deliberately **no `VERIFIED` provenance state**. PackageGate does not
perform Sigstore bundle or certificate-chain verification in this release, so
the strongest truthful claim available to us is `ATTESTATION_PUBLISHED` — the
registry served an attestation for this version. We separately record whether
the attestation's subject digest matches the artifact we actually downloaded,
which binds the bytes we analysed to the bytes the attestation describes but
says nothing about whether the attestation is authentic.

One further subtlety: the attestations endpoint returns an identical 404 for
"this version has no provenance" and "this package does not exist", so
`NOT_FOUND` is corroborated against registry metadata rather than inferred from
the status code alone.

---

## 7. Parsing and coverage gaps

- Files that fail to parse are recorded as `ParseFailure` and are **not**
  analysed. They are never silently dropped, because a package that defeats the
  parser is itself worth knowing about — but their contents are unexamined.
- Very large files are skipped rather than parsed, under an explicit budget.
  Skips are recorded. A package can therefore hide code behind sheer size, and
  the report will tell you that this happened.
- We analyse JavaScript and TypeScript. Other languages present in a package —
  shell scripts, Python, compiled binaries, WASM — are enumerated and hashed but
  not semantically analysed.
- Source maps, bundled vendor code and vendored dependencies are analysed as
  ordinary files, which can attribute behaviour to a package that actually
  originates in something it bundled.

---

## 8. Metadata gaps are not signals

Registry metadata is frequently incomplete for older packages. `fileCount` and
`unpackedSize` in particular are absent on the large majority of pre-2016
versions.

Absent means **unknown**, never zero. Missing metadata is not evidence of
maliciousness and is never scored as such.

---

## 9. Evaluation is bounded by what can be retrieved

Measuring detection against real malware has a structural problem: npm
unpublishes malicious versions after takedown. The labelled corpora are lists of
`name@version` records, not archives of artifacts, so for a large share of known
malicious versions **the tarball no longer exists to analyse**.

This splits evaluation into two different measurements that must not be
conflated:

- **advisory-matching recall**, which works from labels alone
- **static-analysis precision and recall**, which requires artifacts and can
  therefore only run against the retrievable subset plus synthetic fixtures

The evaluation harness reports how many samples were attempted, how many were
actually obtained, and computes metrics only over what was analysed. The
denominator is always visible. A shrinking sample is never hidden to make a
number look better.

Control ("benign") sets are drawn from widely used packages. We do not claim
they are mathematically guaranteed clean — only that they are the packages the
ecosystem already depends on, which makes false positives against them
expensive and therefore meaningful.

---

## 10. Machine output is not a decision

`machineRecommendation` is an input to human judgement. It is stored, displayed
and audited separately from any analyst decision, and one never overwrites the
other.

`BLOCK` is deliberately hard to reach. Under meaningful uncertainty PackageGate
prefers `REVIEW`, because the cost of a wrongly blocked dependency is real and
falls on people who did nothing wrong.

---

## 11. Optional AI does not change any of the above

When enabled, the AI investigator reads an evidence bundle that has already been
produced deterministically. It explains, summarises, offers benign and malicious
interpretations, and names missing evidence.

It cannot create findings, alter the risk score, change advisory state, or
modify an analyst decision — not as policy, but because it has no write path to
any of them. Its output is schema-validated, and a failure or a malformed
response degrades the investigation to its deterministic content rather than
breaking it.

PackageGate runs fully with `AI_PROVIDER=none`, and everything in this document
applies identically whether AI is enabled or not.

---

## 12. Scope

npm only. No PyPI, NuGet, Maven, RubyGems or Go modules. No dynamic sandbox
execution. No machine-learning classification. Single-tenant, no SSO, no
multi-tenancy.

These are deliberate choices to make one ecosystem work properly rather than
several badly.
