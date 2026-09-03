# PackageGate Architecture

PackageGate investigates published npm packages and answers one question:

> What evidence exists that this package/version should be trusted, reviewed,
> escalated, or blocked?

It is a Trust & Safety investigation platform, not a vulnerability lookup and not
a chatbot. The organising principle is **evidence before verdict**: every number
the product shows traces back to something a reviewer can check in the real
artifact.

---

## 1. Principles that shape the design

These are constraints on the code, not slogans.

| Principle | How the architecture enforces it |
| --- | --- |
| Analysed code is never executed | The scanner has no execution path. Nothing calls `require`, `import`, `eval`, `vm` or `child_process` on artifact content. Lint bans `eval`/`Function` project-wide. |
| Artifacts are hostile input | Extraction runs under explicit byte, count, ratio and time budgets, resolves every path against the destination root, and never writes non-regular entries. |
| The score is deterministic | The risk engine is pure code. `RiskAssessment` requires contributions that reconcile to the raw total. No model output can reach it. |
| Known intelligence ≠ heuristic suspicion | They are different `ContributionKind`s and different advisory kinds. A score always shows which produced it. |
| Machine ≠ human judgement | `machineRecommendation` and analyst `decision` are separate columns, separate API fields, separate UI elements. |
| Absence of findings is not safety | No type, endpoint or screen may express "safe". The vocabulary is `ALLOW`/`REVIEW`/`BLOCK` and `LOW_RISK`/`INSUFFICIENT_EVIDENCE`. |

---

## 2. System shape

```
packages/
  shared/            Domain model: Zod schemas + inferred types. No I/O, no Node types.
  npm-registry/      Packuments, version resolution, spec parsing. Read-only.
  artifact-fetcher/  Download, integrity verification, hostile-input-safe extraction
  static-analyser/   Babel AST + binding resolution → Finding[]
  shell-analyser/    Lifecycle command strings parsed as data, never executed
  behaviour-engine/  Findings + AST relationships → BehaviourChain[]
  risk-engine/       Deterministic scoring with family saturation → RiskAssessment
  threat-intel/      Advisory lookups; malware and vulnerability kept separate
  version-diff/      Security-relevant capability delta between two scans
  policy-engine/     Final action across behavioural, completeness and intel lanes
  cli/               scan · diff · fixture · evaluate · scan-tarball
  evaluation/        Metrics harness and control corpus

fixtures/            Inert synthetic packages for analyser tests
ml/                  Optional, disabled by default. Experiment records and datasets.
docs/                Threat model, risk model, limitations, evaluation reports
```

There is no web application or HTTP API in this release. PackageGate is a CLI and
a set of libraries; the domain model is deliberately transport-agnostic so an API
can be added later without reshaping it.

`packages/shared` deliberately compiles **without Node type definitions**. It
performs no I/O and touches no filesystem, which is what lets the same domain
model be imported by a network-disabled scanner process, the CLI, and browser
code in any future interface without divergence.

---

## 3. The pipeline

```
package spec  ──▶ parse & validate ──▶ resolve version ──▶ registry metadata
                                                                │
                                                                ▼
                                                      download tarball
                                                                │
                                    ┌───────────── TRUST BOUNDARY ─────────────┐
                                    │                                          │
                                    ▼                                          │
                              secure extraction                                │
                                    │                                          │
                                    ▼                                          │
              manifest analysis ─▶ file enumeration ─▶ AST static analysis      │
                                                                │              │
                                                                ▼              │
                                                          Finding[]            │
                                                                │              │
                                                                ▼              │
                                                   behaviour-chain analysis    │
                                    │                                          │
                                    └──────────────────────────────────────────┘
                                                                │
                    known intelligence ──┐                      │
                    provenance context ──┼──▶ deterministic risk engine
                    version comparison ──┘                      │
                                                                ▼
                                                                │
                                                                ▼
                                                               CLI
```

Everything above is implemented. Persistence, an HTTP API, a web interface and a
GitHub check are **not** in this release — see §7.

Optional AI analysis attaches **after** the risk assessment exists and can only
read it. It is not in the path that produces a score.

### The trust boundary

Everything inside the boxed region operates on attacker-controlled bytes. The
architecture keeps that region:

- **network-free** — the analyser and behaviour engine receive `{path, content}`
  in memory and perform no I/O whatsoever, so they can be moved into a
  network-disabled container without refactoring
- **credential-free** — nothing inside needs a registry token, database URL or
  API key
- **bounded** — every loop over artifact-controlled data has an explicit cap

This is why `static-analyser` takes file contents as an argument rather than a
directory path. The separation is a design constraint today and a process
boundary later.

---

## 4. Data model highlights

Full definitions live in `packages/shared/src/`. The decisions worth calling out:

**Severity and confidence are orthogonal.** Severity asks "how bad if malicious";
confidence asks "how sure are we this detection is real". A perfectly detected
`process.env.NODE_ENV` read is HIGH confidence and LOW severity. Tools that
collapse these axes end up reporting every build script as critical.

**Behaviour chains record their own reasoning.** A `BehaviourChain` carries
`links[]`, each with a `ChainLinkKind` naming exactly how two steps were
connected — `SHARED_BINDING`, `ARGUMENT_FLOW`, `PROPERTY_ACCESS`, `RETURN_VALUE`
or the deliberately weak `SEQUENTIAL_IN_SCOPE`. `maxConfidenceForLinks()` caps a
chain's confidence at its weakest link, so a chain resting only on statement
proximity can never be reported above LOW. This is the mechanism that stops
"a source and a sink both exist somewhere" from being sold as dataflow.

**Risk breakdowns must reconcile.** `contributionsReconcile()` asserts the
contributions sum to `rawTotal`. A breakdown that does not add up is a bug, and
shipping one would falsify the explainability claim.

**KNOWN_MALWARE is schema-guarded.** `RiskAssessmentSchema` refuses a
`KNOWN_MALWARE` classification unless `knownMalware` is true, which only an
authoritative feed hit can set. Heuristics cannot reach that label by any path.

**Malware and vulnerability are different claims.** `AdvisoryKind` separates
them because they demand different analyst actions. Merging them into an
"advisory count" is a common way supply-chain tools mislead.

**Failures are results, not silence.** Unparseable files become `ParseFailure`
records and failed lookups set `lookupFailed`. A scan that errored must never be
indistinguishable from a scan that found nothing — that would report a hostile
package as clean.

---

## 5. Technology decisions

| Choice | Reason | Alternative rejected |
| --- | --- | --- |
| TypeScript **6.0.3** | `typescript-eslint` declares a peer range of `<6.1.0`. Type-aware lint rules (`no-floating-promises`) matter more here than the newest compiler — a dropped promise in the scanner means a temp directory is never cleaned. | TS 7.0.2 (no lint support yet) |
| **Zod** schemas as source of truth | External input — registry responses, advisory feeds, API bodies — is untrusted. Runtime validation with inferred types beats compile-time-only assertions. | Hand-written interfaces |
| **Babel parser** in the analyser | Error-recovering parse of hostile/minified input, one parser for CJS/ESM/TS/JSX, and a real `Scope`/`Binding` API — binding resolution is what makes honest alias tracking possible instead of text matching. | acorn (no TS), regex (not analysis) |
| **tar-stream** + `zlib` | Every entry decision is explicit and auditable. We never call `fs.symlink`, and budgets are enforced mid-stream. | High-level extractors that hide entry handling |

Deliberately **not** used: Kubernetes, microservices, message queues, search
clusters. None are justified by the workload, and each would be architecture
theatre.

No database, HTTP framework or ORM is a dependency of this release. A
`docker-compose.yml` providing PostgreSQL is kept for the persistence work in
§7, but nothing currently connects to it — the CLI holds no state between runs.

---

## 6. Module ownership

Parallel work is safe only with disjoint file ownership. The boundaries and the
standards each area is held to are recorded in
[`MODULE_OWNERSHIP.md`](MODULE_OWNERSHIP.md).

Each package owns its own colocated unit tests. Cross-cutting integration
coverage and the control corpus live in `packages/evaluation` and
`packages/cli`.

The boundaries that are load-bearing for security rather than merely tidy:

- `shared` must not gain I/O or Node types — that is what keeps one domain model
  valid on both sides of the trust boundary.
- `static-analyser` and `behaviour-engine` must not gain filesystem access. They
  receive file contents, which is what allows the analysis stage to run with no
  network and no credentials.
- `risk-engine` must not gain an input from the optional ML lane.

---

## 7. What this architecture does not do

Stated here so it is not inferred from silence:

- No persistence, HTTP API or web interface. The CLI is stateless; each scan is
  computed fresh and printed.
- No dynamic execution or sandboxed detonation. Static analysis only in v1.
- No whole-program taint analysis. Conservative, mostly intra-file relationship
  inference — see `docs/BEHAVIOUR_ANALYSIS.md`.
- No machine-learning malware classification.
- No ecosystems other than npm.
- No claim that a package is safe. The product reports evidence and its absence.

See `docs/LIMITATIONS.md` for the full honest accounting.
