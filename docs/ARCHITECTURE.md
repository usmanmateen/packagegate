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
apps/
  web/                 Next.js investigation UI
  api/                 Fastify HTTP API

packages/
  shared/              Domain model: Zod schemas + inferred types. No I/O.
  npm-registry/        Registry metadata, version resolution, spec parsing
  artifact-fetcher/    Tarball download + hostile-input-safe extraction
  static-analyser/     AST parsing → Finding[]
  behaviour-engine/    Finding[] + AST relationships → BehaviourChain[]
  risk-engine/         Findings + chains + intelligence → RiskAssessment
  advisory-intelligence/  GitHub Advisories / OSV lookups
  provenance/          npm attestation context
  version-analysis/    Security-relevant diff between two scans
  ai-investigator/     Optional. Explains; never decides.
  cli/                 packagegate scan | compare

workers/scanner/       Analysis process, designed to run without network
evaluation/            Reproducible precision/recall harness
fixtures/              Inert synthetic packages for analyser tests
```

`packages/shared` deliberately compiles **without Node type definitions**. It
performs no I/O and touches no filesystem, which is what lets the same domain
model be imported by the network-disabled scanner, the API, the CLI and browser
code in the Next.js app without divergence.

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
                                                        persist investigation
                                                                │
                                            ┌───────────────────┼───────────────────┐
                                            ▼                   ▼                   ▼
                                          web UI               CLI            GitHub check
```

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
| **Fastify** | Lightweight, first-class schema validation, no decorator metaprogramming. | NestJS (weight unjustified here) |
| **Drizzle** | SQL-first, generated migrations, no runtime proxy magic over a security-critical audit trail. | Prisma |
| **Babel parser** in the analyser | Error-recovering parse of hostile/minified input, one parser for CJS/ESM/TS/JSX, and a real `Scope`/`Binding` API — binding resolution is what makes honest alias tracking possible instead of text matching. | acorn (no TS), regex (not analysis) |
| **tar-stream** + `zlib` | Every entry decision is explicit and auditable. We never call `fs.symlink`, and budgets are enforced mid-stream. | High-level extractors that hide entry handling |
| **PostgreSQL** only | The workload is relational and audit-shaped. | Redis/Kafka/Elasticsearch — complexity must earn its place |

Deliberately **not** used: Kubernetes, microservices, message queues, search
clusters. None are justified by the workload, and each would be architecture
theatre.

---

## 6. Module ownership

Parallel work is safe only with disjoint file ownership. Charters live in
`.claude/agents/`.

| Owner | Modules |
| --- | --- |
| Lead | root config, `packages/shared`, `packages/risk-engine`, `packages/version-analysis`, `docs/ARCHITECTURE.md`, integration |
| Security Researcher | `docs/THREAT_MODEL.md`, `docs/RISK_MODEL.md`, `docs/LIMITATIONS.md`, risk weight tables |
| Static Analysis | `packages/static-analyser`, `packages/behaviour-engine`, related docs |
| Backend / Platform | `packages/npm-registry`, `packages/artifact-fetcher`, `packages/advisory-intelligence`, `packages/provenance`, `apps/api` |
| Frontend / Product | `apps/web` |
| Evaluation / QA | `evaluation`, `fixtures`, integration and e2e tests |
| DevSecOps | `packages/cli`, `workers/scanner`, `docker-compose.yml`, `.github` |

Implementing agents write their own colocated unit tests. QA verifies
independently and reports defects rather than editing another owner's source.

---

## 7. What this architecture does not do

Stated here so it is not inferred from silence:

- No dynamic execution or sandboxed detonation. Static analysis only in v1.
- No whole-program taint analysis. Conservative, mostly intra-file relationship
  inference — see `docs/BEHAVIOUR_ANALYSIS.md`.
- No machine-learning malware classification.
- No ecosystems other than npm.
- No claim that a package is safe. The product reports evidence and its absence.

See `docs/LIMITATIONS.md` for the full honest accounting.
