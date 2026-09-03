# Module boundaries and engineering standards

PackageGate is split so that the parts handling hostile input are small,
auditable, and free of the capabilities they would need to do damage. This
document records where each concern lives and the rules each area is held to.

It is a contributor's map. If you are changing behaviour, find your area here
first — several of these boundaries are load-bearing for security, not
organisational preference.

---

## Boundaries

| Module | Owns | Must not |
| --- | --- | --- |
| `shared` | Domain model: Zod schemas, inferred types, pure helpers | Perform I/O, or import Node types — the browser and a network-isolated scanner both consume this |
| `npm-registry` | Packuments, version resolution, spec parsing | Write to the registry, or send credentials |
| `artifact-fetcher` | Download, integrity verification, hostile-input-safe extraction | Create symlinks or hardlinks, execute anything, leak host paths |
| `static-analyser` | AST parsing, binding resolution, detection rules | Touch the filesystem, or `require`/`eval` analysed code |
| `shell-analyser` | Lifecycle command strings parsed as data | Execute a command string, ever |
| `behaviour-engine` | Source → transformation → sink chain inference | Emit a chain without a recorded linkage |
| `risk-engine` | Deterministic scoring, saturation, thresholds | Take input from a model, or produce a breakdown that does not reconcile |
| `threat-intel` | Advisory lookups | Merge malware and vulnerability into one claim |
| `version-diff` | Security-relevant capability delta | Present a text diff as a security finding |
| `policy-engine` | Final action from behavioural, completeness and intel lanes | Let the optional ML lane reach `BLOCK` |
| `cli` | `scan`, `diff`, `fixture`, `evaluate` | Emit non-JSON on stdout in `--json` mode |
| `evaluation` | Metrics harness and control corpus | Report a metric whose denominator is not stated |

---

## Standards by area

### Anything touching an artifact

The tarball is attacker-controlled. Budgets — compressed size, decompressed
size, per-file size, file count, path length, compression ratio, wall clock —
are enforced **during** streaming, not after. Paths are resolved and compared
against the extraction root; string inspection alone is insufficient because a
symlinked parent can make a clean-looking path escape.

Non-regular entries are drained and recorded, never materialised. Files are
created with `O_CREAT|O_EXCL` at mode 0600 so a planted symlink cannot be
followed. Cleanup is scoped and runs on every exit path, including thrown errors
and timeouts.

A guardrail test greps this source and fails on any `symlink`, `link`, `mknod`,
`chown`, `child_process`, `vm` or `eval` usage. If you need one of those, the
design is wrong.

### Detection rules

A real parser is the primary mechanism. Regex is permitted only against
already-parsed literals, and each use must be justified in a comment.

Severity and confidence are **separate axes**. Severity asks how bad this would
be if malicious; confidence asks how sure we are the detection is real and
correctly attributed. A perfectly detected `process.env.NODE_ENV` read is HIGH
confidence and LOW severity. Collapsing these axes is how scanners end up
reporting every build tool as critical.

Every rule needs a negative test: the case where it must *not* fire.

### Behaviour chains

Never emit a chain because a source and a sink both appear somewhere. Require a
demonstrable relationship, recorded as a `ChainLinkKind`, and cite the lines it
rests on. Confidence is capped by the weakest link, so a chain resting only on
statement proximity can never exceed `LOW` or unlock `BLOCK`.

This is conservative relationship inference. It is not whole-program taint
analysis and must never be described as such.

### Risk and policy

The score is computed by code. Every point traces to exactly one contribution,
and contributions must reconcile to the raw total — a breakdown that does not
add up is a bug, because shipping one falsifies the explainability claim.

`KNOWN_MALWARE` requires an authoritative feed hit; the schema refuses it
otherwise, so heuristics cannot reach that label by any path. Prefer `REVIEW`
under uncertainty. `BLOCK` is deliberately hard to reach.

### Evaluation

Never fabricate a metric. State the denominator. If samples could not be
retrieved, report how many were attempted versus obtained rather than quietly
shrinking the corpus.

False positives are the central product risk. A legitimate package the scanner
escalates is a bug report worth more than a feature.

---

## The stance that matters most

Push back on simplistic assumptions rather than encoding them:

- `postinstall` present ⇒ malware. Thousands of legitimate packages compile
  native modules and fetch platform binaries.
- Network access ⇒ malware. Telemetry and update checks are normal.
- `process.env` access ⇒ malware. `process.env.NODE_ENV` is nearly universal.
- Missing provenance ⇒ malware. Most of the registry predates the feature.
- Minified code ⇒ malware. Bundled output is ubiquitous and legitimate.

A scanner that flags everything is ignored, and an ignored scanner protects
nobody. Suspicion is not malice, and evidence comes before verdict.
