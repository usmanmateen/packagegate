# PackageGate — Threat Model

**Status:** v1 draft · **Owner:** Security Researcher · **Last reviewed:** 2026-08-09

PackageGate statically analyses npm package tarballs and produces evidence-backed
recommendations (`ALLOW` / `REVIEW` / `BLOCK`). It never installs, imports, or executes
the artefacts it analyses.

This document has two halves that are frequently conflated and must not be:

1. **Threats *to consumers of npm*** that PackageGate exists to surface (§3–§5).
2. **Threats *to PackageGate itself***, because a scanned tarball is attacker-controlled
   input to our own parsers, our own filesystem, our own logs, our own database and our
   own browser (§6–§9). This half is the larger risk. A supply-chain scanner is a
   machine that voluntarily ingests hostile archives from strangers, at scale,
   unattended. Historically that is exactly the kind of machine that gets owned.

Requirements are written as **testable assertions** with IDs (`R-*`). Every `R-*` is
expected to become at least one automated test owned by the Evaluation/QA agent. Threat
IDs (`T-*`) are stable and may be referenced from rule metadata and test names.

---

## 1. System overview and data flow

The v1 pipeline, and the intended v2 split, are the same logical stages:

```
 ① registry metadata fetch ──┐
                             ├─→ ② artifact staging ─→ ③ archive parse/extract
 ① tarball fetch ────────────┘                                  │
                                                                ▼
                                            ④ manifest + source normalisation
                                                                │
                                                                ▼
                                        ⑤ static analysis (AST, lexical, structural)
                                                                │
                                                                ▼
                                       ⑥ intelligence correlation (advisories, malware)
                                                                │
                                                                ▼
                                          ⑦ risk engine (deterministic, see RISK_MODEL)
                                                                │
                                        ┌───────────────────────┼─────────────────────┐
                                        ▼                       ▼                     ▼
                                  ⑧ database             ⑨ web UI (analyst)     ⑩ API (CI)
```

**Stages ① and ⑥ require network. Stages ③–⑦ must not.** That boundary is the single
most important structural control in this design (§5, TB-3).

---

## 2. Assets

| ID | Asset | Why an adversary cares | Primary loss |
|----|-------|------------------------|--------------|
| **A-1** | **The analyst** — a human reading findings, snippets, filenames and rendered reports | The analyst is the only component with a browser, a terminal, credentials to the platform, and the authority to overturn a verdict | Compromise of the analyst's workstation; manipulation of their judgement; wasted attention (a denial-of-attention attack is still an attack) |
| **A-2** | **The host running PackageGate** — scanner process, filesystem, credentials in its environment, network position | Ingests attacker-chosen bytes continuously; likely sits inside a CI/corporate network; likely holds registry read tokens and DB credentials | RCE, arbitrary file write, credential theft, lateral movement, use as a proxy/pivot |
| **A-3** | **The CI pipeline consuming verdicts** — the gate that turns `ALLOW`/`BLOCK` into build outcomes | It is the actual control being bypassed. An adversary does not need to own PackageGate; they only need one `ALLOW` | Malicious dependency admitted to a build; or (inverted) mass false `BLOCK` halting all builds |
| **A-4** | **The database** — findings, evidence snippets, verdicts, scan history, intel cache | Contains attacker-controlled strings by construction. Also the audit record that would prove an attack happened | Injection, poisoning of historical baselines, destruction of forensic record, exfiltration of customer dependency inventories |
| **A-5** | **The verdict itself** — its integrity, provenance and reproducibility | A verdict that cannot be reproduced or attributed cannot be defended when it is contested | Loss of the ability to justify a `BLOCK` to a maintainer, or an `ALLOW` to an incident review |
| **A-6** | **The evidence store** — raw snippets, byte offsets, retained tarball hashes | npm's unpublish policy allows a version to disappear; without retention the evidence for a past verdict evaporates | Non-reproducible history; inability to re-derive a decision. See [npm unpublish policy](https://docs.npmjs.com/policies/unpublish) — a version may be unpublished within 72 hours, and `package@version` can never be reused afterwards |

**A-4 note (customer inventory sensitivity):** the set of packages an organisation asks
PackageGate about *is itself* a dependency inventory. Aggregated scan requests are a
reconnaissance asset for an attacker choosing what to typosquat. Treat query logs as
sensitive.

---

## 3. Adversaries

Capability tiers: **C1** can publish packages; **C2** can publish *and* has taken over a
trusted identity; **C3** additionally has read access to PackageGate's rules/behaviour;
**C4** additionally targets PackageGate's operators specifically.

### ADV-1 — Malicious publisher (C1)
Creates accounts and publishes purpose-built malicious packages. Cheap, high volume, low
sophistication in the median case. Publishing is nearly free; name reservation is
permanent (a `package@version` can never be re-used, per npm's unpublish policy), so the
namespace steadily accumulates hostile artefacts.

*Goals:* credential theft (`NPM_TOKEN`, `GITHUB_TOKEN`, cloud keys, wallets), reverse
shells, cryptomining, initial access.
*Observable to us:* usually yes — this population is the easiest to catch and is what
intelligence feeds already cover well.

### ADV-2 — Compromised maintainer account (C2)
The highest-impact adversary. A legitimate, long-lived, widely-depended-upon package
publishes one bad version. GitHub's own post-incident write-up describes the Shai-Hulud
attack of 14 September 2025 as compromising **over 500 packages through maintainer
account takeovers**, and drove npm's response: removal of classic tokens, granular tokens
limited to short lifetimes, migration from TOTP to FIDO 2FA, and a push toward trusted
publishing ([GitHub blog](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)).

*Key property:* **every reputational signal we might use is legitimately good.** High
download count, long history, real repository, real maintainer, possibly valid provenance
and a valid registry signature. Provenance attests to *where and how the artefact was
built*, not to *what the code does* — npm states plainly that established provenance
"does not guarantee the package has no malicious code"
([npm docs](https://docs.npmjs.com/generating-provenance-statements)). A CI-compromise or
a stolen OIDC-privileged workflow can produce a fully attested malicious build.

*Design consequence:* reputation must never be able to buy an `ALLOW` past behavioural
evidence, and **version-to-version behavioural diffing is the highest-value detection
strategy we have for this adversary** (T-ANL-07).

### ADV-3 — Typosquatter / brandjacker (C1)
Registers `lodahs`, `reqeusts`, `@types/`-shaped lookalikes, homoglyph variants, or
scope-stripped names (`node-fetch` vs `@org/node-fetch`).

*Trap:* naive name-distance rules generate enormous false positives against the
legitimate population of forks, ports, community reimplementations and `-fork` /
`-patched` / `-next` variants. Name similarity is only meaningful *combined with* absence
of shared maintainer, repository or provenance linkage.

### ADV-4 — Dependency-confusion attacker (C1)
Publishes a public package matching a private/internal name, with an inflated version so
that resolution prefers it. Alex Birsan's original disclosure documents the mechanism:
where a name exists in both a private and a public source, the manager "defaults to
installing from the source with the **higher version number**", and the payload ran via
install scripts with DNS exfiltration
([Birsan, 2021](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)).

*Detection posture:* the strongest tells (internal-looking scope, first publish at
`99.x.x`, no repository, tiny package, install script only) are metadata-level, cheap,
and reasonably specific — but the *decisive* fact (is this name private to the consumer?)
is knowable only by the consumer, not by us. **PackageGate must expose this as a
consumer-configurable input, not guess it.**

### ADV-5 — PackageGate-aware evader (C3)
Knows the product exists, has read the docs, possibly has run it. Two sub-goals:

- **ADV-5a — Evade.** Split behaviour across modules so no single file shows a chain;
  route data through computed member access, `Reflect`, `globalThis[atob('cHJvY2Vzcw==')]`,
  string concatenation, or a `Proxy`, so alias resolution fails; hide the payload where we
  do not look (a native `.node` binary, a WASM blob, a `bin` shim, a `binding.gyp`, a
  build artefact); rely on the fact that lifecycle scripts run *before* any code analysis
  matters (see T-ANL-05); or exploit a **parser differential** so our tar reader and npm's
  installer see different archive members (T-EXT-08).
- **ADV-5b — Blend.** Do the malicious thing in exactly the idiom a legitimate package
  uses: fetch a "prebuilt binary" from a hostile host inside a `postinstall`, mimicking
  `node-pre-gyp`/`prebuild-install`. This is the hardest case and it is *why the risk
  model refuses to score install-script-plus-download as malicious on its own*.

### ADV-6 — PackageGate-aware weaponiser (C3/C4)
Does not want to evade us. Wants to **use** us. Distinct sub-goals:

- **Weaponise the verdict against a competitor or a maintainer.** Craft a package, or
  contribute code to someone else's package, engineered to trip a documented rule chain so
  that PackageGate publishes a `BLOCK` against an innocent project. Our verdict becomes a
  denial-of-service and a reputational attack delivered by us, at our cost.
- **Weaponise the analyst's browser.** Snippets are attacker-authored source. If any
  render path is unsafe, a scanned package becomes stored XSS in an authenticated console
  (T-UI-01).
- **Weaponise the queue.** Publish thousands of packages whose only purpose is to sit at
  the `REVIEW` threshold, saturating analyst attention so the real payload is triaged by an
  exhausted human at 3am. Attention is a finite, attackable resource.
- **Weaponise the gate.** If a mass false-`BLOCK` breaks every build in an organisation,
  the organisation's rational response is to disable PackageGate. **The adversary's win
  condition is our removal from the pipeline, and we can hand them that win ourselves.**
  This is the single strongest argument for the false-positive discipline in
  `RISK_MODEL.md`.
- **Poison the baseline.** If we compare a version against its predecessors, an adversary
  who controls a package can normalise malicious-looking structure over several benign
  releases first, so the malicious release shows a small diff. Baselines must be treated as
  attacker-influenced data (T-ANL-08).

---

## 4. Threats to npm consumers that PackageGate is meant to surface

Recorded for completeness; detection design lives in `RISK_MODEL.md`.

| ID | Threat | Notes |
|----|--------|-------|
| T-NPM-01 | Install-time code execution | `preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, `postprepare` all run during `npm install`, in that order ([npm scripts docs](https://docs.npmjs.com/cli/v11/using-npm/scripts)). Unattended, pre-review, full user privileges. `--ignore-scripts` exists but defaults to `false` ([npm-install config](https://docs.npmjs.com/cli/v11/commands/npm-install)) |
| T-NPM-02 | Implicit `node-gyp` execution | With a root `binding.gyp` and no `install`/`preinstall` script, npm defaults `install` to `node-gyp rebuild` — **code execution with no `scripts` entry at all**. A scanner that only reads `scripts` misses this entirely |
| T-NPM-03 | Credential and token theft | `~/.npmrc`, `~/.aws/credentials`, `~/.ssh/`, `~/.docker/config.json`, CI env vars |
| T-NPM-04 | Self-replication / worm | Steal a publish token, then publish to every package that token can reach (Shai-Hulud class) |
| T-NPM-05 | Dependency confusion | See ADV-4 |
| T-NPM-06 | Typosquatting / brandjacking | See ADV-3 |
| T-NPM-07 | Manifest confusion | The registry does not validate that the manifest in the PUT body matches the `package.json` inside the tarball; the installer uses the **tarball's** copy. Independent follow-up found ~800 packages with metadata discrepancies, 18 deliberately exploiting the divergence, and reported no registry-side fix ([JFrog retrospective, Mar 2024](https://jfrog.com/blog/npm-manifest-confusion-six-months-later/)) |
| T-NPM-08 | Malicious prebuilt binary / WASM | Payload never appears in JavaScript source |
| T-NPM-09 | Protestware / intentional sabotage by the legitimate author | Behaviourally identical to malware; ethically and legally different |
| T-NPM-10 | Post-publish state change | `dist-tags` move, versions are unpublished, maintainer sets change — the registry is mutable around an immutable artefact |

**T-NPM-07 is a hard requirement on our architecture, not a rule:**

> **R-MAN-01** — All manifest-derived analysis MUST read `package.json` from **inside the
> tarball**. Registry metadata MAY be fetched for context but MUST be stored in a separate
> field and MUST NOT be the source of truth for `scripts`, `bin`, `dependencies` or
> `files`.
> *Test:* a fixture whose registry manifest omits a `postinstall` present in the tarball
> yields the finding and a `meta.tarball_manifest_mismatch` result.

---

## 5. Trust boundaries

| ID | Boundary | What crosses | Control |
|----|----------|--------------|---------|
| **TB-1** | Internet → fetcher | Registry JSON, tarball bytes, intel feeds | TLS; pin expected integrity; treat every byte as hostile; the fetcher writes **only** to a quarantine area |
| **TB-2** | Fetcher → artifact transfer | An opaque, content-addressed blob plus a signed metadata envelope | The transfer format is a narrow, versioned, schema-validated contract — not "a directory the scanner also reads" |
| **TB-3** | Artifact transfer → **network-disabled scanner** | Tarball bytes only | **The scanner has no egress, no DNS, no credentials, no registry token.** This is the boundary that makes stage-⑤ RCE survivable |
| **TB-4** | Scanner → risk engine | Structured `Finding` / `Chain` records with typed fields | Findings are data, never code; no field is `eval`'d, templated into a query, or used as a path |
| **TB-5** | Risk engine → database | Verdicts and evidence, all containing attacker-controlled strings | Parameterised queries; length caps; encoding at write; the DB is *not* a sanitisation layer |
| **TB-6** | API/DB → analyst browser & CI | Rendered snippets, filenames, verdicts | Output encoding at render; strict CSP; machine-readable verdicts are schema-validated |

### The intended v2 split (stated now so v1 does not foreclose it)

```
  ┌─────────────────────────────┐        ┌──────────────────────────────────────┐
  │ FETCHER                     │        │ SCANNER                              │
  │ • network: YES              │  blob  │ • network: NONE (deny-all egress)    │
  │ • registry credentials: YES │ ─────► │ • credentials: NONE                  │
  │ • parses: HTTP + JSON only  │ + hash │ • parses: tar, gzip, JS/TS, JSON     │
  │ • never opens the tarball   │        │ • filesystem: ephemeral, RO except   │
  │ • no analysis logic         │        │   one bounded scratch dir            │
  └─────────────────────────────┘        └──────────────────────────────────────┘
```

Rationale: the component with the *dangerous parsers* (tar, gzip, JS) must be the
component with *nothing worth stealing and nowhere to send it*. The component with
credentials and egress must have an attack surface small enough to reason about (HTTP +
JSON, no archive handling).

> **R-ARCH-01** — The scanner MUST run with egress denied at the network-namespace or
> sandbox level, not by convention.
> *Test:* an integration test in which the scanner process attempts a DNS lookup and an
> outbound TCP connect; both MUST fail, and the attempt MUST be logged.
>
> **R-ARCH-02** — The scanner process MUST NOT have registry, database or cloud
> credentials in its environment.
> *Test:* assert the scanner's `process.env` allowlist contains no secret-shaped keys;
> fail the build if a new one appears.
>
> **R-ARCH-03** — v1 MUST NOT introduce APIs that make the v2 split impossible (e.g. an
> analyser that lazily fetches a dependency mid-scan).
> *Test:* scanner package dependency graph contains no HTTP client; enforced by lint rule.

---

## 6. Attack surface of PackageGate itself: the hostile tarball

**Assumption:** the tarball is fully attacker-controlled, well-formed only where it suits
the attacker, and specifically crafted against the tools listed in our own public
documentation. Every item below has been observed in the wild against real archive
tooling.

### 6.1 Extraction and archive parsing

| ID | Vector | Mechanism |
|----|--------|-----------|
| T-EXT-01 | **Zip-slip / path traversal** | Entry names like `../../../../home/ci/.ssh/authorized_keys`. Disclosed by Snyk in June 2018 across tar, jar, war, cpio, apk, rar and 7z; the exploit needs only a crafted archive plus extraction code that omits path validation ([Snyk research](https://security.snyk.io/research/zip-slip-vulnerability)) |
| T-EXT-02 | **Absolute paths / drive-relative paths** | `/etc/cron.d/x`, `C:\...`, `\\?\`, UNC paths |
| T-EXT-03 | **Symlink escape** | Archive contains a symlink `pkg/x → /` followed by `pkg/x/etc/passwd`. node-tar's CVE-2021-32803 was exactly this class: a directory-cache optimisation allowed a directory to be replaced by a symlink, bypassing symlink checks and permitting writes to arbitrary locations |
| T-EXT-04 | **Hardlink escape** | Hardlink targets outside the root; bypasses symlink-specific checks |
| T-EXT-05 | **Decompression bomb** | Highly-compressible content with inflated size headers. node-tar CVE-2026-59873 (Critical) — the library "does not enforce a hard upper bound on archive size or the volume of decompressed data processed during extraction", and the existing `maxReadSize` option only bounds internal read chunks, **not** cumulative bytes written ([GHSA-23hp-3jrh-7fpw](https://github.com/advisories/GHSA-23hp-3jrh-7fpw)) |
| T-EXT-06 | **Entry-count / nesting exhaustion** | 10⁶ tiny entries; 4000-deep directory nesting; extremely long paths. node-tar GHSA-r292-9mhp-454m is an uncatchable stack-overflow DoS via uncontrolled recursion on crafted long-path tars |
| T-EXT-07 | **Malformed-header parser crash** | node-tar CVE-2026-59871 (PAX numeric path type confusion → process crash), CVE-2026-59874 (negative entry size → infinite loop), CVE-2026-59875 (NUL byte in PAX path/linkpath → uncaught exception) |
| T-EXT-08 | **Parser interpretation differential (file smuggling)** | **The most important item in this table.** node-tar CVE-2026-53655 / [GHSA-vmf3-w455-68vh](https://github.com/advisories/GHSA-vmf3-w455-68vh), CWE-436: node-tar applied a PAX `size=` override to intermediary GNU long-name/long-link headers, desynchronising its stream, while GNU tar, libarchive and Python `tarfile` stayed synchronised. The advisory states the impact directly — a scanner using node-tar "might report 'no suspicious files detected'" while the same archive extracted with system `tar` "reveals hidden malicious content", defeating scanner-versus-extractor workflows. **A verdict is only valid for the member set our parser saw.** |
| T-EXT-09 | **Case/Unicode collision** | `Package.json` vs `package.json`; NFC/NFD variants; trailing-dot and trailing-space names that resolve differently per OS |
| T-EXT-10 | **Special file types** | Device nodes, FIFOs, sockets, setuid bits in the archive |

**Mitigations:**

> **R-EXT-01** — Extraction MUST be *virtual by default*: entries are streamed to memory or
> to content-addressed blobs, never materialised at attacker-chosen paths. If a real
> filesystem extraction is ever required, every entry's resolved real path MUST be a strict
> descendant of the extraction root, checked after `realpath` resolution of each parent
> component.
> *Test:* fixtures `traversal.tgz`, `absolute.tgz`, `symlink-escape.tgz`,
> `hardlink-escape.tgz` each produce **zero** filesystem writes outside the root and one
> `EXTRACT_PATH_ESCAPE` finding.
>
> **R-EXT-02** — Symlinks and hardlinks MUST NOT be followed or created. They are recorded
> as metadata findings with their raw target string and skipped.
> *Test:* symlink fixture yields a `SYMLINK_ENTRY` finding, no link created on disk.
>
> **R-EXT-03** — Hard, enforced limits, configurable but with safe defaults, applied as a
> **running total** and not per-entry: total decompressed bytes (default 512 MiB), entry
> count (default 50 000), path depth (default 64), single-entry size (default 64 MiB),
> path byte length (default 1024), wall-clock per scan (default 120 s), peak RSS.
> Exceeding any limit aborts the scan with a `RESOURCE_LIMIT_EXCEEDED` outcome that is
> **surfaced as `INSUFFICIENT_EVIDENCE`, never as `ALLOW`**.
> *Test:* a 10 GiB-expanding bomb aborts in under 10 s having written < 600 MiB, and the
> scan result classification is `INSUFFICIENT_EVIDENCE`.
>
> **R-EXT-04** — Archive parsing MUST run in a resource-capped child process/worker whose
> death is a normal, handled outcome. An uncaught exception or OOM in the parser MUST NOT
> terminate the service or be reported as a clean scan.
> *Test:* malformed-header fixtures (NUL in PAX path, negative size, deep recursion)
> produce a recorded scan failure; the parent process survives all of them.
>
> **R-EXT-05** — **Differential parse check.** The member list MUST be derived by our
> primary parser and independently verified by a second, structurally different
> implementation. Any disagreement in the set of member names, sizes or types is itself a
> finding (`archive.parser_disagreement`) and forces `INSUFFICIENT_EVIDENCE`.
> *Test:* a PAX-size-override smuggling fixture (CVE-2026-53655 shape) produces
> `archive.parser_disagreement` rather than a clean result.
>
> **R-EXT-06** — Archive-handling dependencies MUST be pinned, and CI MUST fail on any
> advisory affecting them. Our tar reader is a *security control*, not a utility.
> *Test:* `npm audit` gate on the scanner package treats any advisory on the extraction
> dependency set as build-breaking.

### 6.2 Manifest and JSON parsing

| ID | Vector | Mechanism |
|----|--------|-----------|
| T-JSON-01 | **Prototype pollution via parsed JSON** | Verified locally on Node v24.19.0: `JSON.parse('{"__proto__":{"x":1}}')` creates an *own, enumerable data property* named `__proto__` and does **not** pollute anything by itself. The danger is entirely downstream — a naive recursive merge of that object **does** set `Object.prototype.x`, and `Object.assign(target, parsed)` uses `[[Set]]`, which invokes the `__proto__` setter and **silently changes the target's prototype**. Config merging, defaults application and object spread over parsed manifests are the real sinks |
| T-JSON-02 | **Type confusion in `package.json` fields** | Fields legitimately have multiple shapes: `bin` is string *or* object, `repository` is string *or* object, `bundleDependencies` is array *or* boolean ([package.json docs](https://docs.npmjs.com/cli/v11/configuring-npm/package-json)). An attacker supplies shapes that are *not* documented: `scripts` as an array, `name` as an object, `dependencies` as a string, `version` as a number, `files` as a nested array. Naive code does `pkg.scripts.postinstall` and throws, or does `String(pkg.name)` and gets `[object Object]` |
| T-JSON-03 | **Adversarial magnitudes** | 100 MB single JSON string; 10⁵ keys; 200-level nesting; duplicate keys with different values (last-wins in JS, but not in every parser — another differential); `-0`, `1e999`, precision-losing integers |
| T-JSON-04 | **Unicode direction and confusables in metadata** | RTL override in `name`/`description` so the rendered name differs from the stored name |
| T-JSON-05 | **Manifest divergence** | See T-NPM-07 / R-MAN-01 |

> **R-JSON-01** — All parsed JSON MUST be passed through a schema validator that produces
> a **new, null-prototype object graph**; the raw parse result MUST NOT escape the parsing
> module. `__proto__`, `constructor` and `prototype` keys are dropped and recorded as a
> finding.
> *Test:* a manifest with `__proto__`, `constructor.prototype` and deep-merge bait leaves
> `Object.prototype` and `Array.prototype` unmodified across the whole scan; asserted by a
> global sentinel check before and after every scan in the test suite.
>
> **R-JSON-02** — Merge/clone helpers MUST reject `__proto__`/`constructor`/`prototype`
> keys and MUST be the only merge implementations in the codebase.
> *Test:* lint rule bans `Object.assign` and object spread on unvalidated parse output; a
> unit test asserts the sanctioned merge is pollution-safe.
>
> **R-JSON-03** — Every manifest field access MUST go through a typed accessor that
> returns a discriminated result (`{ok, value}` / `{unexpectedType, raw}`). An unexpected
> type is a **finding**, never a crash and never a silent coercion.
> *Test:* a fixture matrix supplying each documented field as each wrong JSON type
> produces `manifest.field_type_unexpected` findings and zero exceptions.
>
> **R-JSON-04** — Size and depth caps on manifest parsing (default 8 MiB, depth 64, 20 000
> keys); exceeding them is `INSUFFICIENT_EVIDENCE`.

### 6.3 Source parsing and analysis

| ID | Vector | Mechanism |
|----|--------|-----------|
| T-ANL-01 | **Parser DoS via pathological source** | Deeply nested expressions (`((((…))))`), a single 50 MB line, 10⁵ chained ternaries, template-literal nesting, regex-literal ambiguity, or an intentionally exponential-blowup pattern for the specific parser we name in our docs |
| T-ANL-02 | **ReDoS in our own rules** | Any regex we ship is attacker-targetable input-side. The canonical demonstration is `ansi-regex` CVE-2021-3807 / [GHSA-93q8-gq69-wqmw](https://github.com/advisories/GHSA-93q8-gq69-wqmw): the *ANSI-stripping regex itself* backtracked exponentially on malformed escape sequences. The tool you reach for to sanitise terminal output is itself a ReDoS vector. Evil-regex shapes are grouping-plus-repetition with overlapping alternation, e.g. `(a+)+$`, `(a|aa)+$` ([OWASP](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)) |
| T-ANL-03 | **Analyser memory exhaustion** | An AST that is small on disk and enormous in memory; symbol tables that grow with file count × identifier count |
| T-ANL-04 | **Non-JS content in JS positions** | A 300 MB "`.js`" that is a video; a `.js` that is minified WASM base64; UTF-16/BOM/encoding tricks that shift byte offsets so our stored evidence points at the wrong bytes |
| T-ANL-05 | **Payload outside analysable code** | Native `.node` binaries, `.wasm`, `binding.gyp` (T-NPM-02), shell scripts, `bin` shims, git submodule references, `patches/` directories |
| T-ANL-06 | **Analysis-order side effects** | Any rule that resolves a path, opens a file relative to the package, or (worst) `require`s something from the package |
| T-ANL-07 | **Evasion of diffing** | Republishing an unchanged-looking version whose behaviour differs only in a native binary or a data file |
| T-ANL-08 | **Baseline poisoning** | See ADV-6; prior versions used as "known good" are attacker-supplied |

> **R-ANL-01** — Parsing and rule evaluation MUST be per-file time-bounded (default 2 s) and
> memory-bounded, in a worker that can be killed. Timeout produces
> `analysis.file_unparsed` and reduces the scan's coverage metric.
> *Test:* pathological-source fixtures each complete or abort within budget; the scan
> reports reduced coverage and cannot return `ALLOW` if coverage falls below threshold.
>
> **R-ANL-02** — No regex applied to package-controlled content may contain nested
> quantifiers or overlapping alternation under repetition. Every such regex MUST be
> statically checked in CI and MUST have a linear-time fuzz test.
> *Test:* a CI job runs a ReDoS static analyser over all rule regexes and fails the build
> on any finding; a fuzz harness asserts sub-linear-in-catastrophe runtime on adversarial
> inputs.
>
> **R-ANL-03** — **The scanner MUST NEVER `require`, `import`, `eval`, `new Function`, `vm`-run,
> or shell out to anything derived from the package.** No exceptions, including for
> "just reading the config".
> *Test:* a lint rule bans dynamic `require`/`import`/`vm`/`child_process` in the scanner
> package; a runtime guard fails the test suite if the scanner spawns any process during a
> scan.
>
> **R-ANL-04** — Every finding MUST carry `{file, byteStart, byteEnd, encodingDetected,
> extractor, ruleVersion}` so evidence remains verifiable independent of rendering.
> *Test:* re-slicing the stored tarball at the recorded offsets reproduces the snippet
> byte-for-byte.
>
> **R-ANL-05** — Un-analysable content (native binaries, WASM, unparsed files, encoded
> blobs) MUST be enumerated and MUST reduce the reported `analysis_coverage`.
> *Test:* a package that is 90 % `.node` binary cannot return `ALLOW`.

### 6.4 Filenames, logs and terminal output

| ID | Vector | Mechanism |
|----|--------|-----------|
| T-LOG-01 | **NUL bytes in names** | Truncate strings at different points in different consumers; produce path-handling differentials; crash parsers (node-tar CVE-2026-59875 is precisely a NUL-in-PAX-path crash) |
| T-LOG-02 | **Newlines / CR in names** | **Log injection.** A filename containing `\n` forges log lines, fabricates a clean verdict in the audit trail, or breaks line-oriented log shipping and SIEM parsing |
| T-LOG-03 | **ANSI escape sequences in names/snippets** | An analyst who `cat`s, `grep`s or tails scan output gets their terminal rewritten: cursor movement to overwrite a `BLOCK` with `ALLOW`, colour abuse, window-title setting, and on some terminals clipboard or paste-buffer manipulation. `\r` alone is enough to hide text |
| T-LOG-04 | **Bidi/RTL overrides in names and source** | The displayed order of characters differs from the logical order; an analyst reading a snippet sees different code than the parser did |
| T-LOG-05 | **Enormous names/values in logs** | Log-volume DoS; per-line truncation that splits a multi-byte character and corrupts the log stream |

> **R-LOG-01** — No string derived from a package (filename, manifest value, snippet,
> error message) may be written to a log, terminal, filename, or error string in raw form.
> A single sanctioned encoder MUST be applied at the boundary: **encode** control
> characters (`U+0000`–`U+001F`, `U+007F`), bidi controls (`U+202A`–`U+202E`,
> `U+2066`–`U+2069`) and `U+001B` to a visible escaped form (`\x1b`), then truncate to a
> byte cap with an explicit ellipsis marker.
> *Rationale for encode-not-strip:* stripping destroys evidence and, per T-ANL-02, the
> stripping regex is itself a ReDoS candidate. The encoder MUST be a linear-time character
> scan, **not a regex**.
> *Test:* fixtures with `\n`, `\r`, `\x00`, `\x1b[2J\x1b[H`, `U+202E` in filenames produce
> single-line, fully-escaped log records; a test asserts the encoder contains no regex and
> is O(n).
>
> **R-LOG-02** — Logs MUST be structured (JSON), with package-derived values only ever in
> designated value positions, never interpolated into a message template.
> *Test:* every emitted log line parses as exactly one JSON object under adversarial
> filename fixtures.
>
> **R-LOG-03** — Any CLI output path MUST apply R-LOG-01 unconditionally, including when
> not attached to a TTY.

### 6.5 Web UI and API

| ID | Vector | Mechanism |
|----|--------|-----------|
| T-UI-01 | **Stored XSS via rendered snippets** | Snippets are attacker-authored source and *will* contain `<script>`, `</script>` mid-string, `<img onerror>`, `javascript:` URLs, and payloads designed to break out of a syntax highlighter's tokenisation. Rendered in an authenticated console this is session theft, verdict tampering, and pivot to A-1/A-4 |
| T-UI-02 | **Highlighter/markdown injection** | Passing a snippet through a markdown renderer, or a highlighter that emits raw HTML, reintroduces XSS after correct escaping upstream |
| T-UI-03 | **`javascript:` / `data:` URLs from manifest fields** | `repository.url`, `homepage`, `bugs.url` rendered as clickable links |
| T-UI-04 | **CSV/formula injection** | Exported reports opened in a spreadsheet; a package name beginning `=`, `+`, `-`, `@`, tab or CR executes on open |
| T-UI-05 | **Rendering DoS** | A 40 MB single-line snippet, or 10⁵ findings, hanging the analyst's browser |
| T-UI-06 | **API response injection into CI** | A CI system that string-interpolates our JSON into a shell command; a package name containing `$(...)` or backticks |
| T-UI-07 | **SSRF via manifest URLs** | Any server-side fetch of `repository.url` or `homepage` — including for "repo linkage" checks — is an attacker-chosen server-side request into our network |

> **R-UI-01** — Snippets MUST be rendered as **text nodes** only. No `innerHTML`,
> `dangerouslySetInnerHTML`, `v-html`, or template raw-interpolation anywhere in a path
> that can carry package-derived data. Syntax highlighting, if present, MUST tokenise into
> DOM elements with text-node content, never emit an HTML string.
> *Test:* an XSS corpus (including `</script>`, broken tags, `<svg onload>`, and
> highlighter-confusing input) is rendered and asserted to produce zero script execution
> and zero elements outside the expected node types; a lint rule bans raw-HTML sinks
> repo-wide.
>
> **R-UI-02** — A strict CSP MUST be served: `default-src 'none'`, `script-src 'self'`
> (no `unsafe-inline`, no `unsafe-eval`), `object-src 'none'`, `frame-ancestors 'none'`,
> `base-uri 'none'`.
> *Test:* an integration test asserts the response headers; a test page attempting inline
> script execution is blocked.
>
> **R-UI-03** — URLs from package metadata MUST be scheme-allowlisted (`https:`, `http:`)
> before rendering, MUST carry `rel="noopener noreferrer"`, and MUST be visually marked as
> untrusted.
> *Test:* `javascript:`, `data:`, `vbscript:` and scheme-relative URLs render as inert text.
>
> **R-UI-04** — The server MUST NOT dereference any URL taken from package metadata.
> Repository-linkage checks MUST use an allowlisted host set and a dedicated egress path,
> or not exist in v1.
> *Test:* a manifest with `repository.url` pointing at `http://169.254.169.254/` produces
> no outbound request.
>
> **R-UI-05** — Snippets MUST be truncated server-side (default 512 bytes, hard cap 4 KiB)
> and findings paginated; the UI MUST remain responsive with 10⁵ findings.
>
> **R-UI-06** — Exported CSV/TSV fields MUST be prefixed-escaped against formula
> injection.
>
> **R-UI-07** — API responses MUST be strictly schema-validated on the way out, with
> documented maximum lengths, so a CI consumer can rely on shape.

### 6.6 Storage and intelligence ingestion

| ID | Vector | Mechanism |
|----|--------|-----------|
| T-DB-01 | **SQL/NoSQL injection via package-derived strings** | Every stored field is attacker-controlled |
| T-DB-02 | **Storage exhaustion** | A package producing 10⁶ findings, or 100 MB of snippets |
| T-DB-03 | **Encoding corruption** | Invalid UTF-8, lone surrogates, NUL in text columns (PostgreSQL rejects `\0` in `text`) — a crash on write is an availability bug *and* an evidence-integrity bug |
| T-DB-04 | **Intel feed poisoning / mis-ingestion** | Feeds are third-party data. OSSF explicitly states "false positives may be present in our dataset from time-to-time" and provides withdrawal and per-version false-positive marking ([ossf/malicious-packages](https://github.com/ossf/malicious-packages)). GitHub's own database separates *reviewed*, *unreviewed* (auto-imported from NVD "without validity checks", not even used for Dependabot alerts) and *malware* advisories ([GitHub docs](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database)) |
| T-DB-05 | **Alias-graph false corroboration** | OSV `aliases` are symmetric and transitive ([OSV schema](https://ossf.github.io/osv-schema/)). Two feeds that both mirror one upstream GHSA are **one** source, not two. Counting them as independent corroboration manufactures confidence from nothing |
| T-DB-06 | **Stale withdrawal** | OSV records carry a `withdrawn` timestamp; caching a withdrawn malware record means we keep blocking a cleared package |

> **R-DB-01** — Parameterised queries only; no string-built SQL anywhere.
> *Test:* lint ban on query concatenation; an injection corpus in package names/versions.
>
> **R-DB-02** — Per-scan caps on finding count (default 5 000) and total evidence bytes
> (default 4 MiB), with explicit truncation markers recorded in the result.
>
> **R-DB-03** — All stored strings MUST be validated as well-formed UTF-8 with NUL and lone
> surrogates encoded at the storage boundary; the raw bytes remain recoverable from the
> retained tarball via R-ANL-04 offsets.
>
> **R-DB-04** — Every intelligence record MUST retain `{sourceId, sourceTier, recordId,
> aliases[], fetchedAt, withdrawn}`. Records MUST NOT be merged into a single opaque
> "known bad" boolean.
> *Test:* a verdict citing intelligence can name the exact source record and its tier.
>
> **R-DB-05** — Corroboration counting MUST deduplicate by transitive alias closure before
> counting independent sources.
> *Test:* two feeds mirroring one GHSA count as one source and do not satisfy the
> two-source `BLOCK` condition.
>
> **R-DB-06** — `withdrawn` records MUST be honoured within one feed refresh cycle, and a
> withdrawal MUST trigger re-evaluation of affected cached verdicts.
> *Test:* injecting a withdrawal into the feed fixture flips the cached verdict on next
> refresh.

### 6.7 Fetcher-side surface

| ID | Vector | Mitigation |
|----|--------|------------|
| T-NET-01 | Registry impersonation / MITM | TLS with certificate validation; no `NODE_TLS_REJECT_UNAUTHORIZED=0` under any flag (**R-NET-01**, test: assert the env var is unset and pinned) |
| T-NET-02 | Tarball substitution | Verify `dist.integrity`/`shasum` before the artefact crosses TB-2. npm signs `${name}@${version}:${dist.integrity}` with ECDSA (`ecdsa-sha2-nistp256`), and `npm audit signatures` verifies both registry signatures and provenance attestations ([npm registry signatures](https://docs.npmjs.com/about-registry-signatures), [npm-audit](https://docs.npmjs.com/cli/v11/commands/npm-audit)). **R-NET-02**: signature/integrity verification result is recorded as evidence, and a *failure* is a finding, not a silent retry |
| T-NET-03 | Redirect chain to internal hosts (SSRF) | Allowlist final hosts; cap redirects; forbid non-public IP destinations (**R-NET-03**) |
| T-NET-04 | Response-size DoS | Cap response bytes before decompression; cap `Content-Encoding` expansion (**R-NET-04**) |
| T-NET-05 | Fetcher credential theft | Scoped, short-lived, read-only registry credentials; never present past TB-3 (R-ARCH-02) |
| T-NET-06 | Time-of-check/time-of-use | Record the exact tarball digest analysed; verdicts are bound to a digest, not a version string (**R-NET-05**) |

---

## 7. Weaponising PackageGate against its own users

Restated as first-class threats because they are the ones most likely to be
under-designed.

| ID | Threat | Mitigation |
|----|--------|------------|
| T-WPN-01 | **Engineered false `BLOCK`** against an innocent project | `BLOCK` requires either tiered authoritative intelligence or ≥2 independent evidenced chains (see `RISK_MODEL.md`). **R-WPN-01:** every `BLOCK` MUST cite either a named intelligence record or ≥2 chains with named evidence spans; a `BLOCK` with neither is a bug that fails the build |
| T-WPN-02 | **Public verdict as reputational attack** | **R-WPN-02:** verdicts about third-party packages MUST NOT be published externally without a documented notification-and-appeal path and a named human approver. A `BLOCK` is an accusation about a real person |
| T-WPN-03 | **Analyst-attention exhaustion** | **R-WPN-03:** the engine MUST emit a triage-priority signal and per-tenant `REVIEW` volume metrics; a sustained rise in `REVIEW` rate is an alertable condition, treated as a possible attack, not just a tuning issue |
| T-WPN-04 | **Gate abandonment via mass false positives** | The entire false-positive discipline in `RISK_MODEL.md`; **R-WPN-04:** a benign-corpus regression suite MUST run on every rule/weight change, and any increase in `REVIEW` rate over that corpus blocks the change until justified |
| T-WPN-05 | **Rule disclosure as an evasion oracle** | Accepted and documented in `LIMITATIONS.md`. We choose explainability over secrecy: a scanner whose reasoning cannot be inspected cannot be trusted, audited, or contested. Mitigate by depending on *behavioural structure* (chains) rather than easily-permuted literals, and by never letting a single rule be decisive |
| T-WPN-06 | **Verdict spoofing in CI** | **R-WPN-05:** API responses MUST be authenticated and integrity-protected; CI integrations MUST fail closed on a malformed or unauthenticated response, never treat "no verdict" as `ALLOW` |
| T-WPN-07 | **Baseline poisoning of diff analysis** | **R-WPN-06:** diff-derived findings MUST record which baseline versions were used and MUST be down-weighted when the baseline set is short, recent, or published by the same account within a narrow window |

---

## 8. Explicit non-goals for v1

Stated so that scope creep is a visible decision rather than an accident.

1. **No dynamic execution. No sandboxed detonation.** We do not run, import, or evaluate
   analysed code, including in a container, a VM or a `vm` context. This is a deliberate
   trade: OpenSSF's Package Analysis does run packages, and needs gVisor sandboxing to do
   it safely ([ossf/package-analysis](https://github.com/ossf/package-analysis)). Adding
   execution multiplies our attack surface, our operational cost and our blast radius. It
   also does not obviate static analysis, because dynamic analysis has the mirror-image
   blind spot: code paths that do not run are invisible.
2. **No full taint analysis.** We do bounded, evidence-carrying dataflow with explicit
   confidence tiers and honest failure. We do not attempt sound interprocedural,
   alias-aware, field-sensitive tracking across the whole package. Claiming taint analysis
   we do not have would license conclusions we cannot support.
3. **No ML or LLM classification in v1.** No model output may influence the score. An LLM
   may be used to *summarise* findings for a human, clearly labelled as such, downstream of
   a completed deterministic verdict, and never as an input to it. A score that cannot be
   recomputed identically from stored evidence is not defensible in an incident review.
4. **No dependency-closure analysis by default.** v1 scores the artefact in front of it.
   Transitive risk is real (see `LIMITATIONS.md`) but closure scanning is a separate
   product surface with its own cost model.
5. **No registry-wide crawling or continuous monitoring** in v1.
6. **No automated takedown, reporting, or public naming.** See T-WPN-02.
7. **Not a vulnerability scanner.** Known CVEs affecting a package are reported in a
   separate field and never contribute to the malicious-behaviour score. A vulnerable
   package is not a malicious package; conflating them inflates scores and destroys the
   meaning of the number.

---

## 9. Assumptions and residual risk

**Assumptions (each is a place this model breaks if it is wrong):**

- The scanner runs on a host whose compromise is *containable* — ephemeral, credential-free,
  egress-denied.
- Analysts access the UI from managed browsers over an authenticated session.
- Intelligence feeds are correct **often**, not **always**, and are treated accordingly.
- Our own dependencies (tar reader, JS parser, JSON parser, highlighter) are themselves
  attack surface and are kept current. The 2026 node-tar advisory cluster is evidence this
  is a live, not theoretical, concern.

**Accepted residual risk:**

- A determined ADV-5 can defeat v1 static analysis. This is stated plainly in
  `LIMITATIONS.md` and is why the product outputs *evidence for a human*, not a
  certification.
- An RCE in a third-party parser we depend on remains possible. The v2 fetcher/scanner
  split is the compensating control, which is why R-ARCH-01/02/03 exist in v1.
- False positives will occur. The mitigation is not zero false positives; it is that
  every finding is inspectable, every score contribution is attributable, and `BLOCK` is
  structurally hard to reach.

---

## 10. Sources

All retrieved 2026-08-09.

- npm, *Generating provenance statements* — https://docs.npmjs.com/generating-provenance-statements
- npm, *Trusted publishing for npm packages* — https://docs.npmjs.com/trusted-publishers/
- npm, *scripts* (lifecycle order, node-gyp default) — https://docs.npmjs.com/cli/v11/using-npm/scripts
- npm, *npm-install* / `ignore-scripts` config — https://docs.npmjs.com/cli/v11/commands/npm-install
- npm, *package.json* field types — https://docs.npmjs.com/cli/v11/configuring-npm/package-json
- npm, *About registry signatures* — https://docs.npmjs.com/about-registry-signatures
- npm, *npm-audit* / `audit signatures` — https://docs.npmjs.com/cli/v11/commands/npm-audit
- npm, *Unpublish policy* — https://docs.npmjs.com/policies/unpublish
- GitHub, *Our plan for a more secure npm supply chain* — https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/
- GitHub, *About the GitHub Advisory Database* — https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database
- OpenSSF, *OSV schema* — https://ossf.github.io/osv-schema/
- OpenSSF, *malicious-packages* — https://github.com/ossf/malicious-packages
- OpenSSF, *package-analysis* — https://github.com/ossf/package-analysis
- GHSA-vmf3-w455-68vh / CVE-2026-53655, node-tar parser interpretation differential — https://github.com/advisories/GHSA-vmf3-w455-68vh
- GHSA-23hp-3jrh-7fpw / CVE-2026-59873, node-tar decompression/parse DoS — https://github.com/advisories/GHSA-23hp-3jrh-7fpw
- CVE-2021-32803, node-tar symlink path traversal via directory cache — https://www.cvedetails.com/cve/CVE-2021-32803/
- GHSA-93q8-gq69-wqmw / CVE-2021-3807, ansi-regex ReDoS — https://github.com/advisories/GHSA-93q8-gq69-wqmw
- Snyk, *Zip Slip* — https://security.snyk.io/research/zip-slip-vulnerability
- OWASP, *ReDoS* — https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- A. Birsan, *Dependency Confusion* — https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- JFrog, *npm Manifest Confusion: Six Months Later* — https://jfrog.com/blog/npm-manifest-confusion-six-months-later/

Prototype-pollution semantics in T-JSON-01 were verified empirically on Node v24.19.0 in
this repository's environment rather than taken from documentation.
