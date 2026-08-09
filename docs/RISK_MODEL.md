# PackageGate — Risk Model

**Status:** v1 draft · **Owner:** Security Researcher · **Last reviewed:** 2026-08-09
**Companion documents:** `THREAT_MODEL.md`, `LIMITATIONS.md`
**Implementation target:** `packages/risk-engine/src/weights.ts`

---

## 0. What this document commits to

1. The score is a **deterministic function of stored evidence**. Given the same tarball
   and the same rule/weight versions, it recomputes bit-identically, offline, forever.
2. **No LLM, model, embedding or learned classifier may contribute to the score.**
   Not as a feature, not as a tie-breaker, not as a confidence estimate. An LLM may
   summarise a finished verdict for a human, labelled as such, downstream of the number.
3. Every point in the final score is attributable to a named rule, a named evidence span,
   and a named arithmetic step.
4. **Known intelligence and heuristic suspicion never merge into one number.** They are two
   lanes with two outputs, combined by an explicit decision function that preserves which
   lane produced the outcome.
5. `BLOCK` is structurally hard. §7 demonstrates arithmetically that behavioural evidence
   alone cannot reach `BLOCK` without multiple independently-evidenced chains — this is a
   property of the formula, not of the tuning.

The engine's job is **not** to decide whether a package is malicious. It is to decide how
much of a human's attention the package deserves, and to hand that human the evidence.

---

## 1. Two lanes, deliberately unmerged

```
                          ┌──────────────────────────────────────┐
  advisory / malware      │  LANE I — INTELLIGENCE               │
  feeds (OSV, GHSA,   ──► │  tiered, provenance-preserving,      │──┐
  ossf/malicious-pkgs)    │  NOT scored, NOT averaged            │  │
                          └──────────────────────────────────────┘  │
                                                                    ▼
                          ┌──────────────────────────────────────┐ ┌──────────────┐
  static findings     ──► │  LANE II — BEHAVIOURAL SCORE 0–100   │►│  DECISION    │
  + chains + coverage     │  saturating, decayed, chain-weighted │ │  FUNCTION    │
                          └──────────────────────────────────────┘ └──────────────┘
                                                                    │
                                    verdict = {score, recommendation, classification,
                                               intelligence[], findings[], chains[],
                                               coverage, modifiers[], engineVersion}
```

**Why not collapse them into one number?** Three reasons, each a real failure mode:

- **Provenance of signal is the analyst's first question.** "Is this 92 because GitHub says
  it is malware, or because our regex saw `atob`?" A merged number cannot answer that,
  and an analyst who cannot answer it will stop trusting the number.
- **They have different error models.** Intelligence errors are *identity* errors (wrong
  package, wrong version range, withdrawn record). Heuristic errors are *inference* errors
  (right code, wrong conclusion). They need different appeals processes, different
  monitoring and different remediation.
- **They decay differently.** A malware record is roughly permanent for that
  `name@version` (npm's unpublish policy makes `package@version` permanently unusable
  after first use, so the identity is stable). A heuristic finding is invalidated the
  moment we improve the rule. Merging them means every rule change silently rewrites
  history.

### 1.1 Lane I — intelligence tiers

| Tier | Meaning | Source examples | Effect |
|------|---------|-----------------|--------|
| **I-0 `AUTHORITATIVE_MALWARE`** | A curated malware record naming this exact `name@version` | GitHub Advisory Database `type:malware` (published automatically from the npm security team and the OpenSSF Malicious Packages repository); a non-withdrawn OSV `MAL-*` record | → `BLOCK` / `KNOWN_MALWARE` |
| **I-1 `CORROBORATED_MALWARE`** | ≥2 **independent** non-curated feeds, after alias-closure deduplication | Commercial feeds, internal intel | → `BLOCK` / `KNOWN_MALWARE` |
| **I-2 `VULNERABILITY`** | A CVE/GHSA *vulnerability* (not malware) affecting this version | GitHub-reviewed advisories, NVD-imported unreviewed advisories | → **reported in a separate field. Contributes zero to the behavioural score.** |
| **I-3 `CONTEXT`** | Deprecation, sibling versions unpublished, maintainer-set change, an advisory on a *different* version of the same package | Registry metadata, feed metadata | → may feed rule family G, capped, always attributed |

**I-2 deserves emphasis: a vulnerable package is not a malicious package.** Mixing CVE
severity into a maliciousness score is a category error that inflates every mature,
well-audited, heavily-reported package — precisely the packages with the most advisories
because they have the most eyes. It would make `lodash` look like malware.

Note that GitHub's *unreviewed* advisories are auto-imported from NVD "without validity
checks" and are not even used to raise Dependabot alerts
([GitHub docs](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database)).
They may be reported to an analyst; they may never drive a recommendation.

**Independence rule (anti-echo-chamber).** OSV `aliases` are symmetric and transitive
([OSV schema](https://ossf.github.io/osv-schema/)). Before counting sources for I-1,
compute the transitive alias closure and count **distinct closures**, not distinct
records. Two feeds mirroring one GHSA are one source. Without this, corroboration is
manufactured from an echo.

**Withdrawal rule.** OSV records carry a `withdrawn` timestamp, and OpenSSF states plainly
that "false positives may be present in our dataset from time-to-time", offering both full
withdrawal and per-version false-positive marking
([ossf/malicious-packages](https://github.com/ossf/malicious-packages)). A withdrawn or
FP-marked record MUST drop to I-3 within one refresh cycle and MUST trigger
re-evaluation of any cached `BLOCK`.

---

## 2. The evidence objects

```ts
type Confidence = number; // 0..1, see §4.3

interface Finding {
  ruleId: string;              // 'B5.env_targeted_secret_names'
  family: FamilyId;            // 'B'
  evidence: EvidenceSpan[];    // {file, byteStart, byteEnd, snippetRef}
  occurrences: number;
  confidence: Confidence;      // extractor certainty, NOT maliciousness
  location: LocationClass;     // see §4.2
  reachability: Reachability;  // INSTALL_TIME | RUNTIME_ENTRY | RUNTIME_DEEP | UNREACHED
  novelInVersion: boolean;     // introduced relative to baseline versions
  ruleVersion: string;
}

interface Chain {
  patternId: string;           // 'J1.secret_to_network'
  source: Finding; transforms: Finding[]; sink: Finding;
  linkage: LinkageTier;        // see §4.4 — determines whether this is a CHAIN at all
  linkageEvidence: EvidenceSpan[];
  confidence: Confidence;      // min(link confidences) x linkage factor
  installTimeRooted: boolean;
}
```

A `Finding.confidence` answers **"how sure are we that the code does this?"** It never
answers "how bad is this". Badness lives entirely in the weight. Keeping these orthogonal
is what makes each contribution explainable in one sentence.

---

## 3. Why isolated API presence must be cheap and chains must be expensive

This is the central design commitment, so it is argued rather than asserted.

### 3.1 The base-rate argument (against isolated signals)

The tempting inference is `P(malicious | postinstall)` from the observation that most
malware uses `postinstall`. That is the wrong conditional. A large 2026 benchmark study of
npm malware detectors reports that **72.21 % of malicious packages exploit install
scripts** and that roughly **21.9 % of malicious packages rely entirely on install scripts,
with no malicious JavaScript in any file** (Guo et al., *How Effective Are NPM Malicious
Package Detectors? A Large-Scale Empirical Study*,
[arXiv:2603.27549](https://arxiv.org/abs/2603.27549); per-tool figures below are from the
v1 HTML rendering).

Those are `P(signal | malicious)`. What a gate needs is `P(malicious | signal)`, and by
Bayes that is dominated by the base rate. We could **not** source a defensible current
figure for what fraction of the npm registry uses install scripts, so we do not assert
one; but the direction is not in doubt, because install scripting is a *designed feature*
of the ecosystem. npm documents seven lifecycle hooks running during install, and
documents that a package with a root `binding.gyp` and no install script gets
`node-gyp rebuild` **by default**
([npm scripts](https://docs.npmjs.com/cli/v11/using-npm/scripts)). Native compilation,
prebuilt-binary download, git-hook setup and platform shims are all normal uses. Any
signal whose legitimate population is orders of magnitude larger than its malicious
population cannot, alone, justify anything stronger than "look closer".

The same study makes the cost of ignoring this concrete. Capability-oriented detectors
that flag on API presence achieve near-total recall and unusable precision — Packj's
static mode is reported at 98.69 % recall with a signal-to-noise ratio of **1:71**. Ours
would be worse, because we would be pointed at the whole registry rather than a balanced
benchmark.

### 3.2 The co-occurrence argument (for chains)

The same study reports that behavioural composition, not capability, is what carries
information: the collection-plus-exfiltration chain raises detection of one malware class
**from 3.2 % to 79.3 %**.

The mechanism is straightforward. Reading `process.env` is what configuration does.
Making an HTTPS request is what clients do. **Reading `process.env` and sending its
contents to a host unrelated to the package's declared repository is not a thing
configuration does.** The joint event is rare among legitimate packages in a way that
neither component is, because legitimate packages have a *reason* for each capability and
those reasons rarely compose into that shape.

### 3.3 Why super-additivity is legitimate arithmetic

Additive scoring assumes findings are independent evidence. They are not: in a legitimate
package, capabilities co-occur because the package is *large*, and size is not
maliciousness. Additive scoring therefore systematically penalises big honest packages —
exactly the ones a false positive hurts most.

So the model does the opposite of naive addition on both axes:

- **Breadth is discounted.** Independent capabilities aggregate with diminishing returns
  (§4.6), because breadth mostly measures package size.
- **Composition is amplified.** An evidenced source→sink link earns far more than its
  endpoints, because the *link* is the rare, informative event.

The asymmetry is not a thumb on the scale. It is the claim that **structure carries the
signal and inventory does not** — and the burden it imposes on us is real: a chain must
be *evidenced*, with a linkage span an analyst can click, or it is not a chain (§4.4).

---

## 4. The scoring pipeline

Six stages. Each is inspectable and each is individually unit-testable.

### 4.1 Stage 1 — per-occurrence contribution

```
c = w(rule) × confidence × locationFactor × reachabilityFactor × noveltyFactor
```

**Hard gate:** findings with `confidence < 0.30` contribute **zero**. They are recorded as
`observations` for the analyst. This is what stops lexical noise from inflating scores.

### 4.2 Location and reachability factors

| `location` | Factor | Why |
|---|---|---|
| `LIFECYCLE_SCRIPT` | 1.00 | Runs unattended, pre-review, with full user privileges |
| `PKG_ENTRY` (`main`/`exports`/`bin`) | 1.00 | Reachable by any consumer |
| `SRC` (imported from an entry) | 1.00 | |
| `DIST_BUNDLE` (minified build output) | 0.60 | Duplicates source; scope harder to establish; double-counting risk |
| `SCRIPTS_DIR` (build scripts not in lifecycle path) | 0.50 | Runs on maintainers, not consumers |
| `TEST` / `__tests__` / `spec` | 0.15 | Ships in tarballs constantly; not executed by consumers |
| `EXAMPLE` / `docs` / `fixtures` | 0.10 | Deliberately contains scary-looking code |
| `TYPES` (`.d.ts`) | 0.05 | Declarations, not behaviour |

| `reachability` | Factor |
|---|---|
| `INSTALL_TIME` | 1.00 |
| `RUNTIME_ENTRY` (≤2 hops from an entry point) | 1.00 |
| `RUNTIME_DEEP` | 0.85 |
| `UNREACHED` (no import path found from any entry) | 0.40 — suspicious *and* less certain; recorded, not amplified |

`noveltyFactor` = **1.35** when the finding is absent from all baseline versions and
present here, else 1.00. Rationale: for a compromised-maintainer attack (ADV-2 in the
threat model), *newness against the package's own history* is the highest-value signal
available to static analysis, because everything else about the package is legitimately
good. Constrained by `R-WPN-06`: the factor is suppressed when the baseline is shorter
than three versions or when all baselines were published by the same account inside a
short window (baseline poisoning).

### 4.3 Confidence tiers (extractor certainty)

| Evidence quality | Confidence |
|---|---|
| AST match, all operands resolve to literals, no aliasing | 0.95 |
| AST match with ≤2 alias hops resolved | 0.80 |
| AST match with computed member access or dynamic property | 0.55 |
| Lexical/regex match only | 0.35 |
| Any of the above inside a minified bundle without a source map | × 0.70 |
| Below 0.30 | **contributes nothing** |

### 4.4 Linkage tiers — what counts as a chain

| Tier | Evidence | Factor | Counts as a chain? |
|---|---|---|---|
| `L1_DIRECT` | Same function, direct dataflow, resolvable | 1.00 | Yes |
| `L2_LOCAL` | Same module, ≤2 intermediate assignments | 0.75 | Yes |
| `L3_MODULE` | Cross-module via an explicit import binding | 0.50 | Yes |
| `L4_COOCCURRENCE` | Both behaviours in the same install-reachable module, **no dataflow evidence** | 0.25 | **No — scored in family K only** |

**Design decision (contestable, see §11):** co-occurrence is empirically powerful (§3.2)
but it is not evidence of a data path. It scores — in its own capped family — and it can
raise a package to `REVIEW`. It can **never** satisfy the chain requirement that unlocks
`BLOCK`. If we let statistical co-occurrence justify a block, we are blocking on
correlation and calling it evidence, and "evidence before verdict" becomes a slogan.

### 4.5 Stage 2 — per-rule saturation

For each rule with contributions `c₁…cₙ` and per-rule cap `κ`:

```
S_rule = κ · (1 − exp(−(Σᵢ cᵢ) / κ))
```

Properties, all of which we want and all of which are testable:

- **Bounded:** `S_rule < κ` always. The 200-`process.env`-reads problem is solved by
  construction, not by a special case.
- **Monotone:** more evidence never lowers the score. Required for regression testing and
  for analyst trust.
- **Unit derivative at zero:** the first occurrence gets ~full credit, so a single strong
  finding is not unfairly discounted.
- **Single interpretable parameter:** `κ` is exactly "the most this behaviour can ever be
  worth on its own".

Worked, for `B3.env_read_generic` (w = 1, κ = 4, confidence 1.0):

| occurrences | 1 | 2 | 5 | 10 | 20 | 50 | 200 |
|---|---|---|---|---|---|---|---|
| contribution | 0.89 | 1.57 | 2.85 | 3.67 | 3.97 | 4.00 | 4.00 |

Two hundred environment reads are worth **4.0 points before family saturation and 3.5
after** — a `LOW_RISK` / `ALLOW` result, as required.

*Why exponential rather than logarithmic or top-k?* Logarithmic is unbounded (200 000
reads would still climb). Top-k is discontinuous, so a one-occurrence change can move the
score by a step, which is hostile to both testing and explanation. The exponential form is
bounded, smooth, monotone and one-parameter.

### 4.6 Stage 3 — family saturation, then cross-family decay

```
S_family = C_f · (1 − exp(−(Σ_rules S_rule) / C_f))
```

Then sort families descending and apply positional decay with **γ = 0.75**:

```
B = Σₖ S_(k) · γ^(k−1)          k = 1, 2, 3, …
```

Decay factors: 1.00, 0.75, 0.56, 0.42, 0.32, 0.24, 0.18, 0.13, 0.10, 0.08.

Rationale: the strongest behavioural family is fully credited; the fifth distinct
capability family is worth about a third of face value. This is the anti-inflation control
for breadth. A large build tool legitimately touches process, filesystem, network and
encoding; without decay, being big would be indistinguishable from being bad.

γ = 0.75 was chosen so that the arithmetic ceiling of the breadth term with **every family
simultaneously saturated** is **56.5** (computed in §7.1) — comfortably below the `BLOCK`
threshold. Breadth alone cannot block, by arithmetic.

### 4.7 Stage 4 — the chain term

```
X_raw = Σ_c  w(pattern_c) × confidence_c × installMultiplier_c
X     = C_X · (1 − exp(−X_raw / C_X)) × (1 + 0.08 · min(n_chains − 1, 3))
```

with `C_X = 65` and `installMultiplier = 1.40` when the chain is rooted in a lifecycle
script, else 1.00.

The `1.40` install multiplier is the largest single multiplier in the model and is
justified by the mechanics of npm rather than by intuition: lifecycle scripts execute
during `npm install`, unattended, before any human has read the code, with the developer's
or CI runner's full privileges, and `--ignore-scripts` defaults to `false`
([npm-install config](https://docs.npmjs.com/cli/v11/commands/npm-install)). The same
chain at runtime requires the consumer to actually call the code; at install time it
requires nothing.

The small `n_chains` bonus (max ×1.24) exists because independent chains are stronger
evidence than one chain of the same total weight — but it is deliberately small, so that
`BLOCK` is driven by *evidence quality*, not by counting.

### 4.8 Stage 5 — modifiers (negative evidence is evidence)

```
M = clamp(Σ modifiers, −20, +0)
```

| ID | Modifier | Value | Justification |
|---|---|---|---|
| **M1** | Downloaded artefact's integrity is verified (checksum/signature) before use | −8 | The difference between `prebuild-install` and a dropper is very often exactly this |
| **M2** | Network endpoints resolve to the declared `repository` host, the npm registry, or a documented CDN for this package | −5 | Destination legitimacy is the strongest available exculpatory fact for network findings |
| **M3** | Verified provenance attestation **and** trusted publisher **and** repository match | −4 | Deliberately small — see §6.4 |
| **M4** | The flagged code region is byte-identical across ≥3 prior published versions | −6 | Longevity under ecosystem scrutiny is weak but real evidence |
| **M5** | Package is on the tenant's explicit allowlist | suppresses to `ALLOW` with a recorded, attributed policy override | Policy, not analysis; always logged |

**Modifiers are disabled entirely** when Lane I is at I-0/I-1, or when any chain has
confidence ≥ 0.80. A package must not be able to buy its way out of strong evidence with
good hygiene. The floor of −20 means no combination of modifiers can zero out a
meaningful score.

### 4.9 Stage 6 — combination and structural caps

```
raw   = B + X + M
cap   = 74  if n_chains = 0
      = 89  if n_chains = 1
      = 100 if n_chains ≥ 2
score = round(clamp(raw, 0, min(100, cap)))
```

The caps are **defence in depth, not the primary mechanism** — §7.1 shows the formula
already cannot exceed ~56.5 without chains. They exist so that a future weight change
cannot silently break the invariant, and so the invariant is directly assertable in a
test.

---

## 5. The weight table

Scale: weights are in points *before* confidence, location, reachability, saturation and
decay. Read every weight as **"the most one strong instance of this can contribute before
its family is capped"**. `κ` is the per-rule saturation cap; "presence" means the rule
fires at most once per package so no cap is needed.

**FP risk** is my estimated probability that a *random package firing this rule* is not
doing anything wrong: **Very high** ≈ almost all firings are benign; **High** ≈ most;
**Moderate** ≈ a substantial minority; **Low** ≈ few; **Very low** ≈ hard to trigger
accidentally. These are calibration hypotheses, not measurements — §10 defines how they
get corrected.

### Family A — Lifecycle and install-time execution · cap C_A = 12

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| A1 | `install_script_present` — any of `preinstall`/`install`/`postinstall` | 3 | presence | Establishes that unattended install-time execution exists at all. Necessary context for every other install-time weight; not evidence of intent | node-gyp builds, `prebuild-install`, husky, Playwright/Puppeteer browser fetch, shell-completion setup, platform shims | **Very high** |
| A2 | `script_body_complex` — inline shell with pipes, `node -e`, `curl`/`wget` piped to an interpreter, base64 in the script body | 9 | presence | A lifecycle script that *constructs and executes* rather than invoking a checked-in file is doing something the repository cannot show a reviewer | Legacy packages with inline `mkdir -p && cp` chains; some `prepare` scripts | **Moderate** |
| A3 | `script_fetches_and_executes` — network fetch in the install path whose result is executed or written to an executable path | 14 | presence | The canonical dropper shape | **This is also the standard native-binary distribution mechanism** (`node-pre-gyp`, `prebuild-install`, `@napi-rs/*`, esbuild, sharp, Playwright). Very large legitimate population | **High** — must be mitigated by M1/M2 |
| A4 | `implicit_node_gyp` — root `binding.gyp` with no `install`/`preinstall` script | 4 | presence | Code execution with no `scripts` entry, per npm's documented default. Recorded because a scanner that only reads `scripts` would report "no install scripts" | Every native addon in the ecosystem | **Very high** — purely contextual |
| A5 | `script_only_package` — install scripts present, no meaningful library surface (no `main` export, negligible source) | 8 | presence | ~21.9 % of malicious packages contain no malicious JavaScript at all ([arXiv:2603.27549](https://arxiv.org/abs/2603.27549)); the payload is the script. This rule targets that blind spot | husky, config-only packages, `@types`-style shims, git-hook installers, CI helper packages | **Moderate** |
| A6 | `bin_shim_nontrivial` — a `bin` entry containing shell/interpreter logic beyond a shebang plus require | 5 | presence | `bin` executes on the consumer's machine and is under-inspected | CLI wrappers, version-managing launchers | **High** |

### Family B — Process, environment and host interaction · cap C_B = 14

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| B1 | `child_process_usage` | 4 | presence | Capability to execute; necessary for many chains | Build tools, CLIs, git wrappers, test runners — enormous population | **Very high** |
| B2 | `dynamic_command_construction` — `exec`/`shell:true` with an interpolated, non-literal command string | 8 | 12 | Command injection surface *and* an obfuscation vector for the command itself | Task runners, CLI wrappers, monorepo tooling | **High** |
| B3 | `env_read_generic` — any `process.env.X` | 1 | 4 | Almost zero information alone. Present so an analyst can see the inventory; kept non-zero only so a package with *nothing but* unusual env access is distinguishable from one with none | `NODE_ENV`, `CI`, `DEBUG`, `PORT`, `HOME` — near-universal | **Very high** |
| B4 | `env_enumeration` — whole-object access: `Object.keys(process.env)`, spread, `JSON.stringify(process.env)` | 6 | 9 | Bulk access has a different purpose profile than named access. You enumerate when you don't know what you want, i.e. when you want everything | dotenv, config libraries, CI reporters, crash reporters scrubbing env, container tooling | **High** |
| B5 | `env_targeted_secret_names` — `NPM_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`, `DOCKER_PASSWORD`, … | 9 | 14 | Named access to credentials is *purposeful*; the package told us what it wants | Publishing tools, deploy CLIs, cloud SDKs, CI plugins, `semantic-release` and its plugin ecosystem | **Moderate** — small but important legitimate population; see §8 |
| B6 | `host_recon` — `os.hostname`, `os.userInfo`, `os.networkInterfaces`, `whoami`, MAC address | 3 | 6 | Individually normal; collectively the standard fingerprinting bundle | Telemetry, crash reporters, licence checks, platform-conditional installers | **High** |
| B7 | `privilege_or_uid_check` — `process.getuid`, `isRoot`, admin checks gating behaviour | 4 | presence | Behaviour that differs under privilege is worth an analyst's eye | Installers warning against `sudo npm install`; permission-fixing tooling | **High** |

### Family C — Network · cap C_C = 16

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| C1 | `outbound_capability` — `http`/`https`/`fetch`/`axios`/`undici`/`got` present | 2 | presence | Inventory only. npm itself is a network client; so is most of the ecosystem | Everything | **Very high** |
| C2 | `hardcoded_public_ip_endpoint` — a non-loopback, non-RFC1918 IP literal as a destination | 7 | 10 | Bypassing DNS avoids domain reputation and DNS-based blocking; also avoids leaving a registrable artefact | Rare: some infra tooling, STUN/TURN defaults, public DNS resolver literals (`1.1.1.1`, `8.8.8.8`) | **Low** — but the resolver-literal exclusion matters |
| C3 | `dns_data_channel` — `dns.resolve`/`lookup` on a hostname built from runtime data | 12 | 10 | DNS exfiltration is the classic egress path that survives HTTP proxying; it is exactly what the original dependency-confusion research used ([Birsan](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)). A *constructed, data-bearing* label has essentially no benign use | Service discovery with templated hostnames; multi-region endpoint construction | **Low** — provided the rule requires runtime-data-derived labels, not any `dns.lookup` |
| C4 | `endpoint_from_encoded_literal` — destination assembled from base64/hex/charCode/reversed strings | 11 | 10 | Concealing the destination is a choice with few honest motives, and separates ADV-5b from an honest binary fetch | Anti-scraping obfuscation; some licence servers; string-splitting to defeat naive greppers | **Low–Moderate** |
| C5 | `exfil_shaped_destination` — paste sites, chat webhooks (Discord/Slack/Telegram bot endpoints), request-catchers (`interact.sh`, `requestbin`, Burp Collaborator), tunnels (`ngrok`, `trycloudflare`) | 13 | 12 | These hosts are attacker infrastructure by default: zero-setup, anonymous, TLS, allowlist-friendly | **Real:** Discord/Telegram bot libraries and CI-notification plugins legitimately post to these APIs. The rule must distinguish *webhook/collector* endpoints from *SDK API* endpoints, and must not fire on a package whose declared purpose is that platform | **Moderate** |
| C6 | `network_in_install_path` | 6 | presence | Combines the two riskiest properties: unattended execution and egress | Prebuilt binary download (very common); deprecated install-time analytics | **High** |
| C7 | `endpoint_unrelated_to_package_identity` — destination host shares no registrable domain with `repository`, `homepage`, or the registry | 5 | 8 | Cheap, surprisingly discriminating context; drives modifier M2 | Packages using third-party CDNs, jsDelivr, GitHub Releases, or a company domain different from the repo host | **High** alone; valuable as a chain qualifier |

### Family D — Filesystem and credential targets · cap C_D = 15

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| D1 | `fs_read_capability` | 1 | 3 | Inventory only | Everything | **Very high** |
| D2 | `credential_path_literals` — `~/.npmrc`, `~/.aws/credentials`, `~/.ssh/id_*`, `~/.docker/config.json`, `~/.config/gcloud`, `~/.kube/config`, browser `Login Data`, wallet paths | 11 | 18 | Naming a credential file is purposeful. Combined with any egress this is the single most common real-world payload | npm auth helpers, AWS/GCP credential-chain implementations, SSH config parsers, kube tooling, credential-manager integrations | **Moderate** |
| D3 | `home_or_root_traversal` — recursive walk rooted at `os.homedir()`, `/`, or `%USERPROFILE%` | 8 | 12 | Enumeration precedes collection | Dotfile managers, backup tools, editors, monorepo tools walking upward for config, disk-usage utilities | **Moderate–High** |
| D4 | `write_outside_package_root` at install time | 9 | 12 | Install-time writes outside the package directory affect the host, not the dependency tree | Shell-completion installation, git hooks (husky), CLI symlinks, cache directories under `~/.cache` | **High** |
| D5 | `sensitive_file_read_then_hold` — credential-shaped read whose value is retained in a variable/structure rather than consumed locally | 7 | 10 | Staging behaviour; the bridge between D2 and family F | Credential-chain libraries genuinely load then pass credentials | **Moderate** |
| D6 | `trace_removal` — deletes its own artefacts, logs, or shell history | 7 | 8 | Anti-forensics has few honest uses | Temp-file cleanup misclassified; uninstall scripts | **Low–Moderate** |

### Family E — Code shape, encoding, obfuscation · cap C_E = 10

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| E1 | `minified_or_bundled` | **0** | — | **Deliberately zero.** Bundled `dist/` output is ubiquitous and legitimate. Minification is not evidence of anything except a build step. Its *only* effect in this model is to **reduce confidence** (§4.3) and **reduce analysis coverage** (§6) — see §6.5, "obfuscation attacks the denominator" | Every published TypeScript/bundled package | n/a |
| E2 | `encoded_payload_then_execution` — base64/hex/charCode decode whose output reaches `eval`, `new Function`, `vm`, `require` of a written file, or a shell | 13 | 12 | Not "obfuscation" but *concealed executable content* — an entirely different claim | Template engines, WASM loaders, source-map tooling, DI frameworks using `new Function`, some polyfill loaders | **Moderate** |
| E3 | `obfuscator_signature` — string-array plus rotation plus hex identifiers plus control-flow flattening (obfuscator.io-family fingerprint) | 9 | presence | A *specific tool fingerprint*, not "looks minified". Deliberate concealment of logic against reading, distinct from minification for size | Commercial licence-protection wrappers, anti-tamper client SDKs, some paid SDK distributions | **Moderate** |
| E4 | `bidi_or_confusable_identifiers` — bidi overrides (`U+202A`–`U+202E`, `U+2066`–`U+2069`) or homoglyph identifiers in source | 6 | 8 | These change what a *human reviewer* sees versus what the parser sees. That is an attack on review itself | Genuinely internationalised strings and comments (the rule must scope to identifiers and control chars, not to non-Latin text) | **Low** if correctly scoped; **High** if it fires on any non-ASCII |
| E5 | `high_entropy_blob_outside_bundle` — large high-entropy literal in a non-`dist` source file with no source map | 4 | 8 | Weak on its own; useful as a chain input and as a coverage reducer | Embedded WASM, fonts, icons, test fixtures, certificates, model weights | **High** |

### Family F — Collection and staging · cap C_F = 12

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| F1 | `aggregate_then_serialize` — multiple recon/credential reads collected into one structure and serialised | 5 | 8 | The shape of a payload being assembled | Telemetry, crash reporters, diagnostics commands (`mytool --info`) | **High** |
| F2 | `encode_before_send` — base64/gzip/XOR applied to collected data prior to an egress call | 8 | 10 | Legitimate telemetry compresses; it rarely XORs, and rarely base64s already-JSON data before an HTTPS POST | Compressed telemetry payloads, multipart encoding | **Moderate** |
| F3 | `archive_of_user_paths` — zip/tar constructed from home or credential paths | 10 | 10 | Bulk collection | Backup and dotfile-sync tools | **Low–Moderate** |

### Family G — Identity, metadata and provenance context · cap C_G = 10

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| G1 | `name_confusable_with_popular` — edit distance ≤2, homoglyph, or scope-strip of a high-download package, **and** no shared maintainer, repository or provenance linkage | 9 | presence | Typosquatting's only reliable static tell. The exclusion clause carries all the weight | Forks, ports, community reimplementations, `-fork`/`-patched`/`-next`/`-legacy` variants, deliberate drop-in replacements | **High without the exclusion clause; Moderate with it** |
| G2 | `version_inflation_anomaly` — first publish at an implausibly high version, or a version far above the package's own history | 5 | presence | The dependency-confusion tell: resolution prefers the higher version | Calendar versioning, `0.0.0-dev` conventions, republished forks preserving upstream versions, deliberate major bumps | **Moderate–High** |
| G3 | `publisher_change_near_release` — the publishing account changed, or a maintainer was added, within N days of this version (registry metadata; fetcher-dependent) | 7 | presence | The clearest metadata correlate of maintainer-account takeover | Genuine maintainer handover, adding a co-maintainer, org migrations, bus-factor improvements | **Moderate** |
| G4 | `no_repository_or_provenance` | **2** | presence | Deliberately tiny. Provenance requires a supported cloud CI provider, a public repository, a matching `repository` field and npm ≥ 9.5.0 ([npm docs](https://docs.npmjs.com/generating-provenance-statements)); trusted publishing supports only GitHub Actions, GitLab CI and CircleCI on cloud-hosted runners, one publisher per package, with no provenance at all on CircleCI ([npm docs](https://docs.npmjs.com/trusted-publishers/)). Absence therefore measures **publishing workflow**, not intent | Most of the registry. Anything published before 2023; anything from a private repo, a self-hosted runner, or a laptop | **Very high** |
| G5 | `tarball_manifest_mismatch` — the tarball's `package.json` differs from registry metadata in `scripts`, `bin`, `dependencies` or `files` | 12 | presence | Manifest confusion: the registry does not validate the two manifests and the installer uses the tarball's copy ([JFrog](https://jfrog.com/blog/npm-manifest-confusion-six-months-later/)). A divergence in *execution-relevant* fields has, to my knowledge, no honest explanation. **Highest weight-to-false-positive ratio in the table** | Publishing-tool bugs; deliberate registry-display cosmetics in non-execution fields (which this rule excludes) | **Very low** |
| G6 | `shipped_files_absent_from_source` — files in the tarball with no counterpart in the linked repository at the published commit | 10 | 8 | The build-vs-source divergence that provenance is *supposed* to let us check | **Build output is exactly this** — `dist/`, generated types, compiled binaries. Only meaningful with provenance and a build-output exclusion; confidence must be heavily reduced without provenance | **Very high** without provenance; **Low** with it |

### Family H — Persistence and host modification · cap C_H = 12

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| H1 | `system_persistence` — crontab, systemd unit, launchd plist, Windows Run key, startup folder | 12 | 10 | Survival past the install is not a build-tool behaviour | Process managers (pm2), service installers, daemon packages | **Low–Moderate** |
| H2 | `shell_rc_modification` — `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.zprofile` | 10 | 10 | Executes on every future shell | PATH and completion setup, nvm-style version-manager installers | **Moderate** — a real and reasonably common honest population |
| H3 | `git_hook_or_npmrc_write` | 8 | 10 | `.git/hooks` executes on developer action; `.npmrc` can redirect the registry or leak a token | husky, lint-staged, `npm login` helpers, registry-configuring enterprise tooling | **High** |
| H4 | `modifies_other_packages` — writes into sibling `node_modules`, or invokes publish/version APIs | 11 | 10 | **The worm primitive.** Self-replication (the Shai-Hulud class, [GitHub blog](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)) requires it | `patch-package`, pnpm patching, monorepo linking, release tooling | **Moderate** |

### Family I — Anti-analysis · cap C_I = 12

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| I1 | `environment_gated_divergence` — CI/container/VM/sandbox detection **that gates a risky code path** | 12 | 10 | Requires *divergence in a risky path*, not merely reading `process.env.CI`. Behaving differently when observed is close to a confession | Tests skipping in CI; container-aware defaults; CI-specific logging | **Low** if the divergence requirement is enforced; **Very high** if it degrades to "reads `CI`" |
| I2 | `debugger_or_inspector_evasion` — `inspector` checks, `debugger` traps, timing checks around sensitive code | 7 | 8 | Few honest uses in a library | Anti-tamper SDKs, licence enforcement, some DRM | **Low–Moderate** |
| I3 | `time_or_geo_gated_execution` — behaviour gated on a date threshold or geographic lookup | 8 | 8 | Logic bombs and region-targeted protestware | Licence expiry, feature flags, region-specific endpoint selection, holiday easter eggs | **Moderate** |
| I4 | `dynamic_dispatch_of_sensitive_api` — `globalThis[decoded]`, `Reflect.get` chains, `process["e"+"nv"]` reaching a sensitive API | 9 | 10 | Direct evasion of static resolution. **We should score the act of hiding from us, but only when what is being hidden is sensitive** | Plugin systems, DI containers, polyfill feature detection, isomorphic shims | **Moderate** |

### Family K — Co-occurrence without evidenced dataflow · cap C_K = 18

| ID | Rule | w | κ | Rationale | Legitimate trigger | FP risk |
|---|---|---|---|---|---|---|
| K1 | `cooccurrence_pair` — two chain-relevant families present in the same install-reachable module, no dataflow evidence (linkage `L4`) | 7 | 18 | Co-occurrence carries real signal (§3.2) and must not be discarded. But it is correlation, so it lives in its own family, is capped, and **cannot unlock `BLOCK`** | Any module that both reads configuration and makes requests — i.e. a great many honest modules | **High** |

K1 is **suppressed for any pair already covered by an evidenced chain**, so a real chain is
never double-counted as both chain and co-occurrence. The high family cap (18) reflects
that this family absorbs the "we see the shape but not the wiring" cases that would
otherwise pressure us into inflating linkage tiers.

### Chain patterns · cap C_X = 65

| ID | Pattern | w | Rationale | Legitimate analogue | FP risk |
|---|---|---|---|---|---|
| J1 | `secret_source → network_sink` (env-secret or credential-file read reaching egress) | 38 | The core exfiltration primitive | **Publishing and deployment tools do exactly this**: read `NPM_TOKEN`, call the registry. Distinguished only by destination (M2) and package purpose. See §8 | **Moderate** |
| J2 | `host_recon → encode → network_sink` | 32 | Fingerprint-and-report | Telemetry and crash reporting, honestly implemented | **Moderate–High** |
| J3 | `remote_fetch → dynamic_execution` (downloaded content evaluated or executed) | 36 | The dropper primitive | **The prebuilt-binary install pattern.** Distinguished by integrity verification (M1) and destination (M2) | **Moderate–High** |
| J4 | `credential_read → filesystem_stage → archive → network_sink` | 45 | Bulk collection and exfiltration; the length of the chain is itself evidence | Backup/sync tools uploading to the *user's own* configured destination | **Low** |
| J5 | `registry_token_read → publish_or_modify_packages` | 50 | Self-replication. The highest-consequence chain in the ecosystem | Release automation (`semantic-release`, `changesets`, `np`) is structurally identical. Requires M2/M3 and package-purpose context to separate | **Moderate** — high consequence in both directions |
| J6 | `install_trigger → any_egress_of_local_data` | 34 | Install-time exfiltration regardless of what is exfiltrated | Install-time telemetry (deprecated practice, still extant) | **Moderate** |

Chain confidence = `min(confidence of each link) × linkage factor (§4.4)`, then
`× 1.40` if install-time rooted.

---

## 6. Why each of these is not enough on its own

### 6.1 `postinstall` presence — maximum contribution ≈ 2.8 points

A1 is weight 3. After confidence (~0.95) and family saturation it contributes under 3
points out of 100 — nowhere near `REVIEW`. Reasons: install scripting is a documented,
first-class npm feature with seven hooks; `node-gyp rebuild` runs by default with no
script at all; and `P(malicious | postinstall)` is not `P(postinstall | malicious)`. The
72.21 % figure from [arXiv:2603.27549](https://arxiv.org/abs/2603.27549) tells us where to
*look*, not what to *conclude*. **What earns points is what the script does** (A2, A3, and
chains rooted at install time), never that it exists.

### 6.2 Network access — maximum contribution ≈ 1.9 points

C1 is weight 2. Update checks, telemetry, binary fetch, API clients, and the entire
category of HTTP libraries all trigger it. npm itself is a network client; so is the CI
runner that generates provenance. A rule that treats egress capability as risk is a rule
that flags the ecosystem. **What earns points is the destination (C2, C4, C5, C7) and the
data flowing to it (J1, J2, J4).**

### 6.3 `process.env` access — 200 reads reach 3.5 points

Demonstrated in §4.5 and §7.2. `NODE_ENV` alone appears in essentially every build tool.
The saturation curve makes volume worthless by construction: the 200th read adds
approximately 10⁻²¹ points. **What earns points is which variables (B5), bulk enumeration
(B4), and where the values go (J1).**

### 6.4 Missing provenance — 2 points, and that is generous

Provenance requires a supported cloud CI provider on a cloud-hosted runner, a public
repository, a matching public `repository` field, and npm ≥ 9.5.0. Trusted publishing
supports GitHub Actions, GitLab CI and CircleCI only, permits one trusted publisher per
package, and produces no provenance at all on CircleCI. Absence of provenance therefore
tells us the maintainer publishes from a laptop, a self-hosted runner, a private repo, or
an unsupported CI — not that they are hostile. Most of the registry predates the mechanism
entirely.

And the converse matters more: **provenance does not bound behaviour.** npm states that
established provenance "does not guarantee the package has no malicious code"
([npm docs](https://docs.npmjs.com/generating-provenance-statements)). A compromised
maintainer with a working CI pipeline produces a fully attested malicious artefact.
Provenance answers "did this come from that repo's build?" — a genuinely valuable
question, and a completely different one from "is this safe?". Hence M3 is only −4.

### 6.5 Minified / obfuscated code — weight **zero**

Bundled, minified `dist/` output is how a large share of the registry ships. Treating it
as risk is treating "uses a build step" as risk.

**Obfuscation attacks the denominator, not the numerator.** Its correct effect is:

- **lower confidence** on findings inside it (§4.3, ×0.70 without a source map), and
- **lower `analysis_coverage`** (§9).

If coverage falls below the floor, the result is `INSUFFICIENT_EVIDENCE` / `REVIEW` — we
say *we cannot vouch for this*, which is true, rather than *this is dangerous*, which we
have not shown. **Obfuscation removes our right to say `ALLOW`; it does not earn a
`BLOCK`.** Points are earned only by the narrower, defensible claims: E2 (encoded content
that is then *executed*), E3 (a specific obfuscator fingerprint), E4 (constructs that
attack human review), I4 (dynamic dispatch specifically hiding a sensitive API).

---

## 7. Demonstrated properties (arithmetic, not assertion)

All figures below are produced by the formulas in §4; the reference computation is
reproducible and belongs in the engine's test suite.

### 7.1 Structural ceilings

| Property | Value |
|---|---|
| Breadth term `B` with **every family simultaneously saturated at its cap** | **56.48** |
| Therefore: maximum achievable score with **zero chains** | **≈ 56** (structural cap 74 never binds) |
| Chain term `X` maximum (`C_X` = 65 × 1.24) | 80.6 |
| Theoretical maximum raw | 137 → clipped to 100 |

**Invariant: no chain ⇒ no `BLOCK`, by arithmetic.** The explicit caps in §4.9 are
belt-and-braces against future weight drift.

### 7.2 Worked examples

| # | Package shape | `B` | `X` | Score | Verdict |
|---|---|---|---|---|---|
| E1 | **Native module** (postinstall, downloads prebuilt binary, child_process, 12 env reads, 3 recon calls, writes outside package root) — *no mitigations applied* | 20.4 | 0 | **20** | `ALLOW` / `LOW_RISK` |
| E1′ | Same, with M1 (checksum verified) + M2 (endpoint = repo host) | 20.4 | 0 | **7** | `ALLOW` / `LOW_RISK` |
| E2 | **200 `process.env` reads**, nothing else | 3.5 | 0 | **3** | `ALLOW` / `LOW_RISK` |
| E6 | **Large build tool** (child_process, 40 env reads, 50 fs reads, bundled dist, high-entropy blobs, network capability) | 13.9 | 0 | **14** | `ALLOW` / `LOW_RISK` |
| E3 | **Credential stealer** (postinstall, 4 targeted secret env reads, env enumeration, 3 credential file paths, webhook destination, encode-before-send, one L2-linked install-time J1 chain) | 25.1 | 27.6 | **53** | `REVIEW` / `HIGH_RISK_BEHAVIOUR` |
| E5 | **Legitimate publishing CLI** (reads `NPM_TOKEN`/`GITHUB_TOKEN`, reads `.npmrc`, one L1 runtime J1 chain to the registry) — *the hardest false positive* | 17.5 | 26.6 | **44** | `REVIEW` / `SUSPICIOUS` |
| E5′ | Same, with M2 + M3 + M4 | 17.5 | 26.6 | **29** | `REVIEW` / `SUSPICIOUS` |
| E4 | **Worm** (Shai-Hulud shape: complex postinstall, targeted secrets, credential paths, home traversal, webhook egress, encoded-then-executed payload, staging, modifies other packages, **three** install-time chains J1/J5/J3) | 33.4 | 66.2 | **100** | `BLOCK` / `HIGH_RISK_BEHAVIOUR` |

### 7.3 `BLOCK` sensitivity

| Evidence configuration | Score | Outcome |
|---|---|---|
| Thin package + 2 strong install-time chains (conf 0.9) | 65 | `REVIEW` |
| Moderate breadth + 2 strong install-time chains | 79 | `REVIEW` |
| Broad breadth + 2 moderate chains (conf 0.8) | 82 | `REVIEW` |
| Broad breadth + 3 install-time chains (conf 0.7) | 97 | `BLOCK` |

**In practice, behavioural `BLOCK` requires roughly three independently-evidenced chains
plus broad supporting evidence.** Two chains are not enough. That is the intended posture
and it is now a measurable property rather than an aspiration.

### 7.4 Note on E5, stated honestly

A legitimate release-automation tool scores 44 (29 with all mitigations) and lands in
`REVIEW`. That is a false positive, and I am not going to hide it behind a weight tweak.
It is structural: reading a publish token and sending it to a remote host **is** the
malicious behaviour; only *purpose and destination* separate the two, and purpose is not
statically decidable.

The correct remedy is a **per-tenant suppression baseline** — an analyst reviews the tool
once, records an attributed suppression scoped to `package + rule + chain pattern`, and
the finding stays visible but stops driving the recommendation. The wrong remedy is
lowering J1, which would blind us to the most common real payload in the ecosystem.
Suppression is therefore a **required v1 feature, not a nice-to-have** (§10).

---

## 8. The decision function

```
if intelligence.tier ∈ {I-0, I-1}:
    → BLOCK, classification = KNOWN_MALWARE
      (behavioural score still computed and reported; never merged)

elif analysis_coverage < COVERAGE_FLOOR (0.60)
     or archive.parser_disagreement
     or resource limit exceeded
     or manifest unparseable:
    → REVIEW, classification = INSUFFICIENT_EVIDENCE
      (never ALLOW; never BLOCK)

elif score ≥ 90 and n_independent_chains ≥ 2 and max_chain_confidence ≥ 0.80:
    → BLOCK, classification = HIGH_RISK_BEHAVIOUR

elif score ≥ 50:
    → REVIEW, classification = HIGH_RISK_BEHAVIOUR

elif score ≥ 25:
    → REVIEW, classification = SUSPICIOUS

else:
    → ALLOW, classification = LOW_RISK
```

Independently: `known_vulnerabilities[]` (tier I-2) is always reported and may drive a
consumer's *policy* decision in CI, but never touches `score`, `classification`, or the
malicious-behaviour recommendation.

**`BLOCK` from behaviour keeps `classification = HIGH_RISK_BEHAVIOUR`, not
`KNOWN_MALWARE`.** We can defend "this package's code does these things, here is the
evidence". We cannot defend "this is malware" without an authoritative record, and the
distinction protects a real maintainer's reputation (T-WPN-02).

### Thresholds defended in triage-cost terms

The bands are set by **what a human does with the output**, not by severity theatre.

- **`ALLOW` ceiling at 24.** Everything below 25 is what an honest package with lifecycle
  scripts, network access and environment reads actually scores: E1 = 20, E6 = 14, E2 = 3.
  If a normal native module scored `REVIEW`, the queue would be the registry and the
  product would be deleted from the pipeline within a week (T-WPN-04). **E1's unmitigated
  20 sits uncomfortably close to 24 and is the model's single most important calibration
  risk** — §10 makes it a monitored quantity, not an assumption.

- **`SUSPICIOUS` band 25–49 → `REVIEW`.** These are "an analyst should glance at this",
  perhaps 5–10 minutes with the findings list. The band is wide because this is where
  uncertainty genuinely lives and because a wrong `REVIEW` is cheap.

- **`HIGH_RISK_BEHAVIOUR` band 50–89 → still `REVIEW`.** At least one evidenced chain
  exists. This is a 30–60 minute investigation with the tarball open. It is deliberately
  the *widest* band and deliberately still `REVIEW`: the model says "there is a real
  behavioural chain here", and a human decides what it means. A Shai-Hulud-class worm with
  only two evidenced chains lands here, at ~80. I accept that, because the alternative —
  lowering the bar until two chains block — makes E5-shaped release tooling blockable, and
  that trade is bad.

- **`BLOCK` at 90 with ≥2 chains and ≥0.80 confidence.** Reserved for evidence so
  overwhelming that a reasonable analyst would reach the same conclusion from the findings
  list alone. §7.3 shows this needs roughly three chains in practice.

**The asymmetry driving all of this:**

| Error | Direct cost | Second-order cost |
|---|---|---|
| False `REVIEW` | ~10–60 analyst-minutes | Queue pressure; at scale, attention exhaustion (T-WPN-03) |
| False `BLOCK` | Broken build for **every** consumer of that package | Emergency escalation; a public accusation against a real maintainer; and — decisively — **the organisation disables the gate**. At that point our true-positive rate is zero |
| False `ALLOW` | A malicious package enters a build | The failure the product exists to prevent |

False `ALLOW` is the worst *single* outcome. But **false `BLOCK` at volume causes false
`ALLOW` at volume**, because it removes us from the pipeline entirely. That is why `BLOCK`
is rationed and `REVIEW` is generous, and it is the reasoning behind every threshold above.

Thresholds are **per-tenant configurable** with the defaults above. Configuration is a
recorded policy artefact carried in the verdict, so a verdict can always be reproduced
under the policy that produced it.

---

## 9. Coverage, and the right to say `ALLOW`

```
analysis_coverage = analysed_bytes_with_AST / analysable_js_bytes
```

Coverage is reduced by unparsed files, per-file timeouts, native binaries, WASM, encoded
blobs, and minified code without source maps. Reported alongside the score, always.

**`ALLOW` is a statement about our evidence, not about the package.** Below the coverage
floor we have not earned it, and the honest output is `INSUFFICIENT_EVIDENCE`. This is the
mechanism that stops "we found nothing" from silently becoming "there is nothing" — the
error `LIMITATIONS.md` treats as the most dangerous one in the product.

---

## 10. Calibration, monitoring and change control

Weights in this document are **hypotheses with stated reasoning**, not measurements.
Treating them as settled would be the same overconfidence the model is designed to avoid.

**Required before v1 ships:**

1. **A benign corpus** — several thousand widely-depended-upon packages spanning native
   modules, CLIs, build tools, release tooling, cloud SDKs and frameworks. Every
   rule/weight change runs against it. **Any increase in the `REVIEW` rate blocks the
   change until justified in writing.** (`R-WPN-04` in the threat model.)
2. **A malicious corpus** with per-sample expected minimum scores, so weight changes
   cannot silently reduce detection.
3. **Per-rule firing telemetry** — firing rate, contribution distribution, and analyst
   disposition. A rule that fires on 40 % of the benign corpus is an inventory field, not
   a scoring rule, and must be re-weighted to 0–2 or moved to `observations`.
4. **Analyst feedback capture** at verdict level (`agreed` / `false positive` / `missed`),
   which is how the FP-risk column in §5 gets corrected. It feeds **rule and weight review
   by a human**; it must never auto-tune weights, because auto-tuning reintroduces
   unexplainable scoring through the back door.
5. **Suppression baselines** (§7.4) — attributed, scoped, expiring, and visible in the
   verdict.
6. **Threshold-boundary monitoring** — the distribution of benign-corpus scores near 24
   and 49. E1's 20 is the canary.

**Change control:** `weights.ts` carries a `WEIGHTS_VERSION`. Every verdict records
`{engineVersion, rulesVersion, weightsVersion, feedSnapshotIds}`. A verdict that cannot be
reproduced from those identifiers is a bug.

**Benchmark caveat:** the detector figures cited in §3 come from a curated benchmark
(6,420 malicious / 7,288 benign). Benchmark precision does **not** transfer to the
production distribution, where benign packages outnumber malicious ones by orders of
magnitude. Those numbers justify *design direction* — capability-alone is noisy,
composition is informative — and nothing about our expected production performance.

---

## 11. The four most contestable decisions in this model

Recorded explicitly so they can be argued with rather than inherited.

1. **`BLOCK` is nearly unreachable from behaviour alone (§7.3: ~3 chains).** A
   Shai-Hulud-class worm with two evidenced chains scores ~80 and gets `REVIEW`. Someone
   will reasonably argue that a scanner that will not block an obvious worm is not doing
   its job. My defence: `REVIEW` at 80 with three named chains is not "no action" — it is
   an urgent, evidenced escalation to a human who can act in minutes. Meanwhile a `BLOCK`
   threshold low enough to catch that worm automatically is also low enough to catch
   release tooling, and the resulting gate abandonment costs more than the delay.

2. **Co-occurrence cannot unlock `BLOCK` (§4.4, family K).** The evidence says
   co-occurrence is powerful (3.2 % → 79.3 %). I still refuse to let it block, because it
   is correlation without a demonstrated data path, and "evidence before verdict" has to
   mean something at the moment it is expensive. Someone will argue I am discarding the
   single most useful empirical finding available.

3. **Vulnerabilities contribute exactly zero (I-2).** Clean separation, but consumers will
   expect one number, and some will interpret `ALLOW` on a package with a critical CVE as
   the tool being broken. This is a documentation and UX burden I am choosing to carry
   rather than corrupt the score.

4. **Legitimate release-automation tooling will sit in `REVIEW` indefinitely (§7.4, E5 =
   44).** I am accepting a known, recurring, un-fixable-by-tuning false positive and
   pushing the remedy into a suppression baseline. If suppression does not ship in v1, this
   becomes a daily irritation that erodes trust in exactly the way §8 warns about — so
   §10.5 is a hard dependency, not a wish.

Two runners-up: the **1.40 install-time multiplier** is the largest single lever in the
model and rests on a qualitative argument about unattended execution; and **γ = 0.75** was
chosen to make the no-chain ceiling land near 56, which is reasoning backwards from a
desired property rather than forwards from first principles. Both deserve challenge.

---

## 12. Sources

All retrieved 2026-08-09.

- npm, *Generating provenance statements* — https://docs.npmjs.com/generating-provenance-statements
- npm, *Trusted publishing for npm packages* — https://docs.npmjs.com/trusted-publishers/
- npm, *scripts* (lifecycle order, `node-gyp` default) — https://docs.npmjs.com/cli/v11/using-npm/scripts
- npm, *npm-install* / `ignore-scripts` — https://docs.npmjs.com/cli/v11/commands/npm-install
- npm, *package.json* — https://docs.npmjs.com/cli/v11/configuring-npm/package-json
- npm, *Unpublish policy* — https://docs.npmjs.com/policies/unpublish
- GitHub, *About the GitHub Advisory Database* (reviewed / unreviewed / malware; `type:malware`) — https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database
- GitHub, *Our plan for a more secure npm supply chain* — https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/
- OpenSSF, *OSV schema* (aliases symmetric/transitive; `withdrawn`; `MAL-` records) — https://ossf.github.io/osv-schema/
- OpenSSF, *malicious-packages* (false-positive caveat, withdrawal process) — https://github.com/ossf/malicious-packages
- W. Guo et al., *How Effective Are NPM Malicious Package Detectors? A Large-Scale Empirical Study*, arXiv:2603.27549 (v1 Mar 2026, v2 Aug 2026) — https://arxiv.org/abs/2603.27549 — source of the 72.21 % install-script figure, the ~21.9 % script-only figure, the 3.2 % → 79.3 % co-occurrence figure, and the 1:71 signal-to-noise figure for capability-oriented static detection
- A. Birsan, *Dependency Confusion* — https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- JFrog, *npm Manifest Confusion: Six Months Later* — https://jfrog.com/blog/npm-manifest-confusion-six-months-later/

**Deliberately not cited:** any figure for the proportion of npm packages that use install
scripts. Widely-repeated numbers exist but I could not verify one against a primary source,
so no such figure appears in this document or in any rule rationale.
