# PackageGate — Static Analysis

**Status:** v1 · **Owner:** Static Analysis Engineer · **Last reviewed:** 2026-08-09
**Companion documents:** `RISK_MODEL.md`, `THREAT_MODEL.md`, `BEHAVIOUR_ANALYSIS.md`
**Implementation:** `packages/static-analyser`

---

## 0. What this component claims

The static analyser reads published JavaScript and TypeScript and reports **observations
about what the code can do**. It does not decide whether a package is malicious, does not
produce a score, and does not rank packages. Weighting is the risk engine's job and is
kept deliberately far from the detection code.

Three properties hold everywhere in the package and are the basis for everything else:

1. **Analysed code is never executed.** There is no `require`, `import()`, `eval`, `vm`,
   `child_process` or shell invocation of package content anywhere in the analyser. A
   tarball is parsed into an AST and inspected as data.
2. **The analyser performs no I/O.** There is no `fs` import in `packages/static-analyser/src`.
   File content arrives as strings from the fetcher, which owns extraction and its own
   traversal, symlink and size defences. This is what makes the analyser safe to run inside
   a network-disabled, read-only process.
3. **Nothing is silently skipped.** Every input file appears in the result as analysed,
   skipped-with-a-reason, or a `ParseFailure`. Every budget that is reached produces a
   `LimitNotice`. "We found nothing" is always distinguishable from "we stopped looking".

**Absence of findings is not evidence of safety.** It means the rules in this document did
not match the code we were able to parse. §5 lists, without hedging, what that excludes.

---

## 1. Mechanism

### 1.1 Parsing

`@babel/parser` v8, with `errorRecovery: true`. ESM is attempted first; when it needs error
recovery a script-mode parse is attempted as well and whichever needed less forgiveness is
kept. That is what correctly handles CommonJS files using `with`, HTML comments and other
sloppy-mode-only constructs. At most two parse attempts are ever made.

Plugins are selected per extension rather than "enable everything", because several Babel
plugins are mutually ambiguous — `flow` and `typescript` cannot coexist, and enabling `jsx`
on a `.ts` file changes how `<T>(x) => x` parses. Getting that wrong does not crash; it
silently produces a wrong AST, which is the worst available failure mode.

A file that cannot be parsed produces a structured `ParseFailure` carrying the path, the
reason and the size. It never throws and it is never dropped.

### 1.2 Capability resolution through scope bindings

Detection resolves through Babel's scope analysis, never through text matching. A module
import creates a **binding**, and the analyser remembers the binding *object* rather than
the name it happened to be given. A use site is resolved by asking its own scope for the
binding of that name.

All of the following resolve to the same capability — `child_process.exec`:

```js
const cp = require("child_process");        cp.exec(x);
const { exec } = require("child_process");  exec(x);
const { exec: run } = require("child_process"); run(x);
import { exec } from "child_process";       exec(x);
import { exec as run } from "child_process"; run(x);
import * as cp from "child_process";        cp.exec(x);
import cp from "child_process";             cp.exec(x);   // CJS interop
const cp = require("node:child_process");   cp.exec(x);
const cp = require("child_process"); const run = cp.exec;  run(x);
const cp = await import("node:child_process"); cp.exec(x);
require("child_process").exec(x);
cp["exec"](x);                                              // literal computed key
```

And, equally importantly, these do **not**:

```js
function exec(command) { return command.length; }  exec("rm -rf /");
import { exec } from "child_process";
function f() { const exec = (v) => v; return exec("x"); }   // shadowed
module.exports = (exec) => exec("ls");                      // parameter shadow
function require(n) { … } const cp = require("child_process"); cp.exec(x);
function handler(process) { return process.env.NPM_TOKEN; } // shadowed global
```

Globals (`process`, `eval`, `fetch`, `Buffer`, `globalThis`) are recognised by the *absence*
of a binding, which is why a parameter named `process` is correctly not treated as the
global. `globalThis.process.env` is collapsed to `process.env`. Alias chains are followed to
a bounded depth (`maxAliasDepth`, default 4) by repeating the collection pass until it stops
learning anything new.

### 1.3 One traversal, bounded

All rules share a single traversal, so cost is proportional to file size rather than to rule
count. A rule that throws is caught, recorded in the file's report, and does not take the
file, the package or the scan with it.

### 1.4 Findings

Rules describe what they saw. The emitter owns identifier derivation, snippet extraction,
sanitisation, deduplication and every per-file budget — a deliberate concentration of the
things that are easy to get subtly wrong. Identifiers are a SHA-256 of stable facts about
the observation, with no timestamp, counter or random component, so the same tarball and
the same rule version produce the same ids forever.

Snippets are read from the real file (never reconstructed by a rule) and passed through
`sanitiseSnippet`, which strips ANSI escapes and control characters. Package source reaches
logs, a database, a terminal and a browser; each is a separate injection surface.

---

## 2. Coverage

### 2.1 What is analysed

| Input | Handling |
|---|---|
| `.js .mjs .cjs .jsx .es .es6` | Parsed and traversed |
| `.ts .tsx .mts .cts` | Parsed and traversed |
| `.json` and friends | Classified, not parsed as code |
| `.node`, ELF/Mach-O/PE/WASM content | Reported as a native binary; contents not analysable |
| Anything else (`.sh`, `.py`, `.md`, …) | Recorded as not analysed, with the reason |
| Tarball manifest `scripts` | Lifecycle analysis (§2.3) |

### 2.2 Detection families

Severity answers "how serious would this be *if* it were malicious". Confidence answers
"how sure are we the code does this". They are independent, and the whole calibration
depends on keeping them independent.

| Category | Rules | Severity | Notes |
|---|---|---|---|
| `PROCESS_EXECUTION` | `child_process` exec/spawn/fork family | LOW; **MEDIUM** when a shell-interpreted command is built at runtime | Spawning processes is what build tooling *is* |
| `SHELL_COMMAND` | Literal command lines containing shell operators | LOW | Context for other findings |
| `ENVIRONMENT_ACCESS` | `process.env.X`; computed keys | LOW | `NODE_ENV` is HIGH confidence, LOW severity |
| `ENVIRONMENT_ACCESS` | `Object.keys(process.env)`, `JSON.stringify(process.env)`, `{...process.env}` | MEDIUM | Bulk access has a different purpose profile |
| `CREDENTIAL_RELATED_ACCESS` | ~30 named credential environment variables | HIGH | Named access is *purposeful* |
| `NETWORK_ACCESS` | `http(s)`, `net`, `tls`, `dgram`, `http2`, `dns`, common HTTP clients, `fetch` | LOW | Inventory; npm itself is a network client |
| `NETWORK_DESTINATION` | URL literals | INFO; **MEDIUM** for a bare public IP; **HIGH** for a public collector | Collectors: paste sites, chat webhooks, request catchers, tunnels |
| `FILESYSTEM_READ` / `FILESYSTEM_WRITE` | `fs`, `fs/promises`, `graceful-fs`, `fs-extra` | LOW; **MEDIUM** for shell profiles, cron, systemd, git hooks | |
| `EXECUTABLE_WRITE` | Writing `.sh`/`.ps1`/… or `chmod` with an execute bit | MEDIUM | |
| `SENSITIVE_FILE_ACCESS`, `CREDENTIAL_RELATED_ACCESS`, `PACKAGE_MANAGER_ACCESS` | `.npmrc`, `.yarnrc.yml`, `.pypirc`, `.ssh/id_*`, `.aws/credentials`, `.config/gcloud`, `.kube/config`, `.docker/config.json`, `.netrc`, `.git-credentials`, shell history, browser password stores, wallets | HIGH | Matched inside parsed literals, anywhere they appear |
| `HOME_DIRECTORY_ACCESS` | `os.homedir()` | LOW | |
| `DYNAMIC_CODE_EXECUTION` | `eval`, `new Function`, `vm.*`, `require(<non-literal>)` | MEDIUM; LOW for a literal operand; **HIGH** when the operand contains a decode | |
| `REMOTE_CODE_FETCH` | Sink operand syntactically contains a network read | HIGH | §3 explains the restriction |
| `ENCODED_PAYLOAD` | `Buffer.from(…, base64\|hex)`, `atob`, `String.fromCharCode(…)` | LOW | Decoding is ubiquitous |
| `HIGH_ENTROPY_PAYLOAD` | ≥96-char base64/hex literal with Shannon entropy ≥ 5.0 | LOW, MEDIUM confidence | Suppressed in minified files |
| `OBFUSCATION_SIGNAL` | Bidi/invisible control characters; ≥8 distinct `_0x[0-9a-f]{4,8}` identifiers; computed dispatch on `process`/`globalThis`/`Reflect.get` | MEDIUM | Never fires on minification alone |
| `SYSTEM_INFORMATION_ACCESS` | `os.hostname/userInfo/networkInterfaces/cpus/…`, `process.platform/versions/getuid/…` | LOW; MEDIUM for host fingerprinting | |
| `NATIVE_BINARY` | ELF/Mach-O/PE/WASM content, `.node` requires, `process.dlopen`, `bindings`/`node-gyp-build`/`node-pre-gyp` | LOW; MEDIUM for `dlopen` and extension/content mismatch | Reduces coverage by definition |
| `CRYPTOGRAPHIC_OPERATION` | `crypto` cipher construction | INFO | |
| `INSTALL_SCRIPT`, `DOWNLOAD_BEHAVIOUR`, `REMOTE_CODE_FETCH` | Lifecycle scripts (§2.3) | LOW → HIGH | |

### 2.3 Lifecycle scripts

Every entry in the tarball manifest's `scripts` becomes a `LifecycleScript` carrying its
name, sanitised command, whether npm runs it on install, and `referencedFiles`.

`referencedFiles` is the bridge into the rest of the analyser: `postinstall: "node
scripts/install.js"` tells us almost nothing, and `scripts/install.js` tells us everything.
The pipeline analyses those files **first**, so an exhausted budget can never be the reason
the install-time code went unexamined.

Command-string parsing is the one place in this package where a real parser is not used.
There is no maintained, safe, cross-shell parser that models bash, sh, cmd and PowerShell
quoting, and writing one would be a larger correctness risk than bounded string handling.
The mitigations: the command is never executed and never handed to a shell; parsing is
bounded by `maxCommandLength`; and every recovered path is validated with
`isSafeRelativePath`, so nothing absolute and nothing containing `..` can reach the pipeline
as a file to open.

Findings: presence of an install script is **LOW** (install scripting is a designed npm
feature — native compilation, prebuilt binaries, git hooks, platform shims). A download is
**MEDIUM** at install time. A download piped into an interpreter is **HIGH**, because the
code that runs is never present in the package at all.

### 2.4 Budgets

Every unbounded dimension has an explicit ceiling in `limits.ts`: file size, files per
package, findings per file, per rule per file and per package, AST nodes per file,
wall-clock per file, literal scan length, snippet length, member depth, alias depth,
command length. Reaching any of them emits a `LimitNotice` naming the file and the budget.

---

## 3. Composition: what is and is not claimed

The analyser makes exactly one kind of compositional claim, and only when the relationship
is visible **inside a single expression** — the value is syntactically an operand of the
sink:

```js
eval(Buffer.from(blob, "base64").toString());   // encoded content executed  → HIGH
eval(await fetch(url));                          // fetched content executed  → HIGH
```

It does **not** claim a relationship because a source and a sink both appear in a file.
`process.env.NPM_TOKEN` on line 3 and `https.request` on line 40 produce two independent
findings and nothing more. Multi-statement, interprocedural and cross-module relationships
are the behaviour engine's problem, under its own evidence rules, documented in
`BEHAVIOUR_ANALYSIS.md`. Chains asserted without a demonstrable data path are the easiest
thing in this product to get dishonestly right-looking, and this package does not do it.

---

## 4. Calibration

The calibration target comes from `RISK_MODEL.md` and is enforced by tests:

- **A legitimate build tool produces nothing above LOW.** A file that spawns `tsc`, reads
  `process.env.NODE_ENV`, reads and writes files and calls `os.platform()` yields nine
  findings, all LOW. If that file produced a high-severity finding, the analyser would be
  flagging a large share of the registry, and the gate would be switched off — after which
  our true-positive rate is zero.
- **Two hundred `process.env` reads stay LOW.** Volume of a mundane behaviour is not
  severity.
- **Minification raises nothing.** Bundled `dist/` output is how much of the registry ships;
  treating it as suspicious is treating "uses a build step" as suspicious. The identical
  program in readable and minified form produces the same rules at the same severities. Its
  only effects are a **confidence** reduction (`RISK_MODEL.md` §4.3) and suppression of the
  high-entropy-literal rule. Obfuscation attacks the denominator — it removes our right to
  say `ALLOW`; it does not earn a `BLOCK`.
- **Confidence is about detection, not danger.** `process.env.NODE_ENV` is HIGH confidence
  and LOW severity. Computed member access drops confidence to MEDIUM because the member is
  a guess, even though the object is not.

---

## 5. Limitations

Stated plainly, because a scanner that hides these is worse than no scanner.

### 5.1 Dynamic behaviour is invisible

Static analysis sees what the code *can* do, never what it *does*. Behaviour behind a
condition — a date check, a CI check, a hostname check, a flag read from a remote server —
is reported as capability with no notion of whether it ever executes. Conversely, code that
never runs is still reported. Reachability from an entry point is **not** computed by this
package.

### 5.2 Computed member access

`obj[name]` where `name` is not a literal resolves the *object* but not the *member*. Such
findings carry MEDIUM confidence, and rules that need a specific member simply do not fire.
`process[decode(x)].NPM_TOKEN` is reported as dynamic dispatch on `process`, not as a
credential read. This is a real gap and it is exactly the gap an evasive package will use.

### 5.3 No cross-file dataflow

Resolution is per file. A credential read in `a.js`, exported, imported by `b.js` and sent
from there produces two unrelated findings. Cross-module linkage is the behaviour engine's
remit and is limited even there.

### 5.4 Module names built from strings

`require("child" + "_process")`, `require(names[i])` and `require(atob(blob))` are not
resolved to a module. The first two are reported as dynamic-require findings; none of them
attributes the resulting calls to a capability. Constant folding is limited to literal
concatenation of literals — the analyser will not evaluate expressions, because evaluating
attacker-controlled expressions is the thing it exists to avoid.

### 5.5 No values are tracked through function boundaries

A wrapper — `function run(c) { return exec(c); }` — is resolved at the `exec` call, but the
*value* of `c` at any call site of `run` is not. No constant propagation, no return-value
modelling, no aliasing through object properties or arrays.

### 5.6 Only JavaScript and TypeScript are parsed

Shell scripts, Python, PowerShell, batch files, WASM, native addons and compiled binaries
are recorded as present and unanalysed. A `postinstall` that runs `install.sh` produces the
lifecycle finding and the recovered reference, and the contents of `install.sh` are not
examined. **Every one of these reduces analysis coverage, which is reported and which
constrains the risk engine's right to say `ALLOW` (`RISK_MODEL.md` §9).**

### 5.7 Error-recovered ASTs are approximations

A file parsed with recovered syntax errors yields an AST that is not exactly the program.
`recoveredParseErrors` is reported per file so this is visible rather than assumed away.

### 5.8 Pattern lists are incomplete and always will be

Credential paths, collector hosts, HTTP client packages and secret environment names are
curated lists. They cover the common cases and can be evaded by anyone who reads this file.
They are supplements to AST analysis applied *inside already-parsed literals*, never a
substitute for it.

### 5.9 Known false-positive shapes

Publishing and deployment tooling reads `NPM_TOKEN` and `.npmrc` and sends data to a remote
host — structurally identical to a credential stealer, separable only by destination and
purpose, and purpose is not statically decidable. Prebuilt-binary installers download and
execute; telemetry collects host information; plugin systems use dynamic `require`;
credential-chain libraries name every credential path in this document. These are reported
and expected to be handled by suppression baselines (`RISK_MODEL.md` §7.4), not by
weakening the rules.

### 5.10 Nothing here proves absence

A `COMPLETED` analysis with zero findings means the rules above did not match the code we
could parse, in the files we were given, within the budgets we applied. It does not mean the
package is safe, and no consumer of this output may present it that way.

---

## 6. Reproducibility

Every result carries `rulesVersion`. Finding ids are deterministic. Given the same file
content and the same rules version, the analyser produces byte-identical findings, offline,
with no network access and no clock dependence. A result that cannot be reproduced from
those identifiers is a bug.
