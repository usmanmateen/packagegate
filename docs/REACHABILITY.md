# Install reachability

A published npm package contains everything the publisher chose to ship:
sources, bundled output, test suites, fixtures, documentation samples. Only some
of it can run when the package is installed or required.

PackageGate computes which files are **install-reachable** so that its
completeness verdict can distinguish two genuinely different situations:

- we could not parse code that can actually run, and
- we could not parse a file nothing points at.

## The problem this solves

Running the scanner across 131 widely used packages produced six escalations.
Five of them carried a behavioural recommendation of `ALLOW` and zero behaviour
chains. They were escalated purely because some file failed to parse.

The clearest case was `pino`, escalated at **99.4% coverage** because of one
file:

```
test/fixtures/syntax-error-esm.mjs — Unexpected token, expected "{" (3:0)
```

A deliberately invalid 33-byte fixture, shipped in the tarball, whose entire
purpose is to be unparseable. `zustand` scored **0** and was escalated for the
same reason.

Interrupting an engineer over a test fixture is the kind of false positive that
gets a scanner switched off.

## What is not the fix

**Ignoring `test/`, `__fixtures__/`, `examples/` and friends.** A path heuristic
is trivially defeated: a package that puts its payload in `test/` gets a free
pass, and the heuristic becomes an instruction manual for hiding.

## The approach

A file is install-reachable if it is:

1. a declared entrypoint — `main`, `module`, `browser`, `types`, or any string
   leaf of `exports` or `bin` (conditional exports maps are traversed fully);
2. referenced by an install lifecycle script (`preinstall`, `install`,
   `postinstall`, `prepare`); or
3. transitively imported from (1) or (2) through **static** relative specifiers
   — `require("./x")`, `import … from "./x"`, `export … from "./x"`,
   `import("./x")`.

Bare specifiers (`require("lodash")`) resolve into `node_modules` and are not
followed; a sibling file that happens to share the name is a different thing.
Directory and extensionless specifiers resolve the way Node resolves them.

Reachability is derived from the declared graph, never from path shape. **A
package whose entrypoint genuinely lives under `test/` is fully reachable**, and
a payload placed under `test/` is reachable the moment anything points at it.

## The security tradeoff, stated plainly

**Unreachable does not mean inert.** The graph is built from static specifiers.
A `require(someVariable)`, a path assembled at runtime, or a consumer
deep-importing an internal path all reach code this analysis calls unreachable.

Four things keep that honest:

1. **Unreachable files are still fully analysed.** Reachability never suppresses
   a finding, a behaviour chain, or a risk contribution. It affects only how a
   *parse failure* is weighed in the completeness verdict. Malicious code in an
   unreachable file is still detected and still scored.
2. **The gap is still reported.** It appears in `analysisCompleteness.reasons`
   with `installReachable: false`. Nothing is hidden; it is labelled.
3. **Any unresolvable dynamic import disables the optimisation.** If the package
   contains a `require()` whose target we cannot determine statically, the graph
   is untrustworthy and every file is treated as reachable.
4. **It fails closed.** With no manifest, no declared entrypoint, or entrypoints
   that resolve to nothing we extracted, the function returns "cannot compute"
   and everything counts as reachable. A package cannot suppress the
   completeness signal by shipping a broken manifest.

The residual risk is a package that hides an unparseable payload in a file
reached only dynamically. That package still gets its findings scored; what it
avoids is a *completeness* downgrade. Given the alternative — escalating on
every deliberately invalid test fixture in the ecosystem — this is the better
trade, and it is bounded by the four properties above.

## Effect

Measured across the 131-package control corpus, before and after:

| | Before | After |
| --- | --- | --- |
| `ALLOW` | 125 | 128 |
| `REVIEW` | 6 | 3 |
| Flag rate | 4.6% | **2.3%** |
| Behaviour chains emitted | 0 | 0 |

Relieved: `pino`, `zustand`, `graphql` — each had exactly one unreachable gap.

Still escalated, correctly:

- `astro` — 39 gaps, of which **3 are reachable** executable source
- `playwright` — 1 reachable gap
- `next` — 27% coverage, 7,241 reachable gaps, below the coverage floor

No package was relieved that had a reachable gap, and no score changed. The
change moves only the completeness verdict, and only for gaps the package's own
declarations do not point at.
