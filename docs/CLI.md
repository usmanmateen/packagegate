# PackageGate CLI

Static analysis only. Package code is **never** executed.

## Commands

```bash
# Registry scan — resolves via npm, can verify registry-declared integrity
pnpm scan lodash@4.17.21
pnpm packagegate scan express@4.21.2 --json
pnpm packagegate scan lodash@4.17.21 --ml

# Local preserved tarball — same investigation pipeline after secure extraction
pnpm packagegate scan-tarball ./preserved-package.tgz
pnpm packagegate scan-tarball ./preserved-package.tgz --sha256 <64-hex-digest>

# Security semantic version diff (not a text diff)
pnpm packagegate diff express@4.20.0 express@4.21.2 --color
pnpm packagegate diff version-diff-benign-v1 version-diff-remote-v2 --color

# Inert offline fixture (never executed)
pnpm packagegate fixture inert-env-exfil --color

# Versioned ML feature/slice export (for training pipelines)
pnpm packagegate ml-export inert-install-curl-bash

# Repeatable evaluation harness (real malware never auto-downloaded)
pnpm packagegate evaluate --json
pnpm packagegate evaluate --malware-root /tmp/packagegate-malware-eval
```

## Investigation questions

1. **What does this package do?** → `scan` / `scan-tarball` / `fixture`
2. **What changed between releases?** → `diff`
3. **What should an analyst do?** → behavioural risk + completeness + threat intel + final policy

## Integrity / intel semantics

| Lane | Meaning |
| --- | --- |
| Behavioural risk | What the artefact appears to do |
| Analysis completeness | How much executable source was fully analysed |
| Threat intelligence | Exact known-bad / known-vulnerable records (offline `none` by default) |
| Final policy | Deterministic combination of the lanes above |

Real malware evaluation requires an explicit `--malware-root`. PackageGate never auto-downloads malware.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The command ran successfully |
| `1` | Usage error — unknown command, missing or invalid arguments |
| `2` | The scan could not be completed — package not found, invalid specifier, registry unavailable, artifact limit exceeded, malformed archive, integrity mismatch |

**The verdict does not affect the exit code.** A package that scores `REVIEW`
still exits `0`, because `0` means "the investigation completed", not "the
package is fine". Conflating the two would make a registry outage
indistinguishable from a clean result — the failure mode this project cares most
about avoiding.

Consumers that want to gate on a verdict should read it from `--json`:

```bash
action=$(packagegate scan "$pkg" --json | jq -r '.finalPolicy.finalAction')
[ "$action" = "ALLOW" ] || exit 1
```

There is currently no `--fail-on` flag. See the limitations section of the
README for the known gaps.

## JSON output

`--json` writes a single JSON document to stdout and nothing else. Diagnostics
go to stderr. When invoking through the pnpm script, pass `pnpm --silent` so
pnpm's own banner does not precede the document:

```bash
pnpm --silent packagegate scan lodash@4.17.21 --json | jq .risk
```
