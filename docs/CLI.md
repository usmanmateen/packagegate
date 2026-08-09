# PackageGate CLI

Static analysis only. Package code is **never** executed.

## Commands

```bash
# Registry scan — resolves via npm, can verify registry-declared integrity
pnpm scan lodash@4.17.21
pnpm packagegate scan express@4.21.2 --json

# Local preserved tarball — same investigation pipeline after secure extraction
pnpm packagegate scan-tarball ./preserved-package.tgz
pnpm packagegate scan-tarball ./preserved-package.tgz --sha256 <64-hex-digest>

# Security semantic version diff (not a text diff)
pnpm packagegate diff express@4.20.0 express@4.21.2 --color

# Inert offline fixture (never executed)
pnpm packagegate fixture inert-env-exfil --color

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
