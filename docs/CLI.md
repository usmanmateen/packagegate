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
pnpm packagegate scan-tarball ./preserved-package.tgz --json

# Inert offline fixture (never executed)
pnpm packagegate fixture inert-env-exfil --color
```

## Integrity semantics

| Source | Registry integrity |
| --- | --- |
| `scan` (npm registry) | Verified when the registry digest matches the downloaded bytes |
| `scan-tarball` | **Not verified** — PackageGate hashes the file (SHA-256) but has no trusted registry digest unless you pass `--sha256` |

A local artifact is not automatically malicious. Unknown provenance is reported honestly; it does not invent behavioural risk.

## Architecture

```
registry acquisition ──┐
                       ├──▶ secure extraction ──▶ analyser ──▶ behaviour ──▶ risk ──▶ report
local tarball ─────────┘
```

Acquisition differs. Investigation does not.
