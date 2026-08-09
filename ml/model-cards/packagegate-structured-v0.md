# PackageGate structured ML baseline (Experiment 0)

## Intended use

Classical classifier over PackageGate structured findings/chain features to
establish a floor **before** fine-tuning code encoders.

## Not intended use

- Proof that a package is safe
- Independent BLOCK decisions
- Replacement for deterministic findings

## Data

Smoke exports from inert fixtures only. Real malware must live outside git
under an explicit quarantine root.

## Leakage controls

- No final policy / threat-intel features
- Package names hashed
- Qualitative holdouts (`02-echo@0.0.7`, lodash/express/debug/JSONStream)
  excluded from train/validation

## Limitations

Tiny smoke corpora are **not** statistically meaningful. Treat metrics as
pipeline validation only until a curated benign hard-negative + malicious
corpus exists.
