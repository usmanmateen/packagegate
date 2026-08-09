# Model card — PG-SLICE-V1

## Intended use

Security **behaviour** representation learning over PackageGate
`STRICT_SECURITY_VIEW` slices. Silver multi-label targets come from
deterministic PackageGate evidence overlapping each slice.

**Not** proof that a package is safe or malicious.

## Base model

| Field | Value |
| --- | --- |
| ID | `microsoft/graphcodebert-base` |
| Revision | `2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d` |
| Architecture used | RoBERTa encoder (CLS pooling); original GraphCodeBERT data-flow inputs **not** used |
| Max sequence length | 512 |
| `trust_remote_code` | `false` |

## Data

- Dataset: frozen V4 + SliceSchemaV2 neural export
- Splits: family-grouped V4 (`ml/data-manifests/v4/neural/`)
- `02-echo@0.0.7` excluded from train/validation

## Labels (silver)

network_access, environment_access, system_information_access,
dynamic_code_execution, install_time_execution, process_execution,
home_directory_access, payload_decode, opaque_executable_source,
shell_execution, remote_download, remote_code_fetch

## Training

- Loss: BCEWithLogits + positive class weights
- Optimiser: AdamW 2e-5, bf16 when supported
- Epochs: 3 (validation micro-F1 selection)
- Checkpoint: `/home/usman/packagegate-ml-models/20260809T191708Z-pg-slice-v1/best.pt` (not in git)

## Untouched slice test (approx.)

- micro-F1 ≈ 0.85
- macro-F1 ≈ 0.79

## Limitations

- Silver labels inherit PackageGate coverage gaps
- ~16% of slices truncate at 512 tokens
- Identity-masked text may remove useful naming cues (intentional)
- Does not consume PackageGate graphs as GraphCodeBERT originally did
