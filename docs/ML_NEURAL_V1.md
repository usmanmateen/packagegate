# PackageGate — Neural V1 data freeze (pre-training)

**Status:** slice-rich V4 neural export frozen  
**Export:** `/tmp/packagegate-ml-data-v4/exports/v4-neural/`  
**Manifests:** `ml/data-manifests/v4/neural/`  
**Splits:** unchanged from Dataset V4  

## Why slices were empty (before)

| Reason | Count (980 exports) |
| --- | ---: |
| Exporter hard-coded `slices: []` in `investigation_to_mle_export` | **980** |
| Findings present but no filePath flat fields in audit (nested `location`) | 773 |
| No findings / no evidence locations | 207 |
| Missing export file | 12 |

Root cause: **feature-export implementation omitted slice generation** (not missing evidence). TS `buildSecuritySlices` existed but the Python pilot path never called it or loaded `sourceByPath`.

## Coverage after SliceSchemaV2

| Population | n | total slices | mean | median | p90 | ge1 | ge2 | zeros |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| All available exports | 980 | 11034 | 11.3 | 6 | 32 | 99.4% | 92.9% | 6 |
| Matched benchmark | 305 | 3562 | 11.7 | 6 | 32 | **99.0%** | **92.1%** | 3 |

Pre-registered coverage gate: matched ≥95% with ≥1 slice and ≥80% with ≥2 — **PASS**.  
Leakage audit on strict records: **0** flags — **PASS**.

Zero-slice packages remain in evaluation with `codeViewAvailable: false` (structured path only).

## Slice strategy

- Evidence windows from findings / chain links / lifecycle / main·bin entrypoints
- Dedup by content hash + token fingerprint
- Priority ranking + per-category diversity (max 6, fill remaining)
- Max 32 slices/package (configurable)
- STRICT masking via existing `identity_mask` / `record_v2` helpers
- `package.json` slices use security-manifest view (no name/version/repo)

**PyTorch / GraphCodeBERT:** not installed until this freeze.
