#!/usr/bin/env bash
# Export inert fixture ML records for structured baseline smoke training.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/ml/data/exports"
mkdir -p "$OUT"
CLI=(node "$ROOT/packages/cli/dist/bin.js")

declare -A LABELS=(
  [inert-normal-installer]=EXPECTED_BENIGN
  [inert-shell-cooccurrence-negative]=EXPECTED_BENIGN
  [version-diff-benign-v1]=EXPECTED_BENIGN
  [version-diff-line-shift-v1]=EXPECTED_BENIGN
  [version-diff-line-shift-v2]=EXPECTED_BENIGN
  [inert-env-exfil]=SYNTHETIC_SUSPICIOUS
  [inert-install-curl-bash]=SYNTHETIC_SUSPICIOUS
  [inert-powershell-irm-iex]=SYNTHETIC_SUSPICIOUS
  [version-diff-remote-v2]=SYNTHETIC_SUSPICIOUS
)

for name in "${!LABELS[@]}"; do
  "${CLI[@]}" ml-export "$name" > "$OUT/$name.json"
  printf '%s\n' "${LABELS[$name]}" > "$OUT/$name.label"
done

echo "Exported ${#LABELS[@]} fixture ML records to $OUT"
