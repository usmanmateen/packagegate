#!/usr/bin/env bash
#
# Measure PackageGate's flag rate against widely used npm packages.
#
# False positives are this project's central product risk, so the number that
# matters most is how often the scanner escalates a package the ecosystem
# already depends on. Run from the repository root after `pnpm build`:
#
#   ./packages/evaluation/corpus/run-control-corpus.sh
#   python3 packages/evaluation/corpus/summarise.py
#
# Scans are sequential and paced. npm publishes no numeric rate limit but bans
# by IP and user-agent, so this stays at roughly one package per second.
#
# These packages are treated as EXPECTED_BENIGN because the ecosystem depends on
# them, not because anyone has proven them clean. See docs/LIMITATIONS.md.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$root"

list="${1:-packages/evaluation/corpus/control-packages.txt}"
out="${2:-packages/evaluation/corpus/results.jsonl}"
bin="packages/cli/dist/bin.js"

[ -f "$bin" ] || { echo "Build first: pnpm build" >&2; exit 1; }

: > "$out"
total=$(grep -cve '^\s*$' "$list")
i=0

while read -r pkg; do
  [ -z "$pkg" ] && continue
  i=$((i + 1))
  printf '\r  scanning %d/%d %-24s' "$i" "$total" "$pkg" >&2
  json=$(timeout 120 node "$bin" scan "$pkg" --json 2>/dev/null)
  if [ -z "$json" ]; then
    printf '{"package":"%s","status":"ERROR"}\n' "$pkg" >> "$out"
  else
    printf '%s' "$json" | PKG="$pkg" python3 -c '
import json, os, sys
pkg = os.environ["PKG"]
try:
    d = json.load(sys.stdin)
except Exception:
    print(json.dumps({"package": pkg, "status": "BADJSON"})); raise SystemExit
risk = d.get("risk") or {}
policy = d.get("finalPolicy") or {}
completeness = d.get("analysisCompleteness") or {}
print(json.dumps({
    "package": pkg,
    "status": "OK",
    "resolved": (d.get("resolved") or {}).get("version"),
    "score": risk.get("score"),
    "recommendation": risk.get("recommendation"),
    "final": policy.get("finalAction"),
    "chains": len(d.get("behaviourChains") or []),
    "findings": len(d.get("findings") or []),
    "completeness": completeness.get("status"),
    "coverage": completeness.get("coverageRatio"),
}))' >> "$out"
  fi
  sleep 0.4
done < "$list"

printf '\r  scanned %d packages -> %s\n' "$i" "$out" >&2
