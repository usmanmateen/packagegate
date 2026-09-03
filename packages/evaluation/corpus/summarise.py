#!/usr/bin/env python3
"""Summarise a control-corpus run into the numbers we publish."""

import collections
import json
import statistics
import sys
from pathlib import Path

path = Path(sys.argv[1] if len(sys.argv) > 1 else "packages/evaluation/corpus/results.jsonl")
rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
ok = [r for r in rows if r.get("status") == "OK"]
bad = [r for r in rows if r.get("status") != "OK"]

print(f"corpus size     : {len(rows)}")
print(f"analysed        : {len(ok)}")
print(f"errored         : {len(bad)}" + (f"  {[r['package'] for r in bad]}" if bad else ""))

if not ok:
    sys.exit("no successful scans to summarise")

actions = collections.Counter(r["final"] for r in ok)
flagged = [r for r in ok if r["final"] in ("REVIEW", "BLOCK")]
scores = sorted(r["score"] for r in ok)

print(f"\nfinal action    : {dict(actions)}")
print(f"flag rate       : {len(flagged)}/{len(ok)} = {len(flagged) / len(ok) * 100:.1f}%")
print(
    f"score           : median={statistics.median(scores)} "
    f"mean={statistics.mean(scores):.1f} "
    f"p95={scores[int(len(scores) * 0.95)]} max={scores[-1]}"
)
print(f"behaviour chains: {sum(1 for r in ok if r['chains'])} package(s) emitted any chain")

if flagged:
    print("\nflagged packages:")
    for r in sorted(flagged, key=lambda r: -r["score"]):
        driver = "completeness" if r["recommendation"] == "ALLOW" else "behaviour"
        print(
            f"  {r['package']:14} score={r['score']:3} {r['final']:7} "
            f"driver={driver:12} coverage={r['coverage']:.3f} chains={r['chains']}"
        )
