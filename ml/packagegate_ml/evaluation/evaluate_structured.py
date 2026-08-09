"""Summarise structured baseline run metrics."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNS = ROOT / "runs"


def main() -> None:
    runs = sorted(RUNS.glob("*-structured"))
    if not runs:
        print(json.dumps({"ok": False, "reason": "No structured runs found"}, indent=2))
        return
    latest = runs[-1]
    meta = json.loads((latest / "metadata.json").read_text(encoding="utf-8"))
    print(json.dumps({"ok": True, "run": str(latest), "metrics": meta.get("metrics")}, indent=2))


if __name__ == "__main__":
    main()
