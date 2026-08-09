"""Build feature tables from PackageGate ml-export JSON files."""

from __future__ import annotations

import json
from pathlib import Path

from packagegate_ml.features.structured import export_to_feature_row

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXPORT_DIR = ROOT / "data" / "exports"
DEFAULT_OUT = ROOT / "data" / "features" / "smoke_features.jsonl"


def main() -> None:
    export_dir = DEFAULT_EXPORT_DIR
    out = DEFAULT_OUT
    out.parent.mkdir(parents=True, exist_ok=True)
    if not export_dir.exists():
        print(
            json.dumps(
                {
                    "ok": False,
                    "reason": f"No exports at {export_dir}. Run scripts/export_smoke_features.sh first.",
                },
                indent=2,
            )
        )
        return

    count = 0
    with out.open("w", encoding="utf-8") as handle:
        for path in sorted(export_dir.glob("*.json")):
            export = json.loads(path.read_text(encoding="utf-8"))
            features = export_to_feature_row(export)
            # Labels come from companion sidecar or filename convention — never paths.
            label_path = path.with_suffix(".label")
            label = (
                label_path.read_text(encoding="utf-8").strip()
                if label_path.exists()
                else "UNKNOWN"
            )
            row = {
                "sample_id": path.stem,
                "label": label,
                "features": features,
            }
            handle.write(json.dumps(row) + "\n")
            count += 1
    print(json.dumps({"ok": True, "rows": count, "out": str(out)}, indent=2))


if __name__ == "__main__":
    main()
