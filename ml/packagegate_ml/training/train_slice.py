"""Slice encoder training entrypoint — gated until data quality is verified."""

from __future__ import annotations

import argparse
import json
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune security slice encoder")
    parser.add_argument(
        "--confirm-download",
        action="store_true",
        help="Acknowledge model download after dataset quality checks",
    )
    parser.add_argument(
        "--config",
        default="configs/slice_graphcodebert.yaml",
        help="Training config path",
    )
    args = parser.parse_args()
    if not args.confirm_download:
        print(
            json.dumps(
                {
                    "ok": False,
                    "reason": (
                        "Refusing to download/fine-tune code models until dataset "
                        "quality checks pass. Re-run with --confirm-download after "
                        "structured baseline + leakage tests succeed."
                    ),
                    "config": args.config,
                },
                indent=2,
            )
        )
        sys.exit(2)
    print(
        json.dumps(
            {
                "ok": False,
                "reason": (
                    "Neural fine-tuning scaffold is present but no verified training "
                    "corpus with grouped splits + hard negatives is loaded yet. "
                    "Install optional torch extras and provide ml/data exports from "
                    "an external malware root before training."
                ),
            },
            indent=2,
        )
    )
    sys.exit(3)


if __name__ == "__main__":
    main()
