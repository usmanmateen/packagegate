"""Package MIL training entrypoint — requires slice embeddings first."""

from __future__ import annotations

import json
import sys


def main() -> None:
    print(
        json.dumps(
            {
                "ok": False,
                "reason": (
                    "Package MIL training requires frozen slice embeddings and a "
                    "verified package-level corpus. Complete Experiment 0 "
                    "(structured baseline) and slice encoder training first."
                ),
            },
            indent=2,
        )
    )
    sys.exit(3)


if __name__ == "__main__":
    main()
