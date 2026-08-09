"""Hardware / environment reproducibility snapshot for PackageGate ML."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str]) -> str | None:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return out.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def collect_system_info() -> dict:
    info: dict = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
    }

    try:
        import psutil  # type: ignore

        mem = psutil.virtual_memory()
        info["ram_total_gb"] = round(mem.total / (1024**3), 2)
        info["ram_available_gb"] = round(mem.available / (1024**3), 2)
    except Exception:
        # Fallback: /proc/meminfo
        try:
            text = Path("/proc/meminfo").read_text(encoding="utf-8")
            for line in text.splitlines():
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    info["ram_total_gb"] = round(kb / (1024**2), 2)
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    info["ram_available_gb"] = round(kb / (1024**2), 2)
        except OSError:
            pass

    usage = shutil.disk_usage(Path.home())
    info["disk_free_gb"] = round(usage.free / (1024**3), 2)

    info["nvidia_smi"] = _run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"])

    try:
        import torch

        info["torch"] = torch.__version__
        info["cuda_available"] = bool(torch.cuda.is_available())
        if torch.cuda.is_available():
            info["cuda_device"] = torch.cuda.get_device_name(0)
            info["cuda_capability"] = ".".join(
                str(x) for x in torch.cuda.get_device_capability(0)
            )
            props = torch.cuda.get_device_properties(0)
            info["vram_total_gb"] = round(props.total_memory / (1024**3), 2)
    except Exception as exc:  # noqa: BLE001 — optional dependency
        info["torch"] = None
        info["cuda_available"] = False
        info["torch_import_error"] = str(exc)

    return info


def main() -> None:
    print(json.dumps(collect_system_info(), indent=2))


if __name__ == "__main__":
    main()
