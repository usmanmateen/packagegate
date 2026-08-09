"""Shared constants for PackageGate neural V1 (GraphCodeBERT + MIL)."""

from __future__ import annotations

BASE_MODEL_ID = "microsoft/graphcodebert-base"
BASE_MODEL_REVISION = "2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d"
MAX_SEQ_LENGTH = 512
SLICE_SCHEMA_VERSION = 2

# Behaviour silver labels with adequate train+val support (>=50 observed).
BEHAVIOUR_LABELS_V1: tuple[str, ...] = (
    "network_access",
    "environment_access",
    "system_information_access",
    "dynamic_code_execution",
    "install_time_execution",
    "process_execution",
    "home_directory_access",
    "payload_decode",
    "opaque_executable_source",
    "shell_execution",
    "remote_download",
    "remote_code_fetch",
)

# Excluded from V1 targets due to tiny support (documented, not trained):
# sensitive_file_access, package_manager_access, credential_access (<50)
