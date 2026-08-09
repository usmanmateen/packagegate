"""PackageGateMlRecordV2 — identity-masked STRICT_SECURITY_VIEW model input."""

from __future__ import annotations

import json
import re
from typing import Any

from packagegate_ml.datasets.feature_families import (
    BEHAVIOUR_SCALAR_KEYS,
    COMPLETENESS_KEYS,
    behaviour_features,
    completeness_features,
)
from packagegate_ml.features.identity_mask import (
    normalise_source_path,
    prepare_strict_source,
    security_manifest_view,
)

ML_EXPORT_SCHEMA_V2 = 2
FORBIDDEN_MODEL_KEYS = frozenset(
    {
        "packageName",
        "package_name",
        "datasetSource",
        "dataset_source",
        "labelSource",
        "label_source",
        "label",
        "familyGroup",
        "family_group",
        "sampleId",
        "sample_id",
        "artifactPath",
        "artifact_path",
        "attackCategory",
        "attack_category",
        "author",
        "maintainers",
        "repository",
        "homepage",
        "description",
        "keywords",
        "funding",
        "finalPolicy",
        "threatIntelligence",
        "nameHash",
    }
)
# Keys forbidden only at top-level / package / manifest identity contexts
FORBIDDEN_IDENTITY_VALUE_KEYS = frozenset({"version", "name"})

# Non-behaviour fields that may remain in strict view (completeness only).
STRICT_COMPLETENESS_KEYS = list(COMPLETENESS_KEYS) + [
    "coverageRatio",  # analysis coverage — security completeness
]

# If somehow present, these are STRICT_INPUT_NUISANCE (should be near-empty).
STRICT_NUISANCE_SURVIVOR_KEYS = [
    "fileCount",
    "analysedExecutableBytes",
]


def behaviour_only_from_structured(structured: dict[str, Any]) -> dict[str, float]:
    """Primary PG-Package structured features: behaviour + completeness only."""
    return behaviour_features(structured)


def strict_input_nuisance(structured: dict[str, Any]) -> dict[str, float]:
    """
    Non-behaviour fields that survive into a strict record (should be minimal).

    Primary STRICT_SECURITY_VIEW excludes these from the behaviour model; this
    extractor measures residual packaging proxies if accidentally retained.
    """
    out = {k: float(structured.get(k, 0)) for k in STRICT_NUISANCE_SURVIVOR_KEYS}
    # Truncation flags from mlInputCompleteness if present at top level
    for k in ("slicesAvailable", "slicesUsed", "truncationOccurred"):
        if k in structured:
            out[k] = float(structured[k])
    return out


def _mask_slice(
    slice_rec: dict[str, Any],
    *,
    package_name: str | None,
    version: str | None,
    strict: bool,
) -> dict[str, Any]:
    path = slice_rec.get("filePath") or slice_rec.get("file_path") or ""
    text = slice_rec.get("sourceText") or slice_rec.get("source_text") or ""
    norm_path = normalise_source_path(path, package_name=package_name, version=version)
    if strict:
        text = prepare_strict_source(
            text, package_name=package_name, version=version, remove_comments=True
        )
    return {
        "sliceId": slice_rec.get("sliceId") or slice_rec.get("slice_id"),
        "filePath": norm_path,
        "startLine": slice_rec.get("startLine") or slice_rec.get("start_line"),
        "endLine": slice_rec.get("endLine") or slice_rec.get("end_line"),
        "sourceText": text,
        "lifecycleReachable": bool(
            slice_rec.get("lifecycleReachable")
            or slice_rec.get("lifecycle_reachable")
        ),
        "lifecycleHook": slice_rec.get("lifecycleHook") or slice_rec.get("lifecycle_hook"),
        "deterministicFindings": list(
            slice_rec.get("deterministicFindings")
            or slice_rec.get("deterministic_findings")
            or []
        ),
        "behaviourLabels": list(
            slice_rec.get("behaviourLabels") or slice_rec.get("behaviour_labels") or []
        ),
        "behaviourChainMembership": list(
            slice_rec.get("behaviourChainMembership")
            or slice_rec.get("behaviour_chain_membership")
            or []
        ),
    }


def build_package_gate_ml_record_v2(
    *,
    v1_or_export: dict[str, Any],
    package_name: str | None,
    version: str | None,
    package_json: dict[str, Any] | None = None,
    view: str = "STRICT_SECURITY_VIEW",
) -> dict[str, Any]:
    """
    Build identity-masked model input from a V1 export / investigation export.

    Training metadata (name, label, source) must NOT be copied into this object.
    """
    structured = dict(v1_or_export.get("structuredFeatures") or v1_or_export.get("structured") or {})
    # Drop optional behaviouralScore from primary unless ablation asks later
    structured.pop("behaviouralScore", None)

    behaviour = behaviour_only_from_structured(structured)
    # Explicitly omit packaging nuisance from primary structured block
    for k in STRICT_NUISANCE_SURVIVOR_KEYS:
        behaviour.pop(k, None)

    lifecycle = []
    for item in v1_or_export.get("lifecycle") or []:
        lifecycle.append(
            {
                "hook": item.get("name") or item.get("hook"),
                "command": item.get("command"),
            }
        )

    findings = []
    for f in v1_or_export.get("findings") or []:
        fpath = f.get("filePath") or f.get("file_path") or ""
        findings.append(
            {
                "id": f.get("id"),
                "category": f.get("category"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "filePath": normalise_source_path(
                    fpath, package_name=package_name, version=version
                ),
                "startLine": f.get("startLine") or f.get("start_line"),
                "endLine": f.get("endLine") or f.get("end_line"),
                # titles may contain paths; keep category/severity as primary signal
                "title": f.get("title"),
            }
        )

    chains = []
    for c in v1_or_export.get("chains") or []:
        chains.append(
            {
                "id": c.get("id"),
                "source": c.get("source"),
                "sink": c.get("sink"),
                "confidence": c.get("confidence"),
                "chainType": c.get("chainType") or c.get("chain_type"),
            }
        )

    strict = view == "STRICT_SECURITY_VIEW"
    slices = [
        _mask_slice(s, package_name=package_name, version=version, strict=strict)
        for s in (v1_or_export.get("slices") or [])
    ]

    completeness = v1_or_export.get("completeness") or {}
    ml_complete = v1_or_export.get("mlInputCompleteness") or {}

    record = {
        "schemaVersion": ML_EXPORT_SCHEMA_V2,
        "view": view,
        # No package.name / package.version / nameHash
        "artifact": {
            # content hash of canonical bytes is ok (not identity); omit path
            "sha256": (v1_or_export.get("artifact") or {}).get("sha256"),
        },
        "securityManifest": security_manifest_view(package_json),
        "lifecycle": lifecycle,
        "findings": findings,
        "chains": chains,
        "completeness": {
            "status": completeness.get("status"),
            "coverageRatio": completeness.get("coverageRatio"),
        },
        "structuredBehaviourFeatures": behaviour,
        "slices": slices,
        "mlInputCompleteness": {
            "slicesAvailable": ml_complete.get("slicesAvailable"),
            "slicesUsed": ml_complete.get("slicesUsed"),
            "truncationOccurred": ml_complete.get("truncationOccurred"),
        },
    }
    return record


COMMON_ENGLISH_TOKENS = frozenset(
    {
        "request",
        "http",
        "https",
        "fs",
        "path",
        "os",
        "util",
        "crypto",
        "stream",
        "buffer",
        "events",
        "url",
        "query",
        "string",
        "object",
        "array",
        "error",
        "debug",
        "log",
        "test",
        "index",
        "main",
        "lib",
        "src",
        "bin",
        "dist",
        "build",
        "core",
        "common",
        "utils",
        "helper",
        "helpers",
        "config",
        "cli",
        "api",
        "sdk",
        "client",
        "server",
        "node",
        "npm",
        "yarn",
        "pnpm",
        "express",
        "react",
        "vue",
        "next",
        "type",
        "types",
        "data",
        "file",
        "files",
        "package",
        "module",
        "modules",
        "script",
        "scripts",
        "install",
        "setup",
        "init",
        "run",
        "exec",
        "spawn",
        "fork",
        "shell",
        "bash",
        "curl",
        "wget",
        "env",
        "home",
        "user",
        "tmp",
        "temp",
        "json",
        "yaml",
        "xml",
        "html",
        "css",
        "js",
        "ts",
    }
)


def audit_strict_record_leakage(
    record: dict[str, Any],
    *,
    package_name: str | None,
    version: str | None,
) -> list[str]:
    """Return list of leakage findings (empty = pass)."""
    issues: list[str] = []
    text = json.dumps(record, sort_keys=True)

    def walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in FORBIDDEN_MODEL_KEYS:
                    issues.append(f"forbidden_key:{path}.{k}" if path else f"forbidden_key:{k}")
                # Identity keys only banned outside lifecycle/findings technical fields
                if k in FORBIDDEN_IDENTITY_VALUE_KEYS and not path.startswith(
                    ("lifecycle", "findings", "chains", "slices", "structuredBehaviour")
                ):
                    if path.startswith("securityManifest") or path == "" or path.startswith("artifact"):
                        issues.append(
                            f"identity_key:{path}.{k}" if path else f"identity_key:{k}"
                        )
                walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")

    walk(record)

    # Structured field probes
    if version and len(version) >= 5 and version in text:
        # allow if version only appears inside lifecycle command that is behavioural —
        # still flag top-level structured keys
        if '"version"' in text.lower() and "securityManifest" in text:
            # version key inside securityManifest should not exist
            sm = record.get("securityManifest") or {}
            if "version" in sm or "name" in sm:
                issues.append("manifest_identity_field")

    if package_name and len(package_name) >= 4:
        bare = package_name.split("/")[-1]
        # Skip common English tokens to avoid false positives
        if bare.lower() not in COMMON_ENGLISH_TOKENS and len(bare) >= 5:
            # Only flag self-root path leak: first path segment == package bare name
            for s in record.get("slices") or []:
                fp = (s.get("filePath") or "").replace("\\", "/")
                first = fp.split("/", 1)[0] if fp else ""
                if first == bare:
                    issues.append(f"path_contains_package_token:{fp}")
            if re.search(rf'"name"\s*:\s*"{re.escape(package_name)}"', text):
                issues.append("literal_package_name_field")

    # Dataset path / label-source tokens must not appear as model context.
    # Do not flag substrings inside network destinations / shell evidence
    # (e.g. hostname containing "malicious").
    for banned in ("/tmp/packagegate", "datadog", "openssf"):
        if banned.lower() in text.lower():
            issues.append(f"banned_token:{banned}")
    if re.search(r'"label"\s*:\s*"(MALICIOUS|COMPROMISED|EXPECTED_BENIGN)"', text):
        issues.append("banned_token:label_field")
    if "EXPECTED_BENIGN" in text or re.search(r'(?<![A-Za-z])MALICIOUS(?![A-Za-z])', text):
        # Whole-token label strings outside evidence — skip if only in finding titles/URLs
        # Already covered by label_field; soft-check for Datadog category dumps:
        if '"attackCategory"' in text or '"attack_category"' in text:
            issues.append("banned_token:attack_category_present")

    return sorted(set(issues))
