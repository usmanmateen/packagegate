"""Tests for PackageGateMlRecordV2 identity masking and leakage audits."""

from __future__ import annotations

from packagegate_ml.features.identity_mask import (
    mask_external_imports,
    normalise_source_path,
    prepare_strict_source,
    security_manifest_view,
    strip_js_comments,
)
from packagegate_ml.features.record_v2 import (
    audit_strict_record_leakage,
    build_package_gate_ml_record_v2,
)


def test_strip_comments_preserves_strings() -> None:
    src = 'const x = "http://evil.com"; // comment\n/* block */\nrequire("fs");\n'
    out = strip_js_comments(src)
    assert "http://evil.com" in out
    assert "comment" not in out
    assert "block" not in out
    assert 'require("fs")' in out


def test_path_normalisation_strips_package_version_root() -> None:
    p = normalise_source_path(
        "package/evil-pkg-1.2.3/scripts/install.js",
        package_name="evil-pkg",
        version="1.2.3",
    )
    assert p == "scripts/install.js" or p.endswith("scripts/install.js")
    assert "1.2.3" not in p


def test_path_preserves_security_layout() -> None:
    p = normalise_source_path("package/scripts/postinstall.js")
    assert p == "scripts/postinstall.js"


def test_external_import_masking_keeps_builtins_and_locals() -> None:
    src = 'require("child_process"); require("lodash"); require("./local"); import x from "@scope/pkg";'
    out = mask_external_imports(src)
    assert 'require("child_process")' in out
    assert 'require("./local")' in out
    assert "<EXTERNAL_MODULE>" in out
    assert "lodash" not in out or "<EXTERNAL_MODULE>" in out


def test_security_manifest_drops_identity() -> None:
    view = security_manifest_view(
        {
            "name": "evil",
            "version": "9.9.9",
            "description": "bad",
            "author": "x",
            "repository": "https://github.com/x/y",
            "scripts": {"preinstall": "node x.js", "test": "jest"},
            "main": "index.js",
            "bin": {"evil": "bin.js"},
        }
    )
    assert "name" not in view
    assert "version" not in view
    assert "description" not in view
    assert "author" not in view
    assert "repository" not in view
    assert view["scripts"]["preinstall"] == "node x.js"
    assert "test" not in view["scripts"]
    assert view["main"] == "index.js"


def test_strict_record_excludes_identity_fields() -> None:
    export = {
        "structuredFeatures": {
            "findingCount": 2,
            "hasPreinstall": 1,
            "fileCount": 10,
            "analysedExecutableBytes": 1000,
            "coverageRatio": 0.9,
            "completenessStatusDegraded": 1,
            "findingsByCategory": {"PROCESS_EXECUTION": 1},
            "chainsByType": {},
            "findingsBySeverity": {},
            "findingsByConfidence": {},
        },
        "lifecycle": [{"name": "preinstall", "command": "node x.js"}],
        "findings": [
            {
                "id": "f1",
                "category": "PROCESS_EXECUTION",
                "severity": "HIGH",
                "confidence": "HIGH",
                "filePath": "package/evil-thing-9.9.9/scripts/x.js",
                "startLine": 1,
                "endLine": 2,
                "title": "exec",
            }
        ],
        "chains": [],
        "completeness": {"status": "DEGRADED", "coverageRatio": 0.9},
        "slices": [
            {
                "sliceId": "s1",
                "filePath": "package/evil-thing-9.9.9/scripts/x.js",
                "sourceText": '// secret identity\nrequire("child_process").exec("curl http://x");\n',
                "lifecycleReachable": True,
                "deterministicFindings": ["PROCESS_EXECUTION"],
                "behaviourLabels": ["process_execution"],
                "behaviourChainMembership": [],
            }
        ],
        "mlInputCompleteness": {
            "slicesAvailable": 1,
            "slicesUsed": 1,
            "truncationOccurred": False,
        },
        "artifact": {"sha256": "abc"},
    }
    rec = build_package_gate_ml_record_v2(
        v1_or_export=export,
        package_name="evil-thing",
        version="9.9.9",
        package_json={
            "name": "evil-thing",
            "version": "9.9.9",
            "scripts": {"preinstall": "node x.js"},
        },
        view="STRICT_SECURITY_VIEW",
    )
    assert "package" not in rec or "name" not in (rec.get("package") or {})
    assert rec["schemaVersion"] == 2
    assert "fileCount" not in rec["structuredBehaviourFeatures"]
    assert rec["structuredBehaviourFeatures"]["hasPreinstall"] == 1.0
    assert "secret identity" not in rec["slices"][0]["sourceText"]
    assert "child_process" in rec["slices"][0]["sourceText"]
    issues = audit_strict_record_leakage(
        rec, package_name="evil-thing", version="9.9.9"
    )
    assert issues == [], issues


def test_prepare_strict_source_masks_self_name_assignment() -> None:
    src = 'module.exports = { name: "uniq-malware-pkg", version: "1.0.0" };'
    out = prepare_strict_source(
        src, package_name="uniq-malware-pkg", version="1.0.0"
    )
    assert "uniq-malware-pkg" not in out
    assert "<PACKAGE>" in out
    assert "<VERSION>" in out
