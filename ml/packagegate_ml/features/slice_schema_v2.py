"""SliceSchemaV2 — bounded, identity-masked security code slices for neural V1.

Silver labels are PackageGate deterministic behaviours overlapping the slice.
They are not independent malware ground truth.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import tarfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from packagegate_ml.features.identity_mask import (
    normalise_source_path,
    prepare_strict_source,
    security_manifest_view,
)

SLICE_SCHEMA_VERSION = 2
DEFAULT_MAX_SLICES = 32
DEFAULT_CONTEXT_LINES = 12
DEFAULT_MAX_SLICE_CHARS = 2048
DEFAULT_MINIFIED_CHAR_RADIUS = 512
DEFAULT_MAX_PER_CATEGORY = 6

# Finding category → silver behaviour labels (multi-label).
CATEGORY_TO_BEHAVIOURS: dict[str, tuple[str, ...]] = {
    "ENVIRONMENT_ACCESS": ("environment_access",),
    "SYSTEM_INFORMATION_ACCESS": ("system_information_access",),
    "CREDENTIAL_RELATED_ACCESS": ("credential_access",),
    "SENSITIVE_FILE_ACCESS": ("sensitive_file_access",),
    "HOME_DIRECTORY_ACCESS": ("home_directory_access",),
    "PROCESS_EXECUTION": ("process_execution",),
    "SHELL_COMMAND": ("shell_execution",),
    "REMOTE_CODE_FETCH": ("remote_code_fetch", "remote_download"),
    "DOWNLOAD_BEHAVIOUR": ("remote_download",),
    "NETWORK_ACCESS": ("network_access",),
    "NETWORK_DESTINATION": ("network_access",),
    "DYNAMIC_CODE_EXECUTION": ("dynamic_code_execution",),
    "ENCODED_PAYLOAD": ("payload_decode",),
    "HIGH_ENTROPY_PAYLOAD": ("opaque_executable_source",),
    "OBFUSCATION_SIGNAL": ("opaque_executable_source",),
    "INSTALL_SCRIPT": ("install_time_execution",),
    "PACKAGE_MANAGER_ACCESS": ("package_manager_access",),
}

# Priority: higher first. No malware label.
PRIORITY_RULES: list[tuple[str, int]] = [
    ("chain_high", 1000),
    ("lifecycle_chain", 900),
    ("credential_access", 850),
    ("sensitive_file_access", 840),
    ("home_directory_access", 830),
    ("remote_code_fetch", 820),
    ("remote_download", 810),
    ("shell_execution", 800),
    ("process_execution", 790),
    ("dynamic_code_execution", 780),
    ("environment_access", 770),
    ("environment_enumeration", 760),
    ("network_access", 750),
    ("opaque_executable_source", 740),
    ("install_time_execution", 700),
    ("other", 100),
]


@dataclass(frozen=True)
class SliceGenConfig:
    max_slices: int = DEFAULT_MAX_SLICES
    context_lines: int = DEFAULT_CONTEXT_LINES
    max_slice_chars: int = DEFAULT_MAX_SLICE_CHARS
    minified_char_radius: int = DEFAULT_MINIFIED_CHAR_RADIUS
    max_per_category: int = DEFAULT_MAX_PER_CATEGORY
    remove_comments: bool = True


@dataclass
class SliceCandidate:
    slice_id: str
    file_path: str
    start_line: int | None
    end_line: int | None
    source_text: str
    lifecycle_reachable: bool
    lifecycle_hook: str | None
    deterministic_findings: list[str]
    behaviour_labels: list[str]
    behaviour_chain_membership: list[str]
    chain_type: str | None
    chain_step_index: int | None
    priority: float
    opaque_source: bool
    full_ast_available: bool
    window_type: str
    source_size_bucket: int
    category_key: str
    content_hash: str

    def to_model_dict(self) -> dict[str, Any]:
        """STRICT model fields only (no package identity)."""
        out: dict[str, Any] = {
            "sliceId": self.slice_id,
            "schemaVersion": SLICE_SCHEMA_VERSION,
            "filePath": self.file_path,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "sourceText": self.source_text,
            "lifecycleReachable": self.lifecycle_reachable,
            "deterministicFindings": list(self.deterministic_findings),
            "behaviourLabels": list(self.behaviour_labels),
            "behaviourChainMembership": list(self.behaviour_chain_membership),
            "priority": self.priority,
            "opaqueSource": self.opaque_source,
            "fullAstAvailable": self.full_ast_available,
            "windowType": self.window_type,
            "sourceSizeBucket": self.source_size_bucket,
            "contentHash": self.content_hash,
        }
        if self.lifecycle_hook:
            out["lifecycleHook"] = self.lifecycle_hook
        if self.chain_type:
            out["chainType"] = self.chain_type
        if self.chain_step_index is not None:
            out["chainStepIndex"] = self.chain_step_index
        return out


@dataclass
class SliceGenerationResult:
    slices: list[SliceCandidate]
    candidate_slices: int
    selected_slices: int
    deduplicated_count: int
    truncated: bool
    code_view_available: bool
    zero_slice_reason: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "candidateSlices": self.candidate_slices,
            "selectedSlices": self.selected_slices,
            "deduplicatedCount": self.deduplicated_count,
            "truncationOccurred": self.truncated,
            "codeViewAvailable": self.code_view_available,
            "zeroSliceReason": self.zero_slice_reason,
        }


def source_size_bucket(n_chars: int) -> int:
    if n_chars < 256:
        return 0
    if n_chars < 1024:
        return 1
    if n_chars < 4096:
        return 2
    if n_chars < 16384:
        return 3
    if n_chars < 65536:
        return 4
    return 5


def load_tarball_sources(tgz: Path) -> dict[str, str]:
    """Map relative package paths → UTF-8 source (best-effort)."""
    out: dict[str, str] = {}
    if not tgz.exists():
        return out
    try:
        with tarfile.open(tgz, "r:*") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                name = member.name.replace("\\", "/")
                # Drop leading package/ root used by npm packs
                rel = name[8:] if name.startswith("package/") else name
                if not rel or rel.endswith("/"):
                    continue
                # Skip huge binaries
                if member.size > 2_000_000:
                    continue
                ext = Path(rel).suffix.lower()
                if ext not in {
                    "",
                    ".js",
                    ".mjs",
                    ".cjs",
                    ".ts",
                    ".tsx",
                    ".jsx",
                    ".json",
                    ".sh",
                    ".bash",
                    ".zsh",
                    ".cmd",
                    ".ps1",
                    ".coffee",
                } and "package.json" not in rel:
                    # still allow extensionless bin scripts under bin/
                    if not rel.startswith(("bin/", "scripts/")):
                        continue
                f = tar.extractfile(member)
                if f is None:
                    continue
                raw = f.read()
                # skip obvious binary
                if b"\x00" in raw[:1024]:
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("utf-8", errors="replace")
                out[rel] = text
                # also index basename variants without package/
                if name.startswith("package/") and rel not in out:
                    out[rel] = text
    except (tarfile.TarError, OSError):
        return out
    return out


def resolve_source(sources: dict[str, str], file_path: str) -> tuple[str | None, str]:
    """Return (text, resolved_rel_path)."""
    p = file_path.replace("\\", "/")
    if p.startswith("package/"):
        p = p[8:]
    for key in (p, f"./{p}", Path(p).name):
        if key in sources:
            return sources[key], key
    # fuzzy: endswith
    for key, text in sources.items():
        if key.endswith("/" + p) or key == p:
            return text, key
    return None, p


def window_source(
    source: str,
    start_line: int | None,
    end_line: int | None,
    *,
    config: SliceGenConfig,
) -> tuple[int | None, int | None, str, str]:
    """
    Return (startLine, endLine, text, windowType).

    Minified/single-line files use a character window.
    """
    lines = source.splitlines()
    n_lines = len(lines)
    # Minified heuristic: few lines but large
    if n_lines <= 2 and len(source) > config.max_slice_chars:
        # character window around approximate offset
        if start_line and start_line > 0 and n_lines >= 1:
            # treat start_line as unused; use middle if unknown
            center = min(len(source) // 2, len(source) - 1)
        else:
            center = len(source) // 2
        # If we have a snippet marker later, caller may pass offset via start_line=None
        lo = max(0, center - config.minified_char_radius)
        hi = min(len(source), center + config.minified_char_radius)
        text = source[lo:hi]
        if len(text) > config.max_slice_chars:
            text = text[: config.max_slice_chars]
        return None, None, text, "SIGNAL_AROUND_OFFSET"

    if not start_line or start_line < 1:
        # file head window
        text = "\n".join(lines[: config.context_lines * 2])
        if len(text) > config.max_slice_chars:
            text = text[: config.max_slice_chars]
        return 1, min(n_lines, config.context_lines * 2), text, "START"

    s = max(1, start_line - config.context_lines)
    e = min(n_lines, (end_line or start_line) + config.context_lines)
    text = "\n".join(lines[s - 1 : e])
    if len(text) > config.max_slice_chars:
        text = text[: config.max_slice_chars]
    return s, e, text, "LINE_WINDOW"


def _finding_location(finding: dict[str, Any]) -> dict[str, Any]:
    loc = finding.get("location") or {}
    if not loc and finding.get("filePath"):
        loc = {
            "filePath": finding.get("filePath"),
            "startLine": finding.get("startLine"),
            "endLine": finding.get("endLine"),
        }
    return loc


def _confidence_rank(conf: str | None) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get((conf or "").upper(), 0)


def score_priority(
    *,
    category: str,
    behaviours: list[str],
    in_chain: bool,
    chain_confidence: str | None,
    lifecycle_reachable: bool,
) -> float:
    score = 100.0
    for beh in behaviours:
        for name, pts in PRIORITY_RULES:
            if beh == name or (name == "other"):
                if beh == name:
                    score = max(score, float(pts))
    # category fallbacks
    cat_map = {
        "CREDENTIAL_RELATED_ACCESS": 850,
        "SENSITIVE_FILE_ACCESS": 840,
        "REMOTE_CODE_FETCH": 820,
        "SHELL_COMMAND": 800,
        "PROCESS_EXECUTION": 790,
        "DYNAMIC_CODE_EXECUTION": 780,
        "ENVIRONMENT_ACCESS": 770,
        "NETWORK_DESTINATION": 750,
        "NETWORK_ACCESS": 750,
        "OBFUSCATION_SIGNAL": 740,
        "HIGH_ENTROPY_PAYLOAD": 740,
        "INSTALL_SCRIPT": 700,
    }
    if category in cat_map:
        score = max(score, float(cat_map[category]))
    if in_chain:
        score += 200 + 50 * _confidence_rank(chain_confidence)
        if lifecycle_reachable:
            score += 100
    elif lifecycle_reachable:
        score += 80
    return score


def content_hash(text: str) -> str:
    # Normalise whitespace for near-dup detection
    norm = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def token_fingerprint(text: str) -> str:
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text.lower())
    # keep first 40 unique tokens
    seen: list[str] = []
    for t in toks:
        if t not in seen:
            seen.append(t)
        if len(seen) >= 40:
            break
    return hashlib.sha256(" ".join(seen).encode()).hexdigest()[:16]


def dedupe_candidates(cands: list[SliceCandidate]) -> tuple[list[SliceCandidate], int]:
    """Keep highest-priority per content hash and near-identical fingerprint."""
    by_hash: dict[str, SliceCandidate] = {}
    removed = 0
    for c in sorted(cands, key=lambda x: (-x.priority, x.file_path, x.slice_id)):
        key = c.content_hash
        fp = token_fingerprint(c.source_text)
        # also collapse identical fingerprints across hashes when text nearly same
        clash = None
        for existing in by_hash.values():
            if token_fingerprint(existing.source_text) == fp and existing.file_path == c.file_path:
                clash = existing.content_hash
                break
        if key in by_hash or clash is not None:
            removed += 1
            continue
        by_hash[key] = c
    return list(by_hash.values()), removed


def select_with_diversity(
    cands: list[SliceCandidate],
    *,
    config: SliceGenConfig,
) -> tuple[list[SliceCandidate], bool]:
    """Priority rank with per-category caps, then fill remaining slots."""
    ranked = sorted(cands, key=lambda x: (-x.priority, x.file_path, x.slice_id))
    selected: list[SliceCandidate] = []
    per_cat: dict[str, int] = {}
    have: set[str] = set()

    def try_add(c: SliceCandidate, *, respect_cap: bool) -> bool:
        if c.slice_id in have or len(selected) >= config.max_slices:
            return False
        if respect_cap and per_cat.get(c.category_key, 0) >= config.max_per_category:
            return False
        selected.append(c)
        have.add(c.slice_id)
        per_cat[c.category_key] = per_cat.get(c.category_key, 0) + 1
        return True

    for c in ranked:
        try_add(c, respect_cap=True)
    if len(selected) < min(config.max_slices, len(ranked)):
        for c in ranked:
            try_add(c, respect_cap=False)
    truncated = len(ranked) > len(selected)
    return selected, truncated


def _package_json_security_text(sources: dict[str, str]) -> str | None:
    for key in ("package.json", "package/package.json"):
        if key in sources:
            try:
                pkg = json.loads(sources[key])
            except json.JSONDecodeError:
                return None
            view = security_manifest_view(pkg)
            if not view:
                return None
            return json.dumps(view, indent=2, sort_keys=True)
    # try any path ending with package.json
    for key, text in sources.items():
        if key.endswith("package.json"):
            try:
                pkg = json.loads(text)
            except json.JSONDecodeError:
                continue
            view = security_manifest_view(pkg)
            if view:
                return json.dumps(view, indent=2, sort_keys=True)
    return None


def generate_slices_for_package(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    lifecycle: list[dict[str, Any]],
    sources: dict[str, str],
    *,
    package_name: str | None,
    version: str | None,
    config: SliceGenConfig | None = None,
) -> SliceGenerationResult:
    """Build STRICT SliceSchemaV2 candidates from genuine artifact sources."""
    cfg = config or SliceGenConfig()
    chain_files: set[str] = set()
    chain_ids_by_file: dict[str, list[str]] = {}
    chain_meta: dict[str, dict[str, Any]] = {}
    for chain in chains:
        cid = chain.get("id") or ""
        conf = chain.get("confidence")
        meta = chain.get("metadata") or {}
        ctype = meta.get("chainType") or f"{chain.get('source')}->{chain.get('sink')}"
        chain_meta[cid] = {"confidence": conf, "chainType": ctype}
        for i, link in enumerate(chain.get("links") or []):
            loc = (link.get("location") or {}) if isinstance(link, dict) else {}
            path = loc.get("filePath")
            if not path:
                continue
            path = path.replace("\\", "/")
            if path.startswith("package/"):
                path = path[8:]
            chain_files.add(path)
            chain_ids_by_file.setdefault(path, []).append(cid)

    # Lifecycle reachable files from referenced files / node script paths
    lifecycle_files: dict[str, str] = {}
    for script in lifecycle:
        hook = script.get("name") or script.get("hook") or ""
        for rel in script.get("referencedFiles") or []:
            normalised = str(rel).replace("\\", "/").lstrip("./")
            if normalised in sources or any(
                k.endswith(normalised) for k in sources
            ):
                lifecycle_files[normalised] = hook
        cmd = script.get("command") or ""
        m = re.search(r"\bnode\s+([./\w-]+\.m?js)\b", cmd, re.I)
        if m:
            rel = m.group(1).lstrip("./")
            if rel in sources:
                lifecycle_files[rel] = hook

    candidates: list[SliceCandidate] = []

    def add_from_text(
        *,
        file_path: str,
        text: str,
        start: int | None,
        end: int | None,
        window_type: str,
        finding_ids: list[str],
        category: str,
        behaviours: list[str],
        opaque: bool = False,
        chain_id: str | None = None,
        step_index: int | None = None,
    ) -> None:
        masked_path = normalise_source_path(
            file_path, package_name=package_name, version=version
        )
        masked_text = prepare_strict_source(
            text,
            package_name=package_name,
            version=version,
            remove_comments=cfg.remove_comments,
        )
        if not masked_text.strip():
            return
        if len(masked_text) > cfg.max_slice_chars:
            masked_text = masked_text[: cfg.max_slice_chars]
        in_chain = file_path in chain_files or masked_path in chain_files
        hook = lifecycle_files.get(file_path) or lifecycle_files.get(masked_path)
        life = hook is not None or file_path in lifecycle_files
        chain_conf = None
        ctype = None
        membership = list(
            dict.fromkeys(
                chain_ids_by_file.get(file_path, [])
                + chain_ids_by_file.get(masked_path, [])
            )
        )
        if chain_id and chain_id not in membership:
            membership.append(chain_id)
        if membership:
            chain_conf = (chain_meta.get(membership[0]) or {}).get("confidence")
            ctype = (chain_meta.get(membership[0]) or {}).get("chainType")
        if category:
            behaviours = list(
                dict.fromkeys(
                    list(behaviours)
                    + list(CATEGORY_TO_BEHAVIOURS.get(category, ()))
                )
            )
        pr = score_priority(
            category=category,
            behaviours=behaviours,
            in_chain=in_chain or bool(membership),
            chain_confidence=chain_conf,
            lifecycle_reachable=life,
        )
        ch = content_hash(masked_text)
        sid = hashlib.sha256(
            f"{masked_path}:{start}:{end}:{ch}:{','.join(finding_ids)}".encode()
        ).hexdigest()[:16]
        candidates.append(
            SliceCandidate(
                slice_id=sid,
                file_path=masked_path,
                start_line=start,
                end_line=end,
                source_text=masked_text,
                lifecycle_reachable=life,
                lifecycle_hook=hook,
                deterministic_findings=list(finding_ids),
                behaviour_labels=behaviours,
                behaviour_chain_membership=membership,
                chain_type=ctype,
                chain_step_index=step_index,
                priority=pr,
                opaque_source=opaque,
                full_ast_available=not opaque,
                window_type=window_type,
                source_size_bucket=source_size_bucket(len(text)),
                category_key=category or (behaviours[0] if behaviours else "other"),
                content_hash=ch,
            )
        )

    # Finding-centred slices
    for finding in findings:
        loc = _finding_location(finding)
        fp = loc.get("filePath")
        if not fp:
            continue
        category = finding.get("category") or "OTHER"
        fid = finding.get("id") or ""
        behaviours = list(CATEGORY_TO_BEHAVIOURS.get(category, ()))

        # package.json → security manifest view (no identity fields)
        if str(fp).endswith("package.json"):
            sec = _package_json_security_text(sources)
            if sec:
                add_from_text(
                    file_path="package.json",
                    text=sec,
                    start=None,
                    end=None,
                    window_type="SECURITY_MANIFEST",
                    finding_ids=[fid] if fid else [],
                    category=category,
                    behaviours=behaviours,
                )
                continue

        text, resolved = resolve_source(sources, str(fp))
        if text is None:
            # Do not invent code. Skip (snippet alone without artifact file is
            # insufficient when the file is missing from the pack).
            continue
        opaque = category in {"OBFUSCATION_SIGNAL", "HIGH_ENTROPY_PAYLOAD"} or (
            len(text) > 100_000
        )
        if opaque and len(text) > cfg.max_slice_chars * 4:
            # bounded opaque windows: START + optional line window
            head = text[: cfg.max_slice_chars]
            add_from_text(
                file_path=resolved,
                text=head,
                start=1,
                end=None,
                window_type="START",
                finding_ids=[fid] if fid else [],
                category=category,
                behaviours=behaviours or ["opaque_executable_source"],
                opaque=True,
            )
            s_line = loc.get("startLine")
            e_line = loc.get("endLine")
            if s_line:
                s, e, win, wtype = window_source(
                    text, s_line, e_line, config=cfg
                )
                add_from_text(
                    file_path=resolved,
                    text=win,
                    start=s,
                    end=e,
                    window_type="SIGNAL_AROUND_OFFSET",
                    finding_ids=[fid] if fid else [],
                    category=category,
                    behaviours=behaviours or ["opaque_executable_source"],
                    opaque=True,
                )
            continue

        s, e, win, wtype = window_source(
            text,
            loc.get("startLine"),
            loc.get("endLine"),
            config=cfg,
        )
        add_from_text(
            file_path=resolved,
            text=win,
            start=s,
            end=e,
            window_type=wtype,
            finding_ids=[fid] if fid else [],
            category=category,
            behaviours=behaviours,
            opaque=opaque,
        )

    # Chain-link slices not already covered by findings (cross-file linkage)
    for chain in chains:
        cid = chain.get("id") or ""
        meta = chain.get("metadata") or {}
        ctype = meta.get("chainType")
        for i, link in enumerate(chain.get("links") or []):
            if not isinstance(link, dict):
                continue
            loc = link.get("location") or {}
            fp = loc.get("filePath")
            if not fp:
                continue
            text, resolved = resolve_source(sources, str(fp))
            if text is None:
                continue
            s, e, win, wtype = window_source(
                text, loc.get("startLine"), loc.get("endLine"), config=cfg
            )
            add_from_text(
                file_path=resolved,
                text=win,
                start=s,
                end=e,
                window_type=wtype,
                finding_ids=[],
                category="CHAIN_LINK",
                behaviours=[],
                chain_id=cid,
                step_index=i,
            )

    # Lifecycle entrypoint files even without findings
    for rel, hook in lifecycle_files.items():
        text, resolved = resolve_source(sources, rel)
        if text is None:
            continue
        s, e, win, wtype = window_source(text, 1, min(40, text.count("\n") + 1), config=cfg)
        add_from_text(
            file_path=resolved,
            text=win,
            start=s,
            end=e,
            window_type=wtype,
            finding_ids=[],
            category="INSTALL_SCRIPT",
            behaviours=["install_time_execution"],
        )

    # Manifest + main/bin entrypoints: genuine code context for packages with
    # no findings (common for expected-benign). Do NOT invent behaviour labels.
    sec = _package_json_security_text(sources)
    if sec and not any(c.window_type == "SECURITY_MANIFEST" for c in candidates):
        add_from_text(
            file_path="package.json",
            text=sec,
            start=None,
            end=None,
            window_type="SECURITY_MANIFEST",
            finding_ids=[],
            category="MANIFEST_CONTEXT",
            behaviours=[],
        )

    entry_paths: list[str] = []
    for key in ("package.json",):
        raw = sources.get(key)
        if not raw:
            continue
        try:
            pkg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        for field in ("main", "module"):
            val = pkg.get(field)
            if isinstance(val, str) and val:
                entry_paths.append(val.lstrip("./"))
        bin_field = pkg.get("bin")
        if isinstance(bin_field, str):
            entry_paths.append(bin_field.lstrip("./"))
        elif isinstance(bin_field, dict):
            for v in bin_field.values():
                if isinstance(v, str):
                    entry_paths.append(v.lstrip("./"))
    for rel in dict.fromkeys(entry_paths):
        text, resolved = resolve_source(sources, rel)
        if text is None:
            continue
        # Prefer head of entrypoint (install/runtime surface)
        s, e, win, wtype = window_source(text, 1, min(30, text.count("\n") + 1), config=cfg)
        add_from_text(
            file_path=resolved,
            text=win,
            start=s,
            end=e,
            window_type=wtype if wtype != "START" else "ENTRYPOINT",
            finding_ids=[],
            category="ENTRYPOINT",
            behaviours=[],
        )

    n_cand = len(candidates)
    deduped, n_removed = dedupe_candidates(candidates)
    selected, truncated = select_with_diversity(deduped, config=cfg)

    reason = None
    if not selected:
        if not findings and not chains and not lifecycle_files:
            reason = "no_security_evidence_locations"
        elif not sources:
            reason = "artifact_sources_unreadable"
        else:
            reason = "evidence_locations_without_resolvable_source"

    return SliceGenerationResult(
        slices=selected,
        candidate_slices=n_cand,
        selected_slices=len(selected),
        deduplicated_count=n_removed,
        truncated=truncated,
        code_view_available=len(selected) > 0,
        zero_slice_reason=reason,
    )
