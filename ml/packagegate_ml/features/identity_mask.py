"""Identity masking for PackageGateMlRecordV2 STRICT_SECURITY_VIEW.

Training metadata may retain package names for splits. Model input must not.
"""

from __future__ import annotations

import re
from typing import Any

# Node built-ins preserved in import masking.
NODE_BUILTINS = frozenset(
    {
        "assert",
        "buffer",
        "child_process",
        "cluster",
        "crypto",
        "dgram",
        "dns",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "querystring",
        "readline",
        "stream",
        "string_decoder",
        "timers",
        "tls",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "worker_threads",
        "zlib",
        "node:assert",
        "node:buffer",
        "node:child_process",
        "node:cluster",
        "node:crypto",
        "node:dgram",
        "node:dns",
        "node:events",
        "node:fs",
        "node:http",
        "node:http2",
        "node:https",
        "node:module",
        "node:net",
        "node:os",
        "node:path",
        "node:perf_hooks",
        "node:process",
        "node:querystring",
        "node:readline",
        "node:stream",
        "node:string_decoder",
        "node:timers",
        "node:tls",
        "node:tty",
        "node:url",
        "node:util",
        "node:v8",
        "node:vm",
        "node:worker_threads",
        "node:zlib",
    }
)

SECURITY_PATH_HINTS = (
    "scripts/",
    "script/",
    "bin/",
    "lib/",
    "src/",
    "dist/",
    "install",
    "setup",
    "postinstall",
    "preinstall",
    "binding",
    "native",
    "addon",
)


def strip_js_comments(source: str) -> str:
    """Remove // and /* */ comments; preserve string literals (best-effort)."""
    out: list[str] = []
    i = 0
    n = len(source)
    in_squote = False
    in_dquote = False
    in_template = False
    in_line = False
    in_block = False
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if in_line:
            if ch == "\n":
                in_line = False
                out.append(ch)
            i += 1
            continue
        if in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 2
                continue
            i += 1
            continue
        if in_squote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if ch == "'":
                in_squote = False
            i += 1
            continue
        if in_dquote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if ch == '"':
                in_dquote = False
            i += 1
            continue
        if in_template:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if ch == "`":
                in_template = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            i += 2
            continue
        if ch == "'":
            in_squote = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dquote = True
            out.append(ch)
            i += 1
            continue
        if ch == "`":
            in_template = True
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def normalise_source_path(path: str, *, package_name: str | None = None, version: str | None = None) -> str:
    """
    Preserve security-relevant path structure; strip package/version identity tokens.

    Does not blindly rewrite arbitrary path segments.
    """
    p = path.replace("\\", "/")
    # Drop leading package/ npm root
    if p.startswith("package/"):
        p = p[len("package/") :]
    bare = None
    if package_name:
        bare = package_name.split("/")[-1] if package_name.startswith("@") else package_name
        # Strip self-package root directory (metrics/foo.js → foo.js)
        parts = p.split("/")
        if len(parts) > 1 and parts[0] == bare:
            p = "/".join(parts[1:])
        # Drop archive roots that embed package@version
        if version:
            for token in (
                f"{package_name}-{version}/",
                f"{bare}-{version}/",
                f"{package_name}@{version}/",
                f"{bare}@{version}/",
            ):
                if p.startswith(token):
                    p = p[len(token) :]
        # leading package folder equal to package name before src/lib/...
        for token in (f"{package_name}/", f"{bare}/"):
            if p.startswith(token) and not any(h in token for h in ("lib/", "src/", "bin/")):
                rest = p[len(token) :]
                if rest.startswith(("src/", "lib/", "dist/", "bin/", "scripts/", "index.")):
                    p = rest
    # Collapse repeated package@version directory mid-path
    if package_name and version:
        bare = package_name.split("/")[-1]
        for token in (f"/{package_name}-{version}/", f"/{bare}-{version}/"):
            p = p.replace(token, "/")
    return p


def mask_external_imports(source: str) -> str:
    """
    Replace require/import module string literals for non-local, non-builtin deps.

    Does not rewrite shell commands, URLs, or non-import strings.
    """

    def repl_require(match: re.Match[str]) -> str:
        quote = match.group(1)
        mod = match.group(2)
        if mod.startswith(".") or mod.startswith("/") or mod in NODE_BUILTINS:
            return match.group(0)
        if mod.startswith("node:") and mod in NODE_BUILTINS:
            return match.group(0)
        return f"require({quote}<EXTERNAL_MODULE>{quote})"

    def repl_from(match: re.Match[str]) -> str:
        quote = match.group(1)
        mod = match.group(2)
        if mod.startswith(".") or mod.startswith("/") or mod in NODE_BUILTINS:
            return match.group(0)
        return f"from {quote}<EXTERNAL_MODULE>{quote}"

    def repl_import(match: re.Match[str]) -> str:
        quote = match.group(1)
        mod = match.group(2)
        if mod.startswith(".") or mod.startswith("/") or mod in NODE_BUILTINS:
            return match.group(0)
        return f"import({quote}<EXTERNAL_MODULE>{quote})"

    text = re.sub(
        r"""require\s*\(\s*(['"])([^'"]+)\1\s*\)""",
        repl_require,
        source,
    )
    text = re.sub(
        r"""from\s+(['"])([^'"]+)\1""",
        repl_from,
        text,
    )
    text = re.sub(
        r"""import\s*\(\s*(['"])([^'"]+)\1\s*\)""",
        repl_import,
        text,
    )
    return text


def _sanitize_binary_indicator(value: Any) -> Any:
    """Keep native/binary install hints; strip identity fields from node-pre-gyp configs."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in {
                "package_name",
                "packageName",
                "name",
                "module_name",
                "moduleName",
                "remote_path",
                "host",
                "repository",
            }:
                continue
            out[k] = _sanitize_binary_indicator(v)
        return out
    if isinstance(value, list):
        return [_sanitize_binary_indicator(v) for v in value]
    return value


def security_manifest_view(package_json: dict[str, Any] | None) -> dict[str, Any]:
    """Keep lifecycle/bin/main; drop identity metadata fields."""
    if not package_json:
        return {}
    out: dict[str, Any] = {}
    scripts = package_json.get("scripts")
    if isinstance(scripts, dict):
        keep = {}
        for key in (
            "preinstall",
            "install",
            "postinstall",
            "preuninstall",
            "uninstall",
            "postuninstall",
            "prepare",
            "prepublish",
            "prepublishOnly",
        ):
            if key in scripts:
                keep[key] = scripts[key]
        # also keep any script whose name contains install
        for key, val in scripts.items():
            if "install" in key.lower() and key not in keep:
                keep[key] = val
        if keep:
            out["scripts"] = keep
    for key in ("main", "module", "bin", "engines", "os", "cpu", "gypfile"):
        if key in package_json:
            out[key] = package_json[key]
    if "binary" in package_json:
        out["binary"] = _sanitize_binary_indicator(package_json["binary"])
        # Preserve that a binary/native indicator existed without identity
        if out["binary"] == {} or out["binary"] is None:
            out["hasNativeBinaryIndicator"] = True
            out.pop("binary", None)
        else:
            out["hasNativeBinaryIndicator"] = True
    return out


def mask_self_identity_narrow(
    source: str,
    *,
    package_name: str | None,
    version: str | None,
) -> str:
    """
    Narrow self-name masking: only replace package name / version tokens
    that look like identity metadata assignments — not global string replace.
    """
    text = source
    if package_name:
        text = re.sub(
            rf'(["\']?name["\']?\s*:\s*)(["\']){re.escape(package_name)}\2',
            r"\1\2<PACKAGE>\2",
            text,
        )
    if version:
        text = re.sub(
            rf'(["\']?version["\']?\s*:\s*)(["\']){re.escape(version)}\2',
            r"\1\2<VERSION>\2",
            text,
        )
    return text


def prepare_strict_source(
    source: str,
    *,
    package_name: str | None,
    version: str | None,
    remove_comments: bool = True,
) -> str:
    text = source
    if remove_comments:
        text = strip_js_comments(text)
    text = mask_external_imports(text)
    text = mask_self_identity_narrow(text, package_name=package_name, version=version)
    return text
