"""Canonical inert archive normalisation for Dataset V3 ML evaluation.

Both Datadog-rebuilt and npm-registry tarballs are re-processed through the
same extract → canonical tree → deterministic pack path before PackageGate
scan-tarball / ML export.

Safety: never executes package code, never runs lifecycle scripts, never
invokes npm/node against package contents.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import tarfile
import tempfile
from pathlib import Path


CANONICAL_MTIME = 0  # deterministic archive timestamps
CANONICAL_UID = 0
CANONICAL_GID = 0
CANONICAL_UNAME = "root"
CANONICAL_GNAME = "root"


def _is_safe_member(member: tarfile.TarInfo, dest: Path) -> bool:
    name = member.name
    if name.startswith("/") or name.startswith("\\"):
        return False
    if ".." in Path(name).parts:
        return False
    if member.issym() or member.islnk():
        return False
    target = (dest / name).resolve()
    try:
        target.relative_to(dest.resolve())
    except ValueError:
        return False
    return True


def safe_extract_tarball(archive: Path, dest: Path) -> Path:
    """Extract a tarball as inert data into dest; return package root."""
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            if not _is_safe_member(member, dest):
                continue
            if member.isdir():
                (dest / member.name).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            out = dest / member.name
            out.parent.mkdir(parents=True, exist_ok=True)
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            data = extracted.read()
            out.write_bytes(data)
            # Drop execute bits — inert data only.
            out.chmod(0o644)

    # Prefer package/ root when present (npm layout).
    pkg = dest / "package"
    if pkg.is_dir():
        return pkg
    # Else find shallowest package.json
    candidates = sorted(dest.rglob("package.json"), key=lambda p: len(p.parts))
    if candidates:
        return candidates[0].parent
    return dest


def find_package_root(tree: Path) -> Path:
    if (tree / "package.json").is_file():
        return tree
    if (tree / "package" / "package.json").is_file():
        return tree / "package"
    candidates = sorted(tree.rglob("package.json"), key=lambda p: len(p.parts))
    if candidates:
        return candidates[0].parent
    return tree


def write_canonical_tgz(package_root: Path, out_tgz: Path) -> str:
    """
    Pack package_root into a deterministic npm-style package/*.tgz.

    Normalises: entry order, uid/gid/uname, mtime, mode, gzip mtime.
    Preserves: relative paths, file bytes, package.json, binaries as data.
    """
    out_tgz.parent.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []
    for path in package_root.rglob("*"):
        if path.is_symlink():
            continue
        if path.is_file():
            files.append(path)
    files.sort(key=lambda p: p.relative_to(package_root).as_posix())

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        for path in files:
            rel = path.relative_to(package_root).as_posix()
            data = path.read_bytes()
            info = tarfile.TarInfo(name=f"package/{rel}")
            info.size = len(data)
            info.mtime = CANONICAL_MTIME
            info.uid = CANONICAL_UID
            info.gid = CANONICAL_GID
            info.uname = CANONICAL_UNAME
            info.gname = CANONICAL_GNAME
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))

    raw_tar = tar_buf.getvalue()
    # Deterministic gzip (mtime=0, fixed OS byte where possible).
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0, compresslevel=9) as gz:
        gz.write(raw_tar)
    out_tgz.write_bytes(gz_buf.getvalue())
    return hashlib.sha256(out_tgz.read_bytes()).hexdigest()


def canonicalise_artifact(src_tgz: Path, out_tgz: Path, *, work_dir: Path | None = None) -> str:
    """
    Extract src_tgz safely and rewrite a canonical evaluation archive to out_tgz.

    Returns SHA-256 of the canonical archive.
    """
    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="pg-canon-"))
        cleanup = True
    else:
        work_dir.mkdir(parents=True, exist_ok=True)
        cleanup = False
    try:
        extract_root = work_dir / "extract"
        if extract_root.exists():
            shutil.rmtree(extract_root)
        extract_root.mkdir(parents=True)
        pkg_root = safe_extract_tarball(src_tgz, extract_root)
        pkg_root = find_package_root(pkg_root)
        return write_canonical_tgz(pkg_root, out_tgz)
    finally:
        if cleanup:
            shutil.rmtree(work_dir, ignore_errors=True)


def behaviour_feature_delta(before: dict, after: dict) -> dict[str, float]:
    """Scalar delta helper for processing-path equivalence checks."""
    keys = sorted(set(before) | set(after))
    return {k: float(after.get(k, 0.0) - before.get(k, 0.0)) for k in keys}
