"""Tests for canonical archive normalisation and processing-path equivalence."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

from packagegate_ml.datasets.canonical import canonicalise_artifact, write_canonical_tgz
from packagegate_ml.datasets.feature_families import structure_nuisance_features


def _make_npm_tgz(tmp: Path, files: dict[str, bytes], name: str = "in.tgz") -> Path:
    """Build a non-canonical tarball (varying mtimes/uids)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for i, (rel, data) in enumerate(sorted(files.items())):
            info = tarfile.TarInfo(name=f"package/{rel}")
            info.size = len(data)
            info.mtime = 1_700_000_000 + i
            info.uid = 501
            info.gid = 20
            info.uname = "alice"
            info.gname = "staff"
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    out = tmp / name
    with gzip.GzipFile(fileobj=out.open("wb"), mode="wb", mtime=1_700_000_000) as gz:
        gz.write(raw)
    return out


def test_canonicalise_is_deterministic(tmp_path: Path) -> None:
    src = _make_npm_tgz(
        tmp_path,
        {
            "package.json": b'{"name":"demo","version":"1.0.0"}',
            "index.js": b"console.log(1)\n",
        },
    )
    a = tmp_path / "a.tgz"
    b = tmp_path / "b.tgz"
    sha_a = canonicalise_artifact(src, a, work_dir=tmp_path / "wa")
    sha_b = canonicalise_artifact(src, b, work_dir=tmp_path / "wb")
    assert sha_a == sha_b
    assert a.read_bytes() == b.read_bytes()


def test_canonicalise_preserves_source_bytes(tmp_path: Path) -> None:
    payload = b"function evil(){return 42}\n"
    src = _make_npm_tgz(
        tmp_path,
        {
            "package.json": b'{"name":"x","version":"1.0.0","scripts":{"preinstall":"node x"}}',
            "x.js": payload,
        },
    )
    out = tmp_path / "canon.tgz"
    canonicalise_artifact(src, out, work_dir=tmp_path / "w")
    with tarfile.open(out, "r:gz") as tar:
        names = sorted(m.name for m in tar.getmembers() if m.isfile())
        assert "package/x.js" in names
        assert "package/package.json" in names
        data = tar.extractfile("package/x.js").read()
        assert data == payload


def test_structure_nuisance_excludes_lifecycle_hooks() -> None:
    feats = structure_nuisance_features(
        {
            "fileCount": 10,
            "analysedExecutableBytes": 100,
            "coverageRatio": 0.9,
            "hasPreinstall": 1,
            "lifecycleHookCount": 3,
        }
    )
    assert "hasPreinstall" not in feats
    assert "lifecycleHookCount" not in feats
    assert feats["fileCount"] == 10.0
