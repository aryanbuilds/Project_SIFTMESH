"""Memory-image acquisition (Epic D deepening): unzip/7z, format detect, fail-closed.

7z subprocess is mocked; the outer zip is a real stdlib zip. No real memory image is used.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from siftmesh_core.evidence import memory_access
from siftmesh_core.mcp_gateway.backends import BackendUnavailableError


def test_detect_format_by_magic(tmp_path: Path) -> None:
    raw = tmp_path / "mem.raw"
    raw.write_bytes(b"PAGEDU64" + b"\x00" * 16)
    assert memory_access.detect_format(raw) == "windows_crashdump64"
    plain = tmp_path / "plain.raw"
    plain.write_bytes(b"\x00" * 32)
    assert memory_access.detect_format(plain) == "raw"


def test_decompress_plain_zip_no_7z_needed(tmp_path: Path) -> None:
    """A zip whose member is the raw image directly needs no 7z step."""
    zip_path = tmp_path / "Memory.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("memory.raw", b"PAGEDU64" + b"\x01" * 4096)
    dest = tmp_path / "extracted"
    img = memory_access.decompress(zip_path, dest)
    assert img.path.is_file()
    assert img.image_format == "windows_crashdump64"
    assert img.size_bytes > 0
    assert len(img.sha256) == 64


def test_decompress_7z_path_lists_then_extracts_member(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    zip_path = tmp_path / "Memory.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("Rocba-Memory.7z", b"7z-bytes-placeholder")
    dest = tmp_path / "extracted"

    monkeypatch.setattr(memory_access.shutil, "which", lambda name: f"/usr/bin/{name}")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> object:
        calls.append(argv)
        if argv[1] == "e":
            (dest / "rocba.mem").write_bytes(b"\x00" * 8192)

        class _P:
            returncode = 0
            stdout = (
                "Path = Rocba-Memory.7z\nType = 7z\n\n"
                "Path = rocba.mem\nFolder = -\nSize = 8192\n\n"
                "Path = notes.txt\nFolder = -\nSize = 12\n\n"
            )
            stderr = ""

        return _P()

    monkeypatch.setattr(memory_access.subprocess, "run", fake_run)
    img = memory_access.decompress(zip_path, dest)
    assert [c[1] for c in calls] == ["l", "e"]  # list, then selective member extract
    assert calls[1][-1] == "rocba.mem"  # largest member, not the 12-byte decoy
    assert img.path.name == "rocba.mem"
    assert not (dest / "Rocba-Memory.7z").exists()  # intermediate archive tidied away


def test_decompress_7z_unlistable_falls_back_to_full_extract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    zip_path = tmp_path / "Memory.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("Rocba-Memory.7z", b"7z-bytes-placeholder")
    dest = tmp_path / "extracted"

    monkeypatch.setattr(memory_access.shutil, "which", lambda name: f"/usr/bin/{name}")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> object:
        calls.append(argv)
        if argv[1] == "x":
            (dest / "rocba.mem").write_bytes(b"\x00" * 8192)

        class _P:
            returncode = 1 if argv[1] == "l" else 0
            stdout = ""
            stderr = "list failed"

        return _P()

    monkeypatch.setattr(memory_access.subprocess, "run", fake_run)
    img = memory_access.decompress(zip_path, dest)
    assert [c[1] for c in calls] == ["l", "x"]
    assert img.path.name == "rocba.mem"


def test_zip_extracts_only_needed_member(tmp_path: Path) -> None:
    """A huge decoy beside the nested archive is never extracted (5hk)."""
    zip_path = tmp_path / "Memory.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("decoy.bin", b"\x00" * 99999)
        zf.writestr("inner/memory.raw", b"PAGEDU64" + b"\x01" * 4096)
    dest = tmp_path / "extracted"
    img = memory_access.decompress(zip_path, dest)
    assert img.path.name == "memory.raw"  # largest non-archive member, basename-flattened
    assert img.image_format == "windows_crashdump64"
    assert not (dest / "decoy.bin").exists()
    assert sorted(p.name for p in dest.iterdir()) == ["memory.raw"]


def test_decompress_fails_closed_without_7z(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    zip_path = tmp_path / "Memory.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("Rocba-Memory.7z", b"7z-bytes")
    monkeypatch.setattr(memory_access.shutil, "which", lambda name: None)
    with pytest.raises(BackendUnavailableError):
        memory_access.decompress(zip_path, tmp_path / "extracted")


def test_zip_member_basename_neutralises_traversal(tmp_path: Path) -> None:
    """A hostile member name is reduced to its basename - never escapes dest."""
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../etc/pwned.raw", b"PAGEDU64" + b"\x00" * 16)
    dest = tmp_path / "extracted"
    img = memory_access.decompress(zip_path, dest)
    assert img.path.parent.resolve() == dest.resolve()
    assert not (tmp_path / "etc" / "pwned.raw").exists()
